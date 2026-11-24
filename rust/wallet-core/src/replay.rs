//! Durable replay protection for authenticated wallet-core envelopes.
//!
//! A nonce is consumed only after the envelope's signature and expiry have
//! already passed verification. The tuple includes signer and key ID so key
//! rotation cannot accidentally create a cross-signer replay domain.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use crate::authenticated::{AuthError, AuthenticatedEnvelope, SignatureVerifier};

const MAGIC: &[u8; 4] = b"BWNR";
const VERSION: u16 = 1;
const NONCE_LEN: usize = 16;
const MAX_ENTRIES: usize = 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ReplayKey {
    signer: String,
    key_id: String,
    nonce: [u8; NONCE_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReplayRecord {
    expires_at_unix: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ReplayError {
    Io,
    Corrupt,
    Expired,
    ZeroNonce,
    AlreadyConsumed,
    CapacityExceeded,
    SignatureRejected,
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io => write!(f, "replay registry I/O failed"),
            Self::Corrupt => write!(f, "replay registry is corrupt"),
            Self::Expired => write!(f, "authenticated envelope is expired"),
            Self::ZeroNonce => write!(f, "authenticated envelope nonce is zero"),
            Self::AlreadyConsumed => write!(f, "authenticated envelope nonce was already consumed"),
            Self::CapacityExceeded => write!(f, "replay registry capacity exceeded"),
            Self::SignatureRejected => write!(f, "authenticated envelope signature rejected"),
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<AuthError> for ReplayError {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::SignatureRejected => Self::SignatureRejected,
            _ => Self::Corrupt,
        }
    }
}

/// Public replay state only: signer identity, key ID, nonce, and expiry.
pub struct PersistentNonceRegistry {
    path: PathBuf,
    entries: RwLock<BTreeMap<ReplayKey, ReplayRecord>>,
}

impl PersistentNonceRegistry {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ReplayError> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            decode(&fs::read(&path).map_err(|_| ReplayError::Io)?)?
        } else {
            BTreeMap::new()
        };
        let registry = Self {
            path,
            entries: RwLock::new(entries),
        };
        if !registry.path.exists() {
            registry.persist(&BTreeMap::new())?;
        }
        Ok(registry)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify the exact envelope and atomically consume its replay nonce.
    pub fn verify_and_consume<V: SignatureVerifier>(
        &self,
        envelope: &AuthenticatedEnvelope,
        verifier: &V,
        now_unix: u64,
    ) -> Result<(), ReplayError> {
        envelope.verify(verifier, now_unix)?;
        self.consume(
            &envelope.signer,
            &envelope.key_id,
            &envelope.context.nonce,
            envelope.context.expires_at_unix,
            now_unix,
        )
    }

    pub fn consume(
        &self,
        signer: &str,
        key_id: &str,
        nonce: &[u8; NONCE_LEN],
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<(), ReplayError> {
        if *nonce == [0; NONCE_LEN] {
            return Err(ReplayError::ZeroNonce);
        }
        if expires_at_unix <= now_unix {
            return Err(ReplayError::Expired);
        }
        if signer.is_empty() || key_id.is_empty() {
            return Err(ReplayError::Corrupt);
        }

        let mut entries = self.entries.write().map_err(|_| ReplayError::Io)?;
        let mut current = entries.clone();
        current.retain(|_, record| record.expires_at_unix > now_unix);
        let key = ReplayKey {
            signer: signer.to_owned(),
            key_id: key_id.to_owned(),
            nonce: *nonce,
        };
        if current.contains_key(&key) {
            return Err(ReplayError::AlreadyConsumed);
        }
        if current.len() >= MAX_ENTRIES {
            return Err(ReplayError::CapacityExceeded);
        }
        current.insert(key, ReplayRecord { expires_at_unix });
        self.persist(&current)?;
        *entries = current;
        Ok(())
    }

    fn persist(&self, entries: &BTreeMap<ReplayKey, ReplayRecord>) -> Result<(), ReplayError> {
        let temporary = self.path.with_extension("tmp");
        let bytes = encode(entries)?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| ReplayError::Io)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| ReplayError::Io)?;
        drop(file);
        fs::rename(&temporary, &self.path).map_err(|_| ReplayError::Io)
    }
}

fn encode(entries: &BTreeMap<ReplayKey, ReplayRecord>) -> Result<Vec<u8>, ReplayError> {
    if entries.len() > MAX_ENTRIES {
        return Err(ReplayError::CapacityExceeded);
    }
    let mut output = Vec::new();
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&VERSION.to_be_bytes());
    output.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (key, record) in entries {
        put_string(&key.signer, &mut output)?;
        put_string(&key.key_id, &mut output)?;
        output.extend_from_slice(&key.nonce);
        output.extend_from_slice(&record.expires_at_unix.to_be_bytes());
    }
    Ok(output)
}

fn decode(bytes: &[u8]) -> Result<BTreeMap<ReplayKey, ReplayRecord>, ReplayError> {
    let mut reader = Reader { bytes, cursor: 0 };
    if reader.take(4)? != MAGIC || reader.u16()? != VERSION {
        return Err(ReplayError::Corrupt);
    }
    let count = reader.u32()? as usize;
    if count > MAX_ENTRIES {
        return Err(ReplayError::Corrupt);
    }
    let mut entries = BTreeMap::new();
    for _ in 0..count {
        let signer = reader.string(256)?;
        let key_id = reader.string(256)?;
        let nonce_slice = reader.take(NONCE_LEN)?;
        let mut nonce = [0; NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);
        let expires_at_unix = reader.u64()?;
        if nonce == [0; NONCE_LEN] || signer.is_empty() || key_id.is_empty() {
            return Err(ReplayError::Corrupt);
        }
        let key = ReplayKey {
            signer,
            key_id,
            nonce,
        };
        if entries
            .insert(key, ReplayRecord { expires_at_unix })
            .is_some()
        {
            return Err(ReplayError::Corrupt);
        }
    }
    if !reader.empty() {
        return Err(ReplayError::Corrupt);
    }
    Ok(entries)
}

fn put_string(value: &str, output: &mut Vec<u8>) -> Result<(), ReplayError> {
    let bytes = value.as_bytes();
    let length = u32::try_from(bytes.len()).map_err(|_| ReplayError::Corrupt)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ReplayError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(ReplayError::Corrupt)?;
        if end > self.bytes.len() {
            return Err(ReplayError::Corrupt);
        }
        let result = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(result)
    }

    fn u16(&mut self) -> Result<u16, ReplayError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, ReplayError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn u64(&mut self) -> Result<u64, ReplayError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn string(&mut self, maximum: usize) -> Result<String, ReplayError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(ReplayError::Corrupt);
        }
        String::from_utf8(self.take(length)?.to_vec()).map_err(|_| ReplayError::Corrupt)
    }

    fn empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authenticated::{AuthenticatedEnvelope, BindingContext};
    use crate::key_registry::{KeyAlgorithm, KeyRegistry, RegisteredKey};
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestVerifier(KeyRegistry);

    impl SignatureVerifier for TestVerifier {
        fn verify(&self, signer: &str, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
            self.0
                .verify_at(signer, key_id, message, signature, 50)
                .is_ok()
        }
    }

    fn path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("bootstrap-wall3t-replay-{label}-{nonce}.bin"))
    }

    fn envelope(key: &SigningKey) -> AuthenticatedEnvelope {
        let unsigned = AuthenticatedEnvelope::from_payload(
            "rust-wallet-core",
            "key-1",
            BindingContext {
                subject: "wallet-1".into(),
                registry_version: 1,
                expires_at_unix: 100,
                nonce: [7; 16],
            },
            7,
            b"BW3C\0\x01\x07payload".to_vec(),
            vec![1],
        )
        .expect("unsigned");
        let signature = key.sign(&unsigned.signed_message()).to_bytes().to_vec();
        AuthenticatedEnvelope::from_payload(
            unsigned.signer,
            unsigned.key_id,
            unsigned.context,
            unsigned.kind,
            unsigned.payload,
            signature,
        )
        .expect("signed")
    }

    #[test]
    fn consume_is_persistent_and_replay_is_rejected() {
        let path = path("roundtrip");
        let registry = PersistentNonceRegistry::open(&path).expect("open");
        registry
            .consume("signer", "key", &[1; 16], 100, 50)
            .expect("consume");
        assert_eq!(
            registry.consume("signer", "key", &[1; 16], 100, 50),
            Err(ReplayError::AlreadyConsumed)
        );
        drop(registry);
        let reopened = PersistentNonceRegistry::open(&path).expect("reopen");
        assert_eq!(
            reopened.consume("signer", "key", &[1; 16], 100, 50),
            Err(ReplayError::AlreadyConsumed)
        );
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn verification_precedes_nonce_consumption() {
        let path = path("verify");
        let signing_key = SigningKey::from_bytes(&[12; 32]);
        let keys = KeyRegistry::new();
        keys.register(RegisteredKey {
            key_id: "key-1".into(),
            signer: "rust-wallet-core".into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: signing_key.verifying_key().to_bytes(),
            not_before_unix: 0,
            expires_at_unix: None,
            revoked: false,
        })
        .expect("key");
        let envelope = envelope(&signing_key);
        let replay = PersistentNonceRegistry::open(&path).expect("open");
        assert!(replay
            .verify_and_consume(&envelope, &TestVerifier(keys), 50)
            .is_ok());
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn corrupt_state_fails_closed() {
        let path = path("corrupt");
        std::fs::write(&path, b"BWNR\0\x01\0\0\0\0\x01").expect("write");
        assert!(matches!(
            PersistentNonceRegistry::open(&path),
            Err(ReplayError::Corrupt)
        ));
        std::fs::remove_file(path).expect("cleanup");
    }
}
