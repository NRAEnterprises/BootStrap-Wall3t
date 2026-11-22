//! Authenticated decoding and hash binding for canonical wallet-core records.
//!
//! The envelope binds the exact canonical payload, record kind, signer, subject,
//! registry version, expiry, domain, and nonce into a SHA-256 digest. Signature
//! verification is intentionally injected through `SignatureVerifier`; this crate
//! does not claim a production signature implementation without a reviewed crypto
//! backend.

use crate::wire::{CanonicalWire, WIRE_VERSION};

pub const AUTH_VERSION: u16 = 1;
const AUTH_MAGIC: &[u8; 4] = b"BWAU";
const AUTH_DOMAIN: &str = "BOOTSTRAP-WALL3T/AUTHENTICATED-WIRE/V1";
const MAX_SIGNER_LEN: usize = 256;
const MAX_KEY_ID_LEN: usize = 256;
const MAX_SUBJECT_LEN: usize = 512;
const MAX_PAYLOAD_LEN: usize = 8 * 1024 * 1024;
const MAX_SIGNATURE_LEN: usize = 16 * 1024;
const NONCE_LEN: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BindingContext {
    pub subject: String,
    pub registry_version: u64,
    pub expires_at_unix: u64,
    pub nonce: [u8; NONCE_LEN],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedEnvelope {
    pub kind: u8,
    pub signer: String,
    pub key_id: String,
    pub context: BindingContext,
    pub payload: Vec<u8>,
    pub payload_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Digest(pub [u8; 32]);

#[derive(Debug, Eq, PartialEq)]
pub enum AuthError {
    Truncated,
    InvalidMagic,
    UnsupportedVersion(u16),
    InvalidKind,
    InvalidUtf8,
    InvalidField(&'static str),
    LengthOverflow,
    TrailingBytes,
    PayloadHeaderMismatch,
    PayloadHashMismatch,
    SignatureMissing,
    SignatureRejected,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated => write!(f, "authenticated envelope is truncated"),
            Self::InvalidMagic => write!(f, "authenticated envelope has invalid magic"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported authenticated envelope version {version}")
            }
            Self::InvalidKind => write!(f, "authenticated envelope has an invalid record kind"),
            Self::InvalidUtf8 => write!(f, "authenticated envelope contains invalid UTF-8"),
            Self::InvalidField(field) => write!(f, "authenticated envelope has invalid {field}"),
            Self::LengthOverflow => write!(f, "authenticated envelope length exceeds the limit"),
            Self::TrailingBytes => write!(f, "authenticated envelope has trailing bytes"),
            Self::PayloadHeaderMismatch => write!(f, "payload header does not match envelope kind"),
            Self::PayloadHashMismatch => write!(f, "payload hash does not match canonical payload"),
            Self::SignatureMissing => write!(f, "authenticated envelope has no signature"),
            Self::SignatureRejected => write!(f, "signature verifier rejected the envelope"),
        }
    }
}

impl std::error::Error for AuthError {}

pub trait SignatureVerifier {
    fn verify(&self, signer: &str, key_id: &str, message: &[u8], signature: &[u8]) -> bool;
}

impl AuthenticatedEnvelope {
    pub fn from_canonical<T: CanonicalWire>(
        signer: impl Into<String>,
        key_id: impl Into<String>,
        context: BindingContext,
        payload: &T,
        signature: Vec<u8>,
    ) -> Result<Self, AuthError> {
        let payload = payload.canonical_bytes();
        Self::from_payload(signer, key_id, context, T::KIND, payload, signature)
    }

    pub fn from_payload(
        signer: impl Into<String>,
        key_id: impl Into<String>,
        context: BindingContext,
        kind: u8,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, AuthError> {
        let signer = signer.into();
        let key_id = key_id.into();
        validate_signer(&signer)?;
        validate_key_id(&key_id)?;
        validate_context(&context)?;
        validate_payload_header(kind, &payload)?;
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(AuthError::LengthOverflow);
        }
        if signature.is_empty() {
            return Err(AuthError::SignatureMissing);
        }
        if signature.len() > MAX_SIGNATURE_LEN {
            return Err(AuthError::LengthOverflow);
        }
        let payload_hash = payload_digest(kind, &payload).0;
        Ok(Self {
            kind,
            signer,
            key_id,
            context,
            payload,
            payload_hash,
            signature,
        })
    }

    pub fn signed_message(&self) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(AUTH_DOMAIN.as_bytes());
        message.push(0);
        put_u16(AUTH_VERSION, &mut message);
        message.push(self.kind);
        put_str(&self.signer, &mut message);
        put_str(&self.key_id, &mut message);
        put_str(&self.context.subject, &mut message);
        put_u64(self.context.registry_version, &mut message);
        put_u64(self.context.expires_at_unix, &mut message);
        message.extend_from_slice(&self.context.nonce);
        message.extend_from_slice(&self.payload_hash);
        message
    }

    pub fn verify<V: SignatureVerifier>(
        &self,
        verifier: &V,
        now_unix: u64,
    ) -> Result<&[u8], AuthError> {
        validate_signer(&self.signer)?;
        validate_key_id(&self.key_id)?;
        validate_context(&self.context)?;
        validate_payload_header(self.kind, &self.payload)?;
        if self.context.expires_at_unix <= now_unix {
            return Err(AuthError::InvalidField("expiry"));
        }
        if payload_digest(self.kind, &self.payload).0 != self.payload_hash {
            return Err(AuthError::PayloadHashMismatch);
        }
        if self.signature.is_empty() {
            return Err(AuthError::SignatureMissing);
        }
        if !verifier.verify(
            &self.signer,
            &self.key_id,
            &self.signed_message(),
            &self.signature,
        ) {
            return Err(AuthError::SignatureRejected);
        }
        Ok(&self.payload)
    }

    pub fn encode(&self) -> Result<Vec<u8>, AuthError> {
        validate_signer(&self.signer)?;
        validate_key_id(&self.key_id)?;
        validate_context(&self.context)?;
        validate_payload_header(self.kind, &self.payload)?;
        if self.payload.len() > MAX_PAYLOAD_LEN || self.signature.len() > MAX_SIGNATURE_LEN {
            return Err(AuthError::LengthOverflow);
        }
        if self.signature.is_empty() {
            return Err(AuthError::SignatureMissing);
        }
        if payload_digest(self.kind, &self.payload).0 != self.payload_hash {
            return Err(AuthError::PayloadHashMismatch);
        }
        let mut out = Vec::new();
        out.extend_from_slice(AUTH_MAGIC);
        put_u16(AUTH_VERSION, &mut out);
        out.push(self.kind);
        put_str(&self.signer, &mut out);
        put_str(&self.key_id, &mut out);
        put_str(&self.context.subject, &mut out);
        put_u64(self.context.registry_version, &mut out);
        put_u64(self.context.expires_at_unix, &mut out);
        out.extend_from_slice(&self.context.nonce);
        put_bytes(&self.payload, &mut out);
        out.extend_from_slice(&self.payload_hash);
        put_bytes(&self.signature, &mut out);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AuthError> {
        let mut reader = Reader::new(bytes);
        if reader.take(4)? != AUTH_MAGIC {
            return Err(AuthError::InvalidMagic);
        }
        let version = reader.u16()?;
        if version != AUTH_VERSION {
            return Err(AuthError::UnsupportedVersion(version));
        }
        let kind = reader.u8()?;
        if !(1..=6).contains(&kind) {
            return Err(AuthError::InvalidKind);
        }
        let signer = reader.string(MAX_SIGNER_LEN)?;
        let key_id = reader.string(MAX_KEY_ID_LEN)?;
        let subject = reader.string(MAX_SUBJECT_LEN)?;
        let registry_version = reader.u64()?;
        let expires_at_unix = reader.u64()?;
        let nonce_slice = reader.take(NONCE_LEN)?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(nonce_slice);
        let payload = reader.bytes(MAX_PAYLOAD_LEN)?;
        let payload_hash_slice = reader.take(32)?;
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(payload_hash_slice);
        let signature = reader.bytes(MAX_SIGNATURE_LEN)?;
        if !reader.is_empty() {
            return Err(AuthError::TrailingBytes);
        }
        let context = BindingContext {
            subject,
            registry_version,
            expires_at_unix,
            nonce,
        };
        validate_signer(&signer)?;
        validate_key_id(&key_id)?;
        validate_context(&context)?;
        validate_payload_header(kind, &payload)?;
        if signature.is_empty() {
            return Err(AuthError::SignatureMissing);
        }
        if payload_digest(kind, &payload).0 != payload_hash {
            return Err(AuthError::PayloadHashMismatch);
        }
        Ok(Self {
            kind,
            signer,
            key_id,
            context,
            payload,
            payload_hash,
            signature,
        })
    }
}

pub fn payload_digest(kind: u8, payload: &[u8]) -> Sha256Digest {
    let mut input = Vec::with_capacity(32 + payload.len());
    input.extend_from_slice(AUTH_DOMAIN.as_bytes());
    input.push(0);
    put_u16(WIRE_VERSION, &mut input);
    input.push(kind);
    put_bytes(payload, &mut input);
    Sha256Digest(sha256(&input))
}

fn validate_signer(signer: &str) -> Result<(), AuthError> {
    if signer.is_empty() || signer.len() > MAX_SIGNER_LEN || signer.chars().any(char::is_control) {
        return Err(AuthError::InvalidField("signer"));
    }
    Ok(())
}

fn validate_key_id(key_id: &str) -> Result<(), AuthError> {
    if key_id.is_empty() || key_id.len() > MAX_KEY_ID_LEN || key_id.chars().any(char::is_control) {
        return Err(AuthError::InvalidField("key identifier"));
    }
    Ok(())
}

fn validate_context(context: &BindingContext) -> Result<(), AuthError> {
    if context.subject.is_empty()
        || context.subject.len() > MAX_SUBJECT_LEN
        || context.subject.chars().any(char::is_control)
    {
        return Err(AuthError::InvalidField("subject"));
    }
    if context.registry_version == 0 {
        return Err(AuthError::InvalidField("registry version"));
    }
    if context.expires_at_unix == 0 {
        return Err(AuthError::InvalidField("expiry"));
    }
    if context.nonce == [0u8; NONCE_LEN] {
        return Err(AuthError::InvalidField("nonce"));
    }
    Ok(())
}

fn validate_payload_header(kind: u8, payload: &[u8]) -> Result<(), AuthError> {
    if !(1..=6).contains(&kind) {
        return Err(AuthError::InvalidKind);
    }
    if payload.len() < 7 || &payload[..4] != b"BW3C" {
        return Err(AuthError::PayloadHeaderMismatch);
    }
    let version = u16::from_be_bytes([payload[4], payload[5]]);
    if version != WIRE_VERSION || payload[6] != kind {
        return Err(AuthError::PayloadHeaderMismatch);
    }
    Ok(())
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(value: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn put_str(value: &str, out: &mut Vec<u8>) {
    put_bytes(value.as_bytes(), out);
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], AuthError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(AuthError::LengthOverflow)?;
        if end > self.bytes.len() {
            return Err(AuthError::Truncated);
        }
        let value = &self.bytes[self.cursor..end];
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, AuthError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, AuthError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u64(&mut self) -> Result<u64, AuthError> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, AuthError> {
        let length = self.u32()? as usize;
        if length > max {
            return Err(AuthError::LengthOverflow);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn u32(&mut self) -> Result<u32, AuthError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self, max: usize) -> Result<String, AuthError> {
        let bytes = self.bytes(max)?;
        String::from_utf8(bytes).map_err(|_| AuthError::InvalidUtf8)
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.bytes.len()
    }
}

// Compact dependency-free SHA-256 implementation for hash binding. Signature
// verification remains outside this function and must use a reviewed backend.
fn sha256(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let padded_len = (input.len() + 9).div_ceil(64) * 64;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(input);
    padded.push(0x80);
    padded.resize(padded_len - 8, 0);
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk_start in (0..padded.len()).step_by(64) {
        let chunk = &padded[chunk_start..chunk_start + 64];
        let mut w = [0u32; 64];
        for (index, word) in w.iter_mut().enumerate().take(16) {
            let offset = index * 4;
            *word = u32::from_be_bytes([
                chunk[offset],
                chunk[offset + 1],
                chunk[offset + 2],
                chunk[offset + 3],
            ]);
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }
        let mut working = h;
        for index in 0..64 {
            let s1 = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let ch = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp1 = working[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let maj =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp2 = s0.wrapping_add(maj);
            working = [
                temp1.wrapping_add(temp2),
                working[0],
                working[1],
                working[2],
                working[3].wrapping_add(temp1),
                working[4],
                working[5],
                working[6],
            ];
        }
        for index in 0..8 {
            h[index] = h[index].wrapping_add(working[index]);
        }
    }
    let mut output = [0u8; 32];
    for (index, word) in h.iter().enumerate() {
        output[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AutomationPolicy, CapabilityId, DocumentHash, PolicyId, UserWalletId};
    use std::collections::BTreeSet;

    struct AcceptingVerifier;
    impl SignatureVerifier for AcceptingVerifier {
        fn verify(&self, _signer: &str, _key_id: &str, _message: &[u8], signature: &[u8]) -> bool {
            signature == b"test-signature"
        }
    }

    fn policy() -> AutomationPolicy {
        let mut chains = BTreeSet::new();
        chains.insert(1);
        AutomationPolicy {
            id: PolicyId::new("policy-1").expect("id"),
            owner: UserWalletId::new("user-1").expect("id"),
            agent: crate::domain::AgentWalletId::new("agent-1").expect("id"),
            scope: crate::domain::PolicyScope {
                chains,
                venues: BTreeSet::new(),
                contracts: BTreeSet::new(),
                assets: BTreeSet::new(),
            },
            budget: crate::domain::Budget {
                max_value: 100,
                max_gas: 20,
                max_turnover: 1_000,
            },
            retry: crate::domain::RetryPolicy {
                max_attempts: 3,
                backoff_secs: 2,
            },
            mode: crate::domain::ExecutionMode::AutonomousBounded,
            document: DocumentHash::new("doc-1").expect("id"),
            capability: CapabilityId::new("cap-1").expect("id"),
        }
    }

    fn context() -> BindingContext {
        BindingContext {
            subject: "wallet-core-test".into(),
            registry_version: 7,
            expires_at_unix: 100,
            nonce: [1; NONCE_LEN],
        }
    }

    #[test]
    fn authenticated_envelope_round_trips_and_verifies() {
        let envelope = AuthenticatedEnvelope::from_canonical(
            "rust-wallet-core",
            "key-1",
            context(),
            &policy(),
            b"test-signature".to_vec(),
        )
        .expect("envelope");
        let encoded = envelope.encode().expect("encode");
        let decoded = AuthenticatedEnvelope::decode(&encoded).expect("decode");
        assert_eq!(decoded, envelope);
        assert!(decoded.verify(&AcceptingVerifier, 99).is_ok());
    }

    #[test]
    fn tampered_payload_is_rejected_before_signature_verification() {
        let envelope = AuthenticatedEnvelope::from_canonical(
            "rust-wallet-core",
            "key-1",
            context(),
            &policy(),
            b"test-signature".to_vec(),
        )
        .expect("envelope");
        let mut encoded = envelope.encode().expect("encode");
        let payload_marker = encoded
            .windows(4)
            .position(|window| window == b"BW3C")
            .expect("payload marker");
        encoded[payload_marker + 7] ^= 1;
        assert_eq!(
            AuthenticatedEnvelope::decode(&encoded),
            Err(AuthError::PayloadHashMismatch)
        );
    }

    #[test]
    fn decoder_rejects_trailing_bytes_and_expired_context() {
        let envelope = AuthenticatedEnvelope::from_canonical(
            "rust-wallet-core",
            "key-1",
            context(),
            &policy(),
            b"test-signature".to_vec(),
        )
        .expect("envelope");
        let mut encoded = envelope.encode().expect("encode");
        encoded.push(0);
        assert_eq!(
            AuthenticatedEnvelope::decode(&encoded),
            Err(AuthError::TrailingBytes)
        );
        assert_eq!(
            envelope.verify(&AcceptingVerifier, 100),
            Err(AuthError::InvalidField("expiry"))
        );
    }

    #[test]
    fn sha256_matches_standard_empty_vector() {
        assert_eq!(
            sha256(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }
}
