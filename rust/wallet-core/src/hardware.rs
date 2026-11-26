//! Hardware-backed custody boundary for wallet-core.
//!
//! Wallet-core stores only opaque hardware handles and public verification metadata.
//! Private keys, PINs, seed material, and device sessions remain inside an external
//! provider such as a hardware wallet, HSM, secure enclave, or remote signing service.

use std::collections::BTreeMap;
use std::sync::RwLock;

use ed25519_dalek::VerifyingKey;

use crate::authenticated::SignatureVerifier;
use crate::key_registry::KeyAlgorithm;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct HardwareKeyHandle(String);

impl HardwareKeyHandle {
    pub fn new(value: impl Into<String>) -> Result<Self, HardwareCustodyError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(HardwareCustodyError::InvalidHandle);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HardwareKeyRecord {
    pub key_id: String,
    pub signer: String,
    pub handle: HardwareKeyHandle,
    pub algorithm: KeyAlgorithm,
    pub public_key: [u8; 32],
    pub not_before_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub revoked: bool,
}

pub trait HardwareCustodyProvider: Send + Sync {
    fn sign(
        &self,
        handle: &HardwareKeyHandle,
        algorithm: KeyAlgorithm,
        message: &[u8],
    ) -> Result<Vec<u8>, HardwareCustodyError>;

    fn verify(
        &self,
        handle: &HardwareKeyHandle,
        algorithm: KeyAlgorithm,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), HardwareCustodyError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HardwareCustodyError {
    InvalidHandle,
    InvalidKeyId,
    InvalidSigner,
    InvalidValidityWindow,
    DuplicateKeyId,
    KeyNotFound,
    SignerMismatch,
    UnsupportedAlgorithm,
    KeyNotYetValid,
    KeyExpired,
    KeyRevoked,
    ProviderUnavailable,
    ProviderRejected,
    InvalidPublicKey,
    InvalidSignature,
}

impl std::fmt::Display for HardwareCustodyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "hardware custody error: {self:?}")
    }
}

impl std::error::Error for HardwareCustodyError {}

pub struct HardwareKeyRegistry<P> {
    provider: P,
    keys: RwLock<BTreeMap<String, HardwareKeyRecord>>,
}

impl<P: HardwareCustodyProvider> HardwareKeyRegistry<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            keys: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn register(&self, key: HardwareKeyRecord) -> Result<(), HardwareCustodyError> {
        validate_record(&key)?;
        let mut keys = self
            .keys
            .write()
            .map_err(|_| HardwareCustodyError::ProviderUnavailable)?;
        if keys.contains_key(&key.key_id) {
            return Err(HardwareCustodyError::DuplicateKeyId);
        }
        keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    pub fn revoke(&self, key_id: &str) -> Result<(), HardwareCustodyError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| HardwareCustodyError::ProviderUnavailable)?;
        let key = keys
            .get_mut(key_id)
            .ok_or(HardwareCustodyError::KeyNotFound)?;
        key.revoked = true;
        Ok(())
    }

    pub fn sign_at(
        &self,
        signer: &str,
        key_id: &str,
        message: &[u8],
        now_unix: u64,
    ) -> Result<Vec<u8>, HardwareCustodyError> {
        let key = self.key(key_id)?;
        validate_active(&key, signer, now_unix)?;
        self.provider.sign(&key.handle, key.algorithm, message)
    }

    pub fn verify_at(
        &self,
        signer: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        now_unix: u64,
    ) -> Result<(), HardwareCustodyError> {
        let key = self.key(key_id)?;
        validate_active(&key, signer, now_unix)?;
        self.provider.verify(
            &key.handle,
            key.algorithm,
            &key.public_key,
            message,
            signature,
        )
    }

    fn key(&self, key_id: &str) -> Result<HardwareKeyRecord, HardwareCustodyError> {
        self.keys
            .read()
            .map_err(|_| HardwareCustodyError::ProviderUnavailable)?
            .get(key_id)
            .cloned()
            .ok_or(HardwareCustodyError::KeyNotFound)
    }
}

impl<P: HardwareCustodyProvider> SignatureVerifier for HardwareKeyRegistry<P> {
    fn verify(&self, signer: &str, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        self.verify_at(signer, key_id, message, signature, current_unix())
            .is_ok()
    }
}

fn validate_record(key: &HardwareKeyRecord) -> Result<(), HardwareCustodyError> {
    if key.key_id.trim().is_empty() || key.key_id.chars().any(char::is_control) {
        return Err(HardwareCustodyError::InvalidKeyId);
    }
    if key.signer.trim().is_empty() || key.signer.chars().any(char::is_control) {
        return Err(HardwareCustodyError::InvalidSigner);
    }
    if key
        .expires_at_unix
        .is_some_and(|expiry| expiry <= key.not_before_unix)
    {
        return Err(HardwareCustodyError::InvalidValidityWindow);
    }
    match key.algorithm {
        KeyAlgorithm::Ed25519 => {
            VerifyingKey::from_bytes(&key.public_key)
                .map_err(|_| HardwareCustodyError::InvalidPublicKey)?;
        }
    }
    Ok(())
}

fn validate_active(
    key: &HardwareKeyRecord,
    signer: &str,
    now_unix: u64,
) -> Result<(), HardwareCustodyError> {
    if key.signer != signer {
        return Err(HardwareCustodyError::SignerMismatch);
    }
    if key.revoked {
        return Err(HardwareCustodyError::KeyRevoked);
    }
    if now_unix < key.not_before_unix {
        return Err(HardwareCustodyError::KeyNotYetValid);
    }
    if key.expires_at_unix.is_some_and(|expiry| now_unix >= expiry) {
        return Err(HardwareCustodyError::KeyExpired);
    }
    Ok(())
}

fn current_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

    struct TestHardware {
        signing_key: SigningKey,
    }

    impl HardwareCustodyProvider for TestHardware {
        fn sign(
            &self,
            handle: &HardwareKeyHandle,
            algorithm: KeyAlgorithm,
            message: &[u8],
        ) -> Result<Vec<u8>, HardwareCustodyError> {
            if handle.as_str() != "hsm://slot-7" || algorithm != KeyAlgorithm::Ed25519 {
                return Err(HardwareCustodyError::ProviderRejected);
            }
            Ok(self.signing_key.sign(message).to_bytes().to_vec())
        }

        fn verify(
            &self,
            handle: &HardwareKeyHandle,
            algorithm: KeyAlgorithm,
            public_key: &[u8; 32],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), HardwareCustodyError> {
            if handle.as_str() != "hsm://slot-7" || algorithm != KeyAlgorithm::Ed25519 {
                return Err(HardwareCustodyError::ProviderRejected);
            }
            let key = VerifyingKey::from_bytes(public_key)
                .map_err(|_| HardwareCustodyError::InvalidPublicKey)?;
            let signature = Signature::from_slice(signature)
                .map_err(|_| HardwareCustodyError::InvalidSignature)?;
            key.verify(message, &signature)
                .map_err(|_| HardwareCustodyError::InvalidSignature)
        }
    }

    fn record(key: &SigningKey) -> HardwareKeyRecord {
        HardwareKeyRecord {
            key_id: "hardware-key-1".into(),
            signer: "hardware-signer".into(),
            handle: HardwareKeyHandle::new("hsm://slot-7").expect("handle"),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: key.verifying_key().to_bytes(),
            not_before_unix: 1,
            expires_at_unix: Some(1_000),
            revoked: false,
        }
    }

    #[test]
    fn hardware_provider_signs_without_exposing_private_material() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let registry = HardwareKeyRegistry::new(TestHardware { signing_key });
        registry
            .register(record(&SigningKey::from_bytes(&[9; 32])))
            .expect("register");
        let signature = registry
            .sign_at("hardware-signer", "hardware-key-1", b"message", 99)
            .expect("sign");
        registry
            .verify_at(
                "hardware-signer",
                "hardware-key-1",
                b"message",
                &signature,
                99,
            )
            .expect("verify");
    }

    #[test]
    fn hardware_revocation_blocks_sign_and_verify() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let registry = HardwareKeyRegistry::new(TestHardware { signing_key });
        registry
            .register(record(&SigningKey::from_bytes(&[9; 32])))
            .expect("register");
        registry.revoke("hardware-key-1").expect("revoke");
        assert_eq!(
            registry.sign_at("hardware-signer", "hardware-key-1", b"message", 99),
            Err(HardwareCustodyError::KeyRevoked)
        );
    }
}
