//! Allowlisted Ed25519 key registry for authenticated wallet-core envelopes.
//!
//! The registry stores public verification material only. Key identifiers are explicit
//! in the authenticated envelope so rotations cannot be ambiguous. A key must be
//! registered, algorithm-allowlisted, within its validity window, and not revoked before
//! an Ed25519 signature is accepted.

use std::collections::BTreeMap;
use std::sync::RwLock;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::authenticated::SignatureVerifier;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyAlgorithm {
    Ed25519,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredKey {
    pub key_id: String,
    pub signer: String,
    pub algorithm: KeyAlgorithm,
    pub public_key: [u8; 32],
    pub not_before_unix: u64,
    pub expires_at_unix: Option<u64>,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeyRegistryError {
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
    InvalidPublicKey,
    InvalidSignatureLength,
    InvalidSignature,
    RegistryUnavailable,
}

impl std::fmt::Display for KeyRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKeyId => write!(f, "invalid key identifier"),
            Self::InvalidSigner => write!(f, "invalid signer identifier"),
            Self::InvalidValidityWindow => write!(f, "invalid key validity window"),
            Self::DuplicateKeyId => write!(f, "key identifier already exists"),
            Self::KeyNotFound => write!(f, "verification key not found"),
            Self::SignerMismatch => write!(f, "key signer does not match envelope signer"),
            Self::UnsupportedAlgorithm => write!(f, "signature algorithm is not allowlisted"),
            Self::KeyNotYetValid => write!(f, "verification key is not active yet"),
            Self::KeyExpired => write!(f, "verification key is expired"),
            Self::KeyRevoked => write!(f, "verification key is revoked"),
            Self::InvalidPublicKey => write!(f, "verification key bytes are invalid"),
            Self::InvalidSignatureLength => write!(f, "signature is not an Ed25519 signature"),
            Self::InvalidSignature => write!(f, "Ed25519 signature is invalid"),
            Self::RegistryUnavailable => write!(f, "key registry lock is unavailable"),
        }
    }
}

impl std::error::Error for KeyRegistryError {}

#[derive(Default)]
pub struct KeyRegistry {
    keys: RwLock<BTreeMap<String, RegisteredKey>>,
}

impl KeyRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, key: RegisteredKey) -> Result<(), KeyRegistryError> {
        validate_key_record(&key)?;
        let mut keys = self
            .keys
            .write()
            .map_err(|_| KeyRegistryError::RegistryUnavailable)?;
        if keys.contains_key(&key.key_id) {
            return Err(KeyRegistryError::DuplicateKeyId);
        }
        keys.insert(key.key_id.clone(), key);
        Ok(())
    }

    pub fn revoke(&self, key_id: &str) -> Result<(), KeyRegistryError> {
        let mut keys = self
            .keys
            .write()
            .map_err(|_| KeyRegistryError::RegistryUnavailable)?;
        let key = keys.get_mut(key_id).ok_or(KeyRegistryError::KeyNotFound)?;
        key.revoked = true;
        Ok(())
    }

    pub fn get(&self, key_id: &str) -> Result<RegisteredKey, KeyRegistryError> {
        self.keys
            .read()
            .map_err(|_| KeyRegistryError::RegistryUnavailable)?
            .get(key_id)
            .cloned()
            .ok_or(KeyRegistryError::KeyNotFound)
    }

    pub fn verify_at(
        &self,
        signer: &str,
        key_id: &str,
        message: &[u8],
        signature: &[u8],
        now_unix: u64,
    ) -> Result<(), KeyRegistryError> {
        let key = self.get(key_id)?;
        if key.signer != signer {
            return Err(KeyRegistryError::SignerMismatch);
        }
        if key.revoked {
            return Err(KeyRegistryError::KeyRevoked);
        }
        if now_unix < key.not_before_unix {
            return Err(KeyRegistryError::KeyNotYetValid);
        }
        if key.expires_at_unix.is_some_and(|expiry| now_unix >= expiry) {
            return Err(KeyRegistryError::KeyExpired);
        }
        match key.algorithm {
            KeyAlgorithm::Ed25519 => {
                let verifying_key = VerifyingKey::from_bytes(&key.public_key)
                    .map_err(|_| KeyRegistryError::InvalidPublicKey)?;
                let signature = Signature::from_slice(signature)
                    .map_err(|_| KeyRegistryError::InvalidSignatureLength)?;
                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| KeyRegistryError::InvalidSignature)
            }
        }
    }
}

impl SignatureVerifier for KeyRegistry {
    fn verify(&self, signer: &str, key_id: &str, message: &[u8], signature: &[u8]) -> bool {
        self.verify_at(signer, key_id, message, signature, current_unix())
            .is_ok()
    }
}

fn validate_key_record(key: &RegisteredKey) -> Result<(), KeyRegistryError> {
    if key.key_id.trim().is_empty() || key.key_id.chars().any(char::is_control) {
        return Err(KeyRegistryError::InvalidKeyId);
    }
    if key.signer.trim().is_empty() || key.signer.chars().any(char::is_control) {
        return Err(KeyRegistryError::InvalidSigner);
    }
    if key
        .expires_at_unix
        .is_some_and(|expiry| expiry <= key.not_before_unix)
    {
        return Err(KeyRegistryError::InvalidValidityWindow);
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
    use crate::authenticated::{AuthenticatedEnvelope, BindingContext};
    use crate::domain::{
        AgentWalletId, AutomationPolicy, Budget, CapabilityId, DocumentHash, ExecutionMode,
        PolicyId, PolicyScope, RetryPolicy, UserWalletId,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::collections::BTreeSet;

    fn policy() -> AutomationPolicy {
        let mut chains = BTreeSet::new();
        chains.insert(1);
        AutomationPolicy {
            id: PolicyId::new("policy-1").expect("id"),
            owner: UserWalletId::new("user-1").expect("id"),
            agent: AgentWalletId::new("agent-1").expect("id"),
            scope: PolicyScope {
                chains,
                venues: BTreeSet::new(),
                contracts: BTreeSet::new(),
                assets: BTreeSet::new(),
            },
            budget: Budget {
                max_value: 100,
                max_gas: 20,
                max_turnover: 1_000,
            },
            retry: RetryPolicy {
                max_attempts: 3,
                backoff_secs: 2,
            },
            mode: ExecutionMode::AutonomousBounded,
            document: DocumentHash::new("doc-1").expect("id"),
            capability: CapabilityId::new("cap-1").expect("id"),
        }
    }

    fn key_record(signing_key: &SigningKey) -> RegisteredKey {
        RegisteredKey {
            key_id: "key-1".into(),
            signer: "rust-wallet-core".into(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key: signing_key.verifying_key().to_bytes(),
            not_before_unix: 0,
            expires_at_unix: None,
            revoked: false,
        }
    }

    fn envelope(signing_key: &SigningKey) -> AuthenticatedEnvelope {
        let unsigned = AuthenticatedEnvelope::from_canonical(
            "rust-wallet-core",
            "key-1",
            BindingContext {
                subject: "wallet-core-test".into(),
                registry_version: 7,
                expires_at_unix: 100,
                nonce: [1; 16],
            },
            &policy(),
            vec![1],
        )
        .expect("unsigned envelope");
        let signature = signing_key
            .sign(&unsigned.signed_message())
            .to_bytes()
            .to_vec();
        AuthenticatedEnvelope::from_canonical(
            "rust-wallet-core",
            "key-1",
            unsigned.context,
            &policy(),
            signature,
        )
        .expect("signed envelope")
    }

    #[test]
    fn registered_ed25519_key_verifies_exact_envelope() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let registry = KeyRegistry::new();
        registry
            .register(key_record(&signing_key))
            .expect("register");
        let envelope = envelope(&signing_key);
        assert!(envelope.verify(&registry, 99).is_ok());
    }

    #[test]
    fn wrong_key_id_and_signer_are_rejected() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let registry = KeyRegistry::new();
        registry
            .register(key_record(&signing_key))
            .expect("register");
        let envelope = envelope(&signing_key);
        assert_eq!(
            registry.verify_at(
                &envelope.signer,
                "missing",
                &envelope.signed_message(),
                &envelope.signature,
                99,
            ),
            Err(KeyRegistryError::KeyNotFound)
        );
        assert_eq!(
            registry.verify_at(
                "other-signer",
                &envelope.key_id,
                &envelope.signed_message(),
                &envelope.signature,
                99,
            ),
            Err(KeyRegistryError::SignerMismatch)
        );
    }

    #[test]
    fn revocation_fails_closed() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let registry = KeyRegistry::new();
        registry
            .register(key_record(&signing_key))
            .expect("register");
        let envelope = envelope(&signing_key);
        registry.revoke("key-1").expect("revoke");
        assert_eq!(
            registry.verify_at(
                &envelope.signer,
                &envelope.key_id,
                &envelope.signed_message(),
                &envelope.signature,
                99,
            ),
            Err(KeyRegistryError::KeyRevoked)
        );
    }

    #[test]
    fn key_validity_window_fails_closed() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let registry = KeyRegistry::new();
        let mut key = key_record(&signing_key);
        key.not_before_unix = 100;
        key.expires_at_unix = Some(200);
        registry.register(key).expect("register");
        let envelope = envelope(&signing_key);
        let message = envelope.signed_message();
        assert_eq!(
            registry.verify_at(
                &envelope.signer,
                &envelope.key_id,
                &message,
                &envelope.signature,
                99,
            ),
            Err(KeyRegistryError::KeyNotYetValid)
        );
        assert_eq!(
            registry.verify_at(
                &envelope.signer,
                &envelope.key_id,
                &message,
                &envelope.signature,
                200,
            ),
            Err(KeyRegistryError::KeyExpired)
        );
    }

    #[test]
    fn duplicate_key_ids_are_rejected() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let registry = KeyRegistry::new();
        registry
            .register(key_record(&signing_key))
            .expect("register");
        assert_eq!(
            registry.register(key_record(&signing_key)),
            Err(KeyRegistryError::DuplicateKeyId)
        );
    }
}
