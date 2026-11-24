//! Typed EVM transaction intents and their BW3C kind-7 canonical payload.

use std::fmt;

use crate::domain::{AgentWalletId, CapabilityId, DocumentHash, PolicyId};
use crate::wire::{encode_entity, CanonicalWire};
use crate::{ChainId, EntityRef};

pub const EVM_TRANSACTION_INTENT_KIND: u8 = 7;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct IntentId(String);

impl IntentId {
    pub fn new(value: impl Into<String>) -> Result<Self, IntentError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(IntentError::InvalidField("intent id"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvmAddress([u8; 20]);

impl EvmAddress {
    pub fn new(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct U256([u8; 32]);

impl U256 {
    pub const ZERO: Self = Self([0; 32]);

    pub fn from_u128(value: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&value.to_be_bytes());
        Self(bytes)
    }

    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrincipalBinding {
    User,
    Agent { agent_id: AgentWalletId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmOperation {
    Deploy,
    ContractCall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmContractLanguage {
    Solidity,
    Vyper,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvmFeePolicy {
    Legacy {
        gas_price: U256,
    },
    Eip1559 {
        max_fee_per_gas: U256,
        max_priority_fee_per_gas: U256,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmDeploymentMetadata {
    pub language: EvmContractLanguage,
    pub contract_name: String,
    pub init_code_hash: [u8; 32],
    pub expected_runtime_code_hash: Option<[u8; 32]>,
    pub source_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvmTransactionIntent {
    pub intent_id: IntentId,
    pub wallet_id: String,
    pub principal: PrincipalBinding,
    pub operation: EvmOperation,
    pub chain_id: ChainId,
    pub from: EvmAddress,
    pub to: Option<EvmAddress>,
    pub nonce: u64,
    pub value: U256,
    pub gas_limit: u64,
    pub fee: EvmFeePolicy,
    pub calldata: Vec<u8>,
    pub deployment: Option<EvmDeploymentMetadata>,
    pub policy_id: PolicyId,
    pub capability_id: CapabilityId,
    pub document_hash: DocumentHash,
    pub footprint: Vec<EntityRef>,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
}

/// An EVM transaction intent that has passed all structural validation.
///
/// The wrapper owns the intent and exposes it only immutably, so callers cannot
/// mutate fields after validation and accidentally reuse a stale validation
/// result. Construct it with [`EvmTransactionIntent::into_validated`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedEvmTransactionIntent(EvmTransactionIntent);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IntentError {
    InvalidField(&'static str),
    InvalidShape(&'static str),
    DuplicateFootprint,
}

impl fmt::Display for IntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidField(field) => write!(f, "invalid EVM intent field: {field}"),
            Self::InvalidShape(shape) => write!(f, "invalid EVM intent shape: {shape}"),
            Self::DuplicateFootprint => {
                write!(f, "EVM intent footprint must be sorted and deduplicated")
            }
        }
    }
}

impl std::error::Error for IntentError {}

impl EvmTransactionIntent {
    /// Validate once and consume the mutable intent into an immutable wrapper.
    pub fn into_validated(self) -> Result<ValidatedEvmTransactionIntent, IntentError> {
        self.validate()?;
        Ok(ValidatedEvmTransactionIntent(self))
    }

    pub fn validate(&self) -> Result<(), IntentError> {
        if self.wallet_id.trim().is_empty() || self.wallet_id.chars().any(char::is_control) {
            return Err(IntentError::InvalidField("wallet id"));
        }
        if self.chain_id == 0 {
            return Err(IntentError::InvalidField("chain id"));
        }
        if self.expires_at_unix <= self.not_before_unix {
            return Err(IntentError::InvalidField("validity window"));
        }
        if self.policy_id.as_str().trim().is_empty()
            || self.capability_id.as_str().trim().is_empty()
            || self.document_hash.as_str().trim().is_empty()
        {
            return Err(IntentError::InvalidField("policy binding"));
        }
        let mut canonical = self.footprint.clone();
        canonical.sort();
        canonical.dedup();
        if canonical != self.footprint {
            return Err(IntentError::DuplicateFootprint);
        }
        if self.footprint.is_empty() {
            return Err(IntentError::InvalidField("footprint"));
        }
        match (&self.operation, &self.to, &self.deployment) {
            (EvmOperation::Deploy, None, Some(metadata)) => {
                if metadata.contract_name.trim().is_empty()
                    || metadata.contract_name.chars().any(char::is_control)
                {
                    return Err(IntentError::InvalidField("contract name"));
                }
            }
            (EvmOperation::Deploy, None, None) => {
                return Err(IntentError::InvalidShape("deployment metadata is required"))
            }
            (EvmOperation::ContractCall, Some(_), None) => {}
            (EvmOperation::Deploy, Some(_), _) => {
                return Err(IntentError::InvalidShape(
                    "deployment target must be absent",
                ))
            }
            (EvmOperation::ContractCall, None, _) => {
                return Err(IntentError::InvalidShape("call target is required"))
            }
            (_, _, Some(_)) => {
                return Err(IntentError::InvalidShape(
                    "deployment metadata only applies to deploy",
                ))
            }
        }
        if let PrincipalBinding::Agent { agent_id } = &self.principal {
            if agent_id.as_str().trim().is_empty() {
                return Err(IntentError::InvalidField("agent id"));
            }
        }
        Ok(())
    }

    pub fn try_canonical_bytes(&self) -> Result<Vec<u8>, IntentError> {
        self.validate()?;
        Ok(self.canonical_bytes_unchecked())
    }

    fn canonical_bytes_unchecked(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"BW3C");
        put_u16(1, &mut out);
        out.push(EVM_TRANSACTION_INTENT_KIND);
        put_str(self.intent_id.as_str(), &mut out);
        put_str(&self.wallet_id, &mut out);
        match &self.principal {
            PrincipalBinding::User => out.push(1),
            PrincipalBinding::Agent { agent_id } => {
                out.push(2);
                put_str(agent_id.as_str(), &mut out);
            }
        }
        out.push(match self.operation {
            EvmOperation::Deploy => 1,
            EvmOperation::ContractCall => 2,
        });
        put_u64(self.chain_id, &mut out);
        out.extend_from_slice(self.from.as_bytes());
        match self.to {
            Some(address) => {
                out.push(1);
                out.extend_from_slice(address.as_bytes());
            }
            None => out.push(0),
        }
        put_u64(self.nonce, &mut out);
        out.extend_from_slice(self.value.as_bytes());
        put_u64(self.gas_limit, &mut out);
        match self.fee {
            EvmFeePolicy::Legacy { gas_price } => {
                out.push(1);
                out.extend_from_slice(gas_price.as_bytes());
            }
            EvmFeePolicy::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
            } => {
                out.push(2);
                out.extend_from_slice(max_fee_per_gas.as_bytes());
                out.extend_from_slice(max_priority_fee_per_gas.as_bytes());
            }
        }
        put_bytes(&self.calldata, &mut out);
        match &self.deployment {
            Some(metadata) => {
                out.push(1);
                out.push(match metadata.language {
                    EvmContractLanguage::Solidity => 1,
                    EvmContractLanguage::Vyper => 2,
                });
                put_str(&metadata.contract_name, &mut out);
                out.extend_from_slice(&metadata.init_code_hash);
                match metadata.expected_runtime_code_hash {
                    Some(hash) => {
                        out.push(1);
                        out.extend_from_slice(&hash);
                    }
                    None => out.push(0),
                }
                out.extend_from_slice(&metadata.source_sha256);
            }
            None => out.push(0),
        }
        put_str(self.policy_id.as_str(), &mut out);
        put_str(self.capability_id.as_str(), &mut out);
        put_str(self.document_hash.as_str(), &mut out);
        put_u32(self.footprint.len() as u32, &mut out);
        for entity in &self.footprint {
            encode_entity(entity, &mut out);
        }
        put_u64(self.not_before_unix, &mut out);
        put_u64(self.expires_at_unix, &mut out);
        out
    }

    pub fn intent_digest(&self) -> Result<[u8; 32], IntentError> {
        let bytes = self.try_canonical_bytes()?;
        Ok(crate::authenticated::sha256(&bytes))
    }
}

impl ValidatedEvmTransactionIntent {
    /// Borrow the validated intent without exposing mutable access.
    pub fn as_intent(&self) -> &EvmTransactionIntent {
        &self.0
    }

    /// Recover the owned intent when leaving the validated-only path.
    pub fn into_inner(self) -> EvmTransactionIntent {
        self.0
    }

    /// Encode without repeating validation, footprint cloning, sorting, or deduplication.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.0.canonical_bytes_unchecked()
    }

    /// Hash the exact canonical bytes without repeating validation.
    pub fn intent_digest(&self) -> [u8; 32] {
        crate::authenticated::sha256(&self.canonical_bytes())
    }
}

impl CanonicalWire for ValidatedEvmTransactionIntent {
    const KIND: u8 = EVM_TRANSACTION_INTENT_KIND;

    fn canonical_bytes(&self) -> Vec<u8> {
        self.canonical_bytes()
    }
}

impl CanonicalWire for EvmTransactionIntent {
    const KIND: u8 = EVM_TRANSACTION_INTENT_KIND;
    fn canonical_bytes(&self) -> Vec<u8> {
        self.try_canonical_bytes()
            .expect("invalid EVM transaction intent")
    }
}

fn put_u16(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u32(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_u64(value: u64, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}
fn put_bytes(value: &[u8], out: &mut Vec<u8>) {
    put_u32(value.len() as u32, out);
    out.extend_from_slice(value);
}
fn put_str(value: &str, out: &mut Vec<u8>) {
    put_bytes(value.as_bytes(), out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AgentWalletId, PolicyId};

    fn intent() -> EvmTransactionIntent {
        let mut footprint = vec![
            EntityRef::Chain { chain_id: 1 },
            EntityRef::Wallet {
                chain_id: 1,
                address: "1111111111111111111111111111111111111111".into(),
            },
            EntityRef::Contract {
                chain_id: 1,
                address: "2222222222222222222222222222222222222222".into(),
            },
        ];
        footprint.sort();
        EvmTransactionIntent {
            intent_id: IntentId::new("intent-1").unwrap(),
            wallet_id: "wallet-1".into(),
            principal: PrincipalBinding::Agent {
                agent_id: AgentWalletId::new("agent-1").unwrap(),
            },
            operation: EvmOperation::ContractCall,
            chain_id: 1,
            from: EvmAddress::new([0x11; 20]),
            to: Some(EvmAddress::new([0x22; 20])),
            nonce: 7,
            value: U256::from_u128(9),
            gas_limit: 100_000,
            fee: EvmFeePolicy::Eip1559 {
                max_fee_per_gas: U256::from_u128(2),
                max_priority_fee_per_gas: U256::from_u128(1),
            },
            calldata: vec![0xaa, 0xbb],
            deployment: None,
            policy_id: PolicyId::new("policy-1").unwrap(),
            capability_id: CapabilityId::new("cap-1").unwrap(),
            document_hash: DocumentHash::new("doc-1").unwrap(),
            footprint,
            not_before_unix: 10,
            expires_at_unix: 20,
        }
    }

    #[test]
    fn canonical_intent_is_versioned_and_repeatable() {
        let first = intent().try_canonical_bytes().unwrap();
        assert_eq!(&first[..4], b"BW3C");
        assert_eq!(u16::from_be_bytes([first[4], first[5]]), 1);
        assert_eq!(first[6], EVM_TRANSACTION_INTENT_KIND);
        assert_eq!(first, intent().try_canonical_bytes().unwrap());
    }

    #[test]
    fn every_transaction_field_change_changes_digest() {
        let first = intent().intent_digest().unwrap();
        let mut changed = intent();
        changed.calldata = vec![0xaa, 0xbc];
        assert_ne!(first, changed.intent_digest().unwrap());
        let mut changed = intent();
        changed.nonce += 1;
        assert_ne!(first, changed.intent_digest().unwrap());
    }

    #[test]
    fn invalid_shape_and_unsorted_footprint_fail_closed() {
        let mut invalid = intent();
        invalid.to = None;
        assert_eq!(
            invalid.validate(),
            Err(IntentError::InvalidShape("call target is required"))
        );
        let mut invalid = intent();
        invalid.footprint.reverse();
        assert_eq!(invalid.validate(), Err(IntentError::DuplicateFootprint));
    }

    #[test]
    fn validated_wrapper_rejects_unsorted_footprints() {
        let mut invalid = intent();
        invalid.footprint.reverse();
        assert_eq!(
            invalid.into_validated(),
            Err(IntentError::DuplicateFootprint)
        );
    }

    #[test]
    fn validated_wrapper_preserves_canonical_bytes_and_digest() {
        let original = intent();
        let expected_bytes = original.try_canonical_bytes().unwrap();
        let expected_digest = original.intent_digest().unwrap();
        let validated = original.into_validated().unwrap();

        assert_eq!(validated.canonical_bytes(), expected_bytes);
        assert_eq!(validated.intent_digest(), expected_digest);
        assert_eq!(validated.as_intent().footprint, intent().footprint);
    }

    #[test]
    fn kind_seven_intent_round_trips_through_authenticated_envelope() {
        let envelope = crate::authenticated::AuthenticatedEnvelope::from_canonical(
            "rust-wallet-core",
            "test-key",
            crate::authenticated::BindingContext {
                subject: "wallet-1".into(),
                registry_version: 1,
                expires_at_unix: 20,
                nonce: [1; 16],
            },
            &intent(),
            b"test-signature".to_vec(),
        )
        .unwrap();
        assert_eq!(envelope.kind, EVM_TRANSACTION_INTENT_KIND);
        let decoded =
            crate::authenticated::AuthenticatedEnvelope::decode(&envelope.encode().unwrap())
                .unwrap();
        assert_eq!(decoded.kind, EVM_TRANSACTION_INTENT_KIND);
        assert_eq!(decoded.payload, envelope.payload);
    }
}
