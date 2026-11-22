//! Deterministic wire encoding for Phase 1 domain contracts.
//!
//! This is deliberately small and dependency-free. It is a canonical byte encoding,
//! not a cryptographic signature or hash. Callers must authenticate and hash the exact
//! returned bytes at the transport/authority boundary.

use std::collections::BTreeSet;

use crate::domain::{
    AgentAssignment, AssignmentScope, AutomationFlow, AutomationPolicy, Budget, EvidenceProvenance,
    ExecutionMode, FlowStep, FundingAuthorization, FundingDirection, PolicyScope, Principal,
    PropagationAcknowledgement, QuarantineEvent, RetryPolicy, VaultKind, VaultPolicy,
};
use crate::{EntityRef, Reporter};

pub const WIRE_VERSION: u16 = 1;

pub trait CanonicalWire {
    const KIND: u8;

    fn canonical_bytes(&self) -> Vec<u8>;
}

fn header(kind: u8, out: &mut Vec<u8>) {
    out.extend_from_slice(b"BW3C");
    put_u16(WIRE_VERSION, out);
    put_u8(kind, out);
}

fn put_u8(value: u8, out: &mut Vec<u8>) {
    out.push(value);
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

fn put_u128(value: u128, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bool(value: bool, out: &mut Vec<u8>) {
    put_u8(u8::from(value), out);
}

fn put_bytes(value: &[u8], out: &mut Vec<u8>) {
    put_u32(value.len() as u32, out);
    out.extend_from_slice(value);
}

fn put_str(value: &str, out: &mut Vec<u8>) {
    put_bytes(value.as_bytes(), out);
}

fn put_set<T>(values: &BTreeSet<T>, out: &mut Vec<u8>, mut encode: impl FnMut(&T, &mut Vec<u8>)) {
    put_u32(values.len() as u32, out);
    for value in values {
        encode(value, out);
    }
}

fn put_vec<T>(values: &[T], out: &mut Vec<u8>, mut encode: impl FnMut(&T, &mut Vec<u8>)) {
    put_u32(values.len() as u32, out);
    for value in values {
        encode(value, out);
    }
}

fn put_entity(entity: &EntityRef, out: &mut Vec<u8>) {
    match entity {
        EntityRef::Token { chain_id, address } => {
            put_u8(1, out);
            put_u64(*chain_id, out);
            put_str(address, out);
        }
        EntityRef::Contract { chain_id, address } => {
            put_u8(2, out);
            put_u64(*chain_id, out);
            put_str(address, out);
        }
        EntityRef::Deployer { chain_id, address } => {
            put_u8(3, out);
            put_u64(*chain_id, out);
            put_str(address, out);
        }
        EntityRef::Pair { chain_id, address } => {
            put_u8(4, out);
            put_u64(*chain_id, out);
            put_str(address, out);
        }
        EntityRef::Chain { chain_id } => {
            put_u8(5, out);
            put_u64(*chain_id, out);
        }
        EntityRef::Provider { chain_id, name } => {
            put_u8(6, out);
            put_u64(*chain_id, out);
            put_str(name, out);
        }
        EntityRef::StrategyFamily { name } => {
            put_u8(7, out);
            put_str(name, out);
        }
        EntityRef::Wallet { chain_id, address } => {
            put_u8(8, out);
            put_u64(*chain_id, out);
            put_str(address, out);
        }
    }
}

fn put_reporter(reporter: &Reporter, out: &mut Vec<u8>) {
    match reporter {
        Reporter::User { identity } => {
            put_u8(1, out);
            put_str(identity, out);
        }
        Reporter::Agent { agent_id } => {
            put_u8(2, out);
            put_str(agent_id, out);
        }
    }
}

fn put_assignment_scope(scope: &AssignmentScope, out: &mut Vec<u8>) {
    match scope {
        AssignmentScope::Chain(chain) => {
            put_u8(1, out);
            put_u64(*chain, out);
        }
        AssignmentScope::Venue(value) => {
            put_u8(2, out);
            put_str(value, out);
        }
        AssignmentScope::Contract(value) => {
            put_u8(3, out);
            put_str(value, out);
        }
        AssignmentScope::Asset(value) => {
            put_u8(4, out);
            put_str(value, out);
        }
        AssignmentScope::Operation(value) => {
            put_u8(5, out);
            put_str(value, out);
        }
    }
}

fn put_principal(principal: &Principal, out: &mut Vec<u8>) {
    match principal {
        Principal::User => put_u8(1, out),
        Principal::RustWalletCore => put_u8(2, out),
        Principal::ElixirOrchestrator => put_u8(3, out),
        Principal::BrowserUi => put_u8(4, out),
        Principal::Agent(agent) => {
            put_u8(5, out);
            put_str(agent.as_str(), out);
        }
    }
}

fn put_vault_kind(kind: &VaultKind, out: &mut Vec<u8>) {
    put_u8(
        match kind {
            VaultKind::Secrets => 1,
            VaultKind::Automations => 2,
            VaultKind::FinancialCold => 3,
        },
        out,
    );
}

fn put_execution_mode(mode: &ExecutionMode, out: &mut Vec<u8>) {
    put_u8(
        match mode {
            ExecutionMode::Observe => 1,
            ExecutionMode::Simulate => 2,
            ExecutionMode::AutonomousBounded => 3,
            ExecutionMode::AutonomousRebalancing => 4,
            ExecutionMode::EmergencyPaused => 5,
        },
        out,
    );
}

fn put_scope(scope: &PolicyScope, out: &mut Vec<u8>) {
    put_set(&scope.chains, out, |chain, output| put_u64(*chain, output));
    put_set(&scope.venues, out, |value, output| put_str(value, output));
    put_set(&scope.contracts, out, |value, output| {
        put_str(value, output)
    });
    put_set(&scope.assets, out, |value, output| put_str(value, output));
}

fn put_budget(budget: &Budget, out: &mut Vec<u8>) {
    put_u128(budget.max_value, out);
    put_u128(budget.max_gas, out);
    put_u128(budget.max_turnover, out);
}

fn put_retry(retry: &RetryPolicy, out: &mut Vec<u8>) {
    put_u16(retry.max_attempts, out);
    put_u64(retry.backoff_secs, out);
}

fn put_step(step: &FlowStep, out: &mut Vec<u8>) {
    put_str(&step.operation, out);
    put_vec(&step.footprint, out, put_entity);
    put_u128(step.estimated_cost, out);
}

fn put_provenance(provenance: &EvidenceProvenance, out: &mut Vec<u8>) {
    put_str(&provenance.source, out);
    put_str(provenance.evidence_hash.as_str(), out);
    put_u64(provenance.observed_at_unix, out);
}

fn put_propagation(propagation: &PropagationAcknowledgement, out: &mut Vec<u8>) {
    put_set(&propagation.expected_wallets, out, |wallet, output| {
        put_str(wallet.as_str(), output)
    });
    put_set(&propagation.acknowledged_wallets, out, |wallet, output| {
        put_str(wallet.as_str(), output)
    });
}

impl CanonicalWire for AgentAssignment {
    const KIND: u8 = 1;

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        header(Self::KIND, &mut out);
        put_str(self.agent.as_str(), &mut out);
        put_str(self.wallet.as_str(), &mut out);
        put_set(&self.scopes, &mut out, put_assignment_scope);
        put_str(self.policy.as_str(), &mut out);
        put_bool(self.revoked, &mut out);
        out
    }
}

impl CanonicalWire for FundingAuthorization {
    const KIND: u8 = 2;

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        header(Self::KIND, &mut out);
        put_str(self.source.as_str(), &mut out);
        put_str(self.destination.as_str(), &mut out);
        put_u8(
            match self.direction {
                FundingDirection::UserToAgent => 1,
                FundingDirection::AgentToUserDenied => 2,
            },
            &mut out,
        );
        put_str(self.policy.as_str(), &mut out);
        out
    }
}

impl CanonicalWire for VaultPolicy {
    const KIND: u8 = 3;

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        header(Self::KIND, &mut out);
        put_vault_kind(&self.kind, &mut out);
        put_set(&self.principals, &mut out, put_principal);
        put_bool(self.cold_storage, &mut out);
        put_bool(self.user_hardware_required, &mut out);
        put_u64(self.withdrawal_delay_secs, &mut out);
        out
    }
}

impl CanonicalWire for AutomationPolicy {
    const KIND: u8 = 4;

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        header(Self::KIND, &mut out);
        put_str(self.id.as_str(), &mut out);
        put_str(self.owner.as_str(), &mut out);
        put_str(self.agent.as_str(), &mut out);
        put_scope(&self.scope, &mut out);
        put_budget(&self.budget, &mut out);
        put_retry(&self.retry, &mut out);
        put_execution_mode(&self.mode, &mut out);
        put_str(self.document.as_str(), &mut out);
        put_str(self.capability.as_str(), &mut out);
        out
    }
}

impl CanonicalWire for AutomationFlow {
    const KIND: u8 = 5;

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        header(Self::KIND, &mut out);
        put_str(self.id.as_str(), &mut out);
        put_str(self.policy.as_str(), &mut out);
        put_str(self.agent.as_str(), &mut out);
        put_str(self.content_hash.as_str(), &mut out);
        put_vec(&self.steps, &mut out, put_step);
        out
    }
}

impl CanonicalWire for QuarantineEvent {
    const KIND: u8 = 6;

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        header(Self::KIND, &mut out);
        put_u64(self.quarantine_id, &mut out);
        put_u64(self.registry_version, &mut out);
        put_entity(&self.subject, &mut out);
        put_str(&self.reason_code, &mut out);
        put_provenance(&self.provenance, &mut out);
        put_reporter(&self.reported_by, &mut out);
        put_propagation(&self.propagation, &mut out);
        match &self.reversal {
            Some(reversal) => {
                put_bool(true, &mut out);
                put_str(reversal.authorization_id.as_str(), &mut out);
                put_str(reversal.user_identity.as_str(), &mut out);
                put_str(reversal.hardware_credential_ref.as_str(), &mut out);
            }
            None => put_bool(false, &mut out),
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        AgentWalletId, AutomationPolicy, CapabilityId, DocumentHash, PolicyId, UserWalletId,
    };

    fn id<T>(new: impl FnOnce(String) -> Result<T, crate::domain::DomainError>, value: &str) -> T {
        new(value.to_owned()).expect("valid id")
    }

    fn policy() -> AutomationPolicy {
        let mut chains = BTreeSet::new();
        chains.insert(1);
        AutomationPolicy {
            id: id(PolicyId::new, "policy-1"),
            owner: id(UserWalletId::new, "user-1"),
            agent: id(AgentWalletId::new, "agent-1"),
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
            document: id(DocumentHash::new, "doc-1"),
            capability: id(CapabilityId::new, "cap-1"),
        }
    }

    #[test]
    fn canonical_policy_encoding_is_repeatable_and_versioned() {
        let first = policy().canonical_bytes();
        let second = policy().canonical_bytes();
        assert_eq!(first, second);
        assert_eq!(&first[..4], b"BW3C");
        assert_eq!(u16::from_be_bytes([first[4], first[5]]), WIRE_VERSION);
        assert_eq!(first[6], AutomationPolicy::KIND);
    }

    #[test]
    fn canonical_encoding_changes_when_policy_authority_changes() {
        let first = policy().canonical_bytes();
        let mut changed = policy();
        changed.capability = id(CapabilityId::new, "cap-2");
        assert_ne!(first, changed.canonical_bytes());
    }
}
