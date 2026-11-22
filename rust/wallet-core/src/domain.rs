//! Phase 1 domain contracts shared by wallet-core and orchestration adapters.
//!
//! These types are intentionally dependency-free and validation-heavy. They define the
//! boundary Elixir may orchestrate without becoming an authority for keys, funding
//! direction, policy admission, or quarantine reversal.

use std::collections::BTreeSet;
use std::fmt;

use super::{ChainId, EntityRef, RegistryVersion, Reporter};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OpaqueId(String);

impl OpaqueId {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.trim().is_empty() || value.chars().any(char::is_control) {
            return Err(DomainError::InvalidIdentifier);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! id_type {
    ($name:ident) => {
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub struct $name(OpaqueId);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
                Ok(Self(OpaqueId::new(value)?))
            }

            pub fn as_str(&self) -> &str {
                self.0.as_str()
            }
        }
    };
}

id_type!(UserWalletId);
id_type!(AgentWalletId);
id_type!(PolicyId);
id_type!(FlowId);
id_type!(DocumentHash);
id_type!(CapabilityId);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WalletStatus {
    Active,
    Paused,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserWallet {
    pub id: UserWalletId,
    pub supported_chains: BTreeSet<ChainId>,
    pub global_policy: PolicyId,
    pub status: WalletStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentWallet {
    pub id: AgentWalletId,
    pub owner: UserWalletId,
    pub status: WalletStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum AssignmentScope {
    Chain(ChainId),
    Venue(String),
    Contract(String),
    Asset(String),
    Operation(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentAssignment {
    pub agent: AgentWalletId,
    pub wallet: AgentWalletId,
    pub scopes: BTreeSet<AssignmentScope>,
    pub policy: PolicyId,
    pub revoked: bool,
}

impl AgentAssignment {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.agent == self.wallet {
            return Err(DomainError::SelfAssignment);
        }
        if self.scopes.is_empty() || self.revoked {
            return Err(DomainError::AssignmentUnavailable);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FundingDirection {
    UserToAgent,
    AgentToUserDenied,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FundingAuthorization {
    pub source: AgentWalletId,
    pub destination: AgentWalletId,
    pub direction: FundingDirection,
    pub policy: PolicyId,
}

impl FundingAuthorization {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.source == self.destination {
            return Err(DomainError::SelfFunding);
        }
        match self.direction {
            FundingDirection::UserToAgent => Ok(()),
            FundingDirection::AgentToUserDenied => Err(DomainError::ParentFundingDenied),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Principal {
    User,
    RustWalletCore,
    ElixirOrchestrator,
    BrowserUi,
    Agent(AgentWalletId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VaultKind {
    Secrets,
    Automations,
    FinancialCold,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VaultPolicy {
    pub kind: VaultKind,
    pub principals: BTreeSet<Principal>,
    pub cold_storage: bool,
    pub user_hardware_required: bool,
    pub withdrawal_delay_secs: u64,
}

impl VaultPolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        match self.kind {
            VaultKind::Secrets => {
                if self.principals.contains(&Principal::BrowserUi)
                    || self.principals.contains(&Principal::ElixirOrchestrator)
                    || self
                        .principals
                        .iter()
                        .any(|principal| matches!(principal, Principal::Agent(_)))
                {
                    return Err(DomainError::SecretsExposure);
                }
                if !self.principals.contains(&Principal::RustWalletCore) {
                    return Err(DomainError::SignerBoundaryMissing);
                }
            }
            VaultKind::Automations => {
                if self.cold_storage || self.user_hardware_required {
                    return Err(DomainError::InvalidAutomationVault);
                }
            }
            VaultKind::FinancialCold => {
                if !self.cold_storage
                    || !self.user_hardware_required
                    || self.withdrawal_delay_secs == 0
                {
                    return Err(DomainError::FinancialVaultNotCold);
                }
                if self.principals.iter().any(|principal| {
                    matches!(
                        principal,
                        Principal::Agent(_) | Principal::ElixirOrchestrator
                    )
                }) {
                    return Err(DomainError::FinancialVaultAgentAccess);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionMode {
    Observe,
    Simulate,
    AutonomousBounded,
    AutonomousRebalancing,
    EmergencyPaused,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyScope {
    pub chains: BTreeSet<ChainId>,
    pub venues: BTreeSet<String>,
    pub contracts: BTreeSet<String>,
    pub assets: BTreeSet<String>,
}

impl PolicyScope {
    pub fn is_empty(&self) -> bool {
        self.chains.is_empty()
            && self.venues.is_empty()
            && self.contracts.is_empty()
            && self.assets.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Budget {
    pub max_value: u128,
    pub max_gas: u128,
    pub max_turnover: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u16,
    pub backoff_secs: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationPolicy {
    pub id: PolicyId,
    pub owner: UserWalletId,
    pub agent: AgentWalletId,
    pub scope: PolicyScope,
    pub budget: Budget,
    pub retry: RetryPolicy,
    pub mode: ExecutionMode,
    pub document: DocumentHash,
    pub capability: CapabilityId,
}

impl AutomationPolicy {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.scope.is_empty() {
            return Err(DomainError::EmptyPolicyScope);
        }
        if self.document.as_str().trim().is_empty() || self.capability.as_str().trim().is_empty() {
            return Err(DomainError::MissingPolicyBinding);
        }
        if self.retry.max_attempts == 0 {
            return Err(DomainError::InvalidRetryPolicy);
        }
        if matches!(self.mode, ExecutionMode::EmergencyPaused) {
            return Err(DomainError::PolicyPaused);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowStep {
    pub operation: String,
    pub footprint: Vec<EntityRef>,
    pub estimated_cost: u128,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationFlow {
    pub id: FlowId,
    pub policy: PolicyId,
    pub agent: AgentWalletId,
    pub content_hash: DocumentHash,
    pub steps: Vec<FlowStep>,
}

impl AutomationFlow {
    pub fn validate(&self, policy: &AutomationPolicy) -> Result<(), DomainError> {
        if self.steps.is_empty() {
            return Err(DomainError::EmptyFlow);
        }
        if self.policy != policy.id || self.agent != policy.agent {
            return Err(DomainError::FlowPolicyMismatch);
        }
        if self.content_hash.as_str().trim().is_empty() {
            return Err(DomainError::MissingFlowHash);
        }
        if self
            .steps
            .iter()
            .any(|step| step.operation.trim().is_empty() || step.footprint.is_empty())
        {
            return Err(DomainError::UnverifiableFlowStep);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceProvenance {
    pub source: String,
    pub evidence_hash: DocumentHash,
    pub observed_at_unix: u64,
}

impl EvidenceProvenance {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.source.trim().is_empty()
            || self.evidence_hash.as_str().trim().is_empty()
            || self.observed_at_unix == 0
        {
            return Err(DomainError::InvalidEvidenceProvenance);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PropagationAcknowledgement {
    pub expected_wallets: BTreeSet<AgentWalletId>,
    pub acknowledged_wallets: BTreeSet<AgentWalletId>,
}

impl PropagationAcknowledgement {
    pub fn validate(&self) -> Result<(), DomainError> {
        if !self.acknowledged_wallets.is_subset(&self.expected_wallets) {
            return Err(DomainError::UnknownPropagationWallet);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReversalAuthorizationRef {
    pub authorization_id: OpaqueId,
    pub user_identity: OpaqueId,
    pub hardware_credential_ref: OpaqueId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineEvent {
    pub quarantine_id: u64,
    pub registry_version: RegistryVersion,
    pub subject: EntityRef,
    pub reason_code: String,
    pub provenance: EvidenceProvenance,
    pub reported_by: Reporter,
    pub propagation: PropagationAcknowledgement,
    pub reversal: Option<ReversalAuthorizationRef>,
}

impl QuarantineEvent {
    pub fn validate(&self, previous_version: RegistryVersion) -> Result<(), DomainError> {
        if self.registry_version <= previous_version || self.reason_code.trim().is_empty() {
            return Err(DomainError::NonMonotonicQuarantine);
        }
        self.provenance.validate()?;
        self.propagation.validate()?;
        if self.quarantine_id == 0 {
            return Err(DomainError::InvalidQuarantineId);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DomainError {
    InvalidIdentifier,
    SelfAssignment,
    AssignmentUnavailable,
    SelfFunding,
    ParentFundingDenied,
    SecretsExposure,
    SignerBoundaryMissing,
    InvalidAutomationVault,
    FinancialVaultNotCold,
    FinancialVaultAgentAccess,
    EmptyPolicyScope,
    MissingPolicyBinding,
    InvalidRetryPolicy,
    PolicyPaused,
    EmptyFlow,
    FlowPolicyMismatch,
    MissingFlowHash,
    UnverifiableFlowStep,
    InvalidEvidenceProvenance,
    UnknownPropagationWallet,
    NonMonotonicQuarantine,
    InvalidQuarantineId,
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for DomainError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn id<T>(new: impl FnOnce(String) -> Result<T, DomainError>, value: &str) -> T {
        new(value.to_owned()).expect("valid id")
    }

    fn wallet_graph_fixture() -> (UserWalletId, AgentWalletId, AgentWalletId, PolicyId) {
        (
            id(UserWalletId::new, "user-1"),
            id(AgentWalletId::new, "agent-1"),
            id(AgentWalletId::new, "agent-2"),
            id(PolicyId::new, "policy-1"),
        )
    }

    #[test]
    fn assignment_is_scoped_and_revocation_fails_closed() {
        let (_, agent, wallet, policy) = wallet_graph_fixture();
        let mut scopes = BTreeSet::new();
        scopes.insert(AssignmentScope::Operation("swap".into()));
        let mut assignment = AgentAssignment {
            agent,
            wallet,
            scopes,
            policy,
            revoked: false,
        };
        assert!(assignment.validate().is_ok());
        assignment.revoked = true;
        assert_eq!(
            assignment.validate(),
            Err(DomainError::AssignmentUnavailable)
        );
    }

    #[test]
    fn agent_cannot_create_parent_funding_direction() {
        let (_, agent, wallet, policy) = wallet_graph_fixture();
        let authorization = FundingAuthorization {
            source: agent,
            destination: wallet,
            direction: FundingDirection::AgentToUserDenied,
            policy,
        };
        assert_eq!(
            authorization.validate(),
            Err(DomainError::ParentFundingDenied)
        );
    }

    #[test]
    fn vaults_enforce_separate_authority_boundaries() {
        let mut secrets = BTreeSet::new();
        secrets.insert(Principal::RustWalletCore);
        secrets.insert(Principal::ElixirOrchestrator);
        let policy = VaultPolicy {
            kind: VaultKind::Secrets,
            principals: secrets,
            cold_storage: false,
            user_hardware_required: false,
            withdrawal_delay_secs: 0,
        };
        assert_eq!(policy.validate(), Err(DomainError::SecretsExposure));

        let mut financial = BTreeSet::new();
        financial.insert(Principal::User);
        let policy = VaultPolicy {
            kind: VaultKind::FinancialCold,
            principals: financial,
            cold_storage: true,
            user_hardware_required: true,
            withdrawal_delay_secs: 60,
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn policy_requires_scope_and_never_encodes_per_transaction_approval() {
        let (_, agent, _, policy_id) = wallet_graph_fixture();
        let empty = AutomationPolicy {
            id: policy_id.clone(),
            owner: id(UserWalletId::new, "user-1"),
            agent,
            scope: PolicyScope {
                chains: BTreeSet::new(),
                venues: BTreeSet::new(),
                contracts: BTreeSet::new(),
                assets: BTreeSet::new(),
            },
            budget: Budget {
                max_value: 1,
                max_gas: 1,
                max_turnover: 1,
            },
            retry: RetryPolicy {
                max_attempts: 1,
                backoff_secs: 1,
            },
            mode: ExecutionMode::AutonomousBounded,
            document: id(DocumentHash::new, "doc-1"),
            capability: id(CapabilityId::new, "cap-1"),
        };
        assert_eq!(empty.validate(), Err(DomainError::EmptyPolicyScope));
    }

    #[test]
    fn flow_requires_hash_matching_policy_and_typed_footprints() {
        let (user, agent, _, policy_id) = wallet_graph_fixture();
        let mut chains = BTreeSet::new();
        chains.insert(1);
        let policy = AutomationPolicy {
            id: policy_id.clone(),
            owner: user,
            agent: agent.clone(),
            scope: PolicyScope {
                chains,
                venues: BTreeSet::new(),
                contracts: BTreeSet::new(),
                assets: BTreeSet::new(),
            },
            budget: Budget {
                max_value: 10,
                max_gas: 10,
                max_turnover: 10,
            },
            retry: RetryPolicy {
                max_attempts: 2,
                backoff_secs: 1,
            },
            mode: ExecutionMode::AutonomousBounded,
            document: id(DocumentHash::new, "doc-1"),
            capability: id(CapabilityId::new, "cap-1"),
        };
        assert!(policy.validate().is_ok());
        let flow = AutomationFlow {
            id: id(FlowId::new, "flow-1"),
            policy: policy_id,
            agent,
            content_hash: id(DocumentHash::new, "flow-hash"),
            steps: vec![],
        };
        assert_eq!(flow.validate(&policy), Err(DomainError::EmptyFlow));
    }

    #[test]
    fn quarantine_event_requires_monotonic_version_evidence_and_known_propagation() {
        let agent = id(AgentWalletId::new, "agent-1");
        let mut expected = BTreeSet::new();
        expected.insert(agent.clone());
        let mut acknowledged = BTreeSet::new();
        acknowledged.insert(id(AgentWalletId::new, "agent-unknown"));
        let event = QuarantineEvent {
            quarantine_id: 1,
            registry_version: 2,
            subject: EntityRef::StrategyFamily {
                name: "bootstrap".into(),
            },
            reason_code: "malicious".into(),
            provenance: EvidenceProvenance {
                source: "agent-report".into(),
                evidence_hash: id(DocumentHash::new, "evidence-1"),
                observed_at_unix: 1,
            },
            reported_by: Reporter::Agent {
                agent_id: agent.as_str().into(),
            },
            propagation: PropagationAcknowledgement {
                expected_wallets: expected,
                acknowledged_wallets: acknowledged,
            },
            reversal: None,
        };
        assert_eq!(
            event.validate(1),
            Err(DomainError::UnknownPropagationWallet)
        );
    }

    #[test]
    fn stale_quarantine_event_cannot_override_registry_version() {
        let event = QuarantineEvent {
            quarantine_id: 1,
            registry_version: 4,
            subject: EntityRef::Chain { chain_id: 1 },
            reason_code: "incident".into(),
            provenance: EvidenceProvenance {
                source: "registry".into(),
                evidence_hash: id(DocumentHash::new, "evidence-2"),
                observed_at_unix: 1,
            },
            reported_by: Reporter::User {
                identity: "user-1".into(),
            },
            propagation: PropagationAcknowledgement {
                expected_wallets: BTreeSet::new(),
                acknowledged_wallets: BTreeSet::new(),
            },
            reversal: None,
        };
        assert_eq!(event.validate(4), Err(DomainError::NonMonotonicQuarantine));
    }
}
