//! BootStrap Wall3t wallet-core trust boundary.
//!
//! This crate deliberately contains no chain signing implementation. It models the
//! security-critical ordering: typed intent admission, simulation, signing, and
//! broadcast must all revalidate the authoritative quarantine version.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub mod domain;

pub type RegistryVersion = u64;
pub type ChainId = u64;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EntityRef {
    Token { chain_id: ChainId, address: String },
    Contract { chain_id: ChainId, address: String },
    Deployer { chain_id: ChainId, address: String },
    Pair { chain_id: ChainId, address: String },
    Chain { chain_id: ChainId },
    Provider { chain_id: ChainId, name: String },
    StrategyFamily { name: String },
    Wallet { chain_id: ChainId, address: String },
}

impl EntityRef {
    pub fn chain_id(&self) -> Option<ChainId> {
        match self {
            Self::Token { chain_id, .. }
            | Self::Contract { chain_id, .. }
            | Self::Deployer { chain_id, .. }
            | Self::Pair { chain_id, .. }
            | Self::Chain { chain_id }
            | Self::Provider { chain_id, .. }
            | Self::Wallet { chain_id, .. } => Some(*chain_id),
            Self::StrategyFamily { .. } => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Reporter {
    User { identity: String },
    Agent { agent_id: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineRecord {
    pub quarantine_id: u64,
    pub registry_version: RegistryVersion,
    pub entity: EntityRef,
    pub reason_code: String,
    pub evidence_refs: Vec<String>,
    pub reported_by: Reporter,
    pub created_at_unix: u64,
    pub active: bool,
    pub reversal_version: Option<RegistryVersion>,
    pub reversed_by: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrySnapshot {
    pub version: RegistryVersion,
    pub active: Vec<QuarantineRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuarantineEvidence {
    pub entity: EntityRef,
    pub reason_code: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserHardwareAuthorization {
    pub identity: String,
    pub hardware_assertion: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RegistryError {
    Unavailable,
    InvalidEvidence,
    NotFound(u64),
    UserAuthorizationRequired,
}

impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "quarantine registry unavailable"),
            Self::InvalidEvidence => write!(f, "quarantine evidence is incomplete"),
            Self::NotFound(id) => write!(f, "quarantine record {id} not found"),
            Self::UserAuthorizationRequired => write!(f, "user hardware authorization required"),
        }
    }
}

impl std::error::Error for RegistryError {}

pub trait QuarantineRegistry: Send + Sync + 'static {
    fn snapshot(&self) -> Result<RegistrySnapshot, RegistryError>;
    fn publish(
        &self,
        reporter: Reporter,
        evidence: QuarantineEvidence,
    ) -> Result<QuarantineRecord, RegistryError>;
    fn reverse(
        &self,
        authorization: UserHardwareAuthorization,
        quarantine_id: u64,
    ) -> Result<QuarantineRecord, RegistryError>;
}

#[derive(Default)]
struct RegistryState {
    version: RegistryVersion,
    next_id: u64,
    records: BTreeMap<u64, QuarantineRecord>,
}

/// A process-local reference implementation of the authoritative registry.
/// Production adapters must preserve the same linearizable and monotonic contract.
#[derive(Default)]
pub struct InMemoryQuarantineRegistry {
    state: RwLock<RegistryState>,
}

impl InMemoryQuarantineRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current_version(&self) -> Result<RegistryVersion, RegistryError> {
        Ok(self
            .state
            .read()
            .map_err(|_| RegistryError::Unavailable)?
            .version)
    }
}

impl QuarantineRegistry for InMemoryQuarantineRegistry {
    fn snapshot(&self) -> Result<RegistrySnapshot, RegistryError> {
        let state = self.state.read().map_err(|_| RegistryError::Unavailable)?;
        Ok(RegistrySnapshot {
            version: state.version,
            active: state
                .records
                .values()
                .filter(|r| r.active)
                .cloned()
                .collect(),
        })
    }

    fn publish(
        &self,
        reporter: Reporter,
        evidence: QuarantineEvidence,
    ) -> Result<QuarantineRecord, RegistryError> {
        if evidence.reason_code.trim().is_empty() || evidence.evidence_refs.is_empty() {
            return Err(RegistryError::InvalidEvidence);
        }
        let mut state = self.state.write().map_err(|_| RegistryError::Unavailable)?;
        state.version += 1;
        state.next_id += 1;
        let record = QuarantineRecord {
            quarantine_id: state.next_id,
            registry_version: state.version,
            entity: evidence.entity,
            reason_code: evidence.reason_code,
            evidence_refs: evidence.evidence_refs,
            reported_by: reporter,
            created_at_unix: now_unix(),
            active: true,
            reversal_version: None,
            reversed_by: None,
        };
        state.records.insert(record.quarantine_id, record.clone());
        Ok(record)
    }

    fn reverse(
        &self,
        authorization: UserHardwareAuthorization,
        quarantine_id: u64,
    ) -> Result<QuarantineRecord, RegistryError> {
        if authorization.identity.trim().is_empty()
            || authorization.hardware_assertion.trim().is_empty()
        {
            return Err(RegistryError::UserAuthorizationRequired);
        }
        let mut state = self.state.write().map_err(|_| RegistryError::Unavailable)?;
        if !state.records.contains_key(&quarantine_id) {
            return Err(RegistryError::NotFound(quarantine_id));
        }
        state.version += 1;
        let reversal_version = state.version;
        let record = state
            .records
            .get_mut(&quarantine_id)
            .expect("record existence checked above");
        record.active = false;
        record.reversal_version = Some(reversal_version);
        record.reversed_by = Some(authorization.identity);
        Ok(record.clone())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentFootprint {
    pub entities: Vec<EntityRef>,
}

impl IntentFootprint {
    pub fn new(mut entities: Vec<EntityRef>) -> Self {
        entities.sort();
        entities.dedup();
        Self { entities }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationKind {
    NativeTransfer,
    TokenTransfer,
    Approval,
    Permit,
    Swap,
    Bridge,
    Staking,
    LightningPayment,
    AgentTransfer,
    StrategyExecution,
    DiscoveryActivation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxIntent {
    pub intent_id: String,
    pub operation: OperationKind,
    pub footprint: IntentFootprint,
    pub canonical_payload: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimulationTicket {
    pub intent: TxIntent,
    pub registry_version: RegistryVersion,
    pub simulation_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedIntent {
    pub ticket: SimulationTicket,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastReceipt {
    pub intent_id: String,
    pub registry_version: RegistryVersion,
    pub transaction_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TrustError {
    Registry(RegistryError),
    StaleRegistry {
        ticket: RegistryVersion,
        current: RegistryVersion,
    },
    Quarantined {
        entity: EntityRef,
        quarantine_id: u64,
        registry_version: RegistryVersion,
    },
    InvalidIntent,
    SigningUnavailable,
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Registry(e) => write!(f, "registry error: {e}"),
            Self::StaleRegistry { ticket, current } => write!(f, "stale registry ticket {ticket}; current version is {current}"),
            Self::Quarantined { entity, quarantine_id, registry_version } => write!(f, "entity {entity:?} denied by quarantine {quarantine_id} at registry version {registry_version}"),
            Self::InvalidIntent => write!(f, "invalid or empty intent"),
            Self::SigningUnavailable => write!(f, "signing capability unavailable"),
        }
    }
}

impl std::error::Error for TrustError {}

impl From<RegistryError> for TrustError {
    fn from(value: RegistryError) -> Self {
        Self::Registry(value)
    }
}

pub trait OpaqueSigner: Send + Sync {
    fn sign(&self, intent: &TxIntent) -> Result<String, TrustError>;
}

#[derive(Default)]
pub struct DeterministicTestSigner;

impl OpaqueSigner for DeterministicTestSigner {
    fn sign(&self, intent: &TxIntent) -> Result<String, TrustError> {
        if intent.canonical_payload.trim().is_empty() {
            return Err(TrustError::SigningUnavailable);
        }
        Ok(format!("test-signature:{}", intent.intent_id))
    }
}

/// Rust wallet-core pipeline. Agent runtimes submit intents; they cannot call the
/// signer or broadcast adapter without passing the same guard at every stage.
pub struct WalletCore<R: QuarantineRegistry, S: OpaqueSigner> {
    registry: Arc<R>,
    signer: Arc<S>,
}

impl<R: QuarantineRegistry, S: OpaqueSigner> WalletCore<R, S> {
    pub fn new(registry: Arc<R>, signer: Arc<S>) -> Self {
        Self { registry, signer }
    }

    pub fn simulate(&self, intent: TxIntent) -> Result<SimulationTicket, TrustError> {
        validate_intent(&intent)?;
        let snapshot = self.registry.snapshot()?;
        guard(&intent.footprint, &snapshot)?;
        Ok(SimulationTicket {
            simulation_hash: format!("simulation:{}@{}", intent.intent_id, snapshot.version),
            intent,
            registry_version: snapshot.version,
        })
    }

    pub fn sign(&self, ticket: SimulationTicket) -> Result<SignedIntent, TrustError> {
        let snapshot = self.registry.snapshot()?;
        ensure_ticket_current(ticket.registry_version, snapshot.version)?;
        guard(&ticket.intent.footprint, &snapshot)?;
        let signature = self.signer.sign(&ticket.intent)?;
        Ok(SignedIntent { ticket, signature })
    }

    pub fn broadcast(&self, signed: SignedIntent) -> Result<BroadcastReceipt, TrustError> {
        let snapshot = self.registry.snapshot()?;
        ensure_ticket_current(signed.ticket.registry_version, snapshot.version)?;
        guard(&signed.ticket.intent.footprint, &snapshot)?;
        Ok(BroadcastReceipt {
            intent_id: signed.ticket.intent.intent_id,
            registry_version: snapshot.version,
            transaction_id: format!("tx:{}", signed.signature),
        })
    }
}

fn validate_intent(intent: &TxIntent) -> Result<(), TrustError> {
    if intent.intent_id.trim().is_empty()
        || intent.canonical_payload.trim().is_empty()
        || intent.footprint.entities.is_empty()
    {
        return Err(TrustError::InvalidIntent);
    }
    Ok(())
}

fn ensure_ticket_current(
    ticket: RegistryVersion,
    current: RegistryVersion,
) -> Result<(), TrustError> {
    if ticket != current {
        return Err(TrustError::StaleRegistry { ticket, current });
    }
    Ok(())
}

fn guard(footprint: &IntentFootprint, snapshot: &RegistrySnapshot) -> Result<(), TrustError> {
    for entity in &footprint.entities {
        if let Some(record) = snapshot.active.iter().find(|r| &r.entity == entity) {
            return Err(TrustError::Quarantined {
                entity: entity.clone(),
                quarantine_id: record.quarantine_id,
                registry_version: snapshot.version,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn token(address: &str) -> EntityRef {
        EntityRef::Token {
            chain_id: 1,
            address: address.into(),
        }
    }

    fn contract(address: &str) -> EntityRef {
        EntityRef::Contract {
            chain_id: 1,
            address: address.into(),
        }
    }

    fn intent(id: &str, entities: Vec<EntityRef>) -> TxIntent {
        TxIntent {
            intent_id: id.into(),
            operation: OperationKind::Swap,
            footprint: IntentFootprint::new(entities),
            canonical_payload: format!("payload:{id}"),
        }
    }

    fn evidence(entity: EntityRef) -> QuarantineEvidence {
        QuarantineEvidence {
            entity,
            reason_code: "malicious-behavior".into(),
            evidence_refs: vec!["incident://test/1".into()],
        }
    }

    fn core() -> (
        Arc<InMemoryQuarantineRegistry>,
        WalletCore<InMemoryQuarantineRegistry, DeterministicTestSigner>,
    ) {
        let registry = Arc::new(InMemoryQuarantineRegistry::new());
        let core = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));
        (registry, core)
    }

    #[test]
    fn agent_report_is_global_and_does_not_require_peer_messaging() {
        let (registry, core) = core();
        registry
            .publish(
                Reporter::Agent {
                    agent_id: "agent-a".into(),
                },
                evidence(token("bad")),
            )
            .unwrap();
        let result = core.simulate(intent("agent-b-action", vec![token("bad")]));
        assert!(matches!(result, Err(TrustError::Quarantined { .. })));
    }

    #[test]
    fn only_user_hardware_authorization_can_reverse() {
        let (registry, _) = core();
        let record = registry
            .publish(
                Reporter::Agent {
                    agent_id: "agent-a".into(),
                },
                evidence(token("bad")),
            )
            .unwrap();
        assert_eq!(
            registry.reverse(
                UserHardwareAuthorization {
                    identity: "".into(),
                    hardware_assertion: "".into()
                },
                record.quarantine_id
            ),
            Err(RegistryError::UserAuthorizationRequired)
        );
        let reversed = registry
            .reverse(
                UserHardwareAuthorization {
                    identity: "alice".into(),
                    hardware_assertion: "hw-proof".into(),
                },
                record.quarantine_id,
            )
            .unwrap();
        assert!(!reversed.active);
        assert!(reversed.reversal_version.unwrap() > record.registry_version);
    }

    #[test]
    fn simulation_ticket_becomes_stale_when_quarantine_is_published() {
        let (registry, core) = core();
        let ticket = core.simulate(intent("s1", vec![token("good")])).unwrap();
        registry
            .publish(
                Reporter::User {
                    identity: "alice".into(),
                },
                evidence(token("other")),
            )
            .unwrap();
        assert!(matches!(
            core.sign(ticket),
            Err(TrustError::StaleRegistry {
                ticket: 0,
                current: 1
            })
        ));
    }

    #[test]
    fn signing_rechecks_footprint_after_simulation() {
        let (registry, core) = core();
        let ticket = core.simulate(intent("s2", vec![token("bad")])).unwrap();
        registry
            .publish(
                Reporter::Agent {
                    agent_id: "agent-a".into(),
                },
                evidence(token("bad")),
            )
            .unwrap();
        assert!(matches!(
            core.sign(ticket),
            Err(TrustError::StaleRegistry { .. })
        ));
    }

    #[test]
    fn broadcast_rechecks_footprint_after_signing() {
        let (registry, core) = core();
        let signed = core
            .sign(core.simulate(intent("s3", vec![token("good")])).unwrap())
            .unwrap();
        registry
            .publish(
                Reporter::Agent {
                    agent_id: "agent-a".into(),
                },
                evidence(token("other")),
            )
            .unwrap();
        assert!(matches!(
            core.broadcast(signed),
            Err(TrustError::StaleRegistry { .. })
        ));
    }

    #[test]
    fn quarantine_of_router_blocks_swap_even_when_tokens_are_clean() {
        let (registry, core) = core();
        let router = contract("router");
        let swap = intent("s4", vec![token("in"), token("out"), router.clone()]);
        registry
            .publish(
                Reporter::Agent {
                    agent_id: "agent-a".into(),
                },
                evidence(router),
            )
            .unwrap();
        assert!(matches!(
            core.simulate(swap),
            Err(TrustError::Quarantined { .. })
        ));
    }

    #[test]
    fn every_operation_uses_the_same_footprint_guard() {
        let operations = [
            OperationKind::NativeTransfer,
            OperationKind::TokenTransfer,
            OperationKind::Approval,
            OperationKind::Permit,
            OperationKind::Swap,
            OperationKind::Bridge,
            OperationKind::Staking,
            OperationKind::LightningPayment,
            OperationKind::AgentTransfer,
            OperationKind::StrategyExecution,
            OperationKind::DiscoveryActivation,
        ];
        for (index, operation) in operations.into_iter().enumerate() {
            let (registry, core) = core();
            let bad = token(&format!("bad-{index}"));
            registry
                .publish(
                    Reporter::User {
                        identity: "alice".into(),
                    },
                    evidence(bad.clone()),
                )
                .unwrap();
            let mut tx = intent(&format!("op-{index}"), vec![bad]);
            tx.operation = operation;
            assert!(matches!(
                core.simulate(tx),
                Err(TrustError::Quarantined { .. })
            ));
        }
    }

    #[test]
    fn concurrent_quarantine_wins_against_signing() {
        let (registry, core) = core();
        let ticket = core
            .simulate(intent("race-sign", vec![token("race")]))
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let registry_thread = registry.clone();
        let barrier_thread = barrier.clone();
        let reporter = thread::spawn(move || {
            barrier_thread.wait();
            registry_thread
                .publish(
                    Reporter::Agent {
                        agent_id: "agent-race".into(),
                    },
                    evidence(token("race")),
                )
                .unwrap();
        });
        barrier.wait();
        reporter.join().unwrap();
        assert!(matches!(
            core.sign(ticket),
            Err(TrustError::StaleRegistry { .. })
        ));
    }

    #[test]
    fn concurrent_quarantine_wins_against_broadcast() {
        let (registry, core) = core();
        let signed = core
            .sign(
                core.simulate(intent("race-broadcast", vec![token("race")]))
                    .unwrap(),
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let registry_thread = registry.clone();
        let barrier_thread = barrier.clone();
        let reporter = thread::spawn(move || {
            barrier_thread.wait();
            registry_thread
                .publish(
                    Reporter::Agent {
                        agent_id: "agent-race".into(),
                    },
                    evidence(token("race")),
                )
                .unwrap();
        });
        barrier.wait();
        reporter.join().unwrap();
        assert!(matches!(
            core.broadcast(signed),
            Err(TrustError::StaleRegistry { .. })
        ));
    }

    #[test]
    fn reversal_invalidates_old_positive_tickets_too() {
        let (registry, core) = core();
        let ticket = core
            .simulate(intent("reversal-race", vec![token("good")]))
            .unwrap();
        let record = registry
            .publish(
                Reporter::User {
                    identity: "alice".into(),
                },
                evidence(token("other")),
            )
            .unwrap();
        registry
            .reverse(
                UserHardwareAuthorization {
                    identity: "alice".into(),
                    hardware_assertion: "hw-proof".into(),
                },
                record.quarantine_id,
            )
            .unwrap();
        assert!(matches!(
            core.sign(ticket),
            Err(TrustError::StaleRegistry {
                ticket: 0,
                current: 2
            })
        ));
    }

    #[test]
    fn empty_and_unverifiable_intents_fail_closed() {
        let (_, core) = core();
        assert_eq!(
            core.simulate(intent("", vec![token("x")])),
            Err(TrustError::InvalidIntent)
        );
        assert_eq!(
            core.simulate(TxIntent {
                intent_id: "unknown".into(),
                operation: OperationKind::Swap,
                footprint: IntentFootprint::new(vec![]),
                canonical_payload: "payload".into(),
            }),
            Err(TrustError::InvalidIntent)
        );
    }

    struct UnavailableRegistry;
    impl QuarantineRegistry for UnavailableRegistry {
        fn snapshot(&self) -> Result<RegistrySnapshot, RegistryError> {
            Err(RegistryError::Unavailable)
        }
        fn publish(
            &self,
            _: Reporter,
            _: QuarantineEvidence,
        ) -> Result<QuarantineRecord, RegistryError> {
            Err(RegistryError::Unavailable)
        }
        fn reverse(
            &self,
            _: UserHardwareAuthorization,
            _: u64,
        ) -> Result<QuarantineRecord, RegistryError> {
            Err(RegistryError::Unavailable)
        }
    }

    #[test]
    fn unavailable_registry_fails_closed_at_admission() {
        let core = WalletCore::new(
            Arc::new(UnavailableRegistry),
            Arc::new(DeterministicTestSigner),
        );
        assert_eq!(
            core.simulate(intent("offline", vec![token("x")])),
            Err(TrustError::Registry(RegistryError::Unavailable))
        );
    }
}
