//! Integration tests over the public wallet-core API.
//!
//! These model several agent wallets plus a user wallet sharing one authoritative
//! registry, which is the actual deployment shape the unit tests only approximate.

use std::sync::Arc;

use wallet_core::{
    ChainId, DeterministicTestSigner, EntityRef, InMemoryQuarantineRegistry, IntentFootprint,
    OperationKind, QuarantineEvidence, QuarantineRegistry, Reporter, SimulationTicket, TrustError,
    TxIntent, UserHardwareAuthorization, WalletCore,
};

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

fn chain(chain_id: ChainId) -> EntityRef {
    EntityRef::Chain { chain_id }
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
        reason_code: "honeypot".into(),
        evidence_refs: vec!["incident://fixture/1".into()],
    }
}

/// Three wallets, one registry: an agent's report must deny the others immediately.
#[test]
fn one_agent_report_denies_every_linked_wallet() {
    let registry = Arc::new(InMemoryQuarantineRegistry::new());
    let agent_a = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));
    let agent_b = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));
    let user_wallet = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));

    registry
        .publish(
            Reporter::Agent {
                agent_id: "agent-a".into(),
            },
            evidence(token("0xbad")),
        )
        .expect("report accepted");

    for (label, core) in [("agent-b", &agent_b), ("user", &user_wallet)] {
        let outcome = core.simulate(intent(label, vec![token("0xbad")]));
        assert!(
            matches!(outcome, Err(TrustError::Quarantined { .. })),
            "{label} was not denied"
        );
    }

    // The reporter is not exempt either.
    assert!(matches!(
        agent_a.simulate(intent("agent-a", vec![token("0xbad")])),
        Err(TrustError::Quarantined { .. })
    ));
}

/// An agent wallet created after the report inherits the deny state at admission.
#[test]
fn newly_created_agent_inherits_active_quarantine() {
    let registry = Arc::new(InMemoryQuarantineRegistry::new());
    registry
        .publish(
            Reporter::User {
                identity: "alice".into(),
            },
            evidence(token("0xbad")),
        )
        .expect("report accepted");

    let fresh_agent = WalletCore::new(registry, Arc::new(DeterministicTestSigner));
    assert!(matches!(
        fresh_agent.simulate(intent("fresh", vec![token("0xbad")])),
        Err(TrustError::Quarantined { .. })
    ));
}

/// A chain-scope quarantine denies any footprint that names that chain.
#[test]
fn chain_scope_quarantine_blocks_all_operations_on_that_chain() {
    let registry = Arc::new(InMemoryQuarantineRegistry::new());
    let core = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));

    registry
        .publish(
            Reporter::Agent {
                agent_id: "agent-a".into(),
            },
            evidence(chain(1)),
        )
        .expect("report accepted");

    let mut tx = intent("chain-wide", vec![token("0xgood"), chain(1)]);
    tx.operation = OperationKind::Bridge;
    assert!(matches!(
        core.simulate(tx),
        Err(TrustError::Quarantined { .. })
    ));
}

/// Unquarantine does not resurrect a ticket issued before the reversal.
#[test]
fn reversal_requires_a_fresh_ticket() {
    let registry = Arc::new(InMemoryQuarantineRegistry::new());
    let core = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));

    let ticket = core
        .simulate(intent("pre-reversal", vec![token("0xgood")]))
        .expect("simulation allowed");

    let record = registry
        .publish(
            Reporter::Agent {
                agent_id: "agent-a".into(),
            },
            evidence(token("0xbad")),
        )
        .expect("report accepted");
    assert!(matches!(
        core.sign(ticket.clone()),
        Err(TrustError::StaleRegistry { .. })
    ));

    registry
        .reverse(
            UserHardwareAuthorization {
                identity: "alice".into(),
                hardware_assertion: "hw-proof".into(),
            },
            record.quarantine_id,
        )
        .expect("user reversal accepted");

    // Still stale: the ticket predates the reversal version.
    assert!(matches!(
        core.sign(ticket),
        Err(TrustError::StaleRegistry { .. })
    ));

    // A fresh ticket is required and now succeeds.
    let fresh = core
        .simulate(intent("post-reversal", vec![token("0xgood")]))
        .expect("simulation allowed after reversal");
    assert!(core.sign(fresh).is_ok());
}

/// Signed approvals must be rechecked at broadcast, not only at simulation.
#[test]
fn approval_quarantined_between_sign_and_broadcast_is_withheld() {
    let registry = Arc::new(InMemoryQuarantineRegistry::new());
    let core = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));

    let mut tx = intent("approve", vec![token("0xasset"), contract("0xspender")]);
    tx.operation = OperationKind::Approval;
    let signed = core
        .sign(core.simulate(tx).expect("simulation allowed"))
        .expect("signing allowed");

    registry
        .publish(
            Reporter::Agent {
                agent_id: "agent-b".into(),
            },
            evidence(contract("0xspender")),
        )
        .expect("report accepted");

    assert!(matches!(
        core.broadcast(signed),
        Err(TrustError::StaleRegistry { .. })
    ));
}

/// Strategy-family quarantine applies to a footprint naming that family.
#[test]
fn strategy_family_quarantine_blocks_template_execution() {
    let registry = Arc::new(InMemoryQuarantineRegistry::new());
    let core = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));
    let family = EntityRef::StrategyFamily {
        name: "momentum-v3".into(),
    };

    registry
        .publish(
            Reporter::User {
                identity: "alice".into(),
            },
            evidence(family.clone()),
        )
        .expect("report accepted");

    let mut tx = intent("strategy-run", vec![token("0xasset"), family]);
    tx.operation = OperationKind::StrategyExecution;
    assert!(matches!(
        core.simulate(tx),
        Err(TrustError::Quarantined { .. })
    ));
}

/// Invalid evidence must never create a deny entry or bump the version.
#[test]
fn invalid_evidence_is_rejected_without_version_change() {
    let registry = InMemoryQuarantineRegistry::new();
    let before = registry.current_version().expect("registry readable");

    let outcome = registry.publish(
        Reporter::Agent {
            agent_id: "agent-a".into(),
        },
        QuarantineEvidence {
            entity: token("0xbad"),
            reason_code: "".into(),
            evidence_refs: vec![],
        },
    );

    assert!(outcome.is_err());
    assert_eq!(
        registry.current_version().expect("registry readable"),
        before
    );
}

/// Reversing an unknown record fails without bumping the version.
#[test]
fn unknown_quarantine_id_does_not_bump_version() {
    let registry = InMemoryQuarantineRegistry::new();
    let before = registry.current_version().expect("registry readable");

    let outcome = registry.reverse(
        UserHardwareAuthorization {
            identity: "alice".into(),
            hardware_assertion: "hw-proof".into(),
        },
        9_999,
    );

    assert!(outcome.is_err());
    assert_eq!(
        registry.current_version().expect("registry readable"),
        before
    );
}

/// A ticket from a different registry version cannot be signed at all.
#[test]
fn forged_ticket_version_is_rejected() {
    let registry = Arc::new(InMemoryQuarantineRegistry::new());
    let core = WalletCore::new(registry.clone(), Arc::new(DeterministicTestSigner));

    let ticket: SimulationTicket = SimulationTicket {
        intent: intent("forged", vec![token("0xgood")]),
        registry_version: 42,
        simulation_hash: "simulation:forged".into(),
    };

    assert!(matches!(
        core.sign(ticket),
        Err(TrustError::StaleRegistry {
            ticket: 42,
            current: 0
        })
    ));
}
