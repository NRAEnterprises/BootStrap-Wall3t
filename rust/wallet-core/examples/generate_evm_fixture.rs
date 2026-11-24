use std::fmt::Write;

use wallet_core::domain::{AgentWalletId, CapabilityId, DocumentHash, PolicyId};
use wallet_core::evm_intent::{
    EvmAddress, EvmFeePolicy, EvmOperation, EvmTransactionIntent, IntentId, PrincipalBinding, U256,
};
use wallet_core::{EntityRef};

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes { write!(&mut out, "{byte:02x}").unwrap(); }
    out
}

fn fixture() -> EvmTransactionIntent {
    let mut footprint = vec![
        EntityRef::Wallet { chain_id: 1, address: "1111111111111111111111111111111111111111".into() },
        EntityRef::Contract { chain_id: 1, address: "2222222222222222222222222222222222222222".into() },
        EntityRef::Chain { chain_id: 1 },
    ];
    footprint.sort();
    EvmTransactionIntent {
        intent_id: IntentId::new("fixture-intent-1").unwrap(),
        wallet_id: "wallet-fixture-1".into(),
        principal: PrincipalBinding::Agent { agent_id: AgentWalletId::new("agent-fixture-1").unwrap() },
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
        calldata: vec![0xaa, 0xbb, 0xcc],
        deployment: None,
        policy_id: PolicyId::new("policy-fixture-1").unwrap(),
        capability_id: CapabilityId::new("cap-fixture-1").unwrap(),
        document_hash: DocumentHash::new("doc-fixture-1").unwrap(),
        footprint,
        not_before_unix: 1_700_000_000,
        expires_at_unix: 1_700_000_600,
    }
}

fn main() {
    let intent = fixture();
    let bytes = intent.try_canonical_bytes().unwrap();
    let digest = intent.intent_digest().unwrap();
    println!("{{");
    println!("  \"schema\": \"bootstrap-wall3t/bw3c-evm-fixture-v1\",");
    println!("  \"wire_version\": 1,");
    println!("  \"record_kind\": 7,");
    println!("  \"intent_digest_sha256\": \"{}\",", hex(&digest));
    println!("  \"canonical_bytes_hex\": \"{}\",", hex(&bytes));
    println!("  \"fields\": {{");
    println!("    \"intent_id\": \"fixture-intent-1\",");
    println!("    \"wallet_id\": \"wallet-fixture-1\",");
    println!("    \"principal\": {{\"kind\": \"agent\", \"agent_id\": \"agent-fixture-1\"}},");
    println!("    \"operation\": \"contract_call\",");
    println!("    \"chain_id\": 1,");
    println!("    \"from\": \"1111111111111111111111111111111111111111\",");
    println!("    \"to\": \"2222222222222222222222222222222222222222\",");
    println!("    \"nonce\": 7,");
    println!("    \"value\": \"9\",");
    println!("    \"gas_limit\": 100000,");
    println!("    \"fee\": {{\"kind\": \"eip1559\", \"max_fee_per_gas\": \"2\", \"max_priority_fee_per_gas\": \"1\"}},");
    println!("    \"calldata_hex\": \"aabbcc\",");
    println!("    \"policy_id\": \"policy-fixture-1\",");
    println!("    \"capability_id\": \"cap-fixture-1\",");
    println!("    \"document_hash\": \"doc-fixture-1\",");
    println!("    \"footprint\": [");
    println!("      {{\"kind\": \"contract\", \"chain_id\": 1, \"address\": \"2222222222222222222222222222222222222222\"}},");
    println!("      {{\"kind\": \"chain\", \"chain_id\": 1}},");
    println!("      {{\"kind\": \"wallet\", \"chain_id\": 1, \"address\": \"1111111111111111111111111111111111111111\"}}");
    println!("    ],");
    println!("    \"not_before_unix\": 1700000000,");
    println!("    \"expires_at_unix\": 1700000600");
    println!("  }}");
    println!("}}");
}
