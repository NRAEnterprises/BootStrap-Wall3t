import hashlib
import json
from pathlib import Path


FIXTURE = Path(__file__).parents[2] / "fixtures/bw3c/evm_transaction_intent_v1.json"


def u16(value): return value.to_bytes(2, "big")
def u32(value): return value.to_bytes(4, "big")
def u64(value): return value.to_bytes(8, "big")
def u256(value): return value.to_bytes(32, "big")
def blob(value): return u32(len(value)) + value
def text(value): return blob(value.encode())


def entity(item):
    kind = item["kind"]
    if kind == "contract": return b"\x02" + u64(item["chain_id"]) + text(item["address"])
    if kind == "chain": return b"\x05" + u64(item["chain_id"])
    if kind == "wallet": return b"\x08" + u64(item["chain_id"]) + text(item["address"])
    raise AssertionError(f"unsupported fixture entity: {kind}")


def encode(fields):
    out = bytearray(b"BW3C" + u16(1) + b"\x07")
    out += text(fields["intent_id"])
    out += text(fields["wallet_id"])
    out += b"\x02" + text(fields["principal"]["agent_id"])
    out += b"\x02" + u64(fields["chain_id"])
    out += bytes.fromhex(fields["from"])
    out += b"\x01" + bytes.fromhex(fields["to"])
    out += u64(fields["nonce"])
    out += u256(int(fields["value"]))
    out += u64(fields["gas_limit"])
    out += b"\x02" + u256(int(fields["fee"]["max_fee_per_gas"])) + u256(int(fields["fee"]["max_priority_fee_per_gas"]))
    out += blob(bytes.fromhex(fields["calldata_hex"]))
    out += b"\x00"
    out += text(fields["policy_id"])
    out += text(fields["capability_id"])
    out += text(fields["document_hash"])
    out += u32(len(fields["footprint"]))
    for item in fields["footprint"]: out += entity(item)
    out += u64(fields["not_before_unix"])
    out += u64(fields["expires_at_unix"])
    return bytes(out)


def test_python_matches_rust_fixture():
    fixture = json.loads(FIXTURE.read_text())
    actual = encode(fixture["fields"])
    assert actual.hex() == fixture["canonical_bytes_hex"]
    assert hashlib.sha256(actual).hexdigest() == fixture["intent_digest_sha256"]
