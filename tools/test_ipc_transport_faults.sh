#!/usr/bin/env bash
set -euo pipefail

# Module 2.7 transport fault skeleton.
# This intentionally uses public fixture metadata only and never prints the
# authenticated envelope, signature, replay file, or service stderr.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
socket_path="$(mktemp -u /tmp/wall3t-wallet-core-faults.XXXXXX.sock)"
replay_path="$(mktemp /tmp/wall3t-wallet-core-faults-replay.XXXXXX)"
service_pid=""
read_timeout_seconds=7
rm -f "$socket_path" "$replay_path"

cleanup() {
  if [[ -n "$service_pid" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  rm -f "$socket_path" "$replay_path"
}
trap cleanup EXIT

fixture="$repo_root/fixtures/bwau/evm_simulation_ticket_v1.json"
readarray -t fixture_values < <(python3 - "$fixture" <<'PY'
import json
import sys

fixture = json.load(open(sys.argv[1], encoding="utf-8"))
print(fixture["public_key_hex"])
print(fixture["signer"])
print(fixture["ticket"]["signer_key_id"])
PY
)
public_key="${fixture_values[0]}"
signer="${fixture_values[1]}"
key_id="${fixture_values[2]}"

/home/ubuntu/.cargo/bin/cargo +stable build \
  --manifest-path "$repo_root/rust/Cargo.toml" \
  --bin wallet_core_socket --quiet
binary="$repo_root/rust/target/debug/wallet_core_socket"
"$binary" "$socket_path" "$signer" "$key_id" "$public_key" "$replay_path" \
  1700000000 development >/dev/null 2>&1 &
service_pid=$!

for _ in $(seq 1 100); do
  [[ -S "$socket_path" ]] && break
  if ! kill -0 "$service_pid" 2>/dev/null; then
    echo "socket service failed to start" >&2
    exit 1
  fi
  sleep 0.02
done
[[ -S "$socket_path" ]] || { echo "socket service did not become ready" >&2; exit 1; }

SOCKET_PATH="$socket_path" WAIT_SECONDS="$read_timeout_seconds" python3 <<'PY'
import os
import socket
import struct
import time

path = os.environ["SOCKET_PATH"]
wait_seconds = float(os.environ["WAIT_SECONDS"])


def receive_frame(connection):
    header = b""
    while len(header) < 4:
        chunk = connection.recv(4 - len(header))
        if not chunk:
            raise AssertionError("service closed without a bounded response")
        header += chunk
    length = struct.unpack(">I", header)[0]
    if length == 0 or length > 1024:
        raise AssertionError("unexpected response frame length")
    body = b""
    while len(body) < length:
        chunk = connection.recv(length - len(body))
        if not chunk:
            raise AssertionError("service closed with a truncated response")
        body += chunk
    return body


def partial_header_timeout():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(wait_seconds + 2)
        connection.connect(path)
        connection.sendall(b"\x00")
        time.sleep(wait_seconds)
        response = receive_frame(connection)
        assert response == b"ERR truncated-frame\n", "partial-header response was not bounded"


def partial_payload_timeout():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(wait_seconds + 2)
        connection.connect(path)
        connection.sendall(struct.pack(">I", 32) + b"abc")
        time.sleep(wait_seconds)
        response = receive_frame(connection)
        assert response == b"ERR truncated-frame\n", "partial-payload response was not bounded"


partial_header_timeout()
partial_payload_timeout()
print("Partial header/payload timeout cases: PASS")
PY

# Follow-up cases to add in Module 2.7:
# - Verify a valid client succeeds while another worker is blocked on a partial frame.
# - Verify disconnect during header and payload does not consume a nonce.
# - Verify Rust exit during a request produces a bounded Elixir client error.
# - Verify no captured stderr/output contains BWAU bytes or credentials.
