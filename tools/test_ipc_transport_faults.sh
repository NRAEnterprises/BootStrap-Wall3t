#!/usr/bin/env bash
set -euo pipefail

# Module 2.7 transport fault acceptance cases. This uses only public fixture
# metadata and never prints the authenticated envelope, signature, replay file,
# credentials, or service stderr.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
socket_path="$(mktemp -u /tmp/wall3t-wallet-core-faults.XXXXXX.sock)"
replay_path="$(mktemp /tmp/wall3t-wallet-core-faults-replay.XXXXXX)"
marker_path="$(mktemp /tmp/wall3t-wallet-core-faults-marker.XXXXXX)"
saturation_marker_path="$(mktemp /tmp/wall3t-wallet-core-faults-saturation.XXXXXX)"
service_log="$(mktemp /tmp/wall3t-wallet-core-faults-log.XXXXXX)"
path_test_root="$(mktemp -d /tmp/wall3t-wallet-core-paths.XXXXXX)"
service_pid=""
read_timeout_seconds=7
rm -f "$socket_path" "$replay_path" "$marker_path" "$saturation_marker_path" "$service_log"

cleanup() {
  if [[ -n "$service_pid" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  rm -f "$socket_path" "$replay_path" "$marker_path" "$saturation_marker_path" "$service_log"
  rm -rf "$path_test_root"
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
print(fixture["envelope_hex"])
PY
)
public_key="${fixture_values[0]}"
signer="${fixture_values[1]}"
key_id="${fixture_values[2]}"
envelope_hex="${fixture_values[3]}"

/home/ubuntu/.cargo/bin/cargo +stable build \
  --manifest-path "$repo_root/rust/Cargo.toml" \
  --bin wallet_core_socket --quiet
binary="$repo_root/rust/target/debug/wallet_core_socket"

start_service() {
  "$binary" "$socket_path" "$signer" "$key_id" "$public_key" "$replay_path" \
    1700000000 development >>"$service_log" 2>&1 &
  service_pid=$!
  for _ in $(seq 1 100); do
    [[ -S "$socket_path" ]] && return 0
    if ! kill -0 "$service_pid" 2>/dev/null; then
      echo "socket service failed to start" >&2
      return 1
    fi
    sleep 0.02
  done
  echo "socket service did not become ready" >&2
  return 1
}

stop_service() {
  if [[ -n "$service_pid" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
    service_pid=""
  fi
  rm -f "$socket_path"
}

submit_valid() {
  cd "$repo_root/elixir/wall3t_orchestrator"
  WALL3T_SOCKET_PATH="$socket_path" WALL3T_ENVELOPE_HEX="$envelope_hex" mix run -e '
    envelope = Base.decode16!(System.fetch_env!("WALL3T_ENVELOPE_HEX"), case: :lower)
    socket = System.fetch_env!("WALL3T_SOCKET_PATH")
    case Wall3t.WalletCore.UnixSocketClient.submit(socket, envelope) do
      {:ok, %{kind: 7, payload_bytes: 427, registry_version: 7}} -> IO.puts("valid request: PASS")
      other -> raise "unexpected bounded response: #{inspect(other)}"
    end
  '
}

submit_health() {
  cd "$repo_root/elixir/wall3t_orchestrator"
  WALL3T_SOCKET_PATH="$socket_path" mix run -e '
    socket = System.fetch_env!("WALL3T_SOCKET_PATH")
    case Wall3t.WalletCore.UnixSocketClient.health(socket) do
      {:ok, %{state_flags: 0x1F, protocol_epoch: 1}} -> IO.puts("concurrent health request: PASS")
      other -> raise "unexpected health response during saturation: #{inspect(other)}"
    end
  '
}

start_service

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
        assert receive_frame(connection) == b"ERR truncated-frame\n"


def partial_payload_timeout():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(wait_seconds + 2)
        connection.connect(path)
        connection.sendall(struct.pack(">I", 32) + b"abc")
        time.sleep(wait_seconds)
        assert receive_frame(connection) == b"ERR truncated-frame\n"


partial_header_timeout()
partial_payload_timeout()
PY
printf '%s\n' 'Partial header/payload timeout cases: PASS'

# Disconnect before header and during payload must not stop the endpoint.
SOCKET_PATH="$socket_path" python3 <<'PY'
import os
import socket

path = os.environ["SOCKET_PATH"]
for payload in (b"\x00", b"\x00\x00\x00\x20abc"):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(path)
    connection.sendall(payload)
    connection.close()
PY
kill -0 "$service_pid"
printf '%s\n' 'Disconnect before/during frame: PASS'

# Path substitutions must fail closed without deleting or replacing the
# attacker-controlled object. These checks exercise the same startup path used
# by pathname-bound development/test sockets; production uses systemd FD 3.
run_rejected_path() {
  local candidate="$1"
  local status
  set +e
  "$binary" "$candidate" "$signer" "$key_id" "$public_key" "$replay_path" \
    1700000000 development >>"$service_log" 2>&1
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || { echo "unsafe socket path was accepted: $candidate" >&2; exit 1; }
}

mkdir -p "$path_test_root/target" "$path_test_root/regular-parent" "$path_test_root/unsafe-parent"
printf '%s\n' 'not a directory' >"$path_test_root/regular-parent/file"
ln -s "$path_test_root/target" "$path_test_root/symlink-parent"
chmod 0777 "$path_test_root/unsafe-parent"
run_rejected_path "$path_test_root/symlink-parent/rejected.sock"
[[ -L "$path_test_root/symlink-parent" && ! -e "$path_test_root/symlink-parent/rejected.sock" ]]
run_rejected_path "$path_test_root/regular-parent/file/rejected.sock"
run_rejected_path "$path_test_root/unsafe-parent/rejected.sock"
run_rejected_path "$path_test_root/target/../rejected.sock"
mkdir "$path_test_root/existing-directory.sock"
run_rejected_path "$path_test_root/existing-directory.sock"
printf 'existing regular file' >"$path_test_root/existing-file.sock"
run_rejected_path "$path_test_root/existing-file.sock"
printf '%s\n' 'Path substitution cases (symlink/file/directory/traversal/unsafe parent): PASS'

# Occupy all workers with partial frames. An authenticated health client is
# submitted concurrently to prove unrelated traffic remains serviceable.
SOCKET_PATH="$socket_path" SATURATION_MARKER_PATH="$saturation_marker_path" python3 <<'PY' &
import os
import socket
import time

path = os.environ["SOCKET_PATH"]
marker = os.environ["SATURATION_MARKER_PATH"]
connections = []
try:
    for _ in range(4):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(1)
        connection.connect(path)
        connection.sendall(b"\x00")
        connections.append(connection)
    with open(marker, "w", encoding="ascii") as ready:
        ready.write("ready")
    time.sleep(3)
finally:
    for connection in connections:
        connection.close()
PY
saturation_pid=$!
for _ in $(seq 1 100); do [[ -s "$saturation_marker_path" ]] && break; sleep 0.02; done
[[ -s "$saturation_marker_path" ]] || { echo "saturation clients did not connect" >&2; exit 1; }
submit_health
wait "$saturation_pid"

# Now fill the bounded queue as well. The excess connection is dropped rather
# than blocking the listener; process liveness is the bounded-behavior check.
SOCKET_PATH="$socket_path" python3 <<'PY'
import os
import socket
import time

path = os.environ["SOCKET_PATH"]
connections = []
try:
    for _ in range(21):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(1)
        connection.connect(path)
        connection.sendall(b"\x00")
        connections.append(connection)
    time.sleep(1)
finally:
    for connection in connections:
        connection.close()
PY
kill -0 "$service_pid"
printf '%s\n' 'Worker/queue saturation remains bounded and authenticated health traffic remains serviceable: PASS'

# Kill Rust while a request is incomplete. The client must observe closure;
# restarting with the same replay journal must then accept the valid envelope.
rm -f "$marker_path"
SOCKET_PATH="$socket_path" MARKER_PATH="$marker_path" python3 - <<'PY' &
import os
import socket

try:
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.connect(os.environ["SOCKET_PATH"])
    connection.sendall(b"\x00")
    response = connection.recv(1)
    result = "closed" if response == b"" else "unexpected response"
except (ConnectionResetError, BrokenPipeError, OSError):
    result = "closed"
finally:
    with open(os.environ["MARKER_PATH"], "w", encoding="ascii") as marker:
        marker.write(result)
PY
client_pid=$!
sleep 0.5
kill "$service_pid"
wait "$service_pid" 2>/dev/null || true
wait "$client_pid" 2>/dev/null || true
[[ "$(cat "$marker_path")" == "closed" ]]
printf '%s\n' 'Rust exit during incomplete request: PASS'

rm -f "$socket_path"
stop_service
start_service
submit_valid
stop_service
if grep -Fq "$envelope_hex" "$service_log" || grep -Fq "$public_key" "$service_log"; then
  echo "secret-bearing material appeared in the service log" >&2
  exit 1
fi
printf '%s\n' 'Secret-free service log review: PASS'
printf '%s\n' 'Restart/recovery after Rust exit: PASS'
