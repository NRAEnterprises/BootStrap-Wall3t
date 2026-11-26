#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/fixtures/bwau/evm_simulation_ticket_v1.json"
binary="$repo_root/rust/target/debug/wallet_core_socket"
run_as=(sudo -n)
suffix="$$"
group="wall3t-ipc-$suffix"
core_user="wall3t-core-$suffix"
orch_user="wall3t-orch-$suffix"
attacker_user="wall3t-attacker-$suffix"
parent="/tmp/wall3t-ipc-$suffix"
socket_path="$parent/wallet-core.sock"
state_path="$parent/state"
replay_path="$state_path/replay.bwnr"
service_binary="$parent/wallet_core_socket"
service_err="/tmp/wall3t-ipc-$suffix.err"
service_pid=""

cleanup() {
  if [[ -n "$service_pid" ]]; then
    "${run_as[@]}" kill "$service_pid" 2>/dev/null || true
  fi
  "${run_as[@]}" pkill -TERM -u "$core_user" 2>/dev/null || true
  "${run_as[@]}" userdel "$attacker_user" 2>/dev/null || true
  "${run_as[@]}" userdel "$orch_user" 2>/dev/null || true
  "${run_as[@]}" userdel "$core_user" 2>/dev/null || true
  "${run_as[@]}" groupdel "$group" 2>/dev/null || true
  "${run_as[@]}" rm -rf "$parent"
  rm -f "$service_err"
}
trap cleanup EXIT

command -v sudo >/dev/null
sudo -n true
public_key="$(python3 - "$fixture" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["public_key_hex"])
PY
)"
signer="$(python3 - "$fixture" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["signer"])
PY
)"
key_id="$(python3 - "$fixture" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["ticket"]["signer_key_id"])
PY
)"
envelope_hex="$(python3 - "$fixture" <<'PY'
import json, sys
print(json.load(open(sys.argv[1]))["envelope_hex"])
PY
)"

/home/ubuntu/.cargo/bin/cargo +stable build --manifest-path "$repo_root/rust/Cargo.toml" --bin wallet_core_socket --quiet

"${run_as[@]}" groupadd --system "$group"
group_gid="$(getent group "$group" | cut -d: -f3)"
"${run_as[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$group" "$core_user"
"${run_as[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$group" "$orch_user"
"${run_as[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$group" "$attacker_user"
core_uid="$(id -u "$core_user")"
orch_uid="$(id -u "$orch_user")"

"${run_as[@]}" install -d -o "$core_user" -g "$group" -m 2750 "$parent"
"${run_as[@]}" install -d -o "$core_user" -g "$group" -m 0750 "$state_path"
"${run_as[@]}" install -o root -g "$group" -m 0750 "$binary" "$service_binary"
"${run_as[@]}" setpriv --reuid="$core_uid" --regid="$group_gid" --init-groups -- "$service_binary" "$socket_path" "$signer" "$key_id" "$public_key" "$replay_path" 1700000000 "production:$orch_uid:$group_gid" 2>"$service_err" &
service_pid=$!
for _ in $(seq 1 1000); do
  "${run_as[@]}" test -S "$socket_path" && break
  if ! kill -0 "$service_pid" 2>/dev/null; then
    cat "$service_err" >&2 || true
    wait "$service_pid" || true
    echo "production IPC service failed to start" >&2
    exit 1
  fi
  sleep 0.02
done
"${run_as[@]}" test -S "$socket_path"
[[ "$(${run_as[*]} stat -c '%a' "$socket_path")" == "660" ]]
[[ "$(${run_as[*]} stat -c '%u' "$socket_path")" == "$core_uid" ]]
[[ "$(${run_as[*]} stat -c '%g' "$socket_path")" == "$group_gid" ]]

python_client() {
  local account="$1"
  local account_uid
  account_uid="$(id -u "$account")"
  "${run_as[@]}" setpriv --reuid="$account_uid" --regid="$group_gid" --init-groups -- python3 - "$socket_path" "$envelope_hex" <<'PY'
import socket, struct, sys
path, envelope_hex = sys.argv[1:]
payload = bytes.fromhex(envelope_hex)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect(path)
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    header = sock.recv(4)
    if len(header) != 4:
        raise SystemExit("missing response header")
    length = struct.unpack(">I", header)[0]
    response = b""
    while len(response) < length:
        chunk = sock.recv(length - len(response))
        if not chunk:
            raise SystemExit("truncated response")
        response += chunk
    print(response.decode("ascii"), end="")
PY
}

[[ "$(python_client "$orch_user")" == "OK kind=7 payload_bytes=427 registry_version=7"* ]]
[[ "$(python_client "$attacker_user")" == "ERR peer:peer uid is not authorized"* ]]

echo "Split-account production IPC policy: PASS"
