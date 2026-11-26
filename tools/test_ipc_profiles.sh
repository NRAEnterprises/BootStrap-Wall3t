#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/fixtures/bwau/evm_simulation_ticket_v1.json"
socket_path="$(mktemp -u /tmp/wall3t-wallet-core-profile.XXXXXX.sock)"
replay_path="$(mktemp /tmp/wall3t-wallet-core-profile-replay.XXXXXX)"
service_pid=""
rm -f "$socket_path" "$replay_path"
cleanup() {
  if [[ -n "$service_pid" ]]; then
    kill "$service_pid" 2>/dev/null || true
    wait "$service_pid" 2>/dev/null || true
  fi
  rm -f "$socket_path" "$replay_path"
}
trap cleanup EXIT

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
binary="$repo_root/rust/target/debug/wallet_core_socket"
current_uid="$EUID"
current_gid="$(id -g)"

start_service() {
  local profile="$1"
  "$binary" "$socket_path" "$signer" "$key_id" "$public_key" "$replay_path" 1700000000 "$profile" &
  service_pid=$!
  for _ in $(seq 1 50); do
    [[ -S "$socket_path" ]] && return 0
    if ! kill -0 "$service_pid" 2>/dev/null; then
      wait "$service_pid" || true
      return 1
    fi
    sleep 0.02
  done
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

submit() {
  cd "$repo_root/elixir/wall3t_orchestrator"
  WALL3T_SOCKET_PATH="$socket_path" WALL3T_ENVELOPE_HEX="$envelope_hex" mix run -e '
    envelope = Base.decode16!(System.fetch_env!("WALL3T_ENVELOPE_HEX"), case: :lower)
    socket = System.fetch_env!("WALL3T_SOCKET_PATH")
    case Wall3t.WalletCore.UnixSocketClient.submit(socket, envelope) do
      {:ok, response} -> IO.puts("OK #{inspect(response)}")
      {:error, reason} -> IO.puts("ERR #{reason}")
    end
  '
}

# Unknown profiles fail before a socket is exposed.
if "$binary" "$socket_path" "$signer" "$key_id" "$public_key" "$replay_path" 1700000000 unknown >/dev/null 2>&1; then
  echo "unknown IPC profile unexpectedly started" >&2
  exit 1
fi
[[ ! -e "$socket_path" ]]

# A production profile with the wrong peer UID rejects before BWAU decoding.
start_service "production:$((current_uid + 1)):$current_gid"
[[ "$(stat -c '%a' "$socket_path")" == "660" ]]
unauthorized="$(submit)"
grep -q '^ERR peer:peer uid is not authorized' <<<"$unauthorized"
stop_service

# The matching production peer is accepted and the previously rejected nonce is usable.
start_service "production:$current_uid:$current_gid"
accepted="$(submit)"
grep -q '^OK %{kind: 7, payload_bytes: 427, registry_version: 7}$' <<<"$accepted"
stop_service

# A production profile whose expected group cannot match the bound socket fails closed.
if "$binary" "$socket_path" "$signer" "$key_id" "$public_key" "$replay_path" 1700000000 "production:$current_uid:$((current_gid + 1))" >/dev/null 2>&1; then
  echo "mismatched production group unexpectedly started" >&2
  exit 1
fi
[[ ! -e "$socket_path" ]]

echo "Typed IPC profiles and peer credentials: PASS"
