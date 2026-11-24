#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/fixtures/bwau/evm_simulation_ticket_v1.json"
socket_path="$(mktemp -u /tmp/wall3t-wallet-core.XXXXXX.sock)"
replay_path="$(mktemp /tmp/wall3t-wallet-core-replay.XXXXXX)"
rm -f "$replay_path" "$socket_path"
service_pid=""
cleanup() {
  if [[ -n "$service_pid" ]]; then kill "$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true; fi
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
"$repo_root/rust/target/debug/wallet_core_socket" "$socket_path" "$signer" "$key_id" "$public_key" "$replay_path" 1700000000 &
service_pid=$!
for _ in $(seq 1 50); do [[ -S "$socket_path" ]] && break; sleep 0.02; done
[[ -S "$socket_path" ]] || { echo "socket service did not start" >&2; exit 1; }

cd "$repo_root/elixir/wall3t_orchestrator"
export WALL3T_SOCKET_PATH="$socket_path"
export WALL3T_ENVELOPE_HEX="$envelope_hex"
mix run -e '
  envelope = Base.decode16!(System.fetch_env!("WALL3T_ENVELOPE_HEX"), case: :lower)
  socket = System.fetch_env!("WALL3T_SOCKET_PATH")
  {:ok, accepted} = Wall3t.WalletCore.UnixSocketClient.submit(socket, envelope)
  unless accepted == %{kind: 7, payload_bytes: 427, registry_version: 7}, do: raise "unexpected accepted response: #{inspect(accepted)}"
  {:error, replay_reason} = Wall3t.WalletCore.UnixSocketClient.submit(socket, envelope)
  unless String.starts_with?(replay_reason, "replay:"), do: raise "unexpected replay response: #{inspect(replay_reason)}"
  {:error, decode_reason} = Wall3t.WalletCore.UnixSocketClient.submit(socket, <<0>>)
  unless String.starts_with?(decode_reason, "decode:"), do: raise "unexpected decode response: #{inspect(decode_reason)}"
  IO.puts("Elixir -> Rust Unix socket E2E: PASS")
'
