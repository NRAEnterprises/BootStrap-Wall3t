#!/usr/bin/env bash
set -euo pipefail

# Disposable production-shaped rollback drill. It never touches the approved
# wall3t units, identities, runtime paths, or live-chain state.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/fixtures/bwau/evm_simulation_ticket_v1.json"
run_as=(sudo -n)
suffix="$$"
unit_prefix="wall3t-rollback-$suffix"
group="w3rbipc-$suffix"
core_user="w3rbcore-$suffix"
orch_user="w3rborch-$suffix"
runtime="/run/$unit_prefix"
state="/var/lib/$unit_prefix"
artifact_dir="/usr/local/libexec/$unit_prefix"
socket_path="$runtime/wallet-core/wallet-core.sock"
socket_unit="$unit_prefix.socket"
service_unit="$unit_prefix.service"
replay_path="$state/replay.bwnr"
active_binary="$artifact_dir/active_wallet_core"
previous_binary="$artifact_dir/previous_wallet_core"
failed_binary="$artifact_dir/failed_wallet_core"
readiness="$artifact_dir/readiness"
env_file="$runtime/wallet-core.env"

cleanup() {
  set +e
  "${run_as[@]}" systemctl stop "$service_unit" "$socket_unit" >/dev/null 2>&1
  "${run_as[@]}" systemctl reset-failed "$service_unit" "$socket_unit" >/dev/null 2>&1
  "${run_as[@]}" rm -f "/run/systemd/system/$socket_unit" "/run/systemd/system/$service_unit"
  "${run_as[@]}" systemctl daemon-reload >/dev/null 2>&1
  "${run_as[@]}" userdel "$orch_user" >/dev/null 2>&1
  "${run_as[@]}" userdel "$core_user" >/dev/null 2>&1
  "${run_as[@]}" groupdel "$group" >/dev/null 2>&1
  "${run_as[@]}" rm -rf "$runtime" "$state" "$artifact_dir"
}
trap cleanup EXIT

command -v systemctl >/dev/null
command -v systemd-analyze >/dev/null
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

"${run_as[@]}" groupadd --system "$group"
group_gid="$(getent group "$group" | cut -d: -f3)"
"${run_as[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$group" "$core_user"
"${run_as[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$group" "$orch_user"
orch_uid="$(id -u "$orch_user")"

"${run_as[@]}" install -d -o root -g "$group" -m 0750 "$runtime"
"${run_as[@]}" install -d -o root -g "$group" -m 2750 "$runtime/wallet-core"
"${run_as[@]}" install -d -o "$core_user" -g "$group" -m 0700 "$state"
"${run_as[@]}" install -d -o root -g root -m 0755 "$artifact_dir"
"${run_as[@]}" install -o root -g root -m 0755 "$repo_root/rust/target/debug/wallet_core_socket" "$previous_binary"
"${run_as[@]}" cp "$previous_binary" "$active_binary"
"${run_as[@]}" cp "$previous_binary" "$failed_binary"
"${run_as[@]}" install -o root -g root -m 0755 "$repo_root/deploy/systemd/wall3t-wallet-core-readiness" "$readiness"
"${run_as[@]}" sh -c "printf '%s\\n' 'WALL3T_CORE_KEY_ID=$key_id' 'WALL3T_CORE_PUBLIC_KEY_HEX=$public_key' > '$env_file'"
"${run_as[@]}" chown root:"$group" "$env_file"
"${run_as[@]}" chmod 0640 "$env_file"

write_service() {
  local binary_path="$1"
  cat > "/tmp/$service_unit" <<EOF
[Unit]
Description=BootStrap Wall3t disposable rollback drill
Requires=$socket_unit
After=$socket_unit

[Service]
Type=simple
User=$core_user
Group=$group
UMask=0077
WorkingDirectory=$state
ExecStart=$binary_path $socket_path $signer \${WALL3T_CORE_KEY_ID} \${WALL3T_CORE_PUBLIC_KEY_HEX} $replay_path 1700000000 production:$orch_uid:$group_gid
EnvironmentFile=$env_file
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=$state
ExecStartPost=$readiness $socket_path $core_user $group 660
Restart=no
EOF
  "${run_as[@]}" install -o root -g root -m 0644 "/tmp/$service_unit" "/run/systemd/system/$service_unit"
  rm -f "/tmp/$service_unit"
  "${run_as[@]}" systemctl daemon-reload
}

cat > "/tmp/$socket_unit" <<EOF
[Unit]
Description=BootStrap Wall3t disposable rollback socket

[Socket]
ListenStream=$socket_path
SocketUser=$core_user
SocketGroup=$group
SocketMode=0660
Accept=no
RemoveOnStop=yes
Service=$service_unit
EOF
"${run_as[@]}" install -o root -g root -m 0644 "/tmp/$socket_unit" "/run/systemd/system/$socket_unit"
rm -f "/tmp/$socket_unit"
write_service "$active_binary"
systemd-analyze verify "/run/systemd/system/$socket_unit" "/run/systemd/system/$service_unit"

submit() {
  local expected="$1"
  "${run_as[@]}" -u "$orch_user" -g "$group" -- python3 - "$socket_path" "$envelope_hex" "$expected" <<'PY'
import socket, struct, sys
path, envelope_hex, expected = sys.argv[1:]
payload = bytes.fromhex(envelope_hex)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect(path)
    sock.sendall(struct.pack(">I", len(payload)) + payload)
    header = sock.recv(4)
    if len(header) != 4:
        raise SystemExit("missing response header")
    length = struct.unpack(">I", header)[0]
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            raise SystemExit("truncated response")
        body += chunk
    text = body.decode("ascii")
    if not text.startswith(expected):
        raise SystemExit(f"unexpected response class: {text[:80]!r}")
    print(text, end="")
PY
}

# Baseline release: consume a valid nonce and capture journal integrity.
"${run_as[@]}" systemctl start "$socket_unit"
"${run_as[@]}" systemctl start "$service_unit"
"${run_as[@]}" systemctl is-active --quiet "$service_unit"
submit 'OK kind=7 payload_bytes=427 registry_version=7' >/dev/null
before_hash="$("${run_as[@]}" sha256sum "$replay_path" | cut -d' ' -f1)"

# Simulate a failed upgrade: stop the service, install a broken candidate unit,
# and verify the candidate cannot become ready or consume/reset replay state.
"${run_as[@]}" systemctl stop "$service_unit"
write_service "$artifact_dir/does-not-exist"
if "${run_as[@]}" systemctl start "$service_unit" >/dev/null 2>&1; then
  echo 'failed upgrade unexpectedly started' >&2
  exit 1
fi
"${run_as[@]}" systemctl stop "$socket_unit" >/dev/null 2>&1 || true
"${run_as[@]}" test ! -e "$socket_path"
after_failed_hash="$("${run_as[@]}" sha256sum "$replay_path" | cut -d' ' -f1)"
test "$before_hash" = "$after_failed_hash"

# Roll back to the previous approved binary and unit, retaining the same journal.
write_service "$previous_binary"
"${run_as[@]}" systemctl start "$socket_unit"
"${run_as[@]}" systemctl start "$service_unit"
"${run_as[@]}" systemctl is-active --quiet "$service_unit"
submit 'ERR replay:' >/dev/null
rollback_hash="$("${run_as[@]}" sha256sum "$replay_path" | cut -d' ' -f1)"
test "$before_hash" = "$rollback_hash"

printf '%s\n' 'systemd production rollback drill: PASS'
printf 'journal_sha256=%s\n' "$rollback_hash"
printf '%s\n' 'failed candidate was rejected; previous release restored; consumed nonce remained denied'
