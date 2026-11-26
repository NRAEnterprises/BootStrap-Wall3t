#!/usr/bin/env bash
set -euo pipefail

# Disposable root-assisted staging verification for the production socket unit.
# It installs transient units under /run/systemd/system, uses dedicated accounts,
# and removes every staging artifact on exit. No private or bearer secret is used.
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$repo_root/fixtures/bwau/evm_simulation_ticket_v1.json"
run_as=(sudo -n)
suffix="$$"
unit_prefix="wall3t-staging-$suffix"
group="w3ipc-$suffix"
core_user="w3core-$suffix"
orch_user="w3orch-$suffix"
attacker_user="w3att-$suffix"
runtime="/run/$unit_prefix"
state="/var/lib/$unit_prefix"
socket_path="$runtime/wallet-core/wallet-core.sock"
artifact_dir="/usr/local/libexec/$unit_prefix"
binary="$artifact_dir/wallet_core_socket"
readiness="$artifact_dir/readiness"
env_file="$runtime/wallet-core.env"
socket_unit="$unit_prefix.socket"
service_unit="$unit_prefix.service"
service_pid=""

cleanup() {
  set +e
  "${run_as[@]}" systemctl stop "$unit_prefix.service" "$unit_prefix.socket" >/dev/null 2>&1
  "${run_as[@]}" systemctl reset-failed "$unit_prefix.service" "$unit_prefix.socket" >/dev/null 2>&1
  "${run_as[@]}" rm -f "/run/systemd/system/$socket_unit" "/run/systemd/system/$service_unit"
  "${run_as[@]}" systemctl daemon-reload >/dev/null 2>&1
  "${run_as[@]}" userdel "$attacker_user" >/dev/null 2>&1
  "${run_as[@]}" userdel "$orch_user" >/dev/null 2>&1
  "${run_as[@]}" userdel "$core_user" >/dev/null 2>&1
  "${run_as[@]}" groupdel "$group" >/dev/null 2>&1
  "${run_as[@]}" rm -rf "$runtime" "$state" "$artifact_dir"
}
trap cleanup EXIT

command -v sudo >/dev/null
sudo -n true
command -v systemctl >/dev/null
command -v systemd-analyze >/dev/null

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
"${run_as[@]}" useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$group" "$attacker_user"
core_uid="$(id -u "$core_user")"
orch_uid="$(id -u "$orch_user")"

"${run_as[@]}" install -d -o root -g "$group" -m 0750 "$runtime"
"${run_as[@]}" install -d -o root -g "$group" -m 2750 "$runtime/wallet-core-parent"
# The production path is intentionally under a root-owned, non-writable parent.
"${run_as[@]}" mv "$runtime/wallet-core-parent" "$runtime/wallet-core"
"${run_as[@]}" install -d -o "$core_user" -g "$group" -m 0700 "$state"
"${run_as[@]}" install -d -o root -g root -m 0755 "$artifact_dir"
"${run_as[@]}" install -o root -g root -m 0755 "$repo_root/rust/target/debug/wallet_core_socket" "$binary"
"${run_as[@]}" install -o root -g root -m 0755 "$repo_root/deploy/systemd/wall3t-wallet-core-readiness" "$readiness"
"${run_as[@]}" sh -c "printf '%s\\n' \
  'WALL3T_CORE_KEY_ID=$key_id' \
  'WALL3T_CORE_PUBLIC_KEY_HEX=$public_key' \
  'WALL3T_ORCHESTRATOR_UID=$orch_uid' \
  'WALL3T_IPC_GID=$group_gid' > '$env_file'"
"${run_as[@]}" chown root:"$group" "$env_file"
"${run_as[@]}" chmod 0640 "$env_file"

cat > "/tmp/$socket_unit" <<EOF
[Unit]
Description=BootStrap Wall3t disposable staging IPC socket

[Socket]
ListenStream=$socket_path
SocketUser=$core_user
SocketGroup=$group
SocketMode=0660
Accept=no
RemoveOnStop=yes
Service=$service_unit

[Install]
WantedBy=sockets.target
EOF
cat > "/tmp/$service_unit" <<EOF
[Unit]
Description=BootStrap Wall3t disposable staging wallet-core
Requires=$socket_unit
After=$socket_unit

[Service]
Type=simple
User=$core_user
Group=$group
UMask=0077
WorkingDirectory=$state
ExecStart=$binary $socket_path $signer \${WALL3T_CORE_KEY_ID} \${WALL3T_CORE_PUBLIC_KEY_HEX} $state/replay.bwnr current production:$orch_uid:$group_gid
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

[Install]
WantedBy=multi-user.target
EOF
"${run_as[@]}" install -o root -g root -m 0644 "/tmp/$socket_unit" "/run/systemd/system/$socket_unit"
"${run_as[@]}" install -o root -g root -m 0644 "/tmp/$service_unit" "/run/systemd/system/$service_unit"
rm -f "/tmp/$socket_unit" "/tmp/$service_unit"
"${run_as[@]}" systemctl daemon-reload
systemd-analyze verify "/run/systemd/system/$socket_unit" "/run/systemd/system/$service_unit"

"${run_as[@]}" systemctl start "$socket_unit"
"${run_as[@]}" test -S "$socket_path"
if ! "${run_as[@]}" systemctl start "$service_unit"; then
  "${run_as[@]}" systemctl status "$service_unit" --no-pager || true
  "${run_as[@]}" journalctl -u "$service_unit" --no-pager -n 40 || true
  exit 1
fi
for _ in $(seq 1 100); do
  if "${run_as[@]}" systemctl is-active --quiet "$service_unit"; then break; fi
  sleep 0.05
done
"${run_as[@]}" systemctl is-active --quiet "$service_unit"
"${run_as[@]}" "$readiness" "$socket_path" "$core_user" "$group" 660

run_client() {
  local account="$1"
  "${run_as[@]}" -u "$account" -g "$group" -- python3 - "$socket_path" "$envelope_hex" <<'PY'
import os
import socket
import struct
import sys

path, envelope_hex = sys.argv[1:]
envelope = bytes.fromhex(envelope_hex)

def send_frame(sock, payload):
    sock.sendall(struct.pack(">I", len(payload)) + payload)

def recv_frame(sock):
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
    return body

def roundtrip(sock, payload):
    send_frame(sock, payload)
    return recv_frame(sock)

def health(sock):
    request_id = os.urandom(16)
    send_frame(sock, b"HREQ" + struct.pack(">H", 1) + request_id + struct.pack(">Q", 2000))
    challenge = recv_frame(sock)
    if len(challenge) != 58 or challenge[:4] != b"HCHL":
        raise SystemExit("invalid health challenge")
    send_frame(sock, b"HACK" + struct.pack(">H", 1) + request_id + challenge[6:38])
    response = recv_frame(sock)
    if len(response) != 50 or response[:4] != b"HOK!":
        raise SystemExit("invalid health response")
    if struct.unpack(">I", response[38:42])[0] != 0x1F:
        raise SystemExit("health flags not ready")

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect(path)
    health(sock)

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect(path)
    response = roundtrip(sock, envelope)
    print(response.decode("ascii"), end="")
PY
}

run_unauthorized() {
  local account="$1"
  "${run_as[@]}" -u "$account" -g "$group" -- python3 - "$socket_path" <<'PY'
import os
import socket
import struct
import sys

path = sys.argv[1]
request_id = os.urandom(16)
request = b"HREQ" + struct.pack(">H", 1) + request_id + struct.pack(">Q", 2000)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
    sock.connect(path)
    sock.sendall(struct.pack(">I", len(request)) + request)
    header = sock.recv(4)
    if len(header) != 4:
        raise SystemExit("missing unauthorized response header")
    length = struct.unpack(">I", header)[0]
    response = sock.recv(length)
    print(response.decode("ascii"), end="")
PY
}

authorized="$(run_client "$orch_user")"
grep -q '^OK kind=7 payload_bytes=427 registry_version=7' <<<"$authorized"
replay="$(run_client "$orch_user")"
grep -q '^ERR ' <<<"$replay"
unauthorized="$(run_unauthorized "$attacker_user")"
grep -q '^ERR ' <<<"$unauthorized"

printf '%s\n' 'systemd socket activation staging: PASS'
printf 'socket=%s owner=%s group=%s mode=%s\n' "$socket_path" "$core_user" "$group" "$("${run_as[@]}" stat -c '%a' "$socket_path")"
