//! Authenticated Unix-domain transport endpoint for the wallet core.
//!
//! Application framing: u32 big-endian length followed by one BWAU envelope.
//! Health framing: the same outer frame with a reserved HREQ/HCHL/HACK/HOK
//! control protocol. Health traffic never enters BWAU decoding or replay.
//! No signing, broadcasting, private keys, or raw secret material cross this socket.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::raw::c_uint;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use wallet_core::authenticated::AuthenticatedEnvelope;
use wallet_core::ipc::{authorize_peer, IpcProfile, TransportConfig};
use wallet_core::key_registry::{KeyAlgorithm, KeyRegistry, RegisteredKey};
use wallet_core::replay::PersistentNonceRegistry;

const MAX_FRAME: usize = 8 * 1024 * 1024;
const MAX_HEALTH_FRAME: usize = 512;
const HEALTH_VERSION: u16 = 1;
const HEALTH_LEASE_LIMIT_MS: u64 = 2_000;
const HEALTH_FLAGS: u32 = 0x1f;
const HEALTH_EPOCH: u64 = 1;
const HREQ_LEN: usize = 30;
const HCHL_LEN: usize = 58;
const HACK_LEN: usize = 54;
const HOK_LEN: usize = 50;
const HERR_LEN: usize = 24;

unsafe extern "C" {
    fn umask(mask: c_uint) -> c_uint;
    fn geteuid() -> c_uint;
    fn getegid() -> c_uint;
}

fn main() {
    if let Err(error) = run() {
        eprintln!("wallet-core socket service: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 8 {
        return Err(format!(
            "usage: {} <socket> <signer> <key-id> <public-key-hex> <replay-file> <now-unix> <ipc-profile>",
            args[0]
        ));
    }
    let socket_path = &args[1];
    let signer = &args[2];
    let key_id = &args[3];
    let public_key = parse_hex_32(&args[4])?;
    let replay_path = &args[5];
    let now_unix = parse_now_unix(&args[6])?;
    let (current_uid, current_gid) = unsafe { (geteuid(), getegid()) };
    let profile = IpcProfile::parse(&args[7], current_uid, current_gid)
        .map_err(|error| format!("IPC profile rejected: {error}"))?;

    let registry = KeyRegistry::new();
    registry
        .register(RegisteredKey {
            key_id: key_id.clone(),
            signer: signer.clone(),
            algorithm: KeyAlgorithm::Ed25519,
            public_key,
            not_before_unix: 0,
            expires_at_unix: None,
            revoked: false,
        })
        .map_err(|error| format!("key registration failed: {error}"))?;
    let replay = PersistentNonceRegistry::open(replay_path)
        .map_err(|error| format!("replay registry failed: {error}"))?;

    let activated = systemd_activation_requested()?;
    let listener = if activated {
        activated_listener(socket_path, profile)?
    } else {
        prepare_socket_path(socket_path)?;
        unsafe { umask(0o077) };
        let listener =
            UnixListener::bind(socket_path).map_err(|_| "cannot bind socket".to_owned())?;
        if let Err(error) = harden_socket_path(socket_path, profile) {
            let _ = fs::remove_file(socket_path);
            return Err(error);
        }
        listener
    };
    let transport = TransportConfig::default()
        .validate()
        .map_err(|error| format!("transport configuration invalid: {error}"))?;
    let server_instance = random_bytes::<16>()?;
    let (sender, receiver) = mpsc::sync_channel::<UnixStream>(transport.queue_capacity);
    let receiver = Arc::new(Mutex::new(receiver));
    let registry = Arc::new(registry);
    let replay = Arc::new(replay);
    for _ in 0..transport.worker_count {
        let receiver = Arc::clone(&receiver);
        let registry = Arc::clone(&registry);
        let replay = Arc::clone(&replay);
        let spawn_result = std::thread::Builder::new()
            .name("wallet-core-ipc".to_owned())
            .spawn(move || {
                worker_loop(
                    receiver,
                    registry,
                    replay,
                    now_unix,
                    profile,
                    transport,
                    server_instance,
                )
            });
        if spawn_result.is_err() {
            if !activated {
                let _ = fs::remove_file(socket_path);
            }
            return Err("cannot spawn IPC worker".to_owned());
        }
    }

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                if sender.try_send(stream).is_err() {
                    continue;
                }
            }
            Err(error) => eprintln!("wallet-core socket accept error: {error}"),
        }
    }
    Ok(())
}

fn systemd_activation_requested() -> Result<bool, String> {
    activation_state(
        env::var("LISTEN_PID").ok().as_deref(),
        env::var("LISTEN_FDS").ok().as_deref(),
        process::id(),
    )
}

fn activation_state(
    listen_pid: Option<&str>,
    listen_fds: Option<&str>,
    process_id: u32,
) -> Result<bool, String> {
    match (listen_pid, listen_fds) {
        (None, None) => Ok(false),
        (Some(pid), Some("1")) if pid.parse::<u32>().ok() == Some(process_id) => Ok(true),
        _ => Err("invalid systemd socket activation environment".to_owned()),
    }
}

fn activated_listener(socket_path: &str, profile: IpcProfile) -> Result<UnixListener, String> {
    if !cfg!(target_os = "linux") {
        return Err("systemd socket activation is supported only on Linux".to_owned());
    }
    let fd: RawFd = 3;
    // LISTEN_PID/LISTEN_FDS were checked above. systemd transfers ownership of
    // fd 3 to this process, so UnixListener owns it after this conversion.
    let listener = unsafe { UnixListener::from_raw_fd(fd) };
    listener
        .set_nonblocking(false)
        .map_err(|_| "cannot configure activated socket".to_owned())?;
    listener
        .local_addr()
        .map_err(|_| "activated fd 3 is not a Unix listener".to_owned())?;
    // PID 1 created and owns the pathname. Validate that node without chmod,
    // unlink, or pathname-bind operations in the Rust service.
    harden_socket_path_metadata(socket_path, profile)?;
    Ok(listener)
}

fn worker_loop(
    receiver: Arc<Mutex<mpsc::Receiver<UnixStream>>>,
    registry: Arc<KeyRegistry>,
    replay: Arc<PersistentNonceRegistry>,
    now_unix: u64,
    profile: IpcProfile,
    transport: TransportConfig,
    server_instance: [u8; 16],
) {
    loop {
        let stream = match receiver
            .lock()
            .expect("IPC worker receiver poisoned")
            .recv()
        {
            Ok(stream) => stream,
            Err(_) => return,
        };
        serve_connection(
            stream,
            &registry,
            &replay,
            now_unix,
            profile,
            transport,
            server_instance,
        );
    }
}

fn serve_connection(
    mut stream: UnixStream,
    registry: &KeyRegistry,
    replay: &PersistentNonceRegistry,
    now_unix: u64,
    profile: IpcProfile,
    transport: TransportConfig,
    server_instance: [u8; 16],
) {
    if stream
        .set_read_timeout(Some(transport.read_timeout))
        .is_err()
        || stream
            .set_write_timeout(Some(transport.write_timeout))
            .is_err()
    {
        return;
    }

    if let Err(error) = authorize_peer(&stream, profile) {
        let _ = write_frame(&mut stream, format!("ERR peer:{error}\n").as_bytes());
        return;
    }
    let request = match read_frame_limited(&mut stream, MAX_FRAME) {
        Ok(bytes) => bytes,
        Err(error) => {
            let _ = write_frame(&mut stream, format!("ERR {error}\n").as_bytes());
            return;
        }
    };
    if request.starts_with(b"HREQ") {
        handle_health(&mut stream, &request, transport, server_instance);
    } else {
        let response = handle_application_request(&request, registry, replay, now_unix);
        let _ = write_frame(&mut stream, response.as_bytes());
    }
}

fn handle_application_request(
    request: &[u8],
    registry: &KeyRegistry,
    replay: &PersistentNonceRegistry,
    now_unix: u64,
) -> String {
    let envelope = match AuthenticatedEnvelope::decode(request) {
        Ok(envelope) => envelope,
        Err(error) => return format!("ERR decode:{error}\n"),
    };
    if let Err(error) = replay.verify_and_consume(&envelope, registry, now_unix) {
        return format!("ERR replay:{error}\n");
    }
    format!(
        "OK kind={} payload_bytes={} registry_version={}\n",
        envelope.kind,
        envelope.payload.len(),
        envelope.context.registry_version
    )
}

fn handle_health(
    stream: &mut UnixStream,
    request: &[u8],
    transport: TransportConfig,
    server_instance: [u8; 16],
) {
    let request_id = request.get(6..22).unwrap_or(&[0u8; 16]);
    let mut request_id_fixed = [0u8; 16];
    if request_id.len() == 16 {
        request_id_fixed.copy_from_slice(request_id);
    }
    let fail = |stream: &mut UnixStream, id: [u8; 16], code: u16| {
        let mut response = Vec::with_capacity(HERR_LEN);
        response.extend_from_slice(b"HERR");
        response.extend_from_slice(&HEALTH_VERSION.to_be_bytes());
        response.extend_from_slice(&id);
        response.extend_from_slice(&code.to_be_bytes());
        let _ = write_frame(stream, &response);
    };
    if request.len() != HREQ_LEN
        || &request[..4] != b"HREQ"
        || read_u16(&request[4..6]) != Some(HEALTH_VERSION)
    {
        fail(stream, request_id_fixed, 1);
        return;
    }
    if request_id_fixed == [0u8; 16] {
        fail(stream, request_id_fixed, 2);
        return;
    }
    let lease_ms = match read_u64(&request[22..30]) {
        Some(value) if value > 0 && value <= HEALTH_LEASE_LIMIT_MS => value,
        _ => {
            fail(stream, request_id_fixed, 3);
            return;
        }
    };
    let challenge = match random_bytes::<32>() {
        Ok(value) => value,
        Err(_) => {
            fail(stream, request_id_fixed, 4);
            return;
        }
    };
    let expires_at = Instant::now() + Duration::from_millis(lease_ms.min(HEALTH_LEASE_LIMIT_MS));
    let mut challenge_frame = Vec::with_capacity(HCHL_LEN);
    challenge_frame.extend_from_slice(b"HCHL");
    challenge_frame.extend_from_slice(&HEALTH_VERSION.to_be_bytes());
    challenge_frame.extend_from_slice(&challenge);
    challenge_frame.extend_from_slice(&server_instance);
    challenge_frame.extend_from_slice(&(lease_ms as u32).to_be_bytes());
    if write_frame(stream, &challenge_frame).is_err() {
        return;
    }

    let acknowledgement = match read_frame_limited(stream, MAX_HEALTH_FRAME) {
        Ok(value) => value,
        Err(_) => {
            fail(stream, request_id_fixed, 5);
            return;
        }
    };
    if Instant::now() > expires_at
        || acknowledgement.len() != HACK_LEN
        || &acknowledgement[..4] != b"HACK"
        || read_u16(&acknowledgement[4..6]) != Some(HEALTH_VERSION)
        || !constant_time_equal(&acknowledgement[6..22], &request_id_fixed)
        || !constant_time_equal(&acknowledgement[22..54], &challenge)
    {
        fail(stream, request_id_fixed, 6);
        return;
    }
    let mut response = Vec::with_capacity(HOK_LEN);
    response.extend_from_slice(b"HOK!");
    response.extend_from_slice(&HEALTH_VERSION.to_be_bytes());
    response.extend_from_slice(&request_id_fixed);
    response.extend_from_slice(&server_instance);
    response.extend_from_slice(&HEALTH_FLAGS.to_be_bytes());
    response.extend_from_slice(&HEALTH_EPOCH.to_be_bytes());
    let _ = write_frame(stream, &response);
    let _ = transport;
}

fn prepare_socket_path(socket_path: &str) -> Result<(), String> {
    let path = Path::new(socket_path);
    if path.symlink_metadata().is_ok() {
        return Err("refusing to replace an existing socket path".to_owned());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    validate_path_components(parent)?;
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| "socket parent is unavailable".to_owned())?;
    if !metadata.is_dir() {
        return Err("socket parent is not a directory".to_owned());
    }
    let mode = metadata.mode();
    if mode & 0o0022 != 0 && mode & 0o1000 == 0 {
        return Err("socket parent is writable by group or other".to_owned());
    }
    Ok(())
}

fn validate_path_components(path: &Path) -> Result<(), String> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .map_err(|_| "socket parent cannot be resolved".to_owned())?
            .join(path)
    };
    let components: Vec<Component<'_>> = absolute.components().collect();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(name) => current.push(name),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err("socket parent contains a parent traversal".to_owned())
            }
            Component::Prefix(_) => continue,
        }
        let metadata = fs::symlink_metadata(&current)
            .map_err(|_| "socket parent component is unavailable".to_owned())?;
        if metadata.file_type().is_symlink() {
            return Err("socket parent contains a symlink component".to_owned());
        }
        if index + 1 < components.len() && !metadata.is_dir() {
            return Err("socket parent component is not a directory".to_owned());
        }
    }
    Ok(())
}

fn harden_socket_path(socket_path: &str, profile: IpcProfile) -> Result<(), String> {
    let path = Path::new(socket_path);
    let mut permissions = fs::metadata(path)
        .map_err(|_| "cannot inspect bound socket".to_owned())?
        .permissions();
    permissions.set_mode(profile.socket_mode());
    fs::set_permissions(path, permissions).map_err(|_| "cannot restrict socket mode".to_owned())?;
    let metadata = fs::metadata(path).map_err(|_| "cannot re-inspect bound socket".to_owned())?;
    if metadata.mode() & 0o7777 != profile.socket_mode() {
        return Err("socket mode does not match the selected IPC profile".to_owned());
    }
    let (uid, _) = unsafe { (geteuid(), getegid()) };
    let (_, expected_gid) = profile.expected_peer();
    if metadata.uid() != uid || metadata.gid() != expected_gid {
        return Err("socket ownership does not match the selected IPC profile".to_owned());
    }
    Ok(())
}

fn harden_socket_path_metadata(socket_path: &str, profile: IpcProfile) -> Result<(), String> {
    let metadata = fs::symlink_metadata(socket_path)
        .map_err(|_| "cannot inspect activated socket path".to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return Err("activated socket path is not a non-symlink socket".to_owned());
    }
    if metadata.mode() & 0o7777 != profile.socket_mode() {
        return Err("activated socket mode does not match the selected IPC profile".to_owned());
    }
    let (_, expected_gid) = profile.expected_peer();
    if metadata.uid() != unsafe { geteuid() } || metadata.gid() != expected_gid {
        return Err(
            "activated socket ownership does not match the selected IPC profile".to_owned(),
        );
    }
    Ok(())
}

fn read_frame_limited(stream: &mut UnixStream, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| "truncated-frame")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > maximum {
        return Err("frame-length");
    }
    let mut payload = vec![0u8; length];
    stream
        .read_exact(&mut payload)
        .map_err(|_| "truncated-frame")?;
    Ok(payload)
}

fn write_frame(stream: &mut UnixStream, response: &[u8]) -> Result<(), String> {
    let length = u32::try_from(response.len()).map_err(|_| "response too large".to_owned())?;
    stream
        .write_all(&length.to_be_bytes())
        .and_then(|_| stream.write_all(response))
        .map_err(|_| "response write failed".to_owned())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut value = [0u8; N];
    let mut random =
        fs::File::open("/dev/urandom").map_err(|_| "OS randomness unavailable".to_owned())?;
    random
        .read_exact(&mut value)
        .map_err(|_| "OS randomness unavailable".to_owned())?;
    Ok(value)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

fn read_u16(value: &[u8]) -> Option<u16> {
    value.try_into().ok().map(u16::from_be_bytes)
}
fn read_u64(value: &[u8]) -> Option<u64> {
    value.try_into().ok().map(u64::from_be_bytes)
}

fn parse_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("public key must be exactly 32-byte hex".to_owned());
    }
    let mut output = [0u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "public key contains invalid hex".to_owned())?;
    }
    Ok(output)
}

fn parse_now_unix(value: &str) -> Result<u64, String> {
    if value == "current" {
        return Ok(current_unix());
    }
    value
        .parse::<u64>()
        .map_err(|_| "now-unix must be a non-negative integer or current".to_owned())
}

#[allow(dead_code)]
fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::{activation_state, parse_now_unix};

    #[test]
    fn activation_requires_a_matching_pid_and_exactly_one_fd() {
        assert_eq!(activation_state(None, None, 42), Ok(false));
        assert_eq!(activation_state(Some("42"), Some("1"), 42), Ok(true));
        assert!(activation_state(Some("41"), Some("1"), 42).is_err());
        assert!(activation_state(Some("42"), Some("2"), 42).is_err());
        assert!(activation_state(Some("42"), None, 42).is_err());
        assert!(activation_state(None, Some("1"), 42).is_err());
    }

    #[test]
    fn current_time_mode_is_supported_without_accepting_arbitrary_text() {
        assert!(parse_now_unix("current").is_ok());
        assert_eq!(parse_now_unix("1700000000"), Ok(1_700_000_000));
        assert!(parse_now_unix("stale").is_err());
    }
}
