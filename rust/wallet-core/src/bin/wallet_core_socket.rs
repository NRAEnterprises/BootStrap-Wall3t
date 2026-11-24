//! Minimal authenticated Unix-domain transport endpoint for the wallet core.
//!
//! Request framing: u32 big-endian length followed by one BWAU envelope.
//! Response framing: u32 big-endian length followed by ASCII status metadata.
//! No signing, broadcasting, private keys, or raw secret material cross this socket.

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::os::raw::c_uint;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use wallet_core::authenticated::AuthenticatedEnvelope;
use wallet_core::ipc::{authorize_peer, IpcProfile, TransportConfig};
use wallet_core::key_registry::{KeyAlgorithm, KeyRegistry, RegisteredKey};
use wallet_core::replay::PersistentNonceRegistry;

const MAX_FRAME: usize = 8 * 1024 * 1024;

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
    let now_unix = args[6]
        .parse::<u64>()
        .map_err(|_| "now-unix must be a non-negative integer".to_owned())?;
    let (current_uid, current_gid) = unsafe { (geteuid(), getegid()) };
    let profile = IpcProfile::parse(&args[7], current_uid, current_gid)
        .map_err(|error| format!("IPC profile rejected: {error}"))?;

    prepare_socket_path(socket_path)?;
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
    // Apply the restrictive umask before bind so there is no permissive creation window.
    unsafe { umask(0o077) };
    let listener = UnixListener::bind(socket_path).map_err(|_| "cannot bind socket".to_owned())?;
    if let Err(error) = harden_socket(socket_path, profile) {
        // Do not expose a socket after a profile or ownership check fails.
        let _ = fs::remove_file(socket_path);
        return Err(error);
    }

    let transport = TransportConfig::default()
        .validate()
        .map_err(|error| format!("transport configuration invalid: {error}"))?;
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
            .spawn(move || worker_loop(receiver, registry, replay, now_unix, profile, transport));
        if spawn_result.is_err() {
            let _ = fs::remove_file(socket_path);
            return Err("cannot spawn IPC worker".to_owned());
        }
    }

    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                // Never wait for a worker here. A full bounded queue closes the
                // connection instead of allowing an attacker to stall accept.
                if sender.try_send(stream).is_err() {
                    continue;
                }
            }
            Err(error) => eprintln!("wallet-core socket accept error: {error}"),
        }
    }
    Ok(())
}

fn worker_loop(
    receiver: Arc<Mutex<mpsc::Receiver<UnixStream>>>,
    registry: Arc<KeyRegistry>,
    replay: Arc<PersistentNonceRegistry>,
    now_unix: u64,
    profile: IpcProfile,
    transport: TransportConfig,
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
        serve_connection(stream, &registry, &replay, now_unix, profile, transport);
    }
}

fn serve_connection(
    mut stream: UnixStream,
    registry: &KeyRegistry,
    replay: &PersistentNonceRegistry,
    now_unix: u64,
    profile: IpcProfile,
    transport: TransportConfig,
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

    let response = match authorize_peer(&stream, profile) {
        Ok(_) => handle_request(&mut stream, registry, replay, now_unix),
        Err(error) => format!("ERR peer:{error}\n"),
    };
    let _ = write_frame(&mut stream, response.as_bytes());
}

fn prepare_socket_path(socket_path: &str) -> Result<(), String> {
    let path = Path::new(socket_path);
    if path.symlink_metadata().is_ok() {
        return Err("refusing to replace an existing socket path".to_owned());
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let metadata = fs::metadata(parent).map_err(|_| "socket parent is unavailable".to_owned())?;
    if !metadata.is_dir() {
        return Err("socket parent is not a directory".to_owned());
    }
    let mode = metadata.mode();
    // A sticky directory such as /tmp is acceptable; otherwise reject group/other writes.
    if mode & 0o0022 != 0 && mode & 0o1000 == 0 {
        return Err("socket parent is writable by group or other".to_owned());
    }
    Ok(())
}

fn harden_socket(socket_path: &str, profile: IpcProfile) -> Result<(), String> {
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

fn handle_request(
    stream: &mut UnixStream,
    registry: &KeyRegistry,
    replay: &PersistentNonceRegistry,
    now_unix: u64,
) -> String {
    let request = match read_frame(stream) {
        Ok(bytes) => bytes,
        Err(error) => return format!("ERR {error}\n"),
    };
    let envelope = match AuthenticatedEnvelope::decode(&request) {
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

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, &'static str> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .map_err(|_| "truncated-frame")?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
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

#[allow(dead_code)]
fn current_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
