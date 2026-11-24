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
use std::time::{SystemTime, UNIX_EPOCH};

use wallet_core::authenticated::AuthenticatedEnvelope;
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
    if args.len() != 7 {
        return Err(format!(
            "usage: {} <socket> <signer> <key-id> <public-key-hex> <replay-file> <now-unix>",
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
    harden_socket(socket_path)?;

    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let response = handle_request(&mut stream, &registry, &replay, now_unix);
                write_frame(&mut stream, response.as_bytes())?;
            }
            Err(error) => eprintln!("wallet-core socket accept error: {error}"),
        }
    }
    Ok(())
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

fn harden_socket(socket_path: &str) -> Result<(), String> {
    let path = Path::new(socket_path);
    let mut permissions = fs::metadata(path)
        .map_err(|_| "cannot inspect bound socket".to_owned())?
        .permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions).map_err(|_| "cannot restrict socket mode".to_owned())?;
    let metadata = fs::metadata(path).map_err(|_| "cannot re-inspect bound socket".to_owned())?;
    if metadata.mode() & 0o7777 != 0o600 {
        return Err("socket mode is not 0600".to_owned());
    }
    let (uid, gid) = unsafe { (geteuid(), getegid()) };
    if metadata.uid() != uid || metadata.gid() != gid {
        return Err("socket ownership does not match the service process".to_owned());
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
