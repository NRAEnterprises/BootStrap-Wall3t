//! Typed local IPC profiles and peer-credential authorization.
//!
//! The profile controls only the transport/deployment boundary. BWAU signature
//! verification and durable replay consumption remain mandatory application gates.
//! Production configuration is explicit and cannot silently fall back to the
//! development profile.

use std::fmt;
use std::time::Duration;

/// Bounded transport resources for the local socket endpoint.
///
/// These values are intentionally fixed in the binary. Production deployment
/// may choose a reviewed build-time profile, but an untrusted environment must
/// not be able to turn the endpoint into an unbounded connection or queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportConfig {
    pub worker_count: usize,
    pub queue_capacity: usize,
    pub read_timeout: Duration,
    pub write_timeout: Duration,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            worker_count: 4,
            queue_capacity: 16,
            read_timeout: Duration::from_secs(5),
            write_timeout: Duration::from_secs(5),
        }
    }
}

impl TransportConfig {
    pub fn validate(self) -> Result<Self, &'static str> {
        if self.worker_count == 0 {
            return Err("worker count must be positive");
        }
        if self.queue_capacity == 0 {
            return Err("queue capacity must be positive");
        }
        if self.read_timeout.is_zero() || self.write_timeout.is_zero() {
            return Err("transport timeouts must be positive");
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcProfile {
    Development {
        expected_peer_uid: u32,
        expected_peer_gid: u32,
    },
    Production {
        expected_peer_uid: u32,
        expected_peer_gid: u32,
    },
}

impl IpcProfile {
    pub fn development(current_uid: u32, current_gid: u32) -> Self {
        Self::Development {
            expected_peer_uid: current_uid,
            expected_peer_gid: current_gid,
        }
    }

    pub fn production(expected_peer_uid: u32, expected_peer_gid: u32) -> Self {
        Self::Production {
            expected_peer_uid,
            expected_peer_gid,
        }
    }

    pub fn socket_mode(self) -> u32 {
        match self {
            Self::Development { .. } => 0o600,
            Self::Production { .. } => 0o660,
        }
    }

    pub fn expected_peer(self) -> (u32, u32) {
        match self {
            Self::Development {
                expected_peer_uid,
                expected_peer_gid,
            }
            | Self::Production {
                expected_peer_uid,
                expected_peer_gid,
            } => (expected_peer_uid, expected_peer_gid),
        }
    }

    pub fn is_production(self) -> bool {
        matches!(self, Self::Production { .. })
    }

    /// Parse the only accepted profile forms:
    /// `development` or `production:<peer-uid>:<peer-gid>`.
    pub fn parse(value: &str, current_uid: u32, current_gid: u32) -> Result<Self, IpcProfileError> {
        if value == "development" {
            return Ok(Self::development(current_uid, current_gid));
        }
        let Some(rest) = value.strip_prefix("production:") else {
            return Err(IpcProfileError::UnknownProfile);
        };
        let mut parts = rest.split(':');
        let uid = parse_id(parts.next())?;
        let gid = parse_id(parts.next())?;
        if parts.next().is_some() {
            return Err(IpcProfileError::InvalidProfile);
        }
        Ok(Self::production(uid, gid))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerCredentialError {
    Unavailable,
    SystemCallFailed,
    UnexpectedLength,
    UnauthorizedUid,
    UnauthorizedGid,
}

impl fmt::Display for PeerCredentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable => write!(f, "peer credentials unavailable"),
            Self::SystemCallFailed => write!(f, "peer credential query failed"),
            Self::UnexpectedLength => write!(f, "peer credential response length invalid"),
            Self::UnauthorizedUid => write!(f, "peer uid is not authorized by the IPC profile"),
            Self::UnauthorizedGid => write!(f, "peer gid is not authorized by the IPC profile"),
        }
    }
}

impl std::error::Error for PeerCredentialError {}

pub fn authorize_peer<P: PeerCredentialSource>(
    source: &P,
    profile: IpcProfile,
) -> Result<PeerCredentials, PeerCredentialError> {
    if profile.is_production() && !source.is_available() {
        return Err(PeerCredentialError::Unavailable);
    }
    let credentials = source.credentials()?;
    let (expected_uid, expected_gid) = profile.expected_peer();
    if credentials.uid != expected_uid {
        return Err(PeerCredentialError::UnauthorizedUid);
    }
    if credentials.gid != expected_gid {
        return Err(PeerCredentialError::UnauthorizedGid);
    }
    Ok(credentials)
}

pub trait PeerCredentialSource {
    fn is_available(&self) -> bool;
    fn credentials(&self) -> Result<PeerCredentials, PeerCredentialError>;
}

#[cfg(unix)]
impl PeerCredentialSource for std::os::unix::net::UnixStream {
    fn is_available(&self) -> bool {
        cfg!(target_os = "linux")
    }

    fn credentials(&self) -> Result<PeerCredentials, PeerCredentialError> {
        peer_credentials(self)
    }
}

#[cfg(target_os = "linux")]
fn peer_credentials(
    stream: &std::os::unix::net::UnixStream,
) -> Result<PeerCredentials, PeerCredentialError> {
    use std::mem::size_of;
    use std::os::fd::AsRawFd;
    use std::os::raw::{c_int, c_void};

    const SOL_SOCKET: c_int = 1;
    const SO_PEERCRED: c_int = 17;
    #[repr(C)]
    struct Ucred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    unsafe extern "C" {
        fn getsockopt(
            socket: c_int,
            level: c_int,
            option_name: c_int,
            option_value: *mut c_void,
            option_len: *mut u32,
        ) -> c_int;
    }

    let mut credentials = Ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = size_of::<Ucred>() as u32;
    let result = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut credentials as *mut Ucred).cast::<c_void>(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(PeerCredentialError::SystemCallFailed);
    }
    if length as usize != size_of::<Ucred>() {
        return Err(PeerCredentialError::UnexpectedLength);
    }
    Ok(PeerCredentials {
        pid: credentials.pid,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

#[cfg(not(target_os = "linux"))]
fn peer_credentials(
    _stream: &std::os::unix::net::UnixStream,
) -> Result<PeerCredentials, PeerCredentialError> {
    Err(PeerCredentialError::Unavailable)
}

fn parse_id(value: Option<&str>) -> Result<u32, IpcProfileError> {
    let value = value.ok_or(IpcProfileError::InvalidProfile)?;
    if value.is_empty() || value.starts_with('+') || value.starts_with('-') {
        return Err(IpcProfileError::InvalidProfile);
    }
    value.parse().map_err(|_| IpcProfileError::InvalidProfile)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcProfileError {
    UnknownProfile,
    InvalidProfile,
}

impl fmt::Display for IpcProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProfile => write!(f, "unknown IPC profile"),
            Self::InvalidProfile => write!(f, "invalid IPC profile"),
        }
    }
}

impl std::error::Error for IpcProfileError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_transport_limits_are_bounded_and_valid() {
        let config = TransportConfig::default();
        assert_eq!(config.validate(), Ok(config));
        assert!(config.worker_count <= 16);
        assert!(config.queue_capacity <= 128);
    }

    #[test]
    fn transport_limits_reject_unbounded_shapes() {
        let config = TransportConfig {
            worker_count: 0,
            ..TransportConfig::default()
        };
        assert_eq!(config.validate(), Err("worker count must be positive"));
        let config = TransportConfig {
            queue_capacity: 0,
            ..TransportConfig::default()
        };
        assert_eq!(config.validate(), Err("queue capacity must be positive"));
        let config = TransportConfig {
            read_timeout: Duration::ZERO,
            ..TransportConfig::default()
        };
        assert_eq!(
            config.validate(),
            Err("transport timeouts must be positive")
        );
    }

    struct FakePeer {
        available: bool,
        credentials: Result<PeerCredentials, PeerCredentialError>,
    }

    impl PeerCredentialSource for FakePeer {
        fn is_available(&self) -> bool {
            self.available
        }

        fn credentials(&self) -> Result<PeerCredentials, PeerCredentialError> {
            self.credentials
        }
    }

    #[test]
    fn profile_parser_accepts_only_typed_forms() {
        assert_eq!(
            IpcProfile::parse("development", 10, 20),
            Ok(IpcProfile::Development {
                expected_peer_uid: 10,
                expected_peer_gid: 20
            })
        );
        assert_eq!(
            IpcProfile::parse("production:1001:2001", 10, 20),
            Ok(IpcProfile::Production {
                expected_peer_uid: 1001,
                expected_peer_gid: 2001
            })
        );
        assert_eq!(
            IpcProfile::parse("production:1001", 10, 20),
            Err(IpcProfileError::InvalidProfile)
        );
        assert_eq!(
            IpcProfile::parse("production:1001:2001:extra", 10, 20),
            Err(IpcProfileError::InvalidProfile)
        );
        assert_eq!(
            IpcProfile::parse("staging", 10, 20),
            Err(IpcProfileError::UnknownProfile)
        );
    }

    #[test]
    fn peer_uid_and_gid_are_checked_before_application_data() {
        let profile = IpcProfile::production(1001, 2001);
        let authorized = FakePeer {
            available: true,
            credentials: Ok(PeerCredentials {
                pid: 7,
                uid: 1001,
                gid: 2001,
            }),
        };
        assert_eq!(
            authorize_peer(&authorized, profile)
                .expect("authorized")
                .pid,
            7
        );

        let wrong_uid = FakePeer {
            available: true,
            credentials: Ok(PeerCredentials {
                pid: 7,
                uid: 1002,
                gid: 2001,
            }),
        };
        assert_eq!(
            authorize_peer(&wrong_uid, profile),
            Err(PeerCredentialError::UnauthorizedUid)
        );

        let wrong_gid = FakePeer {
            available: true,
            credentials: Ok(PeerCredentials {
                pid: 7,
                uid: 1001,
                gid: 2002,
            }),
        };
        assert_eq!(
            authorize_peer(&wrong_gid, profile),
            Err(PeerCredentialError::UnauthorizedGid)
        );
    }

    #[test]
    fn production_never_allows_unavailable_peer_attestation() {
        let peer = FakePeer {
            available: false,
            credentials: Err(PeerCredentialError::Unavailable),
        };
        assert_eq!(
            authorize_peer(&peer, IpcProfile::production(1, 2)),
            Err(PeerCredentialError::Unavailable)
        );
    }
}
