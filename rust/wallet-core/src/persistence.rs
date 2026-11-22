//! Minimal durable persistence for canonical Phase 1 records.
//!
//! The journal is an append-only reference store, not the production replicated registry.
//! Every frame is length-delimited, versioned, typed, checksummed, and fsync'd before
//! append returns. Recovery rejects truncation, unknown framing, length disagreement, and
//! checksum mismatch instead of silently replaying partial state.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::wire::CanonicalWire;

const FRAME_MAGIC: &[u8; 4] = b"BWJR";
const FRAME_VERSION: u16 = 1;
const FRAME_HEADER_LEN: usize = 4 + 2 + 1 + 4 + 8;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalRecord {
    pub kind: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum JournalError {
    Io(io::Error),
    Corrupt(&'static str),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "journal I/O error: {error}"),
            Self::Corrupt(reason) => write!(f, "journal corruption: {reason}"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<io::Error> for JournalError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct DomainJournal {
    path: PathBuf,
    file: File,
}

impl DomainJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, JournalError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        let journal = Self { path, file };
        journal.read_records()?;
        Ok(journal)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn append<T: CanonicalWire>(&mut self, value: &T) -> Result<u64, JournalError> {
        let payload = value.canonical_bytes();
        let mut body = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        body.extend_from_slice(FRAME_MAGIC);
        body.extend_from_slice(&FRAME_VERSION.to_be_bytes());
        body.push(T::KIND);
        body.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        body.extend_from_slice(&checksum(&payload).to_be_bytes());
        body.extend_from_slice(&payload);

        let frame_len =
            u32::try_from(body.len()).map_err(|_| JournalError::Corrupt("frame too large"))?;
        self.file.seek(SeekFrom::End(0))?;
        let offset = self.file.stream_position()?;
        self.file.write_all(&frame_len.to_be_bytes())?;
        self.file.write_all(&body)?;
        self.file.sync_data()?;
        Ok(offset)
    }

    pub fn read_records(&self) -> Result<Vec<JournalRecord>, JournalError> {
        let mut reader = self.file.try_clone()?;
        reader.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        parse_records(&bytes)
    }
}

fn parse_records(bytes: &[u8]) -> Result<Vec<JournalRecord>, JournalError> {
    let mut cursor = 0usize;
    let mut records = Vec::new();
    while cursor < bytes.len() {
        if bytes.len() - cursor < 4 {
            return Err(JournalError::Corrupt("truncated frame length"));
        }
        let frame_len = u32::from_be_bytes([
            bytes[cursor],
            bytes[cursor + 1],
            bytes[cursor + 2],
            bytes[cursor + 3],
        ]) as usize;
        cursor += 4;
        if frame_len < FRAME_HEADER_LEN || frame_len > bytes.len().saturating_sub(cursor) {
            return Err(JournalError::Corrupt("invalid frame length"));
        }
        let body = &bytes[cursor..cursor + frame_len];
        cursor += frame_len;
        if &body[..4] != FRAME_MAGIC {
            return Err(JournalError::Corrupt("unknown frame magic"));
        }
        let version = u16::from_be_bytes([body[4], body[5]]);
        if version != FRAME_VERSION {
            return Err(JournalError::Corrupt("unsupported frame version"));
        }
        let kind = body[6];
        if !(1..=6).contains(&kind) {
            return Err(JournalError::Corrupt("unknown record kind"));
        }
        let payload_len = u32::from_be_bytes([body[7], body[8], body[9], body[10]]) as usize;
        if payload_len != frame_len - FRAME_HEADER_LEN {
            return Err(JournalError::Corrupt("payload length mismatch"));
        }
        let expected_checksum = u64::from_be_bytes([
            body[11], body[12], body[13], body[14], body[15], body[16], body[17], body[18],
        ]);
        let payload = body[FRAME_HEADER_LEN..].to_vec();
        if checksum(&payload) != expected_checksum {
            return Err(JournalError::Corrupt("payload checksum mismatch"));
        }
        records.push(JournalRecord { kind, payload });
    }
    Ok(records)
}

fn checksum(bytes: &[u8]) -> u64 {
    // FNV-1a is used only to detect accidental truncation/corruption. It is not
    // an authenticity primitive; authenticated replication remains a later phase.
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{AgentAssignment, AgentWalletId, AssignmentScope, PolicyId};
    use std::collections::BTreeSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("bootstrap-wall3t-{label}-{nonce}.journal"))
    }

    fn assignment() -> AgentAssignment {
        let agent = AgentWalletId::new("agent-1").expect("id");
        let wallet = AgentWalletId::new("wallet-1").expect("id");
        let mut scopes = BTreeSet::new();
        scopes.insert(AssignmentScope::Operation("swap".into()));
        AgentAssignment {
            agent,
            wallet,
            scopes,
            policy: PolicyId::new("policy-1").expect("id"),
            revoked: false,
        }
    }

    #[test]
    fn journal_round_trips_canonical_payload_and_reopens() {
        let path = temp_path("roundtrip");
        let payload = assignment().canonical_bytes();
        let mut journal = DomainJournal::open(&path).expect("open");
        let offset = journal.append(&assignment()).expect("append");
        assert_eq!(offset, 0);
        assert_eq!(journal.read_records().expect("read").len(), 1);
        drop(journal);
        let reopened = DomainJournal::open(&path).expect("reopen");
        let records = reopened.read_records().expect("records");
        assert_eq!(records[0].kind, AgentAssignment::KIND);
        assert_eq!(records[0].payload, payload);
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn journal_rejects_truncated_frame() {
        let path = temp_path("truncated");
        std::fs::write(&path, [0, 0, 0, 20, b'B']).expect("write");
        assert!(matches!(
            DomainJournal::open(&path),
            Err(JournalError::Corrupt(_))
        ));
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn journal_rejects_checksum_corruption() {
        let path = temp_path("checksum");
        let mut journal = DomainJournal::open(&path).expect("open");
        journal.append(&assignment()).expect("append");
        drop(journal);
        let mut bytes = std::fs::read(&path).expect("read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, bytes).expect("corrupt");
        assert!(matches!(
            DomainJournal::open(&path),
            Err(JournalError::Corrupt(_))
        ));
        std::fs::remove_file(path).expect("cleanup");
    }

    #[test]
    fn journal_rejects_unknown_record_kind() {
        let path = temp_path("unknown-kind");
        let mut journal = DomainJournal::open(&path).expect("open");
        journal.append(&assignment()).expect("append");
        drop(journal);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[4 + 6] = 99;
        std::fs::write(&path, bytes).expect("corrupt");
        assert!(matches!(
            DomainJournal::open(&path),
            Err(JournalError::Corrupt(_))
        ));
        std::fs::remove_file(path).expect("cleanup");
    }
}
