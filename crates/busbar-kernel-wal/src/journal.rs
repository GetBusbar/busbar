// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The journal: ONE chain of fixed records, and every unit's records go on it.

use busbar_contract::crypto::Sha256;
use foldhash::{HashMap, HashSet};

use crate::note::Bridge;
use crate::off_path::bridges_of;
pub use crate::off_path::decode_run;

/// The four bytes every journal record's header opens with.
pub(crate) const JOURNAL_MAGIC: [u8; 4] = *b"BJRN";

/// The journal record layout version. A reader that meets one it does not know stops rather than
pub(crate) const JOURNAL_VERSION: u16 = 1;

/// How long a journal record's fixed header is. The body follows it.
pub const JOURNAL_HEADER_BYTES: usize = 160;

/// Where in the header each field sits. Offsets are named rather than spelled at each use so that a
pub(crate) mod at {
    /// The magic.
    pub const MAGIC: usize = 0;
    /// The layout version.
    pub const VERSION: usize = 4;
    /// The record's class.
    pub const CLASS: usize = 6;
    /// Reserved, always zero.
    pub const RESERVED: usize = 7;
    /// Which node wrote it.
    pub const NODE: usize = 8;
    /// That node's own sequence number.
    pub(crate) const NODE_SEQ: usize = 16;
    /// Which lease generation was in force.
    pub(crate) const LEASE_EPOCH: usize = 24;
    /// Which policy generation was in force.
    pub(crate) const POLICY_EPOCH: usize = 32;
    /// The wall clock, in whole seconds.
    pub const WALL: usize = 40;
    /// The node's monotonic clock.
    pub const MONO: usize = 48;
    /// How many body bytes follow the header.
    pub(crate) const BODY_LEN: usize = 56;
    /// Reserved, always zero.
    pub(crate) const RESERVED2: usize = 60;
    /// The digest of the body.
    pub(crate) const BODY_HASH: usize = 64;
    /// The preceding record's chain hash.
    pub(crate) const PREV_HASH: usize = 96;
    /// This record's own chain hash. Everything before it is what the chain hash covers.
    pub const HASH: usize = 128;
}

/// What a journal record is about.
///
/// The contract's own list, in the contract's own order. A class is one byte on the medium, so the
/// discriminants are pinned: a class that moved would re-read every record already written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum RecordClass {
    /// A hold, a dispatch, a settlement or an adjustment: money moved.
    Transaction = 1,
    /// Somebody read content. The amendment stream's access entry.
    Access = 2,
    /// This node drew or returned its slice of a bucket window.
    Slice = 3,
    /// A lease was taken or lost.
    Lease = 4,
    /// A policy generation was sealed.
    Policy = 5,
    /// A checkpoint was sealed.
    Checkpoint = 6,
    /// A reconciliation pass ran.
    Reconciliation = 7,
    /// The first boot after an upgrade opened this deployment's balances.
    Migration = 8,
    /// A deployment was brought up for the first time.
    Bootstrap = 9,
    /// Retention discarded something.
    Purge = 10,
    /// A load or capacity fact.
    Load = 11,
    /// A durable write was lost, or a run of records was.
    ChainBreak = 12,
    /// A store was restored from a backup.
    StoreRestore = 13,
    /// The fleet could not be reached.
    FleetOutage = 14,
}

impl RecordClass {
    /// Its byte on the medium.
    #[must_use]
    pub fn code(self) -> u8 {
        self as u8
    }

    /// The class a byte names, or `None` for one this build does not know.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        use RecordClass::*;
        Some(match code {
            1 => Transaction,
            2 => Access,
            3 => Slice,
            4 => Lease,
            5 => Policy,
            6 => Checkpoint,
            7 => Reconciliation,
            8 => Migration,
            9 => Bootstrap,
            10 => Purge,
            11 => Load,
            12 => ChainBreak,
            13 => StoreRestore,
            14 => FleetOutage,
            _ => return None,
        })
    }
}

/// What a unit hands the journal. The position, the digests and the link are NOT here: the chain
/// owns them, exactly as the audit record's chain owns its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// What this record is about.
    pub class: RecordClass,
    /// Which lease generation was in force.
    pub lease_epoch: u64,
    /// Which policy generation was in force.
    pub policy_epoch: u64,
    /// The wall clock, in whole seconds.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
    /// The unit's own bytes. Opaque here.
    pub body: Vec<u8>,
}

impl Entry {
    /// An entry of `class` carrying `body`, with the clocks and epochs at zero — the shape a caller
    #[must_use]
    pub fn new(class: RecordClass, body: Vec<u8>) -> Self {
        Entry {
            class,
            lease_epoch: 0,
            policy_epoch: 0,
            wall: 0,
            mono: 0,
            body,
        }
    }

    /// The same entry, stamped with the two clocks.
    #[must_use]
    pub fn at(mut self, wall: u64, mono: u64) -> Self {
        self.wall = wall;
        self.mono = mono;
        self
    }

    /// The same entry, stamped with the two generations in force.
    #[must_use]
    pub fn under(mut self, lease_epoch: u64, policy_epoch: u64) -> Self {
        self.lease_epoch = lease_epoch;
        self.policy_epoch = policy_epoch;
        self
    }
}

/// One record as it sits in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalRecord {
    /// What it is about.
    pub class: RecordClass,
    /// Which node wrote it.
    pub node: u64,
    /// That node's own sequence number, which with `node` is the identity the log deduplicates on.
    pub node_seq: u64,
    /// Which lease generation was in force.
    pub lease_epoch: u64,
    /// Which policy generation was in force.
    pub policy_epoch: u64,
    /// The wall clock, in whole seconds.
    pub wall: u64,
    /// The node's monotonic clock.
    pub mono: u64,
    /// The unit's own bytes.
    pub body: Vec<u8>,
    /// The digest of those bytes.
    pub body_hash: [u8; 32],
    /// The preceding record's chain hash. All zeros at genesis.
    pub prev_hash: [u8; 32],
    /// This record's own chain hash.
    pub hash: [u8; 32],
}

impl JournalRecord {
    /// The bytes of this record: the fixed header, then the body.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; JOURNAL_HEADER_BYTES + self.body.len()];
        self.encode_onto(&mut bytes);
        bytes
    }

    /// [`JournalRecord::encode`] into `out`, reusing its allocation: `out` ends up holding exactly
    /// the encoded bytes.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.clear();
        out.resize(JOURNAL_HEADER_BYTES + self.body.len(), 0);
        self.encode_onto(out);
    }

    /// Write the encoding over `bytes`, which is exactly header plus body long and zeroed.
    fn encode_onto(&self, bytes: &mut [u8]) {
        bytes[at::MAGIC..at::MAGIC + 4].copy_from_slice(&JOURNAL_MAGIC);
        bytes[at::VERSION..at::VERSION + 2].copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
        bytes[at::CLASS] = self.class.code();
        bytes[at::RESERVED] = 0;
        bytes[at::NODE..at::NODE + 8].copy_from_slice(&self.node.to_le_bytes());
        bytes[at::NODE_SEQ..at::NODE_SEQ + 8].copy_from_slice(&self.node_seq.to_le_bytes());
        bytes[at::LEASE_EPOCH..at::LEASE_EPOCH + 8]
            .copy_from_slice(&self.lease_epoch.to_le_bytes());
        bytes[at::POLICY_EPOCH..at::POLICY_EPOCH + 8]
            .copy_from_slice(&self.policy_epoch.to_le_bytes());
        bytes[at::WALL..at::WALL + 8].copy_from_slice(&self.wall.to_le_bytes());
        bytes[at::MONO..at::MONO + 8].copy_from_slice(&self.mono.to_le_bytes());
        bytes[at::BODY_LEN..at::BODY_LEN + 4]
            .copy_from_slice(&(self.body.len() as u32).to_le_bytes());
        bytes[at::RESERVED2..at::RESERVED2 + 4].copy_from_slice(&0u32.to_le_bytes());
        bytes[at::BODY_HASH..at::BODY_HASH + 32].copy_from_slice(&self.body_hash);
        bytes[at::PREV_HASH..at::PREV_HASH + 32].copy_from_slice(&self.prev_hash);
        bytes[at::HASH..at::HASH + 32].copy_from_slice(&self.hash);
        bytes[JOURNAL_HEADER_BYTES..].copy_from_slice(&self.body);
    }

    /// The digest this record's body should carry.
    #[must_use]
    pub fn digest_of_body(&self) -> [u8; 32] {
        body_digest(&self.body)
    }

    /// The chain hash this record's own fields should carry — everything in the header before the
    #[must_use]
    pub fn digest_of_chain(&self) -> [u8; 32] {
        let mut header = [0u8; JOURNAL_HEADER_BYTES];
        header[at::MAGIC..at::MAGIC + 4].copy_from_slice(&JOURNAL_MAGIC);
        header[at::VERSION..at::VERSION + 2].copy_from_slice(&JOURNAL_VERSION.to_le_bytes());
        header[at::CLASS] = self.class.code();
        header[at::RESERVED] = 0;
        header[at::NODE..at::NODE + 8].copy_from_slice(&self.node.to_le_bytes());
        header[at::NODE_SEQ..at::NODE_SEQ + 8].copy_from_slice(&self.node_seq.to_le_bytes());
        header[at::LEASE_EPOCH..at::LEASE_EPOCH + 8]
            .copy_from_slice(&self.lease_epoch.to_le_bytes());
        header[at::POLICY_EPOCH..at::POLICY_EPOCH + 8]
            .copy_from_slice(&self.policy_epoch.to_le_bytes());
        header[at::WALL..at::WALL + 8].copy_from_slice(&self.wall.to_le_bytes());
        header[at::MONO..at::MONO + 8].copy_from_slice(&self.mono.to_le_bytes());
        header[at::BODY_LEN..at::BODY_LEN + 4]
            .copy_from_slice(&(self.body.len() as u32).to_le_bytes());
        header[at::RESERVED2..at::RESERVED2 + 4].copy_from_slice(&0u32.to_le_bytes());
        header[at::BODY_HASH..at::BODY_HASH + 32].copy_from_slice(&self.body_hash);
        header[at::PREV_HASH..at::PREV_HASH + 32].copy_from_slice(&self.prev_hash);
        // at::HASH..end is not part of the preimage.
        let mut hasher = Sha256::new();
        hasher.update(&header[0..at::HASH]);
        crate::record::digest32(hasher)
    }

    /// This record's identity as the log knows it.
    #[must_use]
    pub fn identity(&self) -> (u64, u64) {
        (self.node, self.node_seq)
    }
}

/// The digest of a body.
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    crate::record::digest32(hasher)
}

/// Thirty-two bytes as hexadecimal, written straight into whatever formats it.
#[must_use]
pub fn hex(bytes: &[u8; 32]) -> Hex<'_> {
    Hex(bytes)
}

/// Thirty-two bytes that display as hexadecimal. `Debug` quotes them, as it would the string.
#[derive(Clone, Copy)]
pub struct Hex<'a>(pub &'a [u8; 32]);

impl std::fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "\"{self}\"")
    }
}

pub(crate) fn read4(bytes: &[u8], at: usize) -> [u8; 4] {
    bytes[at..at + 4].try_into().unwrap_or([0; 4])
}

pub(crate) fn read8(bytes: &[u8], at: usize) -> [u8; 8] {
    bytes[at..at + 8].try_into().unwrap_or([0; 8])
}

pub(crate) fn read32(bytes: &[u8], at: usize) -> [u8; 32] {
    bytes[at..at + 32].try_into().unwrap_or([0; 32])
}

/// Where a run of journal records stops verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalBreak {
    /// The one-based index into the run. Zero when the bytes were not a record at all.
    pub at_index: usize,
    /// What is wrong.
    pub kind: JournalBreakKind,
}

/// What is wrong with a run of journal records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalBreakKind {
    /// The bytes are not a journal record: too short, or no magic.
    NotARecord,
    /// A layout version this build does not read.
    UnknownVersion {
        /// The version claimed.
        found: u16,
    },
    /// A class byte this build does not know.
    UnknownClass {
        /// The byte found.
        found: u8,
    },
    /// The header's body length is not the number of bytes that followed it.
    BodyLength {
        /// What the header claims.
        claimed: usize,
        /// What is there.
        found: usize,
    },
    /// The body does not hash to the digest the record carries: the BODY was edited.
    BodyDigestMismatch,
    /// The record's own header does not hash to the chain hash it carries: the HEADER was edited.
    ChainDigestMismatch,
    /// A record does not point at its predecessor: one was inserted, removed or reordered.
    LinkMismatch,
    /// A record's sequence number does not follow its predecessor's.
    SequenceMismatch {
        /// What was expected.
        expected: u64,
        /// What is there.
        found: u64,
    },
}

impl std::fmt::Display for JournalBreak {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            JournalBreakKind::NotARecord => f.write_str("these bytes are not a journal record"),
            JournalBreakKind::UnknownVersion { found } => write!(
                f,
                "journal record layout version {found} is not one this build reads"
            ),
            JournalBreakKind::UnknownClass { found } => {
                write!(
                    f,
                    "journal record class {found} is not one this build knows"
                )
            }
            JournalBreakKind::BodyLength { claimed, found } => write!(
                f,
                "the journal record claims a {claimed}-byte body and {found} bytes followed it"
            ),
            JournalBreakKind::BodyDigestMismatch => write!(
                f,
                "the journal record at index {} does not hash to its own body — it was EDITED",
                self.at_index
            ),
            JournalBreakKind::ChainDigestMismatch => write!(
                f,
                "the journal record at index {} does not hash to its own header — it was EDITED",
                self.at_index
            ),
            JournalBreakKind::LinkMismatch => write!(
                f,
                "the journal record at index {} does not point at its predecessor — a record was \
                 INSERTED, REMOVED or REORDERED here",
                self.at_index
            ),
            JournalBreakKind::SequenceMismatch { expected, found } => write!(
                f,
                "the journal record at index {} is numbered {found} where {expected} was expected",
                self.at_index
            ),
        }
    }
}

impl std::error::Error for JournalBreak {}

/// Whether a run of journal records links and digests correctly, oldest first.
///
/// The run may skip numbers or a link only across a hole that a quarantine `ChainBreak` record on
/// the run itself names, anchored on the record it names as kept before the hole.
pub fn verify(records: &[JournalRecord]) -> Result<(), JournalBreak> {
    verify_bridged(records, &[])
}

/// [`verify`], crossing the holes recovery set aside — those named by a quarantine `ChainBreak` in
fn verify_bridged(records: &[JournalRecord], known: &[Bridge]) -> Result<(), JournalBreak> {
    let bridged = !known.is_empty() || records.iter().any(|r| r.class == RecordClass::ChainBreak);
    let (bridges, anchors) = if bridged {
        bridges_of(records, known)
    } else {
        (Vec::new(), HashSet::default())
    };
    let mut anchored: HashMap<(u64, u64), [u8; 32]> = HashMap::default();
    let mut previous: Option<&JournalRecord> = None;
    let mut expected_prev = records.first().map(|r| r.prev_hash).unwrap_or([0u8; 32]);
    let mut expected_seq = records.first().map(|r| r.node_seq);
    for (i, record) in records.iter().enumerate() {
        let index = i + 1;
        if record.body_hash != record.digest_of_body() {
            return Err(JournalBreak {
                at_index: index,
                kind: JournalBreakKind::BodyDigestMismatch,
            });
        }
        if record.hash != record.digest_of_chain() {
            return Err(JournalBreak {
                at_index: index,
                kind: JournalBreakKind::ChainDigestMismatch,
            });
        }
        let follows = record.prev_hash == expected_prev && expected_seq == Some(record.node_seq);
        let crosses = !follows
            && previous.is_some_and(|prev| {
                bridges
                    .iter()
                    .any(|bridge| bridge.crosses(prev, record, &anchored))
            });
        if !crosses {
            if record.prev_hash != expected_prev {
                return Err(JournalBreak {
                    at_index: index,
                    kind: JournalBreakKind::LinkMismatch,
                });
            }
            if let Some(expected) = expected_seq {
                if record.node_seq != expected {
                    return Err(JournalBreak {
                        at_index: index,
                        kind: JournalBreakKind::SequenceMismatch {
                            expected,
                            found: record.node_seq,
                        },
                    });
                }
            }
        }
        if anchors.contains(&record.identity()) {
            anchored.insert(record.identity(), record.hash);
        }
        previous = Some(record);
        expected_prev = record.hash;
        expected_seq = Some(record.node_seq.saturating_add(1));
    }
    Ok(())
}

impl Bridge {
    /// Whether `record`, coming after `prev` in a run, crosses this hole. See [`verify`].
    fn crosses(
        &self,
        prev: &JournalRecord,
        record: &JournalRecord,
        anchored: &HashMap<(u64, u64), [u8; 32]>,
    ) -> bool {
        if record.node == self.before.0 && record.node_seq <= self.before.1 {
            return false;
        }
        let named_after = self.after == Some(record.identity());

        if named_after && prev.identity() == self.before {
            return true;
        }

        (named_after || self.after.is_none())
            && anchored.get(&self.before) == Some(&record.prev_hash)
    }
}

/// Where a node's own chain has reached in a run of records: the head to link onto and the sequence
#[must_use]
pub fn tail_of(records: &[JournalRecord], node: u64) -> Option<([u8; 32], u64)> {
    records
        .iter()
        .filter(|r| r.node == node)
        .max_by_key(|r| r.node_seq)
        .map(|last| (last.hash, last.node_seq.saturating_add(1)))
}

/// A body a unit builds field by field, with every field length-prefixed.
///
/// Length prefixes rather than a separator, for the same reason the audit record's own digest uses
/// them: these bodies carry text a plane or an operator named — a bucket reference, a currency, a
/// principal pseudonym — and a separator-joined encoding is only unambiguous while no field can
/// contain the separator.
#[derive(Debug, Default, Clone)]
pub struct BodyWriter {
    bytes: Vec<u8>,
}

impl BodyWriter {
    /// An empty one.
    #[must_use]
    pub fn new() -> Self {
        BodyWriter::default()
    }

    /// Add a text field.
    pub fn text(&mut self, value: &str) -> &mut Self {
        self.bytes(value.as_bytes())
    }

    /// Add a text field formatted straight into the body: the same bytes as [`BodyWriter::text`]
    /// over the formatted string, with no string built first.
    pub fn text_fmt(&mut self, value: std::fmt::Arguments<'_>) -> &mut Self {
        /// Formats into the body's bytes.
        struct Onto<'a>(&'a mut Vec<u8>);
        impl std::fmt::Write for Onto<'_> {
            fn write_str(&mut self, s: &str) -> std::fmt::Result {
                self.0.extend_from_slice(s.as_bytes());
                Ok(())
            }
        }
        let prefix = self.bytes.len();
        self.bytes.extend_from_slice(&0u64.to_le_bytes());
        let _ = std::fmt::Write::write_fmt(&mut Onto(&mut self.bytes), value);
        let len = (self.bytes.len() - prefix - 8) as u64;
        self.bytes[prefix..prefix + 8].copy_from_slice(&len.to_le_bytes());
        self
    }

    /// Add a byte field.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_le_bytes());
        self.bytes.extend_from_slice(value);
        self
    }

    /// Add an unsigned number, fixed width and unprefixed — its length is not in doubt.
    pub fn num(&mut self, value: u64) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Add a signed ledger figure, fixed width.
    pub fn figure(&mut self, value: i128) -> &mut Self {
        self.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// The bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// The reading half of [`BodyWriter`]: the same fields, in the same order, read back.
///
/// It exists because a journal nobody reads back is a journal nothing is ever recovered from. A
/// hold that must survive a restart is a record a boot has to READ, and so is every posting the
/// book is rebuilt from — so the one encoding a unit writes has one decoder beside it rather than a
/// hand-rolled offset table at each reader.
///
/// Every read answers `None` rather than panicking on a body that is short or not what the caller
/// expected, because "this record is not one of mine" is an ordinary answer on a chain every unit
/// writes to.
#[derive(Debug, Clone)]
pub struct BodyReader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> BodyReader<'a> {
    /// Read `bytes` from the start.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        BodyReader { bytes, at: 0 }
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(out)
    }

    /// Read a byte field.
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.num()?).ok()?;
        self.take(len)
    }

    /// Read a text field. `None` for bytes that are not text.
    pub fn text(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.bytes()?).ok()
    }

    /// Read an unsigned number.
    pub fn num(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    /// Read a signed ledger figure.
    pub fn figure(&mut self) -> Option<i128> {
        Some(i128::from_le_bytes(self.take(16)?.try_into().ok()?))
    }

    /// Whether every byte has been read. A reader that stops short has not read the body it
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.at == self.bytes.len()
    }
}
