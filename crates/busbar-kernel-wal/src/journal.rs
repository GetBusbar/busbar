// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The journal: ONE chain of fixed records, and every unit's records go on it.

use std::collections::VecDeque;

use busbar_contract::caps::{DurabilityLost, DurableWrite, Grant, StepName};
use ring::digest::{Context, SHA256};

use crate::record::Record;
use crate::recover::{Bridge, QuarantineNote};
use crate::ship::Shipper;
use crate::wal::{BatchAck, Clock, Mode, OpenError, Wal};

/// The four bytes every journal record's header opens with.
pub const JOURNAL_MAGIC: [u8; 4] = *b"BJRN";

/// The journal record layout version. A reader that meets one it does not know stops rather than
pub const JOURNAL_VERSION: u16 = 1;

/// How long a journal record's fixed header is. The body follows it.
pub const JOURNAL_HEADER_BYTES: usize = 160;

/// How many records the memory-buffered journal will hold for a store that has not acknowledged
pub const MEMORY_BUFFER_RECORDS: usize = 8192;

/// How many overflows the in-memory history names in detail.
pub const OVERFLOW_HISTORY_RECORDS: usize = 16;

/// Where in the header each field sits. Offsets are named rather than spelled at each use so that a
mod at {
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
    pub const NODE_SEQ: usize = 16;
    /// Which lease generation was in force.
    pub const LEASE_EPOCH: usize = 24;
    /// Which policy generation was in force.
    pub const POLICY_EPOCH: usize = 32;
    /// The wall clock, in whole seconds.
    pub const WALL: usize = 40;
    /// The node's monotonic clock.
    pub const MONO: usize = 48;
    /// How many body bytes follow the header.
    pub const BODY_LEN: usize = 56;
    /// Reserved, always zero.
    pub const RESERVED2: usize = 60;
    /// The digest of the body.
    pub const BODY_HASH: usize = 64;
    /// The preceding record's chain hash.
    pub const PREV_HASH: usize = 96;
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

    /// Its name, for a report a person reads.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        use RecordClass::*;
        match self {
            Transaction => "Transaction",
            Access => "Access",
            Slice => "Slice",
            Lease => "Lease",
            Policy => "Policy",
            Checkpoint => "Checkpoint",
            Reconciliation => "Reconciliation",
            Migration => "Migration",
            Bootstrap => "Bootstrap",
            Purge => "Purge",
            Load => "Load",
            ChainBreak => "ChainBreak",
            StoreRestore => "StoreRestore",
            FleetOutage => "FleetOutage",
        }
    }

    /// Every class, so a test can say "the set did not change" rather than listing it again.
    #[must_use]
    pub fn all() -> &'static [RecordClass] {
        use RecordClass::*;
        &[
            Transaction,
            Access,
            Slice,
            Lease,
            Policy,
            Checkpoint,
            Reconciliation,
            Migration,
            Bootstrap,
            Purge,
            Load,
            ChainBreak,
            StoreRestore,
            FleetOutage,
        ]
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
        bytes
    }

    /// Read one record back out of its bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalBreak> {
        if bytes.len() < JOURNAL_HEADER_BYTES {
            return Err(JournalBreak {
                at_index: 0,
                kind: JournalBreakKind::NotARecord,
            });
        }
        if bytes[at::MAGIC..at::MAGIC + 4] != JOURNAL_MAGIC {
            return Err(JournalBreak {
                at_index: 0,
                kind: JournalBreakKind::NotARecord,
            });
        }
        let version = u16::from_le_bytes([bytes[at::VERSION], bytes[at::VERSION + 1]]);
        if version != JOURNAL_VERSION {
            return Err(JournalBreak {
                at_index: 0,
                kind: JournalBreakKind::UnknownVersion { found: version },
            });
        }
        let Some(class) = RecordClass::from_code(bytes[at::CLASS]) else {
            return Err(JournalBreak {
                at_index: 0,
                kind: JournalBreakKind::UnknownClass {
                    found: bytes[at::CLASS],
                },
            });
        };
        let body_len = u32::from_le_bytes(read4(bytes, at::BODY_LEN)) as usize;
        if bytes.len() != JOURNAL_HEADER_BYTES + body_len {
            return Err(JournalBreak {
                at_index: 0,
                kind: JournalBreakKind::BodyLength {
                    claimed: body_len,
                    found: bytes.len().saturating_sub(JOURNAL_HEADER_BYTES),
                },
            });
        }
        Ok(JournalRecord {
            class,
            node: u64::from_le_bytes(read8(bytes, at::NODE)),
            node_seq: u64::from_le_bytes(read8(bytes, at::NODE_SEQ)),
            lease_epoch: u64::from_le_bytes(read8(bytes, at::LEASE_EPOCH)),
            policy_epoch: u64::from_le_bytes(read8(bytes, at::POLICY_EPOCH)),
            wall: u64::from_le_bytes(read8(bytes, at::WALL)),
            mono: u64::from_le_bytes(read8(bytes, at::MONO)),
            body: bytes[JOURNAL_HEADER_BYTES..].to_vec(),
            body_hash: read32(bytes, at::BODY_HASH),
            prev_hash: read32(bytes, at::PREV_HASH),
            hash: read32(bytes, at::HASH),
        })
    }

    /// The digest this record's body should carry.
    #[must_use]
    pub fn digest_of_body(&self) -> [u8; 32] {
        body_digest(&self.body)
    }

    /// The chain hash this record's own fields should carry — everything in the header before the
    #[must_use]
    pub fn digest_of_chain(&self) -> [u8; 32] {
        let bytes = self.encode();
        let mut hasher = Context::new(&SHA256);
        hasher.update(&bytes[0..at::HASH]);
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
    let mut hasher = Context::new(&SHA256);
    hasher.update(body);
    crate::record::digest32(hasher)
}

/// Thirty-two bytes as hexadecimal.
#[must_use]
pub fn hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn read4(bytes: &[u8], at: usize) -> [u8; 4] {
    bytes[at..at + 4].try_into().unwrap_or([0; 4])
}

fn read8(bytes: &[u8], at: usize) -> [u8; 8] {
    bytes[at..at + 8].try_into().unwrap_or([0; 8])
}

fn read32(bytes: &[u8], at: usize) -> [u8; 32] {
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
pub fn verify(records: &[JournalRecord]) -> Result<(), JournalBreak> {
    verify_bridged(records, &[])
}

/// [`verify`], crossing the holes recovery set aside — those named by a quarantine `ChainBreak` in
pub fn verify_bridged(records: &[JournalRecord], known: &[Bridge]) -> Result<(), JournalBreak> {
    let mut bridges: Vec<Bridge> = known.to_vec();
    bridges.extend(
        records
            .iter()
            .filter(|r| r.class == RecordClass::ChainBreak)
            .filter_map(|r| QuarantineNote::read(&r.body).and_then(|note| note.bridge)),
    );

    let anchors: std::collections::HashSet<(u64, u64)> = bridges.iter().map(|b| b.before).collect();
    let mut anchored: std::collections::HashMap<(u64, u64), [u8; 32]> =
        std::collections::HashMap::new();
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
    /// Whether `record`, coming after `prev` in a run, crosses this hole. See [`verify_bridged`].
    fn crosses(
        &self,
        prev: &JournalRecord,
        record: &JournalRecord,
        anchored: &std::collections::HashMap<(u64, u64), [u8; 32]>,
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

/// Decode a run of log records into journal records, in order.
pub fn decode_run(records: &[Record]) -> Result<Vec<JournalRecord>, JournalBreak> {
    records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            JournalRecord::decode(&r.body).map_err(|mut e| {
                e.at_index = i + 1;
                e
            })
        })
        .collect()
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

/// What the journal dropped when its bounded buffer was full, and the break it sealed for it.
///
/// A value rather than a log line: the caller can report it, count it and assert on it, and a drop
/// that produced no value would be the silent one this bound exists to prevent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overflow {
    /// How many records were dropped.
    pub dropped: usize,
    /// The identity of the oldest record dropped.
    pub first: (u64, u64),
    /// The identity of the newest record dropped.
    pub last: (u64, u64),
    /// The sequence number of the `ChainBreak` record sealed to say so.
    pub chain_break_seq: u64,
}

impl Overflow {
    /// The `ChainBreak` body: how many went, then the two identities that bracket them — five
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(40);
        body.extend_from_slice(&(self.dropped as u64).to_le_bytes());
        body.extend_from_slice(&self.first.0.to_le_bytes());
        body.extend_from_slice(&self.first.1.to_le_bytes());
        body.extend_from_slice(&self.last.0.to_le_bytes());
        body.extend_from_slice(&self.last.1.to_le_bytes());
        body
    }
}

/// What one journal append did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalAck {
    /// What the log made of the batch.
    pub batch: BatchAck,
    /// The records that went on the chain, in order — the `ChainBreak` first, when there was one.
    pub sealed: Vec<JournalRecord>,
    /// Where the chain ends now.
    pub head: [u8; 32],
    /// What the bound cost, if it was reached.
    pub overflow: Option<Overflow>,
}

/// The journal: one chain, over one log.
pub struct Journal {
    log: Wal,
    node: u64,
    next_seq: u64,
    head: [u8; 32],
    capacity: usize,
    /// The most recent overflows, oldest first. A window, because during an outage every append
    overflows: VecDeque<Overflow>,
    /// How many overflows there have been, window or not.
    overflows_seen: usize,
    /// How many records the bound has cost in total.
    dropped_total: u64,
    /// What reaching the bound does: drop the oldest and seal a break (the default), or keep every
    drop_at_bound: bool,
}

impl std::fmt::Debug for Journal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Journal")
            .field("mode", &self.log.mode())
            .field("node", &self.node)
            .field("next_seq", &self.next_seq)
            .field("head", &hex(&self.head))
            .field("buffered", &self.log.owed().len())
            .field("capacity", &self.capacity)
            .finish()
    }
}

impl Journal {
    /// A journal over a memory-buffered log shipping through `shipper` — the default, and the shape a
    #[must_use]
    pub fn memory_buffered_to(node: u64, shipper: Box<dyn Shipper<Record>>, clock: Clock) -> Self {
        Journal::over(Wal::memory_buffered_to(shipper, clock), node)
    }

    /// A journal whose log keeps its segments as files under `dir`, resuming from whatever chain is
    pub fn in_directory(
        node: u64,
        dir: impl AsRef<std::path::Path>,
        shipper: Box<dyn Shipper<Record>>,
        clock: Clock,
    ) -> Result<Self, OpenError> {
        Ok(Journal::over(Wal::in_directory(dir, shipper, clock)?, node))
    }

    /// [`Journal::in_directory`], writing as the node the directory's chain ALREADY names: the
    pub fn in_directory_adopting(
        fallback: u64,
        dir: impl AsRef<std::path::Path>,
        shipper: Box<dyn Shipper<Record>>,
        clock: Clock,
    ) -> Result<Self, OpenError> {
        let log = Wal::in_directory(dir, shipper, clock)?;
        let node = decode_run(log.recovered())
            .ok()
            .and_then(|records| records.last().map(|r| r.node))
            .unwrap_or(fallback);
        Ok(Journal::over(log, node))
    }

    /// A journal over an already-open log, resuming from the tail the log recovered.
    #[must_use]
    pub fn over(log: Wal, node: u64) -> Self {
        let mut journal = Journal {
            log,
            node,
            next_seq: 1,
            head: [0u8; 32],
            capacity: MEMORY_BUFFER_RECORDS,
            overflows: VecDeque::new(),
            overflows_seen: 0,
            dropped_total: 0,
            drop_at_bound: true,
        };

        if let Ok(records) = decode_run(journal.log.recovered()) {
            if let Some((head, next_seq)) = tail_of(&records, node) {
                journal.head = head;
                journal.next_seq = next_seq;
            }
        }

        journal.floor_seq_to_the_log();
        journal
    }

    /// A memory-buffered journal RESUMED from the chain the configured store kept: `records` are
    pub fn memory_resumed(
        node: u64,
        records: &[Record],
        shipper: Box<dyn Shipper<Record>>,
        clock: Clock,
    ) -> Result<Self, OpenError> {
        let log = Wal::memory_seeded(records, shipper, clock)?;

        let (head, next_seq) = decode_run(records)
            .ok()
            .and_then(|decoded| tail_of(&decoded, node))
            .unwrap_or(([0u8; 32], 1));
        let mut journal = Journal::over(log, node);
        journal.head = head;
        journal.next_seq = next_seq.max(1);

        journal.floor_seq_to_the_log();
        Ok(journal)
    }

    /// The same journal KEEPING every record at its bound instead of dropping the oldest.
    #[must_use]
    pub fn retaining_at_bound(mut self) -> Self {
        self.drop_at_bound = false;
        self
    }

    /// Whether the store has not acknowledged as many records as the buffer is bounded at.
    #[must_use]
    pub fn at_bound(&self) -> bool {
        self.buffered() >= self.capacity
    }

    /// Put every quarantine the log made at open on the chain, as one `ChainBreak` record each —
    pub fn record_quarantines(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        wall: u64,
    ) -> Result<Option<JournalAck>, DurabilityLost> {
        let noted = self.quarantines_on_chain();
        let entries: Vec<Entry> = self
            .log
            .quarantined()
            .iter()
            .filter(|q| !noted.contains(&(q.segment, q.offset)))
            .map(|q| Entry::new(RecordClass::ChainBreak, q.body()).at(wall, 0))
            .collect();
        if entries.is_empty() {
            return Ok(None);
        }
        self.append(token, at, &entries).map(Some)
    }

    /// Every `(segment, first byte)` a quarantine `ChainBreak` already on the chain names. A log
    fn quarantines_on_chain(&self) -> std::collections::HashSet<(u64, u64)> {
        let Ok(back) = self.log.read_back() else {
            return std::collections::HashSet::new();
        };
        back.records
            .iter()
            .filter_map(|r| JournalRecord::decode(&r.body).ok())
            .filter(|r| r.class == RecordClass::ChainBreak)
            .filter_map(|r| QuarantineNote::read(&r.body))
            .map(|note| (note.segment, note.offset))
            .collect()
    }

    /// The same journal with a different buffer bound. For batteries that need to reach the bound
    #[must_use]
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity.max(1);
        self
    }

    /// Which node this journal writes as.
    #[must_use]
    pub fn node(&self) -> u64 {
        self.node
    }

    /// Whether this journal's log is on a disk.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.log.mode()
    }

    /// The chain hash of the most recent record. All zeros on a chain with nothing in it.
    #[must_use]
    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    /// The head in hexadecimal.
    #[must_use]
    pub fn head_hex(&self) -> String {
        hex(&self.head)
    }

    /// The sequence number the next record will take.
    #[must_use]
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// How many records the buffer will hold for a store that has not acknowledged them.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many records the store has not acknowledged.
    #[must_use]
    pub fn buffered(&self) -> usize {
        self.log.owed().len()
    }

    /// The most recent times the bound was reached, oldest first, at most
    #[must_use]
    pub fn overflows(&self) -> Vec<Overflow> {
        self.overflows.iter().cloned().collect()
    }

    /// How many times the bound has been reached, including the ones the window has forgotten.
    #[must_use]
    pub fn overflows_seen(&self) -> usize {
        self.overflows_seen
    }

    /// How many records the bound has cost in total, across every overflow.
    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped_total
    }

    /// The log underneath, for a caller that needs to ask it about segments or poison.
    #[must_use]
    pub fn log(&self) -> &Wal {
        &self.log
    }

    /// Seal a batch of entries onto the chain and commit them through the log.
    pub fn append(
        &mut self,
        token: &Grant<DurableWrite>,
        at: StepName,
        entries: &[Entry],
    ) -> Result<JournalAck, DurabilityLost> {
        let overflow = self.make_room(entries.len());

        let mut sealed = Vec::with_capacity(entries.len() + usize::from(overflow.is_some()));
        if let Some(overflow) = &overflow {
            let wall = entries.iter().map(|e| e.wall).max().unwrap_or(0);
            let mono = entries.iter().map(|e| e.mono).max().unwrap_or(0);
            sealed.push(
                self.seal(&Entry::new(RecordClass::ChainBreak, overflow.body()).at(wall, mono)),
            );
        }
        for entry in entries {
            sealed.push(self.seal(entry));
        }

        let batch: Vec<Record> = sealed
            .iter()
            .map(|r| Record::new(r.node, r.node_seq, r.encode()))
            .collect();

        let batch_ack = self.log.append_batch(token, at, &batch)?;
        Ok(JournalAck {
            batch: batch_ack,
            sealed,
            head: self.head,
            overflow,
        })
    }

    /// Read the chain back out of the whole log, every segment oldest first, verifying as it goes.
    pub fn replay(&self) -> std::io::Result<Result<Vec<JournalRecord>, JournalBreak>> {
        let back = self.log.read_back()?;
        let known: Vec<Bridge> = self
            .log
            .quarantined()
            .iter()
            .filter_map(crate::recover::Quarantine::bridge)
            .collect();
        Ok(decode_run(&back.records)
            .and_then(|records| verify_bridged(&records, &known).map(|()| records)))
    }

    /// Raise the next number to one the log does not already hold for this node.
    fn floor_seq_to_the_log(&mut self) {
        self.next_seq = u64::max(self.next_seq, self.log.next_free_seq(self.node));
    }

    /// Chain one entry and advance the head.
    fn seal(&mut self, entry: &Entry) -> JournalRecord {
        let mut record = JournalRecord {
            class: entry.class,
            node: self.node,
            node_seq: self.next_seq,
            lease_epoch: entry.lease_epoch,
            policy_epoch: entry.policy_epoch,
            wall: entry.wall,
            mono: entry.mono,
            body_hash: body_digest(&entry.body),
            body: entry.body.clone(),
            prev_hash: self.head,
            hash: [0u8; 32],
        };
        record.hash = record.digest_of_chain();
        self.head = record.hash;
        self.next_seq = self.next_seq.saturating_add(1);
        record
    }

    /// Make room for `incoming` records, dropping the oldest unacknowledged ones if the bound would
    fn make_room(&mut self, incoming: usize) -> Option<Overflow> {
        let held = self.log.owed().len();
        if !self.drop_at_bound || held.saturating_add(incoming) <= self.capacity {
            return None;
        }
        let wanted = held.saturating_add(incoming).saturating_add(1);
        let excess = wanted.saturating_sub(self.capacity);
        let dropped = self.log.forget_owed(excess);

        let first = dropped.first().map_or((0, 0), Record::identity);
        let last = dropped.last().map_or((0, 0), Record::identity);
        let overflow = Overflow {
            dropped: dropped.len(),
            first,
            last,
            chain_break_seq: self.next_seq,
        };
        self.overflows_seen = self.overflows_seen.saturating_add(1);
        self.dropped_total = self.dropped_total.saturating_add(dropped.len() as u64);
        self.overflows.push_back(overflow.clone());
        while self.overflows.len() > OVERFLOW_HISTORY_RECORDS {
            self.overflows.pop_front();
        }
        Some(overflow)
    }
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
