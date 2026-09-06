// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The journal: ONE chain of fixed records, and every unit's records go on it.
//!
//! ## Why there is one and not several
//!
//! The audit unit seals records. The ledger posts settlements and seals checkpoints. The migration
//! step writes a marker saying this deployment has opened its balances. Before this module each of
//! those kept its own private notion of where its records lived — a chain in memory, a marker in a
//! node-local shim — and none of them could be verified against the others, because there was no
//! order they all agreed on.
//!
//! A journal is exactly that agreement: one sequence, one hash chain, one head. A record's position
//! in it is a fact about the whole node rather than about whichever unit wrote it, so "what happened
//! at 14:32" has an answer that does not depend on who is asked.
//!
//! ## The record is fixed
//!
//! Every journal record opens with a [`JOURNAL_HEADER_BYTES`]-byte header of fixed offsets: the
//! magic, the layout version, the class, the writer's identity, the two epochs, the two clocks, the
//! body length, the body digest, the previous record's chain hash and this record's own. The body
//! that follows is opaque — the journal has no opinion about what a posting or a sealed audit record
//! contains, and a journal that could parse them would be a journal that has to change whenever they
//! do.
//!
//! The header being fixed is what makes verification cheap and total: a reader walks the run,
//! recomputes each body digest and each chain hash from the record's own bytes, and a record whose
//! body or header was edited fails at exactly that record rather than somewhere later.
//!
//! ## The chain hash, and what it covers
//!
//! `body_hash = SHA-256(body)`, and `hash = SHA-256(header[0 .. hash field])` — which is the
//! contract's `H(version ‖ node ‖ node_seq ‖ prev_hash ‖ body_hash)` with the rest of the fixed
//! header included as well. It is a superset deliberately: the class, the epochs and the two clocks
//! are as much part of what happened as the identity is, and a chain that did not cover them would
//! let a record be re-classed without breaking.
//!
//! ## Where the records physically go
//!
//! Through the log, which is the durable form of this chain and not a second one. With a data
//! directory the log's segments are files and the journal is on that disk. Without one the log is
//! memory-buffered and the records are shipped through the [`Shipper`] seam, which the composition
//! root binds to the store — so there is still no file, no probe and no warning; the journal did not
//! acquire a disk by acquiring a name. Which store verb that is on the other side is deliberately
//! not this crate's business: a log that knew the name of a database would be a log with an opinion
//! about deployments.
//!
//! ## The buffer is bounded, and full is a decision
//!
//! Without a data directory the store is where durability lives, so a batch the store refuses is
//! retained and offered again. Retained where? In a buffer of at most [`MEMORY_BUFFER_RECORDS`]
//! records — 8192 of them, which at the fixed frame size is 4 MiB. A bound is not optional: a node
//! whose store is unreachable for an hour must not answer that by exhausting its own memory.
//!
//! What happens at the bound is a NAMED decision and is on the chain. The oldest unshipped records
//! are dropped, and a [`RecordClass::ChainBreak`] record is sealed naming how many went and the
//! identity range they covered. Three things about that are deliberate:
//!
//! - It is not a silent drop. The loss is a record, in the chain, in order, and it is the class the
//!   contract already uses for a lost durable write.
//! - It is not a refusal. A deployment that configures no data directory is the previous release's
//!   shape, and that shape never refused admission for durability; making it start refusing when a
//!   store hiccups would be a deployment that stopped serving requests it used to serve.
//! - The oldest go, not the newest. What is nearest the head is what a reader is most likely to
//!   need, and a break at a known old position is easier to reconcile from a backup than a hole
//!   punched at the tail.

use std::collections::VecDeque;

use busbar_caps::{DurabilityLost, DurabilityToken, StepName};
use sha2::{Digest as _, Sha256};

use crate::record::Record;
use crate::ship::Shipper;
use crate::wal::{BatchAck, Mode, OpenError, Wal};

/// The four bytes every journal record's header opens with.
pub const JOURNAL_MAGIC: [u8; 4] = *b"BJRN";

/// The journal record layout version. A reader that meets one it does not know stops rather than
/// guessing at field offsets.
pub const JOURNAL_VERSION: u16 = 1;

/// How long a journal record's fixed header is. The body follows it.
pub const JOURNAL_HEADER_BYTES: usize = 160;

/// How many records the memory-buffered journal will hold for a store that has not acknowledged
/// them. At the log's fixed frame size this is 4 MiB.
///
/// Pinned rather than configurable: it is a bound on how much of a node's memory an unreachable
/// store may consume, and an operator who could raise it could turn a store outage into an
/// out-of-memory kill, which is strictly worse than a named break.
pub const MEMORY_BUFFER_RECORDS: usize = 8192;

/// How many overflows the in-memory history names in detail.
///
/// Every overflow seals a `ChainBreak` record carrying the same detail durably, so this window is a
/// convenience for a caller reading the node's current state, not the record of what was dropped.
/// Unbounded it would be a per-request cost for the whole length of a store outage.
pub const OVERFLOW_HISTORY_RECORDS: usize = 16;

/// Where in the header each field sits. Offsets are named rather than spelled at each use so that a
/// layout change is one edit and a reader can check the table against the module preamble.
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
    /// that has no epoch to report writes.
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
    ///
    /// Field-shape only: the digests are checked by [`verify`], because a caller reading a run wants
    /// to be told WHICH record broke and how, and a decode that refused would only be able to say
    /// that one did.
    ///
    /// # Errors
    ///
    /// The bytes are not a journal record: too short for the header, no magic, a layout version this
    /// build does not read, a class byte it does not know, or a body length that does not match what
    /// is there.
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
    /// hash field, which is what makes an edit anywhere in the header break the chain.
    #[must_use]
    pub fn digest_of_chain(&self) -> [u8; 32] {
        let bytes = self.encode();
        let mut hasher = Sha256::new();
        hasher.update(&bytes[0..at::HASH]);
        hasher.finalize().into()
    }

    /// This record's identity as the log knows it.
    #[must_use]
    pub fn identity(&self) -> (u64, u64) {
        (self.node, self.node_seq)
    }

    /// This record's chain hash in hexadecimal, for a report or a comparison a person reads.
    #[must_use]
    pub fn hash_hex(&self) -> String {
        hex(&self.hash)
    }
}

/// The digest of a body.
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().into()
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
///
/// Four separate checks, and they are separate because they fail differently: a body that was edited
/// is not the same event as a record that was removed, and an operator handed one break needs to
/// know which of them happened.
///
/// # Errors
///
/// The first record that does not verify, with what is wrong with it.
pub fn verify(records: &[JournalRecord]) -> Result<(), JournalBreak> {
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
        expected_prev = record.hash;
        expected_seq = Some(record.node_seq.saturating_add(1));
    }
    Ok(())
}

/// Decode a run of log records into journal records, in order.
///
/// This is how a reader gets the chain back out of whatever carried it — the log's own tail, or the
/// batches a store acknowledged.
///
/// # Errors
///
/// A record's bytes are not a journal record.
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
/// number to take next.
///
/// Only this node's records count. A run that carries several nodes' records — a store's replay, a
/// peer's shipment — must not advance this node's own numbering, because `(node, node_seq)` is the
/// identity the log deduplicates on and two nodes numbering from one shared counter would collide.
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
    /// fixed-width numbers, in the order the fields are named above. The break record's own sequence
    /// number is not in the body because the record already carries it in its header.
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
    /// overflows and the detail is already durable in the sealed break.
    overflows: VecDeque<Overflow>,
    /// How many overflows there have been, window or not.
    overflows_seen: usize,
    /// How many records the bound has cost in total.
    dropped_total: u64,
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
    /// A journal over a memory-buffered log that ships nowhere and touches no disk.
    #[must_use]
    pub fn memory_buffered(node: u64) -> Self {
        Journal::over(Wal::memory_buffered(), node)
    }

    /// A journal over a memory-buffered log shipping through `shipper` — the shape a deployment that
    /// names a store but no data directory runs.
    #[must_use]
    pub fn memory_buffered_to(node: u64, shipper: Box<dyn Shipper>) -> Self {
        Journal::over(Wal::memory_buffered_to(shipper), node)
    }

    /// A journal whose log keeps its segments as files under `dir`, resuming from whatever chain is
    /// already there.
    ///
    /// # Errors
    ///
    /// The directory could not be opened, or the log already there could not be read.
    pub fn in_directory(
        node: u64,
        dir: impl AsRef<std::path::Path>,
        shipper: Box<dyn Shipper>,
    ) -> Result<Self, OpenError> {
        Ok(Journal::over(Wal::in_directory(dir, shipper)?, node))
    }

    /// A journal over an already-open log, resuming from the tail the log recovered.
    ///
    /// This is the seam a battery drives, and it is also how the on-disk case resumes: the log's
    /// recovered tail IS the chain, so the head and the next sequence number come off it rather than
    /// being carried in a side file that could disagree with it.
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
        };
        // A tail that does not decode leaves the chain at genesis rather than resuming from bytes
        // this build cannot read. The records are still on the medium; nothing is destroyed by
        // declining to chain onto them.
        if let Ok(records) = decode_run(journal.log.recovered()) {
            if let Some((head, next_seq)) = tail_of(&records, node) {
                journal.head = head;
                journal.next_seq = next_seq;
            }
        }
        journal
    }

    /// A journal continuing a chain somebody else is holding — the store, on a node that keeps no
    /// data directory and whose own buffer therefore did not survive the restart.
    ///
    /// The head and the sequence number come from the records that were SHIPPED, which is the only
    /// honest place for them on such a node: what the store acknowledged is what exists.
    #[must_use]
    pub fn resuming(log: Wal, node: u64, head: [u8; 32], next_seq: u64) -> Self {
        let mut journal = Journal::over(log, node);
        journal.head = head;
        journal.next_seq = next_seq.max(1);
        journal
    }

    /// The same journal with a different buffer bound. For batteries that need to reach the bound
    /// without writing [`MEMORY_BUFFER_RECORDS`] records to get there.
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
    /// [`OVERFLOW_HISTORY_RECORDS`] of them.
    ///
    /// Every one of them also sealed a `ChainBreak` record naming the same thing, so this window is
    /// what the node can tell you about right now — not the record of what was dropped.
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
    ///
    /// The records are chained BEFORE the log is asked to take them, and the chain advances whether
    /// or not the log's answer is a durability loss. That is deliberate: a batch the store refused is
    /// retained by the log and offered again unchanged, so its records exist and are numbered — what
    /// is in doubt is whether anything else has them yet, and re-numbering them on the retry would
    /// make the chain disagree with the copy already in flight.
    ///
    /// # Errors
    ///
    /// The log could not make the batch durable. Without a data directory that means the store
    /// refused it; with one it means a write or a sync failed. Either way the records are retained
    /// and re-offered on the next append, up to the bound.
    pub fn append(
        &mut self,
        token: &DurabilityToken,
        at: StepName,
        entries: &[Entry],
    ) -> Result<JournalAck, DurabilityLost> {
        let overflow = self.make_room(entries.len());

        let mut sealed = Vec::with_capacity(entries.len() + usize::from(overflow.is_some()));
        if let Some(overflow) = &overflow {
            sealed.push(self.seal(&Entry::new(RecordClass::ChainBreak, overflow.body())));
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

    /// Read the chain back out of the log's current segment, verifying as it goes.
    ///
    /// # Errors
    ///
    /// The log could not be read, or what came back does not verify.
    pub fn replay(&self) -> std::io::Result<Result<Vec<JournalRecord>, JournalBreak>> {
        let back = self.log.read_back()?;
        Ok(decode_run(&back.records).and_then(|records| verify(&records).map(|()| records)))
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
    /// otherwise be passed. Returns what went, so the caller can seal a break for it.
    fn make_room(&mut self, incoming: usize) -> Option<Overflow> {
        let held = self.log.owed().len();
        let wanted = held.saturating_add(incoming);
        if wanted <= self.capacity {
            return None;
        }
        let excess = wanted - self.capacity;
        let dropped = self.log.forget_owed(excess);
        let first = dropped.first()?.identity();
        let last = dropped.last()?.identity();
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
