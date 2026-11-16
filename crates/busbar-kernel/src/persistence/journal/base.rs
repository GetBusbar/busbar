// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REPLAY BASE OF AN EPHEMERAL JOURNAL (SEALING-FIX r20 §3.9): the `B@0` row, the audit tail
//! it carries, and the pins that keep live rows above it.
//!
//! Only a journal whose Store reports `Durability::Ephemeral` ever has a base: its data ends with
//! the process, so no other process reads it, and no historical prefix or predecessor exists. A
//! base `Base { magic, count, sequence, hash, records_seal, keep }` is the `Head` and original-byte
//! seal at the cut, so a replay that starts at it produces the same `VerifiedHead` as a full
//! replay. `hash` is the WAL chain hash, never an audit fingerprint.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use super::*;

const BASE_MAGIC: &[u8; 8] = b"BBJBASE1";
/// Fixed part: magic, count, sequence, hash, records_seal, tail (chain_seq, node_seq, fp), kept.
const BASE_FIXED: usize = 8 + 8 + 8 + 32 + 32 + 8 + 8 + 32 + 4;

/// A cut moves the base only by at least this many records (§3.9 `CUT_BATCH`).
pub const CUT_BATCH: u64 = 1024;
/// The newest records a cut always leaves (§3.9 floor (c)): the stamp ring, the admin audit page
/// and a recent-window verify read live rows.
pub const RETAIN_TAIL: u64 = 4096;
/// At most this many record copies ride in a base's `keep` (this boot's `Bootstrap` opening record
/// and its `notary_key` line, §3.9), bounded in bytes too.
pub const KEEP_MAX: usize = 4;
const KEEP_BYTES: usize = 8 * 1024;

/// The newest audit line at or below a journal position: its chain seq, the WAL `node_seq` of the
/// record that carries it, and its fingerprint (`LineAt`, §3.2). All zero before the first line.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditTail {
    pub chain_seq: u64,
    pub node_seq: u64,
    pub fp: [u8; 32],
}

/// The decoded `B@0` row.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Base {
    pub(super) head: Head,
    pub(super) records_seal: [u8; 32],
    pub(super) tail: AuditTail,
    /// Copies of the few record bodies below the base that readers above it still name, in
    /// `node_seq` order. Context only: a copy is never a chain line.
    pub(super) keep: Vec<Record>,
}

impl std::fmt::Debug for Base {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Base")
            .field("count", &self.head.count)
            .field("sequence", &self.head.sequence)
            .field("tail", &self.tail)
            .field("keep", &self.keep.len())
            .finish_non_exhaustive()
    }
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N]> {
    let end = at.checked_add(N).ok_or(Error::Corrupt)?;
    let out = bytes
        .get(*at..end)
        .ok_or(Error::Corrupt)?
        .try_into()
        .map_err(|_| Error::Corrupt)?;
    *at = end;
    Ok(out)
}

impl Base {
    /// The journal ordinal of the newest row this base covers.
    pub(crate) fn count(&self) -> u64 {
        self.head.count
    }

    /// The audit tail at the base.
    pub(crate) fn tail(&self) -> AuditTail {
        self.tail
    }

    pub(super) fn encode(&self) -> Result<Secret<Vec<u8>>> {
        let kept: usize = self.keep.iter().map(|record| 4 + record.body.len()).sum();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(BASE_FIXED + kept)
            .map_err(|_| Error::Budget)?;
        bytes.extend_from_slice(BASE_MAGIC);
        bytes.extend_from_slice(&self.head.count.to_le_bytes());
        bytes.extend_from_slice(&self.head.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.head.hash);
        bytes.extend_from_slice(&self.records_seal);
        bytes.extend_from_slice(&self.tail.chain_seq.to_le_bytes());
        bytes.extend_from_slice(&self.tail.node_seq.to_le_bytes());
        bytes.extend_from_slice(&self.tail.fp);
        let count = u32::try_from(self.keep.len()).map_err(|_| Error::Budget)?;
        bytes.extend_from_slice(&count.to_le_bytes());
        for record in &self.keep {
            let len = u32::try_from(record.body.len()).map_err(|_| Error::Budget)?;
            bytes.extend_from_slice(&len.to_le_bytes());
            bytes.extend_from_slice(&record.body);
        }
        Ok(Secret::new(bytes))
    }

    /// Decode and check a stored base of `node`'s journal: every kept copy verifies as a WAL
    /// original of this node at or below the base, in strictly increasing `node_seq` order.
    pub(super) fn decode(node: u64, raw: &Secret<Vec<u8>>) -> Result<Self> {
        let bytes = raw.expose(&crate::seal::lend());
        if bytes.len() < BASE_FIXED || bytes.get(..8) != Some(BASE_MAGIC.as_slice()) {
            return Err(Error::Corrupt);
        }
        let mut at = 8;
        let head = Head {
            count: u64::from_le_bytes(take(bytes, &mut at)?),
            sequence: u64::from_le_bytes(take(bytes, &mut at)?),
            hash: take(bytes, &mut at)?,
        };
        let records_seal = take(bytes, &mut at)?;
        let tail = AuditTail {
            chain_seq: u64::from_le_bytes(take(bytes, &mut at)?),
            node_seq: u64::from_le_bytes(take(bytes, &mut at)?),
            fp: take(bytes, &mut at)?,
        };
        let kept = u32::from_le_bytes(take(bytes, &mut at)?) as usize;
        if head.count == 0
            || head.sequence == 0
            || tail.node_seq > head.sequence
            || kept > KEEP_MAX
            || bytes.len() - BASE_FIXED > KEEP_BYTES
        {
            return Err(Error::Corrupt);
        }
        let mut keep = Vec::with_capacity(kept);
        let mut previous = 0u64;
        for _ in 0..kept {
            let len = u32::from_le_bytes(take(bytes, &mut at)?) as usize;
            let end = at.checked_add(len).ok_or(Error::Corrupt)?;
            let body = bytes.get(at..end).ok_or(Error::Corrupt)?;
            at = end;
            let decoded = decode_record(node, body)?;
            if decoded.node_seq <= previous || decoded.node_seq > head.sequence {
                return Err(Error::Corrupt);
            }
            previous = decoded.node_seq;
            keep.push(Record::new(node, decoded.node_seq, body));
        }
        if at != bytes.len() {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            head,
            records_seal,
            tail,
            keep,
        })
    }
}

/// What a walk of one node's journal returns (§3.9 "Kept rows first"): the base's kept copies
/// (empty without a base) and the verified rows after the base.
#[derive(Debug, Default)]
pub struct NodeRecords {
    /// Audit context at the exact replay base that precedes `rows`.
    pub base_tail: Option<AuditTail>,
    pub kept: Vec<JournalRecord>,
    pub rows: Vec<JournalRecord>,
}

/// The journal ordinal of `seq` on a journal at `head` (§3.9: on an Ephemeral journal ordinal and
/// sequence both step by one per record, so `ordinal(seq) = seq − head.sequence + head.count`).
pub(super) fn ordinal(head: &Head, seq: u64) -> u64 {
    if seq >= head.sequence {
        head.count.saturating_add(seq - head.sequence)
    } else {
        head.count.saturating_sub(head.sequence - seq)
    }
}

/// THE PINS (§3.9 floor (d)): `seq -> holders` of every row a live in-process structure names. A
/// cut never passes `min − 1`. Lock order: a journal's `state`, then this.
#[derive(Debug, Default)]
pub(super) struct Pins(Mutex<BTreeMap<u64, u32>>);

impl Pins {
    pub(super) fn pin(self: &Arc<Self>, seq: u64) -> Pin {
        let mut held = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let holders = held.entry(seq).or_insert(0);
        *holders = holders.saturating_add(1);
        Pin {
            pins: Arc::clone(self),
            seq,
        }
    }

    /// The lowest pinned sequence.
    pub(super) fn min(&self) -> Option<u64> {
        self.0
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .next()
            .copied()
    }
}

/// AN RAII HOLD ON ONE JOURNAL ROW of an Ephemeral journal (§3.9 floor (d)): while it lives no cut
/// deletes row `seq` or any row after it. Dropping it releases the hold.
pub struct Pin {
    pins: Arc<Pins>,
    seq: u64,
}

impl Pin {
    /// The pinned row's WAL `node_seq`.
    #[must_use]
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

impl Clone for Pin {
    fn clone(&self) -> Self {
        self.pins.pin(self.seq)
    }
}

impl Drop for Pin {
    fn drop(&mut self) {
        let mut held = self.pins.0.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(holders) = held.get_mut(&self.seq) {
            *holders = holders.saturating_sub(1);
            if *holders == 0 {
                held.remove(&self.seq);
            }
        }
    }
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pin").field("seq", &self.seq).finish()
    }
}

static WALK_RESTARTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// A walk restarts from a new base at most this many times, then answers `Busy` (§3.9 "One
/// walker").
pub(super) const WALK_RESTART_LIMIT: u32 = 3;

pub(super) fn count_walk_restart() {
    WALK_RESTARTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Journal walks restarted from a newer base since the process started (`journal_walk_restarts`).
#[must_use]
pub fn journal_walk_restarts() -> u64 {
    WALK_RESTARTS.load(std::sync::atomic::Ordering::Relaxed)
}
