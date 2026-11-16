// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE JOURNAL CODEC'S OFF-PATH CODE: reading a journal back (decoding a stored record, a run of
//! them, the holes a chain may cross), which runs at recovery and verification and never per
//! request. It sits outside the request-path marker because it owns its decoded copies; the
//! request path only writes.

use foldhash::HashSet;

use crate::journal::{
    at, read32, read4, read8, JournalBreak, JournalBreakKind, JournalRecord, RecordClass,
    JOURNAL_HEADER_BYTES, JOURNAL_MAGIC, JOURNAL_VERSION,
};
use crate::note::{Bridge, QuarantineNote};
use crate::record::Record;

impl JournalRecord {
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
        let body = bytes[JOURNAL_HEADER_BYTES..].to_vec();
        Ok(JournalRecord {
            class,
            node: u64::from_le_bytes(read8(bytes, at::NODE)),
            node_seq: u64::from_le_bytes(read8(bytes, at::NODE_SEQ)),
            lease_epoch: u64::from_le_bytes(read8(bytes, at::LEASE_EPOCH)),
            policy_epoch: u64::from_le_bytes(read8(bytes, at::POLICY_EPOCH)),
            wall: u64::from_le_bytes(read8(bytes, at::WALL)),
            mono: u64::from_le_bytes(read8(bytes, at::MONO)),
            body,
            body_hash: read32(bytes, at::BODY_HASH),
            prev_hash: read32(bytes, at::PREV_HASH),
            hash: read32(bytes, at::HASH),
        })
    }
}

/// The holes a run may cross — `known`, then every quarantine `ChainBreak` in `records` — and the
/// records they are anchored on. Only a chain that already carries a break gets here.
pub(crate) fn bridges_of(
    records: &[JournalRecord],
    known: &[Bridge],
) -> (Vec<Bridge>, HashSet<(u64, u64)>) {
    let mut bridges: Vec<Bridge> = known.to_vec();
    bridges.extend(
        records
            .iter()
            .filter(|r| r.class == RecordClass::ChainBreak)
            .filter_map(|r| QuarantineNote::read(&r.body).and_then(|note| note.bridge)),
    );
    let anchors: HashSet<(u64, u64)> = bridges.iter().map(|b| b.before).collect();
    (bridges, anchors)
}

/// Decode a run of log records into journal records, in order.
pub fn decode_run(records: &[Record]) -> Result<Vec<JournalRecord>, JournalBreak> {
    let decoded = records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            JournalRecord::decode(&r.body).map_err(|mut e| {
                e.at_index = i + 1;
                e
            })
        })
        .collect();
    decoded
}
