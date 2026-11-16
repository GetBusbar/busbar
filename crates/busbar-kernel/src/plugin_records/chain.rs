// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host chains in a plugin-records namespace (IF §12.5 round 12, §8.6 LK_CHAIN, §16.111).
//!
//! A chain is named by its key, which is also its digest scope, exactly as 1.5.5 `host_chains.rs` scoped a
//! chained record: UTF-8, not empty, not ending in `/<20 digits>`. Each entry is framed, linked and sealed by
//! the kernel's one chain code (`audit::seal` over `StreamRecord`, length-prefixed with the scope in the
//! digest, the framing plane-mcp's call log and plane-a2a's task events declared) and stored as
//! `host_chains::encode`'s bytes, so a stored frame is byte-equal to 1.5.5's for the same entries.
//!
//! Rows, under the [`CHAINS`] schema: the head `scope ‖ 'h' ‖ chain` = `1 ‖ len (u64 BE) ‖ tail hash`, and
//! one row per entry, `scope ‖ 'e' ‖ chain length (u32 BE) ‖ chain ‖ seq (u64 BE)`. An append is one CoreStore
//! commit that pins the head it read and writes the new head and the new entry together, so two appenders
//! never take one sequence. A read walks the chain from the first entry, verifying sequence, link and digest
//! of every entry and the head's tail hash against the last one; `broken_at` is the first entry that fails or
//! is missing (a missing tail included), and no entry from it on is handed over.

use busbar_contract::Secret;
use busbar_plugin_abi::host_side::caller::Caller;

use crate::audit::stream_registry::{StreamInput, StreamRecord};
use crate::audit::Framing;
use crate::host_chains::{self, ChainFraming};
use crate::persistence::scoped::{Expected, Mutation, Predicate, Request};

use super::store::{denied, scoped_key, StoreRecords, CHAINS};
use super::{ChainRead, RecordsDenied, Scope, MAX_CHAIN_ENTRY, MAX_KEY};

/// plane-mcp's and plane-a2a's declared chain framing (`CHAIN_LENGTH_PREFIXED` with `CHAIN_DIGESTS_SCOPE`).
const FRAMING: ChainFraming = ChainFraming {
    framing: Framing::LengthPrefixed,
    digests_scope: true,
};
/// The head-row version byte.
const HEAD: u8 = 1;
/// Entries read per store crossing.
const BATCH: u64 = 64;

pub(super) fn head_key(scope: Scope, chain: &[u8]) -> Vec<u8> {
    let mut key = scoped_key(scope, b"h");
    key.extend_from_slice(chain);
    key
}

/// Every entry key of `chain` is this prefix and 8 more bytes (the sequence).
pub(super) fn entries_prefix(scope: Scope, chain: &[u8]) -> Vec<u8> {
    let mut key = scoped_key(scope, b"e");
    key.extend_from_slice(&u32::try_from(chain.len()).unwrap_or(u32::MAX).to_be_bytes());
    key.extend_from_slice(chain);
    key
}

pub(super) fn entry_key(prefix: &[u8], seq: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + 8);
    key.extend_from_slice(prefix);
    key.extend_from_slice(&seq.to_be_bytes());
    key
}

fn encode_head(len: u64, tail: &str) -> Secret<Vec<u8>> {
    let mut out = Vec::with_capacity(9 + tail.len());
    out.push(HEAD);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(tail.as_bytes());
    Secret::new(out)
}

fn decode_head(raw: &[u8]) -> Option<(u64, String)> {
    let (&version, rest) = raw.split_first()?;
    if version != HEAD || rest.len() < 8 {
        return None;
    }
    let (len, tail) = rest.split_at(8);
    Some((
        u64::from_be_bytes(len.try_into().ok()?),
        String::from_utf8(tail.to_vec()).ok()?,
    ))
}

/// The chain's digest scope: its name as text.
fn chain_scope(chain: &[u8]) -> Result<&str, RecordsDenied> {
    if chain.len() > MAX_KEY {
        return Err(RecordsDenied::TooLarge);
    }
    host_chains::scope_of(chain).ok_or(RecordsDenied::Invalid)
}

impl StoreRecords {
    pub(super) async fn append_entry(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        entry: &[u8],
    ) -> Result<u64, RecordsDenied> {
        let name = chain_scope(chain)?;
        if entry.len() > MAX_CHAIN_ENTRY {
            return Err(RecordsDenied::TooLarge);
        }
        let records = self.scoped(who)?;
        self.collect_one().await;
        let head = head_key(scope, chain);
        let entries = entries_prefix(scope, chain);
        for _ in 0..=self.retries() {
            let found = records.get(CHAINS, &head).await.map_err(denied)?;
            let (len, tail) = match &found {
                None => (0, String::new()),
                Some(raw) => {
                    let seal = crate::seal::lend();
                    decode_head(raw.expose(&seal)).ok_or(RecordsDenied::Unavailable)?
                }
            };
            // A chain at u64::MAX entries takes no more: the namespace is full for it.
            let seq = len.checked_add(1).ok_or(RecordsDenied::Quota)?;
            let record: StreamRecord = crate::audit::seal(
                name,
                seq,
                tail,
                StreamInput::new(entry.to_vec(), FRAMING.framing, FRAMING.digests_scope),
            );
            let body = host_chains::encode(&record).ok_or(RecordsDenied::TooLarge)?;
            let request = Request {
                op_id: self.operation()?,
                predicates: vec![Predicate {
                    schema: CHAINS.to_string(),
                    key: head.clone(),
                    expected: found.map_or(Expected::Absent, Expected::Exact),
                }],
                mutations: vec![
                    Mutation::Put {
                        schema: CHAINS.to_string(),
                        key: head.clone(),
                        value: encode_head(seq, &record.hash),
                    },
                    Mutation::Put {
                        schema: CHAINS.to_string(),
                        key: entry_key(&entries, seq),
                        value: Secret::new(body),
                    },
                ],
            };
            if self
                .decided(&records, records.conditional_native(&request).await)
                .await?
            {
                return Ok(seq);
            }
        }
        Err(RecordsDenied::Unavailable)
    }

    pub(super) async fn read_chain(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        after: u64,
        limit: u32,
        sink: &mut (dyn FnMut(u64, &[u8]) + Send),
    ) -> Result<ChainRead, RecordsDenied> {
        let name = chain_scope(chain)?;
        let records = self.scoped(who)?;
        let Some(raw) = records
            .get(CHAINS, &head_key(scope, chain))
            .await
            .map_err(denied)?
        else {
            return Ok(ChainRead::default());
        };
        let (len, tail) = {
            let seal = crate::seal::lend();
            decode_head(raw.expose(&seal)).ok_or(RecordsDenied::Unavailable)?
        };
        let entries = entries_prefix(scope, chain);
        let mut read = ChainRead {
            hits: 0,
            len,
            broken_at: 0,
        };
        let mut prev = String::new();
        let mut first = 1u64;
        'walk: while first <= len {
            let last = len.min(first.saturating_add(BATCH - 1));
            let keys: Vec<Vec<u8>> = (first..=last).map(|seq| entry_key(&entries, seq)).collect();
            let at: Vec<(&str, &[u8])> = keys.iter().map(|key| (CHAINS, key.as_slice())).collect();
            let rows = records.read(&at).await.map_err(denied)?;
            if rows.len() != keys.len() {
                return Err(RecordsDenied::Unavailable);
            }
            let seal = crate::seal::lend();
            for (seq, row) in (first..=last).zip(&rows) {
                let verified = row
                    .as_ref()
                    .and_then(|row| host_chains::decode(name, row.expose(&seal), FRAMING))
                    .filter(|r| {
                        r.seq == seq
                            && r.prev_hash == prev
                            && crate::audit::digest(r) == r.hash
                            && (seq != len || r.hash == tail)
                    });
                let Some(record) = verified else {
                    read.broken_at = seq;
                    break 'walk;
                };
                if seq > after && read.hits < limit {
                    sink(seq, &record.content);
                    read.hits += 1;
                }
                prev = record.hash;
            }
            first = last.saturating_add(1);
            if last == u64::MAX {
                break;
            }
        }
        if read.broken_at != 0 {
            tracing::warn!(
                plugin = who.plugin,
                instance = who.name,
                broken_at = read.broken_at,
                len = read.len,
                "a plugin record chain failed verification on read; entries from the break on are withheld"
            );
        }
        Ok(read)
    }
}
