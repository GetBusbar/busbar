// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE RECORD CHAINS ON THE KERNEL'S RECORD PATH (`BUSBAR-1.6.0.md` THE DESIGN, the route
//! pump: "A record kind the plane declares as chained keeps its declared framing (§5:
//! length-prefixed or pipe-separated, with or without the scope in the digest); the host frames
//! and verifies its chain"; Part 3 §5). The contract's words for a chained kind are on
//! `abi::plane::RecordChain`; this is the host's half, naming no plane.
//!
//! * THE DECLARATION ([`ChainFraming::of`]) is the tail's `record_chains` entry for the kind: its
//!   framing and whether the scope enters the digest.
//! * AN APPEND is sealed when the write-behind flush reaches it ([`ChainBook::append`]), on the
//!   pool, one flush at a time, so the chain's order is the queue's. The position (the next
//!   sequence and the tail's digest) is the ONE chain mechanism's ([`crate::audit::Chain`]) and the
//!   digest its ([`crate::audit::frame_prelude`] in the declared framing, then the plane's bytes
//!   raw: [`StreamRecord`]). The position advances only once the store took the record (the
//!   journal's write-ordering rule), so a refused write burns no sequence.
//! * A SCOPE THE CACHE DOES NOT HOLD (the first append after a start, or one evicted past
//!   [`POSITIONS_CAP`]) is RESUMED from the store: its records are read back and VERIFIED; a chain
//!   that does not verify is reported (`PLANE_JOURNAL_RESUME_CHAIN_BROKEN`) and continued from its
//!   tail, never refused, since refusing would make detection a deletion primitive.
//! * A READ ([`verified`]) groups the stored records by chain, verifies each and answers the
//!   records with a span announcing each break ahead of them: the plane learns of it and says it
//!   in its own words. An undecodable record is skipped, counted and reported
//!   (`PLANE_JOURNAL_ROW_UNREADABLE`), never allowed to drop the rest.
//! * A record is stored under `record_key(instance, chain_key(scope, seq))` as [`encode`]'s body:
//!   a version byte, the sequence, the previous and own digests, then the plane's bytes.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;

use busbar_contract::abi::plane::{
    RecordChain, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED,
};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::services::{chain_key, chain_key_parts};

use crate::audit::journal::NeutralRecord;
use crate::audit::stream_registry::{StreamInput, StreamRecord};
use crate::audit::{verify_chain, Chain, ChainBreak, ChainedRecord, Framing};
use crate::host_records::{record_key, RecordRows, WRITE_FAILED};

/// The refusal of a chained write whose key is no scope: empty, not UTF-8, or ending in what a
/// listed record key ends in.
pub const CHAIN_SCOPE_UNFIT: &str =
    "a chained record's key is its chain's scope: UTF-8, not empty, not ending in `/<20 digits>`";
/// The refusal of a chained write too large to keep with its chain fields.
pub const CHAIN_RECORD_TOO_LARGE: &str =
    "a chained record's bytes and its chain fields exceed the record ceiling";
/// The refusal of `records.get` on a chained kind.
pub const CHAIN_READ_WHOLE: &str = "a chained record kind is read whole, through records.list";

/// The stored body's layout version.
const BODY_VERSION: u8 = 1;

/// The most bytes the host adds to a chained record's own: the version, the sequence, and two
/// sha256 digests in hex with a length byte each.
pub const CHAIN_OVERHEAD: usize = 1 + 8 + 1 + 64 + 1 + 64;

/// The most chain positions held in memory; past it the least recently written is resumed from
/// the store on its next append.
pub const POSITIONS_CAP: usize = 65_536;

/// A chained record kind's declaration, as the host frames it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainFraming {
    pub(crate) framing: Framing,
    pub(crate) digests_scope: bool,
}

impl ChainFraming {
    /// The framing `c` declares; `None` for a framing or a flag this build does not know (the
    /// loader refuses such a tail, `check_record_chains`).
    #[must_use]
    pub fn of(c: &RecordChain) -> Option<Self> {
        let framing = match c.framing {
            CHAIN_LENGTH_PREFIXED => Framing::LengthPrefixed,
            CHAIN_PIPE_SEPARATED => Framing::PipeSeparated,
            _ => return None,
        };
        if c.flags & !CHAIN_DIGESTS_SCOPE != 0 {
            return None;
        }
        Some(Self {
            framing,
            digests_scope: c.flags & CHAIN_DIGESTS_SCOPE != 0,
        })
    }
}

/// Whether `key` may name a chain: UTF-8, not empty, and not shaped like a listed record's key
/// (which a break's span, keyed by the bare scope, must never be mistaken for).
#[must_use]
pub fn scope_of(key: &[u8]) -> Option<&str> {
    let scope = std::str::from_utf8(key).ok()?;
    (!scope.is_empty() && chain_key_parts(key).is_none()).then_some(scope)
}

/// The stored body of `r`; `None` when a digest is longer than a length byte holds.
pub(crate) fn encode(r: &StreamRecord) -> Option<Vec<u8>> {
    let (prev, hash) = (r.prev_hash().as_bytes(), r.hash().as_bytes());
    let mut body = Vec::with_capacity(CHAIN_OVERHEAD + r.content().len());
    body.push(BODY_VERSION);
    body.extend_from_slice(&r.seq().to_be_bytes());
    body.push(u8::try_from(prev.len()).ok()?);
    body.extend_from_slice(prev);
    body.push(u8::try_from(hash.len()).ok()?);
    body.extend_from_slice(hash);
    body.extend_from_slice(r.content());
    Some(body)
}

/// The record a stored `body` of the chain `scope` holds, under the declaration `f`; `None` for a
/// body this build did not write.
pub(crate) fn decode(scope: &str, body: &[u8], f: ChainFraming) -> Option<StreamRecord> {
    let (&version, rest) = body.split_first()?;
    if version != BODY_VERSION || rest.len() < 8 {
        return None;
    }
    let (seq, rest) = rest.split_at(8);
    let seq = u64::from_be_bytes(seq.try_into().ok()?);
    let (prev, rest) = digest_text(rest)?;
    let (hash, rest) = digest_text(rest)?;
    Some(StreamRecord::from_parts(
        scope.to_string(),
        seq,
        prev,
        hash,
        rest.to_vec(),
        f.framing,
        f.digests_scope,
    ))
}

/// One length-byte-prefixed digest off the front of `bytes`, and what follows it.
fn digest_text(bytes: &[u8]) -> Option<(String, &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    let len = usize::from(len);
    if rest.len() < len {
        return None;
    }
    let (field, rest) = rest.split_at(len);
    Some((String::from_utf8(field.to_vec()).ok()?, rest))
}

/// One chain's position: the instance's label, the kind, the scope.
type Position = (Arc<str>, String, String);

/// One stored row, `(key, bytes)`.
type Row = (Vec<u8>, Vec<u8>);

/// Every chain's position, the least recently written first.
type Positions = IndexMap<Position, Chain<StreamRecord>>;

/// THE CHAIN POSITIONS of every instance's chained kinds, the flush's to keep.
#[derive(Default)]
pub struct ChainBook {
    positions: Mutex<Positions>,
}

impl std::fmt::Debug for ChainBook {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainBook")
            .field("positions", &self.lock().len())
            .finish()
    }
}

impl ChainBook {
    fn lock(&self) -> MutexGuard<'_, Positions> {
        self.positions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Keep `chain` as the position at `at`, the most recently written.
    fn commit(&self, at: Position, chain: Chain<StreamRecord>) {
        let mut positions = self.lock();
        positions.shift_remove(&at);
        positions.insert(at, chain);
        while positions.len() > POSITIONS_CAP {
            positions.shift_remove_index(0);
        }
    }

    /// APPEND `content` to `instance`'s chain `scope` of `schema`: seal it at the chain's next
    /// position, store it, and advance the position once the store took it.
    ///
    /// # Errors
    ///
    /// [`WRITE_FAILED`] when the store refused the read that resumes the chain or the record;
    /// [`CHAIN_RECORD_TOO_LARGE`] when the sealed record exceeds the ceiling. The position is left
    /// where it was.
    pub(crate) fn append(
        &self,
        rows: &dyn RecordRows,
        instance: &Arc<str>,
        schema: RecordSchemaId,
        scope: &str,
        content: &[u8],
        f: ChainFraming,
    ) -> Result<(), &'static str> {
        let at: Position = (
            Arc::clone(instance),
            schema.as_str().to_string(),
            scope.to_string(),
        );
        let cached = self.lock().get(&at).cloned();
        let mut chain = match cached {
            Some(chain) => chain,
            None => resume(rows, instance, schema, scope, f)?,
        };
        let record = chain.append(
            scope,
            StreamInput::new(content.to_vec(), f.framing, f.digests_scope),
        );
        let body = encode(&record).ok_or(CHAIN_RECORD_TOO_LARGE)?;
        let body = RecordBytes::new(body).map_err(|_| CHAIN_RECORD_TOO_LARGE)?;
        let key = record_key(instance, &chain_key(scope.as_bytes(), record.seq()));
        rows.record_put(schema, &key, &body)
            .map_err(|_| WRITE_FAILED)?;
        self.commit(at, chain);
        Ok(())
    }

    /// DROP `instance`'s chain `scope` of `schema`: a tombstone over each of its records, and its
    /// position forgotten, so its next append starts again at sequence `1`.
    ///
    /// # Errors
    ///
    /// [`WRITE_FAILED`] when the store refused the read or a tombstone.
    pub(crate) fn drop_chain(
        &self,
        rows: &dyn RecordRows,
        instance: &Arc<str>,
        schema: RecordSchemaId,
        scope: &str,
    ) -> Result<(), &'static str> {
        let at: Position = (
            Arc::clone(instance),
            schema.as_str().to_string(),
            scope.to_string(),
        );
        let dropped = tombstone(rows, instance, schema, scope);
        self.lock().shift_remove(&at);
        dropped
    }
}

/// Tombstone every live record of `instance`'s chain `scope`.
fn tombstone(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
) -> Result<(), &'static str> {
    let tomb = RecordBytes::new(Vec::new()).map_err(|_| WRITE_FAILED)?;
    let unscoped = record_key(instance, &[]).len();
    for (key, value) in held(rows, instance, schema, scope)? {
        if value.as_slice().is_empty() {
            continue;
        }
        let ours = key
            .get(unscoped..)
            .and_then(chain_key_parts)
            .is_some_and(|(s, _)| s == scope.as_bytes());
        if ours {
            rows.record_put(schema, &key, &tomb)
                .map_err(|_| WRITE_FAILED)?;
        }
    }
    Ok(())
}

/// The store's rows under `instance`'s chain `scope` (and any chain whose scope it prefixes).
fn held(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
) -> Result<Vec<(Vec<u8>, RecordBytes)>, &'static str> {
    let mut prefix = scope.as_bytes().to_vec();
    prefix.push(b'/');
    rows.record_scan(schema, &record_key(instance, &prefix), u32::MAX)
        .map_err(|_| WRITE_FAILED)
}

/// RESUME `instance`'s chain `scope` from the store: its records read back, VERIFIED, and the
/// position taken from the tail; a break is reported and the chain continued from its tail.
fn resume(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
    f: ChainFraming,
) -> Result<Chain<StreamRecord>, &'static str> {
    let unscoped = record_key(instance, &[]).len();
    let mut stored: Vec<Row> = held(rows, instance, schema, scope)?
        .into_iter()
        .filter_map(|(k, v)| Some((k.get(unscoped..)?.to_vec(), v.as_slice().to_vec())))
        .filter(|(k, _)| chain_key_parts(k).is_some_and(|(s, _)| s == scope.as_bytes()))
        .collect();
    stored.sort();
    let records: Vec<StreamRecord> = decoded(instance, schema, scope, &stored, f)
        .into_iter()
        .map(|(_, r)| r)
        .collect();
    Ok(match Chain::from_persisted(&records) {
        Ok(chain) => chain,
        Err(brk) => {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_JOURNAL_RESUME_CHAIN_BROKEN,
                instance = %instance,
                stream = %schema.as_str(),
                break_detail = %brk,
                "a plane record chain read back from the store to take its next record does NOT \
                 verify against its own hash chain. The chain resumes from the broken tail; the \
                 write is not refused."
            );
            Chain::from_persisted_unverified(&records)
        }
    })
}

/// The live records among `stored` (`(chain key, body)` of one chain, in key order), decoded and
/// each beside its key; an undecodable one is skipped and reported, never allowed to drop the rest.
fn decoded<'k>(
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
    stored: &'k [Row],
    f: ChainFraming,
) -> Vec<(&'k [u8], StreamRecord)> {
    stored
        .iter()
        .filter(|(_, body)| !body.is_empty())
        .filter_map(|(key, body)| {
            let record = decode(scope, body, f);
            if record.is_none() {
                crate::diagnostics::diag_error!(
                    crate::diagnostics::PLANE_JOURNAL_ROW_UNREADABLE,
                    instance = %instance,
                    stream = %schema.as_str(),
                    scope = %scope,
                    key = %String::from_utf8_lossy(key),
                    "a stored plane chain record could not be decoded; it is SKIPPED and counted \
                     rather than dropping the rest of its chain, and reported here so the lost \
                     evidence is never invisible."
                );
            }
            Some((key.as_slice(), record?))
        })
        .collect()
}

/// THE VERIFIED READ of `instance`'s chained kind: `stored` (the store's rows under the list's
/// prefix, keys unscoped) grouped by chain, each chain verified, answered as `(chain key, the
/// plane's own bytes)` per record, with a `(scope, the break in words)` span ahead of each chain
/// that does not verify. Rows that are no chain record's (a tombstone, a foreign key) are not
/// answered.
#[must_use]
pub fn verified(
    instance: &str,
    schema: RecordSchemaId,
    stored: Vec<Row>,
    f: ChainFraming,
) -> Vec<Row> {
    let mut chains: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for (key, body) in stored {
        if body.is_empty() {
            continue;
        }
        let Some(scope) = chain_key_parts(&key)
            .and_then(|(s, _)| std::str::from_utf8(s).ok())
            .map(str::to_string)
        else {
            continue;
        };
        chains.entry(scope).or_default().push((key, body));
    }
    let mut out = Vec::new();
    for (scope, mut rows) in chains {
        rows.sort();
        let records = decoded(instance, schema, &scope, &rows, f);
        let chain: Vec<StreamRecord> = records.iter().map(|(_, r)| r.clone()).collect();
        if let Err(brk) = verify_chain(&chain) {
            out.push((scope.as_bytes().to_vec(), break_words(&brk)));
        }
        out.extend(
            records
                .iter()
                .map(|(key, r)| (key.to_vec(), r.content().to_vec())),
        );
    }
    out
}

/// A break's words, as the span announcing it carries them.
fn break_words(brk: &ChainBreak) -> Vec<u8> {
    brk.to_string().into_bytes()
}

#[cfg(test)]
#[path = "tests/host_chains_unit_tests.rs"]
mod tests;
