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
//! * LEGACY POSITION CLAIMS. Before a record is stored its position is CLAIMED in
//!   the store ([`RecordRows::claim`]): the instance, the kind, the scope, the chain's life, the
//!   sequence and the previous digest. A node that loses the claim, or finds the slot already
//!   holding a record (its cached position is stale: another node wrote there), forgets its
//!   position, resumes from the store's tail and seals again, so two nodes appending to one chain
//!   continue each other's completed records. The chain's LIFE is a counter the
//!   store keeps under the host's own record kind ([`CHAIN_LIFE_SCHEMA`], never a plane's, so a scan
//!   of the plane's kind never meets it): every drop raises it before striking the chain's rows, and
//!   every append rereads it, so a chain dropped and begun again, on this node or any other, never meets
//!   its old claims. (A drop's strikes REMOVE its rows, slot 26's rule, so nothing in the plane's
//!   kind is left to count.) These separate legacy reads, claims and puts cannot atomically fence
//!   a concurrent drop or a lease expiring during a store call. The conditional path below uses
//!   the existing transactional contract for that stronger guarantee.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use indexmap::IndexMap;

use busbar_contract::abi::plane::{
    RecordChain, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED,
};
use busbar_contract::abi::sdk::store::conditional::{Expected, Mutation, Predicate, Request};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::services::{chain_key, chain_key_parts};

use crate::audit::journal::NeutralRecord;
use crate::audit::stream_registry::{StreamInput, StreamRecord};
use crate::audit::{verify_chain, Chain, ChainBreak, ChainedRecord, Framing};
use crate::host_records::{record_key, RecordRows, CLAIM_KIND, WRITE_FAILED};

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

/// How long a position's claim is held, in seconds. Retried writes cannot reuse it after expiry.
const CLAIM_SECS: u64 = 60;

/// The record kind every chain's LIFE is kept under: the host's own, never one a plane declares, so
/// a scan of a plane's kind never answers it.
pub const CHAIN_LIFE_SCHEMA: RecordSchemaId = RecordSchemaId::new("kernel-chain-life");

/// How many times an append resumes from the store's tail after losing its position to another
/// writer before it answers [`WRITE_FAILED`].
const CLAIM_ATTEMPTS: usize = 8;

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

/// A chain's position and its life (how many times the chain had been dropped when it was resumed,
/// as the store's [`CHAIN_LIFE_SCHEMA`] row held it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Held {
    chain: Chain<StreamRecord>,
    life: u64,
    tail: Option<(Vec<u8>, Arc<[u8]>)>,
    conditional: bool,
}

/// Every chain's position, the least recently written first.
type Positions = IndexMap<Position, Held>;

struct RetainedClaim {
    token: String,
    expires_at: u64,
}

/// THE CHAIN POSITIONS of every instance's chained kinds, the flush's to keep.
#[derive(Default)]
pub struct ChainBook {
    positions: Mutex<Positions>,
    /// The position claims this node won and has not yet stored a record under: a write the store
    /// refused after its claim was won is retried under the claim it already holds.
    claimed: Mutex<BTreeMap<Position, RetainedClaim>>,
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

    /// A failed write may reuse its claim only before the exact lease it won expires.
    fn holds(&self, at: &Position, token: &str, now: u64) -> Option<u64> {
        let mut claimed = self.claimed.lock().unwrap_or_else(|e| e.into_inner());
        claimed.retain(|_, held| held.expires_at > now);
        match claimed.get(at) {
            Some(held) if held.token == token => Some(held.expires_at),
            _ => {
                claimed.remove(at);
                None
            }
        }
    }

    /// Retain one current failed-write claim per position, within the existing bound.
    fn hold(&self, at: &Position, token: String, expires_at: u64) {
        let mut claimed = self.claimed.lock().unwrap_or_else(|e| e.into_inner());
        if claimed.contains_key(at) || claimed.len() < POSITIONS_CAP {
            claimed.insert(at.clone(), RetainedClaim { token, expires_at });
        }
    }

    /// Retire only this node's retry hint; never remove or renew a store claim.
    fn retire(&self, at: &Position) {
        self.claimed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(at);
    }

    /// Keep `chain` as the position at `at`, the most recently written.
    fn commit(&self, at: Position, chain: Held) {
        self.retire(&at);
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
    /// [`WRITE_FAILED`] when the store refused the read that resumes the chain, the claim or the
    /// record, or other writers kept taking the chain's next position; [`CHAIN_RECORD_TOO_LARGE`]
    /// when the sealed record exceeds the ceiling. The position is left where it was.
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
        for _ in 0..CLAIM_ATTEMPTS {
            let observed_life = life_of(rows, instance, schema, scope)?;
            let cached = self.lock().get(&at).cloned();
            let held = match cached {
                Some(held) if held.life == observed_life => held,
                Some(_) => {
                    self.retire(&at);
                    self.lock().shift_remove(&at);
                    resume(rows, instance, schema, scope, f)?
                }
                None => resume(rows, instance, schema, scope, f)?,
            };
            let (mut chain, life) = (held.chain, held.life);
            let record = chain.append(
                scope,
                StreamInput::new(content.to_vec(), f.framing, f.digests_scope),
            );
            let body = encode(&record).ok_or(CHAIN_RECORD_TOO_LARGE)?;
            let body = RecordBytes::new(body).map_err(|_| CHAIN_RECORD_TOO_LARGE)?;
            let key = record_key(instance, &chain_key(scope.as_bytes(), record.seq()));
            let now = busbar_kernel::store::now();
            let token = position_token(instance, schema, scope, life, &record);
            let expires_at = match self.holds(&at, &token, now) {
                Some(expires_at) => expires_at,
                None => {
                    let expires_at = now.saturating_add(CLAIM_SECS);
                    if !rows
                        .claim(CLAIM_KIND, &token, expires_at, now)
                        .map_err(|_| WRITE_FAILED)?
                    {
                        self.lock().shift_remove(&at);
                        continue;
                    }
                    self.hold(&at, token, expires_at);
                    expires_at
                }
            };
            let ours = rows
                .record_get(schema, &key)
                .map_err(|_| WRITE_FAILED)?
                .is_none_or(|held| held.as_slice().is_empty())
                && life_of(rows, instance, schema, scope)? == life
                && busbar_kernel::store::now() < expires_at;
            if !ours {
                // Another writer holds this position: read the chain back and seal at its tail.
                self.retire(&at);
                self.lock().shift_remove(&at);
                continue;
            }
            // These fresh observations reject known stale custody, but the legacy store API
            // cannot atomically fence a life change or lease expiry during record_put itself.
            rows.record_put(schema, &key, &body)
                .map_err(|_| WRITE_FAILED)?;
            self.commit(
                at,
                Held {
                    chain,
                    life,
                    tail: None,
                    conditional: false,
                },
            );
            return Ok(());
        }
        crate::diagnostics::diag_error!(
            crate::diagnostics::PLANE_JOURNAL_RESUME_CHAIN_BROKEN,
            instance = %instance,
            stream = %schema.as_str(),
            break_detail = "other writers kept taking the chain's next position",
            "a plane record chain append could not take a position: the write is refused, not \
             stored over another writer's record"
        );
        Err(WRITE_FAILED)
    }

    /// DROP `instance`'s chain `scope` of `schema`: its life raised in the store, a strike over
    /// each of its records, and its position forgotten, so its next append starts again at
    /// sequence `1` in a life whose claims no earlier record took.
    ///
    /// # Errors
    ///
    /// [`WRITE_FAILED`] when the store refused the life, the read or a strike.
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
        // The life is raised FIRST: a strike that fails leaves a chain that is resumed in the new
        // life, never a chain begun again in the old one.
        let dropped = raise_life(rows, instance, schema, scope)
            .and_then(|()| tombstone(rows, instance, schema, scope));
        if dropped.is_ok() {
            self.retire(&at);
        }
        // A failed life write may have left the old life intact. Preserve its retry claim
        // until a later observation proves a changed position/life, or the lease expires.
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

/// Where the store keeps the life of `instance`'s chain `scope` of `schema`, under
/// [`CHAIN_LIFE_SCHEMA`]: the kind and the scope, each length-prefixed, scoped by the instance.
pub(crate) fn life_key(instance: &str, schema: RecordSchemaId, scope: &str) -> Vec<u8> {
    let mut key = Vec::new();
    for field in [schema.as_str(), scope] {
        key.extend_from_slice(&(field.len() as u64).to_be_bytes());
        key.extend_from_slice(field.as_bytes());
    }
    record_key(instance, &key)
}

/// The life of `instance`'s chain `scope` of `schema` as the store keeps it: how many times it was
/// dropped, `0` for a chain never dropped.
fn life_of(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
) -> Result<u64, &'static str> {
    let held = rows
        .record_get(CHAIN_LIFE_SCHEMA, &life_key(instance, schema, scope))
        .map_err(|_| WRITE_FAILED)?;
    parse_life(held.as_ref().map(RecordBytes::as_slice))
}

/// Raise the life of `instance`'s chain `scope` of `schema` by one, in the store. Two drops racing
/// may both write the same next life; either way the chain begun again is in a life above every
/// one its old claims were taken in.
fn raise_life(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
) -> Result<(), &'static str> {
    let next = life_of(rows, instance, schema, scope)?
        .checked_add(1)
        .ok_or("chain life overflow")?;
    let body = RecordBytes::new(next.to_be_bytes().to_vec()).map_err(|_| WRITE_FAILED)?;
    rows.record_put(CHAIN_LIFE_SCHEMA, &life_key(instance, schema, scope), &body)
        .map_err(|_| WRITE_FAILED)
}

fn parse_life(bytes: Option<&[u8]>) -> Result<u64, &'static str> {
    match bytes {
        None => Ok(0),
        Some(bytes) => <[u8; 8]>::try_from(bytes)
            .map(u64::from_be_bytes)
            .map_err(|_| "malformed chain life"),
    }
}

/// Observe the exact optional life before the consumer reads the state it plans to mutate.
pub(crate) fn observe_life(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
) -> Result<Expected, &'static str> {
    let bytes = rows
        .record_get(CHAIN_LIFE_SCHEMA, &life_key(instance, schema, scope))
        .map_err(|_| WRITE_FAILED)?;
    parse_life(bytes.as_ref().map(RecordBytes::as_slice))?;
    Ok(bytes.map_or(Expected::Absent, |value| {
        Expected::Bytes(value.as_slice().to_vec())
    }))
}

#[derive(Debug)]
pub(crate) enum ConditionalChainAction {
    Append(Vec<Vec<u8>>),
    Drop,
    Check,
}

/// A host-authorized chain operation. Its kind and framing came from the admitted declaration.
#[derive(Debug)]
pub(crate) struct ConditionalChain {
    pub schema: RecordSchemaId,
    pub scope: String,
    pub framing: ChainFraming,
    pub life: Expected,
    pub action: ConditionalChainAction,
}

impl zeroize::Zeroize for ConditionalChainAction {
    fn zeroize(&mut self) {
        if let Self::Append(contents) = self {
            zeroize::Zeroize::zeroize(contents);
        }
    }
}
impl zeroize::Zeroize for ConditionalChain {
    fn zeroize(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.scope);
        zeroize::Zeroize::zeroize(&mut self.life);
        zeroize::Zeroize::zeroize(&mut self.action);
    }
}

/// A prepared append advances the committed-position hint only after an Applied receipt.
#[derive(Debug)]
pub(crate) enum ConditionalPosition {
    Append {
        at: Position,
        before: Held,
        after: Held,
    },
    Drop(Position),
    Check,
}

impl ChainBook {
    pub(crate) fn conditional_settled(
        &self,
        position: &ConditionalPosition,
        decision: busbar_contract::abi::sdk::store::conditional::Decision,
    ) {
        use busbar_contract::abi::sdk::store::conditional::Decision;
        match position {
            ConditionalPosition::Append { at, before, after } => {
                let mut positions = self.lock();
                if decision == Decision::ConditionConflict {
                    positions.shift_remove(at);
                } else if positions.get(at).is_none_or(|current| current == before) {
                    // A delayed replay must not regress a hint advanced by a later committed write.
                    positions.shift_remove(at);
                    positions.insert(at.clone(), after.clone());
                    while positions.len() > POSITIONS_CAP {
                        positions.shift_remove_index(0);
                    }
                }
            }
            ConditionalPosition::Drop(at) => {
                self.lock().shift_remove(at);
            }
            ConditionalPosition::Check => {}
        }
    }
}

impl ConditionalChain {
    /// Check and retirement use the original life without reading history. Append resumes only
    /// when its committed-position hint is missing/stale, then fences the exact tail and slots.
    pub(crate) fn prepare(
        &self,
        rows: &dyn RecordRows,
        instance: &str,
        request: &mut Request,
        book: &ChainBook,
    ) -> Result<ConditionalPosition, &'static str> {
        let life_key = life_key(instance, self.schema, &self.scope);
        let life = parse_life(match &self.life {
            Expected::Absent => None,
            Expected::Bytes(bytes) => Some(bytes),
        })?;
        request.predicates.push(Predicate {
            schema: CHAIN_LIFE_SCHEMA.as_str().to_string(),
            key: life_key.clone(),
            expected: self.life.clone(),
        });
        let at = (
            Arc::from(instance),
            self.schema.as_str().to_string(),
            self.scope.clone(),
        );
        let contents = match &self.action {
            ConditionalChainAction::Check => return Ok(ConditionalPosition::Check),
            ConditionalChainAction::Drop => {
                let next_life = life.checked_add(1).ok_or("chain life overflow")?;
                request.mutations.push(Mutation::Put {
                    schema: CHAIN_LIFE_SCHEMA.as_str().to_string(),
                    key: life_key,
                    value: next_life.to_be_bytes().to_vec(),
                });
                let mut scope_prefix = self.scope.as_bytes().to_vec();
                scope_prefix.push(b'/');
                let prefix = record_key(instance, &scope_prefix);
                let exact_key_length = prefix
                    .len()
                    .checked_add(20)
                    .and_then(|length| u64::try_from(length).ok())
                    .ok_or(WRITE_FAILED)?;
                // Retire the fixed-width slot domain, including corrupt same-width suffixes.
                // Valid nested scopes have longer keys and remain untouched.
                request.mutations.push(Mutation::DeleteRange {
                    schema: self.schema.as_str().to_string(),
                    prefix,
                    exact_key_length,
                });
                return Ok(ConditionalPosition::Drop(at));
            }
            ConditionalChainAction::Append(contents) => contents,
        };
        let cached = book
            .lock()
            .get(&at)
            .filter(|held| held.conditional && held.life == life)
            .cloned();
        let before = match cached {
            Some(held) => held,
            None => {
                // This is the existing restart/eviction resume surface. Its store scan ceiling
                // remains a limitation; steady-state appends do not rescan the whole history.
                resume_conditional(rows, instance, self.schema, &self.scope, self.framing, life)?
            }
        };
        let mut chain = before.chain.clone();
        let mut next = match &before.tail {
            Some((key, body)) => {
                request.predicates.push(Predicate {
                    schema: self.schema.as_str().to_string(),
                    key: key.clone(),
                    expected: Expected::Bytes(body.to_vec()),
                });
                chain_key_parts(key)
                    .and_then(|(_, seq)| seq.checked_add(1))
                    .ok_or("conditional chain sequence exhausted")?
            }
            None => 1,
        };
        let mut after = before.clone();
        for (index, content) in contents.iter().enumerate() {
            if index != 0 {
                next = next
                    .checked_add(1)
                    .ok_or("conditional chain sequence exhausted")?;
            }
            let key = record_key(instance, &chain_key(self.scope.as_bytes(), next));
            request.predicates.push(Predicate {
                schema: self.schema.as_str().to_string(),
                key: key.clone(),
                expected: Expected::Absent,
            });
            let record = chain.append(
                &self.scope,
                StreamInput::new(
                    content.clone(),
                    self.framing.framing,
                    self.framing.digests_scope,
                ),
            );
            let body = encode(&record).ok_or(CHAIN_RECORD_TOO_LARGE)?;
            RecordBytes::new(body.clone()).map_err(|_| CHAIN_RECORD_TOO_LARGE)?;
            request.mutations.push(Mutation::Put {
                schema: self.schema.as_str().to_string(),
                key: key.clone(),
                value: body.clone(),
            });
            after.tail = Some((key, Arc::from(body)));
        }
        after.chain = chain;
        Ok(ConditionalPosition::Append { at, before, after })
    }
}

fn resume_conditional(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
    framing: ChainFraming,
    life: u64,
) -> Result<Held, &'static str> {
    let unscoped = record_key(instance, &[]).len();
    let mut stored: Vec<_> = held(rows, instance, schema, scope)?
        .into_iter()
        .filter(|(key, _)| {
            key.get(unscoped..)
                .and_then(chain_key_parts)
                .is_some_and(|(actual, _)| actual == scope.as_bytes())
        })
        .collect();
    stored.sort_by(|a, b| a.0.cmp(&b.0));
    let mut records = Vec::new();
    for (key, body) in &stored {
        let record =
            decode(scope, body.as_slice(), framing).ok_or("malformed conditional chain row")?;
        if key
            .get(unscoped..)
            .and_then(chain_key_parts)
            .map(|(_, seq)| seq)
            != Some(record.seq())
        {
            return Err("invalid conditional chain sequence");
        }
        records.push(record);
    }
    let chain = match Chain::from_persisted(&records) {
        Ok(chain) => chain,
        Err(brk) => {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_JOURNAL_RESUME_CHAIN_BROKEN,
                instance = %instance, stream = %schema.as_str(), break_detail = %brk,
                "a conditional chain resumes from its observed broken tail"
            );
            Chain::from_persisted_unverified(&records)
        }
    };
    let tail = stored
        .last()
        .map(|(key, body)| (key.clone(), Arc::from(body.as_slice())));
    Ok(Held {
        chain,
        life,
        tail,
        conditional: true,
    })
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

/// The claim token of the position `record` takes in `instance`'s chain `scope` of `schema`, in its
/// life `life`: every field length-prefixed, then digested.
pub(crate) fn position_token(
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
    life: u64,
    record: &StreamRecord,
) -> String {
    let mut framed = Vec::new();
    for field in [instance, schema.as_str(), scope, record.prev_hash()] {
        framed.extend_from_slice(&(field.len() as u64).to_be_bytes());
        framed.extend_from_slice(field.as_bytes());
    }
    framed.extend_from_slice(&life.to_be_bytes());
    framed.extend_from_slice(&record.seq().to_be_bytes());
    busbar_contract::redacted::sha256_hex(&framed)
}

/// RESUME `instance`'s chain `scope` from the store: its records read back, VERIFIED, and the
/// position taken from the tail; a break is reported and the chain continued from its tail. Beside
/// it, the chain's life, as the store keeps it ([`life_of`]).
fn resume(
    rows: &dyn RecordRows,
    instance: &str,
    schema: RecordSchemaId,
    scope: &str,
    f: ChainFraming,
) -> Result<Held, &'static str> {
    let life = life_of(rows, instance, schema, scope)?;
    let unscoped = record_key(instance, &[]).len();
    let mut stored: Vec<Row> = held(rows, instance, schema, scope)?
        .into_iter()
        .filter_map(|(k, v)| Some((k.get(unscoped..)?.to_vec(), v.as_slice().to_vec())))
        .filter(|(k, _)| chain_key_parts(k).is_some_and(|(s, _)| s == scope.as_bytes()))
        .collect();
    stored.sort();
    if life_of(rows, instance, schema, scope)? != life {
        return Err(WRITE_FAILED);
    }
    let decoded = decoded(instance, schema, scope, &stored, f);
    let key_mismatch = decoded
        .iter()
        .any(|(key, record)| chain_key_parts(key).is_none_or(|(_, seq)| seq != record.seq()));
    let records: Vec<StreamRecord> = decoded.into_iter().map(|(_, r)| r).collect();
    let mut chain = match Chain::from_persisted(&records) {
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
    };
    let occupied = stored
        .iter()
        .rev()
        .find(|(_, body)| !body.is_empty())
        .and_then(|(key, _)| chain_key_parts(key))
        .map(|(_, seq)| seq);
    if let Some(seq) = occupied {
        // The key is the occupied position even when its body is unreadable or names another
        // sequence. Keep the last readable digest, report the break, and continue beyond it.
        // This temporary position anchor is never persisted or passed off as verified history.
        if key_mismatch || records.last().is_none_or(|last| last.seq() != seq) {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_JOURNAL_RESUME_CHAIN_BROKEN,
                instance = %instance, stream = %schema.as_str(),
                break_detail = "occupied chain keys disagree with the readable tail",
                "a plane record chain continues beyond its occupied broken tail"
            );
            let anchor = StreamRecord::from_parts(
                scope.to_string(),
                seq,
                String::new(),
                records
                    .last()
                    .map_or_else(String::new, |last| last.hash().to_string()),
                Vec::new(),
                f.framing,
                f.digests_scope,
            );
            chain = Chain::from_persisted_unverified(&[anchor]);
        }
        // Saturating the next sequence would otherwise repeatedly target the occupied last slot.
        if seq == u64::MAX {
            return Err(WRITE_FAILED);
        }
    }
    Ok(Held {
        chain,
        life,
        tail: None,
        conditional: false,
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
