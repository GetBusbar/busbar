// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub const CHAIN_SCOPE_UNFIT: &str =
    "a chained record's key is its chain's scope: UTF-8, not empty, not ending in `/<20 digits>`";

pub const CHAIN_RECORD_TOO_LARGE: &str =
    "a chained record's bytes and its chain fields exceed the record ceiling";

pub const CHAIN_READ_WHOLE: &str = "a chained record kind is read whole, through records.list";

const BODY_VERSION: u8 = 1;

pub const CHAIN_OVERHEAD: usize = 1 + 8 + 1 + 64 + 1 + 64;

pub const POSITIONS_CAP: usize = 65_536;

const CLAIM_SECS: u64 = 60;

pub const CHAIN_LIFE_SCHEMA: RecordSchemaId = RecordSchemaId::new("kernel-chain-life");

const CLAIM_ATTEMPTS: usize = 8;

/// A chained record kind's declaration, as the host frames it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainFraming {
    pub(crate) framing: Framing,
    pub(crate) digests_scope: bool,
}

impl ChainFraming {
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

#[must_use]
pub fn scope_of(key: &[u8]) -> Option<&str> {
    let scope = std::str::from_utf8(key).ok()?;
    (!scope.is_empty() && chain_key_parts(key).is_none()).then_some(scope)
}

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

fn digest_text(bytes: &[u8]) -> Option<(String, &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    let len = usize::from(len);
    if rest.len() < len {
        return None;
    }
    let (field, rest) = rest.split_at(len);
    Some((String::from_utf8(field.to_vec()).ok()?, rest))
}

type Position = (Arc<str>, String, String);

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

    fn hold(&self, at: &Position, token: String, expires_at: u64) {
        let mut claimed = self.claimed.lock().unwrap_or_else(|e| e.into_inner());
        if claimed.contains_key(at) || claimed.len() < POSITIONS_CAP {
            claimed.insert(at.clone(), RetainedClaim { token, expires_at });
        }
    }

    fn retire(&self, at: &Position) {
        self.claimed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(at);
    }

    fn commit(&self, at: Position, chain: Held) {
        self.retire(&at);
        let mut positions = self.lock();
        positions.shift_remove(&at);
        positions.insert(at, chain);
        while positions.len() > POSITIONS_CAP {
            positions.shift_remove_index(0);
        }
    }

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
                self.retire(&at);
                self.lock().shift_remove(&at);
                continue;
            }

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

        let dropped = raise_life(rows, instance, schema, scope)
            .and_then(|()| tombstone(rows, instance, schema, scope));
        if dropped.is_ok() {
            self.retire(&at);
        }

        self.lock().shift_remove(&at);
        dropped
    }
}

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

pub(crate) fn life_key(instance: &str, schema: RecordSchemaId, scope: &str) -> Vec<u8> {
    let mut key = Vec::new();
    for field in [schema.as_str(), scope] {
        key.extend_from_slice(&(field.len() as u64).to_be_bytes());
        key.extend_from_slice(field.as_bytes());
    }
    record_key(instance, &key)
}

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

fn break_words(brk: &ChainBreak) -> Vec<u8> {
    brk.to_string().into_bytes()
}

#[cfg(test)]
#[path = "tests/host_chains_unit_tests.rs"]
mod tests;
