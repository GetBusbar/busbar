// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`StoreRecords`]: the plugin-records namespace over the configured store, through CoreStore (IF §12.5).
//!
//! Layout. One host-private scope per (stamp name, configured instance name), framed so no two pairs share it;
//! under it, two schemas: [`RECORDS`] (plain records) and [`CHAINS`] (host chains, chain.rs). Every key starts
//! with its [`Scope`]: `0` for the instance's own records, `1 ‖ subject` for one caller's, so a caller-bound
//! record is never reachable from another subject or from the unscoped namespace. A record's stored value is
//! `1 ‖ expires_at (u64 BE, UNIX seconds, 0 = never) ‖ value`.
//!
//! Time. `ttl_s` 0 = no expiry; a non-zero TTL is clamped to `1..=MAX_TTL_S` (round 12). A record is live
//! while `expires_at == 0 || now < expires_at`; an expired record reads as absent everywhere (GET, LIST, the
//! commit predicates, `claim`) and [`StoreRecords::sweep_expired`] deletes it under an exact predicate.
//!
//! Atomicity. A commit reads its predicates' keys in one coherent read, judges them against the live values,
//! then submits ONE CoreStore commit whose native predicates pin exactly the bytes it judged (absent or exact)
//! and whose mutations are the ops. A concurrent writer turns that into a native conflict and the commit is
//! judged again from a fresh read (bounded), so two conflicting commits never both apply. An in-doubt write is
//! driven again a bounded number of times, then parked and collected later ([`StoreRecords::settle`]), so it
//! never holds a CoreStore queue slot forever.

use core::future::Future;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use busbar_contract::Secret;
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::records::commit::MAX_OPS;

use crate::persistence::commit::SubmitResult;
use crate::persistence::facade::{CoreStore, PendingId};
use crate::persistence::scoped::{self, Expected, Mutation, Predicate, Request, ScopedStore};

use super::{
    ChainRead, CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope, MAX_KEY, MAX_TTL_S,
    MAX_VALUE,
};

/// Plain records.
pub(super) const RECORDS: &str = "busbar.plugin-records.v1";
/// Host chains: one head row and one row per entry (chain.rs).
pub(super) const CHAINS: &str = "busbar.plugin-chains.v1";
/// How many times an in-doubt write is driven again before it is parked.
const IN_DOUBT_RETRIES: usize = 2;
/// The most expired records one sweep deletes (one CoreStore commit).
const SWEEP_BATCH: usize = 32;
/// The most store pages one sweep reads looking for expired records.
const SWEEP_PAGES: usize = 64;
/// The stored-value version byte.
const ENVELOPE: u8 = 1;

/// The plugin-records namespace over CoreStore. One per process, shared (`Arc`) by every consumer.
pub struct StoreRecords {
    store: Arc<CoreStore>,
    clock: fn() -> u64,
    in_doubt: InDoubt,
}

impl StoreRecords {
    /// Records over `store`, timed by the wall clock.
    #[must_use]
    pub fn new(store: Arc<CoreStore>) -> Self {
        Self::with_clock(store, crate::store::now)
    }

    /// Records over `store`; `clock` answers UNIX seconds (TTLs are judged against it).
    #[must_use]
    pub fn with_clock(store: Arc<CoreStore>, clock: fn() -> u64) -> Self {
        Self {
            store,
            clock,
            in_doubt: InDoubt::default(),
        }
    }

    /// Drive the parked in-doubt writes once more; answers how many are still parked. The owner's
    /// maintenance tick calls it; every write also collects one parked write first.
    pub async fn settle(&self) -> usize {
        for _ in 0..self.in_doubt.len() {
            if !self.in_doubt.settle_one(&self.store).await {
                break;
            }
        }
        self.in_doubt.len()
    }

    /// Delete expired records of `who`'s namespace (every scope), at most one batch, each under an exact
    /// predicate so a record rewritten meanwhile stays. Ok(n) = deleted. Reads never see expired records;
    /// this only returns their space.
    pub async fn sweep_expired(&self, who: &Caller<'_>) -> Result<u32, RecordsDenied> {
        let records = self.scoped(who)?;
        sweep(
            &self.store,
            &self.in_doubt,
            &records,
            RECORDS,
            (self.clock)(),
        )
        .await
    }

    #[cfg(test)]
    pub(super) fn store_for_tests(&self) -> &Arc<CoreStore> {
        &self.store
    }

    /// How many times a write is judged again after a concurrent writer changed what it judged: CoreStore's
    /// configured `conflict_retries`, the bound every host owner of the store keeps.
    pub(super) fn retries(&self) -> usize {
        self.store.limits().conflict_retries
    }

    pub(super) fn now(&self) -> u64 {
        (self.clock)()
    }

    pub(super) fn scoped(&self, who: &Caller<'_>) -> Result<ScopedStore, RecordsDenied> {
        ScopedStore::host_private(
            Arc::clone(&self.store),
            &label(who),
            [RECORDS.to_string(), CHAINS.to_string()],
        )
        .map_err(denied)
    }

    pub(super) fn operation(&self) -> Result<[u8; 16], RecordsDenied> {
        operation(&self.store)
    }

    /// Ok(true) = applied, Ok(false) = a native predicate failed and nothing applied.
    pub(super) async fn decided(
        &self,
        records: &ScopedStore,
        first: Result<scoped::Outcome, scoped::Error>,
    ) -> Result<bool, RecordsDenied> {
        self.in_doubt.decided(records, first).await
    }

    pub(super) async fn collect_one(&self) {
        self.in_doubt.settle_one(&self.store).await;
    }

    /// One commit over resolved ops (keys already in their scope).
    async fn run(&self, who: &Caller<'_>, ops: &[Op<'_>]) -> Result<CommitOutcome, RecordsDenied> {
        let mut seen = Vec::new();
        for (i, a) in ops.iter().enumerate() {
            if !a.kind.is_predicate()
                && ops[..i]
                    .iter()
                    .any(|b| !b.kind.is_predicate() && b.key == a.key)
            {
                // Two mutations of one key in one commit: neither order is the plugin's to choose.
                return Err(RecordsDenied::Invalid);
            }
        }
        // The distinct predicate keys, read together; `slot[i]` = op i's index into them.
        let mut slot = Vec::with_capacity(ops.len());
        for op in ops {
            if op.kind.is_predicate() {
                let at = match seen.iter().position(|k: &&[u8]| *k == op.key.as_slice()) {
                    Some(at) => at,
                    None => {
                        seen.push(op.key.as_slice());
                        seen.len() - 1
                    }
                };
                slot.push(Some(at));
            } else {
                slot.push(None);
            }
        }
        let writes = ops.iter().any(|op| !op.kind.is_predicate());
        let records = self.scoped(who)?;
        for _ in 0..=self.retries() {
            let observed = if seen.is_empty() {
                Vec::new()
            } else {
                let read: Vec<(&str, &[u8])> = seen.iter().map(|k| (RECORDS, *k)).collect();
                records.read(&read).await.map_err(denied)?
            };
            if observed.len() != seen.len() {
                return Err(RecordsDenied::Unavailable);
            }
            let now = self.now();
            let request = {
                let seal = crate::seal::lend();
                for (i, (op, at)) in ops.iter().zip(&slot).enumerate() {
                    let Some(at) = at else { continue };
                    let raw = observed[*at]
                        .as_ref()
                        .map(|raw| raw.expose(&seal).as_slice());
                    let value = live_value(raw, now)?;
                    let holds = match op.kind {
                        Kind::Absent => value.is_none(),
                        Kind::Present => value.is_some(),
                        Kind::Equals(expected) => value == Some(expected),
                        Kind::Put(..) | Kind::Del => true,
                    };
                    if !holds {
                        return Ok(CommitOutcome::Conflict {
                            failed: u32::try_from(i).unwrap_or(u32::MAX),
                        });
                    }
                }
                if !writes {
                    return Ok(CommitOutcome::Applied);
                }
                Request {
                    op_id: self.operation()?,
                    predicates: seen
                        .iter()
                        .zip(&observed)
                        .map(|(key, raw)| Predicate {
                            schema: RECORDS.to_string(),
                            key: key.to_vec(),
                            expected: raw.clone().map_or(Expected::Absent, Expected::Exact),
                        })
                        .collect(),
                    mutations: ops
                        .iter()
                        .filter_map(|op| match op.kind {
                            Kind::Put(value, ttl_s) => Some(Mutation::Put {
                                schema: RECORDS.to_string(),
                                key: op.key.clone(),
                                value: envelope(expiry(now, ttl_s), value),
                            }),
                            Kind::Del => Some(Mutation::Delete {
                                schema: RECORDS.to_string(),
                                key: op.key.clone(),
                            }),
                            Kind::Absent | Kind::Present | Kind::Equals(_) => None,
                        })
                        .collect(),
                }
            };
            if self
                .decided(&records, records.conditional_native(&request).await)
                .await?
            {
                return Ok(CommitOutcome::Applied);
            }
        }
        // Writers kept changing what this commit judged: it applied nothing.
        Err(RecordsDenied::Unavailable)
    }
}

impl StoreRecords {
    async fn get_one(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> Result<bool, RecordsDenied> {
        sized(key, &[])?;
        let records = self.scoped(who)?;
        let found = records
            .get(RECORDS, &scoped_key(scope, key))
            .await
            .map_err(denied)?;
        let now = self.now();
        let seal = crate::seal::lend();
        match live_value(found.as_ref().map(|raw| raw.expose(&seal).as_slice()), now)? {
            Some(value) => {
                sink(value);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn put_one(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> Result<(), RecordsDenied> {
        sized(key, value)?;
        let records = self.scoped(who)?;
        self.collect_one().await;
        let stored = envelope(expiry(self.now(), ttl_s), value);
        let first = records.put(RECORDS, &scoped_key(scope, key), stored).await;
        if self.decided(&records, first).await? {
            Ok(())
        } else {
            // A plain write carries no predicate; a conflict is not an answer it can have.
            Err(RecordsDenied::Unavailable)
        }
    }

    async fn claim_one(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> Result<bool, RecordsDenied> {
        sized(key, value)?;
        self.collect_one().await;
        let at = scoped_key(scope, key);
        let ops = [
            Op {
                kind: Kind::Absent,
                key: at.clone(),
            },
            Op {
                kind: Kind::Put(value, ttl_s),
                key: at,
            },
        ];
        Ok(self.run(who, &ops).await? == CommitOutcome::Applied)
    }

    /// A DELETE of a key drops its plain record and its chain (IF §8.6 StoreRec), in one commit when a chain
    /// is there.
    async fn del_key(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
    ) -> Result<(), RecordsDenied> {
        sized(key, &[])?;
        let records = self.scoped(who)?;
        self.collect_one().await;
        let record = scoped_key(scope, key);
        let head = super::chain::head_key(scope, key);
        for _ in 0..=self.retries() {
            let first = match records.get(CHAINS, &head).await.map_err(denied)? {
                None => records.delete(RECORDS, &record).await,
                Some(raw) => {
                    let entries = super::chain::entries_prefix(scope, key);
                    let request = Request {
                        op_id: self.operation()?,
                        predicates: vec![Predicate {
                            schema: CHAINS.to_string(),
                            key: head.clone(),
                            expected: Expected::Exact(raw),
                        }],
                        mutations: vec![
                            Mutation::Delete {
                                schema: RECORDS.to_string(),
                                key: record.clone(),
                            },
                            Mutation::Delete {
                                schema: CHAINS.to_string(),
                                key: head.clone(),
                            },
                            Mutation::DeleteRange {
                                schema: CHAINS.to_string(),
                                exact_key_length: (entries.len() + 8) as u64,
                                prefix: entries,
                            },
                        ],
                    };
                    records.conditional_native(&request).await
                }
            };
            if self.decided(&records, first).await? {
                return Ok(());
            }
        }
        Err(RecordsDenied::Unavailable)
    }

    async fn list_prefix(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        prefix: &[u8],
        limit: u32,
        sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> Result<u32, RecordsDenied> {
        sized(prefix, &[])?;
        if limit == 0 {
            return Ok(0);
        }
        let records = self.scoped(who)?;
        let at = scoped_key(scope, prefix);
        let skip = at.len() - prefix.len();
        let mut cursor = None;
        let mut hits = 0u32;
        loop {
            let page = records
                .page(RECORDS, &at, cursor.as_ref())
                .await
                .map_err(denied)?;
            let now = self.now();
            {
                let seal = crate::seal::lend();
                for (key, raw) in &page.rows {
                    let Some(value) = live_value(Some(raw.expose(&seal).as_slice()), now)? else {
                        continue;
                    };
                    let key = key.get(skip..).ok_or(RecordsDenied::Unavailable)?;
                    sink(key, value);
                    hits += 1;
                    if hits == limit {
                        return Ok(hits);
                    }
                }
            }
            match page.next {
                Some(next) => cursor = Some(next),
                None => return Ok(hits),
            }
        }
    }

    async fn commit_ops(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        ops: &[CommitOp<'_>],
    ) -> Result<CommitOutcome, RecordsDenied> {
        let ops = resolve(scope, ops)?;
        self.collect_one().await;
        self.run(who, &ops).await
    }
}

impl PluginRecords for StoreRecords {
    fn get(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        sink: &mut (dyn FnMut(&[u8]) + Send),
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        self.get_one(who, scope, key, sink)
    }

    fn put(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        self.put_one(who, scope, key, value, ttl_s)
    }

    fn claim(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
        value: &[u8],
        ttl_s: u64,
    ) -> impl Future<Output = Result<bool, RecordsDenied>> + Send {
        self.claim_one(who, scope, key, value, ttl_s)
    }

    fn del(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        key: &[u8],
    ) -> impl Future<Output = Result<(), RecordsDenied>> + Send {
        self.del_key(who, scope, key)
    }

    fn list(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        prefix: &[u8],
        limit: u32,
        sink: &mut (dyn FnMut(&[u8], &[u8]) + Send),
    ) -> impl Future<Output = Result<u32, RecordsDenied>> + Send {
        self.list_prefix(who, scope, prefix, limit, sink)
    }

    fn commit(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        ops: &[CommitOp<'_>],
    ) -> impl Future<Output = Result<CommitOutcome, RecordsDenied>> + Send {
        self.commit_ops(who, scope, ops)
    }

    fn append(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        entry: &[u8],
    ) -> impl Future<Output = Result<u64, RecordsDenied>> + Send {
        self.append_entry(who, scope, chain, entry)
    }

    fn chain(
        &self,
        who: &Caller<'_>,
        scope: Scope,
        chain: &[u8],
        after: u64,
        limit: u32,
        sink: &mut (dyn FnMut(u64, &[u8]) + Send),
    ) -> impl Future<Output = Result<ChainRead, RecordsDenied>> + Send {
        self.read_chain(who, scope, chain, after, limit, sink)
    }
}

/// One commit op with its key in its scope.
struct Op<'a> {
    kind: Kind<'a>,
    key: Vec<u8>,
}

#[derive(Clone, Copy)]
enum Kind<'a> {
    Absent,
    Present,
    Equals(&'a [u8]),
    Put(&'a [u8], u64),
    Del,
}

impl Kind<'_> {
    fn is_predicate(self) -> bool {
        matches!(self, Kind::Absent | Kind::Present | Kind::Equals(_))
    }
}

/// Bound and scope a commit's ops. `caller` ops take the commit's subject scope (REC_CALLER, plane only); a
/// `caller` op in a commit without a subject is Invalid. The rest take the instance's own scope.
fn resolve<'a>(scope: Scope, ops: &[CommitOp<'a>]) -> Result<Vec<Op<'a>>, RecordsDenied> {
    if ops.len() > MAX_OPS as usize {
        return Err(RecordsDenied::Invalid);
    }
    let mut out = Vec::with_capacity(ops.len());
    for op in ops {
        let (kind, key, caller) = match *op {
            CommitOp::Absent { key, caller } => (Kind::Absent, key, caller),
            CommitOp::Present { key, caller } => (Kind::Present, key, caller),
            CommitOp::Equals { key, value, caller } => (Kind::Equals(value), key, caller),
            CommitOp::Put {
                key,
                value,
                ttl_s,
                caller,
            } => (Kind::Put(value, ttl_s), key, caller),
            CommitOp::Del { key, caller } => (Kind::Del, key, caller),
        };
        let value = match kind {
            Kind::Equals(value) | Kind::Put(value, _) => value,
            Kind::Absent | Kind::Present | Kind::Del => &[],
        };
        sized(key, value)?;
        let scope = if caller {
            if scope.subject.is_none() {
                return Err(RecordsDenied::Invalid);
            }
            scope
        } else {
            Scope::default()
        };
        out.push(Op {
            kind,
            key: scoped_key(scope, key),
        });
    }
    Ok(out)
}

/// The host-private scope of one instance: (stamp name, configured instance name), length-framed so no two
/// pairs share it. Never the runtime id and never a config hash; never shown to the plugin.
pub(crate) fn label(who: &Caller<'_>) -> String {
    format!("{}:{}/{}", who.plugin.len(), who.plugin, who.name)
}

/// `key` in `scope`: `0 ‖ key` for the instance's own records, `1 ‖ subject ‖ key` for one caller's.
pub(super) fn scoped_key(scope: Scope, key: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(33 + key.len());
    match scope.subject {
        None => out.push(0),
        Some(subject) => {
            out.push(1);
            out.extend_from_slice(&subject);
        }
    }
    out.extend_from_slice(key);
    out
}

fn sized(key: &[u8], value: &[u8]) -> Result<(), RecordsDenied> {
    if key.len() > MAX_KEY || value.len() > MAX_VALUE {
        Err(RecordsDenied::TooLarge)
    } else {
        Ok(())
    }
}

/// When a record written at `now` with `ttl_s` expires: 0 = never; else `now + min(ttl_s, MAX_TTL_S)`.
pub(crate) fn expiry(now: u64, ttl_s: u64) -> u64 {
    if ttl_s == 0 {
        0
    } else {
        now.saturating_add(ttl_s.min(MAX_TTL_S))
    }
}

pub(crate) fn live(expires_at: u64, now: u64) -> bool {
    expires_at == 0 || now < expires_at
}

/// The stored form: `1 ‖ expires_at (u64 BE) ‖ value`.
pub(crate) fn envelope(expires_at: u64, value: &[u8]) -> Secret<Vec<u8>> {
    let mut out = Vec::with_capacity(9 + value.len());
    out.push(ENVELOPE);
    out.extend_from_slice(&expires_at.to_be_bytes());
    out.extend_from_slice(value);
    Secret::new(out)
}

/// `(expires_at, value)` of a stored record; None = bytes this owner never wrote.
pub(crate) fn opened(raw: &[u8]) -> Option<(u64, &[u8])> {
    let (&version, rest) = raw.split_first()?;
    if version != ENVELOPE || rest.len() < 8 {
        return None;
    }
    let (expires_at, value) = rest.split_at(8);
    Some((u64::from_be_bytes(expires_at.try_into().ok()?), value))
}

/// The live value of a stored record at `now`: Ok(None) = absent or expired; a value this owner never wrote
/// is a store fault, never read as data.
fn live_value(raw: Option<&[u8]>, now: u64) -> Result<Option<&[u8]>, RecordsDenied> {
    let Some(raw) = raw else { return Ok(None) };
    let (expires_at, value) = opened(raw).ok_or(RecordsDenied::Unavailable)?;
    Ok(live(expires_at, now).then_some(value))
}

pub(crate) fn denied(error: scoped::Error) -> RecordsDenied {
    match error {
        scoped::Error::Unauthorized | scoped::Error::Invalid => RecordsDenied::Invalid,
        scoped::Error::Corrupt | scoped::Error::Access(_) | scoped::Error::Backend(_) => {
            RecordsDenied::Unavailable
        }
    }
}

pub(crate) fn operation(store: &CoreStore) -> Result<[u8; 16], RecordsDenied> {
    store
        .next_id()
        .map(|id| id.operation)
        .map_err(|_| RecordsDenied::Unavailable)
}

/// Delete up to [`SWEEP_BATCH`] expired rows of `schema` in `records`' scope, under exact predicates.
pub(crate) async fn sweep(
    store: &CoreStore,
    in_doubt: &InDoubt,
    records: &ScopedStore,
    schema: &str,
    now: u64,
) -> Result<u32, RecordsDenied> {
    let mut expired: Vec<(Vec<u8>, Secret<Vec<u8>>)> = Vec::new();
    let mut cursor = None;
    for _ in 0..SWEEP_PAGES {
        let Ok(page) = records.page(schema, &[], cursor.as_ref()).await else {
            // A namespace that changed under a continued scan: sweep what was found.
            break;
        };
        {
            let seal = crate::seal::lend();
            for (key, raw) in page.rows {
                if expired.len() == SWEEP_BATCH {
                    break;
                }
                if opened(raw.expose(&seal)).is_some_and(|(at, _)| !live(at, now)) {
                    expired.push((key, raw));
                }
            }
        }
        match page.next {
            Some(next) if expired.len() < SWEEP_BATCH => cursor = Some(next),
            _ => break,
        }
    }
    if expired.is_empty() {
        return Ok(0);
    }
    let deleted = u32::try_from(expired.len()).unwrap_or(u32::MAX);
    let request = Request {
        op_id: operation(store)?,
        predicates: expired
            .iter()
            .map(|(key, raw)| Predicate {
                schema: schema.to_string(),
                key: key.clone(),
                expected: Expected::Exact(raw.clone()),
            })
            .collect(),
        mutations: expired
            .into_iter()
            .map(|(key, _)| Mutation::Delete {
                schema: schema.to_string(),
                key,
            })
            .collect(),
    };
    let applied = in_doubt
        .decided(records, records.conditional_native(&request).await)
        .await?;
    // A conflict means one of them was rewritten meanwhile: nothing was deleted; the next sweep retries.
    Ok(if applied { deleted } else { 0 })
}

/// In-doubt CoreStore writes this owner still has to collect. CoreStore keeps an uncertain attempt (and its
/// queue slot) until its owner drives it to a decision with `retry`; an owner that walks away leaks the slot.
#[derive(Default)]
pub(crate) struct InDoubt {
    parked: Mutex<VecDeque<PendingId>>,
}

impl InDoubt {
    fn lock(&self) -> MutexGuard<'_, VecDeque<PendingId>> {
        self.parked.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn len(&self) -> usize {
        self.lock().len()
    }

    fn park(&self, id: PendingId) {
        let mut parked = self.lock();
        if !parked.contains(&id) {
            parked.push_back(id);
        }
    }

    /// Drive the oldest parked write once; a still-undecided one goes to the back. false = none parked.
    pub(crate) async fn settle_one(&self, store: &CoreStore) -> bool {
        let Some(id) = self.lock().pop_front() else {
            return false;
        };
        if let Ok(submission) = store.retry(id).await {
            if matches!(
                submission.result,
                SubmitResult::Uncertain | SubmitResult::Reconcile | SubmitResult::Busy
            ) {
                self.park(id);
            }
        }
        // Err: CoreStore no longer holds it (another driver collected it).
        true
    }

    /// Ok(true) = applied, Ok(false) = a native predicate failed and nothing applied.
    pub(crate) async fn decided(
        &self,
        records: &ScopedStore,
        first: Result<scoped::Outcome, scoped::Error>,
    ) -> Result<bool, RecordsDenied> {
        let mut outcome = first.map_err(denied)?;
        let mut tries = 0;
        loop {
            match outcome {
                scoped::Outcome::Applied => return Ok(true),
                scoped::Outcome::ConditionConflict => return Ok(false),
                scoped::Outcome::Pending(id) | scoped::Outcome::Busy(Some(id))
                    if tries < IN_DOUBT_RETRIES =>
                {
                    tries += 1;
                    match records.retry(id).await {
                        Ok(next) => outcome = next,
                        Err(_) => {
                            self.park(id);
                            return Err(RecordsDenied::Unavailable);
                        }
                    }
                }
                scoped::Outcome::Pending(id)
                | scoped::Outcome::Reconcile(id)
                | scoped::Outcome::Busy(Some(id)) => {
                    self.park(id);
                    return Err(RecordsDenied::Unavailable);
                }
                scoped::Outcome::OpIdConflict
                | scoped::Outcome::Busy(None)
                | scoped::Outcome::NoEffect(_) => return Err(RecordsDenied::Unavailable),
            }
        }
    }
}
