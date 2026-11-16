// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The intents a plane answers with, resolved by core (IF §8.6, §12.5, §12.9, §12.19, §12.24; PLANE-DRIVER.md
//! slice 6). A plane states LOOKUP, STORE, DELETE, COMMIT, WORK, PUSH, SIGNAL, WAKE_AT and DETACH inside an answer;
//! it never calls the store. [`Task::resolve`] takes one answer, applies its intents in answer order (STORE, DELETE
//! and COMMIT before LOOKUP and WORK are resolved), and delivers each result kind back as one `piece(FROM_CORE)`
//! before any other call on the session. The answer to such a piece can carry intents of its own, which resolve the
//! same way; a plane that never settles is a [`Violation::IntentStorm`].
//!
//! [`IntentHost`] is the seam: [`KernelIntents`] is its production form over [`PluginRecords`], the push queue and
//! the session signal registry; a test fakes it. A caller-scoped record (`LK_CALLER`, `REC_CALLER`), a WORK and a
//! caller-scoped SIGNAL all need a verified subject: without one core answers the refusal itself and the host is
//! never asked (it would otherwise answer from the shared namespace).
//!
//! Left to later slices or MRs (PLANE-DRIVER.md): `Entitle`, `Judge`, `Mint`, `Sign`, `Trust*`, `Sight`,
//! `Connect`, `Rendezvous`, `Obs*` stay undriven (`Answer::later`), and the production WORK decider over
//! `host_work`/`host_recovery` (`DurableWork`) is not written: [`NoWork`] answers `R_UNSUPPORTED`, the fail-closed
//! answer the IF defines, so a plane refuses paid dispatch as it does without a recovery runtime.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_plugin_abi::fail::refused::{R_DENIED, R_INVALID, R_RATE_LIMITED, R_UNSUPPORTED};
use busbar_plugin_abi::host_side::caller::{CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::plane::{
    FROM_CORE, LK_CALLER, LK_CHAIN, LK_PREFIX, P_COMMITTED, P_LOOKUP, P_SIGNAL, P_STORE_FAILED,
    P_WORK,
};
use busbar_plugin_abi::records::{commit, tag, RecDelRec, RecPredRec, RecPutRec, Records, Reply};
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::encode::plane::{
    encode_chain_state, encode_committed, encode_lookup_hits, encode_work_answers,
};
use busbar_plugin_loader::ports::plane::WorkAnswer;
use tokio::runtime::Handle;

use super::port_session::{Answer, Calls, Effects, SessionError, Task, Violation};
use crate::channels::SessionSignals;
use crate::hashing::Sha256;
use crate::plugin_records::{
    CommitOp, CommitOutcome, PluginRecords, RecordsDenied, Scope, MAX_KEY, MAX_VALUE,
};
use crate::push::PushQueue;

/// How many rounds of intents one answer may chain (an answer's pieces answering with more intents) before the
/// session is cut. A plane's real chains are two or three deep (LOOKUP, then COMMIT, then WORK).
const MAX_ROUNDS: u32 = 64;

/// One intent of an answer, owned (the sink's borrows end with the answer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Intent {
    Lookup {
        flags: u32,
        limit: u32,
        key: Vec<u8>,
    },
    Store {
        flags: u32,
        ttl_s: u64,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        flags: u32,
        key: Vec<u8>,
    },
    /// `ops` = the nested REC_PRED*, REC_PUT*, REC_DEL* the adapter validated.
    Commit {
        check: u32,
        ops: Vec<u8>,
    },
    Work {
        check: u32,
        op: u32,
        target: Option<String>,
        reference: Option<String>,
    },
    /// `recs` = the nested records core's push queue copies and owns.
    Push {
        ttl_s: u64,
        recs: Vec<u8>,
    },
    Signal {
        flags: u32,
        key: Vec<u8>,
    },
}

/// DETACH: the session outlives its client response until FINISH or `ttl_s` (clamped), registered under `key`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detach {
    pub ttl_s: u64,
    pub flags: u32,
    pub key: Box<[u8]>,
}

/// One hit of a LOOKUP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// A LOOKUP's result: its hits in order, and for `LK_CHAIN` the chain's state (`len`, `broken_at`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Looked {
    pub hits: Vec<Hit>,
    pub chain: Option<(u64, u64)>,
}

/// One WORK intent, the verified principal's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkIntent {
    pub op: u32,
    pub target: Option<String>,
    pub reference: Option<String>,
}

/// One WORK_ANS (§8.6): `status` 0 = done, else a generic REFUSED code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkOutcome {
    pub status: u32,
    pub state: u32,
    pub reference: String,
    pub target: String,
}

impl WorkOutcome {
    /// Core cannot recover here (no store or no recovery runtime, §12.24).
    #[must_use]
    pub fn unsupported() -> Self {
        Self::refused(R_UNSUPPORTED)
    }

    fn refused(status: u32) -> Self {
        Self {
            status,
            state: 0,
            reference: String::new(),
            target: String::new(),
        }
    }
}

/// What resolving an intent needs from core. The calls are synchronous: a driver runs a task inside
/// `spawn_blocking`, and a production host blocks on the runtime for the store.
pub trait IntentHost {
    /// LOOKUP in the scope the resolver chose. `flags` carries `LK_PREFIX` and `LK_CHAIN` (for `LK_CHAIN` the key
    /// is the chain key followed by the 8-byte `after`).
    fn lookup(
        &self,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &[u8],
    ) -> Result<Looked, RecordsDenied>;
    /// STORE. `flags & LK_CHAIN` appends `value` to the host chain `key`.
    fn store(
        &self,
        scope: Scope,
        flags: u32,
        ttl_s: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), RecordsDenied>;
    fn delete(&self, scope: Scope, key: &[u8]) -> Result<(), RecordsDenied>;
    fn commit(&self, scope: Scope, ops: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied>;
    /// WORK under the request's verified principal. The default is the fail-closed answer.
    fn work(&self, _intent: &WorkIntent) -> WorkOutcome {
        WorkOutcome::unsupported()
    }
    fn push(&self, ttl_s: u64, recs: &[u8]) -> Result<(), RecordsDenied>;
    /// SIGNAL: every session of this instance detached under `key` (only `subject`'s when it is Some).
    fn signal(&self, key: &[u8], subject: Option<[u8; 32]>);
}

/// The request's subject scope: SHA-256 of its ID_SUBJECT text (IF §12.5).
#[must_use]
pub fn subject_scope(subject: &str) -> [u8; 32] {
    Sha256::digest(subject.as_bytes())
}

/// One result piece core delivers: `piece(FROM_CORE, 0, flags, bytes)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Piece {
    pub flags: u32,
    pub bytes: Vec<u8>,
}

/// Resolves intents against a host for one request: `subject` is the verified principal's scope, if any.
pub struct Resolver<'h> {
    host: &'h dyn IntentHost,
    subject: Option<[u8; 32]>,
}

impl<'h> Resolver<'h> {
    #[must_use]
    pub fn new(host: &'h dyn IntentHost, subject: Option<[u8; 32]>) -> Self {
        Self { host, subject }
    }

    /// The scope a flag word selects, or `None` when it asks for the caller's scope and there is no subject.
    fn scope(&self, caller_bound: bool) -> Option<Scope> {
        if caller_bound {
            self.subject.map(|s| Scope { subject: Some(s) })
        } else {
            Some(Scope::default())
        }
    }

    /// Applies `intents` in answer order and returns the pieces to deliver, in the IF order.
    #[must_use]
    pub fn resolve(&self, intents: &[Intent]) -> Vec<Piece> {
        // STORE, DELETE, COMMIT, PUSH and SIGNAL first, in answer order; LOOKUP and WORK read what they wrote.
        let mut failed: Vec<&[u8]> = Vec::new();
        let mut committed: Vec<(u32, u32, u32, u32)> = Vec::new();
        for intent in intents {
            match intent {
                Intent::Store {
                    flags,
                    ttl_s,
                    key,
                    value,
                } => {
                    let done = self
                        .scope(flags & LK_CALLER != 0)
                        .ok_or(RecordsDenied::Invalid)
                        .and_then(|scope| self.host.store(scope, *flags, *ttl_s, key, value));
                    if done.is_err() {
                        failed.push(key);
                    }
                }
                Intent::Delete { flags, key } => {
                    let done = self
                        .scope(flags & LK_CALLER != 0)
                        .ok_or(RecordsDenied::Invalid)
                        .and_then(|scope| self.host.delete(scope, key));
                    if done.is_err() {
                        failed.push(key);
                    }
                }
                Intent::Commit { check, ops } => committed.push(self.commit(*check, ops)),
                Intent::Push { ttl_s, recs } => {
                    if let Err(denied) = self.host.push(*ttl_s, recs) {
                        tracing::warn!(?denied, "a plane push was not queued");
                    }
                }
                Intent::Signal { flags, key } => {
                    if flags & LK_CALLER == 0 {
                        self.host.signal(key, None);
                    } else if let Some(subject) = self.subject {
                        self.host.signal(key, Some(subject));
                    }
                }
                Intent::Lookup { .. } | Intent::Work { .. } => {}
            }
        }
        let mut pieces = Vec::new();
        for key in failed {
            pieces.push(Piece {
                flags: P_STORE_FAILED,
                bytes: key.to_vec(),
            });
        }
        if let Some(bytes) = self.lookups(intents) {
            pieces.push(Piece {
                flags: P_LOOKUP,
                bytes,
            });
        }
        if !committed.is_empty() {
            let mut reply = Reply::new();
            // A Reply refuses only past its cap; a commit answer is a few words.
            let put = encode_committed(&mut reply, &committed);
            debug_assert!(put.is_ok(), "COMMITTED answers fit a Reply");
            pieces.push(Piece {
                flags: P_COMMITTED,
                bytes: reply.as_bytes().to_vec(),
            });
        }
        if let Some(bytes) = self.works(intents) {
            pieces.push(Piece {
                flags: P_WORK,
                bytes,
            });
        }
        pieces
    }

    /// One COMMIT: (check, outcome, failed, status).
    fn commit(&self, check: u32, raw: &[u8]) -> (u32, u32, u32, u32) {
        let refused = |status| (check, 0, 0, status);
        let mut ops = Vec::new();
        let mut caller_bound = false;
        let mut mutating = false;
        for rec in Records::new(raw) {
            let Ok(rec) = rec else {
                return refused(R_INVALID);
            };
            let op = match rec.tag {
                tag::REC_PRED if !mutating => {
                    let Ok((head, tail)) = rec.pod_tail::<RecPredRec>() else {
                        return refused(R_INVALID);
                    };
                    let Some((key, value)) = split_key(tail, head.key_len) else {
                        return refused(R_INVALID);
                    };
                    let caller = head.flags & commit::REC_CALLER != 0;
                    caller_bound |= caller;
                    match head.flags & commit::PRED_MASK {
                        commit::PRED_ABSENT if value.is_empty() => CommitOp::Absent { key, caller },
                        commit::PRED_PRESENT if value.is_empty() => {
                            CommitOp::Present { key, caller }
                        }
                        commit::PRED_EQUALS => CommitOp::Equals { key, value, caller },
                        _ => return refused(R_INVALID),
                    }
                }
                tag::REC_PUT => {
                    mutating = true;
                    let Ok((head, tail)) = rec.pod_tail::<RecPutRec>() else {
                        return refused(R_INVALID);
                    };
                    let Some((key, value)) = split_key(tail, head.key_len) else {
                        return refused(R_INVALID);
                    };
                    let caller = head.flags & commit::REC_CALLER != 0;
                    caller_bound |= caller;
                    CommitOp::Put {
                        key,
                        value,
                        ttl_s: head.ttl_s,
                        caller,
                    }
                }
                tag::REC_DEL => {
                    mutating = true;
                    let Ok((head, key)) = rec.pod_tail::<RecDelRec>() else {
                        return refused(R_INVALID);
                    };
                    let caller = head.flags & commit::REC_CALLER != 0;
                    caller_bound |= caller;
                    CommitOp::Del { key, caller }
                }
                _ => return refused(R_INVALID),
            };
            ops.push(op);
        }
        if ops.is_empty() || ops.len() > commit::MAX_OPS as usize {
            return refused(R_INVALID);
        }
        let Some(scope) = self.scope(caller_bound) else {
            return refused(R_DENIED);
        };
        match self.host.commit(scope, &ops) {
            Ok(CommitOutcome::Applied) => (check, commit::APPLIED, 0, 0),
            Ok(CommitOutcome::Conflict { failed }) => (check, commit::CONFLICT, failed, 0),
            Err(denied) => refused(denied_status(&denied)),
        }
    }

    /// The LOOKUP_HIT* (and CHAIN_STATE) of every LOOKUP of the answer, by index; `None` when it has none.
    fn lookups(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut reply = Reply::new();
        let mut any = false;
        let mut index = 0u32;
        for intent in intents {
            let Intent::Lookup { flags, limit, key } = intent else {
                continue;
            };
            any = true;
            let at = index;
            index += 1;
            let looked = match self.scope(flags & LK_CALLER != 0) {
                Some(scope) => match self.host.lookup(scope, *flags, *limit, key) {
                    Ok(looked) => looked,
                    Err(denied) => {
                        tracing::warn!(?denied, "a plane lookup was refused; it reads as a miss");
                        Looked::default()
                    }
                },
                None => Looked::default(),
            };
            let hits: Vec<(u32, &[u8], &[u8])> = looked
                .hits
                .iter()
                .take(*limit as usize)
                .map(|h| (at, &h.key[..], &h.value[..]))
                .collect();
            // The reply refuses only past its cap; the host bounds a hit by MAX_VALUE.
            let put = encode_lookup_hits(&mut reply, &hits);
            debug_assert!(put.is_ok(), "LOOKUP_HITs fit a Reply");
            if let (Some((len, broken_at)), true) = (looked.chain, flags & LK_CHAIN != 0) {
                let put = encode_chain_state(&mut reply, at, len, broken_at);
                debug_assert!(put.is_ok(), "a CHAIN_STATE fits a Reply");
            }
        }
        any.then(|| reply.as_bytes().to_vec())
    }

    /// The WORK_ANS of every WORK of the answer, in intent order; `None` when it has none.
    fn works(&self, intents: &[Intent]) -> Option<Vec<u8>> {
        let mut outcomes: Vec<(u32, WorkOutcome)> = Vec::new();
        for intent in intents {
            let Intent::Work {
                check,
                op,
                target,
                reference,
            } = intent
            else {
                continue;
            };
            let outcome = if self.subject.is_none() {
                // §12.24: no verified principal, no row to bind.
                WorkOutcome::refused(R_DENIED)
            } else {
                self.host.work(&WorkIntent {
                    op: *op,
                    target: target.clone(),
                    reference: reference.clone(),
                })
            };
            outcomes.push((*check, outcome));
        }
        if outcomes.is_empty() {
            return None;
        }
        let answers: Vec<WorkAnswer<'_>> = outcomes
            .iter()
            .map(|(check, o)| WorkAnswer {
                check: *check,
                status: o.status,
                state: o.state,
                reference: &o.reference,
                target: &o.target,
            })
            .collect();
        let mut reply = Reply::new();
        let put = encode_work_answers(&mut reply, &answers);
        debug_assert!(put.is_ok(), "WORK_ANS records fit a Reply");
        Some(reply.as_bytes().to_vec())
    }
}

fn split_key(tail: &[u8], key_len: u32) -> Option<(&[u8], &[u8])> {
    let at = usize::try_from(key_len).ok()?;
    if at > MAX_KEY {
        return None;
    }
    tail.split_at_checked(at)
}

/// The REFUSED code a denied record write answers with (a COMMITTED `status`).
fn denied_status(denied: &RecordsDenied) -> u32 {
    match denied {
        RecordsDenied::Quota => R_RATE_LIMITED,
        RecordsDenied::TooLarge | RecordsDenied::Invalid => R_INVALID,
        RecordsDenied::Unavailable => R_UNSUPPORTED,
    }
}

impl<K: Calls + ?Sized> Task<'_, K> {
    /// Resolves the intents of `first` and of every answer their results provoke. Answers come back in delivery
    /// order, `first` first, each with its intents taken (resolved), so the caller applies their client items,
    /// forward and facts as it would any answer.
    pub fn resolve(
        &mut self,
        first: Answer,
        resolver: &Resolver<'_>,
        effects: &dyn Effects,
    ) -> Result<Vec<Answer>, SessionError> {
        let mut out = Vec::new();
        let mut queue = VecDeque::from([first]);
        let mut rounds = 0u32;
        while let Some(mut answer) = queue.pop_front() {
            let intents = std::mem::take(&mut answer.intents);
            out.push(answer);
            if intents.is_empty() {
                continue;
            }
            rounds += 1;
            if rounds > MAX_ROUNDS {
                return Err(SessionError::Violation(Violation::IntentStorm));
            }
            for piece in resolver.resolve(&intents) {
                let next = self.piece(FROM_CORE, 0, piece.flags, &piece.bytes, effects)?;
                queue.push_back(next);
            }
        }
        Ok(out)
    }
}

/// Who a plane instance is to the store: its record namespace (IF §12.5).
#[derive(Clone)]
pub struct Namespace {
    /// The verified stamp name.
    pub plugin: Arc<str>,
    /// The configured instance name.
    pub name: Arc<str>,
    /// Runtime instance id (the signal registry's key).
    pub instance: u64,
    pub slot: u32,
}

impl Namespace {
    fn caller(&self) -> Caller<'_> {
        Caller {
            plugin: &self.plugin,
            kind: KindCode::Plane,
            name: &self.name,
            instance: self.instance,
            slot: self.slot,
            chain: 1,
            deadline: Instant::now() + Duration::from_secs(30),
            stack: CallStack::default(),
            out_of_process: false,
            limits: InstanceLimits::default(),
        }
    }
}

/// The production [`IntentHost`]: records through [`PluginRecords`], pushes through the [`PushQueue`], signals
/// through the [`SessionSignals`] registry, WORK through the decider (default [`NoWork`]). Its calls block on `rt`,
/// so they run from `spawn_blocking`, never on a runtime worker.
pub struct KernelIntents<R: PluginRecords> {
    records: Arc<R>,
    push: Arc<dyn PushQueue>,
    signals: Arc<dyn SessionSignals>,
    work: Arc<dyn WorkDecider>,
    who: Namespace,
    rt: Handle,
}

/// Decides WORK intents (§12.24).
pub trait WorkDecider: Send + Sync + 'static {
    fn decide(&self, who: &Namespace, intent: &WorkIntent) -> WorkOutcome;
}

/// No recovery runtime: every WORK is `R_UNSUPPORTED`.
pub struct NoWork;

impl WorkDecider for NoWork {
    fn decide(&self, _: &Namespace, _: &WorkIntent) -> WorkOutcome {
        WorkOutcome::unsupported()
    }
}

impl<R: PluginRecords> KernelIntents<R> {
    #[must_use]
    pub fn new(
        records: Arc<R>,
        push: Arc<dyn PushQueue>,
        signals: Arc<dyn SessionSignals>,
        who: Namespace,
        rt: Handle,
    ) -> Self {
        Self {
            records,
            push,
            signals,
            work: Arc::new(NoWork),
            who,
            rt,
        }
    }

    /// WORK is decided by `work` instead of refused.
    #[must_use]
    pub fn with_work(mut self, work: Arc<dyn WorkDecider>) -> Self {
        self.work = work;
        self
    }
}

impl<R: PluginRecords> IntentHost for KernelIntents<R> {
    fn lookup(
        &self,
        scope: Scope,
        flags: u32,
        limit: u32,
        key: &[u8],
    ) -> Result<Looked, RecordsDenied> {
        let who = self.who.caller();
        let mut looked = Looked::default();
        if flags & LK_CHAIN != 0 {
            let split = key.len().checked_sub(8).ok_or(RecordsDenied::Invalid)?;
            let (chain, after) = key.split_at(split);
            let after = u64::from_le_bytes(after.try_into().map_err(|_| RecordsDenied::Invalid)?);
            let mut hits = Vec::new();
            let read = self.rt.block_on(self.records.chain(
                &who,
                scope,
                chain,
                after,
                limit,
                &mut |seq, entry| {
                    let mut hit = chain.to_vec();
                    hit.extend_from_slice(&seq.to_be_bytes());
                    hits.push(Hit {
                        key: hit,
                        value: entry.to_vec(),
                    });
                },
            ))?;
            looked.hits = hits;
            looked.chain = Some((read.len, read.broken_at));
        } else if flags & LK_PREFIX != 0 {
            let mut hits = Vec::new();
            self.rt
                .block_on(self.records.list(&who, scope, key, limit, &mut |k, v| {
                    hits.push(Hit {
                        key: k.to_vec(),
                        value: v.to_vec(),
                    });
                }))?;
            looked.hits = hits;
        } else {
            let mut value = None;
            let found = self
                .rt
                .block_on(self.records.get(&who, scope, key, &mut |v| {
                    value = Some(v.to_vec());
                }))?;
            if let (true, Some(value)) = (found, value) {
                looked.hits.push(Hit {
                    key: key.to_vec(),
                    value,
                });
            }
        }
        Ok(looked)
    }

    fn store(
        &self,
        scope: Scope,
        flags: u32,
        ttl_s: u64,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), RecordsDenied> {
        if key.len() > MAX_KEY || value.len() > MAX_VALUE {
            return Err(RecordsDenied::TooLarge);
        }
        let who = self.who.caller();
        if flags & LK_CHAIN != 0 {
            if ttl_s != 0 {
                return Err(RecordsDenied::Invalid);
            }
            return self
                .rt
                .block_on(self.records.append(&who, scope, key, value))
                .map(|_| ());
        }
        self.rt
            .block_on(self.records.put(&who, scope, key, value, ttl_s))
    }

    fn delete(&self, scope: Scope, key: &[u8]) -> Result<(), RecordsDenied> {
        let who = self.who.caller();
        self.rt.block_on(self.records.del(&who, scope, key))
    }

    fn commit(&self, scope: Scope, ops: &[CommitOp<'_>]) -> Result<CommitOutcome, RecordsDenied> {
        let who = self.who.caller();
        self.rt.block_on(self.records.commit(&who, scope, ops))
    }

    fn work(&self, intent: &WorkIntent) -> WorkOutcome {
        self.work.decide(&self.who, intent)
    }

    fn push(&self, ttl_s: u64, recs: &[u8]) -> Result<(), RecordsDenied> {
        let who = self.who.caller();
        self.rt.block_on(self.push.enqueue(&who, ttl_s, recs))
    }

    fn signal(&self, key: &[u8], subject: Option<[u8; 32]>) {
        self.signals
            .signal(self.who.instance, key, subject, P_SIGNAL, key);
    }
}

#[cfg(test)]
#[path = "tests/port_intents_tests.rs"]
mod tests;
