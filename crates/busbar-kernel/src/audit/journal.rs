// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;
use std::time::{Duration, Instant};

use indexmap::IndexMap;

use crate::audit::{Chain, ChainBreak, ChainedRecord};
use crate::store::plane_view::{encode, PlaneStore};
use busbar_contract::records::{
    PlaneDisposition, PlaneRecord, PlaneSelector, RecordStoreError, RecordStoreResult,
};

const CLAIM_WAIT: Duration = Duration::from_secs(5);

/// Why a journal write could not be made durable. ONE variant today: the durable append failed. It is
/// SURFACED rather than swallowed — an evidence record that is not durable is one a restart will lose,
/// and the caller has to be able to decide whether that is acceptable for what it is recording.
#[derive(Debug)]
pub(crate) enum JournalError {
    /// The durable write failed.
    Store(RecordStoreError),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Store(e) => write!(f, "{e}"),
        }
    }
}

/// TEST ONLY: WHAT A WHOLE-STORE REHYDRATE ([`Journal::restore_scoped`]) FOUND, reported rather
/// than summed. Production seeds each scope through [`Journal::seed_position`]; the tests read a
/// stream back through this to check what a store holds. Neutral field names: a plane wrapper
/// renames these into its own operator vocabulary (`principals`, `active`, …) and emits its own
/// diagnostics from the two that are bad news.
#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Restored {
    /// Scopes whose chain position was resumed.
    pub(crate) scopes: usize,
    /// Records read back across every scope. THE DURABILITY SIGNAL: zero here on a deployment that
    /// has been serving traffic means the configured backend is keeping none of them.
    pub(crate) records: usize,
    /// Scopes the store ENUMERATED but returned no records for — the one shape the verifier cannot
    /// judge on its own, and what a wholesale deletion of one scope's evidence looks like. Named (not
    /// merely counted) so the wrapper can log WHICH.
    pub(crate) empty_scopes: Vec<String>,
    /// Records the reframe callback could NOT decode — a body the store held but this build cannot
    /// read back (a format from a store no released build wrote, or a corrupt row). Counted and
    /// SKIPPED per-record rather than allowed to abort the whole rehydrate: dropping every other
    /// scope's working set because one row would not decode is strictly worse than losing the one row,
    /// exactly as a chain break is tolerated per-scope rather than refused wholesale.
    pub(crate) unreadable: usize,
    /// Chains that FAILED to verify. Tamper evidence. The records are still restored and the chain
    /// still resumes from the broken tail; the break is reported, never silently re-based onto.
    pub(crate) chain_breaks: Vec<ChainBreak>,
}

pub(crate) struct Journal<R> {
    positions: Mutex<IndexMap<String, Chain<R>>>,

    overflowed: AtomicBool,

    sink: Mutex<Option<Arc<dyn PlaneStore>>>,

    cap: usize,

    resume_breaks: Mutex<Vec<ChainBreak>>,

    claimed: Mutex<HashMap<String, ThreadId>>,

    released: Condvar,

    claim_wait: Duration,
}

struct ScopeClaim<'a> {
    claimed: &'a Mutex<HashMap<String, ThreadId>>,
    released: &'a Condvar,
    scope: String,
}

impl Drop for ScopeClaim<'_> {
    fn drop(&mut self) {
        self.claimed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.scope);
        self.released.notify_all();
    }
}

impl<R: ChainedRecord> Journal<R> {
    pub(crate) fn new(cap: usize) -> Self {
        Journal {
            positions: Mutex::new(IndexMap::new()),
            overflowed: AtomicBool::new(false),
            sink: Mutex::new(None),
            cap,
            resume_breaks: Mutex::new(Vec::new()),
            claimed: Mutex::new(HashMap::new()),
            released: Condvar::new(),
            claim_wait: CLAIM_WAIT,
        }
    }

    #[cfg(test)]
    pub(crate) fn set_claim_wait(&mut self, wait: Duration) {
        self.claim_wait = wait;
    }

    fn claim(&self, scope: &str) -> RecordStoreResult<ScopeClaim<'_>> {
        let me = std::thread::current().id();
        let deadline = Instant::now() + self.claim_wait;
        let mut claimed = self.claimed.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let holder = claimed.get(scope).copied();
            match holder {
                None => break,
                Some(owner) if owner == me => {
                    return Err(RecordStoreError(
                        "a journal scope was re-entered from inside its own store call on the same \
                         thread; refused rather than waiting on itself"
                            .to_string(),
                    ));
                }
                Some(_) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(RecordStoreError(
                            "a journal scope stayed claimed by another thread's store write past \
                             the claim deadline; refused rather than waiting on it without end"
                                .to_string(),
                        ));
                    }
                    claimed = self
                        .released
                        .wait_timeout(claimed, left)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            }
        }
        claimed.insert(scope.to_string(), me);
        Ok(ScopeClaim {
            claimed: &self.claimed,
            released: &self.released,
            scope: scope.to_string(),
        })
    }

    fn commit(&self, scope: &str, chain: Chain<R>) {
        let mut positions = self.positions();
        Self::commit_position(&mut positions, &self.overflowed, self.cap, scope, chain);
    }

    pub(crate) fn take_resume_breaks(&self) -> Vec<ChainBreak> {
        std::mem::take(&mut *self.resume_breaks.lock().unwrap_or_else(|e| e.into_inner()))
    }

    fn positions(&self) -> MutexGuard<'_, IndexMap<String, Chain<R>>> {
        self.positions.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub(crate) fn sink(&self) -> Option<Arc<dyn PlaneStore>> {
        self.sink.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub(crate) fn set_sink(&self, store: Arc<dyn PlaneStore>) {
        *self.sink.lock().unwrap_or_else(|e| e.into_inner()) = Some(store);
    }

    fn commit_position(
        positions: &mut IndexMap<String, Chain<R>>,
        overflowed: &AtomicBool,
        cap: usize,
        scope: &str,
        chain: Chain<R>,
    ) {
        match positions.get_index_of(scope) {
            Some(idx) => {
                if let Some((_, slot)) = positions.get_index_mut(idx) {
                    *slot = chain;
                }

                positions.move_index(idx, positions.len() - 1);
            }
            None => {
                positions.insert(scope.to_string(), chain);
            }
        }
        while positions.len() > cap {
            positions.shift_remove_index(0);
            overflowed.store(true, Ordering::Relaxed);
        }
    }

    fn resume_from_store(
        &self,
        kind: &str,
        scope: &str,
        read: impl Fn(&[u8]) -> RecordStoreResult<R>,
    ) -> Result<Chain<R>, JournalError> {
        if !self.overflowed.load(Ordering::Relaxed) {
            return Ok(Chain::new());
        }
        let Some(store) = self.sink() else {
            return Ok(Chain::new());
        };
        let bodies = store
            .list_plane_records(kind, &PlaneSelector::Parent(scope.into()))
            .map_err(JournalError::Store)?;
        if bodies.is_empty() {
            return Ok(Chain::new());
        }
        let mut records = Vec::with_capacity(bodies.len());
        let mut unreadable = None;
        for body in &bodies {
            match read(body) {
                Ok(record) => records.push(record),
                Err(error) => {
                    crate::diagnostics::diag_error!(
                        crate::diagnostics::PLANE_JOURNAL_ROW_UNREADABLE,
                        scope = %scope,
                        error = %error,
                        "a persisted journal record could NOT be reframed on resume; it is being \
                         SKIPPED while the decodable records retain their original chain links. \
                         The unreadable evidence is reported here, never silently discarded."
                    );
                    unreadable = Some(error);
                }
            }
        }

        if records.is_empty() {
            if let Some(error) = unreadable {
                return Err(JournalError::Store(error));
            }
        }
        Ok(match Chain::from_persisted(&records) {
            Ok(chain) => chain,
            Err(brk) => {
                self.resume_breaks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(brk);
                Chain::from_persisted_unverified(&records)
            }
        })
    }

    pub(crate) fn seed_position(&self, scope: &str, records: &[R]) -> Option<ChainBreak> {
        let (chain, brk) = match Chain::from_persisted(records) {
            Ok(c) => (c, None),
            Err(b) => (Chain::from_persisted_unverified(records), Some(b)),
        };
        self.commit(scope, chain);
        brk
    }

    pub(crate) fn forget(&self, scope: &str) {
        self.positions().shift_remove(scope);
        self.overflowed.store(true, Ordering::Relaxed);
    }

    fn append_with(
        &self,
        scope: &str,
        input: R::Input,
        resume: impl FnOnce() -> Result<Chain<R>, JournalError>,
        envelope: impl FnOnce(&R) -> RecordStoreResult<PlaneRecord>,
    ) -> Result<R, JournalError> {
        let _claim = self.claim(scope).map_err(JournalError::Store)?;
        let cached = self.positions().get(scope).cloned();
        let mut candidate = match cached {
            Some(chain) => chain,
            None => resume()?,
        };
        let record = candidate.append(scope, input);
        if let Some(store) = self.sink() {
            let envelope = envelope(&record).map_err(JournalError::Store)?;
            if let Err(e) = store.append_plane_record(envelope.view()) {
                self.forget(scope);
                return Err(JournalError::Store(e));
            }
        }
        self.commit(scope, candidate);
        Ok(record)
    }

    #[cfg(test)]
    pub(crate) fn next_seq(&self, scope: &str) -> u64 {
        self.positions()
            .get(scope)
            .map(Chain::next_seq)
            .unwrap_or(1)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.positions().len()
    }
}

/// The NEUTRAL durable body the store-backed journal persists per record — `{seq, prev_hash, hash,
/// content}`, naming no plane type. The journal persists THIS, and a stream's reframe callback is
/// the decode bridge that turns this shape back into a record on restore.
#[derive(serde::Serialize, serde::Deserialize)]
pub struct NeutralBody {
    /// The chain sequence the host minted for this record.
    pub seq: u64,
    /// The link to the previous record (empty at genesis).
    pub prev_hash: String,
    /// This record's sealed digest.
    pub hash: String,
    /// The plane's OPAQUE pre-framed content suffix (the bytes the digest appends RAW).
    pub content: Vec<u8>,
}

pub(crate) trait NeutralRecord: ChainedRecord + Clone {
    fn content(&self) -> &[u8];
}

pub(crate) type Reframe<'a, R> = dyn Fn(&str, &[u8]) -> RecordStoreResult<R> + 'a;

impl<R: NeutralRecord> Journal<R> {
    fn resume_scoped(
        &self,
        kind: &str,
        scope: &str,
        reframe: &Reframe<'_, R>,
    ) -> Result<Chain<R>, JournalError> {
        self.resume_from_store(kind, scope, |body| reframe(scope, body))
    }

    pub(crate) fn append_scoped(
        &self,
        kind: &str,
        scope: &str,
        input: R::Input,
        reframe: &Reframe<'_, R>,
    ) -> Result<R, JournalError> {
        let envelope = |record: &R| -> RecordStoreResult<PlaneRecord> {
            let body = NeutralBody {
                seq: record.seq(),
                prev_hash: record.prev_hash().to_string(),
                hash: record.hash().to_string(),
                content: record.content().to_vec(),
            };
            Ok(PlaneRecord {
                kind: kind.to_string(),
                id: scope.to_string(),
                parent: Some(scope.to_string()),
                seq: record.seq(),

                ts: busbar_kernel::store::now(),
                disposition: PlaneDisposition::Active,
                body: encode(&body)?,
            })
        };
        self.append_with(
            scope,
            input,
            || self.resume_scoped(kind, scope, reframe),
            envelope,
        )
    }

    #[cfg(test)]
    pub(crate) fn restore_scoped(
        &self,
        kind: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> RecordStoreResult<Restored> {
        let scopes = store.list_plane_record_parents(kind)?;
        let mut out = Restored::default();
        for scope in &scopes {
            let _claim = self.claim(scope)?;

            let raw =
                store.list_plane_records(kind, &PlaneSelector::Parent(scope.as_str().into()))?;

            let store_returned_nothing = raw.is_empty();
            let mut records: Vec<R> = Vec::new();
            for body in raw {
                match reframe(scope, &body) {
                    Ok(r) => records.push(r),
                    Err(e) => {
                        out.unreadable += 1;
                        crate::diagnostics::diag_error!(
                            crate::diagnostics::PLANE_JOURNAL_ROW_UNREADABLE,
                            scope = %scope,
                            error = %e,
                            "a persisted journal record could NOT be reframed on restore; it is being \
                             SKIPPED and counted rather than aborting the whole rehydrate (which would \
                             drop every other scope's working set). The evidence in this one row is \
                             lost — reported here, never skipped silently."
                        );
                    }
                }
            }
            if records.is_empty() {
                if store_returned_nothing {
                    out.empty_scopes.push(scope.clone());
                }
                self.commit(scope, Chain::new());
                out.scopes += 1;
                continue;
            }
            let chain = match Chain::from_persisted(&records) {
                Ok(c) => c,
                Err(brk) => {
                    out.chain_breaks.push(brk);
                    Chain::from_persisted_unverified(&records)
                }
            };
            out.records += records.len();
            self.commit(scope, chain);
            out.scopes += 1;
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn read_scoped(
        &self,
        kind: &str,
        scope: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> RecordStoreResult<Vec<R>> {
        store
            .list_plane_records(kind, &PlaneSelector::Parent(scope.into()))?
            .iter()
            .map(|body| reframe(scope, body))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn verify_scoped(
        &self,
        kind: &str,
        scope: &str,
        store: &dyn PlaneStore,
        reframe: &Reframe<'_, R>,
    ) -> RecordStoreResult<Option<ChainBreak>> {
        let records = self.read_scoped(kind, scope, store, reframe)?;
        Ok(crate::audit::verify_chain(&records).err())
    }

    #[cfg(test)]
    pub(crate) fn compact_scoped(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        match self.sink() {
            Some(store) => {
                store.purge_plane_records(kind, before, busbar_contract::records::Retention::Age)
            }
            None => Ok(0),
        }
    }
}

#[cfg(test)]
#[path = "tests/journal_tests.rs"]
mod journal_tests;

#[cfg(test)]
#[path = "tests/journal_lock_tests.rs"]
mod journal_lock_tests;
