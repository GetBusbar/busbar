// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store-owned overlay generations. Immutable bounded chunks precede one atomic head CAS.
//! Unknown outcomes retain the exact candidate and replay identity; no observation substitutes
//! for its receipt. Store callbacks run without a host mutex guard.
//! Receipt age uses both local monotonic and wall clocks. StoreCalls exposes no authoritative
//! remote clock or receipt deadline; independent Store clock discontinuities remain unobservable.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Instant, SystemTime};

use busbar_contract::abi::sdk::store::conditional::{
    Decision, Expected, Mutation, Predicate, Request, VERSION,
};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::store_calls::StoreCalls;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::overlay::OverlayDoc;

const SCHEMA: &str = "busbar.config.overlay.v1";
const HEAD: &[u8] = b"head";

type OverlaySnapshot = (Option<Vec<u8>>, Option<Vec<u8>>);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u32,
    generation: [u8; 16],
    length: u64,
    digest: [u8; 32],
}

struct Candidate {
    request: Request,
    chunks: Vec<(Vec<u8>, RecordBytes)>,
    first_submit: Option<Instant>,
    first_submit_wall: Option<SystemTime>,
    conflicted: bool,
}

enum State {
    Idle,
    Busy,
    Pending(Candidate),
    NeedsReload,
}

/// Custody is installed before any effect. Unwinding restores the exact unknown candidate;
/// planning failures restore Idle. The mutex protects ownership transfers only.
struct Operation<'a> {
    store: &'a OverlayStore,
    candidate: Option<Candidate>,
    needs_reload: bool,
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let next = self.candidate.take().map_or(
            if self.needs_reload {
                State::NeedsReload
            } else {
                State::Idle
            },
            State::Pending,
        );
        let old = {
            let mut state = self.store.state.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::replace(&mut *state, next)
        };
        drop(old);
    }
}

/// A real opened Store backend. Its name is diagnostic only; it is never a filesystem path.
pub struct OverlayStore {
    calls: Arc<dyn StoreCalls>,
    state: Mutex<State>,
    observed: Arc<Mutex<Option<Option<Vec<u8>>>>>,
    unpublished: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for OverlayStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OverlayStore(configured Store)")
    }
}

impl OverlayStore {
    pub fn new(calls: Arc<dyn StoreCalls>) -> Result<Arc<Self>, String> {
        if !calls.supports_record_transaction() {
            return Err("config overlay requires the configured Store's atomic conditional-record capability".into());
        }
        Ok(Arc::new(Self {
            calls,
            state: Mutex::new(State::Idle),
            observed: Arc::new(Mutex::new(None)),
            unpublished: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    /// A confirmed overlay was not published with its App. Retain any exact unknown receipt,
    /// but refuse further edits through this old generation until reload installs a fresh carrier.
    pub fn require_reload(&self) {
        self.unpublished
            .store(true, std::sync::atomic::Ordering::Release);
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if matches!(*state, State::Idle) {
            *state = State::NeedsReload;
        }
    }

    pub(crate) fn ensure_published(&self) -> Result<(), String> {
        if self.unpublished.load(std::sync::atomic::Ordering::Acquire) {
            return Err("config overlay has a confirmed unpublished generation; reload before further mutation".into());
        }
        Ok(())
    }

    /// Diagnostic identity retained for callers that previously displayed a resolved path.
    pub fn display(&self) -> &'static str {
        "configured Store"
    }

    fn snapshot(&self) -> Result<OverlaySnapshot, String> {
        loop {
            let (raw, bytes) = self.snapshot_once()?;
            if let Some(bytes) = bytes {
                return Ok((raw, Some(bytes)));
            }
            if raw.is_none() {
                return Ok((None, None));
            }
            // A successful CAS retires its predecessor atomically. A reader that already took
            // that predecessor retries only after proving the head was superseded.
            let current = wait(self.calls.record_get(SCHEMA, HEAD)).map_err(|e| e.to_string())?;
            if current.as_ref().map(|value| value.as_slice()) == raw.as_deref() {
                return Err("config overlay generation is incomplete".into());
            }
        }
    }

    fn snapshot_once(&self) -> Result<OverlaySnapshot, String> {
        let raw = wait(self.calls.record_get(SCHEMA, HEAD)).map_err(|e| e.to_string())?;
        let Some(raw) = raw else {
            return Ok((None, None));
        };
        let head: Head = serde_json::from_slice(raw.as_slice())
            .map_err(|e| format!("invalid config overlay head: {e}"))?;
        if head.version != 1 || head.length == 0 {
            return Err("invalid config overlay generation".into());
        }
        let length = usize::try_from(head.length)
            .map_err(|_| "config overlay length cannot be represented")?;
        let mut bytes = Vec::new();
        let count = length.div_ceil(busbar_contract::MAX_RECORD_BYTES);
        for index in 0..count {
            let key = chunk_key(&head.generation, index as u64);
            let Some(chunk) =
                wait(self.calls.record_get(SCHEMA, &key)).map_err(|e| e.to_string())?
            else {
                return Ok((Some(raw.as_slice().to_vec()), None));
            };
            let expected = (length - bytes.len()).min(busbar_contract::MAX_RECORD_BYTES);
            if chunk.as_slice().len() != expected {
                return Err("config overlay chunk length mismatch".into());
            }
            bytes.extend_from_slice(chunk.as_slice());
        }
        if <[u8; 32]>::from(Sha256::digest(&bytes)) != head.digest {
            return Err("config overlay digest mismatch".into());
        }
        Ok((Some(raw.as_slice().to_vec()), Some(bytes)))
    }

    pub fn read_bytes(&self) -> Result<Option<Vec<u8>>, String> {
        self.snapshot().map(|(_, bytes)| bytes)
    }

    /// Fail closed on unreadable data. Boot/reload callers must propagate this result.
    pub fn read_required(&self) -> Result<Option<OverlayDoc>, String> {
        let (head, bytes) = self.snapshot()?;
        let doc = Self::decode(bytes)?;
        // Diagnostics may initialize a fresh carrier, but never advance an already-pinned App.
        let mut observed = self.observed.lock().unwrap_or_else(|p| p.into_inner());
        if observed.is_none() {
            *observed = Some(head);
        }
        drop(observed);
        Ok(doc)
    }

    fn decode(bytes: Option<Vec<u8>>) -> Result<Option<OverlayDoc>, String> {
        match super::overlay::classify_bytes(bytes) {
            super::overlay::OverlayReadState::Absent => Ok(None),
            super::overlay::OverlayReadState::Loaded(doc) => Ok(Some(*doc)),
            super::overlay::OverlayReadState::Unreadable => Err("config overlay in Store is unreadable; use --safe-mode to quarantine it".into()),
            super::overlay::OverlayReadState::VersionTooNew(v) => Err(format!("config overlay version {v} is newer than this binary; use --safe-mode to quarantine it")),
        }
    }

    /// Resolve exact retained custody before a reload reads the authoritative generation. Return
    /// a fresh carrier for the candidate App; it becomes writable only if that App is published.
    /// The old carrier keeps refusing mutations after recovery, even if rebuilding fails.
    pub fn reopen_for_reload(&self) -> Result<(Arc<Self>, Option<OverlayDoc>), String> {
        let previous = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if matches!(*state, State::Busy) {
                return Err("config overlay Store operation is already in progress".into());
            }
            std::mem::replace(&mut *state, State::Busy)
        };
        let needs_reload = matches!(&previous, State::Pending(_) | State::NeedsReload)
            || self.unpublished.load(std::sync::atomic::Ordering::Acquire);
        let mut operation = Operation {
            store: self,
            candidate: match previous {
                State::Pending(candidate) => Some(candidate),
                _ => None,
            },
            needs_reload,
        };
        if let Some(candidate) = operation.candidate.as_mut() {
            let _decision = self.submit(candidate)?;
            drop(operation.candidate.take());
        }
        let (head, bytes) = self.snapshot()?;
        let doc = Self::decode(bytes)?;
        let baseline = {
            let mut observed = self.observed.lock().unwrap_or_else(|p| p.into_inner());
            match observed.as_ref() {
                None => {
                    *observed = Some(head.clone());
                    self.observed.clone()
                }
                Some(current) if current == &head => self.observed.clone(),
                Some(_) => {
                    operation.needs_reload = true;
                    // A failed rebuild must leave the old carrier pinned and quarantined.
                    Arc::new(Mutex::new(Some(head)))
                }
            }
        };
        Ok((
            Arc::new(Self {
                calls: self.calls.clone(),
                state: Mutex::new(State::Idle),
                observed: baseline,
                unpublished: std::sync::atomic::AtomicBool::new(false),
            }),
            doc,
        ))
    }

    pub(super) fn update(&self, edit: impl FnOnce(&mut OverlayDoc)) -> Result<(), String> {
        self.ensure_published()?;
        // Move owned data out before any Store callback or secret-bearing destructor runs.
        let previous = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if matches!(*state, State::Busy) {
                return Err("config overlay Store operation is already in progress".into());
            }
            if matches!(*state, State::NeedsReload) {
                return Err("config overlay recovery requires a successful config reload before further mutation".into());
            }
            std::mem::replace(&mut *state, State::Busy)
        };
        let candidate = match previous {
            State::Pending(candidate) => Some(candidate),
            _ => None,
        };
        let recovering = candidate.is_some();
        let mut operation = Operation {
            store: self,
            candidate,
            needs_reload: recovering,
        };
        if operation.candidate.is_none() {
            let (expected, bytes) = self.snapshot()?;
            let changed = {
                let mut observed = self.observed.lock().unwrap_or_else(|p| p.into_inner());
                match observed.as_ref() {
                    None => {
                        *observed = Some(expected.clone());
                        false
                    }
                    Some(head) => head != &expected,
                }
            };
            if changed {
                operation.needs_reload = true;
                return Err("config overlay changed since this App generation was recovered; reload before mutation".into());
            }
            let mut doc = match super::overlay::classify_bytes(bytes) {
                super::overlay::OverlayReadState::Absent => OverlayDoc::default(),
                super::overlay::OverlayReadState::Loaded(doc) => *doc,
                _ => {
                    return Err(
                        "refusing to overwrite unreadable or newer config overlay in Store".into(),
                    )
                }
            };
            edit(&mut doc);
            doc.version = super::overlay::OVERLAY_VERSION;
            let bytes = serde_json::to_vec(&doc).map_err(|e| e.to_string())?;
            let op_id = crate::door::op_id();
            let head = Head {
                version: 1,
                generation: op_id.0,
                length: bytes.len() as u64,
                digest: Sha256::digest(&bytes).into(),
            };
            let chunks = bytes
                .chunks(busbar_contract::MAX_RECORD_BYTES)
                .enumerate()
                .map(|(index, bytes)| {
                    RecordBytes::new(bytes.to_vec())
                        .map(|value| (chunk_key(&head.generation, index as u64), value))
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            let mut mutations = vec![Mutation::Put {
                schema: SCHEMA.into(),
                key: HEAD.to_vec(),
                value: serde_json::to_vec(&head).map_err(|e| e.to_string())?,
            }];
            if let Some(raw) = &expected {
                let old: Head = serde_json::from_slice(raw).map_err(|e| e.to_string())?;
                let prefix = chunk_prefix(&old.generation);
                mutations.push(Mutation::DeleteRange {
                    schema: SCHEMA.into(),
                    exact_key_length: (prefix.len() + 8) as u64,
                    prefix,
                });
            }
            let request = Request {
                version: VERSION,
                op_id,
                predicates: vec![Predicate {
                    schema: SCHEMA.into(),
                    key: HEAD.to_vec(),
                    expected: expected.map_or(Expected::Absent, Expected::Bytes),
                }],
                mutations,
            };
            operation.candidate = Some(Candidate {
                request,
                chunks,
                first_submit: None,
                first_submit_wall: None,
                conflicted: false,
            });
        }
        let decision = self.submit(
            operation
                .candidate
                .as_mut()
                .expect("candidate custody installed"),
        )?;
        operation.needs_reload |= decision == Decision::ConditionConflict;
        if decision == Decision::Applied && !recovering {
            let candidate = operation
                .candidate
                .as_ref()
                .expect("confirmed candidate custody");
            let Mutation::Put { value, .. } = &candidate.request.mutations[0] else {
                unreachable!("head mutation is first");
            };
            let old = {
                let mut observed = self.observed.lock().unwrap_or_else(|p| p.into_inner());
                observed.replace(Some(value.clone()))
            };
            drop(old);
        }
        // Only definitive decisions relinquish custody, and destructors run without a mutex.
        drop(operation.candidate.take());
        match decision {
            Decision::ConditionConflict => Err("config overlay changed in Store; reload before retrying".into()),
            Decision::Applied if recovering => Err("a prior config overlay candidate was resolved; reload configuration before retrying this mutation".into()),
            Decision::Applied => Ok(()),
        }
    }

    fn submit(&self, candidate: &mut Candidate) -> Result<Decision, String> {
        if candidate.conflicted {
            self.retire_conflicted(candidate)?;
            return Ok(Decision::ConditionConflict);
        }
        if candidate.first_submit.is_some_and(|first| {
            first.elapsed().as_secs() >= busbar_contract::abi::store::OP_ID_RETENTION_SECS
        }) || candidate.first_submit_wall.is_some_and(|first| {
            SystemTime::now()
                .duration_since(first)
                .is_ok_and(|age| age.as_secs() >= busbar_contract::abi::store::OP_ID_RETENTION_SECS)
        }) {
            return Err("config overlay receipt retention expired; exact unknown candidate and identity retained; restart and recover the Store head before changing configuration".into());
        }
        // Once the head was attempted every chunk was already confirmed. A successor may have
        // retired them since; replay the receipt alone so old chunks are never resurrected.
        if candidate.first_submit.is_none() {
            for (key, value) in &candidate.chunks {
                wait(self.calls.record_put(SCHEMA, key, value)).map_err(|e| e.to_string())?;
            }
        }
        candidate
            .first_submit_wall
            .get_or_insert_with(SystemTime::now);
        candidate.first_submit.get_or_insert_with(Instant::now);
        let decision =
            wait(self.calls.record_transaction(&candidate.request)).map_err(|e| e.to_string())?;
        if decision == Decision::ConditionConflict {
            candidate.conflicted = true;
            self.retire_conflicted(candidate)?;
        }
        Ok(decision)
    }

    fn retire_conflicted(&self, candidate: &Candidate) -> Result<(), String> {
        // Definitive conflict proves this generation was never published. Its sole writer has
        // relinquished the CAS; deleting its immutable staging rows cannot affect a reader.
        let empty = RecordBytes::new(Vec::new()).expect("empty deletion record");
        for (key, _) in &candidate.chunks {
            wait(self.calls.record_put(SCHEMA, key, &empty))
                .map_err(|e| format!("config overlay conflict cleanup pending: {e}"))?;
        }
        Ok(())
    }
}

fn chunk_key(generation: &[u8; 16], index: u64) -> Vec<u8> {
    let mut key = chunk_prefix(generation);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn chunk_prefix(generation: &[u8; 16]) -> Vec<u8> {
    let mut key = b"chunk:".to_vec();
    key.extend_from_slice(generation);
    key
}

fn wait<F: Future>(future: F) -> F::Output {
    struct Unpark(std::thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::overlay::{persist_root, write, RootSettings};
    use crate::test_support::TestOverlayStore;

    #[test]
    fn planning_unwind_restores_idle_and_committed_reply_unwind_restores_exact_candidate() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        let panicking = backend.clone();
        assert!(
            std::thread::spawn(move || panicking.update(|_| panic!("planted planning unwind")))
                .join()
                .is_err()
        );
        persist_root(Some(&backend), &RootSettings::default()).unwrap();
        fixture.on_next_transaction_reply(|| panic!("planted lost reply unwind"));
        let panicking = backend.clone();
        assert!(std::thread::spawn(move || persist_root(
            Some(&panicking),
            &RootSettings {
                per_request_fee: Some(7),
                ..Default::default()
            }
        ))
        .join()
        .is_err());
        assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
        let candidates = fixture.candidates();
        assert_eq!(candidates[1], candidates[2]);
        assert_eq!(
            backend
                .read_required()
                .unwrap()
                .unwrap()
                .root
                .unwrap()
                .per_request_fee,
            Some(7)
        );
    }

    #[test]
    fn callbacks_can_reenter_without_holding_the_backend_mutex() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        let reentrant = backend.clone();
        fixture.on_next_transaction_reply(move || {
            assert!(persist_root(Some(&reentrant), &RootSettings::default())
                .unwrap_err()
                .contains("already in progress"))
        });
        persist_root(Some(&backend), &RootSettings::default()).unwrap();
    }

    #[test]
    fn expired_unknown_receipt_retains_custody_without_replay_or_new_identity() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        fixture.lose_next_commit_reply();
        assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
        {
            let mut state = backend.state.lock().unwrap();
            let State::Pending(candidate) = &mut *state else {
                panic!("candidate custody lost");
            };
            candidate.first_submit = Some(
                Instant::now()
                    - std::time::Duration::from_secs(
                        busbar_contract::abi::store::OP_ID_RETENTION_SECS,
                    ),
            );
        }
        let original = fixture.candidates();
        for _ in 0..2 {
            assert!(persist_root(Some(&backend), &RootSettings::default())
                .unwrap_err()
                .contains("retention expired"));
        }
        assert_eq!(fixture.candidates(), original);
        assert!(matches!(*backend.state.lock().unwrap(), State::Pending(_)));
    }

    #[test]
    fn partial_staging_keeps_old_head_and_replays_the_same_generation() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        let mut doc = OverlayDoc::default();
        doc.named_maps.insert(
            "export".into(),
            std::collections::BTreeMap::from([(
                "large".into(),
                serde_json::json!("x".repeat(busbar_contract::MAX_RECORD_BYTES + 10)),
            )]),
        );
        fixture.fail_after_chunk_writes(1);
        assert!(write(&backend, &doc).is_err());
        assert!(backend.read_required().unwrap().is_none());
        fixture.allow_chunk_writes();
        assert!(write(&backend, &OverlayDoc::default()).is_err());
        assert_eq!(
            serde_json::to_value(backend.read_required().unwrap().unwrap()).unwrap(),
            serde_json::to_value(doc).unwrap()
        );
    }

    #[test]
    fn forward_wall_clock_jump_also_expires_unknown_receipt_without_replay() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        fixture.lose_next_commit_reply();
        assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
        {
            let mut state = backend.state.lock().unwrap();
            let State::Pending(candidate) = &mut *state else {
                panic!("candidate custody lost");
            };
            candidate.first_submit_wall = Some(
                SystemTime::now()
                    - std::time::Duration::from_secs(
                        busbar_contract::abi::store::OP_ID_RETENTION_SECS,
                    ),
            );
        }
        let original = fixture.candidates();
        assert!(persist_root(Some(&backend), &RootSettings::default())
            .unwrap_err()
            .contains("retention expired"));
        assert_eq!(fixture.candidates(), original);
    }

    #[test]
    fn head_cas_retires_superseded_and_conflicted_generations() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        let other = fixture.fork_backend();
        persist_root(Some(&backend), &RootSettings::default()).unwrap();
        for fee in 0..20 {
            persist_root(
                Some(&backend),
                &RootSettings {
                    per_request_fee: Some(fee),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        assert_eq!(fixture.stored_record_count(), 2);
        fixture.before_next_transaction(move || {
            persist_root(
                Some(&other),
                &RootSettings {
                    per_request_fee: Some(99),
                    ..Default::default()
                },
            )
            .unwrap()
        });
        assert!(persist_root(
            Some(&backend),
            &RootSettings {
                per_request_fee: Some(100),
                ..Default::default()
            }
        )
        .is_err());
        assert_eq!(fixture.stored_record_count(), 2);
        assert_eq!(
            backend
                .read_required()
                .unwrap()
                .unwrap()
                .root
                .unwrap()
                .per_request_fee,
            Some(99)
        );
    }

    #[test]
    fn reader_retries_only_when_its_immutable_snapshot_was_retired() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        let other = fixture.fork_backend();
        persist_root(
            Some(&backend),
            &RootSettings {
                per_request_fee: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        fixture.on_next_read_reply(move || {
            persist_root(
                Some(&other),
                &RootSettings {
                    per_request_fee: Some(2),
                    ..Default::default()
                },
            )
            .unwrap()
        });
        assert_eq!(
            backend
                .read_required()
                .unwrap()
                .unwrap()
                .root
                .unwrap()
                .per_request_fee,
            Some(2)
        );
    }

    #[test]
    fn replay_of_a_superseded_unknown_commit_never_resurrects_retired_chunks() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        fixture.lose_next_commit_reply();
        assert!(persist_root(
            Some(&backend),
            &RootSettings {
                per_request_fee: Some(1),
                ..Default::default()
            }
        )
        .is_err());
        let other = fixture.fork_backend();
        persist_root(
            Some(&other),
            &RootSettings {
                per_request_fee: Some(2),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(fixture.stored_record_count(), 2);
        assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
        assert_eq!(fixture.stored_record_count(), 2);
        assert_eq!(
            backend
                .read_required()
                .unwrap()
                .unwrap()
                .root
                .unwrap()
                .per_request_fee,
            Some(2)
        );
        let (reopened, _) = backend.reopen_for_reload().unwrap();
        assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
        persist_root(Some(&reopened), &RootSettings::default()).unwrap();
    }

    #[test]
    fn diagnostics_and_failed_rebuild_never_advance_the_old_app_baseline() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        persist_root(Some(&backend), &RootSettings::default()).unwrap();
        let before = backend.observed.lock().unwrap().clone();
        let other = fixture.fork_backend();
        persist_root(
            Some(&other),
            &RootSettings {
                per_request_fee: Some(9),
                ..Default::default()
            },
        )
        .unwrap();
        let _ = backend.read_bytes().unwrap();
        let _ = backend.read_required().unwrap();
        assert_eq!(*backend.observed.lock().unwrap(), before);
        let (candidate, doc) = backend.reopen_for_reload().unwrap();
        assert_eq!(doc.unwrap().root.unwrap().per_request_fee, Some(9));
        assert_eq!(*backend.observed.lock().unwrap(), before);
        drop(candidate); // a semantic rebuild refused before publication
        assert!(persist_root(Some(&backend), &RootSettings::default()).is_err());
        assert_eq!(*backend.observed.lock().unwrap(), before);
    }

    #[test]
    fn a_normal_confirmed_commit_advances_its_reopened_candidate_carrier() {
        let fixture = TestOverlayStore::new();
        let backend = fixture.backend();
        persist_root(Some(&backend), &RootSettings::default()).unwrap();
        let (candidate, _) = backend.reopen_for_reload().unwrap();
        persist_root(
            Some(&backend),
            &RootSettings {
                per_request_fee: Some(1),
                ..Default::default()
            },
        )
        .unwrap();
        persist_root(
            Some(&candidate),
            &RootSettings {
                per_request_fee: Some(2),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            candidate
                .read_required()
                .unwrap()
                .unwrap()
                .root
                .unwrap()
                .per_request_fee,
            Some(2)
        );
    }
}
