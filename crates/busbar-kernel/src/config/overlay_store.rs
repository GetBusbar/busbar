// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Store-owned overlay generations. Immutable bounded chunks precede one atomic head CAS.
//! Unknown outcomes retain the exact candidate and replay identity; no observation substitutes
//! for its receipt. Store callbacks run without a host mutex guard.

use std::future::Future;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};

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
}

enum State {
    Idle,
    Busy,
    Pending(Candidate),
}

/// A real opened Store backend. Its name is diagnostic only; it is never a filesystem path.
pub struct OverlayStore {
    calls: Arc<dyn StoreCalls>,
    state: Mutex<State>,
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
        }))
    }

    /// Diagnostic identity retained for callers that previously displayed a resolved path.
    pub fn display(&self) -> &'static str {
        "configured Store"
    }

    fn snapshot(&self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), String> {
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
            let chunk = wait(self.calls.record_get(SCHEMA, &key))
                .map_err(|e| e.to_string())?
                .ok_or_else(|| "config overlay generation is incomplete".to_string())?;
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
        match super::overlay::classify_bytes(self.read_bytes()?) {
            super::overlay::OverlayReadState::Absent => Ok(None),
            super::overlay::OverlayReadState::Loaded(doc) => Ok(Some(*doc)),
            super::overlay::OverlayReadState::Unreadable => Err("config overlay in Store is unreadable; use --safe-mode to quarantine it".into()),
            super::overlay::OverlayReadState::VersionTooNew(v) => Err(format!("config overlay version {v} is newer than this binary; use --safe-mode to quarantine it")),
        }
    }

    pub(super) fn update(&self, edit: impl FnOnce(&mut OverlayDoc)) -> Result<(), String> {
        // Move owned data out before any Store callback or secret-bearing destructor runs.
        let previous = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if matches!(*state, State::Busy) {
                return Err("config overlay Store operation is already in progress".into());
            }
            std::mem::replace(&mut *state, State::Busy)
        };
        if let State::Pending(candidate) = previous {
            let result = self.submit(&candidate);
            let pending = if result.is_err() {
                State::Pending(candidate)
            } else {
                State::Idle
            };
            let old = {
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                std::mem::replace(&mut *state, pending)
            };
            drop(old);
            if matches!(result?, Decision::ConditionConflict) {
                return Err("config overlay changed in Store; reload before retrying".into());
            }
            return Err("a prior config overlay candidate was resolved; reload configuration before retrying this mutation".into());
        }
        let planned = (|| {
            let (expected, bytes) = self.snapshot()?;
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
            let request = Request {
                version: VERSION,
                op_id,
                predicates: vec![Predicate {
                    schema: SCHEMA.into(),
                    key: HEAD.to_vec(),
                    expected: expected.map_or(Expected::Absent, Expected::Bytes),
                }],
                mutations: vec![Mutation::Put {
                    schema: SCHEMA.into(),
                    key: HEAD.to_vec(),
                    value: serde_json::to_vec(&head).map_err(|e| e.to_string())?,
                }],
            };
            Ok(Candidate { request, chunks })
        })();
        let (next, result) = match planned {
            Err(error) => (State::Idle, Err(error)),
            Ok(candidate) => match self.submit(&candidate) {
                Ok(Decision::Applied) => (State::Idle, Ok(())),
                Ok(Decision::ConditionConflict) => (
                    State::Idle,
                    Err("config overlay changed in Store; reload before retrying".into()),
                ),
                Err(error) => (State::Pending(candidate), Err(error)),
            },
        };
        let old = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            std::mem::replace(&mut *state, next)
        };
        drop(old);
        result
    }

    fn submit(&self, candidate: &Candidate) -> Result<Decision, String> {
        for (key, value) in &candidate.chunks {
            wait(self.calls.record_put(SCHEMA, key, value)).map_err(|e| e.to_string())?;
        }
        wait(self.calls.record_transaction(&candidate.request)).map_err(|e| e.to_string())
    }
}

fn chunk_key(generation: &[u8; 16], index: u64) -> Vec<u8> {
    let mut key = b"chunk:".to_vec();
    key.extend_from_slice(generation);
    key.extend_from_slice(&index.to_be_bytes());
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
