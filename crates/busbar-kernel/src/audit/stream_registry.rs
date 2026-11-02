// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::audit::journal::{Journal, JournalError, NeutralRecord, Reframe};
use crate::audit::{frame_prelude, ChainLabels, ChainedRecord, Digest, Framing};
use crate::store::plane_view::PlaneStore;
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// One appended record: the chain-assigned prelude (`scope`/`seq`/`prev_hash`/`hash`) plus the
/// record's opaque pre-framed content suffix and the stream's framing declaration. Implements the
/// real [`ChainedRecord`] so the ONE [`crate::audit`] verifier walks it unchanged.
#[derive(Clone)]
pub(crate) struct StreamRecord {
    pub(crate) scope: String,
    pub(crate) seq: u64,
    pub(crate) prev_hash: String,
    pub(crate) hash: String,
    /// The record's OWN fields, already framed as a suffix (leading `|` for PipeSeparated).
    pub(crate) content: Vec<u8>,
    /// The stream's prelude framing (carried per-record because the registry serves many streams).
    pub(crate) framing: Framing,
    /// Whether the scope participates in the digest (admin-style streams omit it).
    pub(crate) digests_scope: bool,
}

pub(crate) struct StreamInput {
    content: Vec<u8>,
    framing: Framing,
    digests_scope: bool,
}

impl StreamInput {
    pub(crate) fn new(content: Vec<u8>, framing: Framing, digests_scope: bool) -> Self {
        StreamInput {
            content,
            framing,
            digests_scope,
        }
    }
}

impl StreamRecord {
    #[allow(dead_code)]
    pub(crate) fn from_parts(
        scope: String,
        seq: u64,
        prev_hash: String,
        hash: String,
        content: Vec<u8>,
        framing: Framing,
        digests_scope: bool,
    ) -> Self {
        StreamRecord {
            scope,
            seq,
            prev_hash,
            hash,
            content,
            framing,
            digests_scope,
        }
    }
}

impl ChainedRecord for StreamRecord {
    type Input = StreamInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the plane journal chain",
        scope: "scope",
    };

    const FRAMING: Framing = Framing::LengthPrefixed;

    fn scope_of(&self) -> &str {
        &self.scope
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
    fn hash(&self) -> &str {
        &self.hash
    }

    fn link(scope: &str, seq: u64, prev_hash: String, input: StreamInput) -> Self {
        StreamRecord {
            scope: scope.to_string(),
            seq,
            prev_hash,
            hash: String::new(),
            content: input.content,
            framing: input.framing,
            digests_scope: input.digests_scope,
        }
    }

    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }

    fn digest_fields(&self, d: &mut Digest) {
        let scope = self.digests_scope.then_some(self.scope.as_str());
        d.raw(&frame_prelude(
            self.framing,
            &self.prev_hash,
            scope,
            self.seq,
        ));
        d.raw(&self.content);
    }
}

impl NeutralRecord for StreamRecord {
    fn content(&self) -> &[u8] {
        &self.content
    }
}

pub(crate) type NativeDecode = fn(&str, &[u8]) -> RecordStoreResult<StreamRecord>;

/// How a registered stream's stored body decodes back into its record.
#[derive(Clone)]
pub(crate) enum Decode {
    /// Decoded in core by the stream's own [`NativeDecode`].
    Native(NativeDecode),
}

const DECODE_FAILED: &str = "journal reframe failed: Fault";

struct DurableStream {
    kind: String,
    framing: Framing,
    digests_scope: bool,
    decode: Decode,
    journal: Arc<Journal<StreamRecord>>,
}

fn registry() -> &'static Mutex<HashMap<u32, DurableStream>> {
    static S: OnceLock<Mutex<HashMap<u32, DurableStream>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn registry_lock() -> MutexGuard<'static, HashMap<u32, DurableStream>> {
    registry().lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) struct StreamHandle {
    pub(crate) kind: String,
    pub(crate) framing: Framing,
    pub(crate) digests_scope: bool,
    pub(crate) decode: Decode,
    pub(crate) journal: Arc<Journal<StreamRecord>>,
}

pub(crate) fn register(
    kind_id: u32,
    kind: String,
    framing: Framing,
    digests_scope: bool,
    decode: Decode,
    cap: usize,
    sink: Option<Arc<dyn PlaneStore>>,
) {
    let journal = Arc::new(Journal::<StreamRecord>::new(cap));
    if let Some(store) = sink {
        journal.set_sink(store);
    }
    let stream = DurableStream {
        kind,
        framing,
        digests_scope,
        decode,
        journal,
    };
    registry_lock().insert(kind_id, stream);
}

pub(crate) fn handle(kind_id: u32) -> Option<StreamHandle> {
    let map = registry_lock();
    map.get(&kind_id).map(|s| StreamHandle {
        kind: s.kind.clone(),
        framing: s.framing,
        digests_scope: s.digests_scope,
        decode: s.decode.clone(),
        journal: s.journal.clone(),
    })
}

impl StreamHandle {
    pub(crate) fn decode_native(
        &self,
        scope: &str,
        body: &[u8],
    ) -> RecordStoreResult<StreamRecord> {
        let Decode::Native(decode) = &self.decode;
        let r = decode("", body).map_err(|_| RecordStoreError(DECODE_FAILED.to_string()))?;
        Ok(StreamRecord {
            scope: scope.to_string(),
            framing: self.framing,
            ..r
        })
    }

    pub(crate) fn append(
        &self,
        scope: &str,
        content: Vec<u8>,
        decode: &Reframe<'_, StreamRecord>,
    ) -> Result<StreamRecord, JournalError> {
        let input = StreamInput::new(content, self.framing, self.digests_scope);
        let appended = self.journal.append_scoped(&self.kind, scope, input, decode);
        self.report_resume_breaks();
        appended
    }

    fn report_resume_breaks(&self) {
        for brk in self.journal.take_resume_breaks() {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_JOURNAL_RESUME_CHAIN_BROKEN,
                stream = %self.kind,
                break_detail = %brk,
                "plane journal CHAIN VERIFICATION FAILED on resume — the persisted tail of an evicted \
                 scope does not verify against its own hash chain. The chain resumes from the broken \
                 tail; the write is not refused."
            );
        }
    }
}

pub(crate) fn append_full(
    kind_id: u32,
    scope: &str,
    content: &[u8],
) -> Result<(u64, String, String), RecordStoreError> {
    let Some(h) = handle(kind_id) else {
        return Err(RecordStoreError(
            "journal stream is not registered".to_string(),
        ));
    };
    if scope.is_empty() {
        return Err(RecordStoreError(
            "journal scope must be a non-empty key".to_string(),
        ));
    }
    let decode = |sc: &str, body: &[u8]| h.decode_native(sc, body);
    match h.append(scope, content.to_vec(), &decode) {
        Ok(record) => Ok((
            record.seq(),
            record.prev_hash().to_string(),
            record.hash().to_string(),
        )),
        Err(JournalError::Store(e)) => Err(e),
    }
}

pub(crate) fn seed(kind_id: u32, scope: &str, bodies: &[Vec<u8>]) -> Result<bool, ()> {
    let h = handle(kind_id).ok_or(())?;
    if scope.is_empty() {
        return Err(());
    }
    let records = bodies
        .iter()
        .map(|body| h.decode_native(scope, body))
        .collect::<RecordStoreResult<Vec<_>>>()
        .map_err(|_| ())?;
    Ok(h.journal.seed_position(scope, &records).is_some())
}

#[cfg(test)]
#[path = "tests/stream_registry_tests.rs"]
mod tests;
