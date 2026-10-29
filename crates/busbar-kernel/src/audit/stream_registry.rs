// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REGISTERED DURABLE STREAMS — core's store-backed hash chains, addressed by a `kind_id`.
//!
//! A stream REGISTERS once (its neutral `kind`, its framing, whether the scope is digested, and how
//! one stored body decodes back into its record) and is then addressed by the integer `kind_id`.
//! Each stream owns ONE store-backed [`Journal<StreamRecord>`]: the same seq-authority,
//! position-cache and write-ordering machinery every chain in [`crate::audit`] uses. The chain mints
//! `seq`/`prev_hash`/`hash`, frames the prelude in the stream's framing, joins the record's opaque
//! pre-framed content suffix, and persists the neutral `{seq, prev_hash, hash, content}` body.
//!
//! Core's own stream (the admin audit log, [`crate::audit::auditlog`]) registers with an in-core
//! decode ([`Decode::Native`]) and drives its chain through [`register`], [`append_full`] and
//! [`seed`] directly, with no host handle.
//!
//! ## The digest, and the PipeSeparated landmine
//!
//! `digest_input = frame_prelude(prev_hash, [scope if digests_scope], seq, framing) ⧺ content`.
//! For [`Framing::PipeSeparated`] the prelude always writes `prev_hash` first, so the content must
//! arrive pre-framed WITH its leading `|`, and the record appends it RAW. For
//! [`Framing::LengthPrefixed`] every field self-delimits, so concatenation is exact.

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

/// The caller payload for one append. Carries NO `seq`/`prev_hash`/`hash`: those are the chain's
/// authority, assigned by [`crate::audit::Chain::append`].
pub(crate) struct StreamInput {
    content: Vec<u8>,
    framing: Framing,
    digests_scope: bool,
}

impl StreamInput {
    /// One append's payload: the pre-framed `content` suffix under the stream's `framing`, the scope
    /// digested iff `digests_scope`.
    pub(crate) fn new(content: Vec<u8>, framing: Framing, digests_scope: bool) -> Self {
        StreamInput {
            content,
            framing,
            digests_scope,
        }
    }
}

impl StreamRecord {
    /// Assemble a record from decoded parts: the constructor a stream's decode uses to turn a stored
    /// body + its scope back into a chain record. `scope` is the store parent, never read from the
    /// body; `content` is the opaque pre-framed suffix carried verbatim.
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
    // Unused for framing: `digest_fields` feeds the prelude framed in the RECORD's per-instance
    // `framing` and then the pre-framed suffix RAW, so this const never governs any byte. It only
    // satisfies the trait; the real framing travels on the record.
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
        // The prelude is framed here; the record's suffix is appended RAW. The two Digest::raw calls
        // are a pure byte concat, so `sha256_hex(prelude ⧺ suffix)` matches the legacy single buffer
        // for BOTH framings (the PipeSeparated join `|` lives inside `content`).
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

/// An in-core decode: one stored body back into its chain record. The scope it is handed is inert
/// (the registry re-scopes the record with the store parent it knows).
pub(crate) type NativeDecode = fn(&str, &[u8]) -> RecordStoreResult<StreamRecord>;

/// How a registered stream's stored body decodes back into its record.
#[derive(Clone)]
pub(crate) enum Decode {
    /// Decoded in core by the stream's own [`NativeDecode`].
    Native(NativeDecode),
}

/// The text a failed decode reports, unchanged from the bridge it replaces (a decode fault read
/// back through the seam's status class).
const DECODE_FAILED: &str = "journal reframe failed: Fault";

/// One registered durable stream. The `journal` is an [`Arc`] so an op clones it out from under the
/// registry lock and does its store I/O and decode WITHOUT holding the registry.
struct DurableStream {
    kind: String,
    framing: Framing,
    digests_scope: bool,
    decode: Decode,
    journal: Arc<Journal<StreamRecord>>,
}

/// The process-local registry of durable streams, keyed by the registered `kind_id`.
fn registry() -> &'static Mutex<HashMap<u32, DurableStream>> {
    static S: OnceLock<Mutex<HashMap<u32, DurableStream>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Poison-recovering lock: a panic mid-op must not wedge the registry.
fn registry_lock() -> MutexGuard<'static, HashMap<u32, DurableStream>> {
    registry().lock().unwrap_or_else(|e| e.into_inner())
}

/// The addressable parts of one registered stream, snapshotted so the registry lock is released
/// before any store I/O or decode runs.
pub(crate) struct StreamHandle {
    pub(crate) kind: String,
    pub(crate) framing: Framing,
    pub(crate) digests_scope: bool,
    pub(crate) decode: Decode,
    pub(crate) journal: Arc<Journal<StreamRecord>>,
}

/// REGISTER a durable stream under `kind_id`: record its neutral facts and decode, give its position
/// cache an LRU `cap` (`usize::MAX` opts out of eviction), and attach `sink` as its durable store (no
/// sink ⇒ the positions live in RAM only). Re-registering an id replaces the stream and resets every
/// position.
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

/// The registered stream `kind_id`, or `None` for an id nothing registered.
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
    /// Decode one stored body with the stream's in-core decode and re-scope it with the store parent
    /// `scope` under the stream's framing.
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

    /// APPEND one record to `scope`: mint the chain fields through the ONE core chain, persist the
    /// neutral body, and report any chain break the resume of an evicted scope found. `decode` turns
    /// a stored body back into a record on that resume.
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

    /// REPORT THE CHAIN BREAKS A RESUME FOUND, once each. A scope evicted from the journal's cache is
    /// read back from the store to take its next record; a persisted tail that does not verify is
    /// tamper evidence the journal records and resumes past (it never refuses the write). This drains
    /// those records and names each on the diagnostics envelope, so runtime tamper evidence is as
    /// visible as the boot restore's.
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

/// APPEND one record to the registered stream `kind_id` and return its MINTED chain fields
/// `(seq, prev_hash, hash)`, with no host handle: the append reads no host state, and a resume
/// decodes through the stream's in-core decode. `Err` carries the STORE's own error verbatim (a
/// durable-write failure the caller decides on), or names an unregistered stream or an empty scope.
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

/// SEED one scope's position from its already-read stored bodies, decoded through the stream's
/// in-core decode. `Ok(true)` when the stored chain does not verify (it still resumes from the
/// tail); `Err(())` for an unregistered stream, an empty scope, or a body that would not decode.
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
