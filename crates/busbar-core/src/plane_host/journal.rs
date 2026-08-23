// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JOURNAL family of the plane host-vtable, wired over busbar-core's ONE real audit chain
//! ([`crate::audit`]).
//!
//! ## The seam contract
//!
//! The HOST owns the ONE hash chain; a plane keeps only its *record shape + framing* and hands the
//! host its OWN fields as a pre-framed content SUFFIX (bytes). The host frames the PRELUDE
//! (`prev_hash`, then `scope` iff [`FramingDesc::digests_scope`], then `seq`) in the stream's
//! [`Framing`], byte-concatenates the plane's suffix, digests, links, and appends. The digest input is
//!
//! ```text
//! digest_input = frame_prelude(prev_hash, [scope if digests_scope], seq, framing) ⧺ content_suffix
//! hash         = sha256_hex(digest_input)
//! ```
//!
//! and it is produced through the SAME [`crate::audit::Digest`] mechanism the verifier re-runs, so an
//! appended chain [`crate::audit::verify_chain`]-passes byte-identically.
//!
//! ## The PipeSeparated landmine
//!
//! For [`Framing::PipeSeparated`] a `|` is emitted BEFORE every field except the first (`started`).
//! The prelude always writes `prev_hash` first (even when empty at genesis), so `started` is true by
//! the time the suffix joins — meaning the plane must pre-frame its suffix WITH its leading `|`
//! (Option A: `content = "|ts|kind|…"`), and the host does a pure byte concat via
//! [`crate::audit::Digest::raw`]. If the suffix were framed in a fresh `Digest` (`started == false`)
//! the join would be short exactly one `|` and every PipeSeparated chain would report `DigestMismatch`
//! at the next boot. For [`Framing::LengthPrefixed`] every field self-delimits, so concatenation is
//! exact with no separator. Both cases are handled uniformly here: the prelude is framed, the suffix is
//! appended RAW.
//!
//! ## Durability
//!
//! This module holds the per-scope positions and rows in a PROCESS-LOCAL registry and wires
//! FAITHFULLY to the existing [`crate::audit::Chain::append`] per scope — same seq authority, same
//! seal/digest — producing byte-identical digests. No persisted byte format is changed. A generic
//! store-backed `audit::Journal` (host-side seq-authority + per-scope position cache + LRU +
//! store-resume, naming no plane type) is not yet wired; the two `// durable-store cleave point`
//! markers below flag where it would attach to the durable store.

use super::recover;
use crate::audit::journal::{Journal, NeutralRecord};
use crate::audit::{frame_prelude, Chain, ChainLabels, ChainedRecord, Digest, Framing};
use crate::plane::store::PlaneStoreView;
use busbar_plugin::hot::host::{HostCtx, JournalReframeFn};
use busbar_plugin::hot::{
    ChainBreakHdr, Framing as AbiFraming, FramingDesc, JournalQuery, JournalStreamDesc, ReframeOut,
    RestoredHdr, Seq, StatusClass, VerifyChainHdr, POD_VERSION,
};
use core::mem::MaybeUninit;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

/// One appended journal record: the host-assigned prelude (`scope`/`seq`/`prev_hash`/`hash`) plus the
/// plane's opaque pre-framed content suffix and the stream's framing declaration. Implements the real
/// [`ChainedRecord`] so the ONE [`crate::audit`] verifier walks it unchanged.
#[derive(Clone)]
pub(crate) struct PlaneJournalRecord {
    scope: String,
    seq: u64,
    prev_hash: String,
    hash: String,
    /// The plane's OWN fields, already framed as a suffix (leading `|` for PipeSeparated — Option A).
    content: Vec<u8>,
    /// The stream's prelude framing (carried per-record because the host serves many streams).
    framing: Framing,
    /// Whether the scope participates in the digest (admin-style streams omit it).
    digests_scope: bool,
}

/// The caller payload for one append: everything the plane supplies. Carries NO `seq`/`prev_hash`/
/// `hash` — those are the chain's authority, assigned by [`Chain::append`].
pub(crate) struct PlaneJournalInput {
    content: Vec<u8>,
    framing: Framing,
    digests_scope: bool,
}

impl PlaneJournalInput {
    /// Build an append input from a plane's pre-framed content suffix + the stream's framing facts.
    /// The one constructor a WITHIN-CORE plane seam user (e.g. `plane::taskstore`) reaches, so the
    /// record's fields stay private to this module while the neutral append path is drivable directly
    /// (no FFI `HostCtx`), exactly as the vtable `journal_append_scoped` drives it over the border.
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    pub(crate) fn new(content: Vec<u8>, framing: Framing, digests_scope: bool) -> Self {
        PlaneJournalInput {
            content,
            framing,
            digests_scope,
        }
    }
}

impl PlaneJournalRecord {
    /// Assemble a record from reframed parts — the constructor a plane-side reframe (the `call_reframe`
    /// FFI bridge, OR an in-core seam user's own decode bridge like `plane::taskstore`) uses to turn a
    /// stored body + its scope back into a chain record. `scope` is the store parent, never read from
    /// the body; `content` is the plane's opaque pre-framed suffix carried verbatim.
    #[cfg_attr(
        not(any(feature = "plane-mcp", feature = "plane-a2a")),
        allow(dead_code)
    )]
    pub(crate) fn from_parts(
        scope: String,
        seq: u64,
        prev_hash: String,
        hash: String,
        content: Vec<u8>,
        framing: Framing,
        digests_scope: bool,
    ) -> Self {
        PlaneJournalRecord {
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

impl ChainedRecord for PlaneJournalRecord {
    type Input = PlaneJournalInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the plane journal chain",
        scope: "scope",
    };
    // Unused for framing: `digest_fields` feeds the prelude framed in the RECORD's per-instance
    // `framing` and then the pre-framed suffix RAW, so this const never governs any byte. It only
    // satisfies the trait; the real framing travels on the record (the Phase-3 shape).
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

    fn link(scope: &str, seq: u64, prev_hash: String, input: PlaneJournalInput) -> Self {
        PlaneJournalRecord {
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
        // HOST frames the prelude; the plane's suffix is appended RAW (Option A) — the two Digest::raw
        // calls are a pure byte concat, so `sha256_hex(prelude ⧺ suffix)` matches the legacy single
        // buffer for BOTH framings (the PipeSeparated join `|` lives inside `content`).
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

impl NeutralRecord for PlaneJournalRecord {
    fn content(&self) -> &[u8] {
        &self.content
    }
}

// ── THE DURABLE JOURNAL SEAM (minor-9) — store-backed, keyed by a plane-registered `kind_id` ───────
//
// A plane REGISTERS a stream (its neutral `kind`, framing, digests_scope + a plane-provided REFRAME
// callback) and thereafter addresses append/read/restore/seed/forget/compact/verify by the integer
// `kind_id`. Each stream owns ONE store-backed [`crate::audit::journal::Journal<PlaneJournalRecord>`]
// — the SAME seq-authority + position-cache + write-ordering machinery the three shipped streams use,
// naming no plane type. The host mints seq/prev_hash/hash through the ONE core chain and persists the
// neutral `{seq, prev_hash, hash, content}` body; the plane's reframe is the decode bridge that turns
// a stored body (this neutral body OR a legacy serde row) back into a record on read/restore/verify.

/// One registered durable stream. Holds the neutral facts the host learned at register time and the
/// store-backed journal it drives. The `journal` is an [`Arc`] so an op clones it out from under the
/// registry lock and does its store I/O + reframe callbacks WITHOUT holding the registry.
struct DurableStream {
    kind: String,
    framing: Framing,
    digests_scope: bool,
    reframe: JournalReframeFn,
    journal: Arc<Journal<PlaneJournalRecord>>,
}

/// The process-local registry of durable streams, keyed by the host-assigned `kind_id`.
fn streams() -> &'static Mutex<HashMap<u32, DurableStream>> {
    static S: OnceLock<Mutex<HashMap<u32, DurableStream>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Poison-recovering lock for the durable-stream registry (same discipline as the RAM registry above).
fn streams_lock() -> MutexGuard<'static, HashMap<u32, DurableStream>> {
    streams().lock().unwrap_or_else(|e| e.into_inner())
}

/// The addressable parts of one registered stream, snapshotted so the registry lock is released before
/// any store I/O or reframe callback runs.
struct StreamHandle {
    kind: String,
    framing: Framing,
    digests_scope: bool,
    reframe: JournalReframeFn,
    journal: Arc<Journal<PlaneJournalRecord>>,
}

fn stream_handle(kind_id: u32) -> Option<StreamHandle> {
    let map = streams_lock();
    map.get(&kind_id).map(|s| StreamHandle {
        kind: s.kind.clone(),
        framing: s.framing,
        digests_scope: s.digests_scope,
        reframe: s.reframe,
        journal: s.journal.clone(),
    })
}

/// Read a borrowed `(ptr, len)` range into owned bytes; a null/empty range is the empty vector.
fn read_bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 {
        Vec::new()
    } else {
        // SAFETY: a non-null `(ptr, len)` is a live borrowed range for the call (ABI discipline).
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }
}

/// Read a borrowed `(ptr, len)` range into a `String`; a null/empty range is `None` (a durable scope
/// is a non-empty key, so an empty one is a caller error the slot fails closed on).
fn read_scope(ptr: *const u8, len: usize) -> Option<String> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: a non-null `(ptr, len)` is a live borrowed range for the call (ABI discipline).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Turn one stored body + its scope back into a [`PlaneJournalRecord`] by calling the stream's
/// PLANE-PROVIDED reframe fn-pointer. The plane decodes the body and writes `(seq, prev_hash, hash,
/// pre-framed suffix, digests_scope)`; the host assembles the record with the scope IT knows (the
/// store parent) and the stream's framing. On a too-small buffer the reframe reports the required
/// lengths in [`ReframeOut`] (always initialized) and the host grows and retries.
fn call_reframe(
    host: HostCtx,
    kind_id: u32,
    reframe: JournalReframeFn,
    framing: Framing,
    scope: &str,
    body: &[u8],
) -> busbar_api::StoreResult<PlaneJournalRecord> {
    let mut prev = vec![0u8; 128];
    let mut hash = vec![0u8; 128];
    let mut suffix = vec![0u8; 512];
    loop {
        let mut out = MaybeUninit::<ReframeOut>::uninit();
        let status = reframe(
            host,
            kind_id,
            body.as_ptr(),
            body.len(),
            &mut out,
            prev.as_mut_ptr(),
            prev.len(),
            hash.as_mut_ptr(),
            hash.len(),
            suffix.as_mut_ptr(),
            suffix.len(),
        );
        // SAFETY: the reframe contract ALWAYS initializes `out` (the length-report discipline, like
        // `AdmitRefusal`), so it is readable on both `Ok` and `Refused`.
        let o = unsafe { out.assume_init() };
        match status {
            StatusClass::Ok => {
                let prev_hash =
                    String::from_utf8_lossy(&prev[..o.prev_len.min(prev.len())]).into_owned();
                let hash =
                    String::from_utf8_lossy(&hash[..o.hash_len.min(hash.len())]).into_owned();
                let content = suffix[..o.suffix_len.min(suffix.len())].to_vec();
                return Ok(PlaneJournalRecord {
                    scope: scope.to_string(),
                    seq: o.seq,
                    prev_hash,
                    hash,
                    content,
                    framing,
                    digests_scope: o.digests_scope != 0,
                });
            }
            StatusClass::Refused => {
                // Grow whichever buffer was short and retry (the `egress_poll` length-report pattern).
                let grew = (o.prev_len > prev.len())
                    || (o.hash_len > hash.len())
                    || (o.suffix_len > suffix.len());
                if !grew {
                    return Err(busbar_api::StoreError(
                        "journal reframe refused without a larger-buffer request".to_string(),
                    ));
                }
                if o.prev_len > prev.len() {
                    prev = vec![0u8; o.prev_len];
                }
                if o.hash_len > hash.len() {
                    hash = vec![0u8; o.hash_len];
                }
                if o.suffix_len > suffix.len() {
                    suffix = vec![0u8; o.suffix_len];
                }
            }
            other => {
                return Err(busbar_api::StoreError(format!(
                    "journal reframe failed: {other:?}"
                )))
            }
        }
    }
}

/// REGISTER a durable journal stream: record its neutral facts + reframe callback under `kind_id` and
/// attach the durable sink from the app's governance store (the boot rehydrate pattern; no governance
/// store ⇒ the stream is ephemeral, exactly as the shipped plane state is). Fail-closed on a null/empty
/// descriptor.
pub(crate) extern "C-unwind" fn journal_register(
    host: HostCtx,
    desc: *const JournalStreamDesc,
    reframe: JournalReframeFn,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state = unsafe { recover(host) };
        if desc.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `desc` is a live, initialized `JournalStreamDesc` for the call (ABI).
        let d = unsafe { &*desc };
        let Some(kind) = read_scope(d.kind_ptr, d.kind_len) else {
            return StatusClass::Refused;
        };
        // `usize::MAX`: a durable table opts OUT of position eviction (its working set is bounded
        // elsewhere), exactly as the A2A task journal does.
        let journal = Arc::new(Journal::<PlaneJournalRecord>::new(usize::MAX));
        if let Some(gov) = state.app.governance.as_ref() {
            journal.set_sink(PlaneStoreView::narrow(gov.store()));
        }
        let stream = DurableStream {
            kind,
            framing: map_framing(d.framing),
            digests_scope: d.digests_scope != 0,
            reframe,
            journal,
        };
        streams_lock().insert(d.kind_id, stream);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// APPEND one record to a registered stream's durable `scope`: mint the seq/prev_hash/hash through the
/// ONE core chain, frame the prelude in the stream's framing, join the plane's opaque content suffix,
/// and persist the neutral body. Returns the minted [`Seq`], or [`Seq::NONE`] fail-closed.
pub(crate) extern "C-unwind" fn journal_append_scoped(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    content_ptr: *const u8,
    content_len: usize,
) -> Seq {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        let Some(h) = stream_handle(kind_id) else {
            return Seq::NONE;
        };
        let Some(scope) = read_scope(scope_ptr, scope_len) else {
            return Seq::NONE;
        };
        let content = read_bytes(content_ptr, content_len);
        let input = PlaneJournalInput {
            content,
            framing: h.framing,
            digests_scope: h.digests_scope,
        };
        let reframe =
            |sc: &str, body: &[u8]| call_reframe(host, kind_id, h.reframe, h.framing, sc, body);
        match h.journal.append_scoped(&h.kind, &scope, input, &reframe) {
            Ok(record) => Seq(record.seq()),
            Err(_) => Seq::NONE,
        }
    }))
    .unwrap_or(Seq::NONE)
}

/// READ a registered stream's `scope` window (durable cold read) into the caller buffer; sets
/// `out_written`. Fail-closed on a null query/out; a too-small buffer is `Refused` with the required
/// length reported.
pub(crate) extern "C-unwind" fn journal_read_scoped(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    from_seq: u64,
    limit: u64,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        if out_written.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `out_written` is a live, writable `usize` for the call (ABI). Default to 0.
        unsafe { *out_written = 0 };
        let Some(h) = stream_handle(kind_id) else {
            return StatusClass::Refused;
        };
        let Some(scope) = read_scope(scope_ptr, scope_len) else {
            return StatusClass::Refused;
        };
        let Some(store) = h.journal.sink() else {
            // No durable sink → a legitimate empty read.
            return StatusClass::Ok;
        };
        let reframe =
            |sc: &str, body: &[u8]| call_reframe(host, kind_id, h.reframe, h.framing, sc, body);
        let rows = match h
            .journal
            .read_scoped(&h.kind, &scope, store.as_ref(), &reframe)
        {
            Ok(r) => r,
            Err(_) => return StatusClass::Fault,
        };
        // Verify before trusting the stored chain (mirrors the RAM `journal_read`).
        if crate::audit::verify_chain(&rows).is_err() {
            return StatusClass::Fault;
        }
        let encoded = encode_rows(&rows, from_seq, limit);
        if encoded.len() > buf_cap {
            // SAFETY: see above — report the required length so the caller can size a retry.
            unsafe { *out_written = encoded.len() };
            return StatusClass::Refused;
        }
        if !buf.is_null() && !encoded.is_empty() {
            // SAFETY: `encoded.len() <= buf_cap` and `buf` is a live range of `buf_cap` bytes (ABI).
            unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), buf, encoded.len()) };
        }
        // SAFETY: see above.
        unsafe { *out_written = encoded.len() };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// BOOT REHYDRATE a registered stream from the durable store: resume every scope's position and write
/// the neutral [`RestoredHdr`] counts. No durable sink ⇒ honest zeros.
pub(crate) extern "C-unwind" fn journal_restore(
    host: HostCtx,
    kind_id: u32,
    out: *mut MaybeUninit<RestoredHdr>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        if out.is_null() {
            return StatusClass::Refused;
        }
        let Some(h) = stream_handle(kind_id) else {
            return StatusClass::Refused;
        };
        let reframe =
            |sc: &str, body: &[u8]| call_reframe(host, kind_id, h.reframe, h.framing, sc, body);
        let restored = match h.journal.sink() {
            Some(store) => match h.journal.restore_scoped(&h.kind, store.as_ref(), &reframe) {
                Ok(r) => r,
                Err(_) => return StatusClass::Fault,
            },
            None => crate::audit::journal::Restored::default(),
        };
        let hdr = RestoredHdr {
            size: core::mem::size_of::<RestoredHdr>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scopes: restored.scopes as u64,
            records: restored.records as u64,
            empty_scopes: restored.empty_scopes.len() as u64,
            chain_breaks: restored.chain_breaks.len() as u64,
        };
        // SAFETY: non-null `out` is a writable `MaybeUninit<RestoredHdr>`; write only on the Ok path.
        unsafe { (*out).write(hdr) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// SEED one scope's position from a packed set of already-read stored bodies (`u32` count LE, then per
/// body `u32` len LE + bytes) — the caller-driven rehydrate. Writes a [`ChainBreakHdr`] reporting a
/// broken-but-resumed chain (or a clean verify).
pub(crate) extern "C-unwind" fn journal_seed(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    bodies_ptr: *const u8,
    bodies_len: usize,
    out: *mut MaybeUninit<ChainBreakHdr>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        if out.is_null() {
            return StatusClass::Refused;
        }
        let Some(h) = stream_handle(kind_id) else {
            return StatusClass::Refused;
        };
        let Some(scope) = read_scope(scope_ptr, scope_len) else {
            return StatusClass::Refused;
        };
        let packed = read_bytes(bodies_ptr, bodies_len);
        let Some(bodies) = unpack_bodies(&packed) else {
            return StatusClass::Refused;
        };
        let mut records = Vec::with_capacity(bodies.len());
        for body in &bodies {
            match call_reframe(host, kind_id, h.reframe, h.framing, &scope, body) {
                Ok(r) => records.push(r),
                Err(_) => return StatusClass::Fault,
            }
        }
        let brk = h.journal.seed_position(&scope, &records);
        let hdr = match brk {
            Some(b) => ChainBreakHdr {
                size: core::mem::size_of::<ChainBreakHdr>() as u32,
                version: POD_VERSION,
                broke: 1,
                _reserved: 0,
                _reserved2: 0,
                at_index: b.at_index as u64,
                seq: b.seq,
            },
            None => ChainBreakHdr {
                size: core::mem::size_of::<ChainBreakHdr>() as u32,
                version: POD_VERSION,
                broke: 0,
                _reserved: 0,
                _reserved2: 0,
                at_index: 0,
                seq: 0,
            },
        };
        // SAFETY: non-null `out` is a writable `MaybeUninit<ChainBreakHdr>`; write only on Ok.
        unsafe { (*out).write(hdr) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// FORGET one scope's cached position (a terminal unit evicted from the working set). The durable rows
/// stay in the store.
pub(crate) extern "C-unwind" fn journal_forget(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        let Some(h) = stream_handle(kind_id) else {
            return StatusClass::Refused;
        };
        let Some(scope) = read_scope(scope_ptr, scope_len) else {
            return StatusClass::Refused;
        };
        h.journal.forget(&scope);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// RETENTION: drop a registered stream's durable rows older than `before`, writing the count removed.
pub(crate) extern "C-unwind" fn journal_compact(
    host: HostCtx,
    kind_id: u32,
    before: u64,
    out_removed: *mut u64,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        if out_removed.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `out_removed` is a live, writable `u64` for the call (ABI). Default to 0.
        unsafe { *out_removed = 0 };
        let Some(h) = stream_handle(kind_id) else {
            return StatusClass::Refused;
        };
        match h.journal.compact_scoped(&h.kind, before) {
            Ok(n) => {
                // SAFETY: see above.
                unsafe { *out_removed = n };
                StatusClass::Ok
            }
            Err(_) => StatusClass::Fault,
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// VERIFY one scope's persisted chain (reframed), writing a [`VerifyChainHdr`]. A tamper is REPORTED
/// (not a fault); an unknown/empty scope verifies vacuously.
pub(crate) extern "C-unwind" fn journal_verify_scoped(
    host: HostCtx,
    kind_id: u32,
    scope_ptr: *const u8,
    scope_len: usize,
    out: *mut MaybeUninit<VerifyChainHdr>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        if out.is_null() {
            return StatusClass::Refused;
        }
        let Some(h) = stream_handle(kind_id) else {
            return StatusClass::Refused;
        };
        let Some(scope) = read_scope(scope_ptr, scope_len) else {
            return StatusClass::Refused;
        };
        let reframe =
            |sc: &str, body: &[u8]| call_reframe(host, kind_id, h.reframe, h.framing, sc, body);
        let brk = match h.journal.sink() {
            Some(store) => match h
                .journal
                .verify_scoped(&h.kind, &scope, store.as_ref(), &reframe)
            {
                Ok(b) => b,
                Err(_) => return StatusClass::Fault,
            },
            None => None,
        };
        let hdr = match brk {
            Some(b) => VerifyChainHdr {
                size: core::mem::size_of::<VerifyChainHdr>() as u32,
                version: POD_VERSION,
                verified: 0,
                _reserved: 0,
                _reserved2: 0,
                at_index: b.at_index as u64,
                seq: b.seq,
            },
            None => VerifyChainHdr {
                size: core::mem::size_of::<VerifyChainHdr>() as u32,
                version: POD_VERSION,
                verified: 1,
                _reserved: 0,
                _reserved2: 0,
                at_index: 0,
                seq: 0,
            },
        };
        // SAFETY: non-null `out` is a writable `MaybeUninit<VerifyChainHdr>`; write only on Ok.
        unsafe { (*out).write(hdr) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Unpack the packed body set a [`journal_seed`] carries: `u32` count LE, then per body a `u32` length
/// LE + that many bytes. Returns `None` on a truncated/oversized blob (fail-closed).
fn unpack_bodies(packed: &[u8]) -> Option<Vec<Vec<u8>>> {
    if packed.len() < 4 {
        return Some(Vec::new());
    }
    let count = u32::from_le_bytes(packed[0..4].try_into().ok()?) as usize;
    let mut off = 4;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        if off + 4 > packed.len() {
            return None;
        }
        let len = u32::from_le_bytes(packed[off..off + 4].try_into().ok()?) as usize;
        off += 4;
        if off + len > packed.len() {
            return None;
        }
        out.push(packed[off..off + len].to_vec());
        off += len;
    }
    Some(out)
}

/// One scope's live position + its appended rows. The `Chain` is the seq authority (identical to the
/// three shipped streams); `rows` is the store stand-in this Phase-2 bridge holds in-process.
struct ScopeState {
    chain: Chain<PlaneJournalRecord>,
    rows: Vec<PlaneJournalRecord>,
}

/// The process-local per-scope registry. Durable-store cleave point: this map (position cache + rows)
/// would become the generic scope-keyed Journal over an `Arc<dyn PlaneStore>`.
fn journals() -> &'static Mutex<HashMap<u32, ScopeState>> {
    static J: OnceLock<Mutex<HashMap<u32, ScopeState>>> = OnceLock::new();
    J.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Poison-recovering lock: a panic mid-append must not wedge the registry (same discipline as the
/// dispatch arena).
fn lock() -> std::sync::MutexGuard<'static, HashMap<u32, ScopeState>> {
    journals().lock().unwrap_or_else(|e| e.into_inner())
}

fn map_framing(f: AbiFraming) -> Framing {
    match f {
        AbiFraming::LengthPrefixed => Framing::LengthPrefixed,
        AbiFraming::PipeSeparated => Framing::PipeSeparated,
    }
}

/// WIRED `journal_append` → [`crate::audit::Chain::append`] for the scope. Frames the prelude in the
/// [`FramingDesc`]'s framing, joins the plane's pre-framed content suffix, and appends to the real
/// chain, returning the assigned [`Seq`]. Fail-closed: any panic / null POD → [`Seq::NONE`] (the
/// reserved invalid handle), never a fabricated sequence.
pub(crate) extern "C-unwind" fn journal_append(
    host: HostCtx,
    scope: u32,
    content_ptr: *const u8,
    content_len: usize,
    framing: *const FramingDesc,
) -> Seq {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`). The state is recovered even though this
        // slot draws the chain from the process registry, keeping the boundary discipline uniform.
        let _state = unsafe { recover(host) };
        if framing.is_null() {
            return Seq::NONE;
        }
        // SAFETY: a non-null `framing` is a live, initialized `FramingDesc` for the call (ABI).
        let fd = unsafe { &*framing };
        let content: Vec<u8> = if content_ptr.is_null() || content_len == 0 {
            Vec::new()
        } else {
            // SAFETY: `(content_ptr, content_len)` is a live borrowed range for the call (ABI).
            unsafe { std::slice::from_raw_parts(content_ptr, content_len) }.to_vec()
        };
        let input = PlaneJournalInput {
            content,
            framing: map_framing(fd.framing),
            digests_scope: fd.digests_scope != 0,
        };
        let scope_str = scope.to_string();

        let mut map = lock();
        let st = map.entry(scope).or_insert_with(|| ScopeState {
            chain: Chain::new(),
            rows: Vec::new(),
        });
        // Durable-store cleave point: a store-backed Journal would advance the RAM position only AFTER
        // a durable write ok. Here (no durable store yet) append == commit; the seq authority is
        // already the real `Chain`.
        let record = st.chain.append(&scope_str, input);
        let seq = record.seq();
        st.rows.push(record);
        Seq(seq)
    }))
    .unwrap_or(Seq::NONE) // fail-closed: a panicked append yields no sequence.
}

/// WIRED `journal_read` → the real audit read path: [`crate::audit::verify_chain`] over the stored
/// rows, then the requested window encoded into the caller buffer. Fail-closed: a panic → `Fault`, a
/// tamper-detected chain → `Fault`, a null query/out → `Refused`, a too-small buffer → `Refused` with
/// the required length reported in `out_written`.
pub(crate) extern "C-unwind" fn journal_read(
    host: HostCtx,
    query: *const JournalQuery,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        if query.is_null() || out_written.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `query` is a live, initialized `JournalQuery` for the call (ABI).
        let q = unsafe { &*query };
        // SAFETY: `out_written` is a live, writable `usize` for the call (ABI). Default to 0.
        unsafe { *out_written = 0 };

        let map = lock();
        let Some(st) = map.get(&q.scope) else {
            // An unknown scope has no rows; that is a legitimate empty read, not a fault.
            return StatusClass::Ok;
        };
        // The real audit read path VERIFIES the stored chain before it is trusted — a tamper is
        // surfaced as a fault rather than silently handed back (mirrors `Chain::from_persisted`).
        if crate::audit::verify_chain(&st.rows).is_err() {
            return StatusClass::Fault;
        }
        // Durable-store cleave point: a store-backed Journal would make this window read a range scan.
        let encoded = encode_rows(&st.rows, q.from_seq, q.limit);
        if encoded.len() > buf_cap {
            // SAFETY: see above — report the required length so the caller can size a retry.
            unsafe { *out_written = encoded.len() };
            return StatusClass::Refused;
        }
        if !buf.is_null() && !encoded.is_empty() {
            // SAFETY: `encoded.len() <= buf_cap` and `buf` is a live range of `buf_cap` bytes (ABI).
            unsafe { std::ptr::copy_nonoverlapping(encoded.as_ptr(), buf, encoded.len()) };
        }
        // SAFETY: see above.
        unsafe { *out_written = encoded.len() };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault) // caught panic → the distinct fault class, never `Ok`.
}

/// Encode the rows whose `seq >= from_seq` (up to `limit`, `0` = all) into a self-describing blob:
/// `count:u32-le`, then per row `seq:u64-le · prev_hash · hash · content`, each variable field as
/// `len:u32-le ⧺ bytes`. A neutral bytes-tier shape (the cold read carries bytes, not typed rows).
fn encode_rows(rows: &[PlaneJournalRecord], from_seq: u64, limit: u64) -> Vec<u8> {
    let take = if limit == 0 {
        usize::MAX
    } else {
        limit as usize
    };
    let selected: Vec<&PlaneJournalRecord> = rows
        .iter()
        .filter(|r| r.seq >= from_seq)
        .take(take)
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&(selected.len() as u32).to_le_bytes());
    let field = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    };
    for r in selected {
        out.extend_from_slice(&r.seq.to_le_bytes());
        field(&mut out, r.prev_hash.as_bytes());
        field(&mut out, r.hash.as_bytes());
        field(&mut out, &r.content);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plane_host::{recover, with_dispatch_scope, HostState};
    use busbar_plugin::hot::host::PlaneHostVtable;
    use busbar_plugin::hot::POD_VERSION;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A distinct scope per test run so the process-global registry never collides across parallel
    /// tests (each test owns a fresh chain).
    static NEXT_SCOPE: AtomicU32 = AtomicU32::new(1);
    fn fresh_scope() -> u32 {
        NEXT_SCOPE.fetch_add(1, Ordering::SeqCst)
    }

    fn framing_desc(framing: AbiFraming, digests_scope: u8) -> FramingDesc {
        FramingDesc {
            size: core::mem::size_of::<FramingDesc>() as u32,
            version: POD_VERSION,
            framing,
            digests_scope,
        }
    }

    fn query(scope: u32) -> JournalQuery {
        JournalQuery {
            size: core::mem::size_of::<JournalQuery>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            scope,
            _reserved2: 0,
            from_seq: 0,
            limit: 0,
        }
    }

    fn with_test_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let app = crate::test_support::TestApp::new().build();
        with_dispatch_scope(&app, |host, vt| {
            // SAFETY: live HostState minted by `with_dispatch_scope`.
            let _state: &HostState = unsafe { recover(host) };
            f(host, vt)
        })
    }

    /// The task's gate: append two records to a scope via the VTABLE, then the REAL `verify_chain`
    /// passes on the result and the second record's `prev_hash` byte-exactly links the first.
    fn append_two_and_verify(framing: AbiFraming, digests_scope: u8) {
        let scope = fresh_scope();
        let fd = framing_desc(framing, digests_scope);
        with_test_state(|host, vt| {
            let append = vt.journal_append.unwrap();
            let c1 = b"|ts1|first"; // Option A: leading `|` is inert under LengthPrefixed, load-bearing under PipeSeparated
            let c2 = b"|ts2|second";
            let s1 = append(
                host,
                scope,
                c1.as_ptr(),
                c1.len(),
                &fd as *const FramingDesc,
            );
            let s2 = append(
                host,
                scope,
                c2.as_ptr(),
                c2.len(),
                &fd as *const FramingDesc,
            );
            assert_eq!(s1, Seq(1), "genesis record is seq 1");
            assert_eq!(s2, Seq(2), "second record is seq 2");
        });

        // Read the rows back through the real audit chain: verify_chain must pass, and the link must
        // be byte-exact (record 2's prev_hash == record 1's hash, record 1's prev_hash empty).
        let map = lock();
        let st = map.get(&scope).expect("scope has rows");
        assert!(
            crate::audit::verify_chain(&st.rows).is_ok(),
            "the appended chain must verify byte-identically"
        );
        assert_eq!(st.rows.len(), 2);
        assert_eq!(st.rows[0].prev_hash(), "", "genesis prev_hash is empty");
        assert!(!st.rows[0].hash().is_empty());
        assert_eq!(
            st.rows[1].prev_hash(),
            st.rows[0].hash(),
            "record 2 links record 1 byte-exactly"
        );
    }

    #[test]
    fn append_two_verifies_length_prefixed_with_scope() {
        append_two_and_verify(AbiFraming::LengthPrefixed, 1);
    }

    #[test]
    fn append_two_verifies_pipe_separated_with_scope() {
        // The PipeSeparated landmine: the leading `|` in the suffix + the always-first empty/nonempty
        // prev_hash must reproduce the legacy join. verify_chain re-runs the SAME digest, so a missing
        // `|` at the join would surface here as DigestMismatch.
        append_two_and_verify(AbiFraming::PipeSeparated, 1);
    }

    #[test]
    fn append_two_verifies_pipe_separated_no_scope() {
        // admin-style: digests_scope = 0 — scope must NOT enter the digest.
        append_two_and_verify(AbiFraming::PipeSeparated, 0);
    }

    /// The digest is byte-exact against a hand-built `frame_prelude ⧺ content` recompute — this
    /// localizes any failure to the reframe rather than the whole chain walk.
    #[test]
    fn genesis_digest_matches_hand_built_prelude_join() {
        let scope = fresh_scope();
        let fd = framing_desc(AbiFraming::PipeSeparated, 1);
        with_test_state(|host, vt| {
            let content = b"|ts|kind|state";
            let seq = (vt.journal_append.unwrap())(
                host,
                scope,
                content.as_ptr(),
                content.len(),
                &fd as *const FramingDesc,
            );
            assert_eq!(seq, Seq(1));
        });
        let map = lock();
        let st = map.get(&scope).unwrap();
        let mut expected_input =
            frame_prelude(Framing::PipeSeparated, "", Some(&scope.to_string()), 1);
        expected_input.extend_from_slice(b"|ts|kind|state");
        let expected = busbar_api::sha256_hex(&expected_input);
        assert_eq!(
            st.rows[0].hash(),
            expected,
            "genesis hash == sha256(prelude ⧺ suffix)"
        );
    }

    #[test]
    fn journal_read_returns_ok_and_writes_bytes() {
        let scope = fresh_scope();
        let fd = framing_desc(AbiFraming::LengthPrefixed, 1);
        let q = query(scope);
        with_test_state(|host, vt| {
            let c = b"payload";
            (vt.journal_append.unwrap())(
                host,
                scope,
                c.as_ptr(),
                c.len(),
                &fd as *const FramingDesc,
            );

            let mut out_written: usize = 0;
            let read = vt.journal_read.unwrap();
            // Undersized buffer: Refused, required length reported.
            let mut tiny = [0u8; 1];
            let s = read(
                host,
                &q as *const JournalQuery,
                tiny.as_mut_ptr(),
                tiny.len(),
                &mut out_written as *mut usize,
            );
            assert_eq!(s, StatusClass::Refused);
            assert!(out_written > tiny.len(), "reports the required size");

            let needed = out_written;
            let mut big = vec![0u8; needed];
            let s = read(
                host,
                &q as *const JournalQuery,
                big.as_mut_ptr(),
                big.len(),
                &mut out_written as *mut usize,
            );
            assert_eq!(s, StatusClass::Ok);
            assert_eq!(out_written, needed);
            // First 4 bytes are the row count = 1.
            assert_eq!(u32::from_le_bytes(big[0..4].try_into().unwrap()), 1);
        });
    }

    // ── THE DURABLE SEAM — register + append_scoped + verify/read/restore over a real store ────────

    use crate::audit::journal::NeutralBody;
    use busbar_plugin::hot::{JournalStreamDesc, ReframeOut, RestoredHdr, VerifyChainHdr};
    use std::sync::Arc;

    static NEXT_KIND_ID: AtomicU32 = AtomicU32::new(1);
    fn fresh_kind_id() -> u32 {
        NEXT_KIND_ID.fetch_add(1, Ordering::SeqCst)
    }

    /// A test PLANE reframe: decode the journal's own neutral `{seq, prev_hash, hash, content}` body
    /// back into a record's chain fields (the durable path's decode bridge for CORE-written bodies).
    /// This stream digests its scope, so it reports `digests_scope = 1`. Always initializes `out`.
    extern "C-unwind" fn neutral_reframe(
        _host: HostCtx,
        _kind_id: u32,
        body_ptr: *const u8,
        body_len: usize,
        out: *mut MaybeUninit<ReframeOut>,
        prev_buf: *mut u8,
        prev_cap: usize,
        hash_buf: *mut u8,
        hash_cap: usize,
        suffix_buf: *mut u8,
        suffix_cap: usize,
    ) -> StatusClass {
        // SAFETY: a live borrowed body range for the call (ABI).
        let body = unsafe { std::slice::from_raw_parts(body_ptr, body_len) };
        let nb: NeutralBody = serde_json::from_slice(body).expect("neutral body decodes");
        let prev = nb.prev_hash.as_bytes();
        let hash = nb.hash.as_bytes();
        let suffix = &nb.content;
        let o = ReframeOut {
            size: core::mem::size_of::<ReframeOut>() as u32,
            version: POD_VERSION,
            digests_scope: 1,
            _r: 0,
            seq: nb.seq,
            prev_len: prev.len(),
            hash_len: hash.len(),
            suffix_len: suffix.len(),
        };
        // SAFETY: `out` is a live, writable slot; always initialized (the length-report discipline).
        unsafe { (*out).write(o) };
        if prev.len() > prev_cap || hash.len() > hash_cap || suffix.len() > suffix_cap {
            return StatusClass::Refused;
        }
        // SAFETY: each destination has cap >= the source length (checked above); ranges are live.
        unsafe {
            std::ptr::copy_nonoverlapping(prev.as_ptr(), prev_buf, prev.len());
            std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, hash.len());
            std::ptr::copy_nonoverlapping(suffix.as_ptr(), suffix_buf, suffix.len());
        }
        StatusClass::Ok
    }

    /// A generic PERSISTING `Store` double: the shipped `busbar_store_memory` keeps NO plane records
    /// (the lossy RAM default), so this delegates the required key/usage/metering surface to a real
    /// memory store (so `GovState::new` sees genuine governance behaviour) and PERSISTS the neutral
    /// plane-record verbs generically by `(kind, parent)` — exactly what a durable backend does.
    struct GenericPlaneStore {
        inner: busbar_store_memory::MemoryStore,
        rows: Mutex<Vec<busbar_api::PlaneRecord>>,
    }

    impl GenericPlaneStore {
        fn new() -> Self {
            Self {
                inner: busbar_store_memory::MemoryStore::new(),
                rows: Mutex::new(Vec::new()),
            }
        }
        fn rows(&self) -> std::sync::MutexGuard<'_, Vec<busbar_api::PlaneRecord>> {
            self.rows.lock().unwrap_or_else(|e| e.into_inner())
        }
    }

    impl busbar_api::Store for GenericPlaneStore {
        fn put_key(&self, key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            self.inner.put_key(key)
        }
        fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            self.inner.get_key(id)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            self.inner.list_keys()
        }
        fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
            self.inner.delete_key(id)
        }
        fn get_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
        ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            self.inner.get_usage(bucket_id, window_start)
        }
        fn put_usage(
            &self,
            bucket_id: &str,
            window_start: u64,
            ledger: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            self.inner.put_usage(bucket_id, window_start, ledger)
        }
        fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            self.inner.add_metering(delta)
        }
        fn list_metering(
            &self,
            bucket: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            self.inner.list_metering(bucket)
        }
        // ── The neutral kind-tagged verbs — the durable half this double actually keeps ─────────────
        fn append_plane_record(
            &self,
            record: &busbar_api::PlaneRecord,
        ) -> busbar_api::StoreResult<()> {
            self.rows().push(record.clone());
            Ok(())
        }
        fn upsert_plane_record(
            &self,
            record: &busbar_api::PlaneRecord,
        ) -> busbar_api::StoreResult<()> {
            self.rows().push(record.clone());
            Ok(())
        }
        fn list_plane_records(
            &self,
            kind: &str,
            selector: &busbar_api::PlaneSelector,
        ) -> busbar_api::StoreResult<Vec<Vec<u8>>> {
            Ok(self
                .rows()
                .iter()
                .filter(|r| r.kind == kind)
                .filter(|r| match selector {
                    busbar_api::PlaneSelector::All => true,
                    busbar_api::PlaneSelector::Parent(p) => r.parent.as_deref() == Some(p.as_str()),
                })
                .map(|r| r.body.clone())
                .collect())
        }
        fn list_plane_record_parents(&self, kind: &str) -> busbar_api::StoreResult<Vec<String>> {
            let mut parents: Vec<String> = self
                .rows()
                .iter()
                .filter(|r| r.kind == kind)
                .filter_map(|r| r.parent.clone())
                .collect();
            parents.sort();
            parents.dedup();
            Ok(parents)
        }
    }

    fn durable_app() -> Arc<crate::state::App> {
        durable_app_over(Arc::new(GenericPlaneStore::new()))
    }

    fn durable_app_over(store: Arc<GenericPlaneStore>) -> Arc<crate::state::App> {
        let gov = Arc::new(
            crate::governance::GovState::new(store, None).expect("governance store constructs"),
        );
        crate::test_support::TestApp::new().governance(gov).build()
    }

    fn register(host: HostCtx, vt: &PlaneHostVtable, kind_id: u32, framing: AbiFraming) {
        let kind = b"durable_test_event";
        let desc = JournalStreamDesc {
            size: core::mem::size_of::<JournalStreamDesc>() as u32,
            version: POD_VERSION,
            framing,
            digests_scope: 1,
            kind_id,
            _reserved: 0,
            kind_ptr: kind.as_ptr(),
            kind_len: kind.len(),
        };
        assert_eq!(
            (vt.journal_register.unwrap())(
                host,
                &desc as *const JournalStreamDesc,
                neutral_reframe
            ),
            StatusClass::Ok
        );
    }

    /// The durable analogue of `append_two_and_verify`: register a store-backed stream, append two
    /// records via `journal_append_scoped` (each PERSISTED to the store as a neutral body), then the
    /// durable `journal_verify_scoped` reframes them back and the REAL `verify_chain` passes; a
    /// `journal_restore` counts both records and one scope; a `journal_read_scoped` yields the rows.
    fn durable_append_two_and_verify(framing: AbiFraming) {
        let app = durable_app();
        let kind_id = fresh_kind_id();
        let scope = b"task-1";
        with_dispatch_scope(&app, |host, vt| {
            register(host, vt, kind_id, framing);

            let c1 = b"|ts1|first"; // Option A leading `|` (load-bearing under PipeSeparated)
            let c2 = b"|ts2|second";
            let s1 = (vt.journal_append_scoped.unwrap())(
                host,
                kind_id,
                scope.as_ptr(),
                scope.len(),
                c1.as_ptr(),
                c1.len(),
            );
            let s2 = (vt.journal_append_scoped.unwrap())(
                host,
                kind_id,
                scope.as_ptr(),
                scope.len(),
                c2.as_ptr(),
                c2.len(),
            );
            assert_eq!(s1, Seq(1), "genesis record is seq 1");
            assert_eq!(s2, Seq(2), "second record is seq 2");

            // VERIFY: reframes the persisted neutral bodies and runs the real verifier.
            let mut vout = MaybeUninit::<VerifyChainHdr>::uninit();
            assert_eq!(
                (vt.journal_verify_scoped.unwrap())(
                    host,
                    kind_id,
                    scope.as_ptr(),
                    scope.len(),
                    &mut vout as *mut MaybeUninit<VerifyChainHdr>,
                ),
                StatusClass::Ok
            );
            // SAFETY: Ok published the slot.
            let vhdr = unsafe { vout.assume_init() };
            assert_eq!(
                vhdr.verified, 1,
                "the persisted durable chain verifies byte-identically"
            );

            // RESTORE: counts both durable records under the one scope, zero breaks.
            let mut rout = MaybeUninit::<RestoredHdr>::uninit();
            assert_eq!(
                (vt.journal_restore.unwrap())(
                    host,
                    kind_id,
                    &mut rout as *mut MaybeUninit<RestoredHdr>,
                ),
                StatusClass::Ok
            );
            // SAFETY: Ok published the slot.
            let rhdr = unsafe { rout.assume_init() };
            assert_eq!(rhdr.records, 2, "both records were durable");
            assert_eq!(rhdr.scopes, 1);
            assert_eq!(rhdr.chain_breaks, 0);

            // READ the window back: the encoded blob's row count is 2.
            let mut written: usize = 0;
            let s = (vt.journal_read_scoped.unwrap())(
                host,
                kind_id,
                scope.as_ptr(),
                scope.len(),
                0,
                0,
                std::ptr::null_mut(),
                0,
                &mut written as *mut usize,
            );
            assert_eq!(
                s,
                StatusClass::Refused,
                "a zero buffer reports the required size"
            );
            let mut big = vec![0u8; written];
            let s = (vt.journal_read_scoped.unwrap())(
                host,
                kind_id,
                scope.as_ptr(),
                scope.len(),
                0,
                0,
                big.as_mut_ptr(),
                big.len(),
                &mut written as *mut usize,
            );
            assert_eq!(s, StatusClass::Ok);
            assert_eq!(
                u32::from_le_bytes(big[0..4].try_into().unwrap()),
                2,
                "two rows read back"
            );
        });
    }

    #[test]
    fn durable_append_two_and_verify_length_prefixed() {
        durable_append_two_and_verify(AbiFraming::LengthPrefixed);
    }

    #[test]
    fn durable_append_two_and_verify_pipe_separated() {
        // The PipeSeparated genesis landmine, now through the DURABLE store round-trip.
        durable_append_two_and_verify(AbiFraming::PipeSeparated);
    }

    /// An unregistered `kind_id` fails closed on every scoped op, never fabricating a sequence.
    #[test]
    fn durable_unregistered_kind_fails_closed() {
        let app = durable_app();
        let scope = b"nope";
        with_dispatch_scope(&app, |host, vt| {
            let s = (vt.journal_append_scoped.unwrap())(
                host,
                9_999_001,
                scope.as_ptr(),
                scope.len(),
                scope.as_ptr(),
                scope.len(),
            );
            assert_eq!(s, Seq::NONE, "an unregistered stream mints no sequence");
        });
    }

    // ── THE CHAIN-COMPAT GOLDEN (minor-9) — frozen PRE-CHANGE bodies through the DURABLE seam ──────
    //
    // The SECOND, independent tripwire beside `audit::boot_verify_golden`. Those same frozen
    // `serde_json` bodies a store held before the cleave are fed through the NEW durable seam
    // (`journal_register` + `journal_restore` + `journal_verify_scoped`), reframed PLANE-SIDE back into
    // records, and the host's ONE verifier RECOMPUTES each digest from the reframed prelude ⧺ suffix.
    // If that recompute no longer equals the frozen `hash`, restore reports a chain break and verify
    // fails — RED before a single deployed store does. The frozen bytes are DUPLICATED from
    // `boot_verify_golden.rs` on purpose: two independent tripwires, so a slip in one is caught by the
    // other. DO NOT regenerate these bytes to make a failing test pass.

    const G_MCP_1: &[u8] = br#"{"principal":"vk_alice","seq":1,"ts":1700000000,"server":"srv","tool":"srv_tool","outcome":"dispatched","reason":"","tool_digest":"abc123","pin_generation":7,"request_id":"req-1","prev_hash":"","hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718"}"#;
    const G_MCP_2: &[u8] = br#"{"principal":"vk_alice","seq":2,"ts":1700000060,"server":"srv","tool":"srv_other","outcome":"refused","reason":"not_granted","tool_digest":"","pin_generation":7,"request_id":"req-2","prev_hash":"f1e8c2ec47e8199499663f3e08272d67b96ed4d56bddc8fa9e9371352e5ba718","hash":"721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a"}"#;
    const G_A2A_1: &[u8] = br#"{"task_id":"task-1","seq":1,"ts":1700000000,"kind":"task.submitted","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"submitted","request_id":"req-1","prev_hash":"","hash":"1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1"}"#;
    const G_A2A_2: &[u8] = br#"{"task_id":"task-1","seq":2,"ts":1700000060,"kind":"task.working","context_id":"ctx-1","principal":"vk_alice","agent_id":"planner","state":"working","request_id":"req-2","prev_hash":"1b293d0202f52529b9ae75292c5638675a4ed2ab59e57db5b0f26016a7ef22e1","hash":"6059096fd763aa3293489637e995f70ca396752aa2313d7d4a05105883fe7e19"}"#;
    const G_AD_1: &[u8] = br#"{"seq":1,"ts":1700000000,"action":"hook.register","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"","hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa"}"#;
    const G_AD_2: &[u8] = br#"{"seq":2,"ts":1700000060,"action":"hook.delete","resource":"hook:compress","outcome":"applied","principal":"admin","prev_hash":"52258f59f0ccf11e717462b0cbd040e6bfa7f576624c77a9e332e483553f56aa","hash":"33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264"}"#;

    const G_MCP_TAIL: &str = "721c70456695c90b0085e3ef0170d413a6fa3a1e0ebb65eb02730ab6597ef47a";
    const G_A2A_TAIL: &str = "6059096fd763aa3293489637e995f70ca396752aa2313d7d4a05105883fe7e19";
    const G_AD_TAIL: &str = "33a3906258375ea69278797ddd446d4f2d3f24e91eee181e1f26e0fef19a5264";

    /// When true, the reframe DROPS the leading `|` of the pre-framed suffix — the exact PipeSeparated
    /// genesis-landmine perturbation, which makes the golden below report a chain break. Left `false`
    /// in the shipped tree; set true locally to confirm the golden is a live tripwire, not a decoration.
    const DROP_SEPARATOR: bool = false;

    // Mirrors the FFI `JournalReframeFn` buffer-out signature verbatim, so the arg count is fixed by the ABI.
    #[allow(clippy::too_many_arguments)]
    fn write_reframe(
        out: *mut MaybeUninit<ReframeOut>,
        seq: u64,
        digests_scope: u8,
        prev: &[u8],
        hash: &[u8],
        suffix: &[u8],
        prev_buf: *mut u8,
        prev_cap: usize,
        hash_buf: *mut u8,
        hash_cap: usize,
        suffix_buf: *mut u8,
        suffix_cap: usize,
    ) -> StatusClass {
        let o = ReframeOut {
            size: core::mem::size_of::<ReframeOut>() as u32,
            version: POD_VERSION,
            digests_scope,
            _r: 0,
            seq,
            prev_len: prev.len(),
            hash_len: hash.len(),
            suffix_len: suffix.len(),
        };
        // SAFETY: `out` is a live writable slot; always initialized (the length-report discipline).
        unsafe { (*out).write(o) };
        if prev.len() > prev_cap || hash.len() > hash_cap || suffix.len() > suffix_cap {
            return StatusClass::Refused;
        }
        // SAFETY: each destination cap >= source length (checked above); ranges are live for the call.
        unsafe {
            std::ptr::copy_nonoverlapping(prev.as_ptr(), prev_buf, prev.len());
            std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, hash.len());
            std::ptr::copy_nonoverlapping(suffix.as_ptr(), suffix_buf, suffix.len());
        }
        StatusClass::Ok
    }

    /// A2A plane reframe: decode the legacy `TaskEventRow` and emit the PipeSeparated suffix (Option A
    /// leading `|`), scope-in-digest. `frame_prelude(prev_hash, task_id, seq) ⧺ suffix` == the legacy
    /// `TaskEventRow::digest_fields` byte stream.
    extern "C-unwind" fn a2a_reframe(
        _host: HostCtx,
        _kind_id: u32,
        body_ptr: *const u8,
        body_len: usize,
        out: *mut MaybeUninit<ReframeOut>,
        prev_buf: *mut u8,
        prev_cap: usize,
        hash_buf: *mut u8,
        hash_cap: usize,
        suffix_buf: *mut u8,
        suffix_cap: usize,
    ) -> StatusClass {
        // SAFETY: live borrowed body range (ABI).
        let body = unsafe { std::slice::from_raw_parts(body_ptr, body_len) };
        let r: busbar_api::TaskEventRow =
            serde_json::from_slice(body).expect("TaskEventRow decodes");
        let lead = if DROP_SEPARATOR { "" } else { "|" };
        let suffix = format!(
            "{lead}{}|{}|{}|{}|{}|{}",
            r.ts, r.kind, r.context_id, r.principal, r.agent_id, r.state
        );
        write_reframe(
            out,
            r.seq,
            1,
            r.prev_hash.as_bytes(),
            r.hash.as_bytes(),
            suffix.as_bytes(),
            prev_buf,
            prev_cap,
            hash_buf,
            hash_cap,
            suffix_buf,
            suffix_cap,
        )
    }

    /// MCP plane reframe: decode the legacy `McpCallRecord` and emit the LengthPrefixed suffix
    /// (every field self-delimits: `u64` big-endian length + bytes; a num is its 8-byte big-endian
    /// form). `frame_prelude(prev_hash, principal, seq) ⧺ suffix` == `McpCallRecord::digest_fields`.
    extern "C-unwind" fn mcp_reframe(
        _host: HostCtx,
        _kind_id: u32,
        body_ptr: *const u8,
        body_len: usize,
        out: *mut MaybeUninit<ReframeOut>,
        prev_buf: *mut u8,
        prev_cap: usize,
        hash_buf: *mut u8,
        hash_cap: usize,
        suffix_buf: *mut u8,
        suffix_cap: usize,
    ) -> StatusClass {
        // SAFETY: live borrowed body range (ABI).
        let body = unsafe { std::slice::from_raw_parts(body_ptr, body_len) };
        let r: busbar_api::McpCallRecord =
            serde_json::from_slice(body).expect("McpCallRecord decodes");
        let mut suffix = Vec::new();
        let lp = |buf: &mut Vec<u8>, b: &[u8]| {
            buf.extend_from_slice(&(b.len() as u64).to_be_bytes());
            buf.extend_from_slice(b);
        };
        lp(&mut suffix, &r.ts.to_be_bytes());
        lp(&mut suffix, r.server.as_bytes());
        lp(&mut suffix, r.tool.as_bytes());
        lp(&mut suffix, r.outcome.as_bytes());
        lp(&mut suffix, r.reason.as_bytes());
        lp(&mut suffix, r.tool_digest.as_bytes());
        lp(&mut suffix, &r.pin_generation.to_be_bytes());
        write_reframe(
            out,
            r.seq,
            1,
            r.prev_hash.as_bytes(),
            r.hash.as_bytes(),
            &suffix,
            prev_buf,
            prev_cap,
            hash_buf,
            hash_cap,
            suffix_buf,
            suffix_cap,
        )
    }

    /// Admin plane reframe: decode the legacy `AuditEntry` and emit the PipeSeparated suffix, scope
    /// NOT in the digest (`digests_scope = 0`). `frame_prelude(prev_hash, <no scope>, seq) ⧺ suffix`
    /// == `AuditEntry::digest_fields`.
    extern "C-unwind" fn admin_reframe(
        _host: HostCtx,
        _kind_id: u32,
        body_ptr: *const u8,
        body_len: usize,
        out: *mut MaybeUninit<ReframeOut>,
        prev_buf: *mut u8,
        prev_cap: usize,
        hash_buf: *mut u8,
        hash_cap: usize,
        suffix_buf: *mut u8,
        suffix_cap: usize,
    ) -> StatusClass {
        // SAFETY: live borrowed body range (ABI).
        let body = unsafe { std::slice::from_raw_parts(body_ptr, body_len) };
        let r: crate::admin::audit::AuditEntry =
            serde_json::from_slice(body).expect("AuditEntry decodes");
        let suffix = format!("|{}|{}|{}|{}", r.ts, r.action, r.resource, r.outcome);
        // The last field is `principal`; append it (kept off the format! line only for readability).
        let suffix = format!("{suffix}|{}", r.principal);
        write_reframe(
            out,
            r.seq,
            0,
            r.prev_hash.as_bytes(),
            r.hash.as_bytes(),
            suffix.as_bytes(),
            prev_buf,
            prev_cap,
            hash_buf,
            hash_cap,
            suffix_buf,
            suffix_cap,
        )
    }

    fn put_frozen(store: &GenericPlaneStore, kind: &str, parent: &str, seq: u64, body: &[u8]) {
        use busbar_api::{PlaneDisposition, PlaneRecord, Store};
        store
            .append_plane_record(&PlaneRecord {
                kind: kind.to_string(),
                id: parent.to_string(),
                parent: Some(parent.to_string()),
                seq,
                ts: 0,
                disposition: PlaneDisposition::Active,
                body: body.to_vec(),
            })
            .expect("frozen body persists");
    }

    fn register_stream(
        host: HostCtx,
        vt: &PlaneHostVtable,
        kind_id: u32,
        kind: &[u8],
        framing: AbiFraming,
        digests_scope: u8,
        reframe: JournalReframeFn,
    ) {
        let desc = JournalStreamDesc {
            size: core::mem::size_of::<JournalStreamDesc>() as u32,
            version: POD_VERSION,
            framing,
            digests_scope,
            kind_id,
            _reserved: 0,
            kind_ptr: kind.as_ptr(),
            kind_len: kind.len(),
        };
        assert_eq!(
            (vt.journal_register.unwrap())(host, &desc as *const JournalStreamDesc, reframe),
            StatusClass::Ok
        );
    }

    fn restore_and_verify(
        host: HostCtx,
        vt: &PlaneHostVtable,
        kind_id: u32,
        scope: &[u8],
        expect_tail: &str,
        tail_hash: &str,
    ) {
        // RESTORE: both frozen records, one scope, zero breaks (the digest recompute matched).
        let mut rout = MaybeUninit::<RestoredHdr>::uninit();
        assert_eq!(
            (vt.journal_restore.unwrap())(
                host,
                kind_id,
                &mut rout as *mut MaybeUninit<RestoredHdr>
            ),
            StatusClass::Ok
        );
        // SAFETY: Ok published the slot.
        let r = unsafe { rout.assume_init() };
        assert_eq!(
            r.chain_breaks, 0,
            "a frozen chain reported TAMPERED means the durable-seam digest drifted"
        );
        assert_eq!(r.records, 2, "both frozen records restored");
        assert_eq!(r.scopes, 1);

        // VERIFY the scope explicitly.
        let mut vout = MaybeUninit::<VerifyChainHdr>::uninit();
        assert_eq!(
            (vt.journal_verify_scoped.unwrap())(
                host,
                kind_id,
                scope.as_ptr(),
                scope.len(),
                &mut vout as *mut MaybeUninit<VerifyChainHdr>,
            ),
            StatusClass::Ok
        );
        // SAFETY: Ok published the slot.
        let v = unsafe { vout.assume_init() };
        assert_eq!(
            v.verified, 1,
            "the frozen chain verifies through the durable seam"
        );
        assert_eq!(expect_tail, tail_hash, "the frozen tail hash is intact");
    }

    /// The chain-compat golden: the frozen A2A/MCP/Admin bodies restore + verify through the DURABLE
    /// seam byte-identically — all three framings, including the PipeSeparated genesis landmine and the
    /// `digests_scope = false` admin shape.
    #[test]
    fn frozen_chains_boot_verify_through_the_durable_seam() {
        let store = Arc::new(GenericPlaneStore::new());
        put_frozen(&store, "task_event", "task-1", 1, G_A2A_1);
        put_frozen(&store, "task_event", "task-1", 2, G_A2A_2);
        put_frozen(&store, "call", "vk_alice", 1, G_MCP_1);
        put_frozen(&store, "call", "vk_alice", 2, G_MCP_2);
        put_frozen(&store, "admin_audit", "log", 1, G_AD_1);
        put_frozen(&store, "admin_audit", "log", 2, G_AD_2);

        let app = durable_app_over(store);
        let a2a_id = fresh_kind_id();
        let mcp_id = fresh_kind_id();
        let admin_id = fresh_kind_id();
        with_dispatch_scope(&app, |host, vt| {
            register_stream(
                host,
                vt,
                a2a_id,
                b"task_event",
                AbiFraming::PipeSeparated,
                1,
                a2a_reframe,
            );
            register_stream(
                host,
                vt,
                mcp_id,
                b"call",
                AbiFraming::LengthPrefixed,
                1,
                mcp_reframe,
            );
            register_stream(
                host,
                vt,
                admin_id,
                b"admin_audit",
                AbiFraming::PipeSeparated,
                0,
                admin_reframe,
            );

            let a2a_tail: busbar_api::TaskEventRow = serde_json::from_slice(G_A2A_2).unwrap();
            let mcp_tail: busbar_api::McpCallRecord = serde_json::from_slice(G_MCP_2).unwrap();
            let ad_tail: crate::admin::audit::AuditEntry = serde_json::from_slice(G_AD_2).unwrap();

            restore_and_verify(host, vt, a2a_id, b"task-1", &a2a_tail.hash, G_A2A_TAIL);
            restore_and_verify(host, vt, mcp_id, b"vk_alice", &mcp_tail.hash, G_MCP_TAIL);
            restore_and_verify(host, vt, admin_id, b"log", &ad_tail.hash, G_AD_TAIL);
        });
    }

    #[test]
    fn null_pods_fail_closed() {
        let fd = framing_desc(AbiFraming::LengthPrefixed, 1);
        with_test_state(|host, vt| {
            // Null framing → Seq::NONE, not a fabricated sequence.
            let s =
                (vt.journal_append.unwrap())(host, 999_001, std::ptr::null(), 0, std::ptr::null());
            assert_eq!(s, Seq::NONE);
            let _ = fd;
            // Null query → Refused.
            let mut out_written: usize = 0;
            let s = (vt.journal_read.unwrap())(
                host,
                std::ptr::null(),
                std::ptr::null_mut(),
                0,
                &mut out_written as *mut usize,
            );
            assert_eq!(s, StatusClass::Refused);
        });
    }
}
