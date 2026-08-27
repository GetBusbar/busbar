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

/// TEST ONLY: point an already-registered stream's durable journal at `store` (or detach it) WITHOUT
/// re-registering — so a global-`TASKS` chain test can aim the process-wide `kind_id` at its own
/// ledger for the duration it holds `TASKS_SINK_LOCK`, leaving the chain POSITIONS untouched (a
/// re-register would reset every position and race the no-sink registration the working-set tests
/// share). A no-op if the stream is not registered.
#[cfg(test)]
pub(crate) fn set_stream_sink_for_test(
    kind_id: u32,
    store: Option<Arc<dyn crate::plane::store::PlaneStore>>,
) {
    if let Some(s) = streams_lock().get(&kind_id) {
        match store {
            Some(store) => s.journal.set_sink(store),
            None => s.journal.clear_sink_for_test(),
        }
    }
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

/// THE IN-CORE REFRAME BRIDGE. A within-core plane seam user (`plane::taskstore`, `calllog`)
/// still owns its own native `Fn(&str, &[u8]) -> StoreResult<PlaneJournalRecord>` decode bridge, but
/// the durable seam addresses reframe over the [`JournalReframeFn`] FFI shape. This is the adapter:
/// the plane's `extern "C-unwind"` reframe slot forwards the raw buffers here, and this reads the body,
/// runs the native decode, and writes `(seq, prev_hash, hash, pre-framed suffix, digests_scope)` back
/// into the caller's three buffers under the same length-report discipline [`call_reframe`] expects —
/// so the unsafe buffer work stays in this audited host module and the plane files stay `deny(unsafe)`.
/// The scope the host assembles the record with is its own (the store parent), so the native decode's
/// scope argument is inert here; a placeholder is passed.
#[cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn reframe_bridge(
    body_ptr: *const u8,
    body_len: usize,
    out: *mut MaybeUninit<ReframeOut>,
    prev_buf: *mut u8,
    prev_cap: usize,
    hash_buf: *mut u8,
    hash_cap: usize,
    suffix_buf: *mut u8,
    suffix_cap: usize,
    native: impl FnOnce(&str, &[u8]) -> busbar_api::StoreResult<PlaneJournalRecord>,
) -> StatusClass {
    if out.is_null() {
        return StatusClass::Refused;
    }
    let body = read_bytes(body_ptr, body_len);
    let record = match native("", &body) {
        Ok(r) => r,
        Err(_) => return StatusClass::Fault,
    };
    let prev = record.prev_hash.as_bytes();
    let hash = record.hash.as_bytes();
    let suffix = record.content.as_slice();
    let o = ReframeOut {
        size: core::mem::size_of::<ReframeOut>() as u32,
        version: POD_VERSION,
        digests_scope: u8::from(record.digests_scope),
        _r: 0,
        seq: record.seq,
        prev_len: prev.len(),
        hash_len: hash.len(),
        suffix_len: suffix.len(),
    };
    // SAFETY: non-null `out` is a live, writable `MaybeUninit<ReframeOut>`; always initialized (the
    // length-report discipline), so it is readable on both `Ok` and `Refused`.
    unsafe { (*out).write(o) };
    if prev.len() > prev_cap || hash.len() > hash_cap || suffix.len() > suffix_cap {
        return StatusClass::Refused;
    }
    // SAFETY: each destination cap >= the source length (checked above); the ranges are live for the
    // call (ABI discipline), and a null buffer only occurs paired with a zero cap ⇒ zero-length copy.
    unsafe {
        if !prev.is_empty() {
            std::ptr::copy_nonoverlapping(prev.as_ptr(), prev_buf, prev.len());
        }
        if !hash.is_empty() {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), hash_buf, hash.len());
        }
        if !suffix.is_empty() {
            std::ptr::copy_nonoverlapping(suffix.as_ptr(), suffix_buf, suffix.len());
        }
    }
    StatusClass::Ok
}

/// SAFE SEED WRAPPER for a within-core seam user: drive [`journal_seed`] over a registered stream and
/// return the reported [`ChainBreakHdr`] by value, keeping the `MaybeUninit` read (the one unsafe step)
/// inside this audited module so `plane::taskstore` stays `deny(unsafe)`. `Err(())` is a seam fault
/// (an unregistered stream, an empty scope, or a reframe that could not decode a body).
#[cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]
pub(crate) fn seed_scoped_via_seam(
    host: HostCtx,
    kind_id: u32,
    scope: &str,
    packed: &[u8],
) -> Result<ChainBreakHdr, ()> {
    let mut out = MaybeUninit::<ChainBreakHdr>::uninit();
    let status = journal_seed(
        host,
        kind_id,
        scope.as_ptr(),
        scope.len(),
        packed.as_ptr(),
        packed.len(),
        &mut out as *mut MaybeUninit<ChainBreakHdr>,
    );
    if status != StatusClass::Ok {
        return Err(());
    }
    // SAFETY: an `Ok` status published the slot (the seed's write-only-on-Ok discipline).
    Ok(unsafe { out.assume_init() })
}

/// SAFE COMPACT WRAPPER for a within-core seam user: drive [`journal_compact`] over a registered
/// stream and return the count of durable rows dropped. `Err(())` is a seam fault. No `unsafe` is
/// needed: `removed` is an ordinary stack `u64` the host writes on the `Ok` path.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub(crate) fn compact_via_seam(host: HostCtx, kind_id: u32, before: u64) -> Result<u64, ()> {
    let mut removed: u64 = 0;
    let status = journal_compact(host, kind_id, before, &mut removed as *mut u64);
    if status != StatusClass::Ok {
        return Err(());
    }
    Ok(removed)
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
    // `usize::MAX` over the ABI seam: the [`JournalStreamDesc`] POD carries no LRU cap, and a durable
    // TABLE (the A2A task journal) opts OUT of position eviction — its working set is bounded by its own
    // lifecycle. A stream that needs an LRU cap (the MCP call log, keyed by an unbounded principal space)
    // registers WITHIN CORE through [`journal_register_capped`], which the ABI descriptor cannot express.
    register_stream(host, desc, reframe, usize::MAX)
}

/// REGISTER a durable journal stream with an explicit LRU `cap` on its position cache — the WITHIN-CORE
/// entry point for a stream (the MCP `call` log) whose scope space is unbounded (one position per
/// principal) and must be bounded in RAM. The [`JournalStreamDesc`] ABI POD carries no cap, and this
/// crate must not touch the hot ABI to add one, so an in-core plane seam user reaches this directly
/// instead of the vtable's `journal_register`. Byte-behaviour is identical to the ABI path but for the
/// bound; an evicted position is resumed from the store on the principal's next call.
pub(crate) fn journal_register_capped(
    host: HostCtx,
    desc: *const JournalStreamDesc,
    reframe: JournalReframeFn,
    cap: usize,
) -> StatusClass {
    register_stream(host, desc, reframe, cap)
}

fn register_stream(
    host: HostCtx,
    desc: *const JournalStreamDesc,
    reframe: JournalReframeFn,
    cap: usize,
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
        let journal = Arc::new(Journal::<PlaneJournalRecord>::new(cap));
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

/// APPEND one record and return its MINTED chain fields `(seq, prev_hash, hash)` — the WITHIN-CORE
/// analogue of [`journal_append_scoped`] for a seam user that must reconstruct the TYPED record it
/// returns to its caller (the MCP call log hands back an `McpCallRecord` carrying `prev_hash`/`hash`,
/// which the `Seq`-only ABI append does not surface). `Err` carries the STORE's own error verbatim (a
/// durable-write failure the caller surfaces to decide on), an unregistered stream / empty scope, or a
/// caught panic — so the caller reports the same reason the pre-cleave `Journal::record` did.
pub(crate) fn journal_append_scoped_full(
    host: HostCtx,
    kind_id: u32,
    scope: &str,
    content: &[u8],
) -> Result<(u64, String, String), busbar_api::StoreError> {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state = unsafe { recover(host) };
        let Some(h) = stream_handle(kind_id) else {
            return Err(busbar_api::StoreError(
                "journal stream is not registered".to_string(),
            ));
        };
        if scope.is_empty() {
            return Err(busbar_api::StoreError(
                "journal scope must be a non-empty key".to_string(),
            ));
        }
        let input = PlaneJournalInput {
            content: content.to_vec(),
            framing: h.framing,
            digests_scope: h.digests_scope,
        };
        let reframe =
            |sc: &str, body: &[u8]| call_reframe(host, kind_id, h.reframe, h.framing, sc, body);
        match h.journal.append_scoped(&h.kind, scope, input, &reframe) {
            Ok(record) => Ok((
                record.seq(),
                record.prev_hash().to_string(),
                record.hash().to_string(),
            )),
            Err(crate::audit::journal::JournalError::Store(e)) => Err(e),
        }
    }))
    .unwrap_or_else(|_| {
        Err(busbar_api::StoreError(
            "journal append panicked".to_string(),
        ))
    })
}

/// HOSTLESS append for a within-core seam user that has NO `HostCtx` to open — the deferred MCP
/// client-leg path (`mcp::client::issue`), which is `async` (a `HostCtx` is `!Send` and cannot cross
/// its `.await`s) and reaches no `App`. It appends to the registered `kind_id` stream WITHOUT recovering
/// a host: the append itself never reads host state, and the ONLY host-consuming step (the reframe on a
/// cache-miss resume) is a no-op for the shipped in-core reframes (which ignore the host) and is not
/// reached at all on a stream with no eviction. `Err` carries the store's reason verbatim, as
/// [`journal_append_scoped_full`] does. This is the hostless in-core emit path the durable cleave keeps
/// for the deferred site, not a route any plane crosses the FFI border on.
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
pub(crate) fn journal_append_scoped_full_hostless(
    kind_id: u32,
    scope: &str,
    content: &[u8],
) -> Result<(u64, String, String), busbar_api::StoreError> {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(h) = stream_handle(kind_id) else {
            return Err(busbar_api::StoreError(
                "journal stream is not registered".to_string(),
            ));
        };
        if scope.is_empty() {
            return Err(busbar_api::StoreError(
                "journal scope must be a non-empty key".to_string(),
            ));
        }
        let input = PlaneJournalInput {
            content: content.to_vec(),
            framing: h.framing,
            digests_scope: h.digests_scope,
        };
        // The reframe is reached ONLY on an LRU-evicted-scope resume; the shipped in-core reframes
        // ignore the `host` argument (see `reframe_bridge`), so a null host here is never dereferenced.
        let null_host: HostCtx = core::ptr::null_mut();
        let reframe = |sc: &str, body: &[u8]| {
            call_reframe(null_host, kind_id, h.reframe, h.framing, sc, body)
        };
        match h.journal.append_scoped(&h.kind, scope, input, &reframe) {
            Ok(record) => Ok((
                record.seq(),
                record.prev_hash().to_string(),
                record.hash().to_string(),
            )),
            Err(crate::audit::journal::JournalError::Store(e)) => Err(e),
        }
    }))
    .unwrap_or_else(|_| {
        Err(busbar_api::StoreError(
            "journal append panicked".to_string(),
        ))
    })
}

/// The sequence the next record for `scope` on the registered `kind_id` stream will carry (1 for an
/// uncached scope) — a diagnostic on the position, read WITHIN CORE (the ABI exposes no `next_seq`).
pub(crate) fn journal_next_seq_scoped(kind_id: u32, scope: &str) -> u64 {
    stream_handle(kind_id)
        .map(|h| h.journal.next_seq(scope))
        .unwrap_or(1)
}

/// How many scope positions the registered `kind_id` stream is holding — the diagnostic the MCP call
/// log's bounded-map test reads, exposed WITHIN CORE (the ABI has no `len`).
pub(crate) fn journal_len_scoped(kind_id: u32) -> usize {
    stream_handle(kind_id).map(|h| h.journal.len()).unwrap_or(0)
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
#[path = "tests/journal_tests.rs"]
mod tests;
