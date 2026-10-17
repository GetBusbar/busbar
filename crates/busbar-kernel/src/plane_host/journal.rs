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
//! The durable slots (`journal_register` and the `journal_*_scoped` family) drive the ONE registry of
//! store-backed streams, [`crate::audit::stream_registry`]: this module only reads the borrowed ABI
//! buffers, decodes the descriptor, and hands a stream's own decoder back across the seam. The two
//! RAM slots (`journal_append`/`journal_read`) hold the per-scope positions and rows in a
//! PROCESS-LOCAL registry and wire FAITHFULLY to [`crate::audit::Chain::append`] per scope — same seq
//! authority, same seal/digest — producing byte-identical digests. The two
//! `// durable-store cleave point` markers below flag where a store would attach to them.

use super::recover;
use crate::audit::stream_registry::{
    self, handle as stream_handle, Decode, StreamHandle, StreamInput, StreamRecord,
};
use crate::audit::{Chain, ChainedRecord, Framing};
use crate::plane::store::PlaneStoreView;
use busbar_contract::abi::hot::host::{HostCtx, JournalReframeFn};
use busbar_contract::abi::hot::{
    ChainBreakHdr, Framing as AbiFraming, FramingDesc, JournalQuery, JournalStreamDesc, RawFraming,
    ReframeOut, Seq, StatusClass, POD_VERSION,
};
use busbar_contract::records::{RecordStoreError, RecordStoreResult};
use core::mem::MaybeUninit;
use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, OnceLock};

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

/// Turn one stored body + its scope back into a [`StreamRecord`] by calling the stream's
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
) -> RecordStoreResult<StreamRecord> {
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
                return Ok(StreamRecord {
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
                    return Err(RecordStoreError(
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
                return Err(RecordStoreError(format!(
                    "journal reframe failed: {other:?}"
                )))
            }
        }
    }
}

/// The decode a durable slot hands the journal: the registrant's own decoder across the seam
/// ([`call_reframe`]), or the stream's in-core decode for a stream core registered itself.
fn decode_over(
    host: HostCtx,
    kind_id: u32,
    h: &StreamHandle,
) -> impl Fn(&str, &[u8]) -> RecordStoreResult<StreamRecord> + '_ {
    move |sc: &str, body: &[u8]| match &h.decode {
        Decode::Seam(decoder) => match decoder.downcast_ref::<JournalReframeFn>() {
            Some(reframe) => call_reframe(host, kind_id, *reframe, h.framing, sc, body),
            None => Err(RecordStoreError(
                "journal stream decoder is not a seam decoder".to_string(),
            )),
        },
        Decode::Native(_) => h.decode_native(sc, body),
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
    // lifecycle. A stream that needs an LRU cap (the usage residual log, keyed by an unbounded principal
    // space) registers within core through `stream_registry::register`, which the ABI descriptor cannot
    // express.
    register_stream(host, desc, reframe, usize::MAX)
}

/// REGISTER a durable journal stream with an explicit LRU `cap` on its position cache, which the
/// [`JournalStreamDesc`] ABI POD cannot carry. Byte-behaviour is identical to the ABI path but for the
/// bound; an evicted position is resumed from the store on the scope's next append. Its one caller is
/// the resume-break test, which drives a cap of one through the seam; core's own capped stream
/// registers through [`stream_registry::register`].
#[cfg(test)]
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
        let Some(state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
        if desc.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `desc` is a live, initialized `JournalStreamDesc` for the call (ABI).
        let d = unsafe { &*desc };
        let Some(kind) = read_scope(d.kind_ptr, d.kind_len) else {
            return StatusClass::Refused;
        };
        // Decode the plane-written framing byte BEFORE the stream enters the registry: a framing this
        // build cannot name is `Unsupported`, never a stream registered under a guessed framing.
        let Some(framing) = map_framing(d.framing) else {
            return StatusClass::Unsupported;
        };
        let sink = state
            .app
            .governance
            .as_ref()
            .map(|gov| PlaneStoreView::narrow(gov.store()));
        stream_registry::register(
            d.kind_id,
            kind,
            framing,
            d.digests_scope != 0,
            Decode::Seam(Arc::new(reframe)),
            cap,
            sink,
        );
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
        let Some(_state) = (unsafe { recover(host) }) else {
            return Seq::NONE;
        };
        let Some(h) = stream_handle(kind_id) else {
            return Seq::NONE;
        };
        let Some(scope) = read_scope(scope_ptr, scope_len) else {
            return Seq::NONE;
        };
        let content = read_bytes(content_ptr, content_len);
        let reframe = decode_over(host, kind_id, &h);
        match h.append(&scope, content, &reframe) {
            Ok(record) => Seq(record.seq()),
            Err(_) => Seq::NONE,
        }
    }))
    .unwrap_or(Seq::NONE)
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
        let Some(_state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
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
        let reframe = decode_over(host, kind_id, &h);
        let mut records = Vec::with_capacity(bodies.len());
        for body in &bodies {
            match reframe(scope.as_str(), body.as_slice()) {
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

/// RETENTION: drop a registered stream's durable rows older than `before`, writing the count removed.
pub(crate) extern "C-unwind" fn journal_compact(
    host: HostCtx,
    kind_id: u32,
    before: u64,
    out_removed: *mut u64,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let Some(_state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
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

/// Every packed record costs at least its own `u32` length prefix (4 bytes), even with an empty body,
/// so a blob of `remaining` bytes after the count header can hold at most `remaining / 4` records. Used
/// to BOUND the pre-allocation in [`unpack_bodies`] against the actual input length.
const MIN_PACKED_RECORD_BYTES: usize = 4;

/// The pre-allocation ceiling for [`unpack_bodies`]: never reserve for more records than the remaining
/// bytes could possibly encode. A hostile/corrupt count word (up to `u32::MAX`) would otherwise drive
/// `Vec::with_capacity` to billions of elements — gigabytes — from a few-byte header, an allocation
/// bomb, BEFORE any per-record validation runs. Clamping to `remaining / 4` costs a well-formed blob
/// nothing (its count is already within budget) while capping a hostile one to what the buffer holds;
/// the Vec still grows if the validated data genuinely needs it.
fn seed_capacity(count: usize, remaining: usize) -> usize {
    count.min(remaining / MIN_PACKED_RECORD_BYTES)
}

/// Unpack the packed body set a [`journal_seed`] carries: `u32` count LE, then per body a `u32` length
/// LE + that many bytes. Returns `None` on a truncated/oversized blob (fail-closed). The pre-allocation
/// is BOUNDED against the remaining input length ([`seed_capacity`]) so a hostile count cannot
/// pre-allocate gigabytes before the per-record bounds checks run.
fn unpack_bodies(packed: &[u8]) -> Option<Vec<Vec<u8>>> {
    if packed.len() < 4 {
        return Some(Vec::new());
    }
    let count = u32::from_le_bytes(packed[0..4].try_into().ok()?) as usize;
    let mut off = 4;
    let mut out = Vec::with_capacity(seed_capacity(count, packed.len() - 4));
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
    chain: Chain<StreamRecord>,
    rows: Vec<StreamRecord>,
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

/// Decode the plane-written raw framing byte into core's own [`Framing`], or `None` for a byte no
/// shipped [`AbiFraming`] names. The descriptor is filled ENTIRELY by the plane, so this is a
/// checked decode of untrusted memory, never a `match` on a bare enum: an unnamed byte would
/// otherwise be an invalid discriminant the instant the field is read. There is no neutral
/// fallback — reproducing a stream's stored bytes in the WRONG framing breaks every digest in its
/// chain — so the caller fails closed instead.
fn map_framing(f: RawFraming) -> Option<Framing> {
    Some(match f.framing()? {
        AbiFraming::LengthPrefixed => Framing::LengthPrefixed,
        AbiFraming::PipeSeparated => Framing::PipeSeparated,
    })
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
        let Some(_state) = (unsafe { recover(host) }) else {
            return Seq::NONE;
        };
        if framing.is_null() {
            return Seq::NONE;
        }
        // SAFETY: a non-null `framing` is a live, initialized `FramingDesc` for the call (ABI).
        let fd = unsafe { &*framing };
        // The plane writes this byte. A framing this build cannot name yields the RESERVED invalid
        // sequence — never a record appended (and digested) under a guessed framing.
        let Some(record_framing) = map_framing(fd.framing) else {
            return Seq::NONE;
        };
        let content: Vec<u8> = if content_ptr.is_null() || content_len == 0 {
            Vec::new()
        } else {
            // SAFETY: `(content_ptr, content_len)` is a live borrowed range for the call (ABI).
            unsafe { std::slice::from_raw_parts(content_ptr, content_len) }.to_vec()
        };
        let input = StreamInput::new(content, record_framing, fd.digests_scope != 0);
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
        let Some(_state) = (unsafe { recover(host) }) else {
            return StatusClass::Refused;
        };
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
fn encode_rows(rows: &[StreamRecord], from_seq: u64, limit: u64) -> Vec<u8> {
    let take = if limit == 0 {
        usize::MAX
    } else {
        limit as usize
    };
    let selected: Vec<&StreamRecord> = rows
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
