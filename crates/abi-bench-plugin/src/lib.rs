// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MEASUREMENT-ONLY. The far side of the `dlopen`.
//!
//! This exports the SAME six kind-neutral symbols the shipped `export_plugin!` macro emits and
//! routes every one of them through the SAME `busbar_plugin_sdk::boundary` helpers, so the mandatory
//! `catch_unwind`, the status map, the alloc-after-check out-buffer publish and the
//! plugin-allocates/plugin-frees rule are all charged to the measurement. The only thing it does not
//! reuse is the per-kind `$dispatch`, because the per-kind dispatch is precisely what is under test:
//! `store_dispatch`/`hook_dispatch` hard-code `serde_json::from_slice` + `serde_json::to_vec`, and
//! the whole question is what the number looks like with a different encoding in that slot.
//!
//! The arm is selected by the FIRST BYTE of the request buffer (see `busbar_abi_bench::op`) rather
//! than by a serialized envelope enum. That is deliberate: the envelope parse is one of the costs
//! under test and must not be charged uniformly to every arm.

use busbar_abi_bench::{op, wire::*};
use busbar_plugin_sdk::BoundaryOutcome;
use core::ffi::c_void;
use rkyv::rancor::Error as RkyvError;

/// The instance. Holds the archives that the `*_PREBUILT` arms return WITHOUT a serialize pass —
/// the arm that answers "is nanoseconds reachable if the producer emits the archive natively".
pub struct BenchHandle {
    /// A template request, owned, for arms that must BUILD a response archive from Rust structs.
    template: WireRequest,
    /// The same template, already archived at open. Returned by `RKYV_PREBUILT`.
    prebuilt_req: Vec<u8>,
    /// A stream frame, already archived at open. Returned by `RKYV_FRAME_PREBUILT`.
    prebuilt_frame: Vec<u8>,
}

fn ctor(cfg: &str) -> Result<BenchHandle, String> {
    // The config carries the payload size the template should match, so the response the plugin
    // builds is the same magnitude as the request it was handed. A response that is a constant tiny
    // struct would understate every arm that has to encode one.
    let target: usize = cfg.trim().parse().unwrap_or(1024);
    let template = busbar_abi_bench::build_request(target);
    let prebuilt_req = rkyv::to_bytes::<RkyvError>(&template)
        .map_err(|e| e.to_string())?
        .to_vec();
    let prebuilt_frame = rkyv::to_bytes::<RkyvError>(&busbar_abi_bench::build_frame())
        .map_err(|e| e.to_string())?
        .to_vec();
    Ok(BenchHandle {
        template,
        prebuilt_req,
        prebuilt_frame,
    })
}

/// # Safety
/// `handle` is a live `BenchHandle` published by `busbar_open`; `bytes` is the request buffer.
unsafe fn dispatch(handle: *mut c_void, bytes: &[u8]) -> BoundaryOutcome {
    let h = &*(handle as *const BenchHandle);
    if bytes.len() < busbar_abi_bench::HDR {
        return BoundaryOutcome::Error("short request".into());
    }
    let opcode = bytes[0];
    // The payload starts at HDR (16), not at 1. A zero-copy archive must be 16-byte aligned to be
    // read in place, so a ONE-byte opcode would misalign every rkyv arm by one — see `HDR`'s doc.
    let payload = &bytes[busbar_abi_bench::HDR..];
    match opcode {
        op::NOOP => BoundaryOutcome::Ok(Vec::new()),

        op::ECHO_N => {
            let mut n = [0u8; 4];
            n.copy_from_slice(&payload[..4]);
            BoundaryOutcome::Ok(vec![0xABu8; u32::from_le_bytes(n) as usize])
        }

        op::JSON => match serde_json::from_slice::<WireRequest>(payload) {
            Ok(req) => {
                let acc = busbar_abi_bench::work_owned(&req);
                sink(acc);
                BoundaryOutcome::Ok(serde_json::to_vec(&h.template).unwrap_or_default())
            }
            Err(e) => BoundaryOutcome::Unsupported(format!("malformed request JSON: {e}")),
        },

        op::POSTCARD => match postcard::from_bytes::<WireRequest>(payload) {
            Ok(req) => {
                let acc = busbar_abi_bench::work_owned(&req);
                sink(acc);
                BoundaryOutcome::Ok(postcard::to_allocvec(&h.template).unwrap_or_default())
            }
            Err(e) => BoundaryOutcome::Unsupported(format!("malformed request postcard: {e}")),
        },

        // VALIDATED zero-copy access. `rkyv::access` runs bytecheck over the whole archive before
        // handing back a reference — this is the arm that is honest about a hostile/corrupt buffer,
        // and it is the one to compare against JSON, because JSON's parse also validates.
        op::RKYV_CHECKED => match rkyv::access::<ArchivedWireRequest, RkyvError>(payload) {
            Ok(req) => {
                let acc = busbar_abi_bench::work_archived(req);
                sink(acc);
                BoundaryOutcome::Ok(archive(&h.template))
            }
            Err(e) => BoundaryOutcome::Unsupported(format!("malformed request archive: {e}")),
        },

        // UNVALIDATED access — the true zero-copy read, and UNSOUND on any buffer the host did not
        // itself produce. Measured so the cost of validation is visible as its own line, not so it
        // can be recommended for a dropped-in plugin.
        op::RKYV_UNCHECKED => {
            let req = rkyv::access_unchecked::<ArchivedWireRequest>(payload);
            let acc = busbar_abi_bench::work_archived(req);
            sink(acc);
            BoundaryOutcome::Ok(archive(&h.template))
        }

        // No encode pass at all on the response side: the archive was built once, at open. This is
        // the ceiling a zero-copy design reaches ONLY if the plugin's native output IS the archive.
        op::RKYV_PREBUILT => {
            let req = rkyv::access_unchecked::<ArchivedWireRequest>(payload);
            let acc = busbar_abi_bench::work_archived(req);
            sink(acc);
            BoundaryOutcome::Ok(h.prebuilt_req.clone())
        }

        op::JSON_FRAME => match serde_json::from_slice::<WireStreamEvent>(payload) {
            Ok(ev) => {
                let acc = busbar_abi_bench::frame_work_owned(&ev);
                sink(acc);
                BoundaryOutcome::Ok(serde_json::to_vec(&ev).unwrap_or_default())
            }
            Err(e) => BoundaryOutcome::Unsupported(format!("malformed frame JSON: {e}")),
        },

        op::RKYV_FRAME => {
            let ev = rkyv::access_unchecked::<ArchivedWireStreamEvent>(payload);
            let acc = busbar_abi_bench::frame_work_archived(ev);
            sink(acc);
            BoundaryOutcome::Ok(archive(&busbar_abi_bench::build_frame()))
        }

        op::RKYV_FRAME_PREBUILT => {
            let ev = rkyv::access_unchecked::<ArchivedWireStreamEvent>(payload);
            let acc = busbar_abi_bench::frame_work_archived(ev);
            sink(acc);
            BoundaryOutcome::Ok(h.prebuilt_frame.clone())
        }

        // THE "HAND THE CODEC RAW BYTES" DESIGN. The payload is the caller's HTTP body, unparsed.
        // The plugin does the parse it was going to do anyway and returns an IR archive, so the
        // marginal cost over compiled-in is exactly one IR encode (here) plus one access (host).
        op::RAW_BYTES_TO_RKYV => match serde_json::from_slice::<serde_json::Value>(payload) {
            Ok(v) => {
                let acc = walk_value(&v);
                sink(acc);
                BoundaryOutcome::Ok(archive(&h.template))
            }
            Err(e) => BoundaryOutcome::Unsupported(format!("malformed body JSON: {e}")),
        },

        other => BoundaryOutcome::Unsupported(format!("unknown bench opcode {other}")),
    }
}

/// Where the work accumulator goes. It must LEAVE this function or the optimizer is entitled to
/// delete the traversal — but it must not ride the response buffer either, because appending a byte
/// to an rkyv archive moves the root and makes the archive unreadable. A relaxed atomic is the
/// cheapest sink that is opaque to the optimizer (~1 ns, charged equally to every arm).
#[inline]
fn sink(v: u64) {
    static ACC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    ACC.fetch_add(v, std::sync::atomic::Ordering::Relaxed);
}

/// Serialize to an rkyv archive and hand back the bytes the ABI wants. `into_vec` on rkyv's
/// `AlignedVec` REALLOCATES to an alignment-1 `Vec` — an unavoidable consequence of the transport's
/// out-buffer being freed as a `Box<[u8]>`; see the report's alignment note.
fn archive<T>(v: &T) -> Vec<u8>
where
    T: for<'a> rkyv::Serialize<
        rkyv::api::high::HighSerializer<
            rkyv::util::AlignedVec,
            rkyv::ser::allocator::ArenaHandle<'a>,
            RkyvError,
        >,
    >,
{
    rkyv::to_bytes::<RkyvError>(v)
        .map(|b| b.to_vec())
        .unwrap_or_default()
}

/// Stand-in for a dialect's field walk over a freshly parsed body — the work a protocol plugin does
/// after the parse, in BOTH the compiled-in and the dropped-in design.
pub fn walk_value(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::String(s) => s.len() as u64,
        serde_json::Value::Array(a) => a.iter().map(walk_value).sum(),
        serde_json::Value::Object(o) => o
            .iter()
            .map(|(k, val)| k.len() as u64 + walk_value(val))
            .sum(),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
        serde_json::Value::Bool(b) => *b as u64,
        serde_json::Value::Null => 0,
    }
}

// ── the six symbols, through the shipped boundary helpers ───────────────────────────────────────

/// # Safety
/// Read only by the harness as the frozen TRANSPORT handshake.
#[no_mangle]
pub extern "C-unwind" fn busbar_abi() -> u32 {
    busbar_plugin_sdk::transport_version()
}

/// # Safety
/// Returns a `'static` NUL-terminated string owned by this library.
#[no_mangle]
pub extern "C-unwind" fn busbar_plugin_kind() -> *const u8 {
    busbar_plugin_abi::kind::HOOK_NUL.as_ptr()
}

/// # Safety
/// Called by the harness with ABI-valid pointers.
#[no_mangle]
pub unsafe extern "C-unwind" fn busbar_open(
    cfg: *const u8,
    cfg_len: usize,
    out_handle: *mut *mut c_void,
    out_err: *mut *mut u8,
    out_err_len: *mut usize,
) -> i32 {
    busbar_plugin_sdk::boundary::open_boundary::<BenchHandle>(
        cfg,
        cfg_len,
        out_handle,
        out_err,
        out_err_len,
        |s| ctor(s).map_err(BoundaryOutcome::Error),
    )
}

/// # Safety
/// Called by the harness with a live handle and ABI-valid pointers.
#[no_mangle]
pub unsafe extern "C-unwind" fn busbar_call(
    handle: *mut c_void,
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    busbar_plugin_sdk::boundary::call_boundary(handle, req, req_len, out, out_len, |h, b| {
        dispatch(h, b)
    })
}

/// # Safety
/// Called by the harness with a buffer this library returned.
#[no_mangle]
pub unsafe extern "C-unwind" fn busbar_free(ptr: *mut u8, len: usize) {
    busbar_plugin_sdk::boundary::free_boundary(ptr, len)
}

/// # Safety
/// Called by the harness with a live handle, once.
#[no_mangle]
pub unsafe extern "C-unwind" fn busbar_close(handle: *mut c_void) {
    busbar_plugin_sdk::boundary::close_boundary::<BenchHandle>(handle)
}
