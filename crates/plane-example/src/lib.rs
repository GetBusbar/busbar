// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: plane` plugin** — a `cdylib` exporting a real
//! [`busbar_plugin::hot::PlaneDecl`] over the HOT-tier ABI. It is the in-tree both-ways coverage for
//! the `kind: plane` seam (the ABI-fixture analogue of the other in-tree example plugin fixtures), and
//! the copy-me template a plane author exports through [`busbar_plugin_sdk::export_plane!`].
//!
//! ## STANDALONE ON PURPOSE
//!
//! Like the other in-tree example plugin fixtures, this crate names NO other plane: its whole
//! behaviour is in this file. It is a REAL, loadable plane — every slot is wired (no
//! `unimplemented!()`), every FFI body runs inside a `catch_unwind`, and every out-param is written
//! only on the `Ok` path — but its "work" is deliberately trivial (it counts the work items it is
//! handed) because its job is to prove the ABI round-trips a plane, not to serve a protocol.
//!
//! ## Both-ways by construction
//!
//! [`PLANE_DECL`] is a `pub static`, so the SAME decl is usable STATICALLY (a build depends on this
//! crate as a normal `lib` and hands `&PLANE_DECL` to a registry) OR DROPPED-IN (the `cdylib` the
//! [`export_plane!`](busbar_plugin_sdk::export_plane) symbols deliver, loaded by
//! `busbar_plugin_loader::load_plane`). The drop-in conformance test loads it BOTH ways and asserts
//! the two decls are byte-identical at the vocabulary/carrier/preamble surface — the plane's both-ways
//! proof over the ABI.

use busbar_plugin::hot::decl::{BuildCtx, IngressCarrier, OpaqueHandle};
use busbar_plugin::hot::pod::{OpaqueState, RawStatus, StatusClass};
use busbar_plugin::hot::{PlaneDecl, WorkItem};
use busbar_plugin::{write_out, AbiPreamble};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU64, Ordering};
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

// ── The plane's own vocabulary (borrowed by the decl; `'static` for the life of the image) ──────────
const NAME: &[u8] = b"example";
const SECTION_KEY: &[u8] = b"example";
const SCOPE: &[u8] = b"example";
const LABEL: &[u8] = b"Example Plane";

/// The parsed-config handle `config_validate` produces. Trivial (the example accepts any config), but
/// a REAL heap allocation so the `free` round-trip is exercised, not skipped.
struct ParsedConfig;

/// The built plane's live state: it counts the work items it has dispatched, proving `dispatch`
/// actually recovered the handle `build` produced and ran real state across the seam.
struct PlaneState {
    dispatched: AtomicU64,
}

/// NEVER-PANICS free for a [`ParsedConfig`] handle (the catch-guarded shape a real plane's `free`
/// uses). # Safety: `ptr`, when non-null, is exactly a handle `config_validate` produced.
extern "C-unwind" fn free_parsed(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ptr` was `Box::into_raw`'d from a `Box<ParsedConfig>` in `config_validate`.
        drop(unsafe { Box::from_raw(ptr as *mut ParsedConfig) });
    }));
}

/// NEVER-PANICS free for a [`PlaneState`] handle. # Safety: `ptr`, when non-null, is exactly a handle
/// `build` produced and not yet freed.
extern "C-unwind" fn free_state(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ptr` was `Box::into_raw`'d from a `Box<PlaneState>` in `build`.
        drop(unsafe { Box::from_raw(ptr as *mut PlaneState) });
    }));
}

/// `config_validate` — accept any raw config, producing an opaque parsed handle on `Ok`.
extern "C-unwind" fn config_validate(
    _raw_ptr: *const u8,
    _raw_len: usize,
    out_parsed: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        let handle = OpaqueState {
            ptr: Box::into_raw(Box::new(ParsedConfig)) as *mut c_void,
            free: Some(free_parsed),
        };
        // SAFETY: `out_parsed` is a caller MaybeUninit slot (or null, which `write_out` tolerates);
        // written only on the Ok path (init-only-on-Ok).
        unsafe { write_out(out_parsed, handle) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `build` — construct the plane from a [`BuildCtx`] (secrets pre-resolved), producing the opaque
/// plane handle core keeps and never downcasts. The example ignores the config/refs; it only proves
/// the handle round-trips.
extern "C-unwind" fn build(
    ctx: *const BuildCtx,
    out_handle: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if ctx.is_null() {
            return StatusClass::Refused;
        }
        let handle = OpaqueState {
            ptr: Box::into_raw(Box::new(PlaneState {
                dispatched: AtomicU64::new(0),
            })) as *mut c_void,
            free: Some(free_state),
        };
        // SAFETY: as `config_validate`.
        unsafe { write_out(out_handle, handle) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `hydrate` — no persisted state to restore (idempotent Ok).
extern "C-unwind" fn hydrate(state: *mut c_void) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() {
            StatusClass::Refused
        } else {
            StatusClass::Ok
        }
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `start` — nothing to begin (the example has no live ingress); idempotent Ok.
extern "C-unwind" fn start(state: *mut c_void) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() {
            StatusClass::Refused
        } else {
            StatusClass::Ok
        }
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `dispatch` — THE ingress entry point. Recovers the built [`PlaneState`], touches the work item's
/// inbound (proving the borrowed range crossed the seam), counts it, and returns `Ok`.
extern "C-unwind" fn dispatch(state: *mut c_void, work: *const WorkItem) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() || work.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `state` is a live `PlaneState` `build` produced; `work` is a live `WorkItem` for the
        // call (ABI dispatch discipline). Neither is mutated through a shared ref except the atomic.
        let st = unsafe { &*(state as *const PlaneState) };
        let w = unsafe { &*work };
        // Touch the inbound so a dropped `(ptr,len)` would be observable, not silently ignored.
        let inbound_len = w.inbound.len;
        let _ = inbound_len;
        st.dispatched.fetch_add(1, Ordering::Relaxed);
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// THE decl: the example plane's `#[repr(C)]` HOT-tier vtable. A `pub static` so it is BOTH the
/// compiled-in reference (linked as an `rlib`) AND, via [`export_plane!`](busbar_plugin_sdk::export_plane)
/// below, the dropped-in `cdylib` entrypoint's payload. Provides the request/response carrier; leaves
/// `admin_routes`/`openapi` `None` (the example contributes no admin/OpenAPI surface).
pub static PLANE_DECL: PlaneDecl = PlaneDecl {
    abi: AbiPreamble::CURRENT,
    size: core::mem::size_of::<PlaneDecl>() as u32,
    version: busbar_plugin::ABI_MINOR,
    name_ptr: NAME.as_ptr(),
    name_len: NAME.len(),
    section_key_ptr: SECTION_KEY.as_ptr(),
    section_key_len: SECTION_KEY.len(),
    scope_ptr: SCOPE.as_ptr(),
    scope_len: SCOPE.len(),
    label_ptr: LABEL.as_ptr(),
    label_len: LABEL.len(),
    provided_carriers: IngressCarrier::RequestResponse.bit(),
    _reserved: 0,
    config_validate: Some(config_validate),
    build: Some(build),
    hydrate: Some(hydrate),
    start: Some(start),
    admin_routes: None,
    openapi: None,
    dispatch: Some(dispatch),
};

// Emit the `cdylib` boundary symbols (`busbar_abi`, `busbar_plugin_kind() == "plane"`,
// `busbar_plane_decl()`), delivering `PLANE_DECL` as the dropped-in entrypoint's payload.
busbar_plugin_sdk::export_plane!(PLANE_DECL);
