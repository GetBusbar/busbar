// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`PlaneDecl`] — the core→plane direction: the surface a plane EXPORTS so core can validate its
//! config, build it (with secrets PRE-RESOLVED to references), hydrate/start it, collect its admin
//! and OpenAPI contribution, and drive its ingress carriers via a [`WorkItem`](crate::hot::WorkItem)
//! `dispatch`.
//!
//! Same `#[repr(C)]` discipline as [`PlaneHostVtable`](super::host::PlaneHostVtable): a preamble, a
//! sized/versioned header, `extern "C-unwind"` fn-pointer slots, results into `&mut MaybeUninit<Out>`
//! or bytes-tier caller buffers. `build` yields an [`OpaqueHandle`] — a plane-allocated `*mut c_void`
//! plus a `free` fn — that core stores and NEVER downcasts.

use super::host::HostCtx;
use super::pod::RawStatus;
use super::PlaneHostVtable;
use crate::AbiPreamble;
use core::mem::MaybeUninit;
use std::os::raw::c_void;

/// The opaque, plane-owned handle `build`/`config_validate` produce: a `*mut c_void` the plane
/// allocated plus the `free` fn core calls on config swap. `free` MUST NEVER panic (wrap the body in
/// `catch_unwind`). Re-exported from [`pod`](super::pod) so both directions name one type.
pub type OpaqueHandle = super::pod::OpaqueState;

/// The ingress carrier shapes a plane may provide. RESERVES all five from day one even though only
/// three are wired — a `PlaneDecl` declares WHICH it provides via [`PlaneDecl::provided_carriers`],
/// and the host drives them uniformly. Adding a carrier is an append-only new variant + a minor bump.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressCarrier {
    /// A remote-initiated request expecting one reply. WIRED.
    RequestResponse = 0,
    /// A remote-initiated request expecting a streamed reply. WIRED.
    ResponseStream = 1,
    /// An independent in/out session (either side may originate; unsolicited pushes). WIRED.
    DuplexSession = 2,
    /// A host-initiated, reply-less pull. RESERVED (extension point).
    Subscription = 3,
    /// Many concurrent stateful sockets. RESERVED (extension point).
    AcceptLoop = 4,
}

impl IngressCarrier {
    /// The single-bit mask for this carrier in [`PlaneDecl::provided_carriers`].
    #[inline]
    #[must_use]
    pub const fn bit(self) -> u32 {
        1u32 << (self as u32)
    }
}

/// The build context handed to a plane's `build` fn. Secrets are ALREADY resolved to opaque
/// references (never plaintext); the plane holds refs and passes them to `egress_open`. Carries the
/// inbound [`PlaneHostVtable`] the plane will call back through, plus the validated config bytes.
///
/// # Safety / discipline
/// All borrowed ranges (`config_*`, `resolved_refs_*`) MUST be live for the duration of the `build`
/// call; `host` MUST point at a live vtable that outlives the built plane.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BuildCtx {
    /// `size_of::<BuildCtx>()` at construction (the sized-struct guard).
    pub size: u32,
    /// POD schema version.
    pub version: u16,
    /// Preamble tail padding.
    pub _reserved: u16,
    /// Preamble/alignment padding before the pointers.
    pub _reserved2: u32,
    /// The inbound capability vtable the built plane calls back through.
    pub host: *const PlaneHostVtable,
    /// The opaque host context threaded into every host call.
    pub host_ctx: HostCtx,
    /// Borrowed validated/parsed config bytes (NOT owned).
    pub config_ptr: *const u8,
    /// Length of the config range.
    pub config_len: usize,
    /// Borrowed array of PRE-RESOLVED credential/secret references (opaque u64s, NEVER plaintext).
    pub resolved_refs_ptr: *const u64,
    /// Number of entries in the resolved-refs array.
    pub resolved_refs_len: usize,
}

// ── core→plane fn-pointer signatures (cold/build-time; still `extern "C-unwind"`) ────────────────

/// Validate raw config bytes, producing a parsed opaque handle on Ok.
pub type ConfigValidateFn = extern "C-unwind" fn(
    raw_ptr: *const u8,
    raw_len: usize,
    out_parsed: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus;
/// Build the plane from a [`BuildCtx`] (secrets pre-resolved), producing the opaque plane handle.
pub type BuildFn = extern "C-unwind" fn(
    ctx: *const BuildCtx,
    out_handle: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus;
/// Hydrate persisted state into a built plane (idempotent).
pub type HydrateFn = extern "C-unwind" fn(state: *mut c_void) -> RawStatus;
/// Start the plane's ingress (begin accepting work).
pub type StartFn = extern "C-unwind" fn(state: *mut c_void) -> RawStatus;
/// Serialize the plane's admin-route contribution into a caller buffer; sets `out_written`. MUST be
/// NON-VACUOUS if the plane declares any admin surface (the non-vacuity invariant).
pub type AdminRoutesFn = extern "C-unwind" fn(
    state: *mut c_void,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawStatus;
/// Serialize the plane's OpenAPI contribution into a caller buffer; sets `out_written`. Subject to
/// the same non-vacuity invariant as [`AdminRoutesFn`].
pub type OpenApiFn = extern "C-unwind" fn(
    state: *mut c_void,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawStatus;
/// Drive one [`WorkItem`](crate::hot::WorkItem) through the plane's dispatch. THE ingress entry point:
/// one signature carries every carrier shape via the work item's kind-tagged inbound/emit handles.
pub type DispatchFn =
    extern "C-unwind" fn(state: *mut c_void, work: *const crate::hot::WorkItem) -> RawStatus;

/// The `#[repr(C)]` surface a plane exports for core to drive. Leads with the FROZEN [`AbiPreamble`]
/// and a sized/versioned header; carries the plane's vocabulary (borrowed name/section-key/scope/
/// label), the set of ingress carriers it provides, and the fn-pointer slots. `None` slots are
/// absent capabilities (e.g. a plane with no admin surface leaves `admin_routes` `None` — but a plane
/// that DOES contribute admin routes MUST provide a non-vacuous impl).
///
/// # Safety / discipline
/// The vocabulary `(ptr, len)` ranges MUST point at bytes that outlive the decl.
#[repr(C)]
pub struct PlaneDecl {
    /// The FROZEN airlock header — core `check_preamble`s it before using any slot.
    pub abi: AbiPreamble,
    /// `size_of::<PlaneDecl>()` at construction.
    pub size: u32,
    /// Decl schema version (bumped when a trailing slot/field is appended).
    pub version: u32,

    /// Borrowed plane name bytes (vocabulary; NOT owned).
    pub name_ptr: *const u8,
    /// Length of the name range.
    pub name_len: usize,
    /// Borrowed config section-key bytes (NOT owned).
    pub section_key_ptr: *const u8,
    /// Length of the section-key range.
    pub section_key_len: usize,
    /// Borrowed scope label bytes (NOT owned).
    pub scope_ptr: *const u8,
    /// Length of the scope range.
    pub scope_len: usize,
    /// Borrowed human label bytes (NOT owned).
    pub label_ptr: *const u8,
    /// Length of the label range.
    pub label_len: usize,

    /// Bitset of the [`IngressCarrier`]s this plane provides (OR of [`IngressCarrier::bit`]).
    pub provided_carriers: u32,
    /// Preamble/alignment padding.
    pub _reserved: u32,

    /// Validate raw config.
    pub config_validate: Option<ConfigValidateFn>,
    /// Build the plane (secrets pre-resolved).
    pub build: Option<BuildFn>,
    /// Hydrate persisted state.
    pub hydrate: Option<HydrateFn>,
    /// Start ingress.
    pub start: Option<StartFn>,
    /// Contribute admin routes (non-vacuous if present).
    pub admin_routes: Option<AdminRoutesFn>,
    /// Contribute OpenAPI (non-vacuous if present).
    pub openapi: Option<OpenApiFn>,
    /// Drive a work item through dispatch.
    pub dispatch: Option<DispatchFn>,
}

// SAFETY: `PlaneDecl` holds `AbiPreamble` scalars, `Option<extern "C-unwind" fn>` slots — and,
// UNLIKE `PlaneHostVtable`, genuine `*const u8` fields (`name_ptr`, `section_key_ptr`, `scope_ptr`,
// `label_ptr`). Raw pointers are NOT auto-`Send`/`Sync`, so these hand-written impls are load-bearing
// (they cannot be replaced by a compile-time auto-trait assertion the way the host vtable's were).
// The lifetime contract that makes them sound: every `*const u8` here points INTO the plugin image's
// own read-only vocabulary strings — bytes that are mapped for the whole life of the loaded plugin
// and never mutated or freed while any `PlaneDecl` referencing them exists. Core holds `&PlaneDecl`
// across `.await` and worker threads; the pointees outlive every such borrow because the image does.
unsafe impl Send for PlaneDecl {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for PlaneDecl {}

impl PlaneDecl {
    /// True iff this decl declares it provides `carrier`.
    #[inline]
    #[must_use]
    pub fn provides(&self, carrier: IngressCarrier) -> bool {
        self.provided_carriers & carrier.bit() != 0
    }

    /// A fully-populated STUB decl for one wired plane shape (request/response + response-stream +
    /// duplex-session), every slot an `unimplemented!()` stub. It PROVES the whole export surface
    /// type-checks; downstream agents replace the stubs with a real plane. Invoking any slot panics.
    pub const STUB: PlaneDecl = PlaneDecl {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneDecl>() as u32,
        version: crate::ABI_MINOR,
        name_ptr: core::ptr::null(),
        name_len: 0,
        section_key_ptr: core::ptr::null(),
        section_key_len: 0,
        scope_ptr: core::ptr::null(),
        scope_len: 0,
        label_ptr: core::ptr::null(),
        label_len: 0,
        provided_carriers: IngressCarrier::RequestResponse.bit()
            | IngressCarrier::ResponseStream.bit()
            | IngressCarrier::DuplexSession.bit(),
        _reserved: 0,
        config_validate: Some(stub::config_validate),
        build: Some(stub::build),
        hydrate: Some(stub::hydrate),
        start: Some(stub::start),
        admin_routes: Some(stub::admin_routes),
        openapi: Some(stub::openapi),
        dispatch: Some(stub::dispatch),
    };
}

/// The `unimplemented!()` stub plane exports backing [`PlaneDecl::STUB`]. Each has the EXACT
/// fn-pointer signature of its slot — the type-level proof the export surface compiles. A real plane
/// replaces each with an impl that runs INSIDE a `catch_unwind` and writes out-params only on Ok.
pub mod stub {
    use super::*;

    /// Stub: see module docs.
    pub extern "C-unwind" fn config_validate(
        _raw_ptr: *const u8,
        _raw_len: usize,
        _out_parsed: *mut MaybeUninit<OpaqueHandle>,
    ) -> RawStatus {
        unimplemented!("PlaneDecl::config_validate — stub; wired in a later phase")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn build(
        _ctx: *const BuildCtx,
        _out_handle: *mut MaybeUninit<OpaqueHandle>,
    ) -> RawStatus {
        unimplemented!("PlaneDecl::build — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn hydrate(_state: *mut c_void) -> RawStatus {
        unimplemented!("PlaneDecl::hydrate — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn start(_state: *mut c_void) -> RawStatus {
        unimplemented!("PlaneDecl::start — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn admin_routes(
        _state: *mut c_void,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> RawStatus {
        unimplemented!("PlaneDecl::admin_routes — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn openapi(
        _state: *mut c_void,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> RawStatus {
        unimplemented!("PlaneDecl::openapi — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn dispatch(
        _state: *mut c_void,
        _work: *const crate::hot::WorkItem,
    ) -> RawStatus {
        unimplemented!("PlaneDecl::dispatch — stub")
    }
}

/// An example of a NEVER-PANICS `free` fn for an [`OpaqueHandle`], reusing the boundary discipline:
/// the body runs inside a `catch_unwind` so a panicking `Drop` can never unwind across the seam. A
/// real plane's `free` frees its own state this way; this generic one drops a `Box<()>` placeholder.
///
/// # Safety
/// `ptr`, when non-null, must be exactly a pointer this plane's `build` produced and not yet freed.
pub extern "C-unwind" fn free_noop(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = std::panic::catch_unwind(|| {
        // A real plane: `drop(unsafe { Box::from_raw(ptr as *mut PlaneState) })`. The skeleton frees
        // nothing concrete; it only demonstrates the catch-guarded shape.
    });
}

#[cfg(test)]
#[path = "tests/decl_tests.rs"]
mod tests;
