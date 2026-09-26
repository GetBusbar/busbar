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
/// All borrowed ranges (`config_*`, `resolved_refs_*`, `public_url_*`) MUST be live for the duration
/// of the `build` call; `host` MUST point at a live vtable that outlives the built plane.
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
    // ── appended at minor 23 ──
    /// Borrowed UTF-8 bytes of the deployment's PUBLIC base URL (the operator's `public_url:`), the
    /// origin a plane derives its admission audience from; NULL = the deployment states none.
    pub public_url_ptr: *const u8,
    /// Length of the public-URL range.
    pub public_url_len: usize,
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
/// Serialize what the built plane ANSWERS ON into a caller buffer; sets `out_written`. One claim per
/// line, `<METHOD> <path> <wire>` separated by single spaces (UTF-8, `\n`-terminated or not). Zero
/// bytes written = the plane mounts nothing this generation. Same buffer discipline as
/// [`AdminRoutesFn`].
pub type ClaimsFn = extern "C-unwind" fn(
    state: *mut c_void,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawStatus;
/// Serialize the admission facts the built plane binds into a caller buffer; sets `out_written`:
/// `<audience>\n<resource_metadata>` (UTF-8). Zero bytes written = the plane binds no audience (it
/// has no receiving side). Same buffer discipline as [`AdminRoutesFn`].
pub type AdmissionFn = extern "C-unwind" fn(
    state: *mut c_void,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> RawStatus;
/// Drive one [`WorkItem`](crate::hot::WorkItem) through the plane's dispatch. THE ingress entry point:
/// one signature carries every carrier shape via the work item's kind-tagged inbound/emit handles.
pub type DispatchFn =
    extern "C-unwind" fn(state: *mut c_void, work: *const crate::hot::WorkItem) -> RawStatus;

/// A borrowed UTF-8 range in a [`PlaneDecl`] — the `(ptr, len)` pair the vocabulary fields spell
/// out inline, as one `#[repr(C)]` value so a list of them can be borrowed too. A NULL `ptr` is the
/// ABSENT value (an optional fact the plane does not state); a non-null `ptr` is a stated string,
/// even when `len` is 0. Like every decl range it MUST point at bytes that outlive the decl.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeclStr {
    /// Borrowed UTF-8 bytes (NOT owned); NULL = absent.
    pub ptr: *const u8,
    /// Length of the range.
    pub len: usize,
}

impl DeclStr {
    /// The absent value: a NULL range.
    pub const NONE: DeclStr = DeclStr {
        ptr: core::ptr::null(),
        len: 0,
    };

    /// A stated string, borrowed for the life of the image.
    #[must_use]
    pub const fn new(s: &'static str) -> Self {
        DeclStr {
            ptr: s.as_ptr(),
            len: s.len(),
        }
    }
}

// SAFETY: a `DeclStr` is a borrowed range into the plugin image's own read-only bytes — the same
// lifetime contract (and the same reasoning) as the `*const u8` vocabulary fields of `PlaneDecl`
// below: mapped for the whole life of the loaded plugin, never mutated or freed while a decl that
// references them exists. A plane holds its lists of these in `static`s, which requires `Sync`.
unsafe impl Send for DeclStr {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DeclStr {}

/// One billable class a plane ledgers, and the unit family its count is in — borrowed in a list by
/// [`PlaneDecl::billable_classes_ptr`].
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeclBillableClass {
    /// The class string the plane's raw counts are keyed by.
    pub class: DeclStr,
    /// The unit family the class counts in.
    pub family: DeclStr,
}

/// One metric family a plane declares it emits through the host's `counter_add` — borrowed in a list
/// by [`PlaneDecl::metric_families_ptr`]. The host renders exactly this name and these label keys,
/// in this order, and decodes label values for a declared family only.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DeclMetricFamily {
    /// The series name exactly as it renders.
    pub name: DeclStr,
    /// The family's kind (`counter`).
    pub kind: DeclStr,
    /// Borrowed list of the label keys, in render order.
    pub label_keys_ptr: *const DeclStr,
    /// Number of entries in the label-keys list.
    pub label_keys_len: usize,
}

// SAFETY: the same borrowed-range contract as `DeclStr`: the name, kind and label-key list point
// into the plugin image's read-only bytes for its whole life. A plane holds these in `static`s.
unsafe impl Send for DeclMetricFamily {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DeclMetricFamily {}

/// The `#[repr(C)]` surface a plane exports for core to drive. Leads with the FROZEN [`AbiPreamble`]
/// and a sized/versioned header; carries the plane's vocabulary (borrowed name/section-key/scope/
/// label), the set of ingress carriers it provides, the fn-pointer slots, and — as its tail — the
/// rest of the plane's declaration (nouns, record kind, signing domain, scope kinds, owned sections,
/// billable classes, fee units). `None` slots are
/// absent capabilities (e.g. a plane with no admin surface leaves `admin_routes` `None` — but a plane
/// that DOES contribute admin routes MUST provide a non-vacuous impl).
///
/// # Safety / discipline
/// The vocabulary `(ptr, len)` ranges, every [`DeclStr`] and every borrowed list (and the strings
/// its entries borrow) MUST point at bytes that outlive the decl.
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

    // ── THE PLANE'S DECLARATION (appended at minor 22). Every fact a registered plane states about
    //    itself, so a dropped-in plane states the same declaration a linked one does and the host
    //    invents none of it. A decl that does not reach the end of this tail is refused at load. ──
    /// `1` for the one plane that declares itself the fallback catch-all, else `0`. Any other value
    /// is refused at load.
    pub fallback: u32,
    /// Alignment padding.
    pub _reserved2: u32,
    /// What one registration on this plane is called, in the words an operator reads back.
    pub subject_noun: DeclStr,
    /// The singular hyphenated noun for one registration in this plane's named-definition section.
    pub admin_noun: DeclStr,
    /// The record resource kind for a registration on this plane (and its action-word prefix).
    pub audit_kind: DeclStr,
    /// The versioned domain this plane's signing subkey is derived under; NULL = the plane signs
    /// nothing.
    pub signing_domain: DeclStr,
    /// The `kid` prefix this plane stamps on its signatures; NULL = the plane signs nothing.
    pub signing_kid_prefix: DeclStr,
    /// Borrowed list of the grant kinds that admit traffic on this plane, in declared order. When
    /// `scope` is non-empty it MUST lead this list; when it is empty this list MUST be empty.
    pub scope_kinds_ptr: *const DeclStr,
    /// Number of entries in the scope-kinds list.
    pub scope_kinds_len: usize,
    /// Borrowed list of the top-level config sections this plane owns the grammar of.
    pub owned_sections_ptr: *const DeclStr,
    /// Number of entries in the owned-sections list.
    pub owned_sections_len: usize,
    /// Borrowed list of the billable classes this plane ledgers.
    pub billable_classes_ptr: *const DeclBillableClass,
    /// Number of entries in the billable-classes list.
    pub billable_classes_len: usize,
    /// Borrowed list of the fee units this plane counts.
    pub fee_units_ptr: *const DeclStr,
    /// Number of entries in the fee-units list.
    pub fee_units_len: usize,

    // ── THE PLANE'S DOOR (appended at minor 23): what a BUILT plane answers on and who it admits,
    //    computed from its own state, so the host mounts and admits a dropped-in plane exactly as it
    //    does a linked one. ──
    /// The paths the built plane answers on (see [`ClaimsFn`]).
    pub claims: Option<ClaimsFn>,
    /// The audience the built plane binds (see [`AdmissionFn`]).
    pub admission: Option<AdmissionFn>,

    // ── THE PLANE'S METRIC FAMILIES (appended at minor 25): the families the plane adds to through
    //    the host's `counter_add`. A decl that ends before this tail declares none. ──
    /// Borrowed list of the metric families this plane emits.
    pub metric_families_ptr: *const DeclMetricFamily,
    /// Number of entries in the metric-families list.
    pub metric_families_len: usize,
}

// SAFETY: `PlaneDecl` holds `AbiPreamble` scalars, `Option<extern "C-unwind" fn>` slots — and,
// UNLIKE `PlaneHostVtable`, genuine raw-pointer fields (`name_ptr`, `section_key_ptr`, `scope_ptr`,
// `label_ptr`, the declaration's `DeclStr`s and its borrowed lists). Raw pointers are NOT auto-`Send`/`Sync`, so these hand-written impls are load-bearing
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
        fallback: 0,
        _reserved2: 0,
        subject_noun: DeclStr::NONE,
        admin_noun: DeclStr::NONE,
        audit_kind: DeclStr::NONE,
        signing_domain: DeclStr::NONE,
        signing_kid_prefix: DeclStr::NONE,
        scope_kinds_ptr: core::ptr::null(),
        scope_kinds_len: 0,
        owned_sections_ptr: core::ptr::null(),
        owned_sections_len: 0,
        billable_classes_ptr: core::ptr::null(),
        billable_classes_len: 0,
        fee_units_ptr: core::ptr::null(),
        fee_units_len: 0,
        claims: Some(stub::claims),
        admission: Some(stub::admission),
        metric_families_ptr: core::ptr::null(),
        metric_families_len: 0,
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
    pub extern "C-unwind" fn claims(
        _state: *mut c_void,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> RawStatus {
        unimplemented!("PlaneDecl::claims — stub")
    }
    /// Stub: see module docs.
    pub extern "C-unwind" fn admission(
        _state: *mut c_void,
        _buf: *mut u8,
        _buf_cap: usize,
        _out_written: *mut usize,
    ) -> RawStatus {
        unimplemented!("PlaneDecl::admission — stub")
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
/// real plane's `free` frees its own state this way; this generic one frees nothing concrete — it
/// only demonstrates the catch-guarded shape a real `Box::from_raw`/`drop` would sit inside.
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
