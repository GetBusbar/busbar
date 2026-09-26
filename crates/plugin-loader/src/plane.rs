// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Runtime loading of a protocol **PLANE** from a `cdylib` over the busbar HOT-tier ABI
//! ([`busbar_plugin::hot`]) — the plane analogue of [`load_store`](crate::load_store).
//!
//! A plane cdylib rides the EXACT same tarball / signed-manifest / trust discovery pipeline as the
//! five cold kinds (it exports `busbar_abi` at [`TRANSPORT_VERSION`] and `busbar_plugin_kind() ==
//! "plane"`), but it does NOT speak the six-symbol JSON `call` wire. Instead it exports ONE extra
//! hot-lane symbol, [`busbar_plugin::hot::symbol::PLANE_DECL`] (`busbar_plane_decl`), returning a
//! pointer to its `#[repr(C)]` [`PlaneDecl`] vtable. [`load_plane`]/[`load_plane_from_bytes`] map the
//! library, run the transport + kind + AIRLOCK-preamble handshake, materialise the plane's borrowed
//! vocabulary into owned strings, and hand back a [`DynPlane`] the composition root drives exactly as
//! it drives a compiled-in `PlaneDecl` — the both-ways contract (`DECISIONS #2/#11/#26 S4`).
//!
//! # What this consumes, and what it does not
//!
//! This is the loader half of the hot lane. The host half is `busbar_kernel::plane_host`'s
//! `build_plane_host_vtable()` (44 of 44 slots over live core primitives), and the two are CROSSED:
//! `busbar-plugin-example-plane` is a real cdylib that, once built through [`DynPlane`], calls core's
//! own host slots back from the plugin side — `clock_now`, `govern_admit`, `meter_charge`,
//! `cost_reserve`, `cost_settle` — and REFUSES its work item if any of them is absent or answers
//! fail-closed. That crossing is asserted, per slot and by exact call count, in two places:
//! `src/tests/plane_conformance_tests.rs` (this crate's half, against an instrumented table) and
//! `crates/busbar-kernel/tests/plane_abi_rider.rs` (against the REAL vtable — unreachable from here,
//! because this crate may not name `busbar-kernel`). So `PlaneDecl` + [`PlaneHostVtable`] are no
//! longer the 0-caller ABI `docs/design/BUSBAR-1.6.0.md` §11a forbids.
//!
//! ONE ADMISSION, BOTH DOORS. A plane dropped into `plugins/` reaches the composition root as a
//! [`DynPlane`] through [`load_plane_from_bytes`]; the SAME plane linked into the binary reaches it as
//! a [`DynPlane`] through [`link_plane`] — the same airlock, the same size bound, the same vocabulary
//! reads, with no library behind it. The root adapts either onto the plane axis through one function
//! (`crates/busbar/src/root/linked.rs`, `register_planes`), so a registry row cannot tell which door
//! its plane came in by (#2 rule (1)). The DRIVE is the same too: [`DynPlane::serve`] builds either
//! into a [`ServedPlane`], whose `claims`, `admission` and `dispatch` slots are what the root mounts,
//! admits and serves through (minor 23) — one path over the HOT-lane vtable, whichever door.

use crate::stage;
use busbar_plugin::hot::decl::{
    AdminRoutesFn, AdmissionFn, BuildFn, ClaimsFn, ConfigValidateFn, DeclMetricFamily,
    DeclServedOpClass, DispatchFn, HydrateFn, OpenApiFn, StartFn,
};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::pod::{OpaqueState, RawStatus, StatusClass, POD_VERSION};
use busbar_plugin::hot::workitem::{EmitHandle, EmitKind, InboundHandle};
use busbar_plugin::hot::{
    BuildCtx, DeclBillableClass, DeclStr, IngressCarrier, PlaneDecl, PlaneDeclFn, PlaneHostVtable,
    WorkItem,
};
use busbar_plugin::{check_preamble, AbiPreamble};
use core::mem::MaybeUninit;
use libloading::Library;
use std::path::Path;

/// A protocol plane loaded from a `cdylib` over the HOT-tier ABI. Holds the mapped library alive for
/// as long as the plane lives (the `PlaneDecl` and every vocabulary string point INTO the image), and
/// unloads it on a plugin worker at [`Drop`] (unmapping runs the image's `.fini_array` — plugin code
/// — which must not run on a caller thread that may later retire; the same discipline `RawPlugin`
/// uses).
///
/// The borrowed vocabulary (`name`/`section_key`/`scope`/`label`) is COPIED to owned `String`s at
/// load, so callers read it without holding a raw pointer into the image; the fn-pointer slots are
/// read on demand through the sized-struct guard so a plane built against an OLDER airlock minor (a
/// shorter decl) reads a trailing slot it never wrote as ABSENT, never as bytes past its allocation.
pub struct DynPlane {
    /// The plane's own `PlaneDecl`, pointing into the mapped image. Read only through the sized guard.
    decl: *const PlaneDecl,
    /// The honoured decl `size` (peer-attested; an attestation past this build's
    /// `size_of::<PlaneDecl>()` is refused at load, never clamped).
    honoured_size: u32,
    /// The plane's canonical name (owned copy of the borrowed vocabulary).
    name: String,
    /// The plane's config section-key.
    section_key: String,
    /// The plane's scope label.
    scope: String,
    /// The plane's human label.
    label: String,
    /// The bitset of [`IngressCarrier`]s the plane declares it provides.
    provided_carriers: u32,
    /// The rest of the plane's declaration (the decl's minor-22 tail), owned.
    declaration: HotDeclaration,
    /// The plane name/path, for diagnostics.
    path: String,
    /// The mapped library. `Option` only so `Drop` can TAKE it and unload it on a plugin worker.
    /// Declared BEFORE `_backing` so the unload runs first (Windows' unload-then-remove order).
    _lib: Option<Library>,
    /// The staging backing (Linux memfd / private temp) for a from-bytes load; `None` for a path load.
    _backing: Option<stage::Staged>,
}

// SAFETY: `decl` is a `'static` pointer into a mapped image the plane guarantees is immutable for its
// life; every vocabulary string is copied out to owned `String`s at load, and the fn slots are plain
// code addresses. The host never mutates through `decl`. This mirrors `RawPlugin`'s hand impls.
unsafe impl Send for DynPlane {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DynPlane {}

impl Drop for DynPlane {
    fn drop(&mut self) {
        // Unload on a worker (dlclose runs the image's `.fini_array`), library before staged backing.
        if let Some(lib) = self._lib.take() {
            crate::dlclose_on_worker(lib);
        }
    }
}

impl std::fmt::Debug for DynPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynPlane")
            .field("name", &self.name)
            .field("section_key", &self.section_key)
            .field("scope", &self.scope)
            .field("provided_carriers", &self.provided_carriers)
            .field("declaration", &self.declaration)
            .field("path", &self.path)
            .finish()
    }
}

/// THE REST OF A HOT-LANE PLANE'S DECLARATION — every fact of a registered plane's declaration the
/// vocabulary fields do not carry, read off the decl's declaration tail into owned values. Nothing
/// here is defaulted: a decl that does not reach the end of the tail is refused at load, and each
/// field is what the plane stated (an optional fact the plane left NULL is `None`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotDeclaration {
    /// The plane declares itself the fallback catch-all.
    pub fallback: bool,
    /// What one registration on this plane is called.
    pub subject_noun: String,
    /// The singular hyphenated noun for one registration in its named-definition section.
    pub admin_noun: String,
    /// The record resource kind for a registration on this plane.
    pub audit_kind: String,
    /// The versioned domain the plane's signing subkey is derived under, if it signs.
    pub signing_domain: Option<String>,
    /// The `kid` prefix the plane stamps on its signatures, if it signs.
    pub signing_kid_prefix: Option<String>,
    /// The grant kinds that admit traffic on this plane, in declared order.
    pub scope_kinds: Vec<String>,
    /// The top-level config sections the plane owns the grammar of.
    pub owned_sections: Vec<String>,
    /// The billable classes the plane ledgers, each `(class, family)`.
    pub billable_classes: Vec<(String, String)>,
    /// The fee units the plane counts.
    pub fee_units: Vec<String>,
    /// The metric families the plane adds to through the host's `counter_add` (the minor-25 tail;
    /// empty for a decl that ends before it).
    pub metric_families: Vec<HotMetricFamily>,
    /// The operation classes the plane serves one level down, each `(class, display name)` (the
    /// minor-27 tail; empty for a decl that ends before it).
    pub served_op_classes: Vec<(String, String)>,
    /// The plane-record kinds the plane keeps (the minor-29 tail; empty for a decl that ends
    /// before it).
    pub record_kinds: Vec<String>,
}

/// One metric family a HOT-lane plane declares, read off its decl into owned values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotMetricFamily {
    /// The series name exactly as it renders.
    pub name: String,
    /// The family's kind.
    pub kind: String,
    /// The label keys, in render order.
    pub label_keys: Vec<String>,
}

impl DynPlane {
    /// The plane's canonical name (its vocabulary `name`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The plane's config section-key.
    #[must_use]
    pub fn section_key(&self) -> &str {
        &self.section_key
    }
    /// The plane's scope label.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
    /// The plane's human label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    /// The raw bitset of [`IngressCarrier`]s the plane declares.
    #[must_use]
    pub fn provided_carriers(&self) -> u32 {
        self.provided_carriers
    }
    /// Whether the plane declares it provides `carrier`.
    #[must_use]
    pub fn provides(&self, carrier: IngressCarrier) -> bool {
        self.provided_carriers & carrier.bit() != 0
    }
    /// The rest of the plane's declaration, exactly as the decl states it.
    #[must_use]
    pub fn declaration(&self) -> &HotDeclaration {
        &self.declaration
    }

    // ── Slot readers: pull one `Option<fn>` slot out of the decl through the sized-struct guard.
    //    `Some(fn)` = the plane WROTE this slot (its attested `size` covers it); `None` = absent (an
    //    older-minor plane that never had the slot, or one that left it `None`). The decl-side
    //    analogue of `host_slot!` — `read_sized_field!` yields `Option<Option<fn>>`, flattened. ──
    fn slot_config_validate(&self) -> Option<ConfigValidateFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, config_validate)
            .flatten()
    }
    fn slot_build(&self) -> Option<BuildFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, build).flatten()
    }
    fn slot_hydrate(&self) -> Option<HydrateFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, hydrate)
            .flatten()
    }
    fn slot_start(&self) -> Option<StartFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, start).flatten()
    }
    fn slot_dispatch(&self) -> Option<DispatchFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, dispatch)
            .flatten()
    }
    fn slot_admin_routes(&self) -> Option<AdminRoutesFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, admin_routes)
            .flatten()
    }
    fn slot_openapi(&self) -> Option<OpenApiFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, openapi)
            .flatten()
    }
    fn slot_claims(&self) -> Option<ClaimsFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, claims).flatten()
    }
    fn slot_admission(&self) -> Option<AdmissionFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, PlaneDecl, admission)
            .flatten()
    }

    /// [`config_validate`](Self::config_validate), with the parsed handle OWNED: it is freed through
    /// the plane's own `free` when the returned [`PlaneState`] drops, and it cannot outlive this
    /// plane (the borrow), so it can never be freed into an unmapped image.
    pub fn config_validate_owned(&self, raw: &[u8]) -> (StatusClass, Option<PlaneState<'_>>) {
        let (class, state) = self.config_validate(raw);
        (class, state.map(|raw| PlaneState { plane: self, raw }))
    }

    /// Drive the plane's `config_validate` over raw config bytes, catching any panic across the seam.
    /// Returns the plane-produced [`StatusClass`] and, on `Ok`, the parsed [`OpaqueState`] handle.
    ///
    /// The raw handle is the CALLER's to free, through its own `free`, before this plane drops;
    /// [`config_validate_owned`](Self::config_validate_owned) does that for you.
    pub fn config_validate(&self, raw: &[u8]) -> (StatusClass, Option<OpaqueState>) {
        let Some(f) = self.slot_config_validate() else {
            return (StatusClass::Unsupported, None);
        };
        let mut out = MaybeUninit::<OpaqueState>::uninit();
        let raw_ptr = raw.as_ptr();
        let raw_len = raw.len();
        let out_ptr: *mut MaybeUninit<OpaqueState> = &mut out;
        // Confined: a per-LOAD crossing, the parse half of the plane's constructor (see `build`).
        match crate::ffi_guard_confined(&self.path, "plane_config_validate", || {
            #[cfg(test)]
            tests_decl::note_thread();
            f(raw_ptr, raw_len, out_ptr)
        }) {
            Ok(status) => {
                let class = status.class();
                if class == StatusClass::Ok {
                    // SAFETY: init-only-on-Ok — the plane wrote `out` before returning `Ok`.
                    (class, Some(unsafe { out.assume_init() }))
                } else {
                    (class, None)
                }
            }
            Err(_) => (StatusClass::Fault, None),
        }
    }

    /// [`build`](Self::build), with the plane state OWNED: freed through the plane's own `free` when
    /// the returned [`PlaneState`] drops, and borrow-bound to this plane so it can never outlive the
    /// mapped image its `ptr` and `free` point into.
    ///
    /// # Safety
    /// As [`build`](Self::build).
    pub unsafe fn build_owned(
        &self,
        host: *const PlaneHostVtable,
        host_ctx: HostCtx,
        config: &[u8],
        resolved_refs: &[u64],
    ) -> (StatusClass, Option<PlaneState<'_>>) {
        // SAFETY: forwarded from this fn's own contract.
        let (class, state) = unsafe { self.build(host, host_ctx, config, resolved_refs) };
        (class, state.map(|raw| PlaneState { plane: self, raw }))
    }

    /// BUILD the plane from `config` + PRE-RESOLVED secret `resolved_refs`, threading `host` +
    /// `host_ctx` (the [`PlaneHostVtable`] the built plane calls back through). Returns the plane's
    /// [`StatusClass`] and, on `Ok`, the opaque plane [`OpaqueState`] handle core stores and never
    /// downcasts. A caught panic fails closed (`Fault`, no handle). The raw handle is the CALLER's to
    /// free before this plane drops; [`build_owned`](Self::build_owned) does that for you.
    ///
    /// # Safety
    /// `host`, when non-null, must point at a live [`PlaneHostVtable`] that outlives the built plane
    /// (the vtable's `check` guarantees the shape); `host_ctx` is the opaque context the host recovers.
    pub unsafe fn build(
        &self,
        host: *const PlaneHostVtable,
        host_ctx: HostCtx,
        config: &[u8],
        resolved_refs: &[u64],
    ) -> (StatusClass, Option<OpaqueState>) {
        // SAFETY: forwarded from this fn's own contract.
        unsafe { self.build_at(host, host_ctx, config, resolved_refs, None) }
    }

    /// [`build`](Self::build), stating the deployment's public URL in the build context.
    ///
    /// # Safety
    /// As [`build`](Self::build).
    unsafe fn build_at(
        &self,
        host: *const PlaneHostVtable,
        host_ctx: HostCtx,
        config: &[u8],
        resolved_refs: &[u64],
        public_url: Option<&str>,
    ) -> (StatusClass, Option<OpaqueState>) {
        let Some(f) = self.slot_build() else {
            return (StatusClass::Unsupported, None);
        };
        let ctx = BuildCtx {
            size: core::mem::size_of::<BuildCtx>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            _reserved2: 0,
            host,
            host_ctx,
            config_ptr: config.as_ptr(),
            config_len: config.len(),
            resolved_refs_ptr: resolved_refs.as_ptr(),
            resolved_refs_len: resolved_refs.len(),
            public_url_ptr: public_url.map_or(core::ptr::null(), str::as_ptr),
            public_url_len: public_url.map_or(0, str::len),
        };
        let mut out = MaybeUninit::<OpaqueState>::uninit();
        let ctx_ptr: *const BuildCtx = &ctx;
        let out_ptr: *mut MaybeUninit<OpaqueState> = &mut out;
        // CONFINED, like the cold lane's `busbar_open`: `build` is the plane's CONSTRUCTOR, the
        // per-load crossing where a plane first arms a thread_local with a destructor. Run inline, it
        // would arm it on a caller thread that may retire after this image is unmapped (`ffi_thread`).
        // `hydrate`/`start`/`dispatch` stay on the caller's thread: they run against the BUILT plane,
        // whose host calls are recovered through a `HostCtx` generation that is live only on the
        // thread that minted it, so moving them to a worker would refuse every host crossing.
        match crate::ffi_guard_confined(&self.path, "plane_build", || {
            #[cfg(test)]
            tests_decl::note_thread();
            f(ctx_ptr, out_ptr)
        }) {
            Ok(status) => {
                let class = status.class();
                if class == StatusClass::Ok {
                    // SAFETY: init-only-on-Ok — the plane wrote `out` before returning `Ok`.
                    (class, Some(unsafe { out.assume_init() }))
                } else {
                    (class, None)
                }
            }
            Err(_) => (StatusClass::Fault, None),
        }
    }

    /// HYDRATE persisted state into a built plane (idempotent). `state` is the `ptr` an `Ok`
    /// [`build`](Self::build) produced. A caught panic fails closed (`Fault`).
    ///
    /// # Safety
    /// `state` must be a live plane state pointer this plane's `build` produced and not yet freed.
    pub unsafe fn hydrate(&self, state: *mut std::os::raw::c_void) -> StatusClass {
        self.drive_state("plane_hydrate", state, DynPlane::slot_hydrate)
    }

    /// START the plane's ingress (begin accepting work). Fail-closed on a caught panic (`Fault`).
    ///
    /// # Safety
    /// `state` must be a live plane state pointer this plane's `build` produced and not yet freed.
    pub unsafe fn start(&self, state: *mut std::os::raw::c_void) -> StatusClass {
        self.drive_state("plane_start", state, DynPlane::slot_start)
    }

    /// DISPATCH one [`WorkItem`] through the plane (THE ingress entry point). Returns the plane's
    /// [`StatusClass`]; a caught panic fails closed (`Fault`).
    ///
    /// # Safety
    /// `state` must be a live plane state pointer; `work`'s borrowed inbound range must outlive the
    /// call (the ABI dispatch discipline).
    pub unsafe fn dispatch(
        &self,
        state: *mut std::os::raw::c_void,
        work: &WorkItem,
    ) -> StatusClass {
        let Some(f) = self.slot_dispatch() else {
            return StatusClass::Unsupported;
        };
        let work_ptr: *const WorkItem = work;
        match crate::ffi_guard(&self.path, "plane_dispatch", || f(state, work_ptr)) {
            Ok(status) => status.class(),
            Err(_) => StatusClass::Fault,
        }
    }

    /// The plane's ADMIN-ROUTE contribution, read through its `admin_routes` slot. `Ok(None)` = the
    /// plane declares no admin surface (slot absent). A present slot must honour the decl's
    /// non-vacuity invariant: an empty answer, a non-`Ok` status, a caught panic or a claimed length
    /// past the buffer is refused, never read as "no routes".
    ///
    /// # Safety
    /// `state` must be a live plane state pointer this plane's `build` produced and not yet freed.
    pub unsafe fn admin_routes(
        &self,
        state: *mut std::os::raw::c_void,
    ) -> Result<Option<Vec<u8>>, String> {
        match self.slot_admin_routes() {
            None => Ok(None),
            Some(f) => self.contribution("plane_admin_routes", state, f).map(Some),
        }
    }

    /// The plane's OPENAPI contribution, read through its `openapi` slot — the same contract as
    /// [`admin_routes`](Self::admin_routes).
    ///
    /// # Safety
    /// As [`admin_routes`](Self::admin_routes).
    pub unsafe fn openapi(
        &self,
        state: *mut std::os::raw::c_void,
    ) -> Result<Option<Vec<u8>>, String> {
        match self.slot_openapi() {
            None => Ok(None),
            Some(f) => self.contribution("plane_openapi", state, f).map(Some),
        }
    }

    /// Shared body of the two serialize-into-a-caller-buffer slots (`AdminRoutesFn` and `OpenApiFn`
    /// share one signature).
    fn contribution(
        &self,
        op: &str,
        state: *mut std::os::raw::c_void,
        f: AdminRoutesFn,
    ) -> Result<Vec<u8>, String> {
        let mut buf = vec![0u8; MAX_PLANE_CONTRIBUTION_LEN];
        let mut written = 0usize;
        let (buf_ptr, cap) = (buf.as_mut_ptr(), buf.len());
        let written_ptr: *mut usize = &mut written;
        let status =
            crate::ffi_guard_confined(&self.path, op, || f(state, buf_ptr, cap, written_ptr))?
                .class();
        let path = &self.path;
        if status != StatusClass::Ok {
            return Err(format!("plane '{path}' {op} answered {status:?}"));
        }
        if written == 0 {
            return Err(format!(
                "plane '{path}' {op} slot is present but wrote nothing — a declared contribution \
                 must be non-vacuous"
            ));
        }
        if written > cap {
            return Err(format!(
                "plane '{path}' {op} claims {written} bytes written into a {cap}-byte buffer"
            ));
        }
        buf.truncate(written);
        Ok(buf)
    }

    /// A `claims`/`admission` answer: the slot's bytes as UTF-8. Unlike a [`contribution`](Self::contribution)
    /// an empty answer is a valid one; a non-`Ok` status, a caught panic, a claimed length past the
    /// buffer or non-UTF-8 bytes are refused.
    fn answer(
        &self,
        op: &str,
        state: *mut std::os::raw::c_void,
        f: ClaimsFn,
    ) -> Result<String, String> {
        let mut buf = vec![0u8; MAX_PLANE_CONTRIBUTION_LEN];
        let mut written = 0usize;
        let (buf_ptr, cap) = (buf.as_mut_ptr(), buf.len());
        let written_ptr: *mut usize = &mut written;
        let status =
            crate::ffi_guard(&self.path, op, || f(state, buf_ptr, cap, written_ptr))?.class();
        let path = &self.path;
        if status != StatusClass::Ok {
            return Err(format!("plane '{path}' {op} answered {status:?}"));
        }
        if written > cap {
            return Err(format!(
                "plane '{path}' {op} claims {written} bytes written into a {cap}-byte buffer"
            ));
        }
        buf.truncate(written);
        String::from_utf8(buf).map_err(|_| format!("plane '{path}' {op} answered non-UTF-8 bytes"))
    }

    /// Shared shape for the two `fn(*mut c_void) -> RawStatus` boot hooks (`hydrate`/`start`).
    unsafe fn drive_state(
        &self,
        op: &str,
        state: *mut std::os::raw::c_void,
        pick: impl FnOnce(&Self) -> Option<extern "C-unwind" fn(*mut std::os::raw::c_void) -> RawStatus>,
    ) -> StatusClass {
        let Some(f) = pick(self) else {
            return StatusClass::Unsupported;
        };
        match crate::ffi_guard(&self.path, op, || f(state)) {
            Ok(status) => status.class(),
            Err(_) => StatusClass::Fault,
        }
    }
}

impl DynPlane {
    /// BUILD this plane to SERVE one config generation: its `build` slot, handed `host` (the host's
    /// `'static` vtable, which outlives the built plane as the `build` contract requires), the plane's
    /// raw config `section` bytes and the deployment's `public_url`. The built state is OWNED by the
    /// returned [`ServedPlane`] and freed through the plane's own `free` when it drops. No host call
    /// is live at build, so the build context carries the null `HostCtx`; every dispatch is handed
    /// the one minted for it.
    pub fn serve(
        &'static self,
        host: &'static PlaneHostVtable,
        section: &[u8],
        public_url: Option<&str>,
    ) -> Result<ServedPlane, String> {
        // SAFETY: `host` is a live `'static` vtable, so it outlives the built plane.
        let (class, state) =
            unsafe { self.build_at(host, HostCtx::NULL, section, &[], public_url) };
        match state {
            Some(raw) if class == StatusClass::Ok => Ok(ServedPlane { plane: self, raw }),
            _ => Err(format!("plane '{}' did not build: {class:?}", self.path)),
        }
    }
}

/// A HOT-lane plane BUILT for one config generation: the `'static` plane and the state its `build`
/// produced, owned. It is what the host mounts ([`claims`](Self::claims)), admits
/// ([`admission`](Self::admission)) and drives ([`dispatch`](Self::dispatch)) — the same three calls
/// for a linked plane and a dropped-in one, because both are a [`DynPlane`].
pub struct ServedPlane {
    plane: &'static DynPlane,
    raw: OpaqueState,
}

// SAFETY: the plane-state handle is `Send + Sync` by the ABI's own soundness rule (the plane seam's
// "opaque plane-state handle `Send+Sync`"): a plane's `claims`/`admission`/`dispatch` may be called
// from any thread, concurrently, and its state synchronises itself (the example plane's counters are
// atomics). The host never dereferences the handle; it only hands it back to the plane.
unsafe impl Send for ServedPlane {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for ServedPlane {}

/// One path a built plane answers on, as its `claims` slot states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotClaim {
    /// The HTTP method, upper-case.
    pub method: String,
    /// The exact path.
    pub path: String,
    /// The wire format the path is spoken in.
    pub wire: String,
}

impl ServedPlane {
    /// The plane this state was built from.
    #[must_use]
    pub fn plane(&self) -> &'static DynPlane {
        self.plane
    }

    /// What the built plane answers on, read through its `claims` slot. An absent slot or an empty
    /// answer claims nothing; a non-`Ok` status, a caught panic, an overlong answer or a line that
    /// is not `<METHOD> <path> <wire>` is refused, never read as "no claims".
    pub fn claims(&self) -> Result<Vec<HotClaim>, String> {
        let Some(f) = self.plane.slot_claims() else {
            return Ok(Vec::new());
        };
        let text = self.plane.answer("plane_claims", self.raw.ptr, f)?;
        text.lines()
            .filter(|line| !line.is_empty())
            .map(|line| match line.split(' ').collect::<Vec<_>>()[..] {
                [method, path, wire] if !method.is_empty() && path.starts_with('/') => {
                    Ok(HotClaim {
                        method: method.to_string(),
                        path: path.to_string(),
                        wire: wire.to_string(),
                    })
                }
                _ => Err(format!(
                    "plane '{}' claims `{line}`, not `<METHOD> <path> <wire>`",
                    self.plane.path
                )),
            })
            .collect()
    }

    /// The audience the built plane binds and its resource-metadata URL, read through its
    /// `admission` slot; `None` = it binds none. Refused on the same terms as [`claims`](Self::claims),
    /// and when the answer is not exactly two lines.
    pub fn admission(&self) -> Result<Option<(String, String)>, String> {
        let Some(f) = self.plane.slot_admission() else {
            return Ok(None);
        };
        let text = self.plane.answer("plane_admission", self.raw.ptr, f)?;
        if text.is_empty() {
            return Ok(None);
        }
        match text.split('\n').collect::<Vec<_>>()[..] {
            [audience, metadata] if !audience.is_empty() => {
                Ok(Some((audience.to_string(), metadata.to_string())))
            }
            _ => Err(format!(
                "plane '{}' admission is not `<audience>\\n<resource_metadata>`",
                self.plane.path
            )),
        }
    }

    /// DISPATCH one request-response work item: `inbound` as the finite buffer, a reply channel of
    /// [`MAX_PLANE_REPLY_LEN`] bytes, and the dispatch's own `host` + `host_ctx` (minted for this
    /// call; the plane calls back through them). Returns the plane's status and the reply it wrote;
    /// a caught panic fails closed (`Fault`, no reply), and a claimed reply length past the channel
    /// is a `Fault`.
    pub fn dispatch(
        &self,
        host: &PlaneHostVtable,
        host_ctx: HostCtx,
        inbound: &[u8],
    ) -> (StatusClass, Vec<u8>) {
        // The channel is reserved, not zeroed: the plane writes into it and the host reads back only
        // the prefix the plane says it wrote.
        let mut reply: Vec<u8> = Vec::with_capacity(MAX_PLANE_REPLY_LEN);
        let mut written = 0usize;
        let mut work = WorkItem::new(
            InboundHandle::finite_buffer(inbound),
            EmitHandle::new(EmitKind::Reply, 0),
        )
        .with_host(host, host_ctx);
        work.reply_ptr = reply.as_mut_ptr();
        work.reply_cap = reply.capacity();
        work.reply_written = &mut written;
        // SAFETY: `raw.ptr` is the live state this plane's `build` produced (owned by `self`); every
        // borrow the work item carries (`inbound`, `host`, the reply channel) outlives the call.
        let class = unsafe { self.plane.dispatch(self.raw.ptr, &work) };
        if written > reply.capacity() {
            return (StatusClass::Fault, Vec::new());
        }
        // SAFETY: the plane initialized the first `written` bytes of the channel (the reply
        // discipline), and `written` is within the reserved capacity (checked above).
        unsafe { reply.set_len(written) };
        (class, reply)
    }
}

impl std::fmt::Debug for ServedPlane {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServedPlane")
            .field("plane", &self.plane.name)
            .finish()
    }
}

impl Drop for ServedPlane {
    fn drop(&mut self) {
        // The same guarded, confined teardown an owned `PlaneState` runs.
        drop(PlaneState {
            plane: self.plane,
            raw: OpaqueState {
                ptr: self.raw.ptr,
                free: self.raw.free,
            },
        });
    }
}

/// Cap on one dispatch's reply: the channel the host hands the plane.
const MAX_PLANE_REPLY_LEN: usize = 1024 * 1024;

/// A plane handle (`config_validate`'s parsed config or `build`'s plane state) OWNED by the host.
///
/// Borrows the [`DynPlane`] it came from, so it cannot outlive the mapped image its `ptr` and `free`
/// point into; on drop it runs the plane's own `free` — confined like every other per-load teardown
/// crossing (`busbar_close`) and guarded, so a panicking `free` leaks the state rather than aborting.
pub struct PlaneState<'p> {
    plane: &'p DynPlane,
    raw: OpaqueState,
}

impl PlaneState<'_> {
    /// The plane state pointer, to pass to `hydrate`/`start`/`dispatch`/`admin_routes`/`openapi`.
    #[must_use]
    pub fn ptr(&self) -> *mut std::os::raw::c_void {
        self.raw.ptr
    }
}

impl std::fmt::Debug for PlaneState<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneState")
            .field("plane", &self.plane.name)
            .field("ptr", &self.raw.ptr)
            .finish()
    }
}

impl Drop for PlaneState<'_> {
    fn drop(&mut self) {
        let (Some(free), ptr) = (self.raw.free, self.raw.ptr) else {
            return;
        };
        if ptr.is_null() {
            return;
        }
        if crate::ffi_guard_confined(&self.plane.path, "plane_free", || free(ptr)).is_err() {
            tracing::warn!(
                plugin = %self.plane.path,
                "plane state free panicked; leaking the state to keep the engine alive"
            );
        }
    }
}

/// Cap on one `admin_routes`/`openapi` contribution: the buffer the host hands the slot. A route
/// table or an OpenAPI fragment is kilobytes; a plane that needs more than this is refused rather
/// than handed an unbounded allocation.
const MAX_PLANE_CONTRIBUTION_LEN: usize = 1024 * 1024;

/// Load a plane from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint; see
/// [`load_store_from_bytes`](crate::load_store_from_bytes) for the staging contract). `manifest_kind`
/// is the trust-verified signed-manifest `kind`, cross-checked against `busbar_plugin_kind()`.
pub fn load_plane_from_bytes(
    bytes: &[u8],
    display: &str,
    manifest_kind: &str,
) -> Result<DynPlane, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    wire_up_plane(lib, display.to_string(), manifest_kind, Some(staged))
}

/// Admit a plane LINKED into this binary through exactly the admission a dropped-in one gets: the
/// frozen preamble, the attested-size bound and the capped vocabulary reads of [`assemble`], over
/// the plane's own `'static` decl rather than one resolved out of a mapped library. The composition
/// root adapts the result through the same function it adapts a dropped-in [`DynPlane`] through, so
/// the two doors cannot disagree about what a plane declares.
pub fn link_plane(decl: &'static PlaneDecl, display: &str) -> Result<DynPlane, String> {
    assemble(decl, display.to_string(), None, None)
}

/// Load a plane from the `cdylib` at `lib_path`. A bare path load has no signed manifest, so the
/// seam's expected kind (`plane`) is the authority (the exported-kind gate still enforces it). The
/// trust-verified [`load_plane_from_bytes`] is the real gate for a dropped-in tarball.
#[cold]
#[inline(never)]
pub fn load_plane(lib_path: &Path) -> Result<DynPlane, String> {
    let display = lib_path.display().to_string();
    // SAFETY: an operator-placed library is inherently trusted (its init code runs), like a
    // compiled-in plane. The path comes from config/the plugins dir, never the request path.
    let lib = crate::dlopen_on_worker(lib_path.as_os_str())
        .map_err(|e| format!("failed to load plane '{display}': {e}"))?;
    wire_up_plane(lib, display, busbar_plugin::cold::kind::PLANE, None)
}

/// Resolve + validate a mapped plane library against the frozen contract (transport handshake, kind
/// == `plane` == manifest kind, then the AIRLOCK preamble on the decl), materialise its vocabulary,
/// and assemble a [`DynPlane`]. The plane analogue of `wire_up_raw`.
fn wire_up_plane(
    lib: Library,
    display: String,
    manifest_kind: &str,
    backing: Option<stage::Staged>,
) -> Result<DynPlane, String> {
    // ── 1. Transport handshake FIRST (shared with the cold kinds). ──
    let transport = {
        let f = unsafe { lib.get::<busbar_plugin::cold::AbiFn>(busbar_plugin::cold::symbol::ABI) }
            .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        crate::ffi_guard_confined(&display, "abi", || unsafe { (*f)() })?
    };
    if transport != busbar_plugin::cold::TRANSPORT_VERSION {
        return Err(format!(
            "plane '{display}' targets transport ABI v{transport}, engine speaks v{}",
            busbar_plugin::cold::TRANSPORT_VERSION
        ));
    }

    // ── 2. Kind bound at load — exported kind must be `plane` AND equal the signed manifest kind. ──
    let exported_kind = crate::read_plugin_kind(&lib, &display)?;
    if exported_kind != busbar_plugin::cold::kind::PLANE {
        return Err(format!(
            "plane '{display}' exports kind '{exported_kind}', not 'plane'"
        ));
    }
    if exported_kind != manifest_kind {
        return Err(format!(
            "plane '{display}' kind mismatch: exported symbol says '{exported_kind}', signed \
             manifest says '{manifest_kind}' — refusing to load"
        ));
    }

    // ── 3. Resolve the ONE hot-lane entrypoint and read the decl pointer (guarded). ──
    let decl_ptr = {
        let f = unsafe { lib.get::<PlaneDeclFn>(busbar_plugin::hot::symbol::PLANE_DECL) }
            .map_err(|_| format!("plane '{display}' missing busbar_plane_decl symbol"))?;
        crate::ffi_guard_confined(&display, "plane_decl", || unsafe { (*f)() })?
    };
    assemble(decl_ptr, display, Some(lib), backing)
}

/// Admit a plane's decl and materialise it: refuse a null pointer, check the FROZEN preamble and the
/// attested size, copy the vocabulary out. Everything `wire_up_plane` does after it has the decl
/// pointer, split out so the admission rules are testable over an in-memory decl.
fn assemble(
    decl_ptr: *const PlaneDecl,
    display: String,
    lib: Option<Library>,
    backing: Option<stage::Staged>,
) -> Result<DynPlane, String> {
    if decl_ptr.is_null() {
        return Err(format!("plane '{display}' returned a null PlaneDecl"));
    }

    // ── AIRLOCK: check the FROZEN preamble WITHOUT forming a `&PlaneDecl` over a possibly-shorter
    //    peer allocation (read `abi` + `size` unaligned by address, exactly as `PlaneHostVtable::check`
    //    does), then bound the attested size on BOTH sides. ──
    // SAFETY: `decl_ptr` is a non-null pointer to at least the leading prefix of a `PlaneDecl` (the
    // plane's `'static` decl); `addr_of!` computes addresses only and `read_unaligned` assumes no
    // alignment the peer did not promise.
    let (abi, advertised): (AbiPreamble, u32) = unsafe {
        (
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl_ptr).abi)),
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl_ptr).size)),
        )
    };
    check_preamble(&abi).map_err(|e| {
        format!(
            "plane '{display}' decl preamble refused: {e:?} (rebuild it against this busbar ABI)"
        )
    })?;
    let ours = core::mem::size_of::<PlaneDecl>() as u32;
    // Minimum size that can carry the frozen header + vocabulary + carriers (offset THROUGH
    // `provided_carriers`). A decl that does not even reach the carriers cannot describe a plane.
    let min =
        (core::mem::offset_of!(PlaneDecl, provided_carriers) + core::mem::size_of::<u32>()) as u32;
    if advertised < min {
        return Err(format!(
            "plane '{display}' decl attests size {advertised}, below the {min}-byte vocabulary \
             header — it cannot describe a PlaneDecl"
        ));
    }
    // And THROUGH the declaration tail: a decl built before the tail existed states no declaration,
    // and the host installs a plane only with the declaration the plane stated — never one invented
    // for it — so such a decl is refused, not defaulted.
    let declared =
        (core::mem::offset_of!(PlaneDecl, fee_units_len) + core::mem::size_of::<usize>()) as u32;
    if advertised < declared {
        return Err(format!(
            "plane '{display}' decl attests size {advertised}, below the {declared}-byte \
             declaration — it states no plane declaration; rebuild it against this busbar ABI minor"
        ));
    }
    // REFUSED, not clamped — the same answer `PlaneHostVtable::check` gives the host table
    // (`VtableRefusal::SizeOverBuild`). The decl's trailing members are fn-pointer SLOTS this side
    // CALLS, and a size claim past this build's struct is unverifiable: a decl that really ends
    // early but stamps a wild size would have its missing slots read from whatever follows it.
    if advertised > ours {
        return Err(format!(
            "plane '{display}' decl attests size {advertised}, exceeding this build's own \
             PlaneDecl ({ours} bytes); this build has no definition for the extra bytes and will \
             not call a slot it cannot describe — rebuild the plane against this busbar ABI minor"
        ));
    }
    let honoured_size = advertised;

    // ── Materialise the borrowed vocabulary into owned strings (read through the sized guard). ──
    let name = read_vocab(decl_ptr, honoured_size, Vocab::Name, &display)?;
    let section_key = read_vocab(decl_ptr, honoured_size, Vocab::SectionKey, &display)?;
    let scope = read_vocab(decl_ptr, honoured_size, Vocab::Scope, &display)?;
    let label = read_vocab(decl_ptr, honoured_size, Vocab::Label, &display)?;
    let provided_carriers =
        busbar_plugin::read_sized_field!(decl_ptr, honoured_size, PlaneDecl, provided_carriers)
            .unwrap_or(0);
    let declaration = read_declaration(decl_ptr, honoured_size, &display)?;
    // `scope` is the plane's primary grant kind: it leads `scope_kinds`, and a plane with no scope
    // grants none — so the two statements cannot disagree about what admits the plane's traffic.
    let scope_leads = match declaration.scope_kinds.first() {
        None => scope.is_empty(),
        Some(first) => !scope.is_empty() && *first == scope,
    };
    if !scope_leads {
        return Err(format!(
            "plane '{display}' declares scope {scope:?} but scope kinds {:?}: the scope must lead \
             the scope kinds, and a plane with no scope declares none",
            declaration.scope_kinds
        ));
    }

    Ok(DynPlane {
        decl: decl_ptr,
        honoured_size,
        name,
        section_key,
        scope,
        label,
        provided_carriers,
        declaration,
        path: display,
        _lib: lib,
        _backing: backing,
    })
}

/// Hard cap on a single plane vocabulary string (`name`/`section_key`/`scope`/`label`), enforced
/// BEFORE the `from_raw_parts` slice in [`read_vocab`]. The `*_len` fields of a [`PlaneDecl`] are
/// plugin-attested `usize`s read straight out of the (third-party, possibly-hostile) decl: without a
/// bound, a plane that pairs a short `name_ptr` buffer with a huge `name_len` forces the host to form
/// a slice — and then walk it in `str::from_utf8` — far past the real allocation, an unbounded
/// out-of-bounds read in the ENGINE's address space. This mirrors the discipline the COLD load path
/// already enforces on every plugin-supplied length before its own `from_raw_parts`
/// (`response_len_ok`/`open_err_is_readable` against `MAX_PLUGIN_RESPONSE_LEN`, and `host_log_sink`'s
/// `MAX_LOG_LEN`): the hot-tier vocabulary read must not be the one plugin-length path that skips it.
/// A vocabulary string is an identifier/label; 64 KiB is orders of magnitude past any real one, so a
/// legitimate plane never trips it — an oversize declaration is refused as a hard load error
/// (fail-closed) rather than silently truncated, since a truncated `name`/`section_key` would corrupt
/// the plane's routing identity.
const MAX_PLANE_VOCAB_LEN: usize = 64 * 1024;

/// Which vocabulary `(ptr,len)` pair to read.
#[derive(Clone, Copy)]
enum Vocab {
    Name,
    SectionKey,
    Scope,
    Label,
}

/// Read one borrowed vocabulary range from the decl (through the sized guard) into an owned UTF-8
/// `String`. A null/absent range is the empty string; non-UTF-8 bytes are a load error.
fn read_vocab(
    decl: *const PlaneDecl,
    size: u32,
    which: Vocab,
    display: &str,
) -> Result<String, String> {
    let (ptr, len) = match which {
        Vocab::Name => (
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, name_ptr).flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, name_len).unwrap_or(0),
        ),
        Vocab::SectionKey => (
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, section_key_ptr).flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, section_key_len).unwrap_or(0),
        ),
        Vocab::Scope => (
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, scope_ptr).flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, scope_len).unwrap_or(0),
        ),
        Vocab::Label => (
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, label_ptr).flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, PlaneDecl, label_len).unwrap_or(0),
        ),
    };
    if ptr.is_null() || len == 0 {
        return Ok(String::new());
    }
    // Cap the plugin-attested length BEFORE slicing: `len` is read verbatim from the (third-party)
    // decl, so an unbounded `from_raw_parts` here is an OOB read past the real vocabulary buffer.
    // Refuse the load fail-closed rather than form the slice. See [`MAX_PLANE_VOCAB_LEN`].
    if len > MAX_PLANE_VOCAB_LEN {
        return Err(format!(
            "plane '{display}' declares a {len}-byte vocabulary string, exceeding the \
             {MAX_PLANE_VOCAB_LEN}-byte cap — refusing to load"
        ));
    }
    // SAFETY: the plane's decl guarantees each non-null `(ptr,len)` addresses a live, immutable
    // vocabulary range for the life of the mapped image (the decl's own Send/Sync soundness note),
    // and `len` is now bounded by `MAX_PLANE_VOCAB_LEN`.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| format!("plane '{display}' vocabulary is not valid UTF-8"))
}

/// Cap on the entries of one borrowed declaration list (`scope_kinds`/`owned_sections`/
/// `billable_classes`/`fee_units`), enforced BEFORE any entry is read: the `*_len` is plugin-attested,
/// exactly like a vocabulary length (see [`MAX_PLANE_VOCAB_LEN`]). A plane declares a handful of
/// each; an oversize list is refused as a hard load error rather than walked.
const MAX_PLANE_DECL_ENTRIES: usize = 1024;

/// One field of the declaration tail, read through the sized guard. [`assemble`] refused every decl
/// that does not reach the end of the tail, so an absent field is a refusal here too, never a default.
macro_rules! tail_field {
    ($decl:expr, $size:expr, $field:ident, $display:expr) => {
        busbar_plugin::read_sized_field!($decl, $size, PlaneDecl, $field).ok_or_else(|| {
            format!(
                "plane '{}' decl does not reach its `{}` declaration field",
                $display,
                stringify!($field)
            )
        })?
    };
}

/// Read the decl's declaration tail into an owned [`HotDeclaration`].
fn read_declaration(
    decl: *const PlaneDecl,
    size: u32,
    display: &str,
) -> Result<HotDeclaration, String> {
    let fallback = match tail_field!(decl, size, fallback, display) {
        0 => false,
        1 => true,
        other => {
            return Err(format!(
                "plane '{display}' declares fallback flag {other}; a plane declares 0 or 1"
            ))
        }
    };
    let text = |d: DeclStr| decl_str(d, display);
    let stated = |d: DeclStr, what: &str| {
        text(d)?.ok_or_else(|| format!("plane '{display}' states no {what}"))
    };
    let strs = |ptr: *const DeclStr, len: usize, what: &str| -> Result<Vec<String>, String> {
        decl_list(ptr, len, what, display)?
            .into_iter()
            .map(|d| stated(d, what))
            .collect()
    };
    Ok(HotDeclaration {
        fallback,
        subject_noun: stated(
            tail_field!(decl, size, subject_noun, display),
            "subject noun",
        )?,
        admin_noun: stated(tail_field!(decl, size, admin_noun, display), "admin noun")?,
        audit_kind: stated(tail_field!(decl, size, audit_kind, display), "audit kind")?,
        signing_domain: text(tail_field!(decl, size, signing_domain, display))?,
        signing_kid_prefix: text(tail_field!(decl, size, signing_kid_prefix, display))?,
        scope_kinds: strs(
            tail_field!(decl, size, scope_kinds_ptr, display),
            tail_field!(decl, size, scope_kinds_len, display),
            "scope kind",
        )?,
        owned_sections: strs(
            tail_field!(decl, size, owned_sections_ptr, display),
            tail_field!(decl, size, owned_sections_len, display),
            "owned config section",
        )?,
        billable_classes: decl_list(
            tail_field!(decl, size, billable_classes_ptr, display),
            tail_field!(decl, size, billable_classes_len, display),
            "billable class",
            display,
        )?
        .into_iter()
        .map(|c: DeclBillableClass| {
            Ok((
                stated(c.class, "billable class")?,
                stated(c.family, "billable class family")?,
            ))
        })
        .collect::<Result<_, String>>()?,
        fee_units: strs(
            tail_field!(decl, size, fee_units_ptr, display),
            tail_field!(decl, size, fee_units_len, display),
            "fee unit",
        )?,
        metric_families: read_metric_families(decl, size, display)?,
        served_op_classes: read_served_op_classes(decl, size, display)?,
        record_kinds: read_record_kinds(decl, size, display)?,
    })
}

/// The decl's plane-record-kind tail (minor 29). A decl that ends before it keeps no kind — an
/// append-only absence: the plane states none, so no administrative write lands under it.
fn read_record_kinds(
    decl: *const PlaneDecl,
    size: u32,
    display: &str,
) -> Result<Vec<String>, String> {
    let ptr = busbar_plugin::read_sized_field!(decl, size, PlaneDecl, record_kinds_ptr);
    let len = busbar_plugin::read_sized_field!(decl, size, PlaneDecl, record_kinds_len);
    let (Some(ptr), Some(len)) = (ptr, len) else {
        return Ok(Vec::new());
    };
    decl_list(ptr, len, "record kind", display)?
        .into_iter()
        .map(|d: DeclStr| {
            decl_str(d, display)?.ok_or_else(|| format!("plane '{display}' states no record kind"))
        })
        .collect()
}

/// The decl's served-operation-class tail (minor 27). A decl that ends before it serves no class —
/// an append-only absence: the plane states none, so no nested destination resolves to it.
fn read_served_op_classes(
    decl: *const PlaneDecl,
    size: u32,
    display: &str,
) -> Result<Vec<(String, String)>, String> {
    let ptr = busbar_plugin::read_sized_field!(decl, size, PlaneDecl, served_op_classes_ptr);
    let len = busbar_plugin::read_sized_field!(decl, size, PlaneDecl, served_op_classes_len);
    let (Some(ptr), Some(len)) = (ptr, len) else {
        return Ok(Vec::new());
    };
    let stated = |d: DeclStr, what: &str| {
        decl_str(d, display)?.ok_or_else(|| format!("plane '{display}' states no {what}"))
    };
    decl_list(ptr, len, "served operation class", display)?
        .into_iter()
        .map(|c: DeclServedOpClass| {
            Ok((
                stated(c.op, "served operation class")?,
                stated(c.name, "served operation class display name")?,
            ))
        })
        .collect()
}

/// The decl's metric-family tail (minor 25). A decl that ends before it declares no family — an
/// append-only absence, not a default: the plane states none, so it adds to none.
fn read_metric_families(
    decl: *const PlaneDecl,
    size: u32,
    display: &str,
) -> Result<Vec<HotMetricFamily>, String> {
    let ptr = busbar_plugin::read_sized_field!(decl, size, PlaneDecl, metric_families_ptr);
    let len = busbar_plugin::read_sized_field!(decl, size, PlaneDecl, metric_families_len);
    let (Some(ptr), Some(len)) = (ptr, len) else {
        return Ok(Vec::new());
    };
    let stated = |d: DeclStr, what: &str| {
        decl_str(d, display)?.ok_or_else(|| format!("plane '{display}' states no {what}"))
    };
    decl_list(ptr, len, "metric family", display)?
        .into_iter()
        .map(|f: DeclMetricFamily| {
            Ok(HotMetricFamily {
                name: stated(f.name, "metric family name")?,
                kind: stated(f.kind, "metric family kind")?,
                label_keys: decl_list(f.label_keys_ptr, f.label_keys_len, "label key", display)?
                    .into_iter()
                    .map(|k| stated(k, "label key"))
                    .collect::<Result<_, String>>()?,
            })
        })
        .collect()
}

/// One [`DeclStr`] as an owned string: `None` for a NULL (absent) range, the stated string otherwise.
/// Capped and UTF-8-checked exactly as a vocabulary range is ([`read_vocab`]).
fn decl_str(d: DeclStr, display: &str) -> Result<Option<String>, String> {
    if d.ptr.is_null() {
        return Ok(None);
    }
    if d.len > MAX_PLANE_VOCAB_LEN {
        return Err(format!(
            "plane '{display}' declares a {}-byte declaration string, exceeding the \
             {MAX_PLANE_VOCAB_LEN}-byte cap — refusing to load",
            d.len
        ));
    }
    // SAFETY: a non-null `DeclStr` addresses a live, immutable range for the life of the image (the
    // decl's discipline), and its length is now bounded by `MAX_PLANE_VOCAB_LEN`.
    let bytes = unsafe { std::slice::from_raw_parts(d.ptr, d.len) };
    std::str::from_utf8(bytes)
        .map(|s| Some(s.to_string()))
        .map_err(|_| format!("plane '{display}' declaration string is not valid UTF-8"))
}

/// Copy one borrowed declaration list out of the image, entry by entry (unaligned reads: the list is
/// plugin-attested). An empty list may be NULL; a NULL list claiming entries, or one past
/// [`MAX_PLANE_DECL_ENTRIES`], is refused.
fn decl_list<T: Copy>(
    ptr: *const T,
    len: usize,
    what: &str,
    display: &str,
) -> Result<Vec<T>, String> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(format!(
            "plane '{display}' declares {len} {what} entries behind a null list"
        ));
    }
    if len > MAX_PLANE_DECL_ENTRIES {
        return Err(format!(
            "plane '{display}' declares {len} {what} entries, exceeding the \
             {MAX_PLANE_DECL_ENTRIES}-entry cap — refusing to load"
        ));
    }
    // SAFETY: a non-null list addresses `len` live entries for the life of the image (the decl's
    // discipline), `len` is bounded, and each entry is copied out without assuming alignment.
    Ok((0..len)
        .map(|i| unsafe { core::ptr::read_unaligned(ptr.add(i)) })
        .collect())
}

/// Small extension so `read_sized_field!(...).flatten_ptr()` yields the pointer (or null when the
/// field was absent), mirroring how a `*const u8` field reads back through the guard.
trait FlattenPtr {
    fn flatten_ptr(self) -> *const u8;
}
impl FlattenPtr for Option<*const u8> {
    fn flatten_ptr(self) -> *const u8 {
        self.unwrap_or(core::ptr::null())
    }
}

#[cfg(test)]
#[path = "tests/plane_conformance_tests.rs"]
mod tests;

/// The decl-side seams over an IN-MEMORY decl: size admission, the owned plane state, the
/// admin/OpenAPI slot readers, and which thread the constructor crossings run on.
#[cfg(test)]
#[path = "tests/plane_decl_tests.rs"]
mod tests_decl;
