// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Runtime loading of a **TRANSPORT** carrier from a `cdylib` over the busbar HOT-tier ABI
//! ([`busbar_plugin::hot::transport`]) — the transport analogue of [`load_plane`](crate::load_plane).
//!
//! A transport cdylib rides the EXACT same tarball / signed-manifest / trust discovery pipeline as
//! every other kind (it exports `busbar_abi` at [`TRANSPORT_VERSION`](busbar_plugin::cold::TRANSPORT_VERSION)
//! and `busbar_plugin_kind() == "transport"`), but — like a plane — it does NOT speak the six-symbol
//! JSON `call` wire. Instead it exports ONE hot-lane symbol,
//! [`busbar_plugin::hot::symbol::TRANSPORT_DECL`] (`busbar_transport_decl`), returning a pointer to its
//! `#[repr(C)]` [`TransportDecl`] vtable. [`load_transport`]/[`load_transport_from_bytes`] map the
//! library, run the transport + kind + AIRLOCK-preamble handshake, materialise the carrier's borrowed
//! vocabulary into owned strings, and hand back a [`DynTransport`] the composition root drives exactly
//! as it drives a compiled-in `TransportDecl` — the both-ways contract (`DECISIONS #2/#3/#11`).
//!
//! This is ADDITIVE and does not touch the seven compiled-in carriers
//! (`busbar-transport-{http,ws,stdio,tcp,tls,sse,grpc}`), which stay exactly as they are; it is the
//! DROP-IN packaging path DECISION #3 named as owed, closing the last both-ways gap.

use crate::stage;
use busbar_plugin::hot::decl::BuildFn;
use busbar_plugin::hot::decl::ConfigValidateFn;
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::pod::{OpaqueState, StatusClass, POD_VERSION};
use busbar_plugin::hot::transport::{AcceptFn, ConnectFn, ReadFn, WriteFn};
use busbar_plugin::hot::{
    BuildCtx, PlaneHostVtable, TransportDecl, TransportDeclFn, TransportFacet,
};
use busbar_plugin::{check_preamble, AbiPreamble};
use core::mem::MaybeUninit;
use libloading::Library;
use std::os::raw::c_void;
use std::path::Path;

/// A transport carrier loaded from a `cdylib` over the HOT-tier ABI. Holds the mapped library alive
/// for as long as the carrier lives (the `TransportDecl` and every vocabulary string point INTO the
/// image), and unloads it on a plugin worker at [`Drop`] — the same discipline [`DynPlane`](crate::DynPlane)
/// uses. The borrowed vocabulary is COPIED to owned `String`s at load; the fn-pointer slots are read
/// on demand through the sized-struct guard so a carrier built against an OLDER airlock minor reads a
/// trailing slot it never wrote as ABSENT.
pub struct DynTransport {
    /// The carrier's own `TransportDecl`, pointing into the mapped image. Read only through the guard.
    decl: *const TransportDecl,
    /// The honoured decl `size` (peer-attested, clamped to this build's `size_of::<TransportDecl>()`).
    honoured_size: u32,
    /// The carrier's canonical name (owned copy of the borrowed vocabulary).
    name: String,
    /// The carrier's config section-key.
    section_key: String,
    /// The carrier's scope label.
    scope: String,
    /// The carrier's human label.
    label: String,
    /// The bitset of [`TransportFacet`]s the carrier declares it provides.
    provided_facets: u32,
    /// The carrier name/path, for diagnostics.
    path: String,
    /// The mapped library. `Option` only so `Drop` can TAKE it and unload it on a plugin worker.
    _lib: Option<Library>,
    /// The staging backing (Linux memfd / private temp) for a from-bytes load; `None` for a path load.
    _backing: Option<stage::Staged>,
}

// SAFETY: identical contract to `DynPlane` — `decl` is a `'static` pointer into a mapped image the
// carrier guarantees is immutable for its life; every vocabulary string is copied out at load, and the
// fn slots are plain code addresses. The host never mutates through `decl`.
unsafe impl Send for DynTransport {}
// SAFETY: see the `Send` impl above.
unsafe impl Sync for DynTransport {}

impl Drop for DynTransport {
    fn drop(&mut self) {
        // Unload on a worker (dlclose runs the image's `.fini_array`), library before staged backing.
        if let Some(lib) = self._lib.take() {
            crate::dlclose_on_worker(lib);
        }
    }
}

impl std::fmt::Debug for DynTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynTransport")
            .field("name", &self.name)
            .field("section_key", &self.section_key)
            .field("scope", &self.scope)
            .field("provided_facets", &self.provided_facets)
            .field("path", &self.path)
            .finish()
    }
}

impl DynTransport {
    /// The carrier's canonical name (its vocabulary `name`).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
    /// The carrier's config section-key.
    #[must_use]
    pub fn section_key(&self) -> &str {
        &self.section_key
    }
    /// The carrier's scope label.
    #[must_use]
    pub fn scope(&self) -> &str {
        &self.scope
    }
    /// The carrier's human label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }
    /// The raw bitset of [`TransportFacet`]s the carrier declares.
    #[must_use]
    pub fn provided_facets(&self) -> u32 {
        self.provided_facets
    }
    /// Whether the carrier declares it provides `facet`.
    #[must_use]
    pub fn provides(&self, facet: TransportFacet) -> bool {
        self.provided_facets & facet.bit() != 0
    }

    // ── Slot readers — pull one `Option<fn>` slot out of the decl through the sized-struct guard. ──
    fn slot_config_validate(&self) -> Option<ConfigValidateFn> {
        busbar_plugin::read_sized_field!(
            self.decl,
            self.honoured_size,
            TransportDecl,
            config_validate
        )
        .flatten()
    }
    fn slot_build(&self) -> Option<BuildFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, build)
            .flatten()
    }
    fn slot_accept(&self) -> Option<AcceptFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, accept)
            .flatten()
    }
    fn slot_connect(&self) -> Option<ConnectFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, connect)
            .flatten()
    }
    fn slot_write(&self) -> Option<WriteFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, write)
            .flatten()
    }
    fn slot_read(&self) -> Option<ReadFn> {
        busbar_plugin::read_sized_field!(self.decl, self.honoured_size, TransportDecl, read)
            .flatten()
    }

    /// Drive the carrier's `config_validate` over raw config bytes, catching any panic across the seam.
    pub fn config_validate(&self, raw: &[u8]) -> (StatusClass, Option<OpaqueState>) {
        let Some(f) = self.slot_config_validate() else {
            return (StatusClass::Unsupported, None);
        };
        let mut out = MaybeUninit::<OpaqueState>::uninit();
        let (raw_ptr, raw_len) = (raw.as_ptr(), raw.len());
        let out_ptr: *mut MaybeUninit<OpaqueState> = &mut out;
        match crate::ffi_guard(&self.path, "transport_config_validate", || {
            f(raw_ptr, raw_len, out_ptr)
        }) {
            Ok(status) if status.class() == StatusClass::Ok => {
                // SAFETY: init-only-on-Ok — the carrier wrote `out` before returning `Ok`.
                (StatusClass::Ok, Some(unsafe { out.assume_init() }))
            }
            Ok(status) => (status.class(), None),
            Err(_) => (StatusClass::Fault, None),
        }
    }

    /// BUILD the carrier from `config` + PRE-RESOLVED secret `resolved_refs`, threading `host` +
    /// `host_ctx`. Returns the carrier's [`StatusClass`] and, on `Ok`, the opaque carrier handle core
    /// stores and never downcasts. A caught panic fails closed (`Fault`, no handle).
    ///
    /// # Safety
    /// `host`, when non-null, must point at a live [`PlaneHostVtable`] that outlives the built carrier;
    /// `host_ctx` is the opaque context the host recovers.
    pub unsafe fn build(
        &self,
        host: *const PlaneHostVtable,
        host_ctx: HostCtx,
        config: &[u8],
        resolved_refs: &[u64],
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
        };
        let mut out = MaybeUninit::<OpaqueState>::uninit();
        let ctx_ptr: *const BuildCtx = &ctx;
        let out_ptr: *mut MaybeUninit<OpaqueState> = &mut out;
        match crate::ffi_guard(&self.path, "transport_build", || f(ctx_ptr, out_ptr)) {
            Ok(status) if status.class() == StatusClass::Ok => {
                // SAFETY: init-only-on-Ok.
                (StatusClass::Ok, Some(unsafe { out.assume_init() }))
            }
            Ok(status) => (status.class(), None),
            Err(_) => (StatusClass::Fault, None),
        }
    }

    /// ACCEPT one inbound connection (the passive/server-accept direction). Returns the carrier's
    /// [`StatusClass`] and, on `Ok`, the opaque connection handle. A caught panic fails closed.
    ///
    /// # Safety
    /// `state` must be a live carrier state pointer this carrier's `build` produced and not yet freed.
    pub unsafe fn accept(&self, state: *mut c_void) -> (StatusClass, Option<OpaqueState>) {
        let Some(f) = self.slot_accept() else {
            return (StatusClass::Unsupported, None);
        };
        let mut out = MaybeUninit::<OpaqueState>::uninit();
        let out_ptr: *mut MaybeUninit<OpaqueState> = &mut out;
        match crate::ffi_guard(&self.path, "transport_accept", || f(state, out_ptr)) {
            // SAFETY: init-only-on-Ok — the carrier wrote `out` before returning `Ok`.
            Ok(status) if status.class() == StatusClass::Ok => {
                (StatusClass::Ok, Some(unsafe { out.assume_init() }))
            }
            Ok(status) => (status.class(), None),
            Err(_) => (StatusClass::Fault, None),
        }
    }

    /// CONNECT to a destination (the active/client-connect direction). Returns the carrier's
    /// [`StatusClass`] and, on `Ok`, the opaque connection handle. A caught panic fails closed.
    ///
    /// # Safety
    /// `state` must be a live carrier state pointer; `dest`'s borrowed range outlives the call.
    pub unsafe fn connect(
        &self,
        state: *mut c_void,
        dest: &[u8],
    ) -> (StatusClass, Option<OpaqueState>) {
        let Some(f) = self.slot_connect() else {
            return (StatusClass::Unsupported, None);
        };
        let mut out = MaybeUninit::<OpaqueState>::uninit();
        let (dest_ptr, dest_len) = (dest.as_ptr(), dest.len());
        let out_ptr: *mut MaybeUninit<OpaqueState> = &mut out;
        match crate::ffi_guard(&self.path, "transport_connect", || {
            f(state, dest_ptr, dest_len, out_ptr)
        }) {
            // SAFETY: init-only-on-Ok — the carrier wrote `out` before returning `Ok`.
            Ok(status) if status.class() == StatusClass::Ok => {
                (StatusClass::Ok, Some(unsafe { out.assume_init() }))
            }
            Ok(status) => (status.class(), None),
            Err(_) => (StatusClass::Fault, None),
        }
    }

    /// WRITE `buf` into a connection; returns the carrier's [`StatusClass`] and how many bytes it
    /// accepted (0 on any non-`Ok`). A caught panic fails closed.
    ///
    /// # Safety
    /// `conn` must be a live connection handle an `Ok` [`accept`](Self::accept)/[`connect`](Self::connect)
    /// produced and not yet freed.
    pub unsafe fn write(&self, conn: *mut c_void, buf: &[u8]) -> (StatusClass, usize) {
        let Some(f) = self.slot_write() else {
            return (StatusClass::Unsupported, 0);
        };
        let mut written: usize = 0;
        let (buf_ptr, buf_len) = (buf.as_ptr(), buf.len());
        let written_ptr: *mut usize = &mut written;
        match crate::ffi_guard(&self.path, "transport_write", || {
            f(conn, buf_ptr, buf_len, written_ptr)
        }) {
            Ok(status) if status.class() == StatusClass::Ok => (StatusClass::Ok, written),
            Ok(status) => (status.class(), 0),
            Err(_) => (StatusClass::Fault, 0),
        }
    }

    /// READ up to `buf.len()` bytes out of a connection into `buf`; returns the carrier's
    /// [`StatusClass`] and how many bytes it produced (0 = nothing available or non-`Ok`).
    ///
    /// # Safety
    /// `conn` must be a live connection handle an `Ok` accept/connect produced and not yet freed.
    pub unsafe fn read(&self, conn: *mut c_void, buf: &mut [u8]) -> (StatusClass, usize) {
        let Some(f) = self.slot_read() else {
            return (StatusClass::Unsupported, 0);
        };
        let mut got: usize = 0;
        let cap = buf.len();
        let buf_ptr = buf.as_mut_ptr();
        let got_ptr: *mut usize = &mut got;
        match crate::ffi_guard(&self.path, "transport_read", || {
            f(conn, buf_ptr, cap, got_ptr)
        }) {
            Ok(status) if status.class() == StatusClass::Ok => {
                // Clamp a hostile/buggy over-report to the caller buffer capacity before it is trusted.
                (StatusClass::Ok, got.min(cap))
            }
            Ok(status) => (status.class(), 0),
            Err(_) => (StatusClass::Fault, 0),
        }
    }
}

/// Load a transport carrier from EXACTLY the verified library `bytes` (the TOCTOU-safe entrypoint; see
/// [`load_store_from_bytes`](crate::load_store_from_bytes) for the staging contract). `manifest_kind`
/// is the trust-verified signed-manifest `kind`, cross-checked against `busbar_plugin_kind()`.
pub fn load_transport_from_bytes(
    bytes: &[u8],
    display: &str,
    manifest_kind: &str,
) -> Result<DynTransport, String> {
    let (lib, staged) = stage::load_library_from_bytes(bytes, display)?;
    wire_up_transport(lib, display.to_string(), manifest_kind, Some(staged))
}

/// Load a transport carrier from the `cdylib` at `lib_path`. A bare path load has no signed manifest,
/// so the seam's expected kind (`transport`) is the authority. The trust-verified
/// [`load_transport_from_bytes`] is the real gate for a dropped-in tarball.
#[cold]
#[inline(never)]
pub fn load_transport(lib_path: &Path) -> Result<DynTransport, String> {
    let display = lib_path.display().to_string();
    // SAFETY: an operator-placed library is inherently trusted (its init code runs), like a
    // compiled-in carrier. The path comes from config/the plugins dir, never the request path.
    let lib = crate::dlopen_on_worker(lib_path.as_os_str())
        .map_err(|e| format!("failed to load transport '{display}': {e}"))?;
    wire_up_transport(lib, display, busbar_plugin::cold::kind::TRANSPORT, None)
}

/// Resolve + validate a mapped transport library against the frozen contract (transport handshake,
/// kind == `transport` == manifest kind, then the AIRLOCK preamble on the decl), materialise its
/// vocabulary, and assemble a [`DynTransport`]. The transport analogue of `wire_up_plane`.
fn wire_up_transport(
    lib: Library,
    display: String,
    manifest_kind: &str,
    backing: Option<stage::Staged>,
) -> Result<DynTransport, String> {
    // ── 1. Transport handshake FIRST (shared with every kind). ──
    let transport = {
        let f = unsafe { lib.get::<busbar_plugin::cold::AbiFn>(busbar_plugin::cold::symbol::ABI) }
            .map_err(|_| format!("'{display}' is not a busbar plugin (no busbar_abi symbol)"))?;
        crate::ffi_guard_confined(&display, "abi", || unsafe { (*f)() })?
    };
    if transport != busbar_plugin::cold::TRANSPORT_VERSION {
        return Err(format!(
            "transport '{display}' targets transport ABI v{transport}, engine speaks v{}",
            busbar_plugin::cold::TRANSPORT_VERSION
        ));
    }

    // ── 2. Kind bound at load — exported kind must be `transport` AND equal the signed manifest kind. ──
    let exported_kind = crate::read_plugin_kind(&lib, &display)?;
    if exported_kind != busbar_plugin::cold::kind::TRANSPORT {
        return Err(format!(
            "transport '{display}' exports kind '{exported_kind}', not 'transport'"
        ));
    }
    if exported_kind != manifest_kind {
        return Err(format!(
            "transport '{display}' kind mismatch: exported symbol says '{exported_kind}', signed \
             manifest says '{manifest_kind}' — refusing to load"
        ));
    }

    // ── 3. Resolve the ONE hot-lane entrypoint and read the decl pointer (guarded). ──
    let decl_ptr = {
        let f = unsafe { lib.get::<TransportDeclFn>(busbar_plugin::hot::symbol::TRANSPORT_DECL) }
            .map_err(|_| {
            format!("transport '{display}' missing busbar_transport_decl symbol")
        })?;
        crate::ffi_guard_confined(&display, "transport_decl", || unsafe { (*f)() })?
    };
    if decl_ptr.is_null() {
        return Err(format!(
            "transport '{display}' returned a null TransportDecl"
        ));
    }

    // ── 4. AIRLOCK: check the FROZEN preamble WITHOUT forming a `&TransportDecl` over a possibly-shorter
    //    peer allocation (read `abi` + `size` unaligned by address), then clamp to this build's size. ──
    // SAFETY: `decl_ptr` is a non-null pointer to at least the leading prefix of a `TransportDecl`;
    // `addr_of!` computes addresses only and `read_unaligned` assumes no alignment the peer did not
    // promise.
    let (abi, advertised): (AbiPreamble, u32) = unsafe {
        (
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl_ptr).abi)),
            core::ptr::read_unaligned(core::ptr::addr_of!((*decl_ptr).size)),
        )
    };
    check_preamble(&abi).map_err(|e| {
        format!("transport '{display}' decl preamble refused: {e:?} (rebuild it against this busbar ABI)")
    })?;
    let ours = core::mem::size_of::<TransportDecl>() as u32;
    // Minimum size that can carry the frozen header + vocabulary + facets (offset THROUGH
    // `provided_facets`). A decl that does not even reach the facets cannot describe a carrier.
    let min = (core::mem::offset_of!(TransportDecl, provided_facets) + core::mem::size_of::<u32>())
        as u32;
    if advertised < min {
        return Err(format!(
            "transport '{display}' decl attests size {advertised}, below the {min}-byte vocabulary \
             header — it cannot describe a TransportDecl"
        ));
    }
    let honoured_size = busbar_plugin::honoured_size(advertised, ours as usize);

    // ── 5. Materialise the borrowed vocabulary into owned strings (read through the sized guard). ──
    let name = read_vocab(decl_ptr, honoured_size, Vocab::Name, &display)?;
    let section_key = read_vocab(decl_ptr, honoured_size, Vocab::SectionKey, &display)?;
    let scope = read_vocab(decl_ptr, honoured_size, Vocab::Scope, &display)?;
    let label = read_vocab(decl_ptr, honoured_size, Vocab::Label, &display)?;
    let provided_facets =
        busbar_plugin::read_sized_field!(decl_ptr, honoured_size, TransportDecl, provided_facets)
            .unwrap_or(0);

    Ok(DynTransport {
        decl: decl_ptr,
        honoured_size,
        name,
        section_key,
        scope,
        label,
        provided_facets,
        path: display,
        _lib: Some(lib),
        _backing: backing,
    })
}

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
    decl: *const TransportDecl,
    size: u32,
    which: Vocab,
    display: &str,
) -> Result<String, String> {
    let (ptr, len) = match which {
        Vocab::Name => (
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, name_ptr).flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, name_len).unwrap_or(0),
        ),
        Vocab::SectionKey => (
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, section_key_ptr)
                .flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, section_key_len)
                .unwrap_or(0),
        ),
        Vocab::Scope => (
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, scope_ptr).flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, scope_len).unwrap_or(0),
        ),
        Vocab::Label => (
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, label_ptr).flatten_ptr(),
            busbar_plugin::read_sized_field!(decl, size, TransportDecl, label_len).unwrap_or(0),
        ),
    };
    if ptr.is_null() || len == 0 {
        return Ok(String::new());
    }
    // SAFETY: the carrier's decl guarantees each non-null `(ptr,len)` addresses a live, immutable
    // vocabulary range for the life of the mapped image (the decl's own Send/Sync soundness note).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| format!("transport '{display}' vocabulary is not valid UTF-8"))
}

/// Small extension so `read_sized_field!(...).flatten_ptr()` yields the pointer (or null when the
/// field was absent), mirroring `plane::FlattenPtr`.
trait FlattenPtr {
    fn flatten_ptr(self) -> *const u8;
}
impl FlattenPtr for Option<*const u8> {
    fn flatten_ptr(self) -> *const u8 {
        self.unwrap_or(core::ptr::null())
    }
}

#[cfg(test)]
#[path = "tests/transport_conformance_tests.rs"]
mod tests;
