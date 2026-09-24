// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane decl's seams, driven over an IN-MEMORY `PlaneDecl` built in this file rather than a
//! dlopened fixture: every slot here is a test fn, so each test controls exactly what the plane
//! answers — an over-claimed size, a state with a counting `free`, an admin/OpenAPI contribution,
//! and a record of which thread each crossing ran on.

use super::*;
use busbar_plugin::hot::decl::OpaqueHandle;
use core::mem::MaybeUninit;
use std::os::raw::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// Serialises the tests in this file: they share the statics below.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

// ── Instruments ───────────────────────────────────────────────────────────────────────────────

/// The name of the thread each noted crossing ran on, in order.
static THREADS: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Called from inside the loader's guard closure for the constructor crossings: records the thread
/// the crossing actually ran on.
pub(super) fn note_thread() {
    THREADS.lock().unwrap_or_else(|p| p.into_inner()).push(
        std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string(),
    );
}

fn take_threads() -> Vec<String> {
    std::mem::take(&mut *THREADS.lock().unwrap_or_else(|p| p.into_inner()))
}

/// How many times the plane's `free` ran.
static FREES: AtomicUsize = AtomicUsize::new(0);

extern "C-unwind" fn counting_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        // SAFETY: allocated as a `Box<u64>` by `t_build`/`t_config_validate`.
        drop(unsafe { Box::from_raw(ptr as *mut u64) });
        FREES.fetch_add(1, Ordering::SeqCst);
    }
}

fn write_state(out: *mut MaybeUninit<OpaqueHandle>) {
    let state = OpaqueState {
        ptr: Box::into_raw(Box::new(7u64)) as *mut c_void,
        free: Some(counting_free),
    };
    // SAFETY: the loader hands a valid out slot.
    unsafe { (*out).write(state) };
}

extern "C-unwind" fn t_config_validate(
    _raw: *const u8,
    _len: usize,
    out: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    write_state(out);
    RawStatus::of(StatusClass::Ok)
}

extern "C-unwind" fn t_build(
    _ctx: *const BuildCtx,
    out: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    write_state(out);
    RawStatus::of(StatusClass::Ok)
}

const ROUTES: &[u8] = br#"{"routes":["GET /admin/example"]}"#;

extern "C-unwind" fn t_admin_routes(
    _state: *mut c_void,
    buf: *mut u8,
    cap: usize,
    written: *mut usize,
) -> RawStatus {
    assert!(cap >= ROUTES.len());
    // SAFETY: the loader hands a `cap`-byte buffer and a valid out-length.
    unsafe {
        core::ptr::copy_nonoverlapping(ROUTES.as_ptr(), buf, ROUTES.len());
        *written = ROUTES.len();
    }
    RawStatus::of(StatusClass::Ok)
}

/// An `openapi` slot that is present and writes NOTHING — the non-vacuity invariant's violation.
extern "C-unwind" fn t_openapi_vacuous(
    _state: *mut c_void,
    _buf: *mut u8,
    _cap: usize,
    written: *mut usize,
) -> RawStatus {
    // SAFETY: a valid out-length.
    unsafe { *written = 0 };
    RawStatus::of(StatusClass::Ok)
}

/// An `openapi` slot that claims more bytes than the buffer it was handed.
extern "C-unwind" fn t_openapi_overclaim(
    _state: *mut c_void,
    _buf: *mut u8,
    cap: usize,
    written: *mut usize,
) -> RawStatus {
    // SAFETY: a valid out-length.
    unsafe { *written = cap + 1 };
    RawStatus::of(StatusClass::Ok)
}

const NAME: &[u8] = b"memplane";

fn decl() -> PlaneDecl {
    PlaneDecl {
        abi: AbiPreamble::CURRENT,
        size: core::mem::size_of::<PlaneDecl>() as u32,
        version: busbar_plugin::ABI_MINOR,
        name_ptr: NAME.as_ptr(),
        name_len: NAME.len(),
        section_key_ptr: NAME.as_ptr(),
        section_key_len: NAME.len(),
        scope_ptr: NAME.as_ptr(),
        scope_len: NAME.len(),
        label_ptr: NAME.as_ptr(),
        label_len: NAME.len(),
        provided_carriers: IngressCarrier::RequestResponse.bit(),
        _reserved: 0,
        config_validate: Some(t_config_validate),
        build: Some(t_build),
        hydrate: None,
        start: None,
        admin_routes: Some(t_admin_routes),
        openapi: Some(t_openapi_vacuous),
        dispatch: None,
    }
}

fn plane_over(d: &PlaneDecl) -> Result<DynPlane, String> {
    assemble(d, "memplane".to_string(), None, None)
}

// ── Item 389: a decl size over-claim is REFUSED, as the host vtable's is ──────────────────────

#[test]
fn a_decl_attesting_more_than_this_builds_struct_is_refused() {
    let _s = serial();
    let mut d = decl();
    d.size = u32::MAX;
    let got = plane_over(&d);
    assert!(
        got.as_ref()
            .is_err_and(|e| e.contains("exceeding this build's own")),
        "an over-claimed decl size must be refused, not clamped: {:?}",
        got.map(|p| p.honoured_size)
    );
    d.size = core::mem::size_of::<PlaneDecl>() as u32 + 1;
    assert!(plane_over(&d).is_err());
    d.size = core::mem::size_of::<PlaneDecl>() as u32;
    assert_eq!(plane_over(&d).unwrap().name(), "memplane");
}

// ── Item 386: the plane's state is freed, and cannot outlive the image ───────────────────────

#[test]
fn an_owned_plane_state_is_freed_through_the_planes_own_free() {
    let _s = serial();
    let d = decl();
    let plane = plane_over(&d).unwrap();
    FREES.store(0, Ordering::SeqCst);

    let (class, parsed) = plane.config_validate_owned(b"{}");
    assert_eq!(class, StatusClass::Ok);
    let parsed = parsed.expect("Ok yields a handle");
    assert!(!parsed.ptr().is_null());
    // SAFETY: the plane's `build` ignores `host`; no host call is made.
    let (class, built) = unsafe { plane.build_owned(core::ptr::null(), HostCtx::NULL, b"{}", &[]) };
    assert_eq!(class, StatusClass::Ok);
    let built = built.expect("Ok yields a handle");
    assert_eq!(
        FREES.load(Ordering::SeqCst),
        0,
        "nothing is freed while held"
    );

    drop(parsed);
    assert_eq!(FREES.load(Ordering::SeqCst), 1);
    drop(built);
    assert_eq!(
        FREES.load(Ordering::SeqCst),
        2,
        "each handle is freed exactly once"
    );
}

// ── Item 387: the admin/OpenAPI slots have a reader ──────────────────────────────────────────

#[test]
fn the_admin_routes_and_openapi_slots_are_read() {
    let _s = serial();
    let mut d = decl();
    let plane = plane_over(&d).unwrap();
    let state = core::ptr::null_mut();
    // SAFETY: the test slots never dereference `state`.
    unsafe {
        assert_eq!(plane.admin_routes(state).unwrap().as_deref(), Some(ROUTES));
        let vacuous = plane.openapi(state);
        assert!(
            vacuous.as_ref().is_err_and(|e| e.contains("non-vacuous")),
            "a present slot that writes nothing is refused: {vacuous:?}"
        );
    }
    d.openapi = Some(t_openapi_overclaim);
    d.admin_routes = None;
    let plane = plane_over(&d).unwrap();
    // SAFETY: as above.
    unsafe {
        assert_eq!(
            plane.admin_routes(state).unwrap(),
            None,
            "absent slot = no surface"
        );
        assert!(
            plane.openapi(state).is_err(),
            "a length past the buffer is refused"
        );
    }
}

// ── Item 388: the constructor crossings run on the never-retiring plugin worker ──────────────

#[test]
fn the_constructor_crossings_run_on_the_plugin_worker() {
    let _s = serial();
    let d = decl();
    let plane = plane_over(&d).unwrap();
    take_threads();
    let _ = plane.config_validate_owned(b"{}");
    // SAFETY: as in the free test.
    let _ = unsafe { plane.build_owned(core::ptr::null(), HostCtx::NULL, b"{}", &[]) };
    assert_eq!(
        take_threads(),
        vec![
            "busbar-plugin-ffi".to_string(),
            "busbar-plugin-ffi".to_string()
        ],
        "config_validate and build must cross on the confined worker, not the caller's thread"
    );
}
