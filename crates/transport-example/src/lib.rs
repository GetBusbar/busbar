// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: transport` plugin** — a `cdylib` exporting a real
//! [`busbar_plugin::hot::TransportDecl`] over the HOT-tier ABI. It is the in-tree both-ways coverage
//! for the `kind: transport` seam (the ABI-fixture analogue of `busbar-plugin-example-plane`), and the
//! copy-me template a carrier author exports through [`busbar_plugin_sdk::export_transport_plugin!`].
//!
//! ## STANDALONE ON PURPOSE
//!
//! Like the example plane fixture, this crate names NO shipped carrier: its whole behaviour is in this
//! file. It is a REAL, loadable carrier — every slot is wired (no `unimplemented!()`), every FFI body
//! runs inside a `catch_unwind`, and every out-param is written only on the `Ok` path — but its
//! "carrier" is a deliberately trivial in-memory LOOPBACK (a per-connection FIFO): its job is to prove
//! the ABI round-trips a BIDIRECTIONAL byte stream, not to move bytes over a real socket. The seven
//! shipped carriers (`busbar-transport-{http,ws,stdio,tcp,tls,sse,grpc}`) are untouched.
//!
//! ## Bidirectional by construction
//!
//! The decl provides BOTH directions — [`accept`](busbar_plugin::hot::transport::AcceptFn) (the
//! passive/server-accept side) and [`connect`](busbar_plugin::hot::transport::ConnectFn) (the
//! active/client-connect side) — the two directions of the ONE transport kind (`DECISIONS #3`). Each
//! yields a loopback connection whose [`write`](busbar_plugin::hot::transport::WriteFn) enqueues bytes
//! that its [`read`](busbar_plugin::hot::transport::ReadFn) dequeues, so the conformance rig proves a
//! byte written INTO the carrier over the ABI comes back OUT of it over the ABI — a real round trip.
//!
//! ## Both-ways by construction
//!
//! [`TRANSPORT_DECL`] is a `pub static`, so the SAME decl is usable STATICALLY (compiled-in) OR
//! DROPPED-IN (the `cdylib` the [`export_transport_plugin!`](busbar_plugin_sdk::export_transport_plugin)
//! symbols deliver, loaded by `busbar_plugin_loader::load_transport`). The drop-in conformance test
//! loads it BOTH ways and asserts the two decls are byte-identical at the vocabulary/facet/preamble
//! surface — the carrier's both-ways proof over the ABI.

use busbar_plugin::hot::decl::{BuildCtx, OpaqueHandle};
use busbar_plugin::hot::pod::{OpaqueState, RawStatus, StatusClass};
use busbar_plugin::hot::transport::{TransportDecl, TransportFacet};
use busbar_plugin::{write_out, AbiPreamble};
use core::mem::MaybeUninit;
use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

// ── The carrier's own vocabulary (borrowed by the decl; `'static` for the life of the image) ────────
const NAME: &[u8] = b"example";
const SECTION_KEY: &[u8] = b"example";
const SCOPE: &[u8] = b"example";
const LABEL: &[u8] = b"Example Transport";

/// The parsed-config handle `config_validate` produces. Trivial (the example accepts any config), but
/// a REAL heap allocation so the `free` round-trip is exercised, not skipped.
struct ParsedConfig;

/// The built carrier's live state. The example holds nothing but a real allocation so the handle
/// round-trip (`build` → core keeps it → `free`) is genuinely exercised.
struct CarrierState;

/// A loopback connection: a FIFO of bytes `write` enqueues and `read` dequeues. `Mutex` (not `Cell`)
/// so the [`OpaqueState`] handle is `Send`/`Sync` — it may cross the seam and be driven from any thread.
struct Conn {
    fifo: Mutex<std::collections::VecDeque<u8>>,
}

impl Conn {
    fn new() -> Self {
        Conn {
            fifo: Mutex::new(std::collections::VecDeque::new()),
        }
    }
}

/// NEVER-PANICS free for a [`ParsedConfig`] handle. # Safety: `ptr`, when non-null, is exactly a handle
/// `config_validate` produced.
extern "C-unwind" fn free_parsed(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ptr` was `Box::into_raw`'d from a `Box<ParsedConfig>` in `config_validate`.
        drop(unsafe { Box::from_raw(ptr as *mut ParsedConfig) });
    }));
}

/// NEVER-PANICS free for a [`CarrierState`] handle. # Safety: `ptr`, when non-null, is exactly a
/// handle `build` produced and not yet freed.
extern "C-unwind" fn free_state(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ptr` was `Box::into_raw`'d from a `Box<CarrierState>` in `build`.
        drop(unsafe { Box::from_raw(ptr as *mut CarrierState) });
    }));
}

/// NEVER-PANICS free (the "close") for a [`Conn`] handle. Closing a connection IS freeing its handle —
/// the carrier needs no separate close symbol. # Safety: `ptr`, when non-null, is exactly a handle an
/// `accept`/`connect` produced and not yet freed.
extern "C-unwind" fn free_conn(ptr: *mut c_void) {
    if ptr.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `ptr` was `Box::into_raw`'d from a `Box<Conn>` in `accept`/`connect`.
        drop(unsafe { Box::from_raw(ptr as *mut Conn) });
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

/// `build` — construct the carrier from a [`BuildCtx`] (secrets pre-resolved), producing the opaque
/// carrier handle core keeps and never downcasts. The example ignores the config/refs; it only proves
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
            ptr: Box::into_raw(Box::new(CarrierState)) as *mut c_void,
            free: Some(free_state),
        };
        // SAFETY: as `config_validate`.
        unsafe { write_out(out_handle, handle) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// Shared body for both direction slots: recover the carrier state (proving the handle crossed the
/// seam) and yield a fresh loopback [`Conn`] handle. `accept` (passive) and `connect` (active) produce
/// the SAME loopback shape — the fixture proves both DIRECTION slots round-trip, not two wire formats.
fn open_conn(state: *mut c_void, out_conn: *mut MaybeUninit<OpaqueHandle>) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        if state.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `state` is a live `CarrierState` `build` produced (ABI discipline). Touched only to
        // prove it crossed the seam.
        let _st = unsafe { &*(state as *const CarrierState) };
        let handle = OpaqueState {
            ptr: Box::into_raw(Box::new(Conn::new())) as *mut c_void,
            free: Some(free_conn),
        };
        // SAFETY: init-only-on-Ok.
        unsafe { write_out(out_conn, handle) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// `accept` — the passive/server-accept direction: yield a loopback connection.
extern "C-unwind" fn accept(
    state: *mut c_void,
    out_conn: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    RawStatus::of(open_conn(state, out_conn))
}

/// `connect` — the active/client-connect direction: yield a loopback connection to `dest` (opaque; the
/// example ignores it beyond proving the borrowed range crossed the seam).
extern "C-unwind" fn connect(
    state: *mut c_void,
    dest_ptr: *const u8,
    dest_len: usize,
    out_conn: *mut MaybeUninit<OpaqueHandle>,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        // Touch the destination range so a dropped `(ptr,len)` would be observable, not ignored.
        if dest_len != 0 && dest_ptr.is_null() {
            return StatusClass::Refused;
        }
        open_conn(state, out_conn)
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `write` — enqueue `len` bytes into the loopback FIFO; report all of them accepted.
extern "C-unwind" fn write(
    conn: *mut c_void,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if conn.is_null() || (len != 0 && buf.is_null()) || out_written.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: `conn` is a live `Conn` an accept/connect produced; `buf`/`len` a borrowed range live
        // for the call.
        let c = unsafe { &*(conn as *const Conn) };
        let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
        {
            let mut fifo = c.fifo.lock().unwrap_or_else(|e| e.into_inner());
            fifo.extend(bytes.iter().copied());
        }
        // SAFETY: `out_written` is a live caller slot (non-null checked above).
        unsafe { *out_written = len };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// `read` — dequeue up to `cap` bytes out of the loopback FIFO into the caller buffer.
extern "C-unwind" fn read(
    conn: *mut c_void,
    buf: *mut u8,
    cap: usize,
    out_written: *mut usize,
) -> RawStatus {
    let class = catch_unwind(AssertUnwindSafe(|| {
        if conn.is_null() || (cap != 0 && buf.is_null()) || out_written.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: as `write`.
        let c = unsafe { &*(conn as *const Conn) };
        let mut n = 0usize;
        {
            let mut fifo = c.fifo.lock().unwrap_or_else(|e| e.into_inner());
            while n < cap {
                match fifo.pop_front() {
                    Some(b) => {
                        // SAFETY: `n < cap` and `buf` addresses `cap` writable bytes.
                        unsafe { *buf.add(n) = b };
                        n += 1;
                    }
                    None => break,
                }
            }
        }
        // SAFETY: `out_written` is a live caller slot (non-null checked above).
        unsafe { *out_written = n };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault);
    RawStatus::of(class)
}

/// THE decl: the example carrier's `#[repr(C)]` HOT-tier vtable. A `pub static` so it is BOTH the
/// compiled-in reference (linked as an `rlib`) AND, via
/// [`export_transport_plugin!`](busbar_plugin_sdk::export_transport_plugin) below, the dropped-in
/// `cdylib` entrypoint's payload. Provides BOTH directions — the fully bidirectional carrier.
pub static TRANSPORT_DECL: TransportDecl = TransportDecl {
    abi: AbiPreamble::CURRENT,
    size: core::mem::size_of::<TransportDecl>() as u32,
    version: busbar_plugin::ABI_MINOR,
    name_ptr: NAME.as_ptr(),
    name_len: NAME.len(),
    section_key_ptr: SECTION_KEY.as_ptr(),
    section_key_len: SECTION_KEY.len(),
    scope_ptr: SCOPE.as_ptr(),
    scope_len: SCOPE.len(),
    label_ptr: LABEL.as_ptr(),
    label_len: LABEL.len(),
    provided_facets: TransportFacet::bidirectional(),
    _reserved: 0,
    config_validate: Some(config_validate),
    build: Some(build),
    accept: Some(accept),
    connect: Some(connect),
    write: Some(write),
    read: Some(read),
};

// Emit the `cdylib` boundary symbols (`busbar_abi`, `busbar_plugin_kind() == "transport"`,
// `busbar_transport_decl()`), delivering `TRANSPORT_DECL` as the dropped-in entrypoint's payload.
busbar_plugin_sdk::export_transport_plugin!(TRANSPORT_DECL);
