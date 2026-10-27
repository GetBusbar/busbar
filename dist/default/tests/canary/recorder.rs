// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORDING HOST-TABLE SHIM: a TEST-ONLY wrapper that records the
//! bytes crossing the plugin ABI, both ways, so the canary harness can show where a planted
//! credential crosses (settings, declared secrets, outbound and passthrough credentials).
//!
//! It is built entirely out of the published ABI, in this test binary, and changes no production
//! code path: a plugin door is wrapped on the PLUGIN side of the boundary.
//!
//! * [`wrap`] takes any door (a linked crate's `door`, or the `busbar_plugin_door` symbol of a
//!   cdylib this test `dlopen`ed itself: the same `Door` a dropped-in plugin exports) and answers a
//!   [`DoorFn`] over a copy of it whose every op slot is a trampoline. The trampoline decodes what
//!   the HOST lends the op (`open`/`refresh`/`validate` settings and secrets, an auth op's
//!   credential, settings, caller credential and headers), forwards to the real op, then decodes
//!   what the PLUGIN wrote back into host buffers (an auth `fields` answer).
//! * At `open` (and `ready`) the `HostTables` pointer the loader hands the plugin is swapped for a
//!   RECORDING copy: the services, connector and I/O tables are replaced by tables of trampolines
//!   that decode the bytes the plugin hands the host (a connection's target, every byte written on
//!   a connection or handle, a spawned child's env) and the bytes the host answers
//!   (`records.secret`), then forward to the loader's real slot with the real context.
//!
//! The loader builds ONE `HostTables` shape for every plugin (`dispatch/plugin.rs`, `Plugin::bind`,
//! shared by `load_linked` and the dropped-in loads), so the recording tables wrap the linked and the
//! dropped-in plugins' tables alike; what differs is only where the door came from.
//!
//! Everything here is `unsafe` ABI plumbing over raw pointers the host and plugin exchange. Every read
//! is bounded by the `size` the writer stated, and nothing panics across an `extern "C"` edge: the
//! bookkeeping runs under `catch_unwind`, and the real op or service is always called.

#![allow(unsafe_code)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{offset_of, size_of};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use busbar_contract::abi::auth::{
    slot as auth_slot, FieldSpan, FieldsIn, FieldsOut, NamedValue, OpenOutboundIn, TargetIn,
};
use busbar_contract::abi::host::conn::connector::{ConnectorSlots, EstablishIn, IoIn, RequestIn};
use busbar_contract::abi::host::io::{IoSlots, SpawnIn, WriteIn};
use busbar_contract::abi::host::service::{HostSlots, RecordsSecretIn, ServiceFn, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, InHead, Op, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, DoorParts};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, OpenIn, ReadyIn, RefreshIn, ValidateIn,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};
use busbar_contract::abi::mechanism::KindCode;

/// Which way the bytes went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    /// The host lent or answered them to the plugin.
    HostToPlugin,
    /// The plugin wrote or handed them to the host.
    PluginToHost,
}

impl Dir {
    pub fn arrow(self) -> &'static str {
        match self {
            Dir::HostToPlugin => "host->plugin",
            Dir::PluginToHost => "plugin->host",
        }
    }
}

/// One recorded crossing: who, which way, at which op or service field, and the bytes.
#[derive(Debug, Clone)]
pub struct Crossing {
    pub plugin: String,
    pub dir: Dir,
    pub site: String,
    pub bytes: Vec<u8>,
}

/// Every crossing recorded so far, process-wide.
static LOG: Mutex<Vec<Crossing>> = Mutex::new(Vec::new());

/// Every op and service call the shim forwarded (plugin, site), so a report can show the shim saw
/// traffic even where no bytes were decoded.
static CALLS: Mutex<Vec<(String, String)>> = Mutex::new(Vec::new());

fn push(plugin: &str, dir: Dir, site: String, bytes: Vec<u8>) {
    LOG.lock()
        .unwrap_or_else(|p| p.into_inner())
        .push(Crossing {
            plugin: plugin.to_string(),
            dir,
            site,
            bytes,
        });
}

fn call(plugin: &str, site: String) {
    CALLS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .push((plugin.to_string(), site));
}

/// A snapshot of every crossing recorded so far.
pub fn crossings() -> Vec<Crossing> {
    LOG.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// A snapshot of every forwarded call (plugin, site).
pub fn calls() -> Vec<(String, String)> {
    CALLS.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

// ── raw readers ────────────────────────────────────────────────────────────────────────────────

/// The bytes `ptr..ptr+len`, or nothing for NULL / empty / implausibly long.
///
/// # Safety
/// `ptr` is NULL or valid for `len` bytes, as the ABI states for the field it came from.
unsafe fn bytes(ptr: *const u8, len: usize) -> Vec<u8> {
    if ptr.is_null() || len == 0 || len > (64 << 20) {
        return Vec::new();
    }
    // SAFETY: the caller's contract.
    unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
}

unsafe fn blob(b: &Blob) -> Vec<u8> {
    // SAFETY: a Blob the host or plugin lent states its own extent.
    unsafe { bytes(b.ptr(), b.len()) }
}

unsafe fn abistr(s: &AbiStr) -> Vec<u8> {
    // SAFETY: an AbiStr states its own extent.
    unsafe { bytes(s.ptr(), s.len()) }
}

/// `T` read out of `input`, when the `size` its writer stated covers it.
///
/// # Safety
/// `input` is NULL or points at a struct whose first `u32` is its own size.
unsafe fn read_in<T: Copy>(input: *const c_void) -> Option<T> {
    if input.is_null() {
        return None;
    }
    // SAFETY: every `in` (InHead, ServiceHead) starts with its `size: u32`.
    let size = unsafe { (input as *const u32).read_unaligned() } as usize;
    if size < size_of::<T>() {
        return None;
    }
    // SAFETY: `size` covers `T`.
    Some(unsafe { (input as *const T).read_unaligned() })
}

// ── the door wrapper ───────────────────────────────────────────────────────────────────────────

/// How many doors one test process may wrap.
const MAX_WRAPS: usize = 8;
/// The most op slots a kind's table holds (lifecycle included) that the shim wraps.
const MAX_OPS: usize = 32;

/// One wrapped door: its label, its kind, the real ops and the recording door.
struct Wrapped {
    label: String,
    kind: u32,
    real_ops: Vec<Option<Op>>,
    real_ready: Option<Op>,
    /// The recording door's address (a `&'static Door`, kept as an address so the table is `Sync`).
    door: usize,
}

static WRAPS: [OnceLock<Wrapped>; MAX_WRAPS] = [const { OnceLock::new() }; MAX_WRAPS];
static NEXT_WRAP: AtomicUsize = AtomicUsize::new(0);

/// WRAP `inner` (a door a linked crate or a `dlopen`ed library exports) as `label`: the answer is a
/// [`DoorFn`] over a recording copy of it, admissible wherever the real door is.
///
/// # Safety
/// `inner` is a valid door that outlives the process (a linked door, or a library never unloaded).
pub unsafe fn wrap(label: &str, inner: *const Door) -> DoorFn {
    let w = NEXT_WRAP.fetch_add(1, Ordering::SeqCst);
    assert!(
        w < MAX_WRAPS,
        "the canary shim wraps at most {MAX_WRAPS} doors"
    );
    // SAFETY: the caller's contract.
    let parts: DoorParts = unsafe { Door::read_parts(inner) };
    let ops = parts.ops as *const u8;
    assert!(!ops.is_null(), "the door states an ops table");
    // SAFETY: an ops table starts with OpsHead's `size: u32, slots: u32`.
    let (size, slots) = unsafe {
        (
            (ops as *const u32).read_unaligned() as usize,
            (ops.add(4) as *const u32).read_unaligned() as usize,
        )
    };
    assert!(
        slots <= MAX_OPS && size >= 8 + 8 * slots,
        "an ops table of {slots} slots / {size} bytes"
    );
    let real_ops: Vec<Option<Op>> = (0..slots)
        // SAFETY: `slots` op slots follow the 8-byte head, inside `size`.
        .map(|i| unsafe { (ops.add(8 + 8 * i) as *const Option<Op>).read_unaligned() })
        .collect();
    // The recording table: the real one copied whole, each present slot replaced.
    let mut table = vec![0u64; size.div_ceil(8)];
    // SAFETY: `table` holds at least `size` bytes; the source is the real table of `size` bytes.
    unsafe { std::ptr::copy_nonoverlapping(ops, table.as_mut_ptr() as *mut u8, size) };
    let tramps = op_tramps(w);
    for (i, real) in real_ops.iter().enumerate() {
        if real.is_some() {
            let at = (table.as_mut_ptr() as *mut u8).wrapping_add(8 + 8 * i);
            // SAFETY: slot `i` is inside the table.
            unsafe { (at as *mut Option<Op>).write_unaligned(Some(tramps[i])) };
        }
    }
    let table: &'static [u64] = Box::leak(table.into_boxed_slice());
    let ready = parts.ready.map(|_| ready_tramp(w));
    // SAFETY: the copy states the real door's statement and an ops table of the real one's shape
    // and size; every trampoline forwards to the real slot it replaced.
    let door = unsafe {
        Door::__from_parts(DoorParts {
            ops: table.as_ptr() as *const _,
            ready,
            ..parts
        })
    };
    let door: &'static Door = Box::leak(Box::new(door));
    let _ = WRAPS[w].set(Wrapped {
        label: label.to_string(),
        kind: parts.kind,
        real_ops,
        real_ready: parts.ready,
        door: door as *const Door as usize,
    });
    door_fn(w)
}

fn wrapped(w: usize) -> &'static Wrapped {
    WRAPS[w].get().expect("a wrapped door")
}

extern "C" fn door_at<const W: usize>() -> &'static Door {
    // SAFETY: the address of a leaked `&'static Door` ([`wrap`]).
    unsafe { &*(wrapped(W).door as *const Door) }
}

fn door_fn(w: usize) -> DoorFn {
    match w {
        0 => door_at::<0>,
        1 => door_at::<1>,
        2 => door_at::<2>,
        3 => door_at::<3>,
        4 => door_at::<4>,
        5 => door_at::<5>,
        6 => door_at::<6>,
        _ => door_at::<7>,
    }
}

extern "C" fn op_at<const W: usize, const I: usize>(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    on_op(W, I, instance, input, out)
}

extern "C" fn ready_at<const W: usize>(
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    on_ready(W, instance, input, out)
}

fn ready_tramp(w: usize) -> Op {
    match w {
        0 => ready_at::<0>,
        1 => ready_at::<1>,
        2 => ready_at::<2>,
        3 => ready_at::<3>,
        4 => ready_at::<4>,
        5 => ready_at::<5>,
        6 => ready_at::<6>,
        _ => ready_at::<7>,
    }
}

macro_rules! op_row {
    ($w:literal) => {
        [
            op_at::<$w, 0>,
            op_at::<$w, 1>,
            op_at::<$w, 2>,
            op_at::<$w, 3>,
            op_at::<$w, 4>,
            op_at::<$w, 5>,
            op_at::<$w, 6>,
            op_at::<$w, 7>,
            op_at::<$w, 8>,
            op_at::<$w, 9>,
            op_at::<$w, 10>,
            op_at::<$w, 11>,
            op_at::<$w, 12>,
            op_at::<$w, 13>,
            op_at::<$w, 14>,
            op_at::<$w, 15>,
            op_at::<$w, 16>,
            op_at::<$w, 17>,
            op_at::<$w, 18>,
            op_at::<$w, 19>,
            op_at::<$w, 20>,
            op_at::<$w, 21>,
            op_at::<$w, 22>,
            op_at::<$w, 23>,
            op_at::<$w, 24>,
            op_at::<$w, 25>,
            op_at::<$w, 26>,
            op_at::<$w, 27>,
            op_at::<$w, 28>,
            op_at::<$w, 29>,
            op_at::<$w, 30>,
            op_at::<$w, 31>,
        ]
    };
}

fn op_tramps(w: usize) -> [Op; MAX_OPS] {
    match w {
        0 => op_row!(0),
        1 => op_row!(1),
        2 => op_row!(2),
        3 => op_row!(3),
        4 => op_row!(4),
        5 => op_row!(5),
        6 => op_row!(6),
        _ => op_row!(7),
    }
}

/// The lifecycle and auth op names, for the report.
fn op_name(kind: u32, i: u32) -> String {
    let lifecycle = [
        "validate", "open", "refresh", "retire", "tick", "drive", "cancel", "release", "close",
    ];
    if let Some(n) = lifecycle.get(i as usize) {
        return (*n).to_string();
    }
    if kind == KindCode::Auth as u32 {
        let names = [
            (auth_slot::VERIFY, "verify"),
            (auth_slot::BEGIN_LOGIN, "begin_login"),
            (auth_slot::COMPLETE_LOGIN, "complete_login"),
            (auth_slot::OPEN_OUTBOUND, "open_outbound"),
            (auth_slot::OUTBOUND_READY, "outbound_ready"),
            (auth_slot::FIELDS, "fields"),
            (auth_slot::TARGET, "target"),
        ];
        if let Some((_, n)) = names.iter().find(|(s, _)| *s == i) {
            return (*n).to_string();
        }
    }
    format!("op[{i}]")
}

/// Run `f`, swallowing a panic: bookkeeping must never unwind across the C ABI.
fn quietly(f: impl FnOnce()) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
}

/// The settings and secrets a lifecycle `in` lends.
unsafe fn lent_settings_and_secrets(
    label: &str,
    op: &str,
    settings: &Blob,
    secrets: *const Blob,
    secrets_len: usize,
) {
    // SAFETY: the host lends a settings Blob and `secrets_len` secret Blobs.
    unsafe {
        push(
            label,
            Dir::HostToPlugin,
            format!("op:{op}.settings"),
            blob(settings),
        );
        if !secrets.is_null() && secrets_len <= 64 {
            for k in 0..secrets_len {
                let b = secrets.add(k).read_unaligned();
                push(
                    label,
                    Dir::HostToPlugin,
                    format!("op:{op}.secrets[{k}]"),
                    blob(&b),
                );
            }
        }
    }
}

fn on_op(
    w: usize,
    i: usize,
    instance: *mut c_void,
    input: *const c_void,
    out: *mut c_void,
) -> RawOutcome {
    let wr = wrapped(w);
    let real = wr.real_ops[i].expect("a wrapped slot was present");
    let slot = i as u32;
    let name = op_name(wr.kind, slot);
    let auth = wr.kind == KindCode::Auth as u32;
    quietly(|| call(&wr.label, format!("op:{name}")));
    // BEFORE: what the host lends.
    quietly(|| {
        // SAFETY: `input` is the `in` the host wrote for this slot, sized by its head.
        unsafe {
            match slot {
                life::VALIDATE => {
                    if let Some(v) = read_in::<ValidateIn>(input) {
                        lent_settings_and_secrets(
                            &wr.label,
                            &name,
                            &v.settings,
                            std::ptr::null(),
                            0,
                        );
                    }
                }
                life::OPEN => {
                    if let Some(v) = read_in::<OpenIn>(input) {
                        lent_settings_and_secrets(
                            &wr.label,
                            &name,
                            &v.settings,
                            v.secrets,
                            v.secrets_len,
                        );
                    }
                }
                life::REFRESH => {
                    if let Some(v) = read_in::<RefreshIn>(input) {
                        lent_settings_and_secrets(
                            &wr.label,
                            &name,
                            &v.settings,
                            v.secrets,
                            v.secrets_len,
                        );
                    }
                }
                s if auth && s == auth_slot::OPEN_OUTBOUND => {
                    if let Some(v) = read_in::<OpenOutboundIn>(input) {
                        let h = Dir::HostToPlugin;
                        push(&wr.label, h, format!("op:{name}.style"), abistr(&v.style));
                        push(
                            &wr.label,
                            h,
                            format!("op:{name}.credential"),
                            blob(&v.credential),
                        );
                        push(
                            &wr.label,
                            h,
                            format!("op:{name}.settings"),
                            blob(&v.settings),
                        );
                    }
                }
                s if auth && s == auth_slot::TARGET => {
                    if let Some(v) = read_in::<TargetIn>(input) {
                        let h = Dir::HostToPlugin;
                        push(
                            &wr.label,
                            h,
                            format!("op:{name}.credential"),
                            blob(&v.credential),
                        );
                        push(
                            &wr.label,
                            h,
                            format!("op:{name}.settings"),
                            blob(&v.settings),
                        );
                    }
                }
                s if auth && s == auth_slot::FIELDS => {
                    if let Some(v) = read_in::<FieldsIn>(input) {
                        let h = Dir::HostToPlugin;
                        push(
                            &wr.label,
                            h,
                            format!("op:{name}.caller_credential"),
                            blob(&v.caller_credential),
                        );
                        if !v.headers.is_null() && v.headers_len <= 256 {
                            for k in 0..v.headers_len {
                                let nv: NamedValue = v.headers.add(k).read_unaligned();
                                let mut line = abistr(&nv.name);
                                line.extend_from_slice(b": ");
                                line.extend(blob(&nv.value));
                                push(&wr.label, h, format!("op:{name}.headers[{k}]"), line);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });
    // THE CROSSING: `open` gets the recording host tables in place of the loader's.
    let answer = if slot == life::OPEN && !input.is_null() {
        // SAFETY: an `in` starts with its size; `host` sits at its fixed offset inside it.
        unsafe {
            let size = (input as *const u32).read_unaligned() as usize;
            if size >= size_of::<OpenIn>() {
                let mut copy = vec![0u64; size.div_ceil(8)];
                std::ptr::copy_nonoverlapping(
                    input as *const u8,
                    copy.as_mut_ptr() as *mut u8,
                    size,
                );
                let at = (copy.as_mut_ptr() as *mut u8).add(offset_of!(OpenIn, host))
                    as *mut *const HostTables;
                at.write_unaligned(recording_tables(&wr.label, at.read_unaligned()));
                real(instance, copy.as_ptr() as *const c_void, out)
            } else {
                real(instance, input, out)
            }
        }
    } else {
        real(instance, input, out)
    };
    // AFTER: what the plugin wrote back into the host's buffers.
    quietly(|| {
        if !(auth && slot == auth_slot::FIELDS) || answer.outcome() != Outcome::Ready {
            return;
        }
        // SAFETY: the `in`'s field buffer and span list are the host's, which the plugin wrote; the
        // `out` the plugin answered states how many spans it filled.
        unsafe {
            let (Some(v), Some(o)) = (
                read_in::<FieldsIn>(input),
                read_in::<FieldsOut>(out as *const c_void),
            ) else {
                return;
            };
            if v.fields.is_null() || v.field_buf.is_null() {
                return;
            }
            let n = (o.fields_len.min(v.fields_cap)) as usize;
            let buf = std::slice::from_raw_parts(v.field_buf as *const u8, v.field_buf_cap);
            for k in 0..n {
                let span: FieldSpan = (v.fields as *const FieldSpan).add(k).read_unaligned();
                let pick = |off: u32, len: u32| {
                    let (off, len) = (off as usize, len as usize);
                    buf.get(off..off.saturating_add(len))
                        .unwrap_or(&[])
                        .to_vec()
                };
                let mut line = pick(span.name.offset, span.name.len);
                line.extend_from_slice(b": ");
                line.extend(pick(span.value.offset, span.value.len));
                push(
                    &wr.label,
                    Dir::PluginToHost,
                    format!("op:{name}.answer[{k}]"),
                    line,
                );
            }
        }
    });
    answer
}

fn on_ready(w: usize, instance: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
    let wr = wrapped(w);
    let real = wr.real_ready.expect("a wrapped ready was present");
    quietly(|| call(&wr.label, "op:ready".into()));
    if input.is_null() {
        return real(instance, input, out);
    }
    // SAFETY: as `open`: the `in` is sized by its head and `host` sits at its fixed offset.
    unsafe {
        let size = (input as *const u32).read_unaligned() as usize;
        if size < size_of::<ReadyIn>() {
            return real(instance, input, out);
        }
        let mut copy = vec![0u64; size.div_ceil(8)];
        std::ptr::copy_nonoverlapping(input as *const u8, copy.as_mut_ptr() as *mut u8, size);
        let at =
            (copy.as_mut_ptr() as *mut u8).add(offset_of!(ReadyIn, host)) as *mut *const HostTables;
        at.write_unaligned(recording_tables(&wr.label, at.read_unaligned()));
        real(instance, copy.as_ptr() as *const c_void, out)
    }
}

// ── the recording host tables ──────────────────────────────────────────────────────────────────

/// The three host tables a `HostTables` names.
const SERVICES: usize = 0;
const CONNS: usize = 1;
const IO: usize = 2;
/// The most slots one host table holds that the shim wraps.
const MAX_SVC: usize = 40;

/// The loader's real table of each family (its address), first seen.
static REAL: [OnceLock<usize>; 3] = [const { OnceLock::new() }; 3];
/// The recording table of each family (its address).
static RECORDING: [OnceLock<usize>; 3] = [const { OnceLock::new() }; 3];
/// A host context's plugin label, and the recording `HostTables` made for a real one.
static CONTEXTS: Mutex<Option<HashMap<u64, String>>> = Mutex::new(None);
static MADE: Mutex<Option<HashMap<usize, usize>>> = Mutex::new(None);

fn label_of(ctx: HostCtx) -> String {
    CONTEXTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .as_ref()
        .and_then(|m| m.get(&ctx.handle).cloned())
        .unwrap_or_else(|| format!("ctx#{}", ctx.handle))
}

/// The recording copy of the loader's `real` tables, made once per real tables pointer.
///
/// # Safety
/// `real` is NULL or the loader's `HostTables`, valid for the process.
unsafe fn recording_tables(label: &str, real: *const HostTables) -> *const HostTables {
    if real.is_null() {
        return real;
    }
    let mut made = MADE.lock().unwrap_or_else(|p| p.into_inner());
    let made = made.get_or_insert_with(HashMap::new);
    if let Some(&rec) = made.get(&(real as usize)) {
        return rec as *const HostTables;
    }
    // SAFETY: the caller's contract; `size` states how much of the struct the host wrote.
    let size = unsafe { (real as *const u32).read_unaligned() } as usize;
    if size < size_of::<HostTables>() {
        return real;
    }
    // SAFETY: as above.
    let mut t: HostTables = unsafe { real.read_unaligned() };
    CONTEXTS
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(t.ctx.handle, label.to_string());
    // SAFETY: each table pointer is NULL or the loader's `'static` table.
    unsafe {
        t.services = recording_table(SERVICES, t.services as *const u8) as *const HostSlots;
        t.conns = recording_table(CONNS, t.conns as *const u8) as *const ConnectorSlots;
        t.io = recording_table(IO, t.io as *const u8) as *const IoSlots;
    }
    let rec: &'static HostTables = Box::leak(Box::new(t));
    made.insert(real as usize, rec as *const HostTables as usize);
    rec
}

/// The recording copy of one family's real table (`size: u32, slots: u32`, then `slots` service
/// fns), or the real table itself when this family already had a different one.
unsafe fn recording_table(family: usize, real: *const u8) -> *const u8 {
    if real.is_null() {
        return real;
    }
    let first = *REAL[family].get_or_init(|| real as usize);
    if first != real as usize {
        // A second real table of one family: forward untouched rather than guess.
        return real;
    }
    let rec = *RECORDING[family].get_or_init(|| {
        // SAFETY: a host table starts with `size: u32, slots: u32`.
        let (size, slots) = unsafe {
            (
                (real as *const u32).read_unaligned() as usize,
                (real.add(4) as *const u32).read_unaligned() as usize,
            )
        };
        let slots = slots.min(MAX_SVC).min(size.saturating_sub(8) / 8);
        let mut table = vec![0u64; size.div_ceil(8)];
        // SAFETY: `table` holds `size` bytes; the real table is `size` bytes.
        unsafe { std::ptr::copy_nonoverlapping(real, table.as_mut_ptr() as *mut u8, size) };
        let tramps = svc_tramps(family);
        for (i, tramp) in tramps.iter().enumerate().take(slots) {
            // SAFETY: slot `i` is inside both tables.
            unsafe {
                let present = (real.add(8 + 8 * i) as *const Option<ServiceFn>).read_unaligned();
                if present.is_some() {
                    ((table.as_mut_ptr() as *mut u8).add(8 + 8 * i) as *mut Option<ServiceFn>)
                        .write_unaligned(Some(*tramp));
                }
            }
        }
        Box::leak(table.into_boxed_slice()).as_ptr() as usize
    });
    rec as *const u8
}

extern "C" fn svc_at<const T: usize, const I: usize>(
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    on_svc(T, I, ctx, input, out)
}

macro_rules! svc_row {
    ($t:literal) => {
        [
            svc_at::<$t, 0>,
            svc_at::<$t, 1>,
            svc_at::<$t, 2>,
            svc_at::<$t, 3>,
            svc_at::<$t, 4>,
            svc_at::<$t, 5>,
            svc_at::<$t, 6>,
            svc_at::<$t, 7>,
            svc_at::<$t, 8>,
            svc_at::<$t, 9>,
            svc_at::<$t, 10>,
            svc_at::<$t, 11>,
            svc_at::<$t, 12>,
            svc_at::<$t, 13>,
            svc_at::<$t, 14>,
            svc_at::<$t, 15>,
            svc_at::<$t, 16>,
            svc_at::<$t, 17>,
            svc_at::<$t, 18>,
            svc_at::<$t, 19>,
            svc_at::<$t, 20>,
            svc_at::<$t, 21>,
            svc_at::<$t, 22>,
            svc_at::<$t, 23>,
            svc_at::<$t, 24>,
            svc_at::<$t, 25>,
            svc_at::<$t, 26>,
            svc_at::<$t, 27>,
            svc_at::<$t, 28>,
            svc_at::<$t, 29>,
            svc_at::<$t, 30>,
            svc_at::<$t, 31>,
            svc_at::<$t, 32>,
            svc_at::<$t, 33>,
            svc_at::<$t, 34>,
            svc_at::<$t, 35>,
            svc_at::<$t, 36>,
            svc_at::<$t, 37>,
            svc_at::<$t, 38>,
            svc_at::<$t, 39>,
        ]
    };
}

fn svc_tramps(family: usize) -> [ServiceFn; MAX_SVC] {
    match family {
        SERVICES => svc_row!(0),
        CONNS => svc_row!(1),
        _ => svc_row!(2),
    }
}

/// The slot index of a table field at byte offset `off` (after the 8-byte head).
const fn idx(off: usize) -> usize {
    (off - 8) / 8
}

fn svc_name(family: usize, i: usize) -> String {
    let named: &[(usize, &str)] = match family {
        SERVICES => &[
            (idx(offset_of!(HostSlots, records_get)), "records_get"),
            (idx(offset_of!(HostSlots, records_secret)), "records_secret"),
            (idx(offset_of!(HostSlots, sign)), "sign"),
            (idx(offset_of!(HostSlots, need_admit)), "need_admit"),
            (idx(offset_of!(HostSlots, clock_now)), "clock_now"),
            (idx(offset_of!(HostSlots, random_fill)), "random_fill"),
        ],
        CONNS => &[
            (idx(offset_of!(ConnectorSlots, establish)), "establish"),
            (idx(offset_of!(ConnectorSlots, read)), "read"),
            (idx(offset_of!(ConnectorSlots, write)), "write"),
            (
                idx(offset_of!(ConnectorSlots, write_request)),
                "write_request",
            ),
            (idx(offset_of!(ConnectorSlots, read_reply)), "read_reply"),
            (idx(offset_of!(ConnectorSlots, close)), "close"),
        ],
        _ => &[
            (idx(offset_of!(IoSlots, open)), "open"),
            (idx(offset_of!(IoSlots, write)), "write"),
            (idx(offset_of!(IoSlots, read)), "read"),
            (idx(offset_of!(IoSlots, spawn)), "spawn"),
        ],
    };
    let table = ["services", "conns", "io"][family.min(2)];
    match named.iter().find(|(n, _)| *n == i) {
        Some((_, n)) => format!("svc:{table}.{n}"),
        None => format!("svc:{table}[{i}]"),
    }
}

fn on_svc(
    family: usize,
    i: usize,
    ctx: HostCtx,
    input: *const c_void,
    out: *mut ServiceOut,
) -> RawOutcome {
    let real_table = *REAL[family].get().expect("a recorded family") as *const u8;
    // SAFETY: the recording table only holds a trampoline where the real table holds a service.
    let real = unsafe { (real_table.add(8 + 8 * i) as *const Option<ServiceFn>).read_unaligned() }
        .expect("a wrapped service was present");
    let site = svc_name(family, i);
    let label = label_of(ctx);
    quietly(|| call(&label, site.clone()));
    // BEFORE: what the plugin hands the host.
    quietly(|| {
        let p = Dir::PluginToHost;
        // SAFETY: `input` is the plugin's `in` for this service, sized by its head.
        unsafe {
            match (family, i) {
                (CONNS, n) if n == idx(offset_of!(ConnectorSlots, establish)) => {
                    if let Some(v) = read_in::<EstablishIn>(input) {
                        push(&label, p, format!("{site}.target"), abistr(&v.target));
                        push(&label, p, format!("{site}.within"), abistr(&v.within));
                    }
                }
                (CONNS, n) if n == idx(offset_of!(ConnectorSlots, write)) => {
                    if let Some(v) = read_in::<IoIn>(input) {
                        push(&label, p, format!("{site}.bytes"), bytes(v.buf, v.len));
                    }
                }
                (CONNS, n) if n == idx(offset_of!(ConnectorSlots, write_request)) => {
                    if let Some(v) = read_in::<RequestIn>(input) {
                        push(&label, p, format!("{site}.bytes"), bytes(v.buf, v.len));
                    }
                }
                (IO, n) if n == idx(offset_of!(IoSlots, write)) => {
                    if let Some(v) = read_in::<WriteIn>(input) {
                        push(&label, p, format!("{site}.bytes"), bytes(v.bytes, v.len));
                    }
                }
                (IO, n) if n == idx(offset_of!(IoSlots, spawn)) => {
                    if let Some(v) = read_in::<SpawnIn>(input) {
                        push(&label, p, format!("{site}.program"), abistr(&v.program));
                        if !v.env.is_null() && v.env_len <= 1024 {
                            for k in 0..v.env_len {
                                let f: Field = v.env.add(k).read_unaligned();
                                let mut line = abistr(&f.name);
                                line.push(b'=');
                                line.extend(abistr(&f.value));
                                push(&label, p, format!("{site}.env[{k}]"), line);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });
    let answer = real(ctx, input, out);
    // AFTER: what the host answered into the plugin's buffers.
    quietly(|| {
        if family != SERVICES
            || i != idx(offset_of!(HostSlots, records_secret))
            || answer.outcome() != Outcome::Ready
        {
            return;
        }
        // SAFETY: the plugin's buffers, which the host filled `out.len` bytes of.
        unsafe {
            let (Some(v), Some(o)) = (
                read_in::<RecordsSecretIn>(input),
                read_in::<ServiceOut>(out as *const c_void),
            ) else {
                return;
            };
            let n = (o.len as usize).min(v.into.cap);
            push(
                &label,
                Dir::HostToPlugin,
                format!("{site}.answer"),
                bytes(v.into.buf, n),
            );
        }
    });
    answer
}

// The `InHead` import documents what every `in` starts with; keep it referenced.
const _: usize = size_of::<InHead>();
