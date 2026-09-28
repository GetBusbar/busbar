// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO, DROPPED-IN LEG: the `sdk_door_plugin` example is a `cdylib` built from
//! `plugin_door!` + `export_door!`. This test reads its dynamic symbol table (the door is the only
//! symbol the macros export) and loads it with `dlopen`, reaching the plugin only through
//! `busbar_plugin_door`: a panicking slot answers FAULT and the process lives on.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::mem::size_of;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

use busbar_contract::abi::mechanism::call::{
    Blob, Envelope, InHead, OutHead, Outcome, RawOutcome, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{slot, CancelIn, CancelOut, OpsHead, ValidateIn};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};

extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
}
const RTLD_NOW: c_int = 2;

/// The example `cdylib`, beside this test binary's `deps/` directory.
fn plugin_path() -> PathBuf {
    let exe = std::env::current_exe().expect("test exe");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let name = format!(
        "{}sdk_door_plugin{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = profile.join("examples").join(name);
    assert!(
        path.exists(),
        "the sdk_door_plugin example cdylib was not built at {}: run `cargo test -p busbar-contract` \
         (it builds examples; a `--test`/`--lib`-filtered run or a per-target runner does not)",
        path.display()
    );
    path
}

/// EVERY symbol the image exports (defined, external), read with `nm`.
///
/// The legacy cold lane's `#[no_mangle]` symbols are defined in `busbar-contract` itself
/// (`abi::sdk::__door`), so every image linking the contract exports them until M6 COLD-DELETE;
/// they are listed in [`LEGACY_COLD`] and must be the ONLY other exports. Neither macro emits one.
fn exported_symbols() -> Vec<String> {
    let path = plugin_path();
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-gU"]
    } else {
        &["-D", "--defined-only"]
    };
    let out = Command::new("nm")
        .args(args)
        .arg(&path)
        .output()
        .expect("nm runs");
    assert!(
        out.status.success(),
        "nm failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut syms: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .map(|s| {
            s.strip_prefix('_')
                .filter(|_| cfg!(target_os = "macos"))
                .unwrap_or(s)
        })
        .map(str::to_owned)
        .collect();
    syms.sort();
    syms.dedup();
    syms
}

/// M6-COLD-DELETE: the cold lane's symbols `busbar-contract` defines (`abi::sdk::__door`); this
/// list empties when the cold lane is deleted, leaving `busbar_plugin_door` alone.
const LEGACY_COLD: &[&str] = &[
    "busbar_abi",
    "busbar_call",
    "busbar_close",
    "busbar_free",
    "busbar_open",
    "busbar_plane_arm",
    "busbar_plane_decl",
    "busbar_plugin_kind",
    "busbar_set_log_sink",
    "busbar_transport_decl",
];

#[test]
fn the_macros_export_exactly_one_symbol_the_door() {
    let syms = exported_symbols();
    let door = std::str::from_utf8(&DOOR_SYMBOL[..DOOR_SYMBOL.len() - 1]).unwrap();
    let ours: Vec<&str> = syms
        .iter()
        .map(String::as_str)
        .filter(|s| !LEGACY_COLD.contains(s))
        .collect();
    // In particular the logic crate's `door` is NOT exported: only `export_door!` exports.
    assert_eq!(ours, [door], "all exports: {syms:?}");
}

fn in_head(size: usize, op: u32) -> InHead {
    InHead {
        size: size as u32,
        op,
        flags: 0,
        deadline_class: 0,
        _reserved: [0; 3],
        host: HostCtx {
            ptr: ptr::null_mut(),
        },
        ticket: Ticket::NONE,
        deadline_ns: 0,
        trace_id: [0; 16],
        parent_span_id: 0,
        extensions: absent(),
    }
}

fn absent() -> Blob {
    Blob {
        ptr: ptr::null(),
        len: 0,
        fmt: BLOB_ABSENT,
        flags: 0,
    }
}

fn out_head(size: usize) -> OutHead {
    OutHead {
        size: size as u32,
        outcome: RawOutcome::of(Outcome::Fault),
        _reserved: [0; 3],
        wake_at_ns: 0,
        lease: 0,
        error: busbar_contract::abi::sdk::door::abi_str(""),
        envelope: Envelope {
            metrics: ptr::null(),
            metrics_len: 0,
            diags: ptr::null(),
            diags_len: 0,
        },
        extensions: absent(),
    }
}

#[test]
fn the_dropped_in_door_answers_and_a_panicking_slot_is_fault_not_abort() {
    let path = std::ffi::CString::new(plugin_path().to_str().unwrap()).unwrap();
    // SAFETY: loading a library this build produced; its initializers are Rust's own.
    let lib = unsafe { dlopen(path.as_ptr(), RTLD_NOW) };
    assert!(!lib.is_null(), "dlopen: {:?}", unsafe {
        CStr::from_ptr(dlerror())
    });
    // SAFETY: `DOOR_SYMBOL` is NUL-terminated.
    let sym = unsafe { dlsym(lib, DOOR_SYMBOL.as_ptr().cast()) };
    assert!(!sym.is_null(), "no busbar_plugin_door");
    // SAFETY: the symbol is the macro's `extern "C" fn() -> *const Door`.
    let door_fn: extern "C" fn() -> *const Door = unsafe { std::mem::transmute(sym) };
    // SAFETY: the door is `'static` in the loaded image, which is never unloaded here.
    let door = unsafe { &*door_fn() };
    assert_eq!(door.magic, DOOR_MAGIC);
    assert_eq!(door.mechanism_version, MECHANISM_VERSION);
    assert_eq!(door.kind, KindCode::Secret as u32);
    assert_eq!(door.kind_abi, KindCode::Secret.abi_version());
    // SAFETY: every kind's table begins with an `OpsHead`.
    let head = unsafe { &*door.ops };
    assert_eq!(head.size as usize, size_of::<OpsHead>());

    let validate = head.validate.expect("validate");
    let panics = ValidateIn {
        head: in_head(size_of::<ValidateIn>(), slot::VALIDATE),
        settings: Blob {
            ptr: ptr::null(),
            len: 13,
            fmt: BLOB_ABSENT,
            flags: 0,
        },
    };
    let mut out = out_head(size_of::<OutHead>());
    out.outcome = RawOutcome::of(Outcome::Ready);
    let got = validate(
        ptr::null_mut(),
        ptr::from_ref(&panics).cast(),
        ptr::from_mut(&mut out).cast(),
    );
    assert_eq!(got.outcome(), Outcome::Fault);
    assert_eq!(out.outcome.outcome(), Outcome::Fault);

    // Still alive, still answering; the outcome is mirrored into `out`.
    let cancel = CancelIn {
        head: in_head(size_of::<CancelIn>(), slot::CANCEL),
        ticket: Ticket::NONE,
    };
    let mut out = CancelOut {
        head: out_head(size_of::<CancelOut>()),
        disposition: 0,
        _reserved: 0,
    };
    let got = head.cancel.expect("cancel")(
        ptr::null_mut(),
        ptr::from_ref(&cancel).cast(),
        ptr::from_mut(&mut out).cast(),
    );
    assert_eq!(got.outcome(), Outcome::Failed);
    assert_eq!(out.head.outcome.outcome(), Outcome::Failed);
    assert_eq!(out.disposition, 7);
}
