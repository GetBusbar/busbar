// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO, DROPPED-IN LEG: the `sdk_door_plugin` example is a `cdylib` built from
//! `plugin_door!` + `export_door!`. This test reads its dynamic symbol table against a baseline
//! `cdylib` that links the contract and invokes neither macro (the macros export exactly the door),
//! and loads it with `dlopen`, reaching the plugin only through `busbar_plugin_door`: a panicking
//! slot — lifecycle or kind op — answers FAULT and the process lives on.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::mem::size_of;
use std::path::PathBuf;
use std::process::Command;
use std::ptr;

use busbar_contract::abi::mechanism::call::{
    Blob, Envelope, InHead, Op, OutHead, Outcome, RawOutcome, BLOB_ABSENT,
};
use busbar_contract::abi::mechanism::door::Door;
use busbar_contract::abi::mechanism::lifecycle::{
    slot, CancelIn, CancelOut, GenIn, OpenIn, OpenOut, OpsHead, TickOut, ValidateIn,
    LIFECYCLE_SLOTS,
};
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::mechanism::{KindCode, DOOR_MAGIC, DOOR_SYMBOL, MECHANISM_VERSION};

extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlerror() -> *const c_char;
}
const RTLD_NOW: c_int = 2;

/// The generation at which the fixture's `open` and kind op panic.
const PANIC_GEN: u64 = 13;

/// An example `cdylib`, beside this test binary's `deps/` directory.
fn example_path(example: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("test exe");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let name = format!(
        "{}{example}{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = profile.join("examples").join(name);
    assert!(
        path.exists(),
        "the {example} example cdylib was not built at {}: run `cargo test -p busbar-contract` \
         (it builds examples; a `--test`/`--lib`-filtered run or a per-target runner does not)",
        path.display()
    );
    path
}

/// EVERY symbol an image exports (defined, external), read with `nm`, sorted.
fn exported_symbols(example: &str) -> Vec<String> {
    let args: &[&str] = if cfg!(target_os = "macos") {
        &["-gU"]
    } else {
        &["-D", "--defined-only"]
    };
    let out = Command::new("nm")
        .args(args)
        .arg(example_path(example))
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

#[test]
fn the_macros_export_exactly_one_symbol_the_door() {
    let door = std::str::from_utf8(&DOOR_SYMBOL[..DOOR_SYMBOL.len() - 1]).unwrap();
    let plugin = exported_symbols("sdk_door_plugin");
    // M6-COLD-DELETE: the baseline is not empty while `busbar-contract` itself defines the cold
    // lane's `#[no_mangle]` symbols (`abi::sdk::__door`); after the cold lane is deleted it is, and
    // the plugin's whole export list is the door alone.
    let baseline = exported_symbols("sdk_door_baseline");
    assert!(
        !baseline.iter().any(|s| s == door),
        "the contract alone exports the door: {baseline:?}"
    );
    let missing: Vec<&String> = baseline.iter().filter(|s| !plugin.contains(s)).collect();
    assert!(
        missing.is_empty(),
        "the baseline is not a subset: {missing:?}"
    );
    // Exactly what the macros add — in particular the logic crate's `door` is NOT exported.
    let added: Vec<&str> = plugin
        .iter()
        .map(String::as_str)
        .filter(|s| !baseline.iter().any(|b| b == s))
        .collect();
    assert_eq!(added, [door], "plugin exports: {plugin:?}");
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

/// The host's pre-fill, with `outcome` set to READY so a FAULT is proven written.
fn out_head(size: usize) -> OutHead {
    OutHead {
        size: size as u32,
        outcome: RawOutcome::of(Outcome::Ready),
        _reserved: [0; 3],
        wake_at_ns: 0xAAAA,
        lease: 0xBBBB,
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

fn call<I, O>(op: Option<Op>, input: &I, out: &mut O) -> Outcome {
    op.expect("the macro fills every slot")(
        ptr::null_mut(),
        ptr::from_ref(input).cast(),
        ptr::from_mut(out).cast(),
    )
    .outcome()
}

/// The fixture's table: the lifecycle and one kind op.
#[repr(C)]
struct OneKindOp {
    head: OpsHead,
    echo: Option<Op>,
}

#[test]
fn the_dropped_in_door_answers_and_a_panicking_slot_is_fault_not_abort() {
    let path = std::ffi::CString::new(example_path("sdk_door_plugin").to_str().unwrap()).unwrap();
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
    // SAFETY: the fixture's table is a `OneKindOp`.
    let table = unsafe { &*door.ops.cast::<OneKindOp>() };
    assert_eq!(table.head.size as usize, size_of::<OneKindOp>());
    assert_eq!(table.head.slots, LIFECYCLE_SLOTS + 1);

    // A panicking `validate`.
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
    assert_eq!(call(table.head.validate, &panics, &mut out), Outcome::Fault);
    assert_eq!(out.outcome.outcome(), Outcome::Fault);

    // A panicking `open`: FAULT, and no instance handed back.
    let open = OpenIn {
        head: in_head(size_of::<OpenIn>(), slot::OPEN),
        host: ptr::null(),
        settings: absent(),
        secrets: ptr::null(),
        secrets_len: 0,
        generation: PANIC_GEN,
    };
    let mut out = OpenOut {
        head: out_head(size_of::<OpenOut>()),
        instance: ptr::null_mut(),
    };
    assert_eq!(call(table.head.open, &open, &mut out), Outcome::Fault);
    assert_eq!(out.head.outcome.outcome(), Outcome::Fault);
    assert!(out.instance.is_null());

    // A panicking kind op: FAULT, its out untouched but for the outcome.
    let echo = |generation| GenIn {
        head: in_head(size_of::<GenIn>(), LIFECYCLE_SLOTS),
        generation,
    };
    let mut out = TickOut {
        head: out_head(size_of::<TickOut>()),
        next_tick_ns: 0x5EED,
    };
    assert_eq!(call(table.echo, &echo(PANIC_GEN), &mut out), Outcome::Fault);
    assert_eq!(out.head.outcome.outcome(), Outcome::Fault);
    assert_eq!((out.next_tick_ns, out.head.wake_at_ns), (0x5EED, 0xAAAA));

    // Still alive, still answering; the outcome is mirrored into `out`.
    let mut out = TickOut {
        head: out_head(size_of::<TickOut>()),
        next_tick_ns: 0,
    };
    assert_eq!(call(table.echo, &echo(5), &mut out), Outcome::Ready);
    assert_eq!(
        (out.head.outcome.outcome(), out.next_tick_ns),
        (Outcome::Ready, 5)
    );
    let cancel = CancelIn {
        head: in_head(size_of::<CancelIn>(), slot::CANCEL),
        ticket: Ticket::NONE,
    };
    let mut out = CancelOut {
        head: out_head(size_of::<CancelOut>()),
        disposition: 0,
        _reserved: 0,
    };
    assert_eq!(call(table.head.cancel, &cancel, &mut out), Outcome::Failed);
    assert_eq!(out.head.outcome.outcome(), Outcome::Failed);
    assert_eq!(out.disposition, 7);
}
