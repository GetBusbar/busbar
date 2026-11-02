// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{
    slot, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn,
    TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::sdk::door::{KindOps, RawSlot};

pub const TARGET: &str = "log_witness";

pub const KIND: KindCode = KindCode::Export;

pub const LOG: &[u8] = b"log";

pub const FLOOD: &[u8] = b"flood";

pub const FLOOD_RECORDS: usize = 300;

pub const OUTSIDE: &[u8] = b"outside";

pub const NEST: &[u8] = b"nest";

/// The lifecycle-only table both plugins answer.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ops {
    head: OpsHead,
}

// SAFETY: `#[repr(C)]`, its one field the `OpsHead`.
unsafe impl KindOps for Ops {
    const KIND: KindCode = KIND;
    type Lifecycle = busbar_contract::abi::sdk::door::Lifecycle;
}

fn mode(input: &TickIn) -> &[u8] {
    let b = input.head.extensions;
    if b.ptr.is_null() || b.fmt != BLOB_OCTETS {
        return &[];
    }
    // SAFETY: the host's extensions blob names `len` live bytes for the call.
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
}

fn log_everything(who: &str) {
    tracing::info!(target: TARGET, who, calls = 1, "tracing from the plugin");
    tracing::debug!(target: TARGET, "tracing at debug from the plugin");
    log::warn!(target: TARGET, "log from the plugin, {who}");
    log::trace!(target: TARGET, "log at trace from the plugin");

    let (client, _server) = tokio::io::duplex(64 * 1024);
    let _ = futures::executor::block_on(h2::client::handshake(client));

    let mut socket = tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(Vec::new()),
        tungstenite::protocol::Role::Server,
        None,
    );
    let _ = socket.send(tungstenite::Message::text("witness"));
}

fn log_outside() {
    eprintln!("witness: straight to standard error");
    let _ = std::thread::spawn(|| {
        tracing::error!(target: TARGET, "witness: tracing from a thread of its own");
        log::error!(target: TARGET, "witness: log from a thread of its own");
    })
    .join();
}

fn call_b(mode: &'static [u8]) {
    // SAFETY: `b::door` answers a static complete lifecycle table, immutable for the process.
    let ops = unsafe { *b::door().ops() };
    let (Some(open), Some(tick), Some(close)) = (ops.open, ops.tick, ops.close) else {
        return;
    };
    // SAFETY: these ABI frames contain only integer and raw-pointer fields; all-zero is valid.
    let mut opening: OpenIn = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut opened: OpenOut = unsafe { MaybeUninit::zeroed().assume_init() };
    opening.head.size = size_of::<OpenIn>() as u32;
    opening.head.op = slot::OPEN;
    opened.head.size = size_of::<OpenOut>() as u32;
    // SAFETY: this first OPEN permits NULL; exact initialized exclusive frames remain live, and
    // this known stateless witness neither needs host tables nor retains nested input pointers.
    let result = unsafe {
        open(
            std::ptr::null_mut(),
            std::ptr::from_ref(&opening).cast(),
            std::ptr::from_mut(&mut opened).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
    assert!(!opened.instance.is_null());
    let instance = opened.instance;
    // SAFETY: all-zero is a valid `TickIn`/`TickOut` (the mechanism's rule for every `in`/`out`).
    let mut input: TickIn = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut out: TickOut = unsafe { MaybeUninit::zeroed().assume_init() };
    input.head.size = size_of::<TickIn>() as u32;
    input.head.op = slot::TICK;
    input.head.extensions.ptr = mode.as_ptr();
    input.head.extensions.len = mode.len();
    input.head.extensions.fmt = BLOB_OCTETS;
    out.head.size = size_of::<TickOut>() as u32;
    // SAFETY: instance is this door's completed OPEN result, not yet closed; the exact TICK
    // frames and static mode remain live for this same-thread crossing.
    let _ = unsafe {
        tick(
            instance,
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
    };
    // OPEN and CLOSE produce no records in this witness. Their empty scoped captures restore
    // plugin A's dispatcher on this same thread, preserving its before/after nested-log proof.
    // SAFETY: the close frames are plain ABI heads with a valid all-zero representation.
    let mut closing: InHead = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut closed: OutHead = unsafe { MaybeUninit::zeroed().assume_init() };
    closing.size = size_of::<InHead>() as u32;
    closing.op = slot::CLOSE;
    closed.size = size_of::<OutHead>() as u32;
    // SAFETY: TICK returned before this sole CLOSE; the original live instance and exact
    // initialized close frames remain valid until the fixture retires its capture ownership.
    let result = unsafe {
        close(
            instance,
            std::ptr::from_ref(&closing).cast(),
            std::ptr::from_mut(&mut closed).cast(),
        )
    };
    assert_eq!(result.outcome(), Outcome::Ready);
}

macro_rules! ready {
    ($name:ident, $in:ty, $out:ty) => {
        struct $name;
        impl RawSlot for $name {
            type In = $in;
            type Out = $out;
            unsafe fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                Outcome::Ready
            }
        }
    };
}

struct Open;
impl RawSlot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    unsafe fn call(_: *mut c_void, _: &OpenIn, out: &mut OpenOut) -> Outcome {
        out.instance = std::ptr::NonNull::<u8>::dangling().as_ptr().cast();
        Outcome::Ready
    }
}

ready!(Validate, ValidateIn, OutHead);
ready!(Refresh, RefreshIn, OutHead);
ready!(Retire, GenIn, OutHead);
ready!(Drive, DriveIn, OutHead);
ready!(Cancel, CancelIn, CancelOut);
ready!(Release, ReleaseIn, OutHead);
ready!(Close, InHead, OutHead);

pub mod a {
    use super::*;

    struct Tick;
    impl RawSlot for Tick {
        type In = TickIn;
        type Out = TickOut;
        unsafe fn call(_: *mut c_void, input: &TickIn, _: &mut TickOut) -> Outcome {
            match mode(input) {
                LOG => log_everything("a"),
                named if named.starts_with(b"log:") => log_everything(
                    std::str::from_utf8(&named[4..]).expect("the test's log label is UTF-8"),
                ),
                FLOOD => {
                    (0..FLOOD_RECORDS).for_each(|i| tracing::info!(target: TARGET, i, "flood"))
                }
                OUTSIDE => log_outside(),
                NEST => {
                    tracing::warn!(target: TARGET, "a, before the nested call");
                    call_b(LOG);
                    tracing::warn!(target: TARGET, "a, after the nested call");
                }
                _ => {}
            }
            Outcome::Ready
        }
    }

    busbar_contract::plugin_door! {
        ops: super::Ops,
        statement: busbar_contract::abi::sdk::door::statement("log-witness-a", "1.6.0", 4),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
    }
}

pub mod b {
    use super::*;

    struct Tick;
    impl RawSlot for Tick {
        type In = TickIn;
        type Out = TickOut;
        unsafe fn call(_: *mut c_void, input: &TickIn, _: &mut TickOut) -> Outcome {
            if mode(input) == LOG {
                tracing::warn!(target: TARGET, "b, inside");
            }
            Outcome::Ready
        }
    }

    busbar_contract::plugin_door! {
        ops: super::Ops,
        statement: busbar_contract::abi::sdk::door::statement("log-witness-b", "1.6.0", 4),
        lifecycle: {
            validate: Validate, open: Open, refresh: Refresh, retire: Retire, tick: Tick,
            drive: Drive, cancel: Cancel, release: Release, close: Close,
        },
    }
}
