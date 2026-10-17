// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLUGIN-LOGGING WITNESS — a door-macro plugin that logs.
//!
//! Two plugins over the lifecycle table only, [`a`] and [`b`], each its own `plugin_door!` and so
//! its own call capture. `tick` is the test's side door: the `in`'s extensions blob names what the
//! call does.
//!
//! * [`LOG`] — logs through `tracing` and through `log`, from this crate and from two libraries
//!   inside it: `h2` (`tracing`), driving a client handshake over an in-memory pipe, and
//!   `tungstenite` (`log`), sending a frame into a buffer.
//! * [`FLOOD`] — more records than one reply may carry.
//! * [`OUTSIDE`] — writes straight to standard error, and logs from a thread of its own, both
//!   outside any capture: neither may reach the plugin's log file.
//! * [`NEST`] (plugin [`a`] only) — logs, calls plugin [`b`]'s `tick` on the same thread (which
//!   logs), then logs again: each plugin image's capture must keep its own records.
//!
//! One source, compiled into plugin-loader's test build as a module (the LINKED door) and built
//! as the `log_witness_door` example cdylib behind one `export_door!` line (the DROPPED door); the
//! two plugin log files must be byte-identical. The two builds place this source under different
//! module paths, so the witness's own records name one explicit target, [`TARGET`]; a real plugin
//! is one crate in both builds and needs none. The libraries' records carry their own targets.
#![allow(dead_code)]

use std::ffi::c_void;
use std::mem::{size_of, MaybeUninit};

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{
    slot, CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn,
    TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::sdk::door::{KindOps, Slot};

/// The target the witness's own records carry.
pub const TARGET: &str = "log_witness";

/// The witness's kind code: a lifecycle-only table under a real kind's code, as the dispatcher's
/// own test plugin does.
pub const KIND: KindCode = KindCode::Export;

/// `tick` mode: log from the plugin and from the libraries inside it.
pub const LOG: &[u8] = b"log";
/// `tick` mode: log more than one reply may carry.
pub const FLOOD: &[u8] = b"flood";
/// How many records [`FLOOD`] logs.
pub const FLOOD_RECORDS: usize = 300;
/// `tick` mode: write outside any capture.
pub const OUTSIDE: &[u8] = b"outside";
/// `tick` mode (plugin [`a`]): log around a nested call of plugin [`b`].
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

/// The `tick` mode the `in` names.
fn mode(input: &TickIn) -> &[u8] {
    let b = input.head.extensions;
    if b.ptr.is_null() || b.fmt != BLOB_OCTETS {
        return &[];
    }
    // SAFETY: the host's extensions blob names `len` live bytes for the call.
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
}

/// Log through `tracing` and `log`, from here and from `h2` and `tungstenite`.
fn log_everything(who: &str) {
    tracing::info!(target: TARGET, who, calls = 1, "tracing from the plugin");
    tracing::debug!(target: TARGET, "tracing at debug from the plugin");
    log::warn!(target: TARGET, "log from the plugin, {who}");
    log::trace!(target: TARGET, "log at trace from the plugin");
    // `h2` logs through `tracing` while it binds a client connection.
    let (client, _server) = tokio::io::duplex(64 * 1024);
    let _ = futures::executor::block_on(h2::client::handshake(client));
    // `tungstenite` logs through `log` as it sends a frame.
    let mut socket = tungstenite::protocol::WebSocket::from_raw_socket(
        std::io::Cursor::new(Vec::new()),
        tungstenite::protocol::Role::Server,
        None,
    );
    let _ = socket.send(tungstenite::Message::text("witness"));
}

/// Write to standard error, and log from a thread of the plugin's own: outside every capture.
fn log_outside() {
    eprintln!("witness: straight to standard error");
    let _ = std::thread::spawn(|| {
        tracing::error!(target: TARGET, "witness: tracing from a thread of its own");
        log::error!(target: TARGET, "witness: log from a thread of its own");
    })
    .join();
}

/// Call plugin [`b`]'s `tick` directly, on this thread, with `mode`.
fn call_b(mode: &'static [u8]) {
    // SAFETY: `b::door` answers a `'static` door whose table leads with an `OpsHead`.
    let tick = unsafe { (*(*b::door()).ops).tick };
    let Some(tick) = tick else { return };
    // SAFETY: all-zero is a valid `TickIn`/`TickOut` (the mechanism's rule for every `in`/`out`).
    let mut input: TickIn = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut out: TickOut = unsafe { MaybeUninit::zeroed().assume_init() };
    input.head.size = size_of::<TickIn>() as u32;
    input.head.op = slot::TICK;
    input.head.extensions.ptr = mode.as_ptr();
    input.head.extensions.len = mode.len();
    input.head.extensions.fmt = BLOB_OCTETS;
    out.head.size = size_of::<TickOut>() as u32;
    let instance = std::ptr::NonNull::<u8>::dangling()
        .as_ptr()
        .cast::<c_void>();
    let _ = tick(
        instance,
        std::ptr::from_ref(&input).cast(),
        std::ptr::from_mut(&mut out).cast(),
    );
}

macro_rules! ready {
    ($name:ident, $in:ty, $out:ty) => {
        struct $name;
        impl Slot for $name {
            type In = $in;
            type Out = $out;
            fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                Outcome::Ready
            }
        }
    };
}

/// `open`: a non-NULL instance; the witness keeps no state in it.
struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, _: &OpenIn, out: &mut OpenOut) -> Outcome {
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

/// Plugin A: [`LOG`], [`FLOOD`], [`OUTSIDE`] and [`NEST`].
pub mod a {
    use super::*;

    struct Tick;
    impl Slot for Tick {
        type In = TickIn;
        type Out = TickOut;
        fn call(_: *mut c_void, input: &TickIn, _: &mut TickOut) -> Outcome {
            match mode(input) {
                LOG => log_everything("a"),
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

/// Plugin B: [`LOG`] only; plugin A calls it from inside its own call. Its door is never exported:
/// the test build links it, and plugin A reaches it directly.
pub mod b {
    use super::*;

    struct Tick;
    impl Slot for Tick {
        type In = TickIn;
        type Out = TickOut;
        fn call(_: *mut c_void, input: &TickIn, _: &mut TickOut) -> Outcome {
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
