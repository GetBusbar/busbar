// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO'S TEST PLUGIN, DROPPED-IN LEG: a plugin with one kind op, built with
//! `plugin_door!` (the logic half) and `export_door!` (the `cdylib` half) in one image.
//! `tests/sdk_door_cdylib.rs` loads it, reads its symbol table and calls it through its door.
//! `validate` panics when its settings blob is 13 bytes long; `open` and the kind op `echo`
//! panic at generation 13.

use std::ffi::c_void;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn, TickIn,
    TickOut, ValidateIn, LIFECYCLE_SLOTS,
};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::sdk::door::{KindOps, KindSlot, Slot};

/// The table: the lifecycle and one kind op, `echo` (`GenIn` -> `TickOut`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OneKindOp {
    head: OpsHead,
    echo: Option<busbar_contract::abi::mechanism::call::Op>,
}

// SAFETY: `#[repr(C)]`, `head: OpsHead` first, then one `Option<Op>`.
unsafe impl KindOps for OneKindOp {
    const KIND: KindCode = KindCode::Secret;
}

// SAFETY: this test kind states these structs for its one op.
unsafe impl KindSlot<{ LIFECYCLE_SLOTS }> for OneKindOp {
    type In = GenIn;
    type Out = TickOut;
}

/// The generation at which `open` and `echo` panic.
const PANIC_GEN: u64 = 13;

struct Open;
impl Slot for Open {
    type In = OpenIn;
    type Out = OpenOut;
    fn call(_: *mut c_void, input: &OpenIn, _: &mut OpenOut) -> Outcome {
        assert_ne!(input.generation, PANIC_GEN, "the dropped-in open panics");
        Outcome::Ready
    }
}

struct Echo;
impl Slot for Echo {
    type In = GenIn;
    type Out = TickOut;
    fn call(_: *mut c_void, input: &GenIn, out: &mut TickOut) -> Outcome {
        assert_ne!(input.generation, PANIC_GEN, "the dropped-in kind op panics");
        out.next_tick_ns = input.generation;
        Outcome::Ready
    }
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

struct Validate;
impl Slot for Validate {
    type In = ValidateIn;
    type Out = OutHead;
    fn call(_: *mut c_void, input: &ValidateIn, _: &mut OutHead) -> Outcome {
        if input.settings.len == 13 {
            panic!("the dropped-in slot panics");
        }
        Outcome::Ready
    }
}

struct Cancel;
impl Slot for Cancel {
    type In = CancelIn;
    type Out = CancelOut;
    fn call(_: *mut c_void, _: &CancelIn, out: &mut CancelOut) -> Outcome {
        out.disposition = 7;
        Outcome::Failed
    }
}

ready!(Refresh, RefreshIn, OutHead);
ready!(Retire, GenIn, OutHead);
ready!(Tick, TickIn, TickOut);
ready!(Drive, DriveIn, OutHead);
ready!(Release, ReleaseIn, OutHead);
ready!(Close, InHead, OutHead);

/// The logic half.
pub mod logic {
    use super::*;

    busbar_contract::plugin_door! {
        ops: super::OneKindOp,
        statement: busbar_contract::abi::sdk::door::statement("sdk-door-plugin", "0.0.1", 4),
        lifecycle: {
            validate: Validate,
            open: Open,
            refresh: Refresh,
            retire: Retire,
            tick: Tick,
            drive: Drive,
            cancel: Cancel,
            release: Release,
            close: Close,
        },
        kind_ops: { echo: Echo },
    }
}

busbar_contract::export_door!(logic::door);
