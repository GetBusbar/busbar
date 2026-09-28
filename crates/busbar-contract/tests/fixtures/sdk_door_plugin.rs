// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO'S TEST PLUGIN, DROPPED-IN LEG: a lifecycle-only plugin built with
//! `plugin_door!` (the logic half) and `export_door!` (the `cdylib` half) in one image.
//! `tests/sdk_door_cdylib.rs` loads it, reads its symbol table and calls it through its door.
//! `validate` panics when its settings blob is 13 bytes long.

use std::ffi::c_void;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, OpsHead, RefreshIn, ReleaseIn, TickIn,
    TickOut, ValidateIn,
};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::sdk::door::{KindOps, Slot};

/// The lifecycle-only table.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct LifecycleOnly {
    head: OpsHead,
}

// SAFETY: `#[repr(C)]`, `head: OpsHead` first, nothing after it.
unsafe impl KindOps for LifecycleOnly {
    const KIND: KindCode = KindCode::Secret;
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

ready!(Open, OpenIn, OpenOut);
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
        ops: super::LifecycleOnly,
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
    }
}

busbar_contract::export_door!(logic::door);
