// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR MACRO'S TEST PLUGIN, DROPPED-IN LEG: a plugin with one kind op, built with

use std::ffi::c_void;

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, DriveIn, GenIn, OpenIn, OpenOut, RefreshIn, ReleaseIn, TickIn, TickOut,
    ValidateIn,
};
use busbar_contract::abi::sdk::door::RawSlot;

use busbar_contract::abi::secret::{Ops, ResolveIn, ResolveOut};
/// The generation at which `open` and `echo` panic.
const PANIC_GEN: u64 = 13;

struct Open;
impl RawSlot for Open {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = OpenIn;
    type Out = OpenOut;
    unsafe fn call(_: *mut c_void, input: &OpenIn, _: &mut OpenOut) -> Outcome {
        assert_ne!(input.generation, PANIC_GEN, "the dropped-in open panics");
        Outcome::Ready
    }
}

struct Echo;
impl RawSlot for Echo {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = ResolveIn;
    type Out = ResolveOut;
    unsafe fn call(_: *mut c_void, input: &ResolveIn, out: &mut ResolveOut) -> Outcome {
        assert_ne!(
            input.settings.len as u64, PANIC_GEN,
            "the dropped-in kind op panics"
        );
        out.needed = input.settings.len as u64;
        Outcome::Ready
    }
}

macro_rules! ready {
    ($name:ident, $in:ty, $out:ty) => {
        struct $name;
        impl RawSlot for $name {
            type Kind = busbar_contract::plugin::markers::SecretKind;
            type In = $in;
            type Out = $out;
            unsafe fn call(_: *mut c_void, _: &$in, _: &mut $out) -> Outcome {
                Outcome::Ready
            }
        }
    };
}

struct Validate;
impl RawSlot for Validate {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = ValidateIn;
    type Out = OutHead;
    unsafe fn call(_: *mut c_void, input: &ValidateIn, _: &mut OutHead) -> Outcome {
        if input.settings.len == 13 {
            panic!("the dropped-in slot panics");
        }
        Outcome::Ready
    }
}

struct Cancel;
impl RawSlot for Cancel {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = CancelIn;
    type Out = CancelOut;
    unsafe fn call(_: *mut c_void, _: &CancelIn, out: &mut CancelOut) -> Outcome {
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
        ops: Ops,
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
        kind_ops: { resolve: Echo },
    }
}

busbar_contract::export_door!(logic::door);
