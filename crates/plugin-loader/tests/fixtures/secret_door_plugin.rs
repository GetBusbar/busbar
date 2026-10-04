// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S RED-ARM FIXTURE, on the secret kind's memory ABI (`abi::secret`): a plugin
//! whose `resolve` answers READY while naming an `error_kind`, a contradiction `check_resolve`
//! refuses, so the host must answer FAULT. The conforming side of the secret kind's both-ways proof
//! is the REAL env source (`secret_door_conformance_tests`); a real plugin cannot be broken on
//! purpose, so only the broken door lives here.
//!
//! One source, compiled into plugin-loader's test build as a module (the LINKED door) and built as
//! the example `cdylib` `secret_broken_door` behind one `export_door!` line (the DROPPED door).
#![allow(dead_code)]

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{cancel, ResolveIn, ResolveOut, ERROR_KIND_NOT_FOUND};

/// The broken door's Statement name.
pub const BROKEN_NAME: &str = "both-ways-secret-broken";

/// The instance: it holds nothing.
pub struct Nothing;

impl Life for Nothing {
    const CANCEL: u32 = cancel::ABORTED;

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Nothing)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// `resolve`, BROKEN: READY, naming an `error_kind` (`check_resolve`: a contradiction).
pub struct ResolveBroken;

impl SafeSlot for ResolveBroken {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Nothing>;

    fn call(
        _: Instance<'_, Held<Nothing>>,
        _: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        out.set(|o| &o.error_kind, ERROR_KIND_NOT_FOUND);
        Outcome::Ready
    }
}

/// The broken secret plugin's door.
pub mod broken {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(super::BROKEN_NAME, "1.6.0", 8),
        lifecycle: life(super::Nothing),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::ResolveBroken> },
    }
}
