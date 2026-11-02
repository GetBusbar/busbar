// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![allow(dead_code)]

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{cancel, CheckIn, ResolveIn, ResolveOut, ERROR_KIND_NOT_FOUND};

pub const BROKEN_NAME: &str = "both-ways-secret-broken";

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

pub mod broken {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(super::BROKEN_NAME, "1.6.0", 8),
        lifecycle: life(super::Nothing),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::ResolveBroken> },
    }
}

pub const CHECKING_NAME: &str = "secret-checking";

pub const NOT_ABSOLUTE: &str = "settings.path: must name an absolute path";

pub struct CheckPath;

impl SafeSlot for CheckPath {
    type In = CheckIn;
    type Out = OutHead;
    type State = Held<Nothing>;

    fn call(
        _: Instance<'_, Held<Nothing>>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let settings: serde_json::Value =
            serde_json::from_slice(input.field(|i| &i.settings).bytes()).unwrap_or_default();
        match settings["path"].as_str() {
            Some(p) if p.starts_with('/') => Outcome::Ready,
            _ => out.fail(Refusal::failed(NOT_ABSOLUTE)),
        }
    }
}

pub mod checking {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(super::CHECKING_NAME, "1.6.0", 8),
        lifecycle: life(super::Nothing),
        kind_ops: {
            resolve: busbar_contract::abi::sdk::Safe<super::ResolveBroken>,
            check: busbar_contract::abi::sdk::Safe<super::CheckPath>,
        },
    }
}
