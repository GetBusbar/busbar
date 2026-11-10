// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Deterministic secret-kind ABI witness. It neither reads external state nor implements a source.

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{cancel, CheckIn, ResolveIn, ResolveOut, ERROR_KIND_NOT_FOUND};

pub const NAME: &str = "neutral-secret-witness";
pub const MATERIAL: &str = "sdk-secret-crossing-witness";

pub struct Witness;
impl Life for Witness {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    const CANCEL: u32 = cancel::ABORTED;
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self)
    }
    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

pub struct Resolve;
impl SafeSlot for Resolve {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, Self::Kind>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        if instance.get().is_none() {
            return Outcome::Refused;
        }
        let settings: serde_json::Value =
            serde_json::from_slice(input.field(|i| &i.settings).bytes()).unwrap_or_default();
        if settings["case"] == "hit" {
            busbar_contract::abi::sdk::cred::resolved(
                input,
                &mut out,
                busbar_contract::abi::sdk::cred::Held::new(MATERIAL.as_bytes().to_vec()),
            )
        } else {
            out.set(|o| &o.error_kind, ERROR_KIND_NOT_FOUND);
            out.fail(Refusal::failed("witness miss"))
        }
    }
}

pub struct Check;
impl SafeSlot for Check {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = CheckIn;
    type Out = OutHead;
    type State = Held<Witness>;
    fn call(
        _: Instance<'_, Self::State, Self::Kind>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let settings: serde_json::Value =
            serde_json::from_slice(input.field(|i| &i.settings).bytes()).unwrap_or_default();
        match settings["case"].as_str() {
            Some("hit" | "miss") => Outcome::Ready,
            _ => out.fail(Refusal::failed("expected a witness case")),
        }
    }
}

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::secret::Ops,
    statement: busbar_contract::abi::sdk::door::statement(NAME, "1.6.0", 16),
    lifecycle: life(Witness),
    kind_ops: {
        resolve: busbar_contract::abi::sdk::Safe<Resolve>,
        check: busbar_contract::abi::sdk::Safe<Check>,
    },
}
