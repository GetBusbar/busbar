// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SECRET KIND'S BOTH-WAYS FIXTURE, on the secret kind's memory ABI (`abi::secret`), built
//! with the SDK's generic lifecycle (`lifecycle: life(L)`) and safe slots only.
//!
//! One source, compiled into plugin-loader's test build as a module (the LINKED doors) and built
//! as two example `cdylib`s behind one `export_door!` line each (the DROPPED doors):
//!
//! * [`conforming`] (`secret_door`) — `resolve` answers within the kind's contract: the material
//!   its settings name, READY under a lease; FAILED naming its `error_kind` otherwise.
//! * [`broken`] (`secret_broken_door`) — the same plugin whose `resolve` answers READY while naming
//!   an `error_kind`, a contradiction `check_resolve` refuses: the host must answer FAULT.
//!
//! The settings are `{"values": {"<name>": "<material>"}}`; a resolve's settings `{"name": "<name>"}`.
#![allow(dead_code)]

use std::collections::BTreeMap;

use busbar_contract::abi::mechanism::call::{Outcome, BLOB_OCTETS};
use busbar_contract::abi::sdk::life::{settings_object, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{
    cancel, ResolveIn, ResolveOut, ERROR_KIND_INVALID, ERROR_KIND_NOT_FOUND,
};

/// The conforming door's Statement name.
pub const NAME: &str = "both-ways-secret";
/// The broken door's Statement name.
pub const BROKEN_NAME: &str = "both-ways-secret-broken";

/// The instance: the material each name resolves to.
pub struct Values(BTreeMap<String, String>);

impl Life for Values {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        Self::parse(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Self::parse(settings)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

impl Values {
    fn parse(settings: &[u8]) -> Result<Self, Refusal> {
        let values = settings_object(settings)?
            .remove("values")
            .and_then(|v| match v {
                serde_json::Value::Object(m) => Some(m),
                _ => None,
            })
            .ok_or_else(|| Refusal::failed("settings: `values` must be an object"))?;
        values
            .into_iter()
            .map(|(k, v)| match v {
                serde_json::Value::String(s) => Ok((k, s)),
                _ => Err(Refusal::failed(format!(
                    "settings: `values.{k}` must be a string"
                ))),
            })
            .collect::<Result<_, _>>()
            .map(Values)
    }
}

/// The name a resolve's settings ask for.
fn asked(settings: &[u8]) -> Result<String, &'static str> {
    match serde_json::from_slice::<serde_json::Value>(settings) {
        Ok(serde_json::Value::Object(m)) => match m.get("name") {
            Some(serde_json::Value::String(n)) => Ok(n.clone()),
            _ => Err("resolve: `name` must be a string"),
        },
        _ => Err("resolve: the settings must be a JSON object"),
    }
}

/// `resolve`, within the contract.
pub struct Resolve;

impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Values>;

    fn call(
        instance: Instance<'_, Held<Values>>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        match asked(input.field(|i| &i.settings).bytes()) {
            Err(text) => {
                out.set(|o| &o.error_kind, ERROR_KIND_INVALID);
                out.fail(Refusal::failed(text))
            }
            Ok(name) => match held.life().0.get(&name) {
                None => {
                    out.set(|o| &o.error_kind, ERROR_KIND_NOT_FOUND);
                    out.fail(Refusal::failed(format!("no secret named `{name}`")))
                }
                Some(material) => {
                    out.lease_secret(
                        |o| &o.secret,
                        held.leases(),
                        material.clone().into_bytes(),
                        BLOB_OCTETS,
                    );
                    Outcome::Ready
                }
            },
        }
    }
}

/// `resolve`, BROKEN: READY, naming an `error_kind` (`check_resolve`: a contradiction).
pub struct ResolveBroken;

impl SafeSlot for ResolveBroken {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Values>;

    fn call(
        _: Instance<'_, Held<Values>>,
        _: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        out.set(|o| &o.error_kind, ERROR_KIND_NOT_FOUND);
        Outcome::Ready
    }
}

/// The conforming secret plugin's door.
pub mod conforming {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(super::NAME, "1.6.0", 8),
        lifecycle: life(super::Values),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

/// The broken secret plugin's door.
pub mod broken {
    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(super::BROKEN_NAME, "1.6.0", 8),
        lifecycle: life(super::Values),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::ResolveBroken> },
    }
}
