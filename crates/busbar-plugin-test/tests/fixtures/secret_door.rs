// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's secret fixture: an SDK-authored secret door whose RESOLVE answers the first secret
//! its OPEN was lent (empty when it was lent none), so a test sees exactly what the host lent.

use std::sync::Mutex;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_contract::plugin::markers::SecretKind;

/// The first secret OPEN was lent.
pub struct Lends(Mutex<Vec<u8>>);

impl Life for Lends {
    type Kind = SecretKind;
    const CANCEL: u32 = secret::cancel::ABORTED;

    fn open(_: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self(Mutex::new(
            secrets.first().map(|s| s.to_vec()).unwrap_or_default(),
        )))
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// RESOLVE: the lent secret.
pub struct Resolve;

impl SafeSlot for Resolve {
    type Kind = SecretKind;
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Lends>;

    fn call(
        instance: Instance<'_, Self::State, SecretKind>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let lent = held.life().0.lock().map(|v| v.clone()).unwrap_or_default();
        busbar_contract::abi::sdk::cred::resolved(
            input,
            &mut out,
            busbar_contract::abi::sdk::cred::Held::new(lent),
        )
    }
}

busbar_contract::plugin_door! {
    ops: secret::Ops,
    statement: statement("host-fixture-secret", "0", 1),
    lifecycle: life(Lends),
    kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
}
