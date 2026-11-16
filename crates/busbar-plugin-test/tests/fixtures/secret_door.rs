// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's secret fixture: an SDK-authored secret door whose RESOLVE answers the first secret
//! its OPEN (or its last REFRESH) was lent (empty when it was lent none), so a test sees exactly
//! what the host lent. Its OPEN and REFRESH refuse a JSON list, its TICK asks for the next tick
//! 5 ns on, and every CLOSE it answers is counted ([`CLOSES`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{self, ResolveIn, ResolveOut};
use busbar_contract::plugin::markers::SecretKind;

/// CLOSE crossings into any instance of this fixture, process-wide.
pub static CLOSES: AtomicU64 = AtomicU64::new(0);

/// The settings the fixture's OPEN and REFRESH refuse.
const REFUSED: &[u8] = b"[]";

/// The first secret OPEN, or the last REFRESH that lent any, was lent.
pub struct Lends(Mutex<Vec<u8>>);

impl Life for Lends {
    type Kind = SecretKind;
    const CANCEL: u32 = secret::cancel::ABORTED;

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        if settings == REFUSED {
            return Err(Refusal::refused("open: the fixture refuses a list"));
        }
        Ok(Self(Mutex::new(
            secrets.first().map(|s| s.to_vec()).unwrap_or_default(),
        )))
    }

    fn refresh(&self, settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        if settings == REFUSED {
            return Err(Refusal::refused("refresh: the fixture refuses a list"));
        }
        if let (Some(s), Ok(mut held)) = (secrets.first(), self.0.lock()) {
            *held = s.to_vec();
        }
        Ok(Refreshed::default())
    }

    fn tick(&self, now_ns: u64) -> u64 {
        now_ns.saturating_add(5)
    }

    fn close(&self, _: Option<&Host<SecretKind>>) {
        CLOSES.fetch_add(1, Ordering::SeqCst);
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
