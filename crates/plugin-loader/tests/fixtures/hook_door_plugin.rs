// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S BOTH-WAYS FIXTURE, on the hook kind's memory ABI (`abi::hook`), built with the
//! SDK's generic lifecycle (`lifecycle: life(L)`) and safe slots only.
//!
//! One source, compiled into plugin-loader's test build as a module (the LINKED doors) and built
//! as two example `cdylib`s behind one `export_door!` line each (the DROPPED doors):
//!
//! * [`conforming`] (`hook_door`) — `decide` answers exactly one verb: REJECT with a status when
//!   the request carries more messages than its settings allow, ABSTAIN otherwise.
//! * [`broken`] (`hook_broken_door`) — the same plugin whose `decide` answers two verbs at once
//!   (PREFER and REJECT), which `check_decide` refuses: the host must answer FAULT.
//! * [`untailed`] (linked only) — the conforming plugin whose Statement states no hook tail, which
//!   the host refuses at load (ARCHITECT Q-SO8).
//! * [`panicking`] (linked only) — the same plugin whose `decide` PANICS: the SDK's door catches
//!   it and answers FAULT, which the hook axis answers as broken, never a verdict (PB-81).
//!
//! Both built doors state their tail ([`TAIL`]): a gate that asks for neither view.
//! Every other hook op is REFUSED. The settings are `{"reject_over_messages": <n>}`.
#![allow(dead_code)]

use std::marker::PhantomData;

use busbar_contract::abi::hook::{
    cancel, DecideIn, DecideOut, Tail, CLASS_GATE, PROMPT_NO, USER_NO, VERB_ABSTAIN,
    VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{settings_object, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

/// The fixture's hook tail: a gate that asks for neither the prompt nor the user view.
pub const TAIL: &Tail = &busbar_contract::abi::sdk::hook::tail(CLASS_GATE, PROMPT_NO, USER_NO);

/// The conforming door's Statement name.
pub const NAME: &str = "both-ways-hook";
/// The broken door's Statement name.
pub const BROKEN_NAME: &str = "both-ways-hook-broken";
/// The untailed door's Statement name.
pub const UNTAILED_NAME: &str = "both-ways-hook-untailed";
/// The panicking door's Statement name.
pub const PANICKING_NAME: &str = "both-ways-hook-panicking";

/// The status a rejected request is answered with.
pub const REJECT_STATUS: u16 = 429;

/// The instance: the most messages a request may carry before it is rejected.
pub struct Gate(u64);

impl Life for Gate {
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

impl Gate {
    fn parse(settings: &[u8]) -> Result<Self, Refusal> {
        settings_object(settings)?
            .get("reject_over_messages")
            .and_then(serde_json::Value::as_u64)
            .map(Gate)
            .ok_or_else(|| Refusal::failed("settings: `reject_over_messages` must be a number"))
    }
}

/// `decide`, within the contract: exactly one verb.
pub struct Decide;

impl SafeSlot for Decide {
    type In = DecideIn;
    type Out = DecideOut;
    type State = Held<Gate>;

    fn call(
        instance: Instance<'_, Held<Gate>>,
        input: Lent<'_, DecideIn>,
        mut out: Out<'_, DecideOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        if input.request.message_count > held.life().0 {
            out.set(|o| &o.verbs, VERB_REJECT | VERB_HAS_REJECT_STATUS);
            out.set(|o| &o.reject_status, REJECT_STATUS);
        } else {
            out.set(|o| &o.verbs, VERB_ABSTAIN);
        }
        Outcome::Ready
    }
}

/// `decide`, BROKEN: two verbs at once (`check_decide`: not exactly one).
pub struct DecideBroken;

impl SafeSlot for DecideBroken {
    type In = DecideIn;
    type Out = DecideOut;
    type State = Held<Gate>;

    fn call(
        _: Instance<'_, Held<Gate>>,
        _: Lent<'_, DecideIn>,
        mut out: Out<'_, DecideOut>,
    ) -> Outcome {
        out.set(|o| &o.verbs, VERB_PREFER | VERB_REJECT);
        Outcome::Ready
    }
}

/// `decide`, PANICKING: the slot body panics before it answers.
pub struct DecidePanics;

impl SafeSlot for DecidePanics {
    type In = DecideIn;
    type Out = DecideOut;
    type State = Held<Gate>;

    fn call(_: Instance<'_, Held<Gate>>, _: Lent<'_, DecideIn>, _: Out<'_, DecideOut>) -> Outcome {
        panic!("the panicking hook fixture's decide panics")
    }
}

/// Any other hook op: REFUSED.
pub struct Refuse<I, O>(PhantomData<(I, O)>);

impl<I: AbiIn, O: AbiOut> SafeSlot for Refuse<I, O> {
    type In = I;
    type Out = O;
    type State = Held<Gate>;

    fn call(_: Instance<'_, Held<Gate>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

/// The hook table's kind ops with `decide` named `$decide` over the Statement `$statement`; every
/// other op [`Refuse`]s. `hook_door!(name, decide)` states the name with [`TAIL`].
macro_rules! hook_door {
    (@statement $statement:expr, $decide:ty) => {
        busbar_contract::plugin_door! {
            ops: busbar_contract::abi::hook::Ops,
            statement: $statement,
            lifecycle: life(super::Gate),
            kind_ops: {
                decide: busbar_contract::abi::sdk::Safe<$decide>,
                transform: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::hook::DecideIn,
                    busbar_contract::abi::hook::TransformOut,
                >>,
                notify: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::hook::NotifyIn,
                    busbar_contract::abi::mechanism::call::OutHead,
                >>,
                configure: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::hook::ConfigureIn,
                    busbar_contract::abi::hook::ConfigureOut,
                >>,
                status: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::mechanism::call::InHead,
                    busbar_contract::abi::hook::StatusOut,
                >>,
                describe: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::mechanism::call::InHead,
                    busbar_contract::abi::hook::DescribeOut,
                >>,
                serve: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::hook::ServeIn,
                    busbar_contract::abi::hook::ServeOut,
                >>,
            },
        }
    };
    ($name:expr, $decide:ty) => {
        hook_door!(
            @statement busbar_contract::abi::sdk::hook::statement_with_tail(
                busbar_contract::abi::sdk::door::statement($name, "1.6.0", 8),
                super::TAIL,
            ),
            $decide
        );
    };
}

/// The conforming hook plugin's door.
pub mod conforming {
    hook_door!(super::NAME, super::Decide);
}

/// The broken hook plugin's door.
pub mod broken {
    hook_door!(super::BROKEN_NAME, super::DecideBroken);
}

/// The conforming plugin with NO hook tail: refused at load.
pub mod untailed {
    hook_door!(
        @statement busbar_contract::abi::sdk::door::statement(super::UNTAILED_NAME, "1.6.0", 8),
        super::Decide
    );
}

/// The conforming plugin whose `decide` panics.
pub mod panicking {
    hook_door!(super::PANICKING_NAME, super::DecidePanics);
}
