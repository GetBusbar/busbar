// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S BOTH-WAYS FIXTURE, on the hook kind's memory ABI (`abi::hook`), built with the
//! SDK's generic lifecycle (`lifecycle: life(L)`) and safe slots only.
//!
//! One source, compiled into plugin-loader's test build as a module (the LINKED doors) and built
//! as two example `cdylib`s behind one `export_door!` line each (the DROPPED doors):
//!
//! * [`conforming`] (`hook_door`) — `decide` answers exactly one verb: REJECT with a status when
//!   the request carries more messages than its settings allow, or names the session its settings
//!   refuse, ABSTAIN otherwise.
//! * [`broken`] (`hook_broken_door`) — the same plugin whose `decide` answers two verbs at once
//!   (PREFER and REJECT), which `check_decide` refuses: the host must answer FAULT.
//! * [`ordering`] (linked only) — the conforming plugin whose `decide` answers PREFER, for the
//!   proof that a hook which declared `hook.orders: false` is refused when it orders.
//! * [`untailed`] (linked only) — the conforming plugin whose Statement states no hook tail, which
//!   the host refuses at load.
//! * [`panicking`] (linked only) — the same plugin whose `decide` PANICS: the SDK's door catches
//!   it and answers FAULT, which the hook axis answers as broken, never a verdict (PB-81).
//! * [`configurable`] (linked only) — the conforming plugin whose `configure` acknowledges a pushed
//!   `{"reject_over_messages": <n>}` and gates on it from then on.
//!
//! Both built doors state their tail ([`TAIL`]): a gate that asks for neither view.
//! Every other hook op is REFUSED. The settings are `{"reject_over_messages": <n>}`, plus an
//! optional `"sleep_ms"` the conforming `decide` sleeps before it answers (a slow gate, for the
//! loader's own budget and `max_inflight` proofs), and an optional `"reject_session": "<octets>"`
//! (the request view's opaque session).
#![allow(dead_code)]

use std::marker::PhantomData;

use std::sync::atomic::{AtomicU64, Ordering};

use busbar_contract::abi::hook::{
    cancel, ConfigureIn, ConfigureOut, DecideIn, DecideOut, Tail, CLASS_GATE, PROMPT_NO, USER_NO,
    VERB_ABSTAIN, VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT,
};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{settings_object, Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

/// The fixture's hook tail: a gate that asks for neither the prompt nor the user view.
pub const TAIL: &Tail = &busbar_contract::abi::sdk::hook::tail(CLASS_GATE, PROMPT_NO, USER_NO);

pub const ROUTE_PATH: &str = "/hooks/receiver/feedback";
pub const ROUTED_TAIL: &Tail =
    &busbar_contract::abi::sdk::hook::tail(CLASS_GATE, PROMPT_NO, USER_NO).with_routes(&[
        busbar_contract::abi::hook::Route {
            path: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: ROUTE_PATH.as_ptr(),
                len: ROUTE_PATH.len(),
            },
            method: busbar_contract::abi::mechanism::call::AbiStr {
                ptr: b"POST".as_ptr(),
                len: 4,
            },
            auth: busbar_contract::abi::hook::ROUTE_AUTH_KEY,
            _reserved: 0,
        },
    ]);

/// The conforming door's Statement name.
pub const NAME: &str = "both-ways-hook";
/// The broken door's Statement name.
pub const BROKEN_NAME: &str = "both-ways-hook-broken";
/// The ordering door's Statement name.
pub const ORDERING_NAME: &str = "both-ways-hook-ordering";
/// The untailed door's Statement name.
pub const UNTAILED_NAME: &str = "both-ways-hook-untailed";
/// The panicking door's Statement name.
pub const PANICKING_NAME: &str = "both-ways-hook-panicking";
/// The configurable door's Statement name.
pub const CONFIGURABLE_NAME: &str = "both-ways-hook-configurable";

/// The status a rejected request is answered with.
pub const REJECT_STATUS: u16 = 429;

/// Every door's Statement `max_inflight`.
pub const MAX_INFLIGHT: u32 = 8;

/// The instance: the most messages a request may carry before it is rejected, how long its
/// `decide` sleeps first, and the session whose requests it rejects, if any.
pub struct Gate(AtomicU64, u64, Option<Vec<u8>>, bool, String);

impl Life for Gate {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        Self::parse(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Self::parse(settings)
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Self::parse(settings).map(|_| Refreshed::default())
    }
}

impl Gate {
    fn parse(settings: &[u8]) -> Result<Self, Refusal> {
        let settings = settings_object(settings)?;
        let sleep_ms = settings
            .get("sleep_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let over = Self::over(&settings)?;
        let session = settings
            .get("reject_session")
            .and_then(serde_json::Value::as_str)
            .map(|s| s.as_bytes().to_vec());
        let controlled = settings
            .get("hold_for_cap_test")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let headers = settings
            .get("serve_headers")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("valid")
            .to_owned();
        Ok(Gate(
            AtomicU64::new(over),
            sleep_ms,
            session,
            controlled,
            headers,
        ))
    }

    fn over(settings: &serde_json::Map<String, serde_json::Value>) -> Result<u64, Refusal> {
        settings
            .get("reject_over_messages")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| Refusal::failed("settings: `reject_over_messages` must be a number"))
    }
}

static CAP_CROSSINGS: std::sync::Mutex<(bool, u32)> = std::sync::Mutex::new((false, 0));
static CAP_RELEASE: std::sync::Condvar = std::sync::Condvar::new();

pub struct BlockedCalls;

impl BlockedCalls {
    pub fn hold() -> Self {
        *CAP_CROSSINGS.lock().unwrap() = (false, 0);
        Self
    }
}

impl BlockedCalls {
    pub fn entered(&self) -> u32 {
        CAP_CROSSINGS.lock().unwrap().1
    }

    pub fn release(&self) {
        CAP_CROSSINGS.lock().unwrap().0 = true;
        CAP_RELEASE.notify_all();
    }
}

impl Drop for BlockedCalls {
    fn drop(&mut self) {
        self.release();
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
        let gate = held.life();
        if gate.3 {
            let mut state = CAP_CROSSINGS.lock().unwrap();
            state.1 += 1;
            while !state.0 {
                state = CAP_RELEASE.wait(state).unwrap();
            }
        } else if gate.1 > 0 {
            std::thread::sleep(std::time::Duration::from_millis(gate.1));
        }
        let session = input.field(|i| &i.request).field(|r| &r.session).bytes();
        let over = gate.0.load(Ordering::Acquire);
        if input.request.message_count > over || gate.2.as_deref() == Some(session) {
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

/// `decide`, ORDERING: PREFER (a hook that ranks), the verb a hook declaring `orders: false` never
/// answers.
pub struct DecideOrders;

impl SafeSlot for DecideOrders {
    type In = DecideIn;
    type Out = DecideOut;
    type State = Held<Gate>;

    fn call(
        _: Instance<'_, Held<Gate>>,
        _: Lent<'_, DecideIn>,
        mut out: Out<'_, DecideOut>,
    ) -> Outcome {
        out.set(|o| &o.verbs, VERB_PREFER);
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

/// `configure`, CONFIGURABLE: a pushed `reject_over_messages` is the gate's from now on, and its
/// version acknowledged.
pub struct Configure;

pub struct Serve;

impl SafeSlot for Serve {
    type In = busbar_contract::abi::hook::ServeIn;
    type Out = busbar_contract::abi::hook::ServeOut;
    type State = Held<Gate>;

    fn call(
        instance: Instance<'_, Held<Gate>>,
        input: Lent<'_, Self::In>,
        mut out: Out<'_, Self::Out>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        if held.life().1 > 0 {
            std::thread::sleep(std::time::Duration::from_millis(held.life().1));
        }
        if input.field(|i| &i.query).bytes() == b"lease-count" {
            let count = held.leases().held().to_string().into_bytes();
            out.set(|o| &o.status_code, 200);
            out.lease(
                |o| &o.body,
                held.leases(),
                count,
                busbar_contract::abi::mechanism::call::BLOB_OCTETS,
            );
            return Outcome::Ready;
        }
        let mut echoed = input.field(|i| &i.method).bytes().to_vec();
        echoed.push(b' ');
        echoed.extend_from_slice(input.field(|i| &i.path).bytes());
        echoed.push(b'?');
        echoed.extend_from_slice(input.field(|i| &i.query).bytes());
        echoed.push(b'\n');
        echoed.extend_from_slice(input.field(|i| &i.body).bytes());
        out.set(|o| &o.status_code, 202);
        out.lease(
            |o| &o.body,
            held.leases(),
            echoed,
            busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        );
        use busbar_contract::abi::mechanism::call::AbiStr;
        const NAME: AbiStr = AbiStr {
            ptr: b"x-fixture".as_ptr(),
            len: 9,
        };
        const VALUE: AbiStr = AbiStr {
            ptr: b"present".as_ptr(),
            len: 7,
        };
        const VALID: &[AbiStr] = &[NAME, VALUE];
        const ODD: &[AbiStr] = &[NAME];
        const NULL: &[AbiStr] = &[
            NAME,
            AbiStr {
                ptr: std::ptr::null(),
                len: 1,
            },
        ];
        const OVERLONG: &[AbiStr] = &[
            NAME,
            AbiStr {
                ptr: b"x".as_ptr(),
                len: busbar_contract::abi::mechanism::call::MAX_TEXT + 1,
            },
        ];
        const NON_UTF8: &[AbiStr] = &[
            NAME,
            AbiStr {
                ptr: b"\xff".as_ptr(),
                len: 1,
            },
        ];
        let headers = match held.life().4.as_str() {
            "odd" => ODD,
            "null" => NULL,
            "overlong" => OVERLONG,
            "utf8" => NON_UTF8,
            _ => VALID,
        };
        out.list(|o| &o.headers_out, |o| &o.headers_out_len, headers);
        Outcome::Ready
    }
}

impl SafeSlot for Configure {
    type In = ConfigureIn;
    type Out = ConfigureOut;
    type State = Held<Gate>;

    fn call(
        instance: Instance<'_, Held<Gate>>,
        input: Lent<'_, ConfigureIn>,
        mut out: Out<'_, ConfigureOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let over =
            settings_object(input.field(|i| &i.settings).bytes()).and_then(|s| Gate::over(&s));
        match over {
            Ok(over) => {
                held.life().0.store(over, Ordering::Release);
                out.set(|o| &o.acked_version, input.version);
                Outcome::Ready
            }
            Err(e) => out.fail(e),
        }
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
        hook_door!(@statement $statement, $decide, super::Refuse<
            busbar_contract::abi::hook::ConfigureIn,
            busbar_contract::abi::hook::ConfigureOut,
        >);
    };
    (@statement $statement:expr, $decide:ty, $configure:ty) => {
        hook_door!(@statement $statement, $decide, $configure, super::Refuse<
            busbar_contract::abi::hook::ServeIn,
            busbar_contract::abi::hook::ServeOut,
        >);
    };
    (@statement $statement:expr, $decide:ty, $configure:ty, $serve:ty) => {
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
                configure: busbar_contract::abi::sdk::Safe<$configure>,
                status: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::mechanism::call::InHead,
                    busbar_contract::abi::hook::StatusOut,
                >>,
                describe: busbar_contract::abi::sdk::Safe<super::Refuse<
                    busbar_contract::abi::mechanism::call::InHead,
                    busbar_contract::abi::hook::DescribeOut,
                >>,
                serve: busbar_contract::abi::sdk::Safe<$serve>,
            },
        }
    };
    ($name:expr, $decide:ty) => {
        hook_door!(
            @statement busbar_contract::abi::sdk::hook::statement_with_tail(
                busbar_contract::abi::sdk::door::statement($name, "1.6.0", super::MAX_INFLIGHT),
                super::TAIL,
            ),
            $decide
        );
    };
}

/// The conforming hook plugin's door.
pub mod conforming {
    hook_door!(@statement busbar_contract::abi::sdk::hook::statement_with_tail(
        busbar_contract::abi::sdk::door::statement(super::NAME, "1.6.0", super::MAX_INFLIGHT),
        super::ROUTED_TAIL,
    ), super::Decide, super::Refuse<busbar_contract::abi::hook::ConfigureIn,
        busbar_contract::abi::hook::ConfigureOut>, super::Serve);
}

/// The broken hook plugin's door.
pub mod broken {
    hook_door!(@statement busbar_contract::abi::sdk::hook::statement_with_tail(
        busbar_contract::abi::sdk::door::statement(super::BROKEN_NAME, "1.6.0", super::MAX_INFLIGHT),
        super::ROUTED_TAIL,
    ), super::DecideBroken);
}

/// The conforming plugin whose `decide` answers an order.
pub mod ordering {
    hook_door!(super::ORDERING_NAME, super::DecideOrders);
}

/// The conforming plugin with NO hook tail: refused at load.
pub mod untailed {
    hook_door!(
        @statement busbar_contract::abi::sdk::door::statement(
            super::UNTAILED_NAME,
            "1.6.0",
            super::MAX_INFLIGHT,
        ),
        super::Decide
    );
}

/// The conforming plugin whose `decide` panics.
pub mod panicking {
    hook_door!(super::PANICKING_NAME, super::DecidePanics);
}

/// The conforming plugin whose `configure` sets its gate.
pub mod configurable {
    hook_door!(
        @statement busbar_contract::abi::sdk::hook::statement_with_tail(
            busbar_contract::abi::sdk::door::statement(
                super::CONFIGURABLE_NAME,
                "1.6.0",
                super::MAX_INFLIGHT,
            ),
            super::TAIL,
        ),
        super::Decide,
        super::Configure
    );
}
