// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE AUTH TICK SCHEDULE ([`ticks`]) for an INBOUND instance: `AuthInstance::open` starts it
//! on the runtime it opens on, as the outbound open path does (THE DESIGN: "one clock, which also
//! drives every plugin's `tick`"), and dropping the instance stops it. RED: predev's inbound open
//! started no schedule, so the doubles below were ticked 0 times, and nothing stopped one that ran.
//!
//! The doubles are inbound auth doors over a lifecycle of their own: the SDK's `Verifier` (the
//! inbound doors of `tests/auth_door_tests.rs`) answers every `tick` with `0`, so it cannot ask for
//! a second one.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use busbar_contract::abi::auth::{AuthPoints, AuthTail, CANCEL_ABANDONED};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{carrier, verify_tail, with_tail};
use busbar_contract::abi::sdk::door::{statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::lent::Lent;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::safe::{Instance, SafeSlot};
use busbar_contract::abi::sdk::Out;

use super::*;
use crate::auth_door::{AuthInstance, AuthSink};
use crate::dispatch::{load_linked, Budgets, ConnTable, DispatchConfig, LinkedRow};

/// The gap each `next_tick_ns` asks for.
const GAP_NS: u64 = 10_000_000;

/// The `now_ns` of each tick [`Twice`] was called at.
static TWICE: Mutex<Vec<u64>> = Mutex::new(Vec::new());
/// The ticks [`Forever`] was called.
static FOREVER: AtomicU64 = AtomicU64::new(0);

/// Asks for a tick `GAP_NS` on, twice, then for none (`0`).
struct Twice;

/// Asks for a tick `GAP_NS` on, every time.
struct Forever;

macro_rules! life {
    ($life:ident, $tick:expr) => {
        impl Life for $life {
            const CANCEL: u32 = CANCEL_ABANDONED;
            const DRIVE: Outcome = Outcome::Refused;
            fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
                Ok($life)
            }
            fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
                Ok(Refreshed::default())
            }
            fn tick(&self, now_ns: u64) -> u64 {
                let tick: fn(u64) -> u64 = $tick;
                tick(now_ns)
            }
        }
    };
}

life!(Twice, |now| {
    let mut at = TWICE.lock().unwrap_or_else(|e| e.into_inner());
    at.push(now);
    if at.len() < 3 {
        now + GAP_NS
    } else {
        0
    }
});
life!(Forever, |now| {
    FOREVER.fetch_add(1, Ordering::SeqCst);
    now + GAP_NS
});

/// Every auth op of a double: REFUSED (the schedule is under test, not `verify`).
struct Refuses<L, I, O>(PhantomData<(L, I, O)>);
impl<L: Life, I: AbiIn, O: AbiOut> SafeSlot for Refuses<L, I, O> {
    type In = I;
    type Out = O;
    type State = Held<L>;
    fn call(_: Instance<'_, Held<L>>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

const CARRIERS: &[MarkWord] = &[carrier("X-Key")];
const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD);

macro_rules! door {
    ($module:ident, $life:ident, $name:literal) => {
        mod $module {
            use super::*;
            use busbar_contract::abi::auth as k;
            busbar_contract::plugin_door! {
                ops: k::Ops,
                statement: with_tail(
                    Statement {
                        mark_words: CARRIERS.as_ptr(),
                        mark_words_len: CARRIERS.len(),
                        ..statement($name, "1.0.0", 8)
                    },
                    TAIL
                ),
                lifecycle: life($life),
                kind_ops: {
                    verify: busbar_contract::abi::sdk::Safe<
                        Refuses<$life, k::VerifyIn, k::IdentifyOut>>,
                    begin_login: busbar_contract::abi::sdk::Safe<
                        Refuses<$life, k::BeginLoginIn, k::BeginLoginOut>>,
                    complete_login: busbar_contract::abi::sdk::Safe<
                        Refuses<$life, k::CompleteLoginIn, k::IdentifyOut>>,
                    open_outbound: busbar_contract::abi::sdk::Safe<
                        Refuses<$life, k::OpenOutboundIn, k::OpenOutboundOut>>,
                    outbound_ready: busbar_contract::abi::sdk::Safe<
                        Refuses<$life, k::OutboundReadyIn, k::OutboundReadyOut>>,
                    fields: busbar_contract::abi::sdk::Safe<
                        Refuses<$life, k::FieldsIn, k::FieldsOut>>,
                },
            }
        }
    };
}

door!(twice, Twice, "ticked-twice");
door!(forever, Forever, "ticked-forever");

fn dispatcher() -> Arc<Dispatcher> {
    Arc::new(Dispatcher::new(DispatchConfig {
        workers: 2,
        budgets: Budgets::default(),
        watchdog_period: Duration::from_millis(20),
    }))
}

/// `door` linked, bound to `d` and OPENED as the inbound open path opens it (`AuthRows::open`).
fn opened(
    d: &Arc<Dispatcher>,
    door: busbar_contract::abi::mechanism::door::DoorFn,
    label: &str,
) -> AuthInstance {
    let sink = AuthSink::new(label);
    let bind = crate::dispatch::Bind {
        instance: Arc::from(label),
        max_inflight_cap: 8,
        sink: sink.bind(),
        dispatcher: d.adopter(),
        conns: ConnTable::NoNeeds,
    };
    let row = LinkedRow::of(door).expect("the double states its Statement");
    let p = load_linked::<Auth>(&row, bind).expect("the double loads");
    AuthInstance::open(p, sink, Arc::clone(d), label, b"{}", Vec::new()).expect("the double opens")
}

/// Waits (at most 5 s) until `done`.
async fn until(done: impl Fn() -> bool) {
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while !done() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await;
}

/// AN INBOUND INSTANCE IS TICKED ON THE ONE CLOCK: at its open, then at each `next_tick_ns` it
/// answers, never before it; an answer of `0` ends the schedule. RED: ticked 0 times.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inbound_instance_is_ticked_at_each_next_tick_ns_until_it_answers_zero() {
    let d = dispatcher();
    let a = opened(&d, twice::door, "ticked-twice");
    let ticked = || TWICE.lock().unwrap_or_else(|e| e.into_inner()).clone();
    until(|| ticked().len() >= 3).await;
    // Past the third tick's answer of `0`, no other comes.
    tokio::time::sleep(Duration::from_millis(5 * GAP_NS / 1_000_000)).await;
    let at = ticked();
    assert_eq!(at.len(), 3, "ticked at open and at both next_tick_ns: {at:?}");
    for w in at.windows(2) {
        assert!(
            w[1] >= w[0] + GAP_NS,
            "a tick came before the next_tick_ns it was asked for: {at:?}"
        );
    }
    until(|| a.ticks_ended()).await;
    assert!(a.ticks_ended(), "the schedule ends on an answer of 0");
}

/// A DROPPED INBOUND INSTANCE (retired, or replaced on apply) STOPS ITS SCHEDULE, though its
/// plugin would be ticked on. RED: the ticks go on after the drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_inbound_instance_is_ticked_no_more() {
    let d = dispatcher();
    let a = opened(&d, forever::door, "ticked-forever");
    until(|| FOREVER.load(Ordering::SeqCst) >= 2).await;
    assert!(
        FOREVER.load(Ordering::SeqCst) >= 2,
        "the instance is ticked on its schedule"
    );
    drop(a);
    // A tick already crossing when the schedule was aborted completes; none follows it.
    tokio::time::sleep(Duration::from_millis(3 * GAP_NS / 1_000_000)).await;
    let stopped = FOREVER.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(10 * GAP_NS / 1_000_000)).await;
    assert_eq!(
        FOREVER.load(Ordering::SeqCst),
        stopped,
        "a dropped instance's schedule stops"
    );
}
