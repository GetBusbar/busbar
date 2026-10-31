// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY UNIT THAT ARRIVED IS CLOSED EXACTLY ONCE (`plane_driver/close.rs`), against the double,
//! which counts each unit's closing calls by its key: the `on_piece` answer that says its reply is
//! complete, a `refusal` naming it, a `cancel` naming it or the op it had in flight.
//!
//! A plane keeps a unit from `arrive` until its closing call and lets it go there (`abi::plane`,
//! "ONE UNIT, ONE KEY"); a plane that bounds the units it keeps refuses every arrival once units
//! that never had theirs fill it. Two exits left a unit with none: its caller went away while the
//! gate-first screen ran, and it failed after its answer had begun (a store outage on a record
//! write), so no `refusal` was rendered. The table holds every other exit to one close too, and a
//! completed unit is never closed twice. None of it writes a byte to the caller: the close is the
//! plane's, after the caller's answer.

use super::hook_cases::Nobody;
use super::*;

use busbar_contract::caps::{Canary, Outcome as UnitOutcome, ReasonCode, StepName};
use busbar_kernel::plane_driver::{FarEnd, PlaneUnits};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};

/// The closing calls the double had for the unit keyed `key`.
fn closes(plane: &Double, key: u64) -> u32 {
    plane.closes.lock().unwrap().get(&key).copied().unwrap_or(0)
}

/// Run one unit keyed `key` over `far` through the one loop; its outcome.
async fn drive_as<F: FarEnd>(
    units: &PlaneUnits<'_, common::TestUnits, F, cases::Caller>,
    key: u64,
) -> UnitOutcome {
    let kernel = Kernel::new();
    let (gauge, canary, leases, meter) = (
        ConcurrencyGauge::new(),
        Canary::new(),
        LeaseCell::new(),
        AccrualMeter::new(),
    );
    let cell = common::cell(&kernel);
    let run = Run {
        cell: &cell,
        parent: None,
        leases: &leases,
        gauge: &gauge,
        canary: &canary,
        meter: &meter,
        taps: None,
    };
    match run_unit_async(&kernel, units, &common::ctx(key), run, units).await {
        Ended::Settled { end, .. } => end.outcome(),
        Ended::AlreadySettled => panic!("nothing else holds this unit's cell"),
    }
}

/// A gate-first entry's rewrite hook whose first `stuck` calls never answer (a hook still
/// thinking when the caller goes away), or that panics; every other call abstains.
struct Stuck {
    stuck: AtomicU32,
    panics: bool,
}

#[async_trait::async_trait]
impl busbar_contract::hooks::RoutingPolicy for Stuck {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _candidates: &[busbar_contract::hooks::Candidate<'_>],
        _ctx: &busbar_contract::hooks::RoutingContext<'_>,
        _budget: Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        Ok(busbar_contract::hooks::RoutingDecision::Abstain)
    }

    fn name(&self) -> &'static str {
        "stuck-rewrite"
    }

    async fn transform(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _budget: Duration,
    ) -> busbar_contract::hooks::TransformOutcome {
        assert!(!self.panics, "the rewrite hook panicked");
        let stuck = self
            .stuck
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        if stuck {
            std::future::pending::<()>().await;
        }
        busbar_contract::hooks::TransformOutcome::Abstain
    }
}

/// A gate-first binder attaching `rewrite` as the entry's one rewrite hook.
struct Rewrites(Arc<Stuck>);

impl busbar_kernel::plane_driver::HookBinder for Rewrites {
    fn bind(
        &self,
        _bind: &busbar_kernel::plane_driver::Bind<'_>,
    ) -> Option<busbar_kernel::plane_driver::UnitHooks> {
        None
    }

    fn order(&self) -> busbar_kernel::plane_driver::HookOrder {
        busbar_kernel::plane_driver::HookOrder::Gated
    }

    fn bind_gated(
        &self,
        _container: &str,
        _principal: Option<&str>,
    ) -> Option<busbar_kernel::plane_driver::GatedHooks> {
        Some(busbar_kernel::plane_driver::GatedHooks {
            request_id: 7,
            gates: Vec::new(),
            rewrites: vec![(
                Duration::from_secs(5),
                Arc::clone(&self.0) as Arc<dyn busbar_contract::hooks::RoutingPolicy>,
            )],
            key: None,
            scan: None,
            reads: Arc::new(|_: &str, _: Option<&str>, _: &str, _: bool| {}),
        })
    }
}

/// A driver whose gate-first screen's rewrite hook sticks on its first `stuck` units, or panics.
fn screened(stuck: u32, panics: bool) -> (Arc<Double>, PlaneDriver) {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let binder = Rewrites(Arc::new(Stuck {
        stuck: AtomicU32::new(stuck),
        panics,
    }));
    (r.plane, r.driver.with_hooks(Arc::new(binder)))
}

/// A driver whose ROUTED request stage (the head of the route leg, before the unit's pump and its
/// ticket exist) runs a rewrite hook that sticks on its first unit.
fn routed() -> (Arc<Double>, PlaneDriver) {
    let stuck: Arc<dyn busbar_contract::hooks::RoutingPolicy> = Arc::new(Stuck {
        stuck: AtomicU32::new(1),
        panics: false,
    });
    let hooks = busbar_kernel::plane_driver::BoundHooks {
        rewrites: vec![(Duration::from_secs(5), stuck)],
        gates: Vec::new(),
        pool_rewrites: Default::default(),
        pool_gates: Default::default(),
        pool_policies: Default::default(),
        taps: busbar_kernel::plane_driver::StageTaps::default(),
        requested: busbar_kernel::hooks::RequestedSignals::default(),
        next_request_id: Arc::new(|| 1),
        caller: Arc::new(Nobody),
        dialects: vec!["test-dialect".to_string()],
    };
    let r = rig_with_hooks(
        Way::Double,
        BufferCaps::default(),
        cases::Book::default(),
        Some(hooks),
    );
    (r.plane, r.driver)
}

/// RED, THE FIRST REPORTED EXIT: the caller goes away while a gate-first plane's screen is still
/// running its hook, after `arrive` and before the door. The unit is owed its close and nothing
/// crosses inside the drop; the next arrival's decode pays it with the host's `cancel` naming the
/// unit, once, and the caller was written nothing. Before the fix the unit was never closed: the
/// plane held it for as long as the instance lived.
#[tokio::test]
async fn a_unit_whose_caller_goes_away_at_the_gated_screen_is_closed_once() {
    let (plane, driver) = screened(1, false);
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
    let gone = tokio::time::timeout(Duration::from_millis(30), drive_as(&units, 11)).await;
    assert!(gone.is_err(), "the unit was still at its screen");
    assert!(
        !steps.called().contains(&StepName::Admit),
        "it went away before the door"
    );
    drop(units);
    assert_eq!(
        closes(&plane, 11),
        0,
        "nothing crosses inside the drop: the close is owed"
    );
    assert_eq!(driver.owed_closes(), 1);
    assert_eq!(caller.status(), None, "the caller was answered nothing");
    assert_eq!(caller.text(), "");

    // The next arrival pays it at its decode.
    let (steps, far, next) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &next, cases::arrival("/v1", b"hi"), 0);
    let outcome = drive_as(&units, 12).await;
    assert!(matches!(outcome, UnitOutcome::Completed), "{outcome:?}");
    assert_eq!(closes(&plane, 11), 1, "the gone unit is closed, once");
    assert_eq!(driver.owed_closes(), 0);
    assert_eq!(closes(&plane, 12), 1, "the next unit closed on its own");
    assert_eq!(next.text(), "hello far end");
}

/// RED, THE SECOND REPORTED EXIT: a unit fails after its answer began (the plane's record write on
/// the answer's second window finds the store out), so the caller keeps what streamed and no
/// `refusal` is rendered. The unit is owed its close, paid once by the next sweep, and the caller's
/// bytes are exactly what streamed before the failure. Before the fix the unit was never closed.
#[tokio::test]
async fn a_unit_that_fails_after_its_answer_began_is_closed_once() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["row-late"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = r
        .driver
        .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
    let outcome = drive_as(&units, 21).await;
    assert!(
        matches!(
            outcome,
            UnitOutcome::Failed(StepName::Route, ReasonCode::DurabilityUnavailable)
        ),
        "{outcome:?}"
    );
    assert_eq!(caller.status(), Some(200));
    assert_eq!(caller.text(), "hello ", "the answer had begun");
    assert!(units.take_rendered().is_none(), "no refusal was rendered");
    drop(units);
    assert_eq!(closes(&r.plane, 21), 0, "nothing crosses inside the drop");
    r.driver.sweep();
    assert_eq!(closes(&r.plane, 21), 1, "closed once, by the sweep");
    r.driver.sweep();
    assert_eq!(closes(&r.plane, 21), 1, "and never again");
    assert_eq!(
        caller.text(),
        "hello ",
        "the close wrote the caller nothing"
    );
}

/// A COMPLETED UNIT IS CLOSED ONCE, BY ITS OWN LAST ANSWER, AND NEVER AGAIN: the plane's `EMIT_DONE`
/// is its close, so nothing is owed for it, and the sweeps and arrivals after it add no second call.
#[tokio::test]
async fn a_completed_unit_is_closed_once_and_never_again() {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    for key in [31, 32] {
        let (steps, far, caller) = (
            common::TestUnits::passing(),
            cases::Far::new(&["ok"], cases::CHUNKS),
            cases::Caller::default(),
        );
        let units = r
            .driver
            .unit(&steps, &far, &caller, cases::arrival("/call", b"x"), 0);
        let outcome = drive_as(&units, key).await;
        assert!(matches!(outcome, UnitOutcome::Completed), "{outcome:?}");
        assert_eq!(caller.text(), "hello far end");
        drop(units);
        assert_eq!(r.driver.owed_closes(), 0, "a closed unit owes nothing");
    }
    r.driver.sweep();
    assert_eq!(closes(&r.plane, 31), 1);
    assert_eq!(closes(&r.plane, 32), 1);
    assert_eq!(r.stats()[stat::CANCELS], 0, "no cancel crossed for either");
}

/// The exits a unit that crossed `arrive` leaves by.
#[derive(Debug, Clone, Copy)]
enum Exit {
    /// Its answer completed.
    Completed,
    /// The plane answered it itself.
    AnsweredLocally,
    /// The plane's own `arrive` refused it.
    RefusedAtArrive,
    /// The kernel refused it at authentication.
    RefusedAtAuthenticate,
    /// The door refused it (a spent budget).
    RefusedAtTheDoor,
    /// The gate-first screen's hook vetoed it.
    VetoedAtTheScreen,
    /// Its caller went away during the gate-first screen.
    GoneAtTheScreen,
    /// A hook panicked during the gate-first screen, unwinding the unit.
    PanickedAtTheScreen,
    /// Its caller went away during the routed request stage, admitted, before its pump existed.
    GoneAtTheRoutedHookStage,
    /// The plane faulted before any byte of its answer.
    FailedBeforeTheAnswer,
    /// A record write failed after its answer began (the store out).
    FailedAfterTheAnswerBegan,
    /// A done answer with a retry verdict failed over, then the next attempt failed after its
    /// answer began.
    FailedOverThenFailedAfterTheAnswerBegan,
    /// Its deadline passed with an op in flight.
    PastTheDeadline,
    /// The plane's generation was replaced with an op in flight (drain).
    Drained,
    /// Its caller went away with an op in flight.
    GoneMidAnswer,
    /// Its deadline passed while the op's own done answer was on its way: the answer won.
    DoneAnswerRacingTheDeadline,
    /// Its caller went away while the op's own done answer was on its way: the answer won.
    DoneAnswerRacingAClientDrop,
    /// Its deadline passed while a done answer with a retry verdict, not marked final, was on its
    /// way: the plane keeps the unit for the retry, so it is still owed its close.
    RetryDoneAnswerRacingTheDeadline,
    /// The walk had no member at all.
    NoMemberLeft,
    /// The far end failed over and the walk ran out.
    UpstreamFailedOver,
    /// The dial went out and nothing came back; the walk ran out.
    DialFailed,
    /// The walk's credential refusal, handed to the plane as a piece first, then rendered.
    RefusedAsAPieceFirst,
    /// A duplex session the plane answers itself ended on its own.
    SessionEnded,
}

const EXITS: [Exit; 23] = [
    Exit::Completed,
    Exit::AnsweredLocally,
    Exit::RefusedAtArrive,
    Exit::RefusedAtAuthenticate,
    Exit::RefusedAtTheDoor,
    Exit::VetoedAtTheScreen,
    Exit::GoneAtTheScreen,
    Exit::PanickedAtTheScreen,
    Exit::GoneAtTheRoutedHookStage,
    Exit::FailedBeforeTheAnswer,
    Exit::FailedAfterTheAnswerBegan,
    Exit::FailedOverThenFailedAfterTheAnswerBegan,
    Exit::PastTheDeadline,
    Exit::Drained,
    Exit::GoneMidAnswer,
    Exit::DoneAnswerRacingTheDeadline,
    Exit::DoneAnswerRacingAClientDrop,
    Exit::RetryDoneAnswerRacingTheDeadline,
    Exit::NoMemberLeft,
    Exit::UpstreamFailedOver,
    Exit::DialFailed,
    Exit::RefusedAsAPieceFirst,
    Exit::SessionEnded,
];

/// The unit's key on every exit.
const KEY: u64 = 41;

/// One unit through `exit` on a driver of its own, then the sweep: the closing calls it had.
async fn closed_by(exit: Exit) -> u32 {
    let passing = common::TestUnits::passing;
    let unit_on = |far: &'static str| (cases::Far::new(&[far], cases::CHUNKS), "/call");
    match exit {
        Exit::GoneAtTheScreen | Exit::PanickedAtTheScreen | Exit::GoneAtTheRoutedHookStage => {
            let panics = matches!(exit, Exit::PanickedAtTheScreen);
            let (plane, driver) = if matches!(exit, Exit::GoneAtTheRoutedHookStage) {
                routed()
            } else {
                screened(1, panics)
            };
            let (steps, far, caller) = (
                passing(),
                cases::Far::new(&["ok"], &[]),
                cases::Caller::default(),
            );
            // A body of one `user` turn, so the routed rewrite has a prompt to see.
            let arrival = cases::arrival("/call", b"user:hello");
            let units = driver.unit(&steps, &far, &caller, arrival, 0);
            {
                let mut unit = Box::pin(drive_as(&units, KEY));
                let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let mut cx = Context::from_waker(Waker::noop());
                    unit.as_mut().poll(&mut cx).is_pending()
                }));
                match polled {
                    Ok(pending) => assert!(pending && !panics, "{exit:?}: waits at its hook"),
                    Err(_) => assert!(panics, "{exit:?}: only the panicking hook unwinds"),
                }
            }
            drop(units);
            assert_eq!(
                closes(&plane, KEY),
                0,
                "{exit:?}: nothing crosses inside the drop"
            );
            assert_eq!(
                caller.text(),
                "",
                "{exit:?}: the caller was written nothing"
            );
            driver.sweep();
            closes(&plane, KEY)
        }
        Exit::VetoedAtTheScreen => {
            let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
            let binder = GateFirst {
                gate: Arc::new(Refuses::default()),
                asked: Mutex::new(Vec::new()),
            };
            let driver = r.driver.with_hooks(Arc::new(binder));
            let (steps, far, caller) = (
                passing(),
                cases::Far::new(&["ok"], &[]),
                cases::Caller::default(),
            );
            let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
            let outcome = drive_as(&units, KEY).await;
            assert!(
                matches!(
                    outcome,
                    UnitOutcome::Refused(StepName::Approve, ReasonCode::HookVeto)
                ),
                "{exit:?}: {outcome:?}"
            );
            drop(units);
            driver.sweep();
            closes(&r.plane, KEY)
        }
        Exit::Drained => {
            let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
            let (plane, driver) = (r.plane, Arc::new(r.driver));
            let (steps, (far, target), caller) =
                (passing(), unit_on("hang"), cases::Caller::default());
            let units = driver.unit(&steps, &far, &caller, cases::arrival(target, b"x"), 0);
            let reloader = {
                let driver = Arc::clone(&driver);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    driver.reload();
                })
            };
            let outcome = drive_as(&units, KEY).await;
            reloader.await.unwrap();
            assert!(
                matches!(
                    outcome,
                    UnitOutcome::Failed(StepName::Route, ReasonCode::Drain)
                ),
                "{exit:?}: {outcome:?}"
            );
            drop(units);
            driver.sweep();
            closes(&plane, KEY)
        }
        Exit::DoneAnswerRacingTheDeadline
        | Exit::DoneAnswerRacingAClientDrop
        | Exit::RetryDoneAnswerRacingTheDeadline => {
            // Two windows: the first streams, the second (the reply done) is held past the cut.
            let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
            let (steps, far, caller) = (
                passing(),
                cases::Far::new(
                    &[if matches!(exit, Exit::RetryDoneAnswerRacingTheDeadline) {
                        "retry-done-late"
                    } else {
                        "done-late"
                    }],
                    &[b"hello ", b"end"],
                ),
                cases::Caller::default(),
            );
            let racing_the_deadline = !matches!(exit, Exit::DoneAnswerRacingAClientDrop);
            let deadline = if racing_the_deadline {
                now_ns() + 40_000_000
            } else {
                0
            };
            let units = r.driver.unit(
                &steps,
                &far,
                &caller,
                cases::arrival("/call", b"x"),
                deadline,
            );
            if racing_the_deadline {
                let outcome = drive_as(&units, KEY).await;
                assert!(
                    matches!(
                        outcome,
                        UnitOutcome::Failed(StepName::Route, ReasonCode::DeadlineExceeded)
                    ),
                    "{exit:?}: {outcome:?}"
                );
            } else {
                let gone =
                    tokio::time::timeout(Duration::from_millis(40), drive_as(&units, KEY)).await;
                assert!(
                    gone.is_err(),
                    "{exit:?}: the done answer was still on its way"
                );
            }
            assert_eq!(
                caller.text(),
                "hello ",
                "{exit:?}: the first window streamed"
            );
            drop(units);
            let until = Instant::now() + Duration::from_secs(5);
            while r.driver.buried() > 0 && Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(5)).await;
                r.driver.sweep();
            }
            r.driver.sweep();
            closes(&r.plane, KEY)
        }
        Exit::GoneMidAnswer => {
            let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
            let (steps, (far, target), caller) =
                (passing(), unit_on("hang"), cases::Caller::default());
            let units = r
                .driver
                .unit(&steps, &far, &caller, cases::arrival(target, b"x"), 0);
            let gone = tokio::time::timeout(Duration::from_millis(60), drive_as(&units, KEY)).await;
            assert!(
                gone.is_err(),
                "{exit:?}: the unit was still waiting on the plane"
            );
            drop(units);
            let until = Instant::now() + Duration::from_secs(5);
            while r.driver.buried() > 0 && Instant::now() < until {
                tokio::time::sleep(Duration::from_millis(5)).await;
                r.driver.sweep();
            }
            r.driver.sweep();
            closes(&r.plane, KEY)
        }
        Exit::DialFailed | Exit::RefusedAsAPieceFirst => {
            let mut r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
            let far = if matches!(exit, Exit::DialFailed) {
                Gone {
                    unsent: None,
                    sends: true,
                    then: busbar_kernel::plane_driver::Pick::Exhausted {
                        status: 503,
                        retry_after: None,
                        detail: "nothing answered",
                    },
                }
            } else {
                r.driver = r
                    .driver
                    .with_records(records(), instance())
                    .with_refused_piece();
                Gone {
                    unsent: None,
                    sends: true,
                    then: busbar_kernel::plane_driver::Pick::Refused(
                        ReasonCode::CredentialUnavailable,
                    ),
                }
            };
            let (steps, caller) = (passing(), cases::Caller::default());
            let units = r
                .driver
                .unit(&steps, &far, &caller, cases::arrival("/x", b"x"), 0);
            let outcome = drive_as(&units, KEY).await;
            assert!(
                matches!(outcome, UnitOutcome::Failed(StepName::Route, _)),
                "{exit:?}: {outcome:?}"
            );
            assert!(
                units.take_rendered().is_some(),
                "{exit:?}: the refusal is rendered"
            );
            drop(units);
            r.driver.sweep();
            closes(&r.plane, KEY)
        }
        _ => {
            let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
            let (steps, (far, target), deadline) = match exit {
                Exit::Completed => (passing(), unit_on("ok"), 0),
                Exit::AnsweredLocally => (passing(), (cases::Far::new(&[], &[]), "/local"), 0),
                Exit::RefusedAtArrive => (passing(), (cases::Far::new(&["ok"], &[]), "/refuse"), 0),
                Exit::RefusedAtAuthenticate => (
                    common::TestUnits::refusing(
                        StepName::Authenticate,
                        ReasonCode::Unauthenticated,
                    ),
                    unit_on("ok"),
                    0,
                ),
                Exit::RefusedAtTheDoor => (
                    common::TestUnits::refusing(StepName::Admit, ReasonCode::OverBudget),
                    unit_on("ok"),
                    0,
                ),
                Exit::FailedBeforeTheAnswer => (passing(), unit_on("fault"), 0),
                Exit::FailedAfterTheAnswerBegan => (passing(), unit_on("row-late"), 0),
                Exit::FailedOverThenFailedAfterTheAnswerBegan => (
                    passing(),
                    (
                        cases::Far::new(&["done-retry", "row-late"], cases::CHUNKS),
                        "/call",
                    ),
                    0,
                ),
                Exit::PastTheDeadline => (passing(), unit_on("hang"), now_ns() + 40_000_000),
                Exit::NoMemberLeft => {
                    (passing(), (cases::Far::new(&[], cases::CHUNKS), "/call"), 0)
                }
                Exit::UpstreamFailedOver => (passing(), unit_on("overloaded"), 0),
                Exit::SessionEnded => (passing(), (cases::Far::new(&[], &[]), "/session"), 0),
                _ => unreachable!("{exit:?} has its own arm"),
            };
            let caller = cases::Caller::default();
            let units = r.driver.unit(
                &steps,
                &far,
                &caller,
                cases::arrival(target, b"x"),
                deadline,
            );
            let _outcome = drive_as(&units, KEY).await;
            drop(units);
            r.driver.sweep();
            closes(&r.plane, KEY)
        }
    }
}

/// The closing calls a unit leaving by `exit` has. One on every exit but two, which predate the
/// guard and which it leaves as they are: a unit cut by its deadline or a drain before any byte of
/// its answer has the `cancel` that stops its op (Part 3 section 12, "Cancel": the driver's facts
/// bill from its disposition) and then the `refusal` that renders the caller's answer (the
/// encode seat, "the plane's rendering of the refusal"). Neither can go without changing what the
/// unit bills or what the caller reads, and the guard owes such a unit nothing: a third call would
/// be the guard's.
fn expected(exit: Exit) -> u32 {
    match exit {
        Exit::PastTheDeadline | Exit::Drained => 2,
        _ => 1,
    }
}

/// EVERY EXIT CLOSES AN ARRIVED UNIT, AND THE GUARD NEVER ADDS A CALL: whichever way a unit that
/// crossed `arrive` leaves (completed, answered locally, refused at its arrival, its identity, the
/// door or the screen, its caller gone at the screen, the routed hook stage or mid-answer, a panic
/// unwinding it, failed before or after its answer began, past its deadline, drained by a reload,
/// the walk out of members after a failover or a dial that brought nothing back, a refusal handed
/// as a piece first, a session ended), the plane has exactly one closing call for it once the
/// sweep has run, but for the two [`expected`] names. RED before the fix: the gated screen's two
/// exits, the routed hook stage's, and the failures after the answer began had none.
#[tokio::test]
async fn every_exit_closes_an_arrived_unit_exactly_once() {
    let mut wrong = Vec::new();
    for exit in EXITS {
        let n = closed_by(exit).await;
        if n != expected(exit) {
            wrong.push((exit, n, expected(exit)));
        }
    }
    assert!(
        wrong.is_empty(),
        "(exit, closing calls, expected), where they differ: {wrong:?}"
    );
}
