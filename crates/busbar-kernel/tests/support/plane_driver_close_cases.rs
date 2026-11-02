// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::hook_cases::Nobody;
use super::*;

use busbar_contract::caps::{Outcome as UnitOutcome, ReasonCode, StepName};
use busbar_kernel::canary::Canary;
use busbar_kernel::plane_driver::{FarEnd, PlaneUnits};
use busbar_kernel::slice::{ConcurrencyGauge, LeaseCell};
use busbar_kernel::teller::{run_unit_async, AccrualMeter, Ended, Kernel, Run};

fn closes(plane: &Double, key: u64) -> u32 {
    plane.closes.lock().unwrap().get(&key).copied().unwrap_or(0)
}

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

fn screened(stuck: u32, panics: bool) -> (Arc<Double>, PlaneDriver) {
    let r = rig(Way::Double, BufferCaps::default(), cases::Book::default());
    let binder = Rewrites(Arc::new(Stuck {
        stuck: AtomicU32::new(stuck),
        panics,
    }));
    (r.plane, r.driver.with_hooks(Arc::new(binder)))
}

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

const KEY: u64 = 41;

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
            let outcome = drive_as(&units, KEY).await;
            let reached = match exit {
                Exit::Completed | Exit::AnsweredLocally | Exit::SessionEnded => {
                    outcome == UnitOutcome::Completed
                }
                Exit::RefusedAtArrive => {
                    outcome == UnitOutcome::Refused(StepName::Decode, ReasonCode::DecodeFailed)
                }
                Exit::RefusedAtAuthenticate => {
                    outcome
                        == UnitOutcome::Refused(StepName::Authenticate, ReasonCode::Unauthenticated)
                }
                Exit::RefusedAtTheDoor => {
                    outcome == UnitOutcome::Refused(StepName::Admit, ReasonCode::OverBudget)
                }
                Exit::FailedBeforeTheAnswer => {
                    outcome == UnitOutcome::Failed(StepName::Route, ReasonCode::PlanePanic)
                }
                Exit::FailedAfterTheAnswerBegan | Exit::FailedOverThenFailedAfterTheAnswerBegan => {
                    outcome
                        == UnitOutcome::Failed(StepName::Route, ReasonCode::DurabilityUnavailable)
                }
                Exit::PastTheDeadline => {
                    outcome == UnitOutcome::Failed(StepName::Route, ReasonCode::DeadlineExceeded)
                }
                Exit::NoMemberLeft | Exit::UpstreamFailedOver => matches!(
                    outcome,
                    UnitOutcome::Refused(StepName::Route, ReasonCode::BreakerOpen)
                        | UnitOutcome::Failed(StepName::Route, ReasonCode::BreakerOpen)
                ),
                _ => unreachable!("{exit:?} has its own arm"),
            };
            assert!(reached, "{exit:?} reached a different exit: {outcome:?}");
            match exit {
                Exit::FailedOverThenFailedAfterTheAnswerBegan => {
                    let sent = far.sent();
                    let members: Vec<_> =
                        sent.iter().map(|request| request.member.as_str()).collect();
                    assert_eq!(
                        members,
                        ["done-retry", "row-late"],
                        "{exit:?}: both attempts ran"
                    );
                }
                Exit::UpstreamFailedOver => {
                    let sent = far.sent();
                    let members: Vec<_> =
                        sent.iter().map(|request| request.member.as_str()).collect();
                    assert_eq!(
                        members,
                        ["overloaded"],
                        "{exit:?}: the failed member was tried"
                    );
                    assert_eq!(far.picks(), 2, "{exit:?}: the retry exhausted the walk");
                }
                Exit::NoMemberLeft => {
                    assert!(far.sent().is_empty(), "{exit:?}: no attempt was available");
                    assert_eq!(far.picks(), 1, "{exit:?}: exhausted on the first pick");
                }
                Exit::SessionEnded => {
                    assert!(far.sent().is_empty(), "{exit:?}: the session is local");
                    assert_eq!(
                        caller.text(),
                        "",
                        "{exit:?}: the caller supplied no session piece"
                    );
                    assert!(
                        r.plane.sessions.open.lock().unwrap().is_empty(),
                        "{exit:?}: no session remains open"
                    );
                }
                _ => {}
            }
            match exit {
                Exit::Completed => assert_eq!(caller.text(), "hello far end"),
                Exit::AnsweredLocally => assert_eq!(caller.text(), "x"),
                Exit::FailedBeforeTheAnswer => assert_eq!(caller.text(), ""),
                Exit::FailedAfterTheAnswerBegan | Exit::FailedOverThenFailedAfterTheAnswerBegan => {
                    assert_eq!(caller.status(), Some(200), "{exit:?}");
                    assert_eq!(caller.text(), "hello ", "{exit:?}: the answer began");
                }
                _ => {}
            }
            drop(units);
            r.driver.sweep();
            closes(&r.plane, KEY)
        }
    }
}

#[tokio::test]
async fn every_exit_closes_an_arrived_unit_exactly_once() {
    let mut wrong = Vec::new();
    for exit in EXITS {
        let n = closed_by(exit).await;
        if n != 1 {
            wrong.push((exit, n, 1));
        }
    }
    assert!(
        wrong.is_empty(),
        "(exit, closing calls, expected), where they differ: {wrong:?}"
    );
}

#[tokio::test]
async fn idle_maintenance_pays_a_dropped_units_close_without_another_arrival() {
    let (plane, driver) = screened(1, false);
    let driver = Arc::new(driver);
    let services = services();
    services.register_plane_cleanup(Arc::downgrade(&driver));
    let cadence = Arc::clone(&services);
    let maintenance = tokio::spawn(async move { cadence.flushes().await });
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), drive_as(&units, 811))
            .await
            .is_err()
    );
    drop(units);
    assert_eq!(driver.owed_closes(), 1);
    let settled = tokio::time::timeout(Duration::from_secs(3), async {
        while driver.owed_closes() != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    maintenance.abort();
    assert!(settled.is_ok(), "idle maintenance must pay the owed close");
    assert_eq!(closes(&plane, 811), 1);
    driver.sweep();
    assert_eq!(closes(&plane, 811), 1);
}

#[tokio::test]
async fn cleanup_drain_retains_a_pending_close_and_uses_the_callers_waker() {
    struct Wakes(std::sync::atomic::AtomicUsize);
    impl std::task::Wake for Wakes {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    let (plane, driver) = screened(1, false);
    plane
        .sessions
        .delay_cancel_reply
        .store(true, Ordering::SeqCst);
    let driver = Arc::new(driver);
    let services = services();
    services.register_plane_cleanup(Arc::downgrade(&driver));
    let (steps, far, caller) = (
        common::TestUnits::passing(),
        cases::Far::new(&["ok"], cases::CHUNKS),
        cases::Caller::default(),
    );
    let units = driver.unit(&steps, &far, &caller, cases::arrival("/v1", b"hi"), 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(30), drive_as(&units, 812))
            .await
            .is_err()
    );
    drop(units);
    assert!(!services.drain_plane_cleanup(Duration::ZERO).await);
    assert_eq!(
        driver.owed_closes(),
        1,
        "timeout must retain cancellation custody"
    );
    let wakes = Arc::new(Wakes(std::sync::atomic::AtomicUsize::new(0)));
    let waker = std::task::Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);
    let mut draining = Box::pin(services.drain_plane_cleanup(Duration::from_secs(1)));
    assert!(draining.as_mut().poll(&mut cx).is_pending());
    let before = wakes.0.load(Ordering::SeqCst);
    plane.sessions.cancel_reply.notify_one();
    assert!(
        wakes.0.load(Ordering::SeqCst) > before,
        "cancel completion must wake the actual maintenance caller"
    );
    assert!(draining.await);
    assert_eq!(driver.owed_closes(), 0);
    assert_eq!(closes(&plane, 812), 1);
    assert!(services.drain_plane_cleanup(Duration::ZERO).await);
    assert_eq!(closes(&plane, 812), 1);
}
