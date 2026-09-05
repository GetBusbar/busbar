// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the Teller loop in `crates/busbar-substrate/src/teller/`: the step order the loop
//! enforces, which Audit door a refusal reaches, the one posting per unit, and the gauntlet
//! adapter reproducing the older `run_gauntlet` / `run_gauntlet_session` outcomes.

use super::*;
use crate::plane_host::{
    run_gauntlet, run_gauntlet_session, GauntletPlane, GauntletRequest, VerifyOutcome,
};
use axum::response::Response;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

fn resp(status: u16, body: &'static str) -> Response {
    Response::builder()
        .status(status)
        .body(axum::body::Body::from(body))
        .expect("response")
}

/// What a recording plane saw: every step method the loop called, in order, plus which Audit door
/// it reached and how many postings it received.
#[derive(Default)]
struct Trace {
    steps: Mutex<Vec<StepName>>,
    audited_with_hold: Mutex<Option<(bool, UnitEnd)>>,
    audited_refused_at: Mutex<Option<StepName>>,
    posted: Mutex<Vec<UnitEnd>>,
}

impl Trace {
    fn steps(&self) -> Vec<StepName> {
        self.steps.lock().unwrap().clone()
    }
    fn saw(&self, step: StepName) -> bool {
        self.steps().contains(&step)
    }
    fn posted(&self) -> Vec<UnitEnd> {
        self.posted.lock().unwrap().clone()
    }
}

/// A plane that proceeds at every step except the one it is told to refuse at.
struct RecordingPlane {
    refuse_at: Option<StepName>,
    charged: bool,
    trace: Arc<Trace>,
}

impl RecordingPlane {
    fn note(&self, step: StepName) {
        self.trace.steps.lock().unwrap().push(step);
    }
    fn refuses(&self, step: StepName) -> bool {
        self.refuse_at == Some(step)
    }
}

#[async_trait::async_trait]
impl TellerPlane for RecordingPlane {
    fn arrival(&mut self, token: &UnitToken<Arrival>, _unit: &Unit<'_>) -> Decision<Arrival> {
        self.note(StepName::Arrival);
        if self.refuses(StepName::Arrival) {
            return token.refuse(resp(400, "arrival"));
        }
        token.proceed(())
    }
    fn decode(&mut self, token: &UnitToken<Decode>, _unit: &Unit<'_>) -> Decision<Decode> {
        self.note(StepName::Decode);
        if self.refuses(StepName::Decode) {
            return token.refuse(resp(404, "decode"));
        }
        token.proceed(())
    }
    fn authenticate(
        &mut self,
        token: &UnitToken<Authenticate>,
        unit: &Unit<'_>,
    ) -> Decision<Authenticate> {
        self.note(StepName::Authenticate);
        if self.refuses(StepName::Authenticate) {
            return token.refuse(resp(401, "authenticate"));
        }
        token.proceed(Principal {
            key: unit.gov.key.clone(),
        })
    }
    fn verify(
        &mut self,
        token: &UnitToken<Verify>,
        _unit: &Unit<'_>,
        _principal: &Principal,
    ) -> Decision<Verify> {
        self.note(StepName::Verify);
        if self.refuses(StepName::Verify) {
            return token.refuse(resp(403, "verify"));
        }
        token.proceed(())
    }
    fn approve(
        &mut self,
        token: &UnitToken<Approve>,
        _unit: &Unit<'_>,
        _principal: &Principal,
    ) -> Decision<Approve> {
        self.note(StepName::Approve);
        if self.refuses(StepName::Approve) {
            return token.refuse(resp(403, "approve"));
        }
        token.proceed(())
    }
    fn admit(
        &mut self,
        token: &UnitToken<Admit>,
        _unit: &Unit<'_>,
        _principal: &Principal,
    ) -> Decision<Admit> {
        self.note(StepName::Admit);
        if self.refuses(StepName::Admit) {
            return token.refuse(resp(429, "admit"));
        }
        token.proceed(token.hold(None, None, self.charged))
    }
    async fn route(
        &mut self,
        token: &UnitToken<Route>,
        _unit: &Unit<'_>,
        _hold: &Hold,
    ) -> Decision<Route> {
        self.note(StepName::Route);
        if self.refuses(StepName::Route) {
            return token.refuse(resp(503, "route"));
        }
        token.proceed(resp(200, "routed"))
    }
    async fn meter(
        &mut self,
        token: &UnitToken<Meter>,
        _unit: &Unit<'_>,
        _hold: &Hold,
        resp: Response,
    ) -> Decision<Meter> {
        self.note(StepName::Meter);
        if self.refuses(StepName::Meter) {
            return token.refuse(super::tests::resp(500, "meter"));
        }
        token.proceed(Metered {
            status: resp.status().as_u16(),
            resp,
        })
    }
    fn audit(
        &mut self,
        token: &UnitToken<Audit>,
        _unit: &Unit<'_>,
        hold: Hold,
        closing: Closing,
    ) -> Decision<Audit> {
        self.note(StepName::Audit);
        *self.trace.audited_with_hold.lock().unwrap() = Some((hold.charged(), closing.end));
        let (_admit, _downgraded, _charged) = hold.into_parts();
        token.proceed(closing.resp)
    }
    fn audit_refused(
        &mut self,
        token: &UnitToken<Audit>,
        _unit: &Unit<'_>,
        refusal: Refusal,
    ) -> Decision<Audit> {
        self.note(StepName::Audit);
        *self.trace.audited_refused_at.lock().unwrap() = Some(refusal.step());
        token.proceed(refusal.into_response())
    }
    fn posted(&mut self, _unit: &Unit<'_>, posted: Posted) {
        self.trace.posted.lock().unwrap().push(posted.end());
    }
}

fn plane(refuse_at: Option<StepName>, charged: bool) -> (RecordingPlane, Arc<Trace>) {
    let trace = Arc::new(Trace::default());
    (
        RecordingPlane {
            refuse_at,
            charged,
            trace: Arc::clone(&trace),
        },
        trace,
    )
}

fn unit(gov: &busbar_api::PlaneRequestCtx) -> Unit<'_> {
    Unit::new(gov, "dest", 1, std::time::Instant::now()).with_correlation(7)
}

#[tokio::test]
async fn a_full_pass_runs_all_nine_steps_in_order_and_posts_completed_once() {
    let gov = busbar_api::PlaneRequestCtx::default();
    let (p, trace) = plane(None, true);
    let out = run_unit(p, unit(&gov)).await;
    assert_eq!(out.status(), 200);
    assert_eq!(trace.steps(), StepName::ALL.to_vec(), "canonical order");
    assert_eq!(
        *trace.audited_with_hold.lock().unwrap(),
        Some((true, UnitEnd::Completed)),
        "audit closed a charged hold with a completed end"
    );
    assert_eq!(*trace.audited_refused_at.lock().unwrap(), None);
    assert_eq!(
        trace.posted(),
        vec![UnitEnd::Completed],
        "posted exactly once"
    );
}

#[tokio::test]
async fn a_refusal_at_verify_never_reaches_admit_and_goes_to_audit_refused() {
    let gov = busbar_api::PlaneRequestCtx::default();
    let (p, trace) = plane(Some(StepName::Verify), true);
    let out = run_unit(p, unit(&gov)).await;
    assert_eq!(
        out.status(),
        403,
        "the plane's own refusal comes back verbatim"
    );
    assert_eq!(
        trace.steps(),
        vec![
            StepName::Arrival,
            StepName::Decode,
            StepName::Authenticate,
            StepName::Verify,
            StepName::Audit,
        ]
    );
    assert!(
        !trace.saw(StepName::Admit),
        "verify refused: the door is never reached"
    );
    assert!(!trace.saw(StepName::Route));
    assert_eq!(
        *trace.audited_refused_at.lock().unwrap(),
        Some(StepName::Verify),
        "audited through the no-hold door, stamped with the refusing step"
    );
    assert_eq!(*trace.audited_with_hold.lock().unwrap(), None);
    assert_eq!(trace.posted(), vec![UnitEnd::Refused(StepName::Verify)]);
}

#[tokio::test]
async fn a_refusal_at_admit_has_no_hold_and_goes_to_audit_refused() {
    let gov = busbar_api::PlaneRequestCtx::default();
    let (p, trace) = plane(Some(StepName::Admit), true);
    let out = run_unit(p, unit(&gov)).await;
    assert_eq!(out.status(), 429);
    assert!(trace.saw(StepName::Admit));
    assert!(!trace.saw(StepName::Route));
    assert_eq!(
        *trace.audited_refused_at.lock().unwrap(),
        Some(StepName::Admit)
    );
    assert_eq!(*trace.audited_with_hold.lock().unwrap(), None);
    assert_eq!(trace.posted(), vec![UnitEnd::Refused(StepName::Admit)]);
}

#[tokio::test]
async fn a_refusal_at_route_reaches_audit_with_the_admitted_hold() {
    let gov = busbar_api::PlaneRequestCtx::default();
    let (p, trace) = plane(Some(StepName::Route), true);
    let out = run_unit(p, unit(&gov)).await;
    assert_eq!(
        out.status(),
        503,
        "the plane's route refusal comes back through audit"
    );
    assert!(trace.saw(StepName::Admit));
    assert!(trace.saw(StepName::Route));
    assert!(
        !trace.saw(StepName::Meter),
        "a route refusal skips the meter"
    );
    assert_eq!(
        *trace.audited_with_hold.lock().unwrap(),
        Some((true, UnitEnd::Refused(StepName::Route))),
        "audited WITH the charged hold: the admission stands"
    );
    assert_eq!(*trace.audited_refused_at.lock().unwrap(), None);
    assert_eq!(trace.posted(), vec![UnitEnd::Refused(StepName::Route)]);
}

#[tokio::test]
async fn a_refusal_at_meter_reaches_audit_with_the_hold() {
    let gov = busbar_api::PlaneRequestCtx::default();
    let (p, trace) = plane(Some(StepName::Meter), false);
    let out = run_unit(p, unit(&gov)).await;
    assert_eq!(out.status(), 500);
    assert_eq!(
        *trace.audited_with_hold.lock().unwrap(),
        Some((false, UnitEnd::Refused(StepName::Meter)))
    );
    assert_eq!(trace.posted(), vec![UnitEnd::Refused(StepName::Meter)]);
}

#[test]
fn step_names_after_admit_are_exactly_route_meter_audit() {
    let after: Vec<StepName> = StepName::ALL
        .into_iter()
        .filter(|s| s.after_admit())
        .collect();
    assert_eq!(
        after,
        vec![StepName::Route, StepName::Meter, StepName::Audit]
    );
}

#[test]
fn open_unit_returns_the_hold_on_a_pass_and_posts_only_on_a_refusal() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let (mut p, trace) = plane(None, true);
    let hold = open_unit(&mut p, &unit(&gov)).expect("the door opens");
    assert!(hold.charged());
    assert_eq!(
        trace.steps(),
        StepName::ALL[..6].to_vec(),
        "arrival through admit, no route/meter/audit"
    );
    assert!(
        trace.posted().is_empty(),
        "an open session is not posted yet"
    );
    let (_admit, _downgraded, _charged) = hold.into_parts();

    let (mut p, trace) = plane(Some(StepName::Verify), true);
    let refused = open_unit(&mut p, &unit(&gov)).expect_err("verify refuses the session");
    assert_eq!(refused.status(), 403);
    assert!(!trace.saw(StepName::Admit));
    assert_eq!(
        *trace.audited_refused_at.lock().unwrap(),
        Some(StepName::Verify)
    );
    assert_eq!(trace.posted(), vec![UnitEnd::Refused(StepName::Verify)]);
}

// ── The gauntlet adapter: the older siblings keep their outcomes ─────────────────────────────

/// The same stub the gauntlet-session tests use: refuses or proceeds at verify, records a drive.
struct StubPlane {
    refuse: bool,
    drove: Arc<AtomicBool>,
    seen_correlation: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl GauntletPlane for StubPlane {
    fn verify_destination(&self, req: &GauntletRequest<'_>) -> VerifyOutcome {
        self.seen_correlation
            .store(req.correlation_id as usize, Ordering::SeqCst);
        if self.refuse {
            VerifyOutcome::Refuse(resp(429, "refused"))
        } else {
            VerifyOutcome::Proceed
        }
    }

    async fn drive(self: Box<Self>, req: GauntletRequest<'_>) -> Response {
        assert_eq!(
            req.correlation_id, 77,
            "drive sees the caller's correlation id"
        );
        assert_eq!(
            req.destination, "dest-x",
            "drive sees the caller's destination"
        );
        assert_eq!(req.charged_at, 5, "drive sees the caller's charge window");
        self.drove.store(true, Ordering::SeqCst);
        resp(200, "driven")
    }
}

fn gauntlet_req(gov: &busbar_api::PlaneRequestCtx) -> GauntletRequest<'_> {
    GauntletRequest {
        gov,
        destination: "dest-x",
        correlation_id: 77,
        charged_at: 5,
        started: std::time::Instant::now(),
    }
}

#[tokio::test]
async fn adapter_run_gauntlet_drives_on_proceed_and_returns_the_refusal_on_refuse() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let drove = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicUsize::new(0));
    let out = run_gauntlet(
        gauntlet_req(&gov),
        Box::new(StubPlane {
            refuse: false,
            drove: Arc::clone(&drove),
            seen_correlation: Arc::clone(&seen),
        }),
    )
    .await;
    assert_eq!(out.status(), 200);
    assert!(drove.load(Ordering::SeqCst), "proceed drives");
    assert_eq!(
        seen.load(Ordering::SeqCst),
        77,
        "verify saw the same request facts"
    );

    let drove = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicUsize::new(0));
    let out = run_gauntlet(
        gauntlet_req(&gov),
        Box::new(StubPlane {
            refuse: true,
            drove: Arc::clone(&drove),
            seen_correlation: Arc::clone(&seen),
        }),
    )
    .await;
    assert_eq!(out.status(), 429, "the plane's refusal comes back verbatim");
    assert!(!drove.load(Ordering::SeqCst), "refuse never drives");
}

#[test]
fn adapter_run_gauntlet_session_admits_without_driving_and_refuses_before_any_charge() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let drove = Arc::new(AtomicBool::new(false));
    let admitted = run_gauntlet_session(
        gauntlet_req(&gov),
        Box::new(StubPlane {
            refuse: false,
            drove: Arc::clone(&drove),
            seen_correlation: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .expect("proceed admits");
    assert_eq!(admitted.correlation_id, 77);
    assert!(
        !drove.load(Ordering::SeqCst),
        "the session opener never drives"
    );

    let drove = Arc::new(AtomicBool::new(false));
    let refused = run_gauntlet_session(
        gauntlet_req(&gov),
        Box::new(StubPlane {
            refuse: true,
            drove: Arc::clone(&drove),
            seen_correlation: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .expect_err("refuse denies the session");
    assert_eq!(refused.status(), 429);
    assert!(!drove.load(Ordering::SeqCst));
}
