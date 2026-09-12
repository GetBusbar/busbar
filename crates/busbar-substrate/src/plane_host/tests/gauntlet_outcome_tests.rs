// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO GAUNTLET SIBLINGS KEEP THEIR OUTCOMES — the cells that pinned them while the seam was a
//! nine-step scaffold over the Teller loop, kept word for word now that the scaffold is gone.
//!
//! They are the measurement that made the deletion safe to make: the scaffold answered seven of its
//! nine steps with a bare proceed, an EMPTY hold and an empty posting, so for every caller it ever
//! had its whole observable behaviour was `verify_destination` then `drive`. These cells say so from
//! the outside — the one-shot path drives on a proceed and returns the plane's own refusal verbatim
//! on a refuse; the session opener admits without driving and refuses before anything is charged —
//! and they pass unchanged across the collapse, which is what "by identity" means here.

use super::*;
use axum::response::Response;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

fn resp(status: u16, body: &'static str) -> Response {
    Response::builder()
        .status(status)
        .body(axum::body::Body::from(body))
        .expect("response")
}

/// The same stub the gauntlet-session tests use: refuses or proceeds at verify, records a drive.
struct OutcomePlane {
    refuse: bool,
    drove: Arc<AtomicBool>,
    seen_correlation: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl GauntletPlane for OutcomePlane {
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
async fn run_gauntlet_drives_on_proceed_and_returns_the_refusal_on_refuse() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let drove = Arc::new(AtomicBool::new(false));
    let seen = Arc::new(AtomicUsize::new(0));
    let out = run_gauntlet(
        gauntlet_req(&gov),
        Box::new(OutcomePlane {
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
        Box::new(OutcomePlane {
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
fn run_gauntlet_session_admits_without_driving_and_refuses_before_any_charge() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let drove = Arc::new(AtomicBool::new(false));
    let admitted = run_gauntlet_session(
        gauntlet_req(&gov),
        Box::new(OutcomePlane {
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
        Box::new(OutcomePlane {
            refuse: true,
            drove: Arc::clone(&drove),
            seen_correlation: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .expect_err("refuse denies the session");
    assert_eq!(refused.status(), 429);
    assert!(!drove.load(Ordering::SeqCst));
}
