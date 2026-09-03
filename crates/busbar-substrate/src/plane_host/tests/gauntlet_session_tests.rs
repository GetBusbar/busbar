// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the gauntlet-session sibling in `crates/busbar-substrate/src/plane_host/mod.rs`.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A stub plane that records whether its `drive` (stages 4+5, the CHARGE-bearing leg) ran, and either
/// proceeds or refuses at the verify gate — so a test can prove NEITHER sibling drives on a refuse
/// (verify strictly before charge) and the one-shot path drives on a proceed.
struct StubPlane {
    refuse: bool,
    drove: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl GauntletPlane for StubPlane {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        if self.refuse {
            VerifyOutcome::Refuse(
                axum::response::Response::builder()
                    .status(429)
                    .body(axum::body::Body::from("refused"))
                    .expect("refusal response"),
            )
        } else {
            VerifyOutcome::Proceed
        }
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> axum::response::Response {
        self.drove.store(true, Ordering::SeqCst);
        axum::response::Response::builder()
            .status(200)
            .body(axum::body::Body::from("driven"))
            .expect("driven response")
    }
}

fn req(gov: &busbar_api::PlaneRequestCtx) -> GauntletRequest<'_> {
    GauntletRequest {
        gov,
        destination: "model-x",
        correlation_id: 77,
        charged_at: 1,
        started: std::time::Instant::now(),
    }
}

#[tokio::test]
async fn siblings_coexist_and_share_the_admit_open_gate() {
    let gov = busbar_api::PlaneRequestCtx::default();

    // PROCEED: run_gauntlet DRIVES (charge leg runs); run_gauntlet_session ADMITS (no drive) and the
    // Admitted carries the correlation id — the same shared gate said "proceed" to both.
    let drove_rg = Arc::new(AtomicBool::new(false));
    let resp = run_gauntlet(
        req(&gov),
        Box::new(StubPlane {
            refuse: false,
            drove: Arc::clone(&drove_rg),
        }),
    )
    .await;
    assert_eq!(resp.status(), 200, "proceed drives the one-shot path");
    assert!(
        drove_rg.load(Ordering::SeqCst),
        "run_gauntlet drove on proceed"
    );

    let drove_rgs = Arc::new(AtomicBool::new(false));
    let admitted = run_gauntlet_session(
        req(&gov),
        Box::new(StubPlane {
            refuse: false,
            drove: Arc::clone(&drove_rgs),
        }),
    )
    .expect("proceed admits the session");
    assert_eq!(
        admitted.correlation_id, 77,
        "the admitted session joins on the correlation id"
    );
    assert!(
        !drove_rgs.load(Ordering::SeqCst),
        "the session opener NEVER drives a one-shot response"
    );

    // REFUSE: BOTH siblings return the plane's OWN refusal verbatim and NEITHER drives — the one
    // shared verify-before-charge gate rejects before any charge in both paths.
    let drove_rg_r = Arc::new(AtomicBool::new(false));
    let resp = run_gauntlet(
        req(&gov),
        Box::new(StubPlane {
            refuse: true,
            drove: Arc::clone(&drove_rg_r),
        }),
    )
    .await;
    assert_eq!(
        resp.status(),
        429,
        "refuse returns the plane's refusal verbatim"
    );
    assert!(
        !drove_rg_r.load(Ordering::SeqCst),
        "refuse never drives (run_gauntlet)"
    );

    let drove_rgs_r = Arc::new(AtomicBool::new(false));
    let refusal = run_gauntlet_session(
        req(&gov),
        Box::new(StubPlane {
            refuse: true,
            drove: Arc::clone(&drove_rgs_r),
        }),
    )
    .expect_err("refuse denies the session before any charge");
    assert_eq!(
        refusal.status(),
        429,
        "the session refusal is the plane's own response"
    );
    assert!(
        !drove_rgs_r.load(Ordering::SeqCst),
        "refuse never drives (run_gauntlet_session) — zero bytes, zero charge"
    );
}
