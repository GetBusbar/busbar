// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHADOW-COMPARE: the dormant duplex kernel-loop SESSION rider reproduces the substrate session admit
//! BYTE-FOR-BYTE, and the admit gate stays MONEY-FREE (reserve/per-frame settle are plane-side, after it).
//!
//! The duplex analogue of `gauntlet_kernel`'s `kernel_session_admit_matches_substrate_open_unit` shadow,
//! driving a FAITHFUL stand-in for the duplex WS-accept gate (`duplex_ws.rs`'s `accept_gauntlet` gate)
//! through BOTH admit paths — `leg_legacy` = `busbar_substrate::plane_host::run_gauntlet_session` (the
//! shipped `admit_open` authority `accept_gauntlet` calls), `leg_loop` = the dormant
//! `admit_duplex_session_via_kernel` (→ `open_gauntlet_via_kernel`) — on the same input, and asserting:
//!   (1) PROCEED — identical `Admitted` (correlation), and neither drove (a session opener never routes);
//!   (2) REFUSE — byte-identical status/headers/body (the plane's own 403);
//!   (3) MONEY — the admit gate fires ZERO charges on BOTH legs. The duplex reserve-on-admit and
//!       per-frame settle live INSIDE `on_socket`, AFTER `accept_gauntlet` admits, so a stand-in whose
//!       (unreachable) `drive` would record a charge records NOTHING on either leg: the kernel admit
//!       (empty ZeroHold, Evidence::default, no book) adds nothing, and the substrate admit adds nothing
//!       — zero overlap, zero double-count.
//!
//! Any difference here is a divergence (STOP + report per DECISIONS #28/#29).
//!
//! WHY A STAND-IN. The duplex gate is the plane a caller hands `accept_gauntlet` (voice passes its
//! `SessionGauntlet`; the substrate WS tests pass a `GatePlane`), and `busbar-substrate` cannot reach
//! `open_gauntlet_via_kernel` (which needs `busbar-kernel`). The shadow's claim is narrow and fully
//! proven here: both admit paths run the SAME `plane.verify_destination()` in the SAME
//! verify-before-charge position and shape the SAME admit/refusal, with the kernel exit adding NOTHING —
//! a property of the bridge, provable with any faithful gate. The stand-in mirrors the substrate WS
//! `GatePlane` verbatim: refuse a denied destination with the exact `403` + "destination refused" body,
//! else proceed; `drive` is the session-path-unreachable neutral 500.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use axum::response::Response;
use busbar_substrate::plane_host::{
    run_gauntlet_session, GauntletPlane, GauntletRequest, VerifyOutcome,
};

use crate::root::duplex_kernel_rider::admit_duplex_session_via_kernel;

/// A faithful stand-in for the duplex WS-accept gate (`duplex_ws_tests.rs`'s `GatePlane`):
/// `verify_destination` refuses a denied destination with the gate's OWN `403` + body, else proceeds;
/// `drive` is the session-path-unreachable neutral 500. The `charged` recorder would fire only if the
/// admit gate ever drove (it never does on the session path) — the shadow asserts it stays empty, which
/// is the money-free-gate proof: duplex's real reserve/per-frame settle live AFTER this gate, plane-side.
struct DuplexSessionStandin {
    deny: bool,
    charged: Arc<Mutex<u32>>,
}

#[async_trait::async_trait]
impl GauntletPlane for DuplexSessionStandin {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        if self.deny {
            VerifyOutcome::Refuse(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(Body::from("destination refused"))
                    .expect("static refusal response builds"),
            )
        } else {
            VerifyOutcome::Proceed
        }
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> Response {
        // UNREACHABLE on the session path (the opener runs only the admission gate). If a refactor ever
        // mis-routed a session opener through drive, this charge would fire — the recorder catches it.
        *self.charged.lock().expect("charge recorder lock") += 1;
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("session gate never drives"))
            .expect("static fault response builds")
    }
}

fn standin(deny: bool, charged: &Arc<Mutex<u32>>) -> Box<dyn GauntletPlane> {
    Box::new(DuplexSessionStandin {
        deny,
        charged: Arc::clone(charged),
    })
}

fn req(gov: &busbar_api::PlaneRequestCtx) -> GauntletRequest<'_> {
    GauntletRequest {
        gov,
        destination: "model-x",
        correlation_id: 1,
        charged_at: 1,
        started: Instant::now(),
    }
}

async fn split(resp: Response) -> (StatusCode, axum::http::HeaderMap, axum::body::Bytes) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body drains");
    (status, headers, body)
}

#[test]
fn duplex_kernel_admit_matches_substrate_open_unit_on_proceed() {
    let gov = busbar_api::PlaneRequestCtx::default();
    let legacy_charged = Arc::new(Mutex::new(0));
    let loop_charged = Arc::new(Mutex::new(0));

    let legacy = run_gauntlet_session(req(&gov), standin(false, &legacy_charged))
        .expect("substrate admits the duplex session on proceed");
    let kernel = admit_duplex_session_via_kernel(req(&gov), standin(false, &loop_charged))
        .expect("kernel admits the duplex session on proceed");

    // (1) Same Admitted shape (correlation) — and neither drove (a session opener never routes).
    assert_eq!(
        legacy, kernel,
        "the admitted duplex session shape diverged kernel-vs-substrate"
    );

    // (3) MONEY: the admit gate never drove on either leg — reserve/per-frame settle are plane-side.
    assert_eq!(
        *legacy_charged.lock().unwrap(),
        0,
        "the substrate admit gate must not drive (duplex reserve/settle are post-admit, plane-side)"
    );
    assert_eq!(
        *loop_charged.lock().unwrap(),
        0,
        "MONEY: the kernel admit (empty ZeroHold, Evidence::default, no book) drives nothing — \
         reserve/per-frame settle stay plane-side, zero overlap"
    );
}

#[tokio::test]
async fn duplex_kernel_admit_matches_substrate_open_unit_on_refuse() {
    let gov = busbar_api::PlaneRequestCtx::default();
    let legacy_charged = Arc::new(Mutex::new(0));
    let loop_charged = Arc::new(Mutex::new(0));

    let legacy = run_gauntlet_session(req(&gov), standin(true, &legacy_charged))
        .expect_err("substrate refuses the duplex session before any charge");
    let kernel = admit_duplex_session_via_kernel(req(&gov), standin(true, &loop_charged))
        .expect_err("kernel refuses the duplex session before any charge");

    // (2) BYTE-IDENTICAL REFUSAL — the gate's own 403, verbatim on both legs.
    let (ls, lh, lb) = split(legacy).await;
    let (ks, kh, kb) = split(kernel).await;
    assert_eq!(ls, StatusCode::FORBIDDEN, "the duplex gate's own refusal status");
    assert_eq!(ls, ks, "duplex session refusal status diverged kernel-vs-substrate");
    assert_eq!(lh, kh, "duplex session refusal headers diverged kernel-vs-substrate");
    assert_eq!(lb, kb, "duplex session refusal body diverged kernel-vs-substrate");

    // (3) MONEY: a refused accept costs zero charge on both legs (verify strictly before any charge).
    assert_eq!(*legacy_charged.lock().unwrap(), 0, "substrate refuse charges nothing");
    assert_eq!(*loop_charged.lock().unwrap(), 0, "kernel refuse charges nothing");
}
