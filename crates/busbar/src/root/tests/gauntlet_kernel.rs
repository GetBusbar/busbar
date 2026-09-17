// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHADOW-COMPARE: the dormant kernel-loop rider reproduces the substrate gauntlet BYTE-FOR-BYTE.
//!
//! Both loops are pass-through wrappers around the SAME `GauntletPlane::drive`, so for one plane on
//! one input they must return identical status, headers and body. This is the local proof that the
//! loop unification adds nothing to the wire — the same faithfulness the fleet-box money oracle
//! (DECISIONS #29) will later confirm on the MCP money family. Any difference here is a divergence.

use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use axum::response::Response;
use busbar_substrate::plane_host::{
    run_gauntlet, run_gauntlet_session, GauntletPlane, GauntletRequest, VerifyOutcome,
};

use crate::root::gauntlet_kernel::{open_gauntlet_via_kernel, run_gauntlet_via_kernel};

/// A deterministic plane: verify proceeds, drive returns a fixed status/headers/body. Two identical
/// instances feed the two loops (each `drive` consumes its own box).
struct FixedPlane {
    status: u16,
    body: &'static [u8],
}

impl FixedPlane {
    fn boxed(status: u16, body: &'static [u8]) -> Box<dyn GauntletPlane> {
        Box::new(FixedPlane { status, body })
    }
}

#[async_trait::async_trait]
impl GauntletPlane for FixedPlane {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        VerifyOutcome::Proceed
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> Response {
        let mut resp = Response::new(Body::from(self.body));
        *resp.status_mut() = StatusCode::from_u16(self.status).expect("valid status");
        resp.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        resp.headers_mut()
            .insert("x-busbar-fixed", "42".parse().unwrap());
        resp
    }
}

/// A plane that refuses at verify (pre-charge), returning its own finished response.
struct RefusePlane;

#[async_trait::async_trait]
impl GauntletPlane for RefusePlane {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        let mut resp = Response::new(Body::from("denied"));
        *resp.status_mut() = StatusCode::FORBIDDEN;
        resp.headers_mut()
            .insert("x-refused", "1".parse().unwrap());
        VerifyOutcome::Refuse(resp)
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> Response {
        // Unreachable: a refuse never drives. Kept so the trait is satisfied.
        Response::new(Body::empty())
    }
}

fn req(gov: &busbar_api::PlaneRequestCtx) -> GauntletRequest<'_> {
    GauntletRequest {
        gov,
        destination: "some.tool",
        correlation_id: 0,
        charged_at: 0,
        started: Instant::now(),
    }
}

async fn split(resp: Response) -> (StatusCode, axum::http::HeaderMap, axum::body::Bytes) {
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body drains");
    (status, headers, body)
}

#[tokio::test]
async fn kernel_rider_matches_substrate_gauntlet_on_proceed() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let substrate = run_gauntlet(req(&gov), FixedPlane::boxed(200, br#"{"ok":true}"#)).await;
    let kernel = run_gauntlet_via_kernel(req(&gov), FixedPlane::boxed(200, br#"{"ok":true}"#)).await;

    let (gs, gh, gb) = split(substrate).await;
    let (ks, kh, kb) = split(kernel).await;
    assert_eq!(gs, ks, "status diverged rider-vs-gauntlet");
    assert_eq!(gh, kh, "headers diverged rider-vs-gauntlet");
    assert_eq!(gb, kb, "body diverged rider-vs-gauntlet");
}

#[tokio::test]
async fn kernel_rider_matches_substrate_gauntlet_on_refuse() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let substrate = run_gauntlet(req(&gov), Box::new(RefusePlane)).await;
    let kernel = run_gauntlet_via_kernel(req(&gov), Box::new(RefusePlane)).await;

    let (gs, gh, gb) = split(substrate).await;
    let (ks, kh, kb) = split(kernel).await;
    assert_eq!(gs, StatusCode::FORBIDDEN, "the plane's own refusal status");
    assert_eq!(gs, ks, "refusal status diverged rider-vs-gauntlet");
    assert_eq!(gh, kh, "refusal headers diverged rider-vs-gauntlet");
    assert_eq!(gb, kb, "refusal body diverged rider-vs-gauntlet");
}

// ── SESSION ADMIT GATE (Ruling 3): kernel open_unit vs substrate open_unit ──────────────────────

#[tokio::test]
async fn kernel_session_admit_matches_substrate_open_unit_on_proceed() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let substrate = run_gauntlet_session(req(&gov), FixedPlane::boxed(200, b"ignored"))
        .expect("substrate admits on proceed");
    let kernel = open_gauntlet_via_kernel(req(&gov), FixedPlane::boxed(200, b"ignored"))
        .expect("kernel admits on proceed");

    // Same Admitted shape (correlation id) — and neither drove (a session opener never routes).
    assert_eq!(
        substrate, kernel,
        "the admitted session shape diverged kernel-vs-substrate"
    );
}

#[tokio::test]
async fn kernel_session_admit_matches_substrate_open_unit_on_refuse() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let substrate = run_gauntlet_session(req(&gov), Box::new(RefusePlane))
        .expect_err("substrate refuses the session before any charge");
    let kernel = open_gauntlet_via_kernel(req(&gov), Box::new(RefusePlane))
        .expect_err("kernel refuses the session before any charge");

    let (ss, sh, sb) = split(substrate).await;
    let (ks, kh, kb) = split(kernel).await;
    assert_eq!(ss, StatusCode::FORBIDDEN, "the plane's own refusal status");
    assert_eq!(ss, ks, "session refusal status diverged kernel-vs-substrate");
    assert_eq!(sh, kh, "session refusal headers diverged kernel-vs-substrate");
    assert_eq!(sb, kb, "session refusal body diverged kernel-vs-substrate");
}
