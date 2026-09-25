// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHADOW-COMPARE: a PER-CALL METERING plane rides the unified kernel loop BYTE-FOR-BYTE and
//! MONEY-FOR-MONEY.
//!
//! `gauntlet_kernel`'s own shadow proves the bridge byte-identical for a plane that charges
//! nothing. This one proves the other half of the thin-verbatim-rider claim (DECISIONS #28/#29):
//! a plane whose ONE flat per-call charge fires INSIDE `drive` (the shape of the A2A invoke plane's
//! `meter_request`, `busbar-a2a`'s `receive.rs`) is driven through BOTH loops — `leg_legacy` =
//! `busbar_kernel::plane_host::run_gauntlet` (the shipped authority), `leg_loop` =
//! `run_gauntlet_via_kernel` (the plane-neutral bridge `gauntlet_install::install()` registers as
//! the runner) — on the same input, and the test asserts (1) byte-identical status/headers/body AND
//! (2) identical `meter_charge` rows. Any difference is a divergence (STOP + report).
//!
//! THE MONEY CLAIM, PROVEN HERE. The charge is a pure request `Queries` meter, amount 0, attributed
//! to `(key, resource, provider)`, and it fires inside `drive`. The kernel exit opens an empty
//! `ZeroHold`, reports `Evidence::default` and binds no book — so it settles NOTHING. The `leg_loop`
//! recorder must therefore hold EXACTLY the one row `drive` fired, identical to `leg_legacy` and with
//! nothing added on the kernel exit: zero double-count.
//!
//! This replaces the former test-only `root::a2a_kernel_rider` module, whose one function was a
//! single-line delegation to `run_gauntlet_via_kernel`: the shadow now drives the bridge directly,
//! with the same stand-in and the same assertions, and the composition root keeps no plane-named
//! rider for it.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use axum::response::Response;
use busbar_kernel::plane_host::{run_gauntlet, GauntletPlane, GauntletRequest, VerifyOutcome};

use crate::root::gauntlet_kernel::run_gauntlet_via_kernel;

/// The JSON-RPC success envelope the stand-in's `drive` returns — a deterministic body so the two
/// legs are byte-comparable.
const STANDIN_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"message","messageId":"m-1","role":"agent"}}"#;

/// One `meter_charge` row as a per-call metering plane posts it: the flat per-call `Queries`
/// accrual, amount 0, attributed to `(billed_key_id, resource, provider)` on a named cap scope — the
/// tuple a hot `Usage::with_attribution(Queries, 0, 0, AdmissionId::NONE, billed_key_id, resource,
/// provider)` carries, recorded semantically because the root crate does not depend on
/// `busbar-plugin`, and does not need to: the shadow proves the BRIDGE carries this row through
/// unchanged, not that the hot `Usage` type round-trips.
/// The provider label the stand-in attributes its charge to. Opaque to the bridge.
const PROVIDER: &str = "per-call-plane";

#[derive(Clone, Debug, PartialEq, Eq)]
struct MeterRow {
    cap_scope: &'static str,
    component: &'static str,
    amount: u64,
    billed_key_id: String,
    resource: String,
    provider: &'static str,
}

/// A per-call metering plane: `verify_destination` is a structural `Proceed` (a plane whose
/// destination verification is interleaved with admission does it inside `drive`), and `drive`
/// fires the ONE flat per-call charge into a shared recorder and returns a JSON-RPC response.
///
/// WHY A STAND-IN, NOT A REAL PLANE. A shipped plane's metering fires only under its own engine
/// harness, which the plane's crate owns and proves end-to-end against the ledger; end-to-end money
/// faithfulness on the flip is the fleet-box oracle's job (DECISIONS #29). What the SHADOW must
/// prove is narrower and is fully proven here: both loops invoke the SAME `plane.drive()` verbatim,
/// so byte-identity of the response AND identity of the meter rows `drive` fires — the kernel exit
/// adding NOTHING — is a property of the bridge, provable with any metering plane.
struct PerCallMeterStandin {
    rec: Arc<Mutex<Vec<MeterRow>>>,
    cap_scope: &'static str,
    billed_key_id: &'static str,
    resource: &'static str,
    status: u16,
    body: &'static [u8],
}

#[async_trait::async_trait]
impl GauntletPlane for PerCallMeterStandin {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        VerifyOutcome::Proceed
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> Response {
        // THE PLANE'S ONE CHARGE, fired inside `drive`: a pure request meter (`Queries` → amount 0)
        // against `(billed_key_id, resource, provider)` on this call's cap scope. Fire-and-forget.
        self.rec.lock().expect("recorder lock").push(MeterRow {
            cap_scope: self.cap_scope,
            component: "Queries",
            amount: 0,
            billed_key_id: self.billed_key_id.to_string(),
            resource: self.resource.to_string(),
            provider: PROVIDER,
        });
        let mut resp = Response::new(Body::from(self.body));
        *resp.status_mut() = StatusCode::from_u16(self.status).expect("valid status");
        resp.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        resp
    }
}

/// A fresh stand-in feeding `rec`, with the SAME attribution both legs charge under.
fn standin(rec: &Arc<Mutex<Vec<MeterRow>>>) -> Box<dyn GauntletPlane> {
    Box::new(PerCallMeterStandin {
        rec: Arc::clone(rec),
        cap_scope: "agent:planner",
        billed_key_id: "vk_test",
        resource: "agent:planner",
        status: 200,
        body: STANDIN_BODY,
    })
}

fn req(gov: &busbar_api::PlaneRequestCtx) -> GauntletRequest<'_> {
    GauntletRequest {
        gov,
        // The plane's drive reads its target off the plane, not the request — this label is unused
        // (verify_destination is a no-op).
        destination: "",
        correlation_id: 0,
        charged_at: 0,
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

#[tokio::test]
async fn per_call_metering_plane_matches_substrate_gauntlet_byte_and_meter() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let leg_legacy_rec = Arc::new(Mutex::new(Vec::new()));
    let leg_loop_rec = Arc::new(Mutex::new(Vec::new()));

    let leg_legacy = run_gauntlet(req(&gov), standin(&leg_legacy_rec)).await;
    let leg_loop = run_gauntlet_via_kernel(req(&gov), standin(&leg_loop_rec)).await;

    // (1) BYTE-IDENTICAL RESPONSE.
    let (ls, lh, lb) = split(leg_legacy).await;
    let (ks, kh, kb) = split(leg_loop).await;
    assert_eq!(ls, ks, "status diverged legacy-vs-loop");
    assert_eq!(lh, kh, "headers diverged legacy-vs-loop");
    assert_eq!(lb, kb, "body diverged legacy-vs-loop");

    // (2) IDENTICAL METER ROWS, AND NO DOUBLE-COUNT.
    let legacy_rows = leg_legacy_rec.lock().expect("recorder lock").clone();
    let loop_rows = leg_loop_rec.lock().expect("recorder lock").clone();
    assert_eq!(
        legacy_rows.len(),
        1,
        "the substrate leg fires the plane's ONE flat per-call charge"
    );
    assert_eq!(
        loop_rows.len(),
        1,
        "MONEY: the kernel exit (empty ZeroHold, Evidence::default, no book bound) adds NOTHING — \
         exactly the drive's one charge, so no double-count"
    );
    assert_eq!(
        legacy_rows, loop_rows,
        "meter rows diverged legacy-vs-loop (cap_scope / Queries attribution)"
    );
}
