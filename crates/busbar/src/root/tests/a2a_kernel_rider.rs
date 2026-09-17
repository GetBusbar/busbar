// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHADOW-COMPARE: the dormant A2A kernel-loop rider reproduces the substrate gauntlet
//! BYTE-FOR-BYTE and MONEY-FOR-MONEY.
//!
//! The A2A analogue of `gauntlet_kernel`'s MCP-witness shadow: drive one A2A
//! plane through BOTH loops — `leg_legacy` = `busbar_substrate::plane_host::run_gauntlet` (the
//! shipped authority), `leg_loop` = the dormant `run_a2a_via_kernel` (→ `run_gauntlet_via_kernel`)
//! — on the same input, and assert (1) byte-identical status/headers/body AND (2) identical
//! `meter_charge` rows. Both loops are pass-through wrappers around the SAME `GauntletPlane::drive`,
//! so any difference here is a divergence (STOP + report per DECISIONS #28/#29).
//!
//! THE MONEY CLAIM, PROVEN HERE. A2A's one flat per-call charge (`receive.rs:723-740`,
//! `meter_request`: a pure request `Queries` meter, amount 0, against `(key, resource, "a2a")`)
//! fires INSIDE `drive`. The kernel exit opens an empty `ZeroHold`, reports `Evidence::default` and
//! binds no book — so it settles NOTHING. The `leg_loop` recorder must therefore hold EXACTLY the
//! one row `drive` fired, identical to `leg_legacy` and with nothing added on the kernel exit: zero
//! double-count.

use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use axum::response::Response;
use busbar_substrate::plane_host::{run_gauntlet, GauntletPlane, GauntletRequest, VerifyOutcome};

use crate::root::a2a_kernel_rider::run_a2a_via_kernel;

/// The A2A-shaped JSON-RPC success envelope the stand-in's `drive` returns — a deterministic body so
/// the two legs are byte-comparable.
const A2A_BODY: &[u8] =
    br#"{"jsonrpc":"2.0","id":7,"result":{"kind":"message","messageId":"m-1","role":"agent"}}"#;

/// One `meter_charge` row as `A2aInvokePlane::meter_request` (receive.rs:723-740) posts it: the flat
/// per-call `Queries` accrual, amount 0, attributed to `(billed_key_id, resource, "a2a")` on a named
/// cap scope. The exact tuple the real `busbar_plugin::hot::Usage::with_attribution(Queries, 0, 0,
/// AdmissionId::NONE, billed_key_id, resource, "a2a")` carries — recorded semantically because the
/// root crate does not depend on `busbar-plugin`, and does not need to: the shadow proves the BRIDGE
/// carries this row through unchanged, not that the hot `Usage` type round-trips.
#[derive(Clone, Debug, PartialEq, Eq)]
struct MeterRow {
    cap_scope: &'static str,
    component: &'static str,
    amount: u64,
    billed_key_id: String,
    resource: String,
    provider: &'static str,
}

/// A faithful stand-in for `busbar-a2a`'s crate-private `A2aInvokePlane`: `verify_destination` is a
/// structural `Proceed` (the real one is too — A2A's agent verification is async + interleaved with
/// admission, so it lives inside `drive`), and `drive` fires the ONE flat per-call charge into a
/// shared recorder and returns an A2A-shaped response.
///
/// WHY A STAND-IN, NOT THE REAL PLANE. `A2aInvokePlane` is private to `busbar-a2a` and its
/// `meter_request` only fires under the full A2A relay engine harness (configured agents + backend,
/// `busbar-a2a::a2a::tests::relay_harness`), which drives the plane end-to-end through the real
/// router and reads the ledger. That real-plane meter proof already exists and is green
/// (`busbar-a2a::a2a::tests::metered_verbs_tests`), and end-to-end money faithfulness on the flip is
/// the fleet-box oracle's job (DECISIONS #29). The root crate cannot reach that harness — and
/// `busbar-a2a` cannot reach `run_gauntlet_via_kernel`, which needs `busbar-kernel`. What the SHADOW
/// must prove is narrower and is fully proven here: both loops invoke the SAME `plane.drive()`
/// verbatim, so byte-identity of the response AND identity of the meter rows `drive` fires — the
/// kernel exit adding NOTHING — is a property of the bridge, provable with any metering plane.
struct A2aMeterStandin {
    rec: Arc<Mutex<Vec<MeterRow>>>,
    cap_scope: &'static str,
    billed_key_id: &'static str,
    resource: &'static str,
    status: u16,
    body: &'static [u8],
}

#[async_trait::async_trait]
impl GauntletPlane for A2aMeterStandin {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        VerifyOutcome::Proceed
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> Response {
        // THE PLANE'S ONE CHARGE, fired inside `drive` exactly as `A2aInvokePlane::meter_request`
        // does (receive.rs:723-740): a pure request meter (`Queries` → amount 0) against
        // `(billed_key_id, resource, "a2a")` on this call's cap scope. Fire-and-forget.
        self.rec.lock().expect("recorder lock").push(MeterRow {
            cap_scope: self.cap_scope,
            component: "Queries",
            amount: 0,
            billed_key_id: self.billed_key_id.to_string(),
            resource: self.resource.to_string(),
            provider: "a2a",
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
    Box::new(A2aMeterStandin {
        rec: Arc::clone(rec),
        cap_scope: "a2a:agent:planner",
        billed_key_id: "vk_test",
        resource: "agent:planner",
        status: 200,
        body: A2A_BODY,
    })
}

fn req(gov: &busbar_api::PlaneRequestCtx) -> GauntletRequest<'_> {
    GauntletRequest {
        gov,
        // A2A's drive reads its target off the plane, not the request — this label is unused on the
        // A2A path (verify_destination is a no-op), exactly as `invoke` sets it (receive.rs:887).
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
async fn a2a_kernel_rider_matches_substrate_gauntlet_byte_and_meter() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let leg_legacy_rec = Arc::new(Mutex::new(Vec::new()));
    let leg_loop_rec = Arc::new(Mutex::new(Vec::new()));

    let leg_legacy = run_gauntlet(req(&gov), standin(&leg_legacy_rec)).await;
    let leg_loop = run_a2a_via_kernel(req(&gov), standin(&leg_loop_rec)).await;

    // (1) BYTE-IDENTICAL RESPONSE.
    let (ls, lh, lb) = split(leg_legacy).await;
    let (ks, kh, kb) = split(leg_loop).await;
    assert_eq!(ls, ks, "A2A status diverged legacy-vs-loop");
    assert_eq!(lh, kh, "A2A headers diverged legacy-vs-loop");
    assert_eq!(lb, kb, "A2A body diverged legacy-vs-loop");

    // (2) IDENTICAL METER ROWS, AND NO DOUBLE-COUNT.
    let legacy_rows = leg_legacy_rec.lock().expect("recorder lock").clone();
    let loop_rows = leg_loop_rec.lock().expect("recorder lock").clone();
    assert_eq!(
        legacy_rows.len(),
        1,
        "the substrate leg fires the plane's ONE flat per-call charge (receive.rs:723-740)"
    );
    assert_eq!(
        loop_rows.len(),
        1,
        "MONEY: the kernel exit (empty ZeroHold, Evidence::default, no book bound) adds NOTHING — \
         exactly the drive's one charge, so no double-count"
    );
    assert_eq!(
        legacy_rows, loop_rows,
        "A2A meter rows diverged legacy-vs-loop (cap_scope / Queries attribution)"
    );
}
