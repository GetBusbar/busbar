// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SHADOW-COMPARE: the dormant kernel-loop rider reproduces the substrate gauntlet BYTE-FOR-BYTE.
//!
//! Both loops are pass-through wrappers around the SAME `GauntletPlane::drive`, so for one plane on
//! one input they must return identical status, headers and body. This is the local proof that the
//! loop unification adds nothing to the wire — the same faithfulness the fleet-box money oracle
//! (DECISIONS #29) will later confirm on the MCP money family. Any difference here is a divergence.

use std::future::Future;
use std::pin::Pin;
use std::time::Instant;

use axum::body::{to_bytes, Body};
use axum::http::StatusCode;
use axum::response::Response;
use busbar_kernel::plane_host::{
    register_gauntlet_runner, register_session_runner, run_gauntlet, run_gauntlet_session,
    Admitted, GauntletPlane, GauntletRequest, VerifyOutcome,
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
        resp.headers_mut().insert("x-refused", "1".parse().unwrap());
        VerifyOutcome::Refuse(resp)
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> Response {
        // Unreachable: a refuse never drives. Kept so the trait is satisfied.
        Response::new(Body::empty())
    }
}

/// A plane that self-reports a capability key, so the host-selection seam can route it. Its `drive`
/// returns a distinct sentinel so a test can tell "routed to substrate `drive`" from "routed to a
/// registered runner".
struct KeyedPlane {
    key: &'static str,
}

#[async_trait::async_trait]
impl GauntletPlane for KeyedPlane {
    fn verify_destination(&self, _req: &GauntletRequest<'_>) -> VerifyOutcome {
        VerifyOutcome::Proceed
    }

    async fn drive(self: Box<Self>, _req: GauntletRequest<'_>) -> Response {
        // Reached only when the seam routes to the SUBSTRATE loop (which runs `drive`).
        Response::new(Body::from("SUBSTRATE-DRIVE"))
    }

    fn capability_key(&self) -> Option<&str> {
        Some(self.key)
    }
}

/// A sentinel one-shot runner: proves the seam routed to a REGISTERED runner rather than substrate.
fn sentinel_one_shot<'a>(
    _req: GauntletRequest<'a>,
    _plane: Box<dyn GauntletPlane + 'a>,
) -> Pin<Box<dyn Future<Output = Response> + Send + 'a>> {
    Box::pin(async {
        let mut resp = Response::new(Body::from("ROUTED-TO-REGISTERED-RUNNER"));
        *resp.status_mut() = StatusCode::from_u16(599).unwrap();
        resp
    })
}

/// A sentinel session runner with a distinctive correlation id.
#[allow(clippy::result_large_err)]
fn sentinel_session<'a>(
    _req: GauntletRequest<'a>,
    _plane: Box<dyn GauntletPlane + 'a>,
) -> Result<Admitted, Response> {
    Ok(Admitted {
        correlation_id: 4242,
    })
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
    let body = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body drains");
    (status, headers, body)
}

#[tokio::test]
async fn kernel_rider_matches_substrate_gauntlet_on_proceed() {
    let gov = busbar_api::PlaneRequestCtx::default();

    let substrate = run_gauntlet(req(&gov), FixedPlane::boxed(200, br#"{"ok":true}"#)).await;
    let kernel =
        run_gauntlet_via_kernel(req(&gov), FixedPlane::boxed(200, br#"{"ok":true}"#)).await;

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
    assert_eq!(
        ss, ks,
        "session refusal status diverged kernel-vs-substrate"
    );
    assert_eq!(
        sh, kh,
        "session refusal headers diverged kernel-vs-substrate"
    );
    assert_eq!(sb, kb, "session refusal body diverged kernel-vs-substrate");
}

// ── HOST-SELECTION SEAM (Ruling: composition-tier runner registry) ──────────────────────────────
// Unique test capability keys, so registration is isolated from every real plane (which returns
// None) and from the other tests (which use their own planes) — no global-state cross-talk.

#[tokio::test]
async fn host_selection_seam_unset_key_routes_to_substrate() {
    // A plane whose key has NO runner registered rides the substrate loop (its `drive` runs).
    let gov = busbar_api::PlaneRequestCtx::default();
    let resp = run_gauntlet(
        req(&gov),
        Box::new(KeyedPlane {
            key: "kappa-unregistered-oneshot",
        }),
    )
    .await;
    let (status, _h, body) = split(resp).await;
    assert_eq!(status, StatusCode::OK, "substrate drive's default status");
    assert_eq!(
        body,
        axum::body::Bytes::from_static(b"SUBSTRATE-DRIVE"),
        "an unregistered key must run the plane's substrate drive, byte-identical to today"
    );
}

#[tokio::test]
async fn host_selection_seam_routes_one_shot_to_registered_runner_when_set() {
    register_gauntlet_runner("kappa-test-oneshot", sentinel_one_shot);
    let gov = busbar_api::PlaneRequestCtx::default();
    let resp = run_gauntlet(
        req(&gov),
        Box::new(KeyedPlane {
            key: "kappa-test-oneshot",
        }),
    )
    .await;
    let (status, _h, body) = split(resp).await;
    assert_eq!(
        status.as_u16(),
        599,
        "the registered runner ran, not substrate drive"
    );
    assert_eq!(
        body,
        axum::body::Bytes::from_static(b"ROUTED-TO-REGISTERED-RUNNER")
    );
}

#[test]
fn host_selection_seam_unset_session_key_routes_to_substrate() {
    // No session runner registered for this key → the inline fallback admits (correlation from req),
    // byte-identical to the deleted substrate `admit_open`.
    let gov = busbar_api::PlaneRequestCtx::default();
    let admitted = run_gauntlet_session(
        req(&gov),
        Box::new(KeyedPlane {
            key: "kappa-unregistered-session",
        }),
    )
    .expect("substrate admits on proceed");
    assert_eq!(
        admitted.correlation_id, 0,
        "the inline fallback carries the request's own correlation id (0 here)"
    );
}

// ── W2.a: THE MCP PRODUCTION FLIP ───────────────────────────────────────────────────────────────
// The shipped serving path for MCP `tools/call` now rides the unified kernel loop: the plane declares
// its capability key and the composition root registers the kernel-loop runner under it at boot.

#[cfg(feature = "plane-mcp")]
#[test]
fn install_flips_mcp_onto_the_unified_kernel_loop() {
    // The composition-root install (main.rs calls this at boot) must register a kernel-loop runner
    // under MCP's capability key — the per-plane FLIP. Before W2.a this was empty (dormant), so this
    // asserts the shipped MCP path is genuinely swapped onto the unified loop, not the substrate loop.
    crate::root::gauntlet_install::install();
    assert!(
        busbar_kernel::plane_host::gauntlet_runner_registered(busbar_mcp::PLANE_KEY),
        "install() must register MCP ({}) onto the unified kernel loop — the W2.a flip",
        busbar_mcp::PLANE_KEY,
    );
}

// ── W2.b: THE REMAINING PRODUCTION FLIPS ────────────────────────────────────────────────────────
// Every other plane now rides the unified kernel loop too. Each declares its capability key and the
// composition root registers a kernel-loop runner under it at boot — one-shot for a2a/llm, session
// for voice/streaming. Red-before-green: with the plane's `flip_*_to_kernel(..)` line removed from
// install(), each of these asserts fails (no runner registered); with it present, they pass.

#[cfg(feature = "plane-a2a")]
#[test]
fn install_flips_a2a_onto_the_unified_kernel_loop() {
    crate::root::gauntlet_install::install();
    assert!(
        busbar_kernel::plane_host::gauntlet_runner_registered(busbar_a2a::PLANE_KEY),
        "install() must register A2A ({}) onto the unified kernel loop — the W2.b flip",
        busbar_a2a::PLANE_KEY,
    );
}

#[cfg(feature = "proto-llm")]
#[test]
fn install_flips_llm_onto_the_unified_kernel_loop() {
    crate::root::gauntlet_install::install();
    assert!(
        busbar_kernel::plane_host::gauntlet_runner_registered(busbar_llm::PLANE_KEY),
        "install() must register the LLM native plane ({}) onto the unified kernel loop — the W2.b flip",
        busbar_llm::PLANE_KEY,
    );
}

#[cfg(feature = "plane-voice")]
#[test]
fn install_flips_voice_session_onto_the_unified_kernel_loop() {
    // Voice/streaming is a SESSION plane, so the flip registers a SESSION runner (open-pass admit),
    // asserted through the session read-side twin rather than the one-shot one.
    crate::root::gauntlet_install::install();
    assert!(
        busbar_kernel::plane_host::session_runner_registered(busbar_voice::PLANE_KEY),
        "install() must register the voice session plane ({}) onto the unified kernel loop — the W2.b flip",
        busbar_voice::PLANE_KEY,
    );
}

/// THE ROOT'S PROSE AGREES WITH `install()` (item 238).
///
/// The four tests above prove `install()` registers the kernel-loop runner for every plane in the
/// build. The files that describe that runner used to call it DORMANT and "not the shipped path",
/// and `install()`'s own doc said a key with no runner "fails closed" when `run_gauntlet` runs the
/// inline fallback. An on-call engineer tracing a billing figure reads the prose first, so a
/// contradiction there sends them to the wrong path. Every composition-root source file is read,
/// so a new file cannot reintroduce the claim beside the ones this was written about.
#[test]
fn no_root_prose_calls_the_registered_kernel_runner_dormant() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/root");
    let mut files = Vec::new();
    for dir in [root.clone(), root.join("units_admin")] {
        for entry in std::fs::read_dir(&dir).expect("the composition root is on disk") {
            let path = entry.expect("a directory entry").path();
            if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    assert!(
        files.len() > 10,
        "the scan found the composition root: {files:?}"
    );
    for path in files {
        let text = std::fs::read_to_string(&path).expect("a readable source file");
        for (no, line) in text.lines().enumerate() {
            let lower = line.to_ascii_lowercase();
            assert!(
                !(lower.contains("dormant") && lower.contains("kernel-loop")),
                "{}:{} calls a kernel-loop path `install()` registers at boot dormant: {line}",
                path.display(),
                no + 1
            );
            for stale in [
                "not the shipped path",
                "registers zero planes",
                "rides the substrate loop",
                "now fails closed",
            ] {
                assert!(
                    !lower.contains(stale),
                    "{}:{} contradicts what `install()` registers at boot ({stale:?}): {line}",
                    path.display(),
                    no + 1
                );
            }
        }
    }
}

#[test]
fn host_selection_seam_routes_session_to_registered_runner_when_set() {
    register_session_runner("kappa-test-session", sentinel_session);
    let gov = busbar_api::PlaneRequestCtx::default();
    let admitted = run_gauntlet_session(
        req(&gov),
        Box::new(KeyedPlane {
            key: "kappa-test-session",
        }),
    )
    .expect("the registered session runner admits");
    assert_eq!(
        admitted.correlation_id, 4242,
        "the registered session runner ran, not the inline fallback"
    );
}
