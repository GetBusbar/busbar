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

fn req(gov: &busbar_contract::records::PlaneRequestCtx) -> GauntletRequest<'_> {
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
    let gov = busbar_contract::records::PlaneRequestCtx::default();

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
    let gov = busbar_contract::records::PlaneRequestCtx::default();

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
    let gov = busbar_contract::records::PlaneRequestCtx::default();

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
    let gov = busbar_contract::records::PlaneRequestCtx::default();

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
    let gov = busbar_contract::records::PlaneRequestCtx::default();
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
    let gov = busbar_contract::records::PlaneRequestCtx::default();
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
    let gov = busbar_contract::records::PlaneRequestCtx::default();
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

// ── THE KERNEL-LOOP AXES, READ OFF THE LINKED TABLE ────────────────────────────────────────────
// Which planes ride the unified kernel loop is manifest data: a `[package.metadata.busbar.linked-axes]`
// row carrying `gauntlet-one-shot` or `gauntlet-session` puts the plane's declaration key in
// `LINKED.gauntlet_one_shot` / `LINKED.gauntlet_session`, and `install()` flips every key it finds
// there. These tests ask the registered roster, never a plane by name.

/// The declaration keys this build's linked table puts on either kernel-loop axis.
fn gauntlet_rows() -> std::collections::BTreeSet<&'static str> {
    crate::LINKED
        .gauntlet_one_shot
        .iter()
        .chain(crate::LINKED.gauntlet_session)
        .copied()
        .collect()
}

/// EVERY ROW IS FLIPPED ONTO THE RUNNER ITS AXIS NAMES: `install()` registers the one-shot runner
/// under each `gauntlet-one-shot` row's key and the session runner under each `gauntlet-session`
/// row's, and each such key is a plane this build links.
#[test]
fn install_flips_every_linked_gauntlet_row_onto_the_runner_its_axis_names() {
    crate::root::gauntlet_install::install();
    let linked = linked_planes();
    for key in crate::LINKED.gauntlet_one_shot {
        assert!(
            linked.contains(*key),
            "`{key}` is on the gauntlet-one-shot axis and is no linked plane"
        );
        assert!(
            busbar_kernel::plane_host::gauntlet_runner_registered(key),
            "install() must flip the linked plane `{key}` onto the unified kernel loop's one-shot runner"
        );
    }
    for key in crate::LINKED.gauntlet_session {
        assert!(
            linked.contains(*key),
            "`{key}` is on the gauntlet-session axis and is no linked plane"
        );
        assert!(
            busbar_kernel::plane_host::session_runner_registered(key),
            "install() must flip the linked plane `{key}` onto the unified kernel loop's session runner"
        );
    }
}

/// EVERY FLIP LANDS WHERE ITS PLANE LOOKS: for each kernel-loop row, the key its plane's gauntlet
/// asks the host-selection seam for (`<crate>::PLANE_KEY`) is the declaration key `install()` flips
/// it under. A drift would register a runner nobody asks for, and the plane would run the inline
/// fallback with its flip still "present".
#[test]
fn every_gauntlet_row_is_flipped_under_the_key_its_plane_asks_for() {
    let asks: std::collections::BTreeSet<&str> = crate::LINKED_GAUNTLET_ASKS
        .iter()
        .map(|(declared, _)| *declared)
        .collect();
    assert_eq!(
        asks,
        gauntlet_rows(),
        "the generated ask table covers exactly the kernel-loop rows"
    );
    for (declared, asked) in crate::LINKED_GAUNTLET_ASKS {
        assert_eq!(
            declared, asked,
            "plane `{declared}` is flipped under its declaration key and its gauntlet asks for a \
             runner under `{asked}`"
        );
    }
}

/// EVERY LINKED PLANE THE TELLER LEDGER RUNS RIDES THE KERNEL LOOP. `qa/teller-steps.json` holds a
/// row of Teller steps for each plane the unified loop carries (DECISIONS #28); every such plane this
/// build links must be on a kernel-loop axis and flipped. Drop a row's gauntlet axis from the
/// manifest and that plane is unflipped: this goes red.
#[test]
fn every_linked_plane_the_teller_ledger_runs_rides_the_kernel_loop() {
    crate::root::gauntlet_install::install();
    let steps = ledger("teller-steps.json");
    let rows = gauntlet_rows();
    let linked = linked_planes();
    let owed: Vec<&String> = steps["matrix"]
        .as_object()
        .expect("`matrix` is an object")
        .keys()
        .filter(|plane| linked.contains(*plane))
        .collect();
    for plane in owed {
        assert!(
            rows.contains(plane.as_str()),
            "the linked plane `{plane}` runs the Teller steps and its linked-axes row carries no \
             gauntlet axis: install() never flips it onto the unified kernel loop"
        );
        assert!(
            busbar_kernel::plane_host::gauntlet_runner_registered(plane)
                || busbar_kernel::plane_host::session_runner_registered(plane),
            "the linked plane `{plane}` has no kernel-loop runner registered after install()"
        );
    }
}

/// THE ROOT'S PROSE AGREES WITH `install()` (item 238).
///
/// The tests above prove `install()` registers the kernel-loop runner for every plane the build's
/// linked table puts on a kernel-loop axis. The files that describe that runner used to call it DORMANT and "not the shipped path",
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
    let gov = busbar_contract::records::PlaneRequestCtx::default();
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

// ── THE SERVED LEG, ASKED OF EVERY SERVED PLANE ─────────────────────────────────────────────────
//
// The rider above is the served root leg of every one-shot plane `install()` flips (DECISIONS #28):
// nothing of a plane's capability lives in it — the plane's `drive` carries all of it — so what the
// root owes the ledgers is proof that each capability and each loop step HOLDS WHEN THE PLANE IS
// DRIVEN THROUGH THIS RIDER. Each test below asks exactly that of every served plane the ledgers
// (`qa/capability-equality.json`, `qa/teller-steps.json`) cite it for: it installs the real runners
// (`gauntlet_install::install()`, what boot calls), runs the plane's own served witness for the
// capability — the plane's `testkit::SERVED` table, reached through `$OUT_DIR/served_witness.rs`,
// which `build.rs` generates from the manifest, so this file names no plane — and requires the
// plane's `drive` to have run INSIDE THE KERNEL LOOP exactly as many times as the witness says it
// served a unit. A SESSION plane rides no `drive`: what the session rider carries is the open, so
// for it the count is the opens the loop's door ran. Unflip a plane and its units stop landing here:
// every test citing it goes red.

mod served {
    include!(concat!(env!("OUT_DIR"), "/served_witness.rs"));
}

/// This file, as the ledgers spell a test that lives in it.
const THIS_FILE: &str = "crates/busbar/src/root/tests/gauntlet_kernel.rs";

fn ledger(name: &str) -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../qa")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{} parses: {e}", path.display()))
}

/// The plane keys whose ledger cells name `THIS_FILE::test_fn` as their root-leg proof: a
/// capability-equality column (`<plane>-client` / `<plane>-server`) or a teller-steps matrix row.
fn planes_citing(test_fn: &str) -> std::collections::BTreeSet<String> {
    let cite = format!("{THIS_FILE}::{test_fn}");
    let mut planes = std::collections::BTreeSet::new();
    let equality = ledger("capability-equality.json");
    for cell in equality["cells"].as_array().expect("`cells` is an array") {
        if cell["root"]["test"].as_str() == Some(cite.as_str()) {
            let column = cell["plane"].as_str().expect("a cell names its column");
            let plane = column.split_once('-').map_or(column, |(p, _)| p);
            planes.insert(plane.to_string());
        }
    }
    let steps = ledger("teller-steps.json");
    for (plane, row) in steps["matrix"].as_object().expect("`matrix` is an object") {
        for cell in row.as_object().expect("a matrix row is an object").values() {
            if cell["root"]["test"].as_str() == Some(cite.as_str()) {
                planes.insert(plane.clone());
            }
        }
    }
    planes
}

/// The plane keys this build links, off the linked table boot registers from.
fn linked_planes() -> std::collections::BTreeSet<String> {
    crate::LINKED
        .planes
        .iter()
        .map(|decl| decl.declaration.key.to_string())
        .collect()
}

/// Every unit THIS thread's kernel-loop rider has carried: a one-shot plane's `drive` run inside the
/// loop, and a session plane's open run through the loop's door.
fn carried_in_loop() -> u64 {
    crate::root::gauntlet_kernel::DRIVES_IN_LOOP.with(std::cell::Cell::get)
        + crate::root::gauntlet_kernel::OPENS_IN_LOOP.with(std::cell::Cell::get)
}

/// Run `witness` — a loop step or a core capability — through the served rider for every linked
/// plane whose served-witness table carries it, and require each plane's `drive` to have run inside
/// the kernel loop exactly as many times as its witness served a unit. Every linked plane a ledger
/// cell cites `test_fn` for must be among the planes that answered.
async fn run_served(witness: &str, test_fn: &str) {
    crate::root::gauntlet_install::install();
    let linked = linked_planes();
    let mut answered = std::collections::BTreeSet::new();
    for (plane, table) in served::SERVED_WITNESSES
        .iter()
        .filter(|(key, _)| linked.contains(*key))
    {
        let Some((_, run)) = table.iter().find(|(id, _)| *id == witness) else {
            continue;
        };
        let before = carried_in_loop();
        let served = run().await;
        let driven = carried_in_loop() - before;
        assert!(
            served >= 1,
            "plane `{plane}`'s `{witness}` witness served no unit at all"
        );
        assert_eq!(
            driven, served,
            "plane `{plane}`'s `{witness}` witness served {served} unit(s), and the kernel-loop rider \
             carried {driven} of them into the plane's `drive` or through its session door: the \
             capability did not hold on the served root leg"
        );
        answered.insert(plane.to_string());
    }
    // What this build owes is what the ledgers cite `test_fn` for AMONG THE PLANES IT LINKS. A
    // "some served plane carries the witness" floor is a claim about every plane at once: a build
    // linking one served plane would be asked for a witness only an unlinked plane carries. The
    // floor that keeps the test from passing over nothing is the ledgers' own citation, which does
    // not move with the feature set.
    let cited = planes_citing(test_fn);
    assert!(
        !cited.is_empty(),
        "no ledger cell cites {THIS_FILE}::{test_fn} as any plane's served-leg proof, so the \
         `{witness}` witness is owed by nobody and this test proves nothing"
    );
    let owed: Vec<String> = cited
        .into_iter()
        .filter(|p| linked.contains(p) && !answered.contains(p))
        .collect();
    assert!(
        owed.is_empty(),
        "the ledgers cite {THIS_FILE}::{test_fn} as the served-leg proof for {owed:?}, and no \
         `{witness}` witness of theirs ran through the rider"
    );
}

/// ARRIVAL, on the served leg: one call is one unit the rider carries.
#[tokio::test]
async fn served_rider_carries_one_unit_per_call() {
    run_served("arrival", "served_rider_carries_one_unit_per_call").await;
}

/// DECODE, on the served leg: a body that is not an envelope is refused by its decode.
#[tokio::test]
async fn served_rider_refuses_a_body_that_does_not_decode() {
    run_served("decode", "served_rider_refuses_a_body_that_does_not_decode").await;
}

/// AUTHENTICATE, on the served leg: only an authenticated caller becomes a unit.
#[tokio::test]
async fn served_rider_is_reached_only_by_an_authenticated_caller() {
    run_served(
        "authenticate",
        "served_rider_is_reached_only_by_an_authenticated_caller",
    )
    .await;
}

/// VERIFY, on the served leg: a destination the unit may not reach is refused before any dial.
#[tokio::test]
async fn served_rider_refuses_a_destination_before_it_dials() {
    run_served(
        "verify",
        "served_rider_refuses_a_destination_before_it_dials",
    )
    .await;
}

/// APPROVE, on the served leg: a grant short of the operation's scope is refused.
#[tokio::test]
async fn served_rider_refuses_a_grant_short_of_the_operation() {
    run_served(
        "approve",
        "served_rider_refuses_a_grant_short_of_the_operation",
    )
    .await;
}

/// ADMIT, on the served leg: a caller over its budget is refused before the dial.
#[tokio::test]
async fn served_rider_refuses_an_over_budget_caller_before_it_dials() {
    run_served(
        "admit",
        "served_rider_refuses_an_over_budget_caller_before_it_dials",
    )
    .await;
}

/// ROUTE, on the served leg: a failed upstream is answered inside the unit.
#[tokio::test]
async fn served_rider_answers_a_failed_upstream_inside_the_unit() {
    run_served(
        "route",
        "served_rider_answers_a_failed_upstream_inside_the_unit",
    )
    .await;
}

/// METER, on the served leg: one call meters exactly one request.
#[tokio::test]
async fn served_rider_meters_exactly_one_request_per_call() {
    run_served("meter", "served_rider_meters_exactly_one_request_per_call").await;
}

/// AUDIT, on the served leg: one call is audited exactly once.
#[tokio::test]
async fn served_rider_audits_each_call_once() {
    run_served("audit", "served_rider_audits_each_call_once").await;
}

/// EXIT, on the served leg: one call ends once.
#[tokio::test]
async fn served_rider_ends_each_call_once() {
    run_served("exit", "served_rider_ends_each_call_once").await;
}

/// AUDIT-CHAIN, on the served leg: the call's record is linked into its tamper-evident chain.
#[tokio::test]
async fn served_rider_chains_what_it_audits() {
    run_served("audit-chain", "served_rider_chains_what_it_audits").await;
}

/// GOVERNANCE-BUDGET, on the served leg: the spend is the presenting key's.
#[tokio::test]
async fn served_rider_charges_the_presenting_key() {
    run_served(
        "governance-budget",
        "served_rider_charges_the_presenting_key",
    )
    .await;
}

/// DISPOSITION, on the served leg: an upstream answer is classified, not mistaken for a trip.
#[tokio::test]
async fn served_rider_classifies_the_upstream_answer() {
    run_served("disposition", "served_rider_classifies_the_upstream_answer").await;
}

/// METRICS, on the served leg: the upstream leg is on the scrape.
#[tokio::test]
async fn served_rider_counts_the_upstream_attempt() {
    run_served("metrics", "served_rider_counts_the_upstream_attempt").await;
}

/// TRUST-PINNING, on the served leg: a drifted or demoted peer is not served.
#[tokio::test]
async fn served_rider_refuses_an_unpinned_peer() {
    run_served("trust-pinning", "served_rider_refuses_an_unpinned_peer").await;
}

/// NET-GUARD, on the served leg: the dialled address is the one the guard judged.
#[tokio::test]
async fn served_rider_dials_only_the_judged_address() {
    run_served("net-guard", "served_rider_dials_only_the_judged_address").await;
}

/// EGRESS-AUTH, on the served leg: the upstream is handed the planned credential only.
#[tokio::test]
async fn served_rider_presents_only_the_planned_credential() {
    run_served(
        "egress-auth",
        "served_rider_presents_only_the_planned_credential",
    )
    .await;
}

/// VERIFY, on a session's served leg: the destination the door judged is the one the session runs
/// under.
#[tokio::test]
async fn served_rider_opens_the_session_on_the_destination_it_judged() {
    run_served(
        "session-verify",
        "served_rider_opens_the_session_on_the_destination_it_judged",
    )
    .await;
}

/// ROUTE, on a session's served leg: the session the door opened relays both directions.
#[tokio::test]
async fn served_rider_opens_a_session_that_relays_both_ways() {
    run_served(
        "session-route",
        "served_rider_opens_a_session_that_relays_both_ways",
    )
    .await;
}

/// AUTHENTICATE, on a session's served leg: the session answers for the key the door resolved.
#[tokio::test]
async fn served_rider_attributes_the_session_to_the_resolved_key() {
    run_served(
        "session-authenticate",
        "served_rider_attributes_the_session_to_the_resolved_key",
    )
    .await;
}

/// METER, on a session's served leg: each turn is ledgered per class the plane declares.
#[tokio::test]
async fn served_rider_meters_each_turn_per_declared_class() {
    run_served(
        "session-meter",
        "served_rider_meters_each_turn_per_declared_class",
    )
    .await;
}

/// METRICS, on a session's served leg: each session the door opens is reported under its labels.
#[tokio::test]
async fn served_rider_reports_each_session_it_opens() {
    run_served(
        "session-metrics",
        "served_rider_reports_each_session_it_opens",
    )
    .await;
}

/// BREAKER-FASTFAIL, on the served leg: a tripped upstream cell refuses before any socket opens.
#[tokio::test]
async fn served_rider_fast_fails_a_tripped_upstream() {
    run_served(
        "breaker-fastfail",
        "served_rider_fast_fails_a_tripped_upstream",
    )
    .await;
}

/// CATALOGUE, on the served leg: what the caller may not see is not served.
#[tokio::test]
async fn served_rider_serves_only_the_callers_catalogue() {
    run_served(
        "catalogue",
        "served_rider_serves_only_the_callers_catalogue",
    )
    .await;
}
