// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODEL LISTING, SERVED END TO END (ARCHITECT RULING D, 2026-10-07; spec Part 2 #49, THE
//! DESIGN §5 l.958-960, l.410): `GET /v1/models` and `GET /v1beta/models` stay the kernel's own
//! routes behind its key gate; the kernel computes the caller's visible names and the llm door's
//! `serve` renders them in the caller's dialect, through the data listener's lines as production
//! hands them over. Each cell drives the real data router built with the llm door (the rig of
//! `serve_hook_seats.rs`) and is pinned to the bytes the kernel answered before the listing moved
//! to the plane (`fixtures/list_models_1_5_5.cells`: status, content type and body, every
//! fingerprint variant, under each grant). A listing is no unit: the node's audit records, its
//! journal, the key's ledger and the request families stay as they were.

use super::hook_seat_tests::{rig, DoorRig, RigOpts};
use super::planes_tests::{Published, PUBLISHING};

/// The kernel's answers before the move (busbar 091fee8b82 `list_models_dialect`, the 1.5.5 bytes).
const CELLS: &str = include_str!("fixtures/list_models_1_5_5.cells");

/// One recorded answer.
struct Cell {
    path: String,
    head: Vec<(String, String)>,
    key: String,
    status: u16,
    content_type: String,
    body: String,
}

fn cells() -> Vec<Cell> {
    CELLS
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let cols: Vec<&str> = l.splitn(6, " | ").collect();
            assert_eq!(cols.len(), 6, "a cell has six columns: {l}");
            let head = if cols[1] == "-" {
                Vec::new()
            } else {
                cols[1]
                    .split(',')
                    .map(|f| {
                        let (n, v) = f.split_once('=').expect("name=value");
                        (n.to_string(), v.to_string())
                    })
                    .collect()
            };
            Cell {
                path: cols[0].to_string(),
                head,
                key: cols[2].to_string(),
                status: cols[3].parse().expect("a status"),
                content_type: cols[4].to_string(),
                body: cols[5].to_string(),
            }
        })
        .collect()
}

/// The recorded topology on the llm door: lanes `model-a0`, `model-a1`, `model-b`; `pool-a` over the
/// first two, `pool-b` over the third; the caller's grant as the cell's key names it (`nokey`: the
/// data front door is open and the caller presents nothing). No far end is ever reached.
async fn listing_rig(instance: &'static str, key: &str) -> DoorRig {
    rig(
        instance,
        RigOpts {
            members: &[(9, 1), (9, 1), (9, 1)],
            names: Some(&["model-a0", "model-a1", "model-b"]),
            pooled: Some(2),
            main_pool: Some("pool-a"),
            pools: &[("pool-b", &[2], "")],
            allowed_pools: match key {
                "pool-a" => Some(&["pool-a"]),
                "empty" => Some(&[]),
                _ => None,
            },
            open: key == "nokey",
            hookless: true,
            ..RigOpts::default()
        },
    )
    .await
}

/// One listing GET as the cell's caller: the rig's key presented where the cell's dialect SDK
/// presents it (a gemini caller in its own key field, any other as a bearer), none for `nokey`.
async fn list(rig: &DoorRig, cell: &Cell) -> (u16, axum::http::HeaderMap, Vec<u8>) {
    use tower::ServiceExt as _;
    let mut req = axum::http::Request::builder().method("GET").uri(&cell.path);
    let gemini_key = cell.head.iter().any(|(n, _)| n == "x-goog-api-key");
    for (name, value) in &cell.head {
        match name.as_str() {
            // The caller's own credential field carries the rig's key.
            "x-goog-api-key" if cell.key != "nokey" => {
                req = req.header(name.as_str(), rig.token.as_str());
            }
            "authorization" if cell.key != "nokey" => {}
            _ => req = req.header(name.as_str(), value.as_str()),
        }
    }
    if cell.key != "nokey" && !gemini_key {
        req = req.header("authorization", format!("Bearer {}", rig.token));
    }
    let response = rig
        .router
        .clone()
        .oneshot(req.body(axum::body::Body::empty()).expect("a request"))
        .await
        .expect("the router answers");
    let status = response.status().as_u16();
    let head = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body")
        .to_vec();
    (status, head, body)
}

/// Every recorded cell under one grant, answered through the real data router and the llm door,
/// byte for byte.
async fn cells_hold_under(instance: &'static str, key: &str) {
    let _one = PUBLISHING.lock().await;
    let _published = Published(instance);
    let rig = listing_rig(instance, key).await;
    let mut checked = 0;
    for cell in cells().iter().filter(|c| c.key == key) {
        // An unkeyed caller presenting a bearer the deployment never minted is the auth gate's
        // question, not the listing's: the kernel-level cell answered it with no gate at all.
        if key == "nokey" && cell.head.iter().any(|(n, _)| n == "authorization") {
            continue;
        }
        let (status, head, body) = list(&rig, cell).await;
        let what = format!("{} {:?} key={}", cell.path, cell.head, cell.key);
        assert_eq!(status, cell.status, "status: {what}");
        assert_eq!(
            head.get("content-type").and_then(|v| v.to_str().ok()),
            Some(cell.content_type.as_str()),
            "content type: {what}"
        );
        assert_eq!(String::from_utf8_lossy(&body), cell.body, "body: {what}");
        checked += 1;
    }
    assert!(checked >= 10, "every cell under {key} ran ({checked})");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listing_answers_the_recorded_bytes_to_an_unrestricted_key() {
    cells_hold_under("serve-listing-open", "open").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listing_answers_the_recorded_bytes_to_a_key_restricted_to_one_pool() {
    cells_hold_under("serve-listing-pool-a", "pool-a").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listing_answers_the_recorded_bytes_to_a_key_with_no_scopes() {
    cells_hold_under("serve-listing-empty", "empty").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_listing_answers_the_recorded_bytes_through_an_open_front_door() {
    cells_hold_under("serve-listing-nokey", "nokey").await;
}

/// `busbar_requests_total` and `busbar_request_duration_seconds` samples, summed over the series
/// naming any of the listed names or the unresolved label a unit with no route would carry. The
/// request log is emitted only beside these families (`telemetry::model_request_finished`).
fn request_families(scrape: &str) -> (f64, f64) {
    let ours = |l: &str| {
        [
            "pool-a",
            "pool-b",
            "model-a0",
            "model-a1",
            "model-b",
            "unresolved",
        ]
        .iter()
        .any(|p| l.contains(&format!("pool=\"{p}\"")))
    };
    let sum = |prefix: &str| -> f64 {
        scrape
            .lines()
            .filter(|l| l.starts_with(prefix) && ours(l))
            .filter_map(|l| l.rsplit(' ').next()?.trim().parse::<f64>().ok())
            .sum()
    };
    (
        sum("busbar_requests_total{"),
        sum("busbar_request_duration_seconds_count{"),
    )
}

/// A LISTING IS NO UNIT (ARCHITECT RULING D): no audit record is sealed, nothing is journaled, the
/// key's ledger and its admission counts do not move, and no request family is counted, whichever
/// path and dialect it is answered in.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listing_leaves_the_audit_the_journal_the_ledger_and_the_metrics_as_they_were() {
    let _one = PUBLISHING.lock().await;
    let instance = "serve-listing-no-unit";
    let _published = Published(instance);
    let rig = listing_rig(instance, "open").await;
    let journal = |rig: &DoorRig| {
        let book = rig
            .book
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (book.journal.next_seq(), book.journal.head())
    };
    let (audit, journaled, ledger) = (
        rig.audit_records(),
        journal(&rig),
        rig.ledger_after(0).await,
    );
    let ring = || {
        busbar_kernel::audit_ring::AUDIT
            .export()
            .iter()
            .filter(|e| format!("{e:?}").contains("models"))
            .count()
    };
    let rows = ring();
    let families = request_families(&busbar_kernel::metrics::render());
    let mut answered = 0;
    for cell in cells().iter().filter(|c| c.key == "open") {
        let (status, _, _) = list(&rig, cell).await;
        assert_eq!(status, 200);
        answered += 1;
    }
    assert!(answered >= 10);
    // A unit would seal its record at its end, after its caller's last byte: wait as the door
    // tests wait for one, then read.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(rig.audit_records(), audit, "no audit record is sealed");
    assert_eq!(journal(&rig), journaled, "nothing is journaled");
    assert_eq!(
        rig.ledger_after(0).await,
        ledger,
        "the key's ledger is unmoved"
    );
    assert_eq!(ring(), rows, "the kernel's audit log holds no row for it");
    assert_eq!(
        request_families(&busbar_kernel::metrics::render()),
        families,
        "no request family is counted"
    );
}
