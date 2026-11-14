// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-REQUEST WORK-BUDGET GATE (REQUEST-PATH-BUDGET, decision 206).
//!
//! One openai -> openai request, buffered and streamed, through the real node path: the linked
//! LLM plane, the native store plugin behind the loader, and a fake upstream. Counts the work it
//! does, not how long it takes, and fails when any count is above `perf/work-budget.toml`.
//!
//! Counted: heap allocations (the test build's counting global allocator), plugin crossings (at
//! the loader boundary, `busbar_contract::work_count::Work::Crossing`, so the gate keeps working
//! when MIN-3 replaces the mechanism behind that boundary) and store round trips. A request's
//! count is the lowest of [`RUNS`] identical requests after [`WARM`] warm-up requests, so lazy
//! first-use work and stray background work cannot raise it.

use busbar_contract::work_count::Tally;

use super::*;

const BUDGET: &str = include_str!("../../../../../perf/work-budget.toml");

/// Requests answered before counting, to take first-use work out of the measurement.
const WARM: usize = 1;
/// Requests counted; each count is the lowest of these.
const RUNS: usize = 3;

/// One section of the budget file: `name = number` lines under `[section]`.
fn budget(section: &str) -> Tally {
    let mut current = "";
    let mut out = Tally::default();
    let mut seen = 0;
    for line in BUDGET.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            current = name.trim();
            continue;
        }
        if current != section {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("perf/work-budget.toml: `{line}` is not `name = number`"));
        let value: u64 = value
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("perf/work-budget.toml: `{line}` is not a whole number"));
        match key.trim() {
            "allocations" => out.allocations = value,
            "plugin_crossings" => out.crossings = value,
            "store_round_trips" => out.store_round_trips = value,
            other => panic!("perf/work-budget.toml: unknown count `{other}` in [{section}]"),
        }
        seen += 1;
    }
    assert_eq!(
        seen, 3,
        "perf/work-budget.toml: [{section}] must name allocations, plugin_crossings and store_round_trips"
    );
    out
}

/// One request through the node, counted from hand-off until its last body byte is read.
async fn counted(rig: &Rig, node: &Node, fixture: Fixture) -> Tally {
    let arrival = plane::WalkArrival {
        host: rig.host(),
        gov: rig.gov(),
        proto: PROTO,
        operation: busbar_contract::operation::OpVerb::CHAT,
        caller_token: None,
        headers: json_headers(),
        query: None,
        body: fixture.body(),
        path: None,
    };
    let before = Tally::now();
    let resp = node.answer(plane::handed(arrival, None)).await;
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    let work = Tally::now().since(before);
    let body = body.expect("the answer's body reads to its end");
    assert_eq!(
        status,
        200,
        "{fixture:?} must be served to count its work: {}",
        String::from_utf8_lossy(&body)
    );
    work
}

/// Lowest count of each kind over [`RUNS`] requests, after [`WARM`] warm-up requests.
async fn measure(fixture: Fixture) -> Tally {
    let rig = rig(fixture).await;
    let node = Node::new();
    for _ in 0..WARM {
        let _ = counted(&rig, &node, fixture).await;
    }
    let mut low = Tally {
        allocations: u64::MAX,
        crossings: u64::MAX,
        store_round_trips: u64::MAX,
    };
    for _ in 0..RUNS {
        let work = counted(&rig, &node, fixture).await;
        low.allocations = low.allocations.min(work.allocations);
        low.crossings = low.crossings.min(work.crossings);
        low.store_round_trips = low.store_round_trips.min(work.store_round_trips);
    }
    rig.server.shutdown().await;
    low
}

fn gate(section: &str, fixture: Fixture, measured: Tally) {
    let budget = budget(section);
    let rows = [
        ("allocations", measured.allocations, budget.allocations),
        ("plugin_crossings", measured.crossings, budget.crossings),
        (
            "store_round_trips",
            measured.store_round_trips,
            budget.store_round_trips,
        ),
    ];
    let report = rows
        .iter()
        .map(|(name, got, max)| format!("  {name} = {got} (budget {max})"))
        .collect::<Vec<_>>()
        .join("\n");
    println!("work-budget [{section}] {fixture:?}:\n{report}");
    let over: Vec<&str> = rows
        .iter()
        .filter(|(_, got, max)| got > max)
        .map(|(name, _, _)| *name)
        .collect();
    assert!(
        over.is_empty(),
        "[{section}] per-request work went UP in {over:?}; remove the work, never raise \
         perf/work-budget.toml:\n{report}"
    );
    let under: Vec<&str> = rows
        .iter()
        .filter(|(_, got, max)| got < max)
        .map(|(name, _, _)| *name)
        .collect();
    if !under.is_empty() {
        println!(
            "work-budget [{section}]: {under:?} fell below budget; lower perf/work-budget.toml to the \
             measured numbers in this change (budgets only ratchet down)"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_openai_request_stays_within_its_work_budget() {
    let measured = measure(Fixture::BufferedOk).await;
    gate("buffered", Fixture::BufferedOk, measured);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_openai_request_stays_within_its_work_budget() {
    let measured = measure(Fixture::StreamedOk).await;
    gate("streamed", Fixture::StreamedOk, measured);
}
