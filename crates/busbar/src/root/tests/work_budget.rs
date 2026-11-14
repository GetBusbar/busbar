// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-REQUEST WORK-BUDGET GATE (REQUEST-PATH-BUDGET, decision 206).
//!
//! One openai -> openai request, buffered and streamed, through the real node path: the linked
//! LLM plane, the native store plugin behind the loader, and a fake upstream. Counts the work it
//! does, not how long it takes, and fails when any count is above `perf/work-budget.toml`. An item
//! with no entry there is measured and printed (`WORK-COUNT section=<s> <item>=<n>`), not enforced.
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

/// The counted items, in the order they are reported, with their names in the budget file.
const ITEMS: [&str; 3] = ["allocations", "plugin_crossings", "store_round_trips"];

fn item(work: Tally, name: &str) -> u64 {
    match name {
        "allocations" => work.allocations,
        "plugin_crossings" => work.crossings,
        "store_round_trips" => work.store_round_trips,
        other => unreachable!("not a counted item: {other}"),
    }
}

/// One section of the budget file: `name = number` lines under `[section]`. An item with no line
/// has no budget yet: it is measured and reported, not enforced.
fn budget(section: &str) -> [Option<u64>; 3] {
    let mut current = "";
    let mut out = [None; 3];
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
        let at = ITEMS
            .iter()
            .position(|name| *name == key.trim())
            .unwrap_or_else(|| {
                panic!("perf/work-budget.toml: unknown count `{key}` in [{section}]")
            });
        assert!(
            out[at].replace(value).is_none(),
            "perf/work-budget.toml: `{key}` named twice in [{section}]"
        );
    }
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
    let mut over = Vec::new();
    for (name, max) in ITEMS.iter().zip(budget) {
        let got = item(measured, name);
        // Fixed, greppable: one line per item, read to write the first budget.
        println!("WORK-COUNT section={section} {name}={got}");
        match max {
            None => println!(
                "work-budget [{section}] {fixture:?}: {name} has no budget yet; measured, not \
                 enforced (add `{name} = {got}` to perf/work-budget.toml)"
            ),
            Some(max) if got > max => over.push(format!("{name} = {got} (budget {max})")),
            Some(max) if got < max => println!(
                "work-budget [{section}] {fixture:?}: {name} = {got} fell below its budget {max}; \
                 lower perf/work-budget.toml to it in this change (budgets only ratchet down)"
            ),
            Some(_) => {}
        }
    }
    assert!(
        over.is_empty(),
        "[{section}] {fixture:?}: per-request work went UP; remove the work, never raise \
         perf/work-budget.toml: {over:?}"
    );
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
