// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-REQUEST WORK-BUDGET GATE (REQUEST-PATH-BUDGET, decision 206).
//!
//! One request in the linked LLM plane's own dialect (its door word `dialect`), buffered and
//! streamed, through the real door path: the linked plane door serving the `pools` map, bound
//! through the loader, composed by the root, its money on the node's book in the native store
//! plugin, and a far end on loopback. Counts the work it does, not how long it takes, and fails
//! when any count is above `perf/work-budget.toml`. An item with no entry there is measured and
//! printed (`WORK-COUNT section=<s> <item>=<n>`), not enforced.
//!
//! Counted: heap allocations (the test build's counting global allocator), plugin crossings (at
//! the loader boundary, `busbar_contract::work_count::Work::Crossing`, so the gate keeps working
//! when MIN-3 replaces the mechanism behind that boundary) and store round trips. A request's
//! count is the lowest of [`RUNS`] identical requests after [`WARM`] warm-up requests, so lazy
//! first-use work, and background work that lands in only some of the runs, do not raise it.
//!
//! The counters are process-wide statics, so a count is this request's work only while no other
//! test shares the process: the gate relies on nextest's process-per-test execution and refuses to
//! run under any other harness (libtest runs tests on threads of one process, whose concurrent
//! work would land in these counts).

use busbar_contract::work_count::Tally;

use super::node_rig::{far_end, node_rig, reply, NodeRig, NodeRigOpts, LANE, POOL};

const BUDGET: &str = include_str!("../../../../../perf/work-budget.toml");

/// Requests answered before counting, to take first-use work out of the measurement.
const WARM: usize = 1;
/// Requests counted; each count is the lowest of these.
const RUNS: usize = 3;

/// The counted items, in the order they are reported, with their names in the budget file.
const ITEMS: [&str; 4] = [
    "allocations",
    "plugin_crossings",
    "store_round_trips",
    "connector_clock_reads",
];

const INPUT: u64 = 11;
const OUTPUT: u64 = 7;

/// The two served ends the gate counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fixture {
    /// The whole loop, delivered, buffered.
    BufferedOk,
    /// The same loop with the accrual landing at stream end rather than at the buffered tap.
    StreamedOk,
}

impl Fixture {
    fn body(self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "model": POOL,
            "messages": [{"role": "user", "content": "hi"}],
        });
        if self == Fixture::StreamedOk {
            v["stream"] = serde_json::Value::Bool(true);
        }
        v
    }

    /// The far end's whole HTTP/1.1 reply.
    fn reply(self) -> String {
        let (content_type, body) = match self {
            Fixture::BufferedOk => (
                "application/json",
                serde_json::json!({
                    "id": "chatcmpl-root", "object": "chat.completion", "created": 0,
                    "model": LANE,
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant", "content": "hello"}}],
                    "usage": {"prompt_tokens": INPUT, "completion_tokens": OUTPUT,
                              "total_tokens": INPUT + OUTPUT}
                })
                .to_string(),
            ),
            Fixture::StreamedOk => (
                "text/event-stream",
                [
                    serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                                       "created": 0, "model": LANE,
                                       "choices": [{"index": 0, "delta": {"role": "assistant",
                                                                          "content": "hello"}}]})
                    .to_string(),
                    serde_json::json!({"id": "chatcmpl-root", "object": "chat.completion.chunk",
                                       "created": 0, "model": LANE,
                                       "choices": [{"index": 0, "delta": {},
                                                    "finish_reason": "stop"}],
                                       "usage": {"prompt_tokens": INPUT,
                                                 "completion_tokens": OUTPUT,
                                                 "total_tokens": INPUT + OUTPUT}})
                    .to_string(),
                    "[DONE]".to_string(),
                ]
                .iter()
                .map(|event| format!("data: {event}\n\n"))
                .collect(),
            ),
        };
        reply(content_type, &body)
    }
}

fn item(work: Tally, name: &str) -> u64 {
    match name {
        "allocations" => work.allocations,
        "plugin_crossings" => work.crossings,
        "store_round_trips" => work.store_round_trips,
        "connector_clock_reads" => work.clock_reads,
        other => unreachable!("not a counted item: {other}"),
    }
}

/// One section of the budget file: `name = number` lines under `[section]`. An item with no line
/// has no budget yet: it is measured and reported, not enforced.
fn budget(section: &str) -> [Option<u64>; ITEMS.len()] {
    let mut current = "";
    let mut out = [None; ITEMS.len()];
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

fn tally_since(before: Tally) -> Tally {
    Tally::now().since(before)
}

/// One request through the door, counted from hand-off until its last body byte is read.
async fn counted(rig: &NodeRig, fixture: Fixture) -> Tally {
    use tower::ServiceExt as _;
    let request = axum::http::Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("authorization", format!("Bearer {}", rig.token))
        .header("content-type", "application/json")
        .body(axum::body::Body::from(fixture.body().to_string()))
        .expect("a request");
    #[cfg(not(target_env = "msvc"))]
    busbar_contract::work_count::count_allocations_through(|| {
        let stats = crate::GLOBAL.stats();
        stats.allocations as u64 + stats.reallocations as u64
    });
    let before = Tally::now();
    let resp = rig
        .router
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = resp.status().as_u16();
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX).await;
    let work = tally_since(before);
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
async fn measure(instance: &'static str, fixture: Fixture) -> Tally {
    // The counters are process-wide: only a process running this one test counts its work alone.
    assert_eq!(
        std::env::var("NEXTEST_EXECUTION_MODE").as_deref(),
        Ok("process-per-test"),
        "the work-budget gate counts process-wide; run it under cargo nextest (one process per \
         test), never a harness that shares the process between tests"
    );
    let rig = node_rig(
        instance,
        far_end(fixture.reply()).await,
        NodeRigOpts {
            fee_cents: 1,
            ..Default::default()
        },
    )
    .await;
    for _ in 0..WARM {
        let _ = counted(&rig, fixture).await;
    }
    let mut low = Tally {
        allocations: u64::MAX,
        crossings: u64::MAX,
        store_round_trips: u64::MAX,
        clock_reads: u64::MAX,
    };
    for _ in 0..RUNS {
        let work = counted(&rig, fixture).await;
        low.allocations = low.allocations.min(work.allocations);
        low.crossings = low.crossings.min(work.crossings);
        low.store_round_trips = low.store_round_trips.min(work.store_round_trips);
        low.clock_reads = low.clock_reads.min(work.clock_reads);
    }
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
    let measured = measure("work-budget-buffered", Fixture::BufferedOk).await;
    gate("buffered", Fixture::BufferedOk, measured);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_streamed_openai_request_stays_within_its_work_budget() {
    let measured = measure("work-budget-streamed", Fixture::StreamedOk).await;
    gate("streamed", Fixture::StreamedOk, measured);
}
