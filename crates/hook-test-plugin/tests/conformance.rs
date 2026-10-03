// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S CONFORMANCE (TODO ABI-b4, M6/contract): the shipped compiled-in build and the
//! dropped-in build of ONE real hook plugin, driven through the same table.
//!
//! The subject is this crate. Its door is reached two ways, each as a row of the hook axis
//! ([`HookRows`]) on a dispatcher of its own, the way the composition root reaches a hook:
//!
//! * COMPILED IN — [`busbar_hook_test_plugin::door`] linked into this test binary;
//! * DROPPED IN — this crate's own `cdylib`, its bytes admitted against the Statement the linked
//!   door renders (what a signed manifest carries).
//!
//! One fixed request set runs through [`HookCalls`] on each: a pass (`decide` ranking, `decide`
//! abstaining), a rewrite (`transform`), a deny (`decide` and `transform` over the screen token)
//! and a timeout (a gate slower than its budget). The transcript carries everything the host reads
//! off each answer — outcome, verbs, status, order, message, rewrite body — and then the plugin's
//! OWN count of the crossings it served, read back over `status`. The two transcripts must be
//! equal, line for line, and the counts are asserted EXACTLY (not "above 0"): a build that dropped
//! or doubled a crossing fails here. Run it against the shipped profile: `cargo nextest run
//! --release -p busbar-hook-test-plugin`, with `BUSBAR_EXPECT_RELEASE=1` to have the suite itself
//! refuse a debug build.
//!
//! RED ARM, KEPT: [`a_door_that_ranks_the_other_way_answers_differently`] runs the same script
//! over the same plugin with its orders reversed; the transcript differs at the order lines, so a
//! build that ranked differently cannot pass for this one.
//!
//! A missing dropped-in image is a failure, never a skip: this test IS the dropped-in door's proof.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::hook::{DecideOut, TransformOut};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::door::DoorFn;
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::hook::{Decoded, Hook as HookImpl, HookOpen, Verdict};
use busbar_contract::hook_calls::{Answered, HookAxis, HookCalls};
use busbar_contract::hooks::{Candidate, PromptProjection, RoutingContext, RoutingRequest};
use busbar_hook_test_plugin::{NAME, STATEMENT};
use busbar_plugin_loader::boot::{Candidate as Row, Origin};
use busbar_plugin_loader::dispatch::{rendering_of, DispatchConfig, Dispatcher};
use busbar_plugin_loader::hook_door::HookRows;
use serde_json::json;
use std::task::Poll;

/// The gate's settings: rank `[1, 0]` (with an index the host must drop), screen `BLOCKME` with a
/// 429 on `decide`.
fn settings() -> serde_json::Value {
    json!({"order": [9, 1, 0], "reject_if_contains": "BLOCKME", "reject_status": 429})
}

/// Every call's budget, but the timeout's.
const BUDGET: Duration = Duration::from_secs(5);

fn request(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "acme",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
        signals: Default::default(),
    }
}

fn candidate(idx: usize) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "prov",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: None,
        tags: &[],
        latency_ms: None,
        available_concurrency: 1,
        budget_remaining: None,
        rate_headroom: None,
        signals: Default::default(),
    }
}

/// The `decide` frame of `text` over two candidates.
fn decide_frame(text: &str) -> Arc<DecideFrame> {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    DecideFrame::first(DecideView::build(
        &request(text),
        &[candidate(0), candidate(1)],
        &ctx,
    ))
}

/// The `transform` frame of `text`: the prompt, no candidates.
fn transform_frame(text: &str) -> Arc<DecideFrame> {
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    DecideFrame::first(DecideView::build(&request(text), &[], &ctx))
}

/// This crate's `cdylib` in the test's target dir, newest wins: uplifted, or under `deps` with its
/// metadata hash. A missing one is a failure.
fn image() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary has a path");
    let profile = exe
        .parent()
        .and_then(|d| d.parent())
        .expect("target/<profile>");
    let name = busbar_plugin_loader::plugin_library_filename("busbar_hook_test_plugin");
    let (prefix, suffix) = name
        .split_once("busbar_hook_test_plugin")
        .expect("the library name carries the crate's");
    let in_deps = std::fs::read_dir(profile.join("deps"))
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .and_then(|f| f.strip_prefix(prefix))
                .and_then(|f| f.strip_suffix(suffix))
                .and_then(|f| f.strip_prefix("busbar_hook_test_plugin"))
                .is_some_and(|stem| {
                    stem.is_empty()
                        || stem.strip_prefix('-').is_some_and(|h| {
                            !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
        });
    std::iter::once(profile.join(&name))
        .chain(in_deps)
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
        .unwrap_or_else(|| panic!("the plugin's cdylib ({name}) is not built under {profile:?}"))
}

/// How a row reaches the axis.
#[derive(Clone, Copy)]
enum Way {
    Linked,
    Dropped,
}

/// The axis over `door`, its one row reached `way`, on a dispatcher of its own.
fn rows(door: DoorFn, way: Way) -> HookRows {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    match way {
        Way::Linked => HookRows::new(&[door], None, dispatcher).expect("the linked row"),
        Way::Dropped => {
            let bytes = std::fs::read(image()).expect("the cdylib reads");
            let row = Row::from_rendering(
                rendering_of(door).expect("the door renders its Statement"),
                None,
                Origin::Dropped {
                    file: "busbar-hook-test-plugin.tar.gz".to_string(),
                    bytes: Arc::new(bytes),
                },
            )
            .expect("the rendering states a candidate");
            HookRows::of(vec![row], dispatcher)
        }
    }
}

fn decided(step: &str, a: &Answered<DecideOut>) -> String {
    match a {
        Answered::Answer {
            outcome,
            out,
            error,
            frame,
        } => format!(
            "{step}: {outcome:?} verbs={:#x} status={} order={:?} message={:?} error={error:?}",
            out.verbs,
            out.reject_status,
            frame.order(out.order_written),
            frame.reject_message(out.reject_message_written),
        ),
        Answered::TimedOut => format!("{step}: timed out"),
        Answered::Broken(why) => format!("{step}: broken ({why})"),
    }
}

fn transformed(step: &str, a: &Answered<TransformOut>) -> String {
    match a {
        Answered::Answer {
            outcome,
            out,
            error,
            frame,
        } => format!(
            "{step}: {outcome:?} verbs={:#x} status={} message={:?} rewrite={} error={error:?}",
            out.verbs,
            out.reject_status,
            frame.reject_message(out.reject_message_written),
            String::from_utf8_lossy(&frame.rewrite(out.rewrite_written)),
        ),
        Answered::TimedOut => format!("{step}: timed out"),
        Answered::Broken(why) => format!("{step}: broken ({why})"),
    }
}

/// The plugin's own count of `name`, read back over `status`.
async fn count(calls: &dyn HookCalls, name: &str) -> u64 {
    let bytes = calls
        .status(BUDGET)
        .await
        .expect("the plugin answers status");
    let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("status is JSON");
    doc["status"]["metrics"]
        .as_array()
        .and_then(|m| m.iter().find(|m| m["name"] == name))
        .and_then(|m| m["value"].as_f64())
        .unwrap_or_else(|| panic!("status carries no metric {name}: {doc}")) as u64
}

/// The exact crossings the script makes on the gate: three `decide`s.
const GATE_DECIDES: u64 = 3;
/// And on the abstaining instance: one.
const ABSTAIN_DECIDES: u64 = 1;

/// THE SCRIPT over `rows`, one line per answer. The counts it reads are asserted by the caller.
async fn script(rows: &HookRows, module: &str) -> (Vec<String>, Vec<u64>) {
    let mut lines = Vec::new();
    let mut counts = Vec::new();

    // PASS, DENY, REWRITE: the gate that ranks, screens and rewrites.
    let gate = rows
        .open(module, "hooks.gate", &settings(), BUDGET)
        .expect("the gate opens");
    lines.push(format!("name: {}", gate.name()));
    lines.push(decided(
        "pass: rank",
        &gate.decide(decide_frame("hello"), BUDGET).await,
    ));
    lines.push(decided(
        "deny: decide",
        &gate.decide(decide_frame("please BLOCKME"), BUDGET).await,
    ));
    lines.push(transformed(
        "rewrite",
        &gate.transform(transform_frame("hello"), BUDGET).await,
    ));
    lines.push(transformed(
        "deny: transform",
        &gate.transform(transform_frame("BLOCKME"), BUDGET).await,
    ));
    lines.push(decided(
        "pass: rank again",
        &gate.decide(decide_frame("hello"), BUDGET).await,
    ));
    counts.push(count(gate.as_ref(), "test_decides_total").await);

    // PASS: the gate with nothing to say abstains.
    let quiet = rows
        .open(module, "hooks.quiet", &json!({}), BUDGET)
        .expect("the quiet gate opens");
    lines.push(decided(
        "pass: abstain",
        &quiet.decide(decide_frame("hello"), BUDGET).await,
    ));
    counts.push(count(quiet.as_ref(), "test_decides_total").await);

    // TIMEOUT: a gate slower than its budget is cut off at the budget, not waited out.
    let slow = rows
        .open(
            module,
            "hooks.slow",
            &json!({"order": [0], "sleep_ms": 2000}),
            BUDGET,
        )
        .expect("the slow gate opens");
    let started = Instant::now();
    lines.push(decided(
        "timeout: decide",
        &slow
            .decide(decide_frame("x"), Duration::from_millis(100))
            .await,
    ));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the deadline cuts the call off promptly, not after the sleep"
    );
    (lines, counts)
}

/// The suite asked to run against the shipped profile refuses a debug build.
#[test]
fn the_suite_runs_in_the_profile_it_was_asked_to() {
    if std::env::var_os("BUSBAR_EXPECT_RELEASE").is_some() {
        assert!(
            !cfg!(debug_assertions),
            "BUSBAR_EXPECT_RELEASE is set: run this suite with `--release`"
        );
    }
}

#[tokio::test]
async fn the_compiled_in_and_the_dropped_in_hook_answer_the_same_request_set_identically() {
    let door = busbar_hook_test_plugin::door;
    let (linked, linked_counts) = script(&rows(door, Way::Linked), NAME).await;
    let (dropped, dropped_counts) = script(&rows(door, Way::Dropped), NAME).await;
    assert_eq!(linked, dropped, "the same table, whichever build");

    // EXACT crossing counts, both builds: the plugin served each `decide` once and no more.
    assert_eq!(linked_counts, [GATE_DECIDES, ABSTAIN_DECIDES]);
    assert_eq!(dropped_counts, [GATE_DECIDES, ABSTAIN_DECIDES]);

    // The script reached every answer it names: equal transcripts of failures would prove nothing.
    // The unknown index 9 is the host's to drop, so the plugin's own order still carries it.
    assert!(
        linked[1].starts_with("name: ") && linked[1].ends_with(NAME),
        "{}",
        linked[1]
    );
    assert!(
        linked[2].contains("Ready") && linked[2].contains("verbs=0x1 "),
        "{}",
        linked[2]
    );
    assert!(linked[2].contains("order=[9, 1, 0]"), "{}", linked[2]);
    assert!(
        linked[3].contains("Ready")
            && linked[3].contains("verbs=0x14 ")
            && linked[3].contains("status=429")
            && linked[3].contains("blocked by test gate"),
        "{}",
        linked[3]
    );
    assert!(
        linked[4].contains("Ready")
            && linked[4].contains("verbs=0x1 ")
            && linked[4].contains("rewritten by test gate"),
        "{}",
        linked[4]
    );
    assert!(
        linked[5].contains("Ready")
            && linked[5].contains("status=451")
            && linked[5].contains("screened"),
        "{}",
        linked[5]
    );
    assert!(linked[7].contains("verbs=0x2 "), "{}", linked[7]);
    assert_eq!(linked[8], "timeout: decide: timed out");
}

/// A request that crosses is counted once through each build, however many are sent: the count is
/// the number of calls, exactly, so a build that stopped crossing, or crossed twice, fails.
#[tokio::test]
async fn each_build_serves_exactly_the_crossings_it_is_sent() {
    for way in [Way::Linked, Way::Dropped] {
        let rows = rows(busbar_hook_test_plugin::door, way);
        let gate = rows
            .open(NAME, "hooks.count", &json!({"order": [0]}), BUDGET)
            .expect("opens");
        assert_eq!(count(gate.as_ref(), "test_decides_total").await, 0);
        for sent in 1..=10u64 {
            let a = gate.decide(decide_frame("hello"), BUDGET).await;
            assert!(
                matches!(
                    &a,
                    Answered::Answer {
                        outcome: Outcome::Ready,
                        ..
                    }
                ),
                "{a:?}"
            );
            assert_eq!(count(gate.as_ref(), "test_decides_total").await, sent);
        }
        // `transform` is not a `decide`: it crosses without moving the `decide` count.
        let _ = gate.transform(transform_frame("hello"), BUDGET).await;
        assert_eq!(count(gate.as_ref(), "test_decides_total").await, 10);
    }
}

/// The plugin with its preferred orders reversed: the red arm's door. The same Statement, the same
/// gate behind it.
mod reversed {
    use super::{Decoded, HookImpl, HookOpen, Op, Poll, Verdict, STATEMENT};
    use busbar_contract::abi::sdk::hook::{DecodedTap, RewriteVerdict};

    struct Reversed(Box<dyn HookImpl>);

    impl HookImpl for Reversed {
        fn decide(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<Verdict> {
            self.0.decide(view, op).map(|v| match v {
                Verdict::Prefer(mut order) => {
                    order.reverse();
                    Verdict::Prefer(order)
                }
                other => other,
            })
        }
        fn transform(&self, view: &Decoded<'_>, op: &Op<'_>) -> Poll<RewriteVerdict> {
            self.0.transform(view, op)
        }
        fn notify(&self, tap: &DecodedTap<'_>, op: &Op<'_>) -> Poll<()> {
            self.0.notify(tap, op)
        }
        fn configure(
            &self,
            settings: &serde_json::Map<String, serde_json::Value>,
            version: u64,
        ) -> bool {
            self.0.configure(settings, version)
        }
        fn status(&self) -> serde_json::Value {
            self.0.status()
        }
        fn describe(&self) -> serde_json::Value {
            self.0.describe()
        }
    }

    pub struct Open;

    impl HookOpen for Open {
        fn open(settings: &str) -> Result<Box<dyn HookImpl>, String> {
            busbar_hook_test_plugin::Open::open(settings)
                .map(|h| Box::new(Reversed(h)) as Box<dyn HookImpl>)
        }
    }

    busbar_contract::hook_door! {
        open: Open,
        statement: STATEMENT,
    }
}

#[tokio::test]
async fn a_door_that_ranks_the_other_way_answers_differently() {
    let (honest, _) = script(&rows(busbar_hook_test_plugin::door, Way::Linked), NAME).await;
    let (red, _) = script(&rows(reversed::door, Way::Linked), NAME).await;
    assert_eq!(red.len(), honest.len());
    let differ: Vec<_> = honest.iter().zip(&red).filter(|(a, b)| a != b).collect();
    assert!(
        !differ.is_empty(),
        "a reversed ranking must answer differently"
    );
    assert!(
        differ.iter().all(|(a, _)| a.contains("rank")),
        "the two differ at the orders, nowhere else: {differ:#?}"
    );
}
