// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LINKED RANKING DOOR, PROVEN WHERE IT IS LINKED (R-FIX3). The kernel's test build no longer
//! takes the ranking plugin: it links its in-crate double (`busbar_kernel::test_support::
//! ranking_double`), and its own hook tests run against that. These are the twins of the kernel's
//! ranking tests, run against the REAL door through the axis the shipped binary installs
//! (`crate::root::hooks::axis` over `crate::LINKED.hook_doors`), never through the kernel's
//! stand-in rows. And they prove the double copies the real door: the same Statement, the same
//! refusals, the same decisions.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::{VERB_ABSTAIN, VERB_PREFER};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::door::{DoorFn, MARK_WORD_HOOK};
use busbar_contract::abi::mechanism::rendering;
use busbar_contract::hook_calls::{Answered, HookAxis, HookFacts};
use busbar_contract::hooks::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
use busbar_kernel::config::{
    parse_strategy, PoolPolicy, DEFAULT_POLICY_TIMEOUT_MS, ON_ERROR_WEIGHTED, RESERVED_HOOK_NAMES,
};
use busbar_kernel::test_support::ranking_double;

use crate::root::loader::hook_door::HookRows;
use crate::root::loader::PluginRegistry;

/// The hook axis the shipped binary installs, over an empty registry: the linked rows alone.
fn linked_axis() -> Arc<dyn HookAxis> {
    crate::root::hooks::axis(&Arc::new(PluginRegistry::empty())).expect("the linked hook rows")
}

/// An axis over the kernel's ranking double alone, on the same dispatcher.
fn double_axis() -> Arc<dyn HookAxis> {
    let rows = HookRows::new(
        &[ranking_double::door],
        Some(&PluginRegistry::empty()),
        crate::root::dispatch::dispatcher(),
    )
    .expect("the double states itself");
    Arc::new(rows)
}

/// `(idx, cost, latency, concurrency, rate headroom)`.
type Row = (usize, Option<f64>, Option<f64>, usize, Option<f64>);

fn cand(&(idx, cost, lat, conc, rate): &Row) -> Candidate<'static> {
    Candidate {
        idx,
        model: "m",
        provider: "p",
        weight: 1,
        context_max: None,
        tier: None,
        cost_per_mtok: cost,
        tags: &[],
        latency_ms: lat,
        available_concurrency: conc,
        budget_remaining: None,
        rate_headroom: rate,
        signals: Default::default(),
    }
}

fn request() -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "wire-a",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: 10,
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: None,
        identity: None,
        signals: Default::default(),
        session: None,
    }
}

/// The 1.5.5 natives' cases (the ranking plugin's lib_tests before the door), as the kernel's
/// `each_strategy_word_ranks_as_1_5_5_did_through_the_door_and_never_reaches_on_error` states them:
/// word, candidates, the decision 1.5.5 answered.
fn cases() -> Vec<(&'static str, Vec<Row>, RoutingDecision)> {
    let prefer = |o: &[usize]| RoutingDecision::Prefer(o.to_vec());
    vec![
        (
            "cheapest",
            vec![
                (0, Some(15.0), None, 1, None),
                (1, Some(3.0), None, 1, None),
                (2, None, None, 1, None),
            ],
            prefer(&[1, 0, 2]),
        ),
        (
            "cheapest",
            vec![(0, None, None, 1, None), (1, None, None, 1, None)],
            RoutingDecision::Abstain,
        ),
        (
            "cheapest",
            vec![(0, Some(5.0), None, 1, None)],
            prefer(&[0]),
        ),
        (
            "fastest",
            vec![
                (0, None, Some(120.0), 1, None),
                (1, None, Some(40.0), 1, None),
                (2, None, Some(80.0), 1, None),
            ],
            prefer(&[1, 2, 0]),
        ),
        (
            "fastest",
            vec![(0, None, None, 1, None), (1, None, None, 1, None)],
            RoutingDecision::Abstain,
        ),
        (
            "fastest",
            vec![(0, None, Some(30.0), 1, None)],
            prefer(&[0]),
        ),
        (
            "least_busy",
            vec![
                (0, None, None, 2, None),
                (1, None, None, 9, None),
                (2, None, None, 5, None),
            ],
            prefer(&[1, 2, 0]),
        ),
        (
            "least_busy",
            vec![
                (0, None, None, 0, None),
                (1, None, None, 0, None),
                (2, None, None, 0, None),
            ],
            prefer(&[0, 1, 2]),
        ),
        ("least_busy", vec![(0, None, None, 3, None)], prefer(&[0])),
        (
            "usage",
            vec![
                (0, None, None, 1, Some(0.10)),
                (1, None, None, 1, Some(0.90)),
                (2, None, None, 1, None),
                (3, None, None, 1, Some(0.50)),
            ],
            prefer(&[1, 3, 0, 2]),
        ),
        (
            "usage",
            vec![
                (0, None, None, 1, None),
                (1, None, None, 1, None),
                (2, None, None, 1, None),
            ],
            RoutingDecision::Abstain,
        ),
        (
            "usage",
            vec![(0, None, None, 1, Some(0.0)), (1, None, None, 1, Some(0.0))],
            prefer(&[0, 1]),
        ),
        ("cheapest", Vec::new(), RoutingDecision::Abstain),
        ("fastest", Vec::new(), RoutingDecision::Abstain),
        ("least_busy", Vec::new(), RoutingDecision::Abstain),
        ("usage", Vec::new(), RoutingDecision::Abstain),
    ]
}

/// `word` opened on `axis` with `{"policy": "<word>"}` under the axis's Call class budget, and
/// asked to `decide` over `rows`: the decision read back as the host reads a ranking's answer
/// (PREFER = the order, unknown indices dropped; ABSTAIN), or why there was none.
async fn decide(
    axis: &Arc<dyn HookAxis>,
    word: &str,
    rows: &[Row],
    budget: Duration,
) -> Result<RoutingDecision, String> {
    let calls = axis.open(word, word, &serde_json::json!({ "policy": word }), budget)?;
    let cands: Vec<Candidate<'_>> = rows.iter().map(cand).collect();
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    let frame = DecideFrame::first(DecideView::build(&request(), &cands, &ctx));
    match calls.decide(frame, budget).await {
        Answered::Answer {
            outcome: Outcome::Ready,
            out,
            frame,
            ..
        } => match out.verbs {
            VERB_PREFER => {
                let valid: HashSet<usize> = cands.iter().map(|c| c.idx).collect();
                Ok(RoutingDecision::from_ranked(
                    frame.order(out.order_written),
                    &valid,
                ))
            }
            VERB_ABSTAIN => Ok(RoutingDecision::Abstain),
            verbs => Err(format!("a ranking answered verbs {verbs:#x}")),
        },
        Answered::Answer { error, .. } => Err(format!("FAILED: {}", error.unwrap_or_default())),
        Answered::TimedOut => Err("timed out".into()),
        Answered::Broken(why) => Err(why),
    }
}

/// The built-in strategy words (every reserved hook name but `weighted`, the inline floor).
fn strategy_words() -> Vec<&'static str> {
    RESERVED_HOOK_NAMES
        .iter()
        .copied()
        .filter(|n| parse_strategy(n) != PoolPolicy::Weighted)
        .collect()
}

/// The twin of the kernel's test of the same name, on the REAL door: the built-in ranking
/// strategies are the HOOK WORDS of ONE linked ranking door on the hook axis — each
/// strategy word names that row, and opens (with `{"policy": "<word>"}`). `weighted` stays the
/// inline floor (no row). The words are the door's Statement marks, never registry aliases.
#[test]
fn the_built_in_ranking_strategies_are_hook_words_of_one_linked_door_on_the_hook_axis() {
    let axis = linked_axis();
    for name in strategy_words() {
        assert!(
            axis.linked(name),
            "a built-in ranking strategy is a hook word of the linked ranking door: {name}"
        );
        let opened = axis.open(
            name,
            name,
            &serde_json::json!({ "policy": name }),
            axis.call_budget(),
        );
        assert!(opened.is_ok(), "the strategy opens: {name}");
    }
    assert!(!axis.linked(ON_ERROR_WEIGHTED));
    let reg = PluginRegistry::empty();
    assert!(
        reg.resolve("cheapest").is_none(),
        "a strategy word is the door's mark, not a registry alias"
    );
}

/// The twin of the kernel's test of the same name, on the REAL door (ARCHITECT Q-SO9): each of
/// the four strategy words, opened through the hook axis and called through the hook seam,
/// answers exactly the decision 1.5.5's in-process native answered on the ranking parity cases.
/// Every answer is `Ok`: the call never fails, times out or reaches `on_error`. Its deadline is
/// the dispatcher's Call class budget, never the 1 ms gate default.
#[tokio::test]
async fn each_strategy_word_ranks_as_1_5_5_did_through_the_door_and_never_reaches_on_error() {
    let axis = linked_axis();
    let budget = axis.call_budget();
    let gate_default = Duration::from_millis(DEFAULT_POLICY_TIMEOUT_MS);
    for (word, rows, want) in cases() {
        assert!(
            budget > gate_default,
            "`{word}`'s deadline is the dispatcher's Call class budget, not the gate default"
        );
        match decide(&axis, word, &rows, budget).await {
            Ok(got) => assert_eq!(got, want, "`{word}` over {rows:?}"),
            Err(e) => panic!("`{word}` reached on_error ({e}); 1.5.5's ranking never did"),
        }
    }
}

/// The linked door that claims `word` as a hook word.
fn linked_door_claiming(word: &str) -> DoorFn {
    *crate::LINKED
        .hook_doors
        .iter()
        .find(|door| hook_words(&read(**door)).iter().any(|w| w == word))
        .expect("a linked hook door claims the word")
}

fn read(door: DoorFn) -> rendering::Read {
    let stated = crate::root::loader::dispatch::rendering_of(door).expect("the door states");
    rendering::read(&stated).expect("the rendering reads")
}

fn hook_words(r: &rendering::Read) -> Vec<String> {
    r.mark_words
        .iter()
        .filter(|(class, _)| *class == MARK_WORD_HOOK)
        .map(|(_, w)| w.clone())
        .collect()
}

/// R-FIX3: THE KERNEL'S RANKING DOUBLE STATES WHAT THE LINKED RANKING DOOR STATES, so the kernel's
/// hook tests, which run against the double, judge the door the binary ships. Both Statements
/// rendered: the same kind, `max_inflight`, flag marks, hook words and tail, and the tail's facts
/// the same (class and grants, as the hook axis reads them); the name is the double's own (the
/// kernel names no plugin, C1). Both opened: the same refusals, byte for byte once each door's own
/// name is read as one. Both asked: the same decision on every 1.5.5 parity case.
///
/// RED by flipping any copied literal or rule in the double (e.g. `least_busy` ascending).
#[tokio::test]
async fn the_kernel_ranking_double_states_what_the_linked_ranking_door_states() {
    let real = read(linked_door_claiming("cheapest"));
    let double = read(ranking_double::door);
    assert_ne!(
        double.name, real.name,
        "the double states its own name: the kernel names no plugin (C1)"
    );
    assert_eq!(double.name, ranking_double::NAME, "the Statement name");
    assert_eq!(double.kind, real.kind);
    assert_eq!(double.kind_abi, real.kind_abi);
    assert_eq!(double.max_inflight, real.max_inflight, "max_inflight");
    assert_eq!(double.marks, real.marks, "the flag marks");
    assert_eq!(hook_words(&double), hook_words(&real), "the hook words");
    assert_eq!(double.mark_words, real.mark_words, "every word mark");
    assert_eq!(double.kind_tail_size, real.kind_tail_size, "the tail");

    let (linked, doubled) = (linked_axis(), double_axis());
    let budget = linked.call_budget();
    for word in hook_words(&real) {
        let settings = serde_json::json!({ "policy": word });
        let facts = |axis: &Arc<dyn HookAxis>| axis.probe(&word, &word, &settings);
        // The door's facts, its Statement name read as the double's own (C1).
        let want = facts(&linked).map(|(stated, problems)| {
            let stated = stated.map(|f| HookFacts {
                name: ranking_double::NAME.to_string(),
                ..f
            });
            (stated, problems)
        });
        assert_eq!(facts(&doubled), want, "the tail's facts, `{word}`");
    }
    for settings in [
        serde_json::json!({}),
        serde_json::json!({ "policy": "nope" }),
        serde_json::json!({ "policy": "weighted" }),
    ] {
        let refusal =
            |axis: &Arc<dyn HookAxis>, name: &str| axis.open(name, name, &settings, budget).err();
        // The door's refusal, its Statement name and its own prefix read as the double's name.
        let want = refusal(&linked, &real.name).map(|e| {
            e.replace(&real.name, ranking_double::NAME)
                .replace("hook-ranking", ranking_double::NAME)
        });
        assert!(want.is_some(), "the linked door refuses {settings}");
        assert_eq!(
            refusal(&doubled, ranking_double::NAME),
            want,
            "the refusal of {settings}"
        );
    }

    for (word, rows, _) in cases() {
        assert_eq!(
            decide(&doubled, word, &rows, budget).await,
            decide(&linked, word, &rows, budget).await,
            "`{word}` over {rows:?}"
        );
    }
}
