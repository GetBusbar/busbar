// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::hook::{VERB_ABSTAIN, VERB_PREFER};
use busbar_contract::abi::host::hook::{DecideFrame, DecideView};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::hook_calls::{Answered, HookAxis};
use busbar_contract::hooks::{Candidate, RoutingContext, RoutingDecision, RoutingRequest};
use busbar_kernel::config::{
    is_strategy_name, DEFAULT_POLICY_TIMEOUT_MS, ON_ERROR_WEIGHTED, RESERVED_HOOK_NAMES,
};

use crate::root::loader::PluginRegistry;

fn linked_axis() -> Arc<dyn HookAxis> {
    crate::root::hooks::axis(
        &(Arc::new(PluginRegistry::empty()) as Arc<dyn busbar_contract::plugin_rows::PluginRows>),
    )
    .expect("the linked hook rows")
}

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
        // An infinity is a key like any other, ordered as 1.5.5 ordered it (the v1.5.5 ranking
        // natives' `lib.rs:77-80`, `:99-102`): never dropped as absent.
        (
            "cheapest",
            vec![
                (0, Some(f64::INFINITY), None, 1, None),
                (1, Some(f64::INFINITY), None, 1, None),
            ],
            prefer(&[0, 1]),
        ),
        (
            "cheapest",
            vec![
                (0, Some(3.0), None, 1, None),
                (1, Some(f64::NEG_INFINITY), None, 1, None),
                (2, None, None, 1, None),
            ],
            prefer(&[1, 0, 2]),
        ),
        (
            "fastest",
            vec![
                (0, None, Some(f64::INFINITY), 1, None),
                (1, None, Some(10.0), 1, None),
            ],
            prefer(&[1, 0]),
        ),
        (
            "usage",
            vec![
                (0, None, None, 1, Some(0.5)),
                (1, None, None, 1, None),
                (2, None, None, 1, Some(f64::INFINITY)),
            ],
            prefer(&[2, 0, 1]),
        ),
    ]
}

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

fn strategy_words() -> Vec<&'static str> {
    RESERVED_HOOK_NAMES
        .iter()
        .copied()
        .filter(|n| is_strategy_name(n) && *n != ON_ERROR_WEIGHTED)
        .collect()
}

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
