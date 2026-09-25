// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: hook`, BOTH WAYS** (DECISIONS #2 rule (1), K5). The in-tree test hook registered through
//! the LINKED door (its `rlib`'s `BUSBAR_COLD_ENTRY`) and the DROPPED-IN door (its `cdylib`, signed
//! into `plugins/`) resolves to the byte-identical registry row, and the routing policy each door's
//! `open_hook` opens answers one script byte-identically: two decisions (an order, a gate reject), two
//! transforms (a rewrite, a reject) and its settings schema. See [`super::both_ways`].
//!
//! RED by planting the door bypass the axis replaces — linked rows handed to [`PluginRegistry::link`]
//! and never registered — which leaves the linked registry with no row for the name.

use super::both_ways::{both_doors, statement};
use crate::hook::HookProjectors;
use busbar_api::{
    Candidate, RoutingContext, RoutingDecision, RoutingPolicy, RoutingRequest, TransformOutcome,
};
use std::sync::Arc;
use std::time::Duration;

/// The plugin's config: echo the order `[1, 0]`, reject a prompt carrying the screen token.
const CFG: &str = r#"{"order": [1, 0], "reject_if_contains": "BLOCKME"}"#;

/// The prompt's messages, projected as the engine's wire does.
fn messages(req: &RoutingRequest<'_>) -> serde_json::Value {
    serde_json::json!(req.prompt.as_ref().map(|p| {
        p.messages
            .iter()
            .map(|(r, t)| serde_json::json!({"role": r.as_ref(), "text": t.as_ref()}))
            .collect::<Vec<_>>()
    }))
}

/// The value a reply's `reject` member carries, if it has one.
fn reject(v: &serde_json::Value) -> Option<(u16, String)> {
    let r = v.get("reject")?;
    let status = r.get("status").and_then(|s| s.as_u64()).unwrap_or(403) as u16;
    let message = r.get("message").and_then(|m| m.as_str()).unwrap_or("");
    Some((status, message.to_string()))
}

/// Engine-side projectors, the small fail-closed shape `hook_tests` drives the seam with.
fn projectors() -> Arc<HookProjectors> {
    Arc::new(HookProjectors {
        decide: Box::new(|req, cands, _ctx| {
            serde_json::json!({
                "request": {"pool": req.pool, "messages": messages(req)},
                "candidates": cands.iter().map(|c| serde_json::json!({"idx": c.idx})).collect::<Vec<_>>(),
            })
        }),
        transform: Box::new(|req| serde_json::json!({"request": {"messages": messages(req)}})),
        normalize: Box::new(|v, cands| {
            if let Some((status, message)) = reject(&v) {
                return Ok(RoutingDecision::Reject { status, message });
            }
            let Some(order) = v.get("order").and_then(|o| o.as_array()) else {
                return Ok(RoutingDecision::Abstain);
            };
            let valid: std::collections::HashSet<usize> = cands.iter().map(|c| c.idx).collect();
            Ok(RoutingDecision::from_ranked(
                order.iter().filter_map(|x| x.as_u64().map(|x| x as usize)),
                &valid,
            ))
        }),
        transform_outcome: Box::new(|v| {
            if let Some((status, message)) = reject(&v) {
                return TransformOutcome::Reject { status, message };
            }
            match v
                .get("rewrite")
                .and_then(|r| r.get("messages"))
                .and_then(|m| m.as_array())
            {
                Some(msgs) if !msgs.is_empty() => {
                    TransformOutcome::Rewrite(busbar_api::RewriteReply {
                        messages: msgs.clone(),
                        tools: Vec::new(),
                    })
                }
                _ => TransformOutcome::Abstain,
            }
        }),
        status: Box::new(|_| None),
        describe_schema: Box::new(|v| v.get("schema").cloned()),
    })
}

/// A request carrying one user message.
fn request(text: &str) -> RoutingRequest<'static> {
    RoutingRequest {
        request_id: 1,
        pool: "p",
        ingress_protocol: "proto-a",
        requested_model: None,
        message_count: 1,
        tool_count: 0,
        has_tools: false,
        total_chars: text.len(),
        system_chars: 0,
        max_tokens: None,
        stream: false,
        prompt: Some(busbar_api::PromptProjection {
            system: None,
            messages: vec![("user".into(), text.to_string().into())],
        }),
        identity: None,
        signals: Default::default(),
    }
}

/// A candidate at `idx`.
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

/// The script, driven on a runtime of its own: the policy's name, two decisions, two transforms and
/// the schema it describes.
fn script(policy: &Arc<dyn RoutingPolicy>) -> String {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a runtime for the script");
    let budget = Duration::from_secs(5);
    let cands = [candidate(0), candidate(1)];
    let ctx = RoutingContext {
        pool: "p",
        budget_remaining: None,
        budget: &[],
    };
    rt.block_on(async {
        let mut out = vec![format!("name={}", policy.name())];
        for text in ["hello", "please BLOCKME now"] {
            let d = policy.decide(&request(text), &cands, &ctx, budget).await;
            out.push(format!("decide {text:?} -> {d:?}"));
        }
        for text in ["hello", "BLOCKME"] {
            let t = policy.transform(&request(text), budget).await;
            out.push(format!("transform {text:?} -> {t:?}"));
        }
        out.push(format!("describe -> {:?}", policy.describe(budget).await));
        out.join("\n")
    })
}

/// THE EXIT TEST: the test hook linked and dropped in registers the same row and opens a policy that
/// decides and transforms the same.
#[test]
fn a_linked_and_a_dropped_in_hook_register_byte_identical_rows() {
    let manifest = statement(
        "hook",
        "test-hook",
        "gate",
        busbar_plugin::cold::hook::HOOK_ABI_VERSION,
    );
    let Some([linked, dropped]) = both_doors(
        manifest,
        &busbar_hook_test_plugin::BUSBAR_COLD_ENTRY,
        "busbar_hook_test_plugin",
        |registry| {
            registry
                .open_hook("gate", CFG, "gate", projectors())
                .expect("the hook opens through its alias")
        },
        script,
    ) else {
        eprintln!("skip: hook test plugin cdylib not built");
        return;
    };
    assert!(
        !linked.0.starts_with("no row"),
        "the linked door registered no row: {}",
        linked.0
    );
    assert!(
        linked.1.contains("Prefer([1, 0])") && linked.1.contains("blocked by test gate"),
        "the linked policy ran the script: {}",
        linked.1
    );
    assert_eq!(linked, dropped, "the two doors must register one row");
}
