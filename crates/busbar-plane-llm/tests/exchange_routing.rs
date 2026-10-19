// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The generation's routing (u26), as the plane resolves it from its sections and publishes it on
//! the snapshot (`PlaneSnapshot.routing`), in the form agreed with the kernel's routing lane.

use busbar_contract::abi::plane::{
    FACT_ATTEMPT_TIMEOUT_MS, FACT_CONCURRENCY_CAP, FACT_CONTEXT_WINDOW, FACT_FAILOVER_MAX_HOPS,
    FACT_FAILOVER_TIMEOUT_SECS, FACT_MAX_REQUESTS,
};
use busbar_contract::abi::sdk::publish::{RouteEntrySpec, RouteMemberSpec};
use busbar_plane_llm::exchange::routing::{
    self, DEFAULT_FAILOVER_MAX_HOPS, DEFAULT_FAILOVER_TIMEOUT_SECS,
};
use busbar_plane_llm::exchange::shaping::Shaping;
use serde_json::{json, Value};

fn settings() -> Value {
    json!({
        "providers": {
            "oai": { "protocol": "openai", "base_url": "https://api.example" },
            "ant": { "base_url": "https://anthropic.example" }
        },
        "models": {
            "gpt": { "provider": "oai", "upstream_model": "o1-mini", "max_concurrent": 4,
                     "max_requests": 100, "attempt_timeout_ms": 9000 },
            "claude": { "provider": "ant" },
            "lonely": { "provider": "ant", "max_requests": -1 }
        },
        "pools": {
            "upstream_credentials": "own",
            "main": {
                "members": [ "claude",
                             { "model": "gpt", "weight": 3, "tier": "gold", "tags": ["fast"],
                               "context_max": 8000, "attempt_timeout_ms": 500 } ],
                "failover": { "exclusions": ["claude"], "max_hops": 5 }
            },
            "alt": { "members": [ { "model": "gpt", "context_max": 8000 } ] }
        }
    })
}

fn entry<'a>(routes: &'a [RouteEntrySpec], section: &str, name: &str) -> &'a RouteEntrySpec {
    routes
        .iter()
        .find(|e| e.section == section && e.entry == name)
        .unwrap_or_else(|| panic!("no {section}/{name} entry in {routes:#?}"))
}

/// A lane's facts are the same on every member naming it; only the attempt bound is the member's.
fn gpt_member(weight: u32, tier: &str, tags: &[&str], attempt_ms: u64) -> RouteMemberSpec {
    RouteMemberSpec {
        lane: "gpt".into(),
        provider: "oai".into(),
        upstream: "o1-mini".into(),
        weight,
        tier: tier.into(),
        tags: tags.iter().map(|t| (*t).to_string()).collect(),
        facts: vec![
            (FACT_CONCURRENCY_CAP, 4),
            (FACT_CONTEXT_WINDOW, 8000),
            (FACT_MAX_REQUESTS, 100),
            (FACT_ATTEMPT_TIMEOUT_MS, attempt_ms),
        ],
    }
}

/// RED: a model loses its own entry, its one member, or a lane fact it states.
#[test]
fn every_model_is_its_own_entry_with_its_one_lane() {
    let routes = routing::of(&settings()).unwrap();
    let gpt = entry(&routes, "models", "gpt");
    assert_eq!(gpt.path, ["models", "gpt"]);
    assert!(gpt.fallback.is_empty() && gpt.exclude.is_empty() && gpt.facts.is_empty());
    assert_eq!(gpt.members, [gpt_member(1, "", &[], 9000)]);
    // A model no pool names still routes, and a negative max_requests states no bound.
    let lonely = entry(&routes, "models", "lonely");
    assert_eq!(
        lonely.members,
        [RouteMemberSpec {
            lane: "lonely".into(),
            provider: "ant".into(),
            weight: 1,
            ..RouteMemberSpec::default()
        }]
    );
}

/// RED: a pool's members lose their order, weight, tier, tags, or the member's own attempt bound;
/// or the failover block's stated and defaulted values move.
#[test]
fn a_pool_is_its_members_in_order_and_its_failover_block() {
    let routes = routing::of(&settings()).unwrap();
    let main = entry(&routes, "pools", "main");
    assert_eq!(main.path, ["pools", "main"]);
    assert!(main.fallback.is_empty(), "on_exhausted is the kernel's");
    assert_eq!(main.exclude, ["claude"]);
    assert_eq!(
        main.facts,
        [
            (FACT_FAILOVER_TIMEOUT_SECS, DEFAULT_FAILOVER_TIMEOUT_SECS),
            (FACT_FAILOVER_MAX_HOPS, 5)
        ]
    );
    assert_eq!(main.members[0].lane, "claude");
    assert_eq!(main.members[0].weight, 1);
    assert_eq!(main.members[1], gpt_member(3, "gold", &["fast"], 500));
    // No failover block: no failover facts, no exclusions; the model's attempt bound fills in.
    let alt = entry(&routes, "pools", "alt");
    assert!(alt.facts.is_empty() && alt.exclude.is_empty());
    assert_eq!(alt.members, [gpt_member(1, "", &[], 9000)]);
}

/// RED: an empty failover block stops stating 1.5.5's serde defaults.
#[test]
fn an_empty_failover_block_states_the_1_5_5_defaults() {
    let mut s = settings();
    s["pools"]["alt"]["failover"] = json!({});
    let routes = routing::of(&s).unwrap();
    assert_eq!(
        entry(&routes, "pools", "alt").facts,
        [
            (FACT_FAILOVER_TIMEOUT_SECS, DEFAULT_FAILOVER_TIMEOUT_SECS),
            (FACT_FAILOVER_MAX_HOPS, DEFAULT_FAILOVER_MAX_HOPS)
        ]
    );
    assert_eq!(
        (DEFAULT_FAILOVER_TIMEOUT_SECS, DEFAULT_FAILOVER_MAX_HOPS),
        (120, 3)
    );
}

/// RED: the plane states a fact the kernel owns (fact 0, a probe fact) or a reserved key's value.
#[test]
fn the_plane_states_no_probe_or_reserved_fact() {
    let routes = routing::of(&settings()).unwrap();
    let ours = [
        FACT_CONCURRENCY_CAP,
        FACT_CONTEXT_WINDOW,
        FACT_MAX_REQUESTS,
        FACT_ATTEMPT_TIMEOUT_MS,
        FACT_FAILOVER_TIMEOUT_SECS,
        FACT_FAILOVER_MAX_HOPS,
    ];
    for e in &routes {
        for (fact, _) in e
            .facts
            .iter()
            .chain(e.members.iter().flat_map(|m| m.facts.iter()))
        {
            assert!(
                ours.contains(fact),
                "{}/{} states fact {fact}",
                e.section,
                e.entry
            );
        }
    }
}

/// RED: a context_max of 0 is stated (0 is undeclared to the kernel).
#[test]
fn a_zero_context_window_is_not_stated() {
    let mut s = settings();
    s["pools"]["alt"]["members"][0]["context_max"] = json!(0);
    s["pools"]["main"]["members"][1]["context_max"] = json!(0);
    let routes = routing::of(&s).unwrap();
    let gpt = &entry(&routes, "models", "gpt").members[0];
    assert!(gpt.facts.iter().all(|(f, _)| *f != FACT_CONTEXT_WINDOW));
}

/// RED: a blob without `models:` (the boot's own-section deal) routes something, or the tables
/// stop carrying the routing the snapshot publishes.
#[test]
fn the_tables_carry_the_routing_the_snapshot_publishes() {
    assert!(
        routing::of(&json!({ "pools": settings()["pools"].clone() }))
            .unwrap()
            .is_empty()
    );
    let shaping = Shaping::from_settings(&settings()).unwrap();
    assert_eq!(shaping.routing, routing::of(&settings()).unwrap());
    assert_eq!(shaping.routing.len(), 5, "three models, two pools");
}
