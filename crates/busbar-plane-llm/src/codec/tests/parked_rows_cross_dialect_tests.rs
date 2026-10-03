// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-DIALECT behaviour of every member CARRY-TABLE moved from "always raw in `extra`" into a
//! parked mapping row: Anthropic `service_tier`; Responses `metadata`, `service_tier`, `store`,
//! `safety_identifier`, `prompt_cache_key`. Parking changed where the SAME-dialect raw member
//! lives (`extra` only when the slot cannot reproduce it); it must not change what crosses.
//!
//! What crosses is the typed slot, exactly as before the move: these slots are the Q57 IR wave
//! (`ir-slots-landed.md` IR-03..06), already carried cross-dialect by the readers before this lane
//! (pinned by `openai_responses::ir_slot_wiring_tests::ir03_07_shared_request_members_cross_the_seam`
//! and `anthropic::ir_slot_wiring_tests::ir04_service_tier_is_carried`). v1.5.5 had no such slots
//! (`crates/busbar/src/ir/mod.rs` `IrRequest`) and cleared `extra` on the seam
//! (`crates/busbar/src/ir/variant.rs:295`), so in v1.5.5 every one of these members was DROPPED
//! cross-dialect; the carry below is the Q57 wave's, not this lane's.
//!
//! That carry is the signed-off 1.6.0 behaviour: docs/design/1.6.0-QUESTIONS.md Q61 (owner) —
//! "the IR maps 100% wherever a target dialect can carry a field — a drop is a defect". Every drop
//! pinned below is a target with no member for the field.

use crate::codec::proto_codec::protocol_for;
use serde_json::{json, Value};

/// `ingress` reader → the cross-protocol seam (clears `extra`) → `egress` writer.
fn cross(ingress: &str, egress: &str, body: &Value) -> Value {
    let mut req = protocol_for(ingress)
        .expect("ingress")
        .reader()
        .read_request(body)
        .expect("read");
    crate::codec::chat_handle::chat_prepare_for_egress(
        &mut req,
        &busbar_contract::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: "x",
            egress_requires_max_tokens: false,
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::codec::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
            lane_caps: Default::default(),
        },
    );
    assert!(req.extra.is_empty(), "the seam clears extra");
    protocol_for(egress)
        .expect("egress")
        .writer()
        .write_request(&req)
}

const MOVED: [&str; 5] = [
    "metadata",
    "service_tier",
    "store",
    "safety_identifier",
    "prompt_cache_key",
];

/// Responses → every dialect: each member as the Q57 slot carries it, or dropped.
#[test]
fn responses_parked_members_cross_as_their_slots_or_drop() {
    let body = json!({"model": "gpt", "input": "hi",
        "metadata": {"a": "1"}, "service_tier": "flex", "store": false,
        "safety_identifier": "sid", "prompt_cache_key": "pck"});
    let carried = json!({"metadata": {"a": "1"}, "service_tier": "flex", "store": false,
        "safety_identifier": "sid", "prompt_cache_key": "pck"});
    for egress in ["openai", "responses"] {
        let out = cross("responses", egress, &body);
        for k in MOVED {
            assert_eq!(out.get(k), carried.get(k), "{egress} {k}: {out}");
        }
    }
    // Anthropic and Cohere have no form for any of them (Flex has no Anthropic tier word).
    for egress in ["anthropic", "cohere"] {
        let out = cross("responses", egress, &body);
        for k in MOVED {
            assert!(out.get(k).is_none(), "{egress} {k}: {out}");
        }
    }
    // Gemini: metadata as `labels`, the tier as `serviceTier`, `store` as itself (DF-MAP: Gemini's
    // own members, mapped in gemini.toml), the rest dropped.
    let out = cross("responses", "gemini", &body);
    assert_eq!(out.get("labels"), Some(&json!({"a": "1"})), "{out}");
    assert_eq!(out.get("serviceTier"), Some(&json!("flex")), "{out}");
    assert_eq!(out.get("store"), Some(&json!(false)), "{out}");
    for k in [
        "metadata",
        "service_tier",
        "safety_identifier",
        "prompt_cache_key",
    ] {
        assert!(out.get(k).is_none(), "gemini {k}: {out}");
    }
    // Bedrock: metadata as `requestMetadata`, the tier as `serviceTier.type`, the rest dropped.
    let out = cross("responses", "bedrock", &body);
    assert_eq!(
        out.get("requestMetadata"),
        Some(&json!({"a": "1"})),
        "{out}"
    );
    assert_eq!(
        out.get("serviceTier"),
        Some(&json!({"type": "flex"})),
        "{out}"
    );
    for k in MOVED {
        assert!(out.get(k).is_none(), "bedrock {k}: {out}");
    }
}

/// Anthropic `service_tier` → every dialect: the IR tier in each dialect's word, or dropped.
#[test]
fn anthropic_parked_service_tier_crosses_as_its_slot_or_drops() {
    let body = |tier: &str| {
        json!({"model": "m", "max_tokens": 64, "service_tier": tier,
               "messages": [{"role": "user", "content": "hi"}]})
    };
    for (tier, openai, bedrock) in [
        (
            "standard_only",
            Some("default"),
            Some(json!({"type": "default"})),
        ),
        ("auto", Some("auto"), None),
    ] {
        for egress in ["openai", "responses"] {
            let out = cross("anthropic", egress, &body(tier));
            assert_eq!(
                out.get("service_tier").and_then(Value::as_str),
                openai,
                "{tier} {egress}: {out}"
            );
        }
        let out = cross("anthropic", "anthropic", &body(tier));
        assert_eq!(out.get("service_tier"), Some(&json!(tier)), "{out}");
        let out = cross("anthropic", "bedrock", &body(tier));
        assert_eq!(out.get("serviceTier").cloned(), bedrock, "{tier}: {out}");
        for egress in ["gemini", "cohere"] {
            let out = cross("anthropic", egress, &body(tier));
            assert!(out.get("service_tier").is_none(), "{tier} {egress}: {out}");
        }
    }
}

/// DF-MAP (design DIALECT FIDELITY F3/F4; the owner's dialect-fidelity standing rule, 2026-10-02): Gemini's
/// `serviceTier` and `store` are the fields OpenAI Chat and Responses map as `service_tier` /
/// `store`. They cross both ways now; 1.5.5 and predev dropped them on every crossing.
#[test]
fn gemini_service_tier_and_store_cross_both_ways() {
    let gemini = |tier: &str| {
        json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
               "serviceTier": tier, "store": true})
    };
    for (tier, openai) in [
        ("standard", "default"),
        ("flex", "flex"),
        ("priority", "priority"),
    ] {
        for egress in ["openai", "responses"] {
            let out = cross("gemini", egress, &gemini(tier));
            assert_eq!(
                out.get("service_tier"),
                Some(&json!(openai)),
                "{tier} {egress}: {out}"
            );
            assert_eq!(out.get("store"), Some(&json!(true)), "{egress}: {out}");
        }
    }
    // A tier with no IR word crosses as nothing (Gemini's own `unspecified`).
    let out = cross("gemini", "openai", &gemini("unspecified"));
    assert!(out.get("service_tier").is_none(), "{out}");

    let openai = |tier: &str| {
        json!({"model": "m", "messages": [{"role": "user", "content": "hi"}],
               "service_tier": tier, "store": false})
    };
    for (tier, gemini_word) in [
        ("default", Some("standard")),
        ("flex", Some("flex")),
        ("priority", Some("priority")),
        ("auto", None),
        ("scale", None),
    ] {
        let out = cross("openai", "gemini", &openai(tier));
        assert_eq!(
            out.get("serviceTier").and_then(Value::as_str),
            gemini_word,
            "{tier}: {out}"
        );
        assert_eq!(out.get("store"), Some(&json!(false)), "{out}");
    }
}

/// Gemini -> Gemini through the IR keeps the caller's exact `serviceTier`, a word the slot cannot
/// reproduce included (the row is parked).
#[test]
fn gemini_service_tier_same_dialect_keeps_the_raw_word() {
    for tier in ["standard", "unspecified"] {
        let body = json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                          "serviceTier": tier, "store": false});
        let req = protocol_for("gemini")
            .expect("gemini")
            .reader()
            .read_request(&body)
            .expect("read");
        let out = protocol_for("gemini")
            .expect("gemini")
            .writer()
            .write_request(&req);
        assert_eq!(out.get("serviceTier"), Some(&json!(tier)), "{out}");
        assert_eq!(out.get("store"), Some(&json!(false)), "{out}");
    }
}

/// DF-MAP: Converse `outputConfig.effort` is the reasoning effort Anthropic (`output_config.effort`)
/// and the OpenAI family (`reasoning_effort`, `reasoning.effort`) map. It is read when the request
/// states no `additionalModelRequestFields` reasoning ask (that ask wins).
#[test]
fn bedrock_output_config_effort_crosses_as_the_reasoning_ask() {
    let body = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}],
                      "outputConfig": {"effort": "high"}});
    let out = cross("bedrock", "openai", &body);
    assert_eq!(out.get("reasoning_effort"), Some(&json!("high")), "{out}");
    // Anthropic spells an effort word as adaptive thinking + `output_config.effort` only on a lane
    // whose model declares it (`LaneCaps::anthropic_adaptive_thinking`, ANT-10: `budget_tokens`
    // 400s there); every other Anthropic lane takes the effort as its numeric thinking budget.
    let mut req = protocol_for("bedrock")
        .expect("bedrock")
        .reader()
        .read_request(&body)
        .expect("read");
    req.extra.clear();
    let adaptive = busbar_contract::ir::egress_prep::LaneCaps {
        anthropic_adaptive_thinking: true,
        ..Default::default()
    };
    let out = protocol_for("anthropic")
        .expect("anthropic")
        .writer()
        .write_request_for_lane(&req, "claude-opus-4-7", &adaptive);
    assert_eq!(
        out.pointer("/output_config/effort"),
        Some(&json!("high")),
        "{out}"
    );
    assert_eq!(
        out.pointer("/thinking/type"),
        Some(&json!("adaptive")),
        "{out}"
    );
    let out = cross("bedrock", "anthropic", &body);
    assert!(
        out.pointer("/thinking/budget_tokens")
            .is_some_and(Value::is_u64),
        "a lane without adaptive thinking takes the effort as a budget: {out}"
    );
    assert!(out.pointer("/output_config/effort").is_none(), "{out}");

    // An explicit thinking budget in additionalModelRequestFields wins over the effort word.
    let both = json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}],
                      "outputConfig": {"effort": "low"},
                      "additionalModelRequestFields":
                          {"thinking": {"type": "enabled", "budget_tokens": 2048}}});
    let out = cross("bedrock", "anthropic", &both);
    assert_eq!(
        out.pointer("/thinking/budget_tokens"),
        Some(&json!(2048)),
        "{out}"
    );
    assert!(out.pointer("/output_config/effort").is_none(), "{out}");
}
