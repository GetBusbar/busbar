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
    // Gemini: metadata as `labels`, the rest dropped.
    let out = cross("responses", "gemini", &body);
    assert_eq!(out.get("labels"), Some(&json!({"a": "1"})), "{out}");
    for k in MOVED {
        assert!(out.get(k).is_none(), "gemini {k}: {out}");
    }
    // Bedrock: metadata as `requestMetadata`, the tier as `serviceTier.type`, the rest dropped.
    let out = cross("responses", "bedrock", &body);
    assert_eq!(out.get("requestMetadata"), Some(&json!({"a": "1"})), "{out}");
    assert_eq!(out.get("serviceTier"), Some(&json!({"type": "flex"})), "{out}");
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
        ("standard_only", Some("default"), Some(json!({"type": "default"}))),
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
