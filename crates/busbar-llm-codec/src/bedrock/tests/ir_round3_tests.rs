// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping: the Bedrock lane-capability and service-tier cases.
use crate::proto_codec::{protocol_for, LaneCaps};
use serde_json::json;

fn anthropic_off() -> crate::ir::IrRequest {
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(
            &json!({"model": "m", "max_tokens": 4096, "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("read");
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off));
    ir.extra.clear();
    ir
}

/// Item 12: on a Bedrock Claude lane declaring `thinking_always_on` an Off ask OMITS `thinking`
/// (`{type:"disabled"}` 400s there); the default lane keeps today's bytes.
#[test]
fn item12_off_omits_thinking_on_an_always_on_lane() {
    let w = protocol_for("bedrock").unwrap();
    let always_on = LaneCaps {
        anthropic_adaptive_thinking: true,
        native_structured_output: true,
        thinking_always_on: true,
        ..Default::default()
    };
    let model = "us.anthropic.claude-fable-5-v1:0";
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), model, &always_on);
    assert!(
        out.pointer("/additionalModelRequestFields/thinking")
            .is_none(),
        "{out}"
    );
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), model, &Default::default());
    assert_eq!(
        out.pointer("/additionalModelRequestFields/thinking"),
        Some(&json!({"type": "disabled"})),
        "{out}"
    );
}

// ───────────────────────── item 8: the shipped Bedrock catalog entry ─────────────────────────

/// Item 8, the writer's half: a lane whose catalog entry turns adaptive thinking and native
/// structured output on (the shipped catalog does so for the newest Claude generations on Bedrock —
/// the host's suite pins that resolution) gets a word reasoning ask written as adaptive thinking.
#[test]
fn item8_a_word_ask_on_an_adaptive_lane_writes_adaptive_thinking() {
    let caps = LaneCaps {
        anthropic_adaptive_thinking: true,
        native_structured_output: true,
        ..LaneCaps::NONE
    };
    // And the writer turns them into the native forms: a word ask on Fable → adaptive thinking.
    let ir = protocol_for("openai")
        .unwrap()
        .reader()
        .read_request(
            &json!({"model": "m", "max_tokens": 4096, "reasoning_effort": "high",
            "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("read");
    let model = "us.anthropic.claude-fable-5-1-v1:0";
    let out = protocol_for("bedrock")
        .unwrap()
        .writer()
        .write_request_for_lane(&ir, model, &caps);
    assert_eq!(
        out.pointer("/additionalModelRequestFields/thinking/type"),
        Some(&json!("adaptive")),
        "{out}"
    );
}

// ─────────────── item 14: citation domain and the Converse serviceTier member ───────────────

/// Item 14 (BED-14): a Converse `web` citation location's `domain` rides IrCitation.domain and is
/// written back beside the url.
#[test]
fn item14_web_citation_domain_round_trips() {
    let converse = json!({
        "output": {"message": {"role": "assistant", "content": [{"citationsContent": {
            "content": [{"text": "Paris is the capital."}],
            "citations": [{"title": "Atlas", "sourceContent": [{"text": "Paris"}],
                "location": {"web": {"url": "https://atlas.example/p", "domain": "atlas.example"}}}]
        }}]}},
        "stopReason": "end_turn",
        "usage": {"inputTokens": 3, "outputTokens": 5, "totalTokens": 8}
    });
    let ir = protocol_for("bedrock")
        .unwrap()
        .reader()
        .read_response(&converse)
        .expect("read");
    let cit = ir
        .content
        .iter()
        .find_map(|b| match b {
            crate::ir::IrBlock::Text { citations, .. } => citations.first().cloned(),
            _ => None,
        })
        .expect("citation");
    assert_eq!(cit.domain.as_deref(), Some("atlas.example"));
    let out = protocol_for("bedrock")
        .unwrap()
        .writer()
        .write_response(&ir);
    let s = out.to_string();
    assert!(
        s.contains(r#""web":{"domain":"atlas.example","url":"https://atlas.example/p"}"#)
            || s.contains(r#""web":{"url":"https://atlas.example/p","domain":"atlas.example"}"#),
        "{out}"
    );
}

/// Item 14 (IR-04): Converse `serviceTier: {type}` reads into the IR tier and a foreign tier ask
/// reaches a Bedrock lane as that member; Auto / Scale have no Converse word (dropped, reported).
#[test]
fn item14_converse_service_tier_maps_both_ways() {
    let ir = protocol_for("bedrock")
        .unwrap()
        .reader()
        .read_request(
            &json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}],
            "serviceTier": {"type": "flex"}}),
        )
        .expect("read");
    assert_eq!(ir.service_tier, Some(crate::ir::IrServiceTier::Flex));
    for (tier, want) in [
        ("priority", Some("priority")),
        ("default", Some("default")),
        ("flex", Some("flex")),
        ("scale", None),
    ] {
        let mut req = protocol_for("openai")
            .unwrap()
            .reader()
            .read_request(&json!({"model": "m", "service_tier": tier,
                "messages": [{"role": "user", "content": "hi"}]}))
            .expect("read");
        req.extra.clear();
        let out = protocol_for("bedrock")
            .unwrap()
            .writer()
            .write_request(&req);
        assert_eq!(
            out.pointer("/serviceTier/type").and_then(|t| t.as_str()),
            want,
            "{tier}: {out}"
        );
        let dropped = protocol_for("bedrock")
            .unwrap()
            .writer()
            .dropped_egress_controls(&req);
        assert_eq!(dropped.contains(&"service_tier"), want.is_none(), "{tier}");
    }
}
