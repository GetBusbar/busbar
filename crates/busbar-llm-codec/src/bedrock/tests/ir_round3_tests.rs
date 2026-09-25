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

/// The `bedrock` entry's `model_capabilities` from the shipped providers.yaml (written in flow /
/// JSON style so this crate can read it without a YAML parser).
fn shipped_bedrock_rules() -> Vec<busbar_substrate_values::ir::lane_caps::ModelCapabilities> {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../providers.yaml"))
        .expect("read providers.yaml");
    let entry = &raw[raw.find("\nbedrock:\n").expect("bedrock entry")..];
    let rules = &entry[entry
        .find("  model_capabilities:")
        .expect("bedrock model_capabilities")..];
    let json = &rules[rules.find('[').unwrap()..=rules.find("\n  ]").unwrap() + 3];
    serde_json::from_str(json).expect("flow-style rules parse as JSON")
}

fn shipped_caps(model: &str) -> LaneCaps {
    busbar_substrate_values::ir::lane_caps::resolve_lane_caps(
        Default::default(),
        &shipped_bedrock_rules(),
        model,
    )
}

/// Item 8: the catalog turns adaptive thinking + native structured output on for the newest
/// Claude generations on Bedrock, native structured output alone for the 4.5/4.6 models AWS lists,
/// and nothing for any other model.
#[test]
fn item8_shipped_bedrock_catalog_declares_claude_lane_caps() {
    for newest in [
        "anthropic.claude-opus-4-7-v1:0",
        "us.anthropic.claude-opus-5-v1:0",
        "global.anthropic.claude-sonnet-5-20260101-v1:0",
        "us.anthropic.claude-fable-5-1-v1:0",
    ] {
        let caps = shipped_caps(newest);
        assert!(
            caps.anthropic_adaptive_thinking && caps.native_structured_output,
            "{newest}: {caps:?}"
        );
    }
    for listed in [
        "anthropic.claude-sonnet-4-5-20250929-v1:0",
        "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "anthropic.claude-opus-4-5-20251101-v1:0",
        "us.anthropic.claude-opus-4-6-v1",
    ] {
        let caps = shipped_caps(listed);
        assert!(
            caps.native_structured_output && !caps.anthropic_adaptive_thinking,
            "{listed}: {caps:?}"
        );
    }
    for other in [
        "anthropic.claude-sonnet-4-6",
        "anthropic.claude-3-7-sonnet-20250219-v1:0",
        "amazon.nova-pro-v1:0",
    ] {
        assert_eq!(shipped_caps(other), LaneCaps::NONE, "{other}");
    }
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
        .write_request_for_lane(&ir, model, &shipped_caps(model));
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
