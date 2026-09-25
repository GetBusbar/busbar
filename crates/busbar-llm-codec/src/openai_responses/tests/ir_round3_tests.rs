// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! IR mapping round 3 (IR-INTEGRATE, Q57): the Responses share of items 11, 12 and 16.
use crate::proto_codec::{protocol_for, LaneCaps};
use serde_json::json;

fn anthropic_off() -> crate::ir::IrRequest {
    let mut ir = protocol_for("anthropic")
        .unwrap()
        .reader()
        .read_request(
            &json!({"model": "m", "max_tokens": 64, "thinking": {"type": "disabled"},
            "messages": [{"role": "user", "content": "hi"}]}),
        )
        .expect("read");
    assert_eq!(ir.reasoning, Some(crate::ir::IrReasoningAsk::Off));
    ir.extra.clear();
    ir
}

/// Item 12: a lane declaring `reasoning_none` gets `reasoning.effort: "none"` for an Off ask; the
/// default lane keeps today's bytes (omitted).
#[test]
fn item12_off_is_reasoning_effort_none_on_a_declaring_lane() {
    let w = protocol_for("responses").unwrap();
    let none_lane = LaneCaps {
        reasoning_none: true,
        ..Default::default()
    };
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), "gpt-5.1", &none_lane);
    assert_eq!(out["reasoning"], json!({"effort": "none"}), "{out}");
    let out = w
        .writer()
        .write_request_for_lane(&anthropic_off(), "gpt-4o", &Default::default());
    assert!(out.get("reasoning").is_none(), "{out}");
}
