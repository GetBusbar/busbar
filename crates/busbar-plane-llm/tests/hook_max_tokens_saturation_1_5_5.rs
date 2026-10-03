// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The size signal a hook sees for an output cap above `u32::MAX`, as 1.5.5 projected it.
//!
//! In 1.5.5 the hook projection read the cap from the ingress body and saturated it
//! (`max_tokens_for`: `u32::try_from(n).unwrap_or(u32::MAX)`), and the v1.5.5 hook tests pinned it:
//! `max_tokens_saturates_not_wraps` expected `Some(u32::MAX)` for `5_000_000_000`, and
//! `max_tokens_signal_is_dialect_aware_for_responses` expected `Some(u32::MAX)` for `u64::MAX`.
//! Predev builds the signal from the IR, whose readers drop an out-of-range cap to `None`, and the
//! ported test was changed to expect `None`. A routing hook keyed on the size signal now reads
//! "no cap" where 1.5.5 told it "the largest cap there is". These tests hold the 1.5.5 value.

use busbar_contract::ir::facts::IrFacts;
use busbar_plane_llm::codec::proto_codec::protocol_for;

fn hook_max_tokens(dialect: &str, body: serde_json::Value) -> Option<u32> {
    let protocol = protocol_for(dialect).expect("the dialect has a codec");
    let ir = protocol
        .reader()
        .read_request(&body)
        .expect("the request reads");
    ir.shape().max_tokens
}

#[test]
fn an_anthropic_cap_above_u32_saturates() {
    let body = serde_json::json!({
        "model": "m0",
        "max_tokens": 5_000_000_000u64,
        "messages": [{"role": "user", "content": "hi"}]
    });
    assert_eq!(hook_max_tokens("anthropic", body), Some(u32::MAX));
}

#[test]
fn an_openai_cap_above_u32_saturates() {
    let body = serde_json::json!({
        "model": "m0",
        "max_tokens": u64::MAX,
        "messages": [{"role": "user", "content": "hi"}]
    });
    assert_eq!(hook_max_tokens("openai", body), Some(u32::MAX));
}
