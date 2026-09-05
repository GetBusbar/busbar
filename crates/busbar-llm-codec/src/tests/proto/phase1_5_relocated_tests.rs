// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PURE-DIALECT unit tests RELOCATED here from `busbar-core`.
//!
//! Each of these named a witnessed dialect codec fn directly (`bedrock::synth_amzn_request_id`,
//! `openai_responses::read_reasoning_*`) inside a core test, which a neutral crate's tests must not.
//! They exercise nothing but the dialect codec, so they belong beside it in the LLM plugin. Every
//! assertion is BYTE-IDENTICAL to the pre-relocation core suite.

use super::*;
// `IrRequest::shape()` is a method of the `IrFacts` trait — bring it into scope for the
// exhaustiveness guard (the core suite imported it as `crate::ir::facts::IrFacts`).
use busbar_substrate_values::ir::facts::IrFacts;

/// UUID-v4 shape checker — a private copy of the core auth suite's helper (which stays in core for
/// its other callers), so the relocated `synth_amzn_request_id` shape test carries its own oracle.
fn assert_uuid_v4_shaped(id: &str) {
    let segs: Vec<&str> = id.split('-').collect();
    assert_eq!(
        segs.iter().map(|s| s.len()).collect::<Vec<_>>(),
        vec![8, 4, 4, 4, 12],
        "x-amzn-requestid must be UUID-v4 shaped (8-4-4-4-12), got '{id}'"
    );
    assert!(
        id.chars()
            .all(|c| c == '-' || c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "UUID must be lowercase hex with dashes only, got '{id}'"
    );
    // Version nibble: first char of the third group.
    assert_eq!(
        segs[2].chars().next(),
        Some('4'),
        "UUID version nibble must be 4, got '{id}'"
    );
    // Variant nibble: first char of the fourth group must be one of 8,9,a,b.
    assert!(
        matches!(segs[3].chars().next(), Some('8' | '9' | 'a' | 'b')),
        "UUID variant nibble must be 8/9/a/b, got '{id}'"
    );
}

#[test]
fn test_synth_amzn_request_id_is_uuid_v4() {
    // Regression for the flat-32-hex-no-dashes format: a Bedrock x-amzn-RequestId must be a
    // CSPRNG UUID-v4, matching real AWS. The auth path mints this id through the CANONICAL
    // `bedrock::synth_amzn_request_id` (via `proxy::ingress_error` → `attach_bedrock_error_headers`),
    // not a private copy — assert the canonical fn's shape so the bedrock auth-failure header
    // contract stays covered. Two consecutive ids must differ (entropy-sourced, not a predictable
    // timestamp||counter).
    let a = bedrock::synth_amzn_request_id().expect("entropy must be available under test");
    let b = bedrock::synth_amzn_request_id().expect("entropy must be available under test");
    assert_uuid_v4_shaped(&a);
    assert_uuid_v4_shaped(&b);
    assert_ne!(a, b, "consecutive synthetic request ids must differ");
}

/// The reader's own accept/skip rules for a `reasoning` item's `encrypted_content`: an empty string
/// or a non-string yields no usable blob. That filter is the READER's —
/// `read_reasoning_encrypted_content` — and this points at it directly, where it lives.
#[test]
fn responses_reasoning_reader_rejects_malformed_encrypted_content() {
    let empty_string: serde_json::Value =
        serde_json::json!({"type": "reasoning", "encrypted_content": ""});
    assert!(openai_responses::read_reasoning_encrypted_content(&empty_string).is_none());

    let non_string: serde_json::Value =
        serde_json::json!({"type": "reasoning", "encrypted_content": 123});
    assert!(openai_responses::read_reasoning_encrypted_content(&non_string).is_none());
}

/// A single text-bearing reasoning part (in EITHER `content[]` or `summary[]` alone) must come
/// through the reader's own walk still BORROWED.
#[test]
fn responses_single_part_reasoning_text_borrows() {
    let content_only = serde_json::json!({
        "type": "reasoning",
        "content": [{"type": "reasoning_text", "text": "one part"}]
    });
    assert!(matches!(
        openai_responses::read_reasoning_text(&content_only),
        std::borrow::Cow::Borrowed(_)
    ));

    let summary_only = serde_json::json!({
        "type": "reasoning",
        "summary": [{"type": "summary_text", "text": "just a summary"}]
    });
    assert!(matches!(
        openai_responses::read_reasoning_text(&summary_only),
        std::borrow::Cow::Borrowed(_)
    ));
}

/// Two `content[]` parts + one `summary[]` part must still allocate — and concatenate
/// content-array-then-summary-array, with NO separator (the deliberate separator-less concat).
#[test]
fn responses_multi_part_reasoning_text_concatenates() {
    let item = serde_json::json!({
        "type": "reasoning",
        "content": [
            {"type": "reasoning_text", "text": "first "},
            {"type": "reasoning_text", "text": "second "}
        ],
        "summary": [{"type": "summary_text", "text": "third"}]
    });
    let t = openai_responses::read_reasoning_text(&item);
    assert!(matches!(t, std::borrow::Cow::Owned(_)));
    assert_eq!(t.as_ref(), "first second third");
}

/// The bedrock forward-kind → `x-amzn-errortype`/`__type` mapping, for the kinds the ingress error
/// path emits. RELOCATED from core's `ingress` and `proxy` suites,
/// which asserted the same mapping directly via `bedrock::error_kind_to_bedrock_type`; the CORE
/// tests keep their neutral `hdr == expected` header-correctness check (driven through the neutral
/// `ingress_error` seam), while the dialect mapping's identity is proven here beside the codec.
#[test]
fn error_kind_to_bedrock_type_covers_ingress_emitted_kinds() {
    use busbar_core::proxy::{
        KIND_INSUFFICIENT_QUOTA, KIND_INVALID_REQUEST, KIND_PERMISSION, KIND_RATE_LIMIT,
    };
    assert_eq!(
        bedrock::error_kind_to_bedrock_type(KIND_INVALID_REQUEST),
        "ValidationException"
    );
    assert_eq!(
        bedrock::error_kind_to_bedrock_type(KIND_RATE_LIMIT),
        "ThrottlingException"
    );
    assert_eq!(
        bedrock::error_kind_to_bedrock_type(KIND_PERMISSION),
        "AccessDeniedException"
    );
    assert_eq!(
        bedrock::error_kind_to_bedrock_type(KIND_INSUFFICIENT_QUOTA),
        "ServiceQuotaExceededException"
    );
}

/// THE EXHAUSTIVENESS GUARD: every registered protocol has a reader that produces a readable IR, so
/// a seventh protocol is covered by REGISTERING rather than by an arm added anywhere. Names the
/// witnessed codec (`protocol_for(...).reader()`) and the concrete IR (`ir.shape()` / `ir::project`),
/// so it lives beside them in the plugin (RELOCATED from core).
#[test]
fn every_known_protocol_has_a_declared_reasoning_wire_shape() {
    for &proto in known_protocols() {
        let p = protocol_for(proto)
            .unwrap_or_else(|| panic!("'{proto}' is in KNOWN_PROTOCOLS but is not registered"));
        // A minimal, universally-legal body for the dialect's conversation container: whichever key
        // this protocol reads, an absent one is legal and yields an empty conversation.
        let empty: serde_json::Value =
            serde_json::json!({"messages": [], "contents": [], "input": []});
        let ir = p
            .reader()
            .read_request(&empty)
            .unwrap_or_else(|e| panic!("'{proto}' cannot read an empty conversation: {e:?}"));
        let shape = ir.shape();
        assert_eq!(
            shape.turn_count, 0,
            "'{proto}' invented turns for an empty conversation"
        );
        assert_eq!(shape.text_chars, 0);
        assert!(
            crate::ir::project(&ir).is_empty(),
            "'{proto}' projected content for an empty conversation"
        );
    }
}
