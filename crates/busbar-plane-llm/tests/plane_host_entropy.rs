// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN IDENTIFIER THE PLANE MINTS IS THE HOST'S BYTES. The door reaches a codec through the host it
//! is handed (`busbar_contract::codec::CodecHost`), so there is no path on which a minted identifier
//! is drawn from nothing and zero-filled. A host whose entropy is a known non-zero pattern must show
//! up in the identifier the served whole-answer translation (`exchange::reply::whole::translate`)
//! writes.

use busbar_contract::operation::OpVerb;
use busbar_plane_llm::exchange::reply::whole::{self, WholeCtx, WholeEnd};

/// A host whose entropy is one repeated, non-zero byte, and which holds no clock.
struct PatternHost(u8);

impl busbar_contract::codec::CodecHost for PatternHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        out.fill(self.0);
        true
    }

    fn wall_clock_now(&self) -> Option<u64> {
        None
    }
}

/// A Bedrock Converse answer with no identifier of its own.
const BEDROCK_ANSWER: &str = r#"{"output":{"message":{"role":"assistant","content":[{"text":"Hello there!"}]}},"stopReason":"end_turn","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}"#;

/// The id an OpenAI caller reads for that answer, when the door hands `host`.
fn minted_id(host: &dyn busbar_contract::codec::CodecHost) -> String {
    let ctx = WholeCtx {
        ingress: "openai",
        egress: "bedrock",
        operation: OpVerb::CHAT,
        model: "anthropic.claude-sonnet-4-5",
        wants_stream: false,
        json_array: false,
        request: None,
        now_s: 1_752_000_000,
        elapsed_ms: None,
        translate_cap: busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
    };
    let w = whole::translate(host, &ctx, 200, BEDROCK_ANSWER.as_bytes());
    assert_eq!(w.end, WholeEnd::Delivered, "{:?}", w.refused);
    let v: serde_json::Value = serde_json::from_slice(&w.answer.body).expect("a document");
    v["id"]
        .as_str()
        .expect("an OpenAI answer always carries an id")
        .to_string()
}

#[test]
fn a_minted_identifier_carries_the_hosts_entropy() {
    for pattern in [0x2A_u8, 0x41] {
        let id = minted_id(&PatternHost(pattern));
        let token = id
            .strip_prefix("chatcmpl-")
            .unwrap_or_else(|| panic!("the native prefix, got {id:?}"));
        let expected =
            busbar_plane_llm::codec::dialect::BASE62_ALPHABET[usize::from(pattern % 62)] as char;
        assert_ne!(
            expected, '0',
            "the pattern must not map to the zero-fill character"
        );
        assert!(
            !token.is_empty() && token.chars().all(|c| c == expected),
            "every character of the minted token is the host's byte {pattern:#04x} \
             ({expected:?}), never a zero fill: got {id:?}"
        );
    }
}
