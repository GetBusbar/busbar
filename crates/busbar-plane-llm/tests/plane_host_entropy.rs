// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN IDENTIFIER THE PLANE MINTS IS THE HOST'S BYTES. The `Plane` surface reaches a codec through
//! the context, and the context carries the host's codec services (`Ctx::host`): a context cannot
//! be built without one, so there is no path on which a minted identifier is drawn from nothing and
//! zero-filled. A host whose entropy is a known non-zero pattern must show up in the identifier.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Plane, Progress};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{LlmPlane, Upstream};

/// One Bedrock lane and one OpenAI lane: a Bedrock answer carries no id, so an OpenAI caller's
/// answer must mint one.
const UPSTREAMS: &[Upstream] = &[
    Upstream {
        lane: LaneId::new("lane-bedrock"),
        host: "bedrock.invalid",
        dialect: "bedrock",
        model: "anthropic.claude-sonnet-4-5",
        caps: busbar_contract::ir::egress_prep::LaneCaps::NONE,
    },
    Upstream {
        lane: LaneId::new("lane-openai"),
        host: "openai.invalid",
        dialect: "openai",
        model: "gpt-4o-mini",
        caps: busbar_contract::ir::egress_prep::LaneCaps::NONE,
    },
];

/// A Bedrock Converse answer with no identifier of its own.
const BEDROCK_ANSWER: &str = r#"{"output":{"message":{"role":"assistant","content":[{"text":"Hello there!"}]}},"stopReason":"end_turn","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}"#;

/// The id an OpenAI caller reads for that answer, when the context hands `host`.
fn minted_id(host: &dyn busbar_contract::codec::CodecHost) -> String {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakPlaneAlloc;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for("openai"), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx_with_host(&arena, &config, &transport, &labels, host);
    let dest = harness::destination("bedrock.invalid", LaneId::new("lane-bedrock"));
    let frames = vec![harness::frame(BEDROCK_ANSWER.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut cursor, &dest, None, &ctx)
        .expect("a Bedrock answer reads")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer is terminal, got {other:?}"),
    };
    let written = plane
        .encode_response(&response, None, &ctx)
        .expect("an OpenAI caller can read it")
        .as_slice()
        .to_vec();
    let v: serde_json::Value = serde_json::from_slice(&written).expect("a document");
    v["id"]
        .as_str()
        .expect("an OpenAI answer always carries an id")
        .to_string()
}

#[test]
fn a_minted_identifier_carries_the_hosts_entropy() {
    for pattern in [0x2A_u8, 0x41] {
        let id = minted_id(&harness::PatternHost(pattern));
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
