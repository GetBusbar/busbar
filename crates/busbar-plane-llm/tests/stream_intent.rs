// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Whether the client asked for a stream is read from wherever the dialect carries the intent.
//!
//! Most dialects carry it as a `stream` member of the request body. One carries it in the request
//! target instead: the same model-scoped surface has a `:generateContent` action for a whole answer
//! and a `:streamGenerateContent` action for a streamed one, and a client that wants a stream names
//! the streaming action and sends no `stream` member at all. Reading only the body member answers
//! that client "not a stream", and the stream it explicitly asked for is silently served whole.
//!
//! `FACT_STREAM` is a draft fact sealed at decode, so this drives the real `decode_ingress` and
//! reads the fact off the draft it seals.

mod harness;

use busbar_contract::bounded::{FactValue, Labels};
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::meta;
use busbar_plane_llm::{LlmPlane, Upstream};

const GEMINI_UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-gemini"),
    host: "gemini.invalid",
    dialect: "gemini",
    model: "gemini-2.0-flash",
}];

const OPENAI_UPSTREAMS: &[Upstream] = &[Upstream {
    lane: LaneId::new("lane-openai"),
    host: "openai.invalid",
    dialect: "openai",
    model: "gpt-4o",
}];

/// Decode one request against the given target and return whether `FACT_STREAM` was sealed true.
fn decoded_stream(path: &str, upstreams: &'static [Upstream], body: &[u8]) -> bool {
    let plane = LlmPlane::new(upstreams);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(path, &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(body)];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the request decodes")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("expected one complete unit, got {other:?}"),
    };
    matches!(
        draft.facts.get(meta::FACT_STREAM),
        Some(FactValue::Bool(true))
    )
}

const GEMINI_BODY: &[u8] = br#"{"contents":[{"role":"user","parts":[{"text":"Hi"}]}]}"#;

/// A Gemini request that names the streaming action carries stream intent in the target, not the
/// body, and the fact must reflect that.
#[test]
fn a_gemini_stream_action_target_is_a_stream() {
    assert!(
        decoded_stream(
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
            GEMINI_UPSTREAMS,
            GEMINI_BODY,
        ),
        "the :streamGenerateContent action is a stream even with no body `stream` member"
    );
}

/// The same dialect's whole-answer action is not a stream.
#[test]
fn a_gemini_whole_action_target_is_not_a_stream() {
    assert!(
        !decoded_stream(
            "/v1beta/models/gemini-2.0-flash:generateContent",
            GEMINI_UPSTREAMS,
            GEMINI_BODY,
        ),
        "the :generateContent action is a whole answer"
    );
}

/// The body member still carries the intent for the dialects that spell it there.
#[test]
fn a_body_stream_member_is_still_read() {
    assert!(
        decoded_stream(
            "/v1/chat/completions",
            OPENAI_UPSTREAMS,
            br#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Hi"}]}"#,
        ),
        "a body `stream:true` is a stream"
    );
    assert!(
        !decoded_stream(
            "/v1/chat/completions",
            OPENAI_UPSTREAMS,
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hi"}]}"#,
        ),
        "a body with no `stream` member is a whole answer"
    );
}
