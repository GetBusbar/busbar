// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE STREAM, ONE IDENTITY — across every dialect writer that stamps a stream id.
//!
//! A stream is not guaranteed to carry exactly one `MessageStart`. Five of the six readers gate it
//! on their own started flag, but the Anthropic reader emits it 1:1 with the upstream
//! `message_start` frame, so ANY egress fed from an Anthropic ingress can see two. Every writer
//! below stamped the second one with a FRESH synthesized id, so one message announced itself twice
//! under two different identities — and the official SDKs latch the id from the first frame that
//! supplies it, leaving the client correlating against an id nothing else in the stream mentions.
//!
//! The ids fed here are DISTINCT on purpose. Passing the same literal twice cannot see the defect:
//! a writer that re-minted the identity would still hand back the id the first event named.

use super::*;
use crate::ir::{IrRole, IrStreamEvent};

/// A `MessageStart` naming `id`, as an Anthropic-ingress duplicate would deliver it.
fn start(id: &str) -> IrStreamEvent {
    IrStreamEvent::MessageStart {
        role: IrRole::Assistant,
        usage: None,
        id: Some(id.to_string()),
        created: Some(1_700_000_000),
        model: Some("m".to_string()),
    }
}

/// The id each writer stamps on its opening frame, at that dialect's own JSON pointer.
fn opening_id(frame: &serde_json::Value, pointer: &str) -> String {
    frame
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_else(|| panic!("no id at {pointer} in {frame}"))
        .to_string()
}

/// Drive one writer through `MessageStart("first")`, `MessageStart("second")` and return the id
/// each opening frame carried.
fn two_starts<W: ProtocolWriter>(w: &W, pointer: &str) -> (String, String) {
    let one = w.write_response_event(&start("id_first")).expect("frame");
    let two = w.write_response_event(&start("id_second")).expect("frame");
    (opening_id(&one.1, pointer), opening_id(&two.1, pointer))
}

#[test]
fn a_duplicate_message_start_keeps_the_stream_id_it_opened_with() {
    // Each dialect's own home for the stream id, in the frame its `MessageStart` arm writes.
    let w = anthropic_writer();
    let anthropic = two_starts(&w, "/message/id");
    assert_eq!(
        anthropic.0, anthropic.1,
        "anthropic: one message_start id per stream, got {anthropic:?}"
    );
    assert_eq!(anthropic.0, "id_first");

    let w = OpenAiWriter;
    let openai = two_starts(&w, "/id");
    assert_eq!(
        openai.0, openai.1,
        "openai chat: one chunk id per stream, got {openai:?}"
    );
    assert_eq!(openai.0, "id_first");

    let w = GeminiWriter;
    let gemini = two_starts(&w, "/responseId");
    assert_eq!(
        gemini.0, gemini.1,
        "gemini: one responseId per stream, got {gemini:?}"
    );
    assert_eq!(gemini.0, "id_first");

    let w = CohereWriter;
    let cohere = two_starts(&w, "/id");
    assert_eq!(
        cohere.0, cohere.1,
        "cohere: one message-start id per stream, got {cohere:?}"
    );
    assert_eq!(cohere.0, "id_first");

    let w = ResponsesWriter;
    let responses = two_starts(&w, "/response/id");
    assert_eq!(
        responses.0, responses.1,
        "responses: one response.id per stream, got {responses:?}"
    );
    assert_eq!(responses.0, "id_first");
}

#[test]
fn a_synthesized_stream_id_is_also_minted_only_once() {
    // The cross-protocol case: `StreamTranslate` strips the foreign id, so every writer synthesizes
    // one. A duplicate must replay that synthesized id rather than minting a second — the arm that
    // invents an id is exactly the arm where a re-mint is invisible to an id-passthrough test.
    let stripped = || IrStreamEvent::MessageStart {
        role: IrRole::Assistant,
        usage: None,
        id: None,
        created: None,
        model: Some("m".to_string()),
    };
    // Each writer is bound to a local: the value-namespace const inlines a FRESH instance per use,
    // and the per-stream cell being proved lives on the instance.
    for (name, a, b) in [
        {
            let w = anthropic_writer();
            let (a, b) = two_starts_stripped(&w, "/message/id", &stripped);
            ("anthropic", a, b)
        },
        {
            let w = OpenAiWriter;
            let (a, b) = two_starts_stripped(&w, "/id", &stripped);
            ("openai", a, b)
        },
        {
            let w = GeminiWriter;
            let (a, b) = two_starts_stripped(&w, "/responseId", &stripped);
            ("gemini", a, b)
        },
        {
            let w = CohereWriter;
            let (a, b) = two_starts_stripped(&w, "/id", &stripped);
            ("cohere", a, b)
        },
        {
            let w = ResponsesWriter;
            let (a, b) = two_starts_stripped(&w, "/response/id", &stripped);
            ("responses", a, b)
        },
    ] {
        assert_eq!(
            a, b,
            "{name}: a synthesized stream id is minted once, not once per MessageStart"
        );
        assert!(!a.is_empty(), "{name}: an identity frame states an id");
    }
}

/// The identity-stripped twin of [`two_starts`].
fn two_starts_stripped<W: ProtocolWriter>(
    w: &W,
    pointer: &str,
    ev: &dyn Fn() -> IrStreamEvent,
) -> (String, String) {
    let one = w.write_response_event(&ev()).expect("frame");
    let two = w.write_response_event(&ev()).expect("frame");
    (opening_id(&one.1, pointer), opening_id(&two.1, pointer))
}
