// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a URL-model dialect's request line says.
//!
//! These cells came WITH the reading they exercise: they used to sit beside it in the engine crate,
//! where the reading was bound to a host seam a mounted caller does not hold. Same assertions, same
//! inputs, in the crate that now owns the answer.

use busbar_plane_llm::url::{
    bedrock_model, bedrock_url, gemini_api_version, gemini_is_stream, gemini_json_array,
    gemini_tail, gemini_url, query_has_alt_sse, url_model, BedrockUrl, GeminiUrl,
};

/// The selector is recognized only as a genuine pair, never as a substring of another parameter's
/// value, and order and neighbours do not change the answer.
#[test]
fn the_framing_selector_is_a_pair_and_not_a_substring() {
    // (query, does it select the event framing)
    for (query, selects) in [
        ("alt=sse", true),
        ("key=abc&alt=sse", true),
        ("alt=sse&key=abc", true),
        ("alt=json", false),
        ("", false),
        // A different parameter whose VALUE merely contains the pair.
        ("foo=alt=sse", false),
        // A bare key with no value is not the pair either.
        ("alt", false),
    ] {
        assert_eq!(query_has_alt_sse(query), selects, "`{query}`");
    }
}

/// `gemini_api_version` maps each ingress prefix to the token the native error echoes.
#[test]
fn the_api_version_echoed_is_the_one_the_caller_used() {
    assert_eq!(gemini_api_version("/v1/models/foo:countTokens"), "v1");
    assert_eq!(
        gemini_api_version("/v1beta/models/foo:countTokens"),
        "v1beta"
    );
    // Unexpected shape falls back to the historical default.
    assert_eq!(gemini_api_version("/weird/path"), "v1beta");
}

/// The tail is everything after `/models/`, and an address that has none carries none.
#[test]
fn the_model_scoped_tail_is_what_follows_the_surface() {
    assert_eq!(
        gemini_tail("/v1beta/models/foo:generateContent"),
        "foo:generateContent"
    );
    assert_eq!(gemini_tail("/v1/models/foo"), "foo");
    assert_eq!(gemini_tail("/healthz"), "");
}

/// The split is on the LAST colon, and a half that names nothing names nothing.
#[test]
fn a_tail_names_a_model_and_an_action_or_it_names_neither() {
    assert_eq!(
        gemini_url("gemini-2.0-flash:streamGenerateContent"),
        GeminiUrl::Action {
            model: "gemini-2.0-flash",
            action: "streamGenerateContent"
        }
    );
    // A model whose own name carries a colon: the LAST colon is the action's.
    assert_eq!(
        gemini_url("tuned:models:x:generateContent"),
        GeminiUrl::Action {
            model: "tuned:models:x",
            action: "generateContent"
        }
    );
    // The stable surface shared with another SDK's `model.retrieve` carries no action at all.
    assert_eq!(gemini_url("gemini-2.0-flash"), GeminiUrl::NoAction);
    assert_eq!(gemini_url(":generateContent"), GeminiUrl::NoAction);
    assert_eq!(gemini_url("model:"), GeminiUrl::NoAction);
    assert_eq!(gemini_url(""), GeminiUrl::NoAction);
}

/// One action names a stream; every other action this surface answers does not.
#[test]
fn one_action_asks_for_a_stream() {
    assert!(gemini_is_stream("streamGenerateContent"));
    assert!(!gemini_is_stream("generateContent"));
    assert!(!gemini_is_stream("embedContent"));
    assert!(!gemini_is_stream("predict"));
}

/// The JSON-array framing is what a request that asked to be streamed without `alt=sse` asks for, and nothing else.
#[test]
fn the_array_framing_is_a_stream_without_the_sse_selector() {
    assert!(gemini_json_array(true, None));
    assert!(gemini_json_array(true, Some("key=abc")));
    assert!(!gemini_json_array(true, Some("alt=sse")));
    assert!(!gemini_json_array(false, None));
    assert!(!gemini_json_array(false, Some("alt=sse")));
}

/// Three verbs under one model path, and nothing else is this dialect's address.
#[test]
fn the_verb_is_the_last_segment_and_there_are_three() {
    assert_eq!(bedrock_url("/model/m/converse"), BedrockUrl::Converse);
    assert_eq!(
        bedrock_url("/model/m/converse-stream"),
        BedrockUrl::ConverseStream
    );
    assert_eq!(bedrock_url("/model/m/invoke"), BedrockUrl::Invoke);
    assert_eq!(bedrock_url("/model/m/embed"), BedrockUrl::Unclaimed);
    assert_eq!(bedrock_url("/v1/chat/completions"), BedrockUrl::Unclaimed);
}

/// The model is the middle segment, and an address with an empty one names none.
#[test]
fn the_bedrock_model_is_the_segment_between_the_surface_and_the_verb() {
    assert_eq!(bedrock_model("/model/m/converse"), Some("m"));
    assert_eq!(bedrock_model("/model/a.b-c/converse-stream"), Some("a.b-c"));
    assert_eq!(bedrock_model("/model//converse"), None);
    assert_eq!(bedrock_model("/model/converse"), None);
    assert_eq!(bedrock_model("/v1/chat/completions"), None);
}

/// **THE ONE ENTRY POINT A DRIVER WITH NO HOST NEEDS**, over every shape it answers.
#[test]
fn what_the_request_line_says_for_the_two_dialects_that_keep_the_model_there() {
    let facts = url_model("gemini", "/v1beta/models/gm:generateContent", None)
        .expect("this address names a model");
    assert_eq!(facts.model, "gm");
    assert!(!facts.stream);
    assert!(!facts.gemini_json_array);
    assert_eq!(
        facts.model_not_found_message.as_deref(),
        Some(
            "models/gm is not found for API version v1beta, \
             or is not supported for the task you are trying to perform."
        )
    );

    let facts = url_model("gemini", "/v1/models/gm:streamGenerateContent", None)
        .expect("this address names a model");
    assert!(facts.stream);
    assert!(
        facts.gemini_json_array,
        "a stream with no alt=sse is an array"
    );
    let facts = url_model(
        "gemini",
        "/v1/models/gm:streamGenerateContent",
        Some("alt=sse"),
    )
    .expect("this address names a model");
    assert!(
        !facts.gemini_json_array,
        "the selector chooses the event framing"
    );

    let facts =
        url_model("bedrock", "/model/bm/converse", None).expect("this address names a model");
    assert_eq!(facts.model, "bm");
    assert!(!facts.stream);
    assert_eq!(facts.model_not_found_message, None);
    assert!(
        url_model("bedrock", "/model/bm/converse-stream", None)
            .expect("this address names a model")
            .stream
    );

    // The three ways a request line names no model, which are all the same statement.
    assert!(url_model("openai", "/v1/chat/completions", None).is_none());
    assert!(url_model("gemini", "/v1/models/gm", None).is_none());
    assert!(url_model("bedrock", "/model/bm/invoke", None).is_none());
}
