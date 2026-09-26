// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Detection tests for the LLM plugin's dialects — RELOCATED from `busbar-core`'s `proto/detect.rs`
//! and `proto/tests/tests.rs` because they NAME DIALECTS, which a neutral crate's tests must not, and
//! then from the LLM codec's suite to the composition root (#83a SD-3), because the fold they
//! exercise is the HOST's: the codec's tests prove the codec's own seam and never reach the host.
//!
//! They exercise the generic detection fold (`busbar_kernel::proto::detect_protocol` /
//! `residual_dialect_for_path`) through the LLM plugin's registered `ProtocolDecl::claims` /
//! `residual_claims` predicates — the same registry a shipped binary folds. The assertions are
//! BYTE-IDENTICAL to the ones the core `if`-ladder carried: this is the proof the ladder→predicate
//! move changed no routing.

use busbar_contract::http::{HeaderMap, HeaderValue};
use busbar_contract::operation::OpVerb;

use busbar_kernel::proto::{detect_protocol, residual_dialect_for_path};

/// The cell a protocol declares, read off the LLM plugin's own declaration.
fn request_handler(proto: &str) -> Option<&'static dyn busbar_contract::codec::RequestHandler> {
    busbar_llm::DECLS
        .iter()
        .find(|d| d.name == proto)
        .and_then(|d| d.handler)
}

/// Seed the process-global protocol registry with THIS plugin's declarations.
///
/// The module doc above claims the registry the test sees is core's `test-support` built-in table.
/// It is not: under `test-support` core's `BUILTIN_DECLS` is `&[]`, so `detect_protocol` and
/// `residual_dialect_for_path` fold an EMPTY registry until something registers. Every test here
/// must seed first, or its verdict is decided by which test ran before it.
fn seeded() {
    // The detection fold is the HOST's, over the declarations the host has registered: register
    // the LLM plugin's six with the host's test seam, as the composition root installs them.
    busbar_kernel::proto::register_test_protocols(busbar_llm::DECLS);
}

fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(*k, HeaderValue::from_static(v));
    }
    h
}

/// The resolver table, exercised through the REAL two-step pipeline:
/// the fold IDs the protocol, then that protocol's `RequestHandler::resolve_operation` decides the
/// operation. Includes collision defaults and the ordering (an Anthropic request to a shared path
/// must not fall through to OpenAI).
#[test]
fn resolver_table() {
    seeded();
    // (path, headers, expected (protocol, operation)) — aliased to keep the type readable.
    type ResolverCase = (
        &'static str,
        &'static [(&'static str, &'static str)],
        Option<(&'static str, OpVerb)>,
    );
    let cases: &[ResolverCase] = &[
        ("/v1/chat/completions", &[], Some(("openai", OpVerb::CHAT))),
        ("/v1/embeddings", &[], Some(("openai", OpVerb::EMBEDDINGS))),
        ("/v1/moderations", &[], Some(("openai", OpVerb::MODERATION))),
        (
            "/v1/images/generations",
            &[],
            Some(("openai", OpVerb::IMAGE)),
        ),
        (
            "/v1/audio/transcriptions",
            &[],
            Some(("openai", OpVerb::TRANSCRIPTION)),
        ),
        (
            "/v1/audio/translations",
            &[],
            Some(("openai", OpVerb::TRANSCRIPTION)),
        ),
        ("/v1/audio/speech", &[], Some(("openai", OpVerb::SPEECH))),
        ("/v2/chat", &[], Some(("cohere", OpVerb::CHAT))),
        ("/v2/embed", &[], Some(("cohere", OpVerb::EMBEDDINGS))),
        ("/v2/rerank", &[], Some(("cohere", OpVerb::RERANK))),
        ("/v1/responses", &[], Some(("responses", OpVerb::CHAT))),
        // anthropic ingress: mandatory header wins even though path is model-prefixed
        (
            "/claude-3/v1/messages",
            &[("anthropic-version", "2023-06-01")],
            Some(("anthropic", OpVerb::CHAT)),
        ),
        // anthropic via x-api-key alone (curl user, no version header)
        (
            "/v1/messages",
            &[("x-api-key", "sk-ant-xxx")],
            Some(("anthropic", OpVerb::CHAT)),
        ),
        // anthropic via anthropic-beta alone
        (
            "/v1/messages",
            &[("anthropic-beta", "prompt-caching-2024-07-31")],
            Some(("anthropic", OpVerb::CHAT)),
        ),
        // gemini via header
        (
            "/v1beta/models/x:generateContent",
            &[("x-goog-api-key", "k")],
            Some(("gemini", OpVerb::CHAT)),
        ),
        // gemini via path verb (no header)
        (
            "/v1beta/models/x:embedContent",
            &[],
            Some(("gemini", OpVerb::EMBEDDINGS)),
        ),
        (
            "/v1beta/models/x:predict",
            &[],
            Some(("gemini", OpVerb::IMAGE)),
        ),
        // bedrock via SigV4 auth; InvokeModel op comes from the BODY (see body cases below)
        (
            "/model/m/converse",
            &[("authorization", "AWS4-HMAC-SHA256 Credential=x")],
            Some(("bedrock", OpVerb::CHAT)),
        ),
        // non-operation paths → None
        ("/v1/models", &[], None),
        ("/healthz", &[], None),
    ];
    for (path, headers, expect) in cases {
        let got = detect_protocol(path, &hm(headers)).and_then(|proto| {
            request_handler(proto)
                .and_then(|rh| rh.resolve_operation(path, b""))
                .map(|op| (proto, op))
        });
        assert_eq!(got, *expect, "path {path:?} headers {headers:?}");
    }

    // BODY-disambiguated cases (the RequestHandler needs more than the path):
    let body_cases: &[(&str, &[u8], (&str, OpVerb))] = &[
            ("/model/m/invoke", br#"{"inputText":"hi"}"#, ("bedrock", OpVerb::EMBEDDINGS)),
            ("/model/m/invoke", br#"{"taskType":"TEXT_IMAGE","textToImageParams":{"text":"x"}}"#,
             ("bedrock", OpVerb::IMAGE)),
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"inline_data":{"mime_type":"audio/wav","data":"AA=="}}]}]}"#,
             ("gemini", OpVerb::TRANSCRIPTION)),
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"responseModalities":["AUDIO"]}}"#,
             ("gemini", OpVerb::SPEECH)),
            // an inline IMAGE part is multimodal CHAT, not audio
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"inline_data":{"mime_type":"image/png","data":"AA=="}}]}]}"#,
             ("gemini", OpVerb::CHAT)),
        ];
    for (path, body, (want_proto, want_op)) in body_cases {
        let proto = detect_protocol(path, &hm(&[])).expect(path);
        assert_eq!(proto, *want_proto, "protocol for {path:?}");
        let op = request_handler(proto)
            .and_then(|rh| rh.resolve_operation(path, body))
            .expect(path);
        assert_eq!(op, *want_op, "operation for {path:?} with body");
    }
}

#[test]
fn mandatory_header_beats_path_ordering() {
    seeded();
    // an Anthropic request to a path that also looks bearer-ish must resolve Anthropic, not fall through.
    let p = detect_protocol("/v1/messages", &hm(&[("anthropic-version", "2023-06-01")])).unwrap();
    assert_eq!(p, "anthropic");
}

/// Conformance (`residual_dialect_for_path`): a `GET /v1/models/<id>` whose id legitimately
/// CONTAINS a colon (OpenAI fine-tuned `ft:...`, deployment-style `gpt-4o:deployment`) must
/// classify as OpenAI — NOT Gemini — so `model.retrieve` gets an OpenAI-decodable error envelope.
/// Only the known Gemini ACTION suffixes (`:generateContent`, …) are Gemini.
#[test]
fn test_residual_dialect_colon_model_id_is_openai_not_gemini() {
    seeded();
    // OpenAI fine-tuned model id (multiple colons) on the model.retrieve path → OpenAI.
    assert_eq!(
        residual_dialect_for_path("/v1/models/ft:gpt-3.5-turbo:my-org::abc123"),
        Some("openai"),
        "a colon-bearing OpenAI fine-tuned model id must stay OpenAI"
    );
    // Azure-style deployment id with a colon → OpenAI.
    assert_eq!(
        residual_dialect_for_path("/v1/models/gpt-4o:deployment"),
        Some("openai")
    );
    // Plain model id (no colon) → OpenAI.
    assert_eq!(
        residual_dialect_for_path("/v1/models/gpt-4o"),
        Some("openai")
    );
    // A genuine Gemini action suffix → Gemini.
    assert_eq!(
        residual_dialect_for_path("/v1/models/gemini-pro:generateContent"),
        Some("gemini"),
        "the Gemini :generateContent action suffix still classifies as Gemini"
    );
    assert_eq!(
        residual_dialect_for_path("/v1/models/gemini-pro:streamGenerateContent"),
        Some("gemini")
    );
    assert_eq!(
        residual_dialect_for_path("/v1/models/text-embedding-004:embedContent"),
        Some("gemini")
    );
    assert_eq!(
        residual_dialect_for_path("/v1/models/gemini-pro:countTokens"),
        Some("gemini")
    );
}

/// A PATH THAT NAMES NO DIALECT ANSWERS `None`, and that is the whole of the change: the classifier
/// used to end in `else { openai }`, so it asserted an OpenAI identity for every path it did not
/// recognise — including `/mcp`, a path an operator may have MOUNTED as another plane entirely. The
/// site composing a reply decides what to say to an unknown caller (`ingress::native`); the
/// classifier's job is to say what it knows, and here it knows nothing.
#[test]
fn test_residual_dialect_names_none_rather_than_defaulting_to_openai() {
    seeded();
    // POSITIVE CONTROL. Every assertion below is a negative, and an UNSEEDED registry answers `None`
    // for every path — so this test passed for the wrong reason, and would have kept passing if
    // production had regressed to the old `else { openai }` default. Prove the fold is live first.
    assert_eq!(
        residual_dialect_for_path("/v1/models/gpt-4o"),
        Some("openai"),
        "the residual fold must be live, or the `None` assertions below prove nothing"
    );
    for path in [
        "/",
        "/stats",
        "/mcp",
        "/mcp/anything",
        "/a2a",
        "/totally/unknown/path",
        // `/model/...` without a Converse suffix: the arm exists and deliberately declines.
        "/model/foo/bar",
    ] {
        assert_eq!(
            residual_dialect_for_path(path),
            None,
            "`{path}` names no LLM dialect — the classifier must say so, not answer `openai`"
        );
    }
}
