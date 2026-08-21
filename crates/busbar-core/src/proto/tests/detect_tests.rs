// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/proto/detect.rs`.

use super::*;
use axum::http::{HeaderMap, HeaderValue};

fn hm(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (k, v) in pairs {
        h.insert(*k, HeaderValue::from_static(v));
    }
    h
}

/// The resolver table, exercised through the REAL two-step pipeline:
/// Router IDs the protocol, then that protocol's `RequestHandler::resolve_operation` decides the
/// operation. Includes collision defaults and the ordering (an Anthropic request to a shared path
/// must not fall through to OpenAI).
#[test]
fn resolver_table() {
    use crate::operation::Operation;
    // (path, headers, expected (protocol, operation)) — aliased to keep the type readable.
    type ResolverCase = (
        &'static str,
        &'static [(&'static str, &'static str)],
        Option<(&'static str, Operation)>,
    );
    let cases: &[ResolverCase] = &[
        (
            "/v1/chat/completions",
            &[],
            Some(("openai", Operation::CHAT)),
        ),
        (
            "/v1/embeddings",
            &[],
            Some(("openai", Operation::EMBEDDINGS)),
        ),
        (
            "/v1/moderations",
            &[],
            Some(("openai", Operation::MODERATION)),
        ),
        (
            "/v1/images/generations",
            &[],
            Some(("openai", Operation::IMAGE)),
        ),
        (
            "/v1/audio/transcriptions",
            &[],
            Some(("openai", Operation::TRANSCRIPTION)),
        ),
        (
            "/v1/audio/translations",
            &[],
            Some(("openai", Operation::TRANSCRIPTION)),
        ),
        ("/v1/audio/speech", &[], Some(("openai", Operation::SPEECH))),
        ("/v2/chat", &[], Some(("cohere", Operation::CHAT))),
        ("/v2/embed", &[], Some(("cohere", Operation::EMBEDDINGS))),
        ("/v2/rerank", &[], Some(("cohere", Operation::RERANK))),
        ("/v1/responses", &[], Some(("responses", Operation::CHAT))),
        // anthropic ingress: mandatory header wins even though path is model-prefixed
        (
            "/claude-3/v1/messages",
            &[("anthropic-version", "2023-06-01")],
            Some(("anthropic", Operation::CHAT)),
        ),
        // anthropic via x-api-key alone (curl user, no version header)
        (
            "/v1/messages",
            &[("x-api-key", "sk-ant-xxx")],
            Some(("anthropic", Operation::CHAT)),
        ),
        // anthropic via anthropic-beta alone
        (
            "/v1/messages",
            &[("anthropic-beta", "prompt-caching-2024-07-31")],
            Some(("anthropic", Operation::CHAT)),
        ),
        // gemini via header
        (
            "/v1beta/models/x:generateContent",
            &[("x-goog-api-key", "k")],
            Some(("gemini", Operation::CHAT)),
        ),
        // gemini via path verb (no header)
        (
            "/v1beta/models/x:embedContent",
            &[],
            Some(("gemini", Operation::EMBEDDINGS)),
        ),
        (
            "/v1beta/models/x:predict",
            &[],
            Some(("gemini", Operation::IMAGE)),
        ),
        // bedrock via SigV4 auth; InvokeModel op comes from the BODY (see body cases below)
        (
            "/model/m/converse",
            &[("authorization", "AWS4-HMAC-SHA256 Credential=x")],
            Some(("bedrock", Operation::CHAT)),
        ),
        // non-operation paths → None
        ("/v1/models", &[], None),
        ("/healthz", &[], None),
    ];
    for (path, headers, expect) in cases {
        let got = protocol_id(path, &hm(headers)).and_then(|proto| {
            crate::handlers::request_handler(proto)
                .and_then(|rh| rh.resolve_operation(path, b""))
                .map(|op| (proto, op))
        });
        assert_eq!(got, *expect, "path {path:?} headers {headers:?}");
    }

    // BODY-disambiguated cases (the RequestHandler needs more than the path):
    let body_cases: &[(&str, &[u8], (&str, Operation))] = &[
            ("/model/m/invoke", br#"{"inputText":"hi"}"#, ("bedrock", Operation::EMBEDDINGS)),
            ("/model/m/invoke", br#"{"taskType":"TEXT_IMAGE","textToImageParams":{"text":"x"}}"#,
             ("bedrock", Operation::IMAGE)),
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"inline_data":{"mime_type":"audio/wav","data":"AA=="}}]}]}"#,
             ("gemini", Operation::TRANSCRIPTION)),
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"text":"hi"}]}],"generationConfig":{"responseModalities":["AUDIO"]}}"#,
             ("gemini", Operation::SPEECH)),
            // an inline IMAGE part is multimodal CHAT, not audio
            ("/v1beta/models/x:generateContent",
             br#"{"contents":[{"parts":[{"inline_data":{"mime_type":"image/png","data":"AA=="}}]}]}"#,
             ("gemini", Operation::CHAT)),
        ];
    for (path, body, (want_proto, want_op)) in body_cases {
        let proto = protocol_id(path, &hm(&[])).expect(path);
        assert_eq!(proto, *want_proto, "protocol for {path:?}");
        let op = crate::handlers::request_handler(proto)
            .and_then(|rh| rh.resolve_operation(path, body))
            .expect(path);
        assert_eq!(op, *want_op, "operation for {path:?} with body");
    }
}

#[test]
fn mandatory_header_beats_path_ordering() {
    // an Anthropic request to a path that also looks bearer-ish must resolve Anthropic, not fall through.
    let p = protocol_id("/v1/messages", &hm(&[("anthropic-version", "2023-06-01")])).unwrap();
    assert_eq!(p, "anthropic");
}
