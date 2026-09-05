// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the arrival helpers: the gemini `alt=sse` selector recognizer and the gemini API\n//! version parse. Relocated out of `arrival.rs` per the tests-in-their-own-file convention.

use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use busbar_substrate::ingress::arrival::{ArrivalCtx, ArrivalHost};

use super::{
    bedrock_path_parse, gemini_api_version, gemini_path_parse, gemini_rest, query_has_alt_sse,
    PathArrivalFacts,
};

/// `query_has_alt_sse` recognizes the gemini SSE selector only as a genuine `alt=sse` pair, not
/// a substring of another param's value, and ignores order / other params. Moved here with the
/// gemini URL-model arrival helper it exercises.
#[test]
fn test_query_has_alt_sse() {
    assert!(query_has_alt_sse("alt=sse"));
    assert!(query_has_alt_sse("key=abc&alt=sse"));
    assert!(query_has_alt_sse("alt=sse&key=abc"));
    assert!(!query_has_alt_sse("alt=json"));
    assert!(!query_has_alt_sse(""));
    // Not fooled by a different param whose VALUE merely contains "alt=sse".
    assert!(!query_has_alt_sse("foo=alt=sse"));
    // `alt` with no value is not the SSE selector.
    assert!(!query_has_alt_sse("alt"));
}

/// Unit: `gemini_api_version` maps each ingress prefix to the token the native error echoes.
#[test]
fn test_gemini_api_version_prefix_mapping() {
    assert_eq!(
        gemini_api_version("/v1/models/foo:countTokens"),
        "v1",
        "stable surface ⇒ v1"
    );
    assert_eq!(
        gemini_api_version("/v1beta/models/foo:countTokens"),
        "v1beta",
        "beta surface ⇒ v1beta"
    );
    // Unexpected shape falls back to the historical default.
    assert_eq!(
        gemini_api_version("/weird/path"),
        "v1beta",
        "fallback ⇒ v1beta"
    );
}

// ── THE URL PARSE, DRIVEN ─────────────────────────────────────────────────────────────────────

/// THE HOST, reduced to what a URL parse actually asks of it.
///
/// The parse reaches the request pipeline for exactly two things: to shape a rejection in a dialect's
/// own envelope, and to say which dialect an answer to a path is shaped in. Neither needs a
/// deployment, so this stands in for one — the shaping delegates to the same neutral renderer core's
/// host delegates to, and the accounting is a pass-through, because what these tests read is the
/// FACTS the parse produces and the SHAPE of what it refuses, not the counters core keeps.
struct ParseHost;

impl ArrivalHost for ParseHost {
    fn finish_rejected(
        &self,
        _ctx: &ArrivalCtx,
        _proto: &str,
        _pool: &str,
        _started: Instant,
        _charged_at: u64,
        resp: Response,
    ) -> Response {
        resp
    }

    fn ingress_error(&self, proto: &str, status: StatusCode, kind: &str, message: &str) -> Response {
        busbar_substrate::proxy::ingress_error(proto, status, kind, message)
    }

    fn envelope_dialect(&self, _ctx: &ArrivalCtx, path: &str) -> &'static str {
        // The mount classifier core runs, in the one shape these tests exercise: the beta surface is
        // gemini's alone; anything else answers in the residual default dialect.
        if path.starts_with("/v1beta/") {
            crate::proto_codec::PROTO_GEMINI
        } else {
            busbar_substrate::proto::residual_default_protocol().unwrap_or("")
        }
    }

    fn fallback_not_found(
        &self,
        _ctx: &ArrivalCtx,
        _path: &str,
        status: StatusCode,
        err_type: &str,
        message: &str,
    ) -> Response {
        busbar_substrate::proxy::ingress_error(
            busbar_substrate::proto::residual_default_protocol().unwrap_or(""),
            status,
            err_type,
            message,
        )
    }

    fn percent_decode(&self, s: &str) -> String {
        // The URLs below carry no escapes, so the decode is the identity on every one of them; a
        // stand-in that guessed at an escape would be a stand-in testing itself.
        assert!(!s.contains('%'), "this stand-in decodes no escapes: {s}");
        s.to_string()
    }

    fn kind_not_found(&self) -> &'static str {
        busbar_substrate::proxy::KIND_NOT_FOUND
    }

    fn kind_invalid_request(&self) -> &'static str {
        busbar_substrate::proxy::KIND_INVALID_REQUEST
    }

    fn err_type_not_found(&self) -> &'static str {
        busbar_substrate::proxy::KIND_NOT_FOUND
    }
}

fn parse_host() -> (Arc<dyn ArrivalHost>, ArrivalCtx) {
    busbar_llm_codec::ensure_test_protocols_registered();
    (Arc::new(ParseHost), ArrivalCtx::new(()))
}

/// The gemini native request body these URLs are sent with — no model in it, which is the point.
fn gemini_body() -> Bytes {
    Bytes::from_static(br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#)
}

fn bedrock_body() -> Bytes {
    Bytes::from_static(br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}]}"#)
}

fn now() -> (Instant, u64) {
    (Instant::now(), busbar_substrate::store::now())
}

/// The path-model facts a URL resolves to; anything else is this fixture naming the wrong URL.
fn facts(parsed: PathArrivalFacts) -> super::PathModelFacts {
    match parsed {
        PathArrivalFacts::PathModel(f) => f,
        PathArrivalFacts::BodyModel { .. } => panic!("this URL names its stream intent"),
        PathArrivalFacts::Refused(_) => panic!("this URL is a request"),
    }
}

/// GEMINI'S URL, READ. Each of the surfaces the loop drives, and the facts it carries.
#[test]
fn the_gemini_parse_reads_its_own_url_space() {
    let (host, ctx) = parse_host();
    let (started, charged_at) = now();
    let read = |path: &str, query: &str| {
        let full = if query.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{query}")
        };
        let uri: Uri = full.parse().expect("a fixture uri parses");
        let rest = gemini_rest(&host, path);
        gemini_path_parse(
            &host,
            &ctx,
            &rest,
            &uri,
            &gemini_body(),
            started,
            charged_at,
        )
    };

    // Buffered: the model, no stream, no framing shim, and gemini's own versioned miss copy.
    let f = facts(read("/v1beta/models/p:generateContent", ""));
    assert_eq!(f.model, "p");
    assert_eq!(f.operation, busbar_api::operation::Operation::CHAT);
    assert!(!f.stream);
    assert!(!f.gemini_json_array);
    assert_eq!(
        f.model_not_found_message.as_deref(),
        Some(
            "models/p is not found for API version v1beta, \
             or is not supported for the task you are trying to perform."
        )
    );

    // Streamed with no `alt=sse`: the JSON-array framing.
    let f = facts(read("/v1beta/models/p:streamGenerateContent", ""));
    assert!(f.stream && f.gemini_json_array);

    // Streamed WITH `alt=sse`: SSE framing, so no array shim.
    let f = facts(read("/v1beta/models/p:streamGenerateContent", "alt=sse"));
    assert!(f.stream && !f.gemini_json_array);

    // A model this deployment has never heard of is still a well-formed URL: the parse reads it out
    // and the miss copy names it. That copy is what the forward uses when the name resolves to no
    // lane, which is why it is a FACT OF THE URL rather than a decision taken downstream.
    let f = facts(read("/v1beta/models/no-such-model:generateContent", ""));
    assert_eq!(f.model, "no-such-model");
    assert_eq!(
        f.model_not_found_message.as_deref(),
        Some(
            "models/no-such-model is not found for API version v1beta, \
             or is not supported for the task you are trying to perform."
        )
    );

    // The stable prefix versions its own copy.
    let f = facts(read("/v1/models/p:generateContent", ""));
    assert!(f
        .model_not_found_message
        .as_deref()
        .is_some_and(|m| m.contains("API version v1,")));

    // An action this surface does not proxy is not a request at all.
    assert!(matches!(
        read("/v1beta/models/p:countTokens", ""),
        PathArrivalFacts::Refused(_)
    ));
    // And neither is a colon-less path.
    assert!(matches!(
        read("/v1beta/models/p", ""),
        PathArrivalFacts::Refused(_)
    ));
}

/// BEDROCK'S URL, READ. Three shapes under one model path, and the 404 for anything else.
#[test]
fn the_bedrock_parse_reads_its_own_url_space() {
    let (host, ctx) = parse_host();
    let (started, charged_at) = now();
    let read_with = |path: &str, body: &Bytes| {
        let uri: Uri = path.parse().expect("a fixture uri parses");
        bedrock_path_parse(&host, &ctx, path, &uri, body, started, charged_at)
    };
    let read = |path: &str| read_with(path, &bedrock_body());

    let f = facts(read("/model/p/converse"));
    assert_eq!(f.model, "p");
    assert_eq!(f.operation, busbar_api::operation::Operation::CHAT);
    assert!(!f.stream);
    // Bedrock has no array framing and no copy of its own: the neutral sentence is its sentence.
    assert!(!f.gemini_json_array);
    assert_eq!(f.model_not_found_message, None);

    let f = facts(read("/model/p/converse-stream"));
    assert_eq!(f.model, "p");
    assert!(f.stream && !f.gemini_json_array);

    // `invoke` names only the model: the operation is the body's, so this is the body-model shape
    // with a routing hint rather than a path-model unit — and a body that names no operation this
    // dialect serves is the dialect's own 400, decided by the same read.
    let invoke_body = Bytes::from_static(br#"{"inputText":"hi"}"#);
    match read_with("/model/p/invoke", &invoke_body) {
        PathArrivalFacts::BodyModel { model_hint, .. } => assert_eq!(model_hint, "p"),
        _ => panic!("invoke leaves the operation to the body"),
    }
    assert!(matches!(
        read("/model/p/invoke"),
        PathArrivalFacts::Refused(_)
    ));

    // Anything else under the model path is not a request this dialect answers.
    assert!(matches!(
        read("/model/p/invoke-with-response-stream"),
        PathArrivalFacts::Refused(_)
    ));
    assert!(matches!(
        read("/model/p/nope"),
        PathArrivalFacts::Refused(_)
    ));
}

/// IDENTITY, THE TWO STEPS TOGETHER. The facts a dialect's URL parse produces, driven through step 0
/// and step 1, land on exactly the bytes and exactly the handler the live path-model entry point
/// lands on — the splice run here against the live splice, and the lookup against the live lookup.
///
/// Gated with the step files themselves: with the waist compiled out there are no steps to drive, and
/// the parse above is still the parse.
#[cfg(feature = "teller-waist")]
#[test]
fn the_url_facts_drive_the_two_steps_to_the_live_paths_answer() {
    let (host, ctx) = parse_host();
    let (started, charged_at) = now();
    let cases: [(&str, &str, Bytes); 2] = [
        (
            crate::proto_codec::PROTO_GEMINI,
            "/v1beta/models/p:streamGenerateContent",
            gemini_body(),
        ),
        (
            crate::proto_codec::PROTO_BEDROCK,
            "/model/p/converse-stream",
            bedrock_body(),
        ),
    ];
    for (proto, path, body) in cases {
        let uri: Uri = path.parse().expect("a fixture uri parses");
        let parsed = if proto == crate::proto_codec::PROTO_GEMINI {
            let rest = gemini_rest(&host, path);
            gemini_path_parse(&host, &ctx, &rest, &uri, &body, started, charged_at)
        } else {
            bedrock_path_parse(&host, &ctx, path, &uri, &body, started, charged_at)
        };
        let f = facts(parsed);

        // STEP 0, over the URL's facts.
        let step0 = crate::unit::arrival::arrival_path_model(
            &body,
            &f.model,
            f.stream,
            f.gemini_json_array,
            proto,
        )
        .unwrap_or_else(|r| panic!("{path} refused at arrival: {r:?}"));

        // The live splice, run here on the same bytes and the same facts.
        let mut v: serde_json::Value = busbar_substrate::json::parse(&body).expect("live parse");
        let obj = v.as_object_mut().expect("a native body is a document");
        obj.insert(
            "model".to_string(),
            serde_json::Value::String(f.model.clone()),
        );
        obj.insert("stream".to_string(), serde_json::Value::Bool(f.stream));
        if f.gemini_json_array {
            if let Some(key) = busbar_substrate::proto::array_stream_shim_key_for(proto) {
                obj.insert(key.to_string(), serde_json::Value::Bool(true));
            }
        }
        let live: Bytes = busbar_substrate::json::to_vec(&v)
            .expect("live serialize")
            .into();
        assert_eq!(
            step0.injected, live,
            "{path}: the step's injected body is not the live path's"
        );

        // STEP 1, in the path-model spelling: the live arm's one chained lookup.
        let step1 = crate::unit::decode::decode_path_model(proto, f.operation, &f.model)
            .unwrap_or_else(|r| panic!("{path} refused at decode: {r:?}"));
        let live_handler = busbar_substrate::handlers::request_handler(proto)
            .and_then(|rh| rh.operation_handler(f.operation))
            .expect("the live lookup resolves this pair");
        assert!(
            std::ptr::eq(
                live_handler as *const dyn busbar_substrate::handlers::OperationHandler as *const u8,
                step1.op_handler as *const dyn busbar_substrate::handlers::OperationHandler
                    as *const u8
            ),
            "{path}: the step resolved a different handler than the live lookup"
        );
        assert_eq!(step1.model, f.model);
    }
}
