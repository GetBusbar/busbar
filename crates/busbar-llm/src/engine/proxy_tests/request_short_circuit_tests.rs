use super::translate_request_cross_protocol;
use crate::engine::AppEngineExt as _;
use crate::test_support::{LaneSpec, TestApp};
use serde_json::json;

// Build a single-lane App whose one lane speaks `proto` with the given `lane_model`. The lane
// base_url is unused (the short-circuit never dispatches). `i == 0` is the lane index.
fn app_with_lane(proto: &'static str, lane_model: &str) -> std::sync::Arc<busbar_core::state::App> {
    TestApp::new()
        .lane(LaneSpec::new(lane_model, proto, "http://unused.local"))
        .build()
}

// Drive the request seam for a SAME-protocol hop (ingress == egress) and return the egress bytes.
fn shape_same_proto(
    proto: &'static str,
    proto_name: &'static str,
    lane_model: &str,
    body: serde_json::Value,
) -> Vec<u8> {
    let app = app_with_lane(proto, lane_model);
    // hop_bytes = the exact serialized source bytes the caller retained for this hop.
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    translate_request_cross_protocol(
        &app,
        0,
        proto_name,
        busbar_substrate::handlers::chat(proto_name, busbar_substrate::transport::Transport::Http),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect("same-proto shaping is infallible for a valid body")
    .to_vec()
}

// ---- FIDELITY PROOF: pristine same-proto request → bytes == retained original, all 6 protocols.

// BODY-MODEL protocols (anthropic/openai/cohere/responses): a pristine request carries `model`
// == lane.model and no shim keys, so NOTHING mutates → short-circuit emits the original bytes.
#[test]
fn pristine_same_proto_is_byte_identical_body_model() {
    crate::testkit::install_test_seams();
    let cases: &[(&'static str, &'static str, serde_json::Value)] = &[
        (
            crate::proto_codec::PROTO_ANTHROPIC,
            "anthropic",
            json!({"model":"claude-3","max_tokens":7,"messages":[{"role":"user","content":"hi"}]}),
        ),
        (
            crate::proto_codec::PROTO_OPENAI,
            "openai",
            json!({"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":0.5}),
        ),
        (
            crate::proto_codec::PROTO_COHERE,
            "cohere",
            json!({"model":"command-r","messages":[{"role":"user","content":"hi"}]}),
        ),
        (
            crate::proto_codec::PROTO_RESPONSES,
            "responses",
            json!({"model":"gpt-4o","input":"hi"}),
        ),
    ];
    for (proto, name, body) in cases {
        // lane.model == body.model → rewrite_model_if_needed is a no-op (#3 not triggered).
        let lane_model = body.get("model").and_then(|m| m.as_str()).unwrap();
        let hop_bytes = busbar_substrate::json::to_vec(body).unwrap();
        let out = shape_same_proto(proto, name, lane_model, body.clone());
        assert_eq!(
            out, hop_bytes,
            "{name}: pristine same-proto request must short-circuit to the retained original bytes"
        );
    }
}

// `upstream_model` override must win on the wire. Covers the override branch of
// `Lane::upstream_model()` that no existing test exercises (all default `upstream_model` to
// `None`). Body-model protocol: rewrite_model_if_needed installs `upstream_model`. URL-model
// protocol: upstream_path_for_stream embeds `upstream_model` in the path.
#[test]
fn upstream_model_override_rewrites_body_and_url_model() {
    crate::testkit::install_test_seams();
    // Body-model protocol: rewrite_model_if_needed installs `upstream_model`.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "config-key",
                crate::proto_codec::PROTO_OPENAI,
                "http://unused.local",
            )
            .upstream_model("upstream-real"),
        )
        .build();
    let body = json!({"model":"client-alias","messages":[]});
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    let out = translate_request_cross_protocol(
        &app,
        0,
        "openai",
        busbar_substrate::handlers::chat("openai", busbar_substrate::transport::Transport::Http),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect("same-proto shaping is infallible for a valid body");
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("model").and_then(|m| m.as_str()),
        Some("upstream-real"),
        "body-model egress must carry the upstream_model override"
    );

    // URL-model protocol: upstream_path_for_stream embeds upstream_model in the path.
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "config-key",
                crate::proto_codec::PROTO_BEDROCK,
                "http://unused.local",
            )
            .upstream_model("upstream.real/model"),
        )
        .build();
    // Neutral registry seam: resolve the lane's egress codec by NAME through the installed
    // registry (`decl_for(name).dialect()`), as production does — never the witnessed
    // `protocol_for(name).writer()`. `DialectCodec::upstream_path_for_stream` delegates to
    // `writer().upstream_path_for_stream`, so this is byte-identical to the pre-relocation path.
    let dialect = busbar_substrate::proto::decl_for(app.engine_tables().lanes()[0].protocol)
        .and_then(|d| d.dialect())
        .expect("lane protocol resolves");
    assert_eq!(
            dialect.upstream_path_for_stream(app.engine_tables().lanes()[0].wire_model(), false),
            "/model/upstream.real/model/converse",
            "URL-model path must embed the upstream_model override (raw; percent-encoding happens at sign/send time)"
        );
}

// Claude-on-Vertex: an anthropic lane with a Vertex `path_base` carries the model in the URL
// (`:rawPredict`), so request finalization must DROP the body `model` and INJECT `anthropic_version`
// (Vertex's required discriminator). This is the BODY half of the wrinkle — the harness proves the
// URL/mint end-to-end, but a signature-blind mock can't assert the body transform, so it's pinned
// here. A regression that stopped dropping `model` or stopped injecting the version would 400 on
// real Vertex; this test catches it offline.
#[test]
fn claude_on_vertex_drops_model_and_injects_anthropic_version() {
    crate::testkit::install_test_seams();
    let vbase = "/v1/projects/p/locations/us-central1/publishers/anthropic/models";
    let app = TestApp::new()
        .lane(
            LaneSpec::new(
                "claude-3-5-sonnet",
                crate::proto_codec::PROTO_ANTHROPIC,
                "https://us-central1-aiplatform.googleapis.com",
            )
            .path_base(vbase),
        )
        .build();
    let body = json!({"model":"claude-3-5-sonnet","max_tokens":7,"messages":[{"role":"user","content":"hi"}]});
    let hop_bytes = bytes::Bytes::from(busbar_substrate::json::to_vec(&body).unwrap());
    let out = translate_request_cross_protocol(
        &app,
        0,
        "anthropic",
        busbar_substrate::handlers::chat("anthropic", busbar_substrate::transport::Transport::Http),
        Some(body),
        crate::engine::APPLICATION_JSON,
        true,
        &hop_bytes,
        "test-key",
    )
    .expect("anthropic-vertex shaping is infallible for a valid body");
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        v.get("model").is_none(),
        "model must be dropped — it rides the :rawPredict URL, not the body: {v}"
    );
    assert_eq!(
        v.get("anthropic_version").and_then(|x| x.as_str()),
        Some("vertex-2023-10-16"),
        "the anthropic_version discriminator must be injected: {v}"
    );
    assert!(
        v.get("messages").is_some(),
        "the rest of the request body must be preserved through the transform: {v}"
    );
}

// MODEL-IN-URL protocols (gemini/bedrock): a pristine native request carries NO body `model`
#[test]
fn pristine_same_proto_is_byte_identical_url_model() {
    crate::testkit::install_test_seams();
    let cases: &[(&'static str, &'static str, serde_json::Value)] = &[
        (
            crate::proto_codec::PROTO_GEMINI,
            "gemini",
            json!({"contents":[{"role":"user","parts":[{"text":"hi"}]}]}),
        ),
        (
            crate::proto_codec::PROTO_BEDROCK,
            "bedrock",
            json!({"messages":[{"role":"user","content":[{"text":"hi"}]}]}),
        ),
    ];
    for (proto, name, body) in cases {
        let hop_bytes = busbar_substrate::json::to_vec(body).unwrap();
        // The egress payload is byte-identical to the retained original. Bedrock reaches this via
        // the true short-circuit (its `rewrite_model_if_needed` is a no-op → pristine). Gemini's
        // default rewrite inserts the lane model which the same-proto strip then removes — a net
        // no-op on the Value, so canonical re-serialization still yields the identical bytes. Both
        // satisfy the byte-fidelity contract (the test that matters); only the path differs.
        let out = shape_same_proto(proto, name, "url-model-x", body.clone());
        assert_eq!(
            out, hop_bytes,
            "{name}: pristine same-proto url-model request egress must be byte-identical to input"
        );
    }
}

// ---- INVALIDATORS #1-#4: each must force NON-pristine and produce the correct rewritten bytes.

// #1: gemini JSON-array shim key present → stripped → NON-pristine → bytes differ, key gone.
#[test]
fn invalidator_1_gemini_array_shim_key_forces_non_pristine() {
    crate::testkit::install_test_seams();
    // Use a body-model ingress so only #1 fires (the key is stripped on EVERY egress).
    // The never-native array shim key, reached through the NEUTRAL registry accessor (it is a
    // Gemini-declared marker; core names no dialect module to obtain it).
    let gemini_array_shim_key = busbar_substrate::proto::array_stream_shim_key_for("gemini")
        .expect("gemini declares a json-array shim key");
    let body = json!({"model":"gpt-4o","messages":[],(gemini_array_shim_key):true});
    let hop_bytes = busbar_substrate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(crate::proto_codec::PROTO_OPENAI, "openai", "gpt-4o", body);
    assert_ne!(
        out, hop_bytes,
        "#1: array-shim key present must invalidate the short-circuit"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get(gemini_array_shim_key).is_none(),
        "#1: the never-native array shim key must be stripped from the egress body"
    );
}

// #2: `stream` present on a PATH-MODEL egress (gemini) → stripped → NON-pristine → stream gone.
#[test]
fn invalidator_2_stream_on_path_model_egress_forces_non_pristine() {
    crate::testkit::install_test_seams();
    let body = json!({"contents":[{"role":"user","parts":[{"text":"hi"}]}],"stream":true});
    let hop_bytes = busbar_substrate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(
        crate::proto_codec::PROTO_GEMINI,
        "gemini",
        "url-model-x",
        body,
    );
    assert_ne!(
        out, hop_bytes,
        "#2: `stream` on a path-model egress must invalidate"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get("stream").is_none(),
        "#2: `stream` must be stripped for a path-model (gemini) egress"
    );
}

// #2 negative control: `stream` on a BODY-MODEL egress (openai) is the writer-authored field the
// backend needs → NOT stripped → with model matching lane, request stays pristine + byte-identical.
#[test]
fn invalidator_2_stream_on_body_model_egress_stays_pristine() {
    crate::testkit::install_test_seams();
    let body = json!({"model":"gpt-4o","messages":[],"stream":true});
    let hop_bytes = busbar_substrate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(crate::proto_codec::PROTO_OPENAI, "openai", "gpt-4o", body);
    assert_eq!(
        out, hop_bytes,
        "#2 neg: `stream` on a body-model egress must be PRESERVED → request stays pristine"
    );
}

// #3: lane.model differs from body.model → rewrite_model_if_needed installs the lane model →
// NON-pristine → bytes differ, model rewritten to the authoritative lane model.
#[test]
fn invalidator_3_model_rewrite_forces_non_pristine() {
    crate::testkit::install_test_seams();
    let body = json!({"model":"client-alias","messages":[]});
    let hop_bytes = busbar_substrate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(
        crate::proto_codec::PROTO_OPENAI,
        "openai",
        "gpt-4o-real",
        body,
    );
    assert_ne!(
        out, hop_bytes,
        "#3: a model alias differing from lane.model must invalidate"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(
        parsed.get("model").and_then(|m| m.as_str()),
        Some("gpt-4o-real"),
        "#3: the egress body must carry the authoritative lane model"
    );
}

// #3 negative control: body.model already EQUALS lane.model → no change → pristine short-circuit.
#[test]
fn invalidator_3_matching_model_stays_pristine() {
    crate::testkit::install_test_seams();
    let body = json!({"model":"gpt-4o-real","messages":[]});
    let hop_bytes = busbar_substrate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(
        crate::proto_codec::PROTO_OPENAI,
        "openai",
        "gpt-4o-real",
        body,
    );
    assert_eq!(
        out, hop_bytes,
        "#3 neg: a body model already matching lane.model must NOT invalidate (byte-identical)"
    );
}

// #4: same-proto gemini passthrough with a body `model` (a router shim) → stripped after rewrite →
// NON-pristine → bytes differ, model gone (gemini carries model in the URL).
#[test]
fn invalidator_4_same_proto_model_shim_strip_forces_non_pristine() {
    crate::testkit::install_test_seams();
    let body = json!({"model":"router-shim","contents":[{"role":"user","parts":[{"text":"hi"}]}]});
    let hop_bytes = busbar_substrate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(
        crate::proto_codec::PROTO_GEMINI,
        "gemini",
        "url-model-x",
        body,
    );
    assert_ne!(
        out, hop_bytes,
        "#4: a same-proto path-model body `model` must invalidate"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(
        parsed.get("model").is_none(),
        "#4: a same-proto gemini/bedrock body `model` shim must be stripped"
    );
}

// SAME-PROTOCOL GEMINI->GEMINI THOUGHTSIGNATURE NON-REGRESSION (guard, not new behavior). A
// Gemini request carrying a real `thoughtSignature` sibling of `functionCall` relays byte-
// identically on the same-protocol short-circuit — it never touches the IR, so
// `prepare_for_egress`'s sentinel-fill logic never runs and the sentinel value must never appear.
// This should already pass before AND after the thoughtSignature fix (same-protocol never goes
// through the IR at all); it is here as a permanent guard against ever routing same-proto Gemini
// traffic through the cross-protocol IR seam.
#[test]
fn same_proto_gemini_thought_signature_round_trips_verbatim() {
    crate::testkit::install_test_seams();
    let body = json!({
        "contents": [
            {
                "role": "model",
                "parts": [
                    {
                        "functionCall": {"name": "get_weather", "args": {"city": "SF"}},
                        "thoughtSignature": "a-real-opaque-signature-token"
                    }
                ]
            }
        ]
    });
    let hop_bytes = busbar_substrate::json::to_vec(&body).unwrap();
    let out = shape_same_proto(
        crate::proto_codec::PROTO_GEMINI,
        "gemini",
        "url-model-x",
        body,
    );
    assert_eq!(
        out, hop_bytes,
        "same-proto gemini->gemini functionCall+thoughtSignature must relay byte-identically"
    );
    let text = String::from_utf8(out).unwrap();
    assert!(
        text.contains("a-real-opaque-signature-token"),
        "the real signature must survive the passthrough"
    );
    assert!(
        !text.contains("skip_thought_signature_validator"),
        "the sentinel must never appear on a same-protocol passthrough"
    );
}
