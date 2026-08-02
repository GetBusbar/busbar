//! THE REGRESSION NET for the `response_format` bug class. Before the typed `IrResponseFormat`
//! layer, the same "writer echoes a foreign shape cross-protocol → backend 400" bug surfaced once
//! per writer (openai → cohere → gemini → responses). Now the IR is typed, so a writer physically
//! cannot hold or echo a foreign shape — and this matrix proves every projection lands native.
use super::*;
use crate::ir::{IrBlock, IrMessage, IrResponseFormat, IrRole};

fn req_with_format(rf: IrResponseFormat) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        response_format: Some(rf),
        ..Default::default()
    }
}

/// ONE typed directive, projected by EVERY native-structured-output writer, must land in THAT
/// writer's own wire shape — never a foreign one — with the schema preserved.
#[test]
fn every_writer_emits_its_native_shape() {
    let schema = serde_json::json!({"type":"object","properties":{"x":{"type":"string"}}});
    let req = req_with_format(IrResponseFormat {
        json: true,
        schema: Some(schema),
        name: Some("out".to_string()),
        strict: None,
        description: None,
    });

    // OpenAI: {type:"json_schema", json_schema:{name, schema}} — schema NESTED under .schema.
    let o = OpenAiWriter.write_request(&req);
    assert_eq!(
        o.pointer("/response_format/type"),
        Some(&serde_json::json!("json_schema"))
    );
    assert_eq!(
        o.pointer("/response_format/json_schema/schema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(o.pointer("/response_format/json_schema/name").is_some());
    assert!(
        o.pointer("/response_format/responseMimeType").is_none(),
        "no Gemini-shaped key may leak into OpenAI: {o}"
    );

    // Cohere: {type:"json_object", json_schema:<schema DIRECTLY>}.
    let cohere_writer = CohereWriter;
    let c = cohere_writer.write_request(&req);
    assert_eq!(
        c.pointer("/response_format/type"),
        Some(&serde_json::json!("json_object"))
    );
    assert_eq!(
        c.pointer("/response_format/json_schema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(
        c.pointer("/response_format/json_schema/schema").is_none(),
        "Cohere does NOT nest under .schema (that's OpenAI's shape): {c}"
    );

    // Gemini: generationConfig.responseMimeType + responseSchema; no top-level response_format.
    let gemini_writer = GeminiWriter;
    let g = gemini_writer.write_request(&req);
    assert_eq!(
        g.pointer("/generationConfig/responseMimeType"),
        Some(&serde_json::json!("application/json"))
    );
    assert_eq!(
        g.pointer("/generationConfig/responseSchema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(
        g.pointer("/response_format").is_none(),
        "Gemini has no top-level response_format: {g}"
    );

    // Responses: text.format FLAT json_schema (name/schema beside type, not nested).
    let responses_writer = ResponsesWriter;
    let r = responses_writer.write_request(&req);
    assert_eq!(
        r.pointer("/text/format/type"),
        Some(&serde_json::json!("json_schema"))
    );
    assert_eq!(
        r.pointer("/text/format/schema/properties/x/type"),
        Some(&serde_json::json!("string"))
    );
    assert!(
        r.pointer("/text/format/json_schema").is_none(),
        "Responses text.format is FLAT, not nested under json_schema: {r}"
    );
}

/// And the read side: each protocol's NATIVE structured-output request canonicalizes into the
/// same typed directive — proving readers feed the agnostic IR, not a protocol-shaped blob.
#[test]
fn every_reader_canonicalizes_to_typed_ir() {
    let oi = OpenAiReader
            .read_request(&serde_json::json!({
                "messages":[{"role":"user","content":"hi"}],
                "response_format":{"type":"json_schema","json_schema":{"name":"out","schema":{"type":"object"}}}
            }))
            .unwrap();
    let rf = oi.response_format.unwrap();
    assert!(rf.json && rf.name.as_deref() == Some("out") && rf.schema.is_some());

    let co = CohereReader
        .read_request(&serde_json::json!({
            "model":"command-r",
            "messages":[{"role":"user","content":"hi"}],
            "response_format":{"type":"json_object","json_schema":{"type":"object"}}
        }))
        .unwrap();
    let rf = co.response_format.unwrap();
    assert!(rf.json && rf.schema.is_some());

    let ge = GeminiReader
            .read_request(&serde_json::json!({
                "contents":[{"role":"user","parts":[{"text":"hi"}]}],
                "generationConfig":{"responseMimeType":"application/json","responseSchema":{"type":"object"}}
            }))
            .unwrap();
    let rf = ge.response_format.unwrap();
    assert!(rf.json && rf.schema.is_some());

    let re = ResponsesReader
        .read_request(&serde_json::json!({
            "input":"hi",
            "text":{"format":{"type":"json_schema","name":"out","schema":{"type":"object"}}}
        }))
        .unwrap();
    let rf = re.response_format.unwrap();
    assert!(rf.json && rf.name.as_deref() == Some("out") && rf.schema.is_some());
}

// ── class-6 6b2/6b4: tool_choice-without-tools guard + stop-sequence vendor-cap clamp ──────────────
// Six-writer REQUEST matrix (unlike `stop_reason_matrix_tests.rs`, which is response/`write_response`
// only — `write_request` never appears there).

fn req_with_tool_choice_no_tools() -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        tools: vec![],
        tool_choice: Some(crate::ir::IrToolChoice::Required),
        ..Default::default()
    }
}

/// A `tool_choice` with NO accompanying `tools` is a guaranteed 400 on every vendor that models the
/// constraint (Anthropic/OpenAI/Gemini/Cohere/Responses all reject it; only Bedrock's Converse ALSO
/// documents + guards this today). Reachable cross-protocol: `prepare_for_egress` strips hosted
/// tools while a `tool_choice` directive can survive. Every writer must omit `tool_choice` in this
/// shape; Bedrock is a REGRESSION PROOF (it already guarded before this fix).
#[test]
fn tool_choice_without_tools_is_omitted_on_every_writer() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let req = req_with_tool_choice_no_tools();
    let cohere_writer = CohereWriter;
    let gemini_writer = GeminiWriter;
    let responses_writer = ResponsesWriter;
    let bedrock_writer = BedrockWriter;

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let (a, o, g, b, c, r) = tracing::subscriber::with_default(subscriber, || {
        (
            AnthropicWriter.write_request(&req),
            OpenAiWriter.write_request(&req),
            gemini_writer.write_request(&req),
            bedrock_writer.write_request(&req),
            cohere_writer.write_request(&req),
            responses_writer.write_request(&req),
        )
    });

    assert!(
        a.get("tool_choice").is_none(),
        "anthropic must omit tool_choice with no tools; got {a}"
    );
    assert!(
        o.get("tool_choice").is_none(),
        "openai must omit tool_choice with no tools; got {o}"
    );
    assert!(
        g.get("toolConfig")
            .and_then(|tc| tc.get("functionCallingConfig"))
            .is_none(),
        "gemini must omit functionCallingConfig with no tools; got {g}"
    );
    assert!(
        b.get("toolConfig")
            .and_then(|tc| tc.get("toolChoice"))
            .is_none(),
        "bedrock (regression proof) must omit toolChoice with no tools; got {b}"
    );
    assert!(
        c.get("tool_choice").is_none(),
        "cohere must omit tool_choice with no tools; got {c}"
    );
    assert!(
        r.get("tool_choice").is_none(),
        "responses must omit tool_choice with no tools; got {r}"
    );

    // Every writer that dropped a directive must have warned (Bedrock already did, pre-fix).
    for name in [
        "Anthropic",
        "OpenAI",
        "Gemini",
        "Cohere",
        "Responses",
        "Bedrock",
    ] {
        assert!(
            cap.contains("dropping") && cap.contains("tool_choice") || cap.contains("toolChoice"),
            "expected a warn naming the dropped tool_choice (checking around {name}); got {:?}",
            cap.messages()
        );
    }
}

fn req_with_stop(stop: Vec<String>) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        stop,
        ..Default::default()
    }
}

/// The IR's `stop` is an unbounded `Vec<String>` (no protocol enforces a cap on ingress), so a
/// cross-protocol request can carry more stop sequences than a smaller target vendor allows: OpenAI
/// caps at 4, Gemini/Cohere at 5 — exceeding either is a guaranteed 400. Anthropic/Bedrock publish
/// no fixed cap and are LEFT UNCHANGED (inventing one would be a new lossy behavior this fix does
/// not license).
#[test]
fn stop_sequences_clamped_per_vendor_cap() {
    let stops: Vec<String> = (0..8).map(|i| format!("STOP{i}")).collect();
    let req = req_with_stop(stops.clone());

    let o = OpenAiWriter.write_request(&req);
    let o_stop = o["stop"].as_array().expect("openai stop array");
    assert!(
        o_stop.len() <= 4,
        "openai must clamp stop to its documented cap of 4; got {} entries: {o_stop:?}",
        o_stop.len()
    );

    let gemini_writer = GeminiWriter;
    let g = gemini_writer.write_request(&req);
    let g_stop = g["generationConfig"]["stopSequences"]
        .as_array()
        .expect("gemini stopSequences array");
    assert!(
        g_stop.len() <= 5,
        "gemini must clamp stopSequences to its documented cap of 5; got {} entries: {g_stop:?}",
        g_stop.len()
    );

    let cohere_writer = CohereWriter;
    let c = cohere_writer.write_request(&req);
    let c_stop = c["stop_sequences"]
        .as_array()
        .expect("cohere stop_sequences array");
    assert!(
        c_stop.len() <= 5,
        "cohere must clamp stop_sequences to its documented cap of 5; got {} entries: {c_stop:?}",
        c_stop.len()
    );

    // Anthropic and Bedrock publish no fixed cap — UNCHANGED, still carrying all 8.
    let a = AnthropicWriter.write_request(&req);
    let a_stop = a["stop_sequences"]
        .as_array()
        .expect("anthropic stop_sequences array");
    assert_eq!(
        a_stop.len(),
        8,
        "anthropic publishes no fixed stop-sequence cap; must NOT be clamped"
    );
}

/// class-6 6c1 egress: an OpenAI/Anthropic caller who DID set `parallel_tool_calls` and routes to
/// Gemini/Cohere/Bedrock (none of which model any parallelism control) must get a WARN naming the
/// drop — the flag silently vanishing was the exact class-9-adjacent bug this fix removes. The
/// `is_some()` gate is what discriminates from noise: a request that never carried the flag must
/// NOT warn (the negative half is a regression proof for the false-positive risk).
#[test]
fn parallel_tool_calls_discarded_on_gemini_cohere_bedrock_warns() {
    use crate::test_support::warn_capture::WarnCapture;
    use tracing_subscriber::layer::SubscriberExt as _;

    let req = |parallel: Option<bool>| crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Text {
                text: "hi".to_string(),
                cache_control: None,
                citations: Vec::new(),
            }],
        }],
        parallel_tool_calls: parallel,
        ..Default::default()
    };

    // Positive half: Some(_) must warn on all three.
    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let with_flag = req(Some(true));
    let gemini_writer = GeminiWriter;
    let cohere_writer = CohereWriter;
    let bedrock_writer = BedrockWriter;
    tracing::subscriber::with_default(subscriber, || {
        gemini_writer.write_request(&with_flag);
        cohere_writer.write_request(&with_flag);
        bedrock_writer.write_request(&with_flag);
    });
    assert!(
        cap.contains("parallel_tool_calls") && cap.contains("Gemini"),
        "gemini must warn on a carried parallel_tool_calls: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("parallel_tool_calls") && cap.contains("Cohere"),
        "cohere must warn on a carried parallel_tool_calls: {:?}",
        cap.messages()
    );
    assert!(
        cap.contains("parallel_tool_calls") && cap.contains("Bedrock"),
        "bedrock must warn on a carried parallel_tool_calls: {:?}",
        cap.messages()
    );

    // Negative half (REGRESSION PROOF): None must NOT warn — this is what makes the positive half
    // a real signal instead of firing on every request regardless of content.
    let cap2 = WarnCapture::default();
    let subscriber2 = tracing_subscriber::registry().with(cap2.clone());
    let without_flag = req(None);
    tracing::subscriber::with_default(subscriber2, || {
        gemini_writer.write_request(&without_flag);
        cohere_writer.write_request(&without_flag);
        bedrock_writer.write_request(&without_flag);
    });
    assert!(
        !cap2.contains("parallel_tool_calls"),
        "a request that never carried the flag must not warn about dropping it: {:?}",
        cap2.messages()
    );
}
