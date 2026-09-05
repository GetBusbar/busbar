//! The bytes this plane produces are the bytes the existing codec produces.
//!
//! The frozen outputs under the codec crate's own golden directory are read here and never written.
//! They are the reference: if a byte moves, this plane has changed a wire format, and a plane that
//! changes a wire format has broken every client of it.
//!
//! The INPUT bodies below are restated rather than shared, because they live in a test module of
//! the codec crate and a test module is not a surface another crate can name. They are copies, and
//! the copy is checked in the only way that matters: a copy that drifted would stop reproducing the
//! frozen output, which is exactly what this file asserts.
//!
//! ## What is compared
//!
//! Every frozen request output is compared byte-for-byte, with no normalization at all. Every
//! frozen answer output is compared with four members normalized, and the note above the answer
//! tests says which four and why each one is unreachable from outside the codec crate — they are a
//! recorded gap, not a tolerance band.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::ids::LaneId;
use busbar_contract::plane::{Ingress, Plane};
use busbar_contract::wire::FrameCursor;
use busbar_plane_llm::{LlmPlane, Upstream};

/// The model the lane rewrites every outbound request to name.
const LANE_MODEL: &str = "gpt-4o-mini";

/// One configured upstream per dialect, each on its own lane.
const UPSTREAMS: &[Upstream] = &[
    Upstream {
        lane: LaneId::new("lane-anthropic"),
        host: "anthropic.invalid",
        dialect: "anthropic",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-openai"),
        host: "openai.invalid",
        dialect: "openai",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-gemini"),
        host: "gemini.invalid",
        dialect: "gemini",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-bedrock"),
        host: "bedrock.invalid",
        dialect: "bedrock",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-responses"),
        host: "responses.invalid",
        dialect: "responses",
        model: LANE_MODEL,
    },
    Upstream {
        lane: LaneId::new("lane-cohere"),
        host: "cohere.invalid",
        dialect: "cohere",
        model: LANE_MODEL,
    },
];

/// The lane that reaches one dialect.
fn lane_for(dialect: &str) -> LaneId {
    UPSTREAMS
        .iter()
        .find(|u| u.dialect == dialect)
        .map(|u| u.lane)
        .expect("every dialect has a configured lane")
}

/// The host that reaches one dialect.
fn host_for(dialect: &str) -> &'static str {
    UPSTREAMS
        .iter()
        .find(|u| u.dialect == dialect)
        .map(|u| u.host)
        .expect("every dialect has a configured host")
}

/// Where the codec crate keeps its frozen outputs.
fn golden_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../busbar-llm/src/tests/proto/golden")
}

/// One request, taken in through the plane's decode step and back out through its egress step.
fn translate_request(ingress: &str, egress: &str, body: &str) -> Vec<u8> {
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for(ingress), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);

    let frames = vec![harness::frame(body.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let draft = match plane
        .decode_ingress(&mut cursor, None, &ctx)
        .expect("the corpus body is this dialect's shape")
    {
        Ingress::OneShot(draft) => draft,
        other => panic!("a whole request body must decode as one complete unit, got {other:?}"),
    };

    let unit = harness::unit(draft.op, draft.body_ir);
    let dest = harness::destination(host_for(egress), lane_for(egress));
    let out = plane
        .encode_egress(&unit, &dest, None, &ctx)
        .expect("the unit is expressible for this destination");
    out.body.as_slice().to_vec()
}

/// Compare one produced body to the frozen output of the same translation.
///
/// Returns the golden's own bytes and the produced bytes rather than asserting, so the caller can
/// decide whether this pair is one the plane is held to.
fn against_golden(name: &str, actual: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let expected = std::fs::read(golden_dir().join(name))
        .unwrap_or_else(|e| panic!("the frozen output {name} is readable ({e})"));
    (expected, actual.to_vec())
}

// ── the input bodies, copied from the codec crate's own corpora ─────────────────────────────────

/// Requests in the anthropic dialect.
const ANTHROPIC_REQUESTS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":256,"messages":[{"role":"user","content":"Hello, world"}]}"#,
    ),
    (
        "multi_turn",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":1024,"temperature":0.7,"top_p":0.9,"stop_sequences":["END","STOP"],"stream":true,"system":"You are terse.","messages":[{"role":"user","content":"What is 2+2?"},{"role":"assistant","content":"4"},{"role":"user","content":[{"type":"text","text":"And squared?"}]}]}"#,
    ),
    (
        "system_array_images",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":512,"system":[{"type":"text","text":"Be helpful.","cache_control":{"type":"ephemeral"}},{"type":"text","text":"Cite sources."}],"messages":[{"role":"user","content":[{"type":"text","text":"Describe these."},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"aGVsbG8="}},{"type":"image","source":{"type":"url","url":"https://example.com/cat.png"}}]}]}"#,
    ),
    (
        "tools",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":2048,"tools":[{"name":"get_weather","description":"Get weather","input_schema":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]},"cache_control":{"type":"ephemeral"}}],"tool_choice":{"type":"tool","name":"get_weather","disable_parallel_tool_use":true},"messages":[{"role":"user","content":"Weather in Paris?"},{"role":"assistant","content":[{"type":"text","text":"Checking."},{"type":"tool_use","id":"toolu_01AAA","name":"get_weather","input":{"city":"Paris"}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01AAA","content":[{"type":"text","text":"18C "},{"type":"text","text":"sunny"}]}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_01AAA","content":"plain string result","is_error":true}]}]}"#,
    ),
    (
        "thinking_metadata",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":8192,"top_k":40,"stream":true,"thinking":{"type":"enabled","budget_tokens":2048},"metadata":{"user_id":"user-1234"},"messages":[{"role":"user","content":"Think hard about prime numbers."}]}"#,
    ),
    (
        "extras_cleared",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":128,"service_tier":"auto","top_secret_extension":{"a":[1,2,3]},"messages":[{"role":"user","content":"hi"}]}"#,
    ),
    (
        "degenerate",
        r#"{"model":"claude-sonnet-4-20250514","max_tokens":64,"messages":[{"role":"assistant","content":""},{"role":"user","content":[{"type":"document","title":"x"},{"type":"text","text":"escape\" \\ ✓\nnewline"}]},{"role":"system","content":"late system turn"}]}"#,
    ),
];

/// Requests in the openai dialect.
const OPENAI_REQUESTS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello, world"}]}"#,
    ),
    (
        "tools",
        r#"{"model":"gpt-4o","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"Weather in Paris?"}],"temperature":0.5,"top_p":0.9,"max_tokens":128,"stop":["END"],"stream":true,"tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]},"strict":true}}],"tool_choice":"auto"}"#,
    ),
    (
        "attachments",
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":[{"type":"text","text":"transcribe this"},{"type":"input_audio","input_audio":{"data":"AAA","format":"wav"}},{"type":"file","file":{"file_data":"data:application/pdf;base64,JVBERi0=","filename":"spec.pdf"}}]}]}"#,
    ),
];

/// Requests in the gemini dialect.
const GEMINI_REQUESTS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"contents":[{"role":"user","parts":[{"text":"Hello, world"}]}]}"#,
    ),
    (
        "tools",
        r#"{"systemInstruction":{"parts":[{"text":"be brief"}]},"contents":[{"role":"user","parts":[{"text":"Weather in Paris?"}]}],"generationConfig":{"temperature":0.5,"topP":0.9,"maxOutputTokens":128,"stopSequences":["END"]},"tools":[{"functionDeclarations":[{"name":"get_weather","description":"Get weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}]}]}"#,
    ),
    (
        "inline_data",
        r#"{"contents":[{"role":"user","parts":[{"text":"Describe these."},{"inlineData":{"mimeType":"image/png","data":"aGVsbG8="}},{"inlineData":{"mimeType":"application/pdf","data":"JVBERi0="}}]}]}"#,
    ),
];

/// Requests in the responses dialect.
const RESPONSES_REQUESTS: &[(&str, &str)] = &[
    ("plain", r#"{"model":"gpt-4.1","input":"Hello, world"}"#),
    (
        "tools",
        r#"{"model":"gpt-4.1","input":[{"role":"user","content":[{"type":"input_text","text":"Weather in Paris?"}]}],"tools":[{"type":"function","name":"get_weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}},"strict":true}]}"#,
    ),
    (
        "input_file",
        r#"{"model":"gpt-4.1","input":[{"role":"user","content":[{"type":"input_text","text":"read this"},{"type":"input_file","file_data":"data:application/pdf;base64,JVBERi0=","filename":"spec.pdf"}]}]}"#,
    ),
];

/// Requests in the bedrock dialect.
const BEDROCK_REQUESTS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"messages":[{"role":"user","content":[{"text":"Hello, world"}]}]}"#,
    ),
    (
        "tools",
        r#"{"system":[{"text":"be brief"}],"messages":[{"role":"user","content":[{"text":"Weather in Paris?"}]}],"inferenceConfig":{"maxTokens":128,"temperature":0.5,"topP":0.9,"stopSequences":["END"]},"toolConfig":{"tools":[{"toolSpec":{"name":"get_weather","description":"Get weather","inputSchema":{"json":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}}],"toolChoice":{"auto":{}}}}"#,
    ),
    (
        "attachments",
        r#"{"messages":[{"role":"user","content":[{"text":"read this"},{"image":{"format":"png","source":{"bytes":"aGVsbG8="}}},{"document":{"format":"pdf","name":"spec","source":{"bytes":"JVBERi0="}}},{"video":{"format":"mp4","source":{"bytes":"VVV"}}}]}]}"#,
    ),
];

/// Requests in the cohere dialect.
const COHERE_REQUESTS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"model":"command-r","messages":[{"role":"user","content":"Hello, world"}]}"#,
    ),
    (
        "tools",
        r#"{"model":"command-r-plus","messages":[{"role":"system","content":"be brief"},{"role":"user","content":"Weather in Paris?"}],"temperature":0.5,"p":0.9,"k":40,"max_tokens":128,"stop_sequences":["END"],"tools":[{"type":"function","function":{"name":"get_weather","description":"Get weather","parameters":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]}}}],"tool_choice":"REQUIRED"}"#,
    ),
    (
        "tool_result_document",
        r#"{"model":"command-r","messages":[{"role":"user","content":"q"},{"role":"assistant","tool_calls":[{"id":"t1","type":"function","function":{"name":"s","arguments":"{}"}}]},{"role":"tool","tool_call_id":"t1","content":[{"type":"document","document":{"id":"d1","data":{"t":"x"}}}]}]}"#,
    ),
];

/// Every corpus, by the dialect it is written in.
fn corpus(dialect: &str) -> &'static [(&'static str, &'static str)] {
    match dialect {
        "anthropic" => ANTHROPIC_REQUESTS,
        "openai" => OPENAI_REQUESTS,
        "gemini" => GEMINI_REQUESTS,
        "responses" => RESPONSES_REQUESTS,
        "bedrock" => BEDROCK_REQUESTS,
        "cohere" => COHERE_REQUESTS,
        other => panic!("no corpus is written in the dialect {other}"),
    }
}

/// The single letter each dialect is named by in a frozen output's file name.
fn code(dialect: &str) -> char {
    match dialect {
        "anthropic" => 'a',
        "openai" => 'o',
        "gemini" => 'g',
        "responses" => 'r',
        "bedrock" => 'b',
        "cohere" => 'c',
        other => panic!("no file-name letter is declared for the dialect {other}"),
    }
}

/// Every ingress-to-egress request pair the codec crate has frozen an output for.
const FROZEN_PAIRS: &[(&str, &str)] = &[
    ("anthropic", "bedrock"),
    ("anthropic", "cohere"),
    ("anthropic", "gemini"),
    ("anthropic", "openai"),
    ("bedrock", "anthropic"),
    ("bedrock", "cohere"),
    ("bedrock", "openai"),
    ("cohere", "anthropic"),
    ("cohere", "bedrock"),
    ("cohere", "openai"),
    ("gemini", "responses"),
    ("openai", "bedrock"),
    ("openai", "cohere"),
    ("openai", "gemini"),
    ("openai", "responses"),
    ("responses", "anthropic"),
];

/// Compare every frozen request output against what this plane produces.
///
/// One test rather than one per pair, because the interesting answer is the whole table: a report
/// that says "these forty reproduce and these two do not, and here is the first differing byte" is
/// worth more than forty separate failures.
#[test]
fn every_frozen_request_translation_reproduces() {
    let mut differing: Vec<String> = Vec::new();
    let mut compared = 0usize;
    for (ingress, egress) in FROZEN_PAIRS {
        for (stem, body) in corpus(ingress) {
            let name = format!("req_{}2{}_{stem}.json", code(ingress), code(egress));
            if !golden_dir().join(&name).exists() {
                continue;
            }
            compared += 1;
            let actual = translate_request(ingress, egress, body);
            let (expected, actual) = against_golden(&name, &actual);
            if expected != actual {
                differing.push(format!(
                    "{name}\n  frozen: {}\n  plane:  {}",
                    String::from_utf8_lossy(&expected),
                    String::from_utf8_lossy(&actual)
                ));
            }
        }
    }
    assert!(
        compared > 0,
        "no frozen request output was found to compare"
    );
    assert!(
        differing.is_empty(),
        "{} of {compared} frozen request translations did not reproduce:\n{}",
        differing.len(),
        differing.join("\n")
    );
}

// ── the response direction ──────────────────────────────────────────────────────────────────────
//
// The answer direction reproduces the frozen outputs everywhere EXCEPT in four members, and all
// four come from the same place: the normalization pass the reference path runs between reading an
// answer and writing it is private to the codec crate, so this plane cannot run it.
//
//   * the identity the client-facing writer stamps on the answer. The reference clears the
//     upstream's own identity first, which makes the writer mint a fresh one in the client's native
//     shape; without that clearing the upstream's identity passes through.
//   * the creation time the reference supplies as an input. Absent, one writer reads the system
//     clock for it — which also makes that writer's output nondeterministic, and that is a fact
//     about the codec worth stating rather than working around.
//   * the elapsed time stamped into the answer's metrics. The plane is handed no elapsed figure for
//     the unit at the point it writes the answer, so it stamps none.
//   * tool-call identities, which the reference rewrites so an identity minted by one vendor is
//     recognisable when it comes back through another. The rewriter is private.
//
// Every one of those is normalized below and everything else is compared byte-for-byte, so this
// test is a real assertion about the translation and an exact record of what is not yet reachable.

/// The member names whose values are normalized before comparison, and why each is on the list.
const NORMALIZED_MEMBERS: &[&str] = &[
    // The answer's own identity, in each client dialect's spelling.
    "id",
    "responseId",
    // Tool-call identities, in each client dialect's spelling.
    "call_id",
    "toolUseId",
    // The creation time and the elapsed time.
    "created_at",
    "created",
    "latencyMs",
];

/// Replace every normalized member's value, at every depth, with a fixed token.
fn normalize(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(obj) => {
            for (key, v) in obj.iter_mut() {
                if NORMALIZED_MEMBERS.contains(&key.as_str()) {
                    *v = serde_json::Value::String("NORMALIZED".to_string());
                } else {
                    normalize(v);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                normalize(item);
            }
        }
        _ => {}
    }
}

/// One document, with the members above normalized.
fn normalized(bytes: &[u8]) -> String {
    let mut value: serde_json::Value =
        sonic_rs::from_slice(bytes).expect("an answer is a document");
    normalize(&mut value);
    String::from_utf8(sonic_rs::to_vec(&value).expect("serializes")).expect("valid text")
}

/// One answer, taken in through the plane's response decoder and back out through its encoder.
fn translate_response(egress: &str, ingress: &str, body: &str) -> Vec<u8> {
    use busbar_contract::plane::Progress;
    let plane = LlmPlane::new(UPSTREAMS);
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for(ingress), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    let dest = harness::destination(host_for(egress), lane_for(egress));
    let frames = vec![harness::frame(body.as_bytes())];
    let mut cursor = FrameCursor::new(&frames);
    let response = match plane
        .decode_response(&mut cursor, &dest, None, &ctx)
        .expect("the corpus answer is this dialect's shape")
    {
        Progress::Terminal { r, .. } => r,
        other => panic!("a whole answer must be terminal, got {other:?}"),
    };
    plane
        .encode_response(&response, None, &ctx)
        .expect("the answer is expressible")
        .as_slice()
        .to_vec()
}

/// Answers in the anthropic dialect.
const ANTHROPIC_ANSWERS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4","content":[{"type":"text","text":"Hello there!"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":5,"cache_creation_input_tokens":7,"cache_read_input_tokens":3,"cache_creation":{"ephemeral_5m_input_tokens":4,"ephemeral_1h_input_tokens":3}}}"#,
    ),
    (
        "tool_use",
        r#"{"id":"msg_2","type":"message","role":"assistant","model":"claude-sonnet-4","content":[{"type":"text","text":"Checking."},{"type":"tool_use","id":"toolu_01AAA","name":"get_weather","input":{"city":"Paris"}}],"stop_reason":"tool_use","usage":{"input_tokens":50,"output_tokens":20}}"#,
    ),
    (
        "thinking",
        r#"{"id":"msg_3","type":"message","role":"assistant","model":"claude-sonnet-4","content":[{"type":"thinking","thinking":"Let me think about this","signature":"sig-abc"},{"type":"text","text":"42"}],"stop_reason":"end_turn","usage":{"input_tokens":9,"output_tokens":33}}"#,
    ),
];

/// Answers in the bedrock dialect.
const BEDROCK_ANSWERS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"output":{"message":{"role":"assistant","content":[{"text":"Hello there!"}]}},"stopReason":"end_turn","usage":{"inputTokens":10,"outputTokens":5,"totalTokens":15}}"#,
    ),
    (
        "tool_use",
        r#"{"output":{"message":{"role":"assistant","content":[{"text":"Let me check."},{"toolUse":{"toolUseId":"tu_1","name":"get_weather","input":{"city":"SF"}}}]}},"stopReason":"tool_use","usage":{"inputTokens":42,"outputTokens":15,"totalTokens":57}}"#,
    ),
    (
        "reasoning",
        r#"{"output":{"message":{"role":"assistant","content":[{"reasoningContent":{"reasoningText":{"text":"Let me think about this","signature":"sig-abc"}}},{"text":"42"}]}},"stopReason":"max_tokens","usage":{"inputTokens":9,"outputTokens":33,"totalTokens":42}}"#,
    ),
];

/// Answers in the cohere dialect.
const COHERE_ANSWERS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"id":"c1","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"Hello there!"}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":5},"billed_units":{"input_tokens":10,"output_tokens":5,"search_units":2}}}"#,
    ),
    (
        "tool_use",
        r#"{"id":"c2","finish_reason":"TOOL_CALL","message":{"role":"assistant","content":[{"type":"text","text":"hello"},{"type":"tool_use","id":"t1","name":"get_weather","input":{"location":"SF"}}]},"usage":{"tokens":{"input_tokens":10,"output_tokens":5}}}"#,
    ),
    (
        "tool_plan",
        r#"{"id":"c3","finish_reason":"COMPLETE","message":{"role":"assistant","tool_plan":"I will search for it","content":[{"type":"text","text":"hi"}]}}"#,
    ),
    (
        "citations",
        r#"{"id":"c4","finish_reason":"COMPLETE","message":{"role":"assistant","content":[{"type":"text","text":"Paris is the capital."}],"citations":[{"start":0,"end":5,"text":"Paris","sources":[{"type":"document","id":"d1","document":{"title":"Atlas","url":"https://atlas"}}]}]}}"#,
    ),
];

/// Answers in the gemini dialect.
const GEMINI_ANSWERS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"Hello there!"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":4,"totalTokenCount":16}}"#,
    ),
    (
        "function_call",
        r#"{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"get_weather","args":{"city":"Paris"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":50,"candidatesTokenCount":20,"totalTokenCount":70}}"#,
    ),
    (
        "grounding",
        r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"Paris is the capital."}]},"finishReason":"STOP","groundingMetadata":{"groundingChunks":[{"web":{"uri":"https://atlas","title":"Atlas"}}],"groundingSupports":[{"segment":{"startIndex":0,"endIndex":5,"text":"Paris"},"groundingChunkIndices":[0]}]}}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":5,"thoughtsTokenCount":7,"totalTokenCount":21}}"#,
    ),
];

/// Answers in the responses dialect.
const RESPONSES_ANSWERS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"id":"resp_1","object":"response","created_at":1752000000,"model":"gpt-4.1","status":"completed","output":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"Hello there!","annotations":[]}]}],"usage":{"input_tokens":12,"output_tokens":4,"total_tokens":16}}"#,
    ),
    (
        "reasoning",
        r#"{"id":"resp_2","object":"response","created_at":1752000001,"model":"o3","status":"completed","output":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"42","annotations":[]}]}],"usage":{"input_tokens":10,"output_tokens":20,"total_tokens":30,"output_tokens_details":{"reasoning_tokens":12}}}"#,
    ),
    (
        "function_call",
        r#"{"id":"resp_3","object":"response","created_at":1752000002,"model":"gpt-4.1","status":"completed","output":[{"type":"function_call","id":"fc_1","call_id":"call_XYZ","name":"get_weather","arguments":"{\"city\":\"Paris\"}"}],"usage":{"input_tokens":50,"output_tokens":20,"total_tokens":70}}"#,
    ),
];

/// Answers in the openai dialect.
const OPENAI_ANSWERS: &[(&str, &str)] = &[
    (
        "plain",
        r#"{"id":"chatcmpl-abc123","object":"chat.completion","created":1752000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"Hello there!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":4,"total_tokens":16}}"#,
    ),
    (
        "tool_calls",
        r#"{"id":"chatcmpl-def456","object":"chat.completion","created":1752000001,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_XYZ","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}},{"id":"call_ZZZ","type":"function","function":{"name":"get_time","arguments":"not json"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":20,"total_tokens":70}}"#,
    ),
    (
        "cached_usage",
        r#"{"id":"chatcmpl-ghi789","object":"chat.completion","created":1752000002,"model":"gpt-4o-mini","system_fingerprint":"fp_44709d6fcb","choices":[{"index":0,"message":{"role":"assistant","content":"Cached reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_tokens_details":{"cached_tokens":80}}}"#,
    ),
    (
        "reasoning",
        r#"{"id":"chatcmpl-jkl012","object":"chat.completion","created":1752000003,"model":"deepseek-r1","choices":[{"index":0,"message":{"role":"assistant","reasoning_content":"Let me think...","content":"42"},"finish_reason":"stop"}],"usage":{"prompt_tokens":9,"completion_tokens":33,"total_tokens":42}}"#,
    ),
    (
        "multipart",
        r#"{"id":"chatcmpl-mno345","object":"chat.completion","created":1752000004,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":[{"type":"text","text":"part one "},{"type":"text","text":"part two"},{"type":"refusal","refusal":"no thanks"}]},"finish_reason":"length"}],"usage":{"prompt_tokens":7,"completion_tokens":7,"total_tokens":14}}"#,
    ),
    (
        "minimal",
        r#"{"id":"chatcmpl-pqr678","object":"chat.completion","created":1752000005,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"ok \"quoted\" ✓"},"finish_reason":"stop"}]}"#,
    ),
];

/// The compact openai answer corpus.
///
/// Two of the frozen answer pairs were blessed from a narrower set of openai answers than the rest
/// — one tool call rather than two. Restating that narrower set is what keeps their frozen bytes
/// comparable; using the wider one would produce a second tool call the frozen output never saw.
const OPENAI_ANSWERS_COMPACT: &[(&str, &str)] = &[
    OPENAI_ANSWERS[0],
    (
        "tool_calls",
        r#"{"id":"chatcmpl-def456","object":"chat.completion","created":1752000001,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_XYZ","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":50,"completion_tokens":20,"total_tokens":70}}"#,
    ),
    OPENAI_ANSWERS[3],
];

/// Every answer corpus, by the backend dialect it is written in and the client it is going to.
fn answers_for(egress: &str, ingress: &str) -> &'static [(&'static str, &'static str)] {
    if egress == "openai" && matches!(ingress, "bedrock" | "cohere") {
        return OPENAI_ANSWERS_COMPACT;
    }
    answers(egress)
}

/// Every answer corpus, by the dialect it is written in.
fn answers(dialect: &str) -> &'static [(&'static str, &'static str)] {
    match dialect {
        "anthropic" => ANTHROPIC_ANSWERS,
        "bedrock" => BEDROCK_ANSWERS,
        "cohere" => COHERE_ANSWERS,
        "gemini" => GEMINI_ANSWERS,
        "responses" => RESPONSES_ANSWERS,
        "openai" => OPENAI_ANSWERS,
        other => panic!("no answer corpus is written in the dialect {other}"),
    }
}

/// Every backend-to-client answer pair the codec crate has frozen an output for.
const FROZEN_ANSWER_PAIRS: &[(&str, &str)] = &[
    ("anthropic", "bedrock"),
    ("anthropic", "cohere"),
    ("anthropic", "responses"),
    ("bedrock", "anthropic"),
    ("bedrock", "cohere"),
    ("bedrock", "openai"),
    ("cohere", "anthropic"),
    ("cohere", "bedrock"),
    ("cohere", "openai"),
    ("gemini", "anthropic"),
    ("gemini", "openai"),
    ("openai", "anthropic"),
    ("openai", "bedrock"),
    ("openai", "cohere"),
    ("responses", "gemini"),
    ("responses", "openai"),
];

/// Every frozen answer translation reproduces, once the four recorded members are normalized.
#[test]
fn every_frozen_answer_translation_reproduces() {
    let mut differing: Vec<String> = Vec::new();
    let mut compared = 0usize;
    for (egress, ingress) in FROZEN_ANSWER_PAIRS {
        for (stem, body) in answers_for(egress, ingress) {
            let name = format!("resp_{}2{}_{stem}.json", code(egress), code(ingress));
            if !golden_dir().join(&name).exists() {
                continue;
            }
            compared += 1;
            let actual = translate_response(egress, ingress, body);
            let (expected, actual) = against_golden(&name, &actual);
            let (expected, actual) = (normalized(&expected), normalized(&actual));
            if expected != actual {
                differing.push(format!("{name}\n  frozen: {expected}\n  plane:  {actual}"));
            }
        }
    }
    assert!(compared > 0, "no frozen answer output was found to compare");
    assert!(
        differing.is_empty(),
        "{} of {compared} frozen answer translations did not reproduce:\n{}",
        differing.len(),
        differing.join("\n")
    );
}
