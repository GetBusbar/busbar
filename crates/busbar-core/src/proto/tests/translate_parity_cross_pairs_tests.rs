// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Cross-protocol TRANSLATE-PATH byte-parity goldens for the OTHER high-traffic dialect pairs.
//!
//! `translate_parity_golden_tests.rs` pins the single anthropic⇄openai pair. This file extends that
//! corpus to the remaining pairs among the four high-traffic dialects (anthropic `a`, openai chat
//! `o`, gemini `g`, responses `r`), so every important ingress→egress translation among them has a
//! frozen, reviewable "correct bytes" reference. It replays the SAME production step list the sibling
//! file documents and generates its goldens the SAME way (`BUSBAR_BLESS_GOLDEN=1`), so this is a pure
//! extension of that fidelity wall, not a new mechanism.
//!
//! Pairs covered here (client `x`, backend `y` → `req_xy` request goldens, `resp_yx` response
//! goldens), chosen so each of the four dialects appears as BOTH a request reader/writer AND a
//! response reader/writer at least once across this file and its sibling:
//!
//!   * {anthropic, gemini}   client anthropic  → `req_a2g`, `resp_g2a`
//!   * {openai, gemini}      client openai     → `req_o2g`, `resp_g2o`
//!   * {openai, responses}   client openai     → `req_o2r`, `resp_r2o`
//!   * {responses, anthropic} client responses → `req_r2a`, `resp_a2r`
//!   * {gemini, responses}   client gemini     → `req_g2r`, `resp_r2g`
//!
//! REQUEST goldens are FULLY DETERMINISTIC — the request writers mint no random ids — so they are
//! compared byte-exact with no normalization. RESPONSE goldens carry the ingress writer's synthesized
//! id(s) (the ONLY nondeterministic bytes), which are shape-asserted and then NORMALIZED to a fixed
//! token before comparison, exactly as the sibling file normalizes the anthropic `msg_...` id. Each
//! ingress writer mints its own native id shape (anthropic `msg_01…`, openai `chatcmpl-…`, responses
//! `resp_…` plus per-item `msg_/fc_/rs_`, gemini an unprefixed `responseId`); the bedrock response
//! writer mints none.
//!
//! Regenerating goldens (ONLY for an intentional wire-shape change):
//!   `BUSBAR_BLESS_GOLDEN=1 cargo test -p busbar-core translate_parity_cross_pairs` then commit the
//!   diff.

use serde_json::{json, Value};

/// The lane wire model stamped on the egress request (mirrors `rewrite_model_if_needed`); shared with
/// the sibling file's convention. Deterministic, which is all the byte-golden needs.
const LANE_MODEL: &str = "gpt-4o-mini";
/// Fixed epoch handed to `prepare_for_ingress` for the synthesized `created` boundary signal.
const FIXED_NOW: u64 = 1_752_000_000;

fn golden_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/proto/tests/golden")
}

fn bless() -> bool {
    std::env::var_os("BUSBAR_BLESS_GOLDEN").is_some()
}

/// Compare `actual` to the committed golden `name`, or rewrite it in bless mode. Byte-for-byte with
/// the sibling harness's `check_golden`.
fn check_golden(name: &str, actual: &[u8]) {
    let path = golden_dir().join(name);
    if bless() {
        std::fs::create_dir_all(golden_dir()).expect("create golden dir");
        std::fs::write(&path, actual).expect("write golden");
        return;
    }
    let expected = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("missing golden {name} ({e}); run with BUSBAR_BLESS_GOLDEN=1"));
    assert_eq!(
        expected,
        actual,
        "translate output drifted from golden {name}\n--- golden ---\n{}\n--- actual ---\n{}",
        String::from_utf8_lossy(&expected),
        String::from_utf8_lossy(actual),
    );
}

/// The production REQUEST translate steps for an arbitrary `ingress`→`egress` lane, byte-for-byte.
/// Mirrors `translate_request_a2o` in the sibling file exactly, parameterized on the two protocols.
fn translate_request(ingress: &'static str, egress: &str, body: &str) -> Vec<u8> {
    let ingress_p = crate::proto::protocol_for(ingress).expect("ingress protocol");
    let egress_p = crate::proto::protocol_for(egress).expect("egress protocol");
    let v: Value = crate::json::parse(body.as_bytes()).expect("valid corpus JSON");
    let mut req = ingress_p.reader().read_request(&v).expect("reads");
    crate::proto::chat_handle::chat_prepare_for_egress(
        &mut req,
        &crate::ir::egress_prep::EgressPrep {
            thought_signature_fill: false,
            ingress_protocol: ingress,
            egress_requires_max_tokens: egress_p.decl().is_some_and(|d| d.requires_max_tokens),
            lane_default_max_tokens: None,
            global_default_max_tokens: 4096,
            reasoning_allowed: true,
            reasoning_budgets: crate::ir::REASONING_BUDGET_DEFAULTS,
            prompt_caching_allowed: true,
            cache_control_cap: None,
        },
    );
    let mut out = egress_p.writer().write_request(&req);
    crate::proxy::strip_router_shim_keys(&mut out, egress);
    egress_p
        .writer()
        .rewrite_model_if_needed(&mut out, LANE_MODEL);
    crate::json::to_vec(&out).expect("serializes")
}

/// Shape-assert an ingress-synthesized id at `obj[key]` (`<prefix><base62 tail>`) and normalize it to
/// a fixed token, so everything else is compared byte-exact. No-op when the key is absent.
fn normalize_id(obj: &mut serde_json::Map<String, Value>, key: &str, prefix: &str) {
    if let Some(id) = obj.get(key).and_then(Value::as_str).map(str::to_owned) {
        assert!(
            id.starts_with(prefix)
                && id.len() > prefix.len()
                && id.as_bytes()[prefix.len()..]
                    .iter()
                    .all(u8::is_ascii_alphanumeric),
            "ingress-synthesized id at `{key}` must be `{prefix}<base62>`, got {id:?}"
        );
        obj.insert(key.to_string(), json!(format!("{prefix}NORMALIZED")));
    }
}

/// Normalize whatever id(s) the given `ingress` response writer synthesizes. The sibling file's
/// anthropic case is `msg_01<24 base62>`; the others are their own native shapes. Bedrock mints none,
/// so it is a deliberate no-op; gemini mints only an unprefixed `responseId` token.
fn normalize_ingress_ids(ingress: &str, out: &mut Value) {
    let Some(obj) = out.as_object_mut() else {
        return;
    };
    match ingress {
        "anthropic" => normalize_id(obj, "id", "msg_01"),
        "openai" => normalize_id(obj, "id", "chatcmpl-"),
        "cohere" => normalize_id(obj, "id", "c"),
        // Gemini synthesizes a top-level `responseId` (an unprefixed base62 token) on a
        // cross-protocol egress; no other field is nondeterministic.
        "gemini" => normalize_id(obj, "responseId", ""),
        "responses" => {
            normalize_id(obj, "id", "resp_");
            // Every `output[]` item carries a synthesized item-level `id` (`msg_`/`fc_`/`rs_`) that
            // the IR has no carrier for — distinct from a passed-through `call_id`, which is NOT
            // touched. Normalize each so a tool-call or reasoning item stays byte-comparable.
            if let Some(items) = obj.get_mut("output").and_then(Value::as_array_mut) {
                for item in items {
                    let Some(item_obj) = item.as_object_mut() else {
                        continue;
                    };
                    let Some(id) = item_obj
                        .get("id")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                    else {
                        continue;
                    };
                    let prefix = ["msg_", "fc_", "rs_"]
                        .into_iter()
                        .find(|p| id.starts_with(p))
                        .unwrap_or_else(|| {
                            panic!("responses output item id has an unexpected prefix: {id:?}")
                        });
                    assert!(
                        id.len() > prefix.len()
                            && id.as_bytes()[prefix.len()..]
                                .iter()
                                .all(u8::is_ascii_alphanumeric),
                        "responses item id must be `{prefix}<base62>`, got {id:?}"
                    );
                    item_obj.insert("id".to_string(), json!(format!("{prefix}NORMALIZED")));
                }
            }
        }
        // gemini / bedrock synthesize no id — nothing to normalize.
        _ => {}
    }
}

/// The production RESPONSE translate steps for an arbitrary `egress`→`ingress` lane, byte-for-byte,
/// with the ingress writer's synthesized id(s) normalized. Mirrors `translate_response_o2a`.
fn translate_response(egress: &str, ingress: &'static str, body: &str) -> Vec<u8> {
    let egress_p = crate::proto::protocol_for(egress).expect("egress protocol");
    let ingress_p = crate::proto::protocol_for(ingress).expect("ingress protocol");
    let v: Value = crate::json::parse(body.as_bytes()).expect("valid corpus JSON");
    let mut resp = egress_p.reader().read_response(&v).expect("reads");
    crate::proto::chat_handle::chat_prepare_for_ingress(&mut resp, ingress, FIXED_NOW);
    let mut out = ingress_p.writer().write_response(&resp);
    ingress_p
        .writer()
        .inject_response_metrics(&mut out, Some(123));
    normalize_ingress_ids(ingress, &mut out);
    crate::json::to_vec(&out).expect("serializes")
}

// ─────────────────────────────────────────────────────────────────────────────
// INPUT CORPORA — hand-written bodies in the SOURCE dialect (the ingress dialect for a request, the
// egress/backend dialect for a response). Only the INPUTS are hand-written; every expected OUTPUT
// under tests/golden/ is blessed from the real translate path above. Bodies are adapted from the
// vetted fixtures in `roundtrip_fidelity_tests.rs` so each is known to parse.
// ─────────────────────────────────────────────────────────────────────────────

/// OpenAI Chat REQUEST bodies (client=openai): plain, sampling+system+tools+strict, attachments.
const OPENAI_REQUEST_CORPUS: &[(&str, &str)] = &[
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

/// Gemini REQUEST bodies (client=gemini): plain, system+config+tools, non-image inline data.
const GEMINI_REQUEST_CORPUS: &[(&str, &str)] = &[
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

/// OpenAI Responses REQUEST bodies (client=responses): plain string input, tools+strict, input_file.
const RESPONSES_REQUEST_CORPUS: &[(&str, &str)] = &[
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

/// Gemini RESPONSE bodies (backend=gemini): plain, functionCall, reasoning(thoughts), grounding.
const GEMINI_RESPONSE_CORPUS: &[(&str, &str)] = &[
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

/// Anthropic RESPONSE bodies (backend=anthropic): plain+full usage, tool_use, thinking.
const ANTHROPIC_RESPONSE_CORPUS: &[(&str, &str)] = &[
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

/// OpenAI Responses RESPONSE bodies (backend=responses): plain, reasoning usage, function_call.
const RESPONSES_RESPONSE_CORPUS: &[(&str, &str)] = &[
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

/// The anthropic REQUEST corpus is already vetted in the sibling file; reuse it verbatim for the
/// `a2g` lane rather than duplicate it.
use super::translate_parity_golden_tests::REQUEST_CORPUS as ANTHROPIC_REQUEST_CORPUS;

// ─────────────────────────────────────────────────────────────────────────────
// REQUEST goldens (deterministic; no normalization).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn req_anthropic_to_gemini() {
    for (name, body) in ANTHROPIC_REQUEST_CORPUS {
        // The sibling names are `req_a2o_<x>.json`; rename the `a2o` stem to `a2g` for this lane.
        let stem = name.strip_prefix("req_a2o_").expect("sibling naming");
        let out = translate_request("anthropic", "gemini", body);
        check_golden(&format!("req_a2g_{stem}"), &out);
    }
}

#[test]
fn req_openai_to_gemini() {
    for (name, body) in OPENAI_REQUEST_CORPUS {
        let out = translate_request("openai", "gemini", body);
        check_golden(&format!("req_o2g_{name}.json"), &out);
    }
}

#[test]
fn req_openai_to_responses() {
    for (name, body) in OPENAI_REQUEST_CORPUS {
        let out = translate_request("openai", "responses", body);
        check_golden(&format!("req_o2r_{name}.json"), &out);
    }
}

#[test]
fn req_responses_to_anthropic() {
    for (name, body) in RESPONSES_REQUEST_CORPUS {
        let out = translate_request("responses", "anthropic", body);
        check_golden(&format!("req_r2a_{name}.json"), &out);
    }
}

#[test]
fn req_gemini_to_responses() {
    for (name, body) in GEMINI_REQUEST_CORPUS {
        let out = translate_request("gemini", "responses", body);
        check_golden(&format!("req_g2r_{name}.json"), &out);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// RESPONSE goldens (ingress-synthesized ids normalized).
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn resp_gemini_to_anthropic() {
    for (name, body) in GEMINI_RESPONSE_CORPUS {
        let out = translate_response("gemini", "anthropic", body);
        check_golden(&format!("resp_g2a_{name}.json"), &out);
    }
}

#[test]
fn resp_gemini_to_openai() {
    for (name, body) in GEMINI_RESPONSE_CORPUS {
        let out = translate_response("gemini", "openai", body);
        check_golden(&format!("resp_g2o_{name}.json"), &out);
    }
}

#[test]
fn resp_anthropic_to_responses() {
    for (name, body) in ANTHROPIC_RESPONSE_CORPUS {
        let out = translate_response("anthropic", "responses", body);
        check_golden(&format!("resp_a2r_{name}.json"), &out);
    }
}

#[test]
fn resp_responses_to_openai() {
    for (name, body) in RESPONSES_RESPONSE_CORPUS {
        let out = translate_response("responses", "openai", body);
        check_golden(&format!("resp_r2o_{name}.json"), &out);
    }
}

#[test]
fn resp_responses_to_gemini() {
    for (name, body) in RESPONSES_RESPONSE_CORPUS {
        let out = translate_response("responses", "gemini", body);
        check_golden(&format!("resp_r2g_{name}.json"), &out);
    }
}
