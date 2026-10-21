// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refusals, rendered, against the previous release's recorded answers (the shadow oracle's golden
//! cells, read here and never written): the status, the JSON body and the head field names.

use std::path::{Path, PathBuf};

use busbar_plane_llm::exchange::arrive::envelope_for;
use busbar_plane_llm::exchange::refuse::{kernel_refusal, status_before_arrive, Rendered};
use busbar_plane_llm::refusal::reason;
use serde_json::Value;

fn golden() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testing/shadow-oracle/golden/1.5.5/cells")
}

fn recorded(cell: &str) -> Value {
    let path = golden().join(format!("{cell}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("a recording is JSON")
}

/// The host's entropy, so a dialect that mints a request id mints one: a fixed fill, and no clock.
struct SevensHost;

impl busbar_contract::codec::CodecHost for SevensHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        out.fill(7);
        true
    }

    fn wall_clock_now(&self) -> Option<u64> {
        None
    }
}

/// The handle every codec call here is handed.
const HOST: &dyn busbar_contract::codec::CodecHost = &SevensHost;

/// The bedrock spend-cap cell 1.6.0 answers differently from 1.5.5 (PR #958): accepted difference
/// "C-22 bedrock budget refusal is a declared Converse error" moves its status 400 -> 429 and its
/// `__type` / `x-amzn-errortype` `ServiceQuotaExceededException` -> `ThrottlingException`.
const C22_CELL: &str = "llm__bedrock__bedrock__request__over_budget_total";
const C22_ID: &str = "C-22 bedrock budget refusal is a declared Converse error";

/// The answer 1.6.0 owes for `cell`: the recording, with the owner-accepted differences applied.
fn owed(cell: &str) -> Value {
    let mut want = recorded(cell);
    // Accepted difference A17 (owner, 2026-09-05): an Anthropic-dialect quota refusal names
    // Anthropic's own `billing_error`, where 1.5.5 named OpenAI's `insufficient_quota`.
    if cell == "llm__anthropic__anthropic__request__over_budget_total" {
        want["body"]["json"]["error"]["type"] = Value::String("billing_error".into());
    }
    if cell == C22_CELL {
        // The register entry is present and names this cell, so this can forgive nothing the
        // register does not.
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../testing/shadow-oracle/accepted-differences.json");
        let text = std::fs::read_to_string(&path).expect("the register is readable");
        let register: Value = serde_json::from_str(&text).expect("the register is JSON");
        let entry = register["accepted"]
            .as_array()
            .expect("the register holds `accepted`")
            .iter()
            .find(|e| e["id"].as_str() == Some(C22_ID))
            .unwrap_or_else(|| panic!("accepted difference {C22_ID:?} is in the register"));
        assert!(
            entry["cells"]
                .as_str()
                .is_some_and(|c| c.contains(&cell.replace("__", "\\|"))),
            "accepted difference {C22_ID:?} names {cell}"
        );
        want["status"] = Value::from(429);
        want["body"]["json"]["__type"] = Value::String("ThrottlingException".into());
    }
    want
}

/// The owed answer's status, body and head-field names (content-length is the transport's).
fn assert_matches(cell: &str, r: &Rendered) {
    let want = owed(cell);
    assert_eq!(
        u64::from(r.status),
        want["status"].as_u64().expect("status"),
        "{cell}: status"
    );
    let mut body: Value = serde_json::from_slice(&r.body).expect("the rendered body is JSON");
    // A minted request id is recorded as the oracle's placeholder.
    if let Some(id) = body.get_mut("request_id") {
        *id = Value::String("<ID>".into());
    }
    assert_eq!(body, want["body"]["json"], "{cell}: body");
    let mut have: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
    let mut rec: Vec<&str> = want["headers"]
        .as_object()
        .expect("headers")
        .keys()
        .map(String::as_str)
        .filter(|n| *n != "content-length")
        .collect();
    have.sort_unstable();
    rec.sort_unstable();
    assert_eq!(have, rec, "{cell}: head field names");
    let ct = r
        .fields
        .iter()
        .find(|(n, _)| n == "content-type")
        .map(|(_, v)| v.as_slice());
    assert_eq!(ct, Some(b"application/json".as_slice()), "{cell}");
}

const SIX: [&str; 6] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

fn target_of(dialect: &str) -> &'static str {
    match dialect {
        "anthropic" => "/v1/messages",
        "openai" => "/v1/chat/completions",
        "gemini" => "/v1beta/models/gemini-pro:generateContent",
        "bedrock" => "/model/m/converse",
        "responses" => "/v1/responses",
        _ => "/v2/chat",
    }
}

#[test]
fn an_unauthenticated_caller_reads_its_paths_dialect_in_vendor_terms() {
    for d in SIX {
        let cell = format!("llm__{d}__{d}__request__unauthenticated");
        let status = recorded(&cell)["status"].as_u64().expect("status") as u16;
        // Rendered before the plane read the arrival: the envelope comes from the target alone.
        let envelope = envelope_for(target_of(d));
        assert_eq!(envelope, d, "the path rule names {d}");
        let r = kernel_refusal(
            HOST,
            envelope,
            reason::UNAUTHENTICATED,
            status,
            "unauthenticated",
            0,
        );
        assert_matches(&cell, &r);
    }
}

#[test]
fn a_blocked_limit_reads_the_kernels_text_with_its_retry_advice() {
    for d in SIX {
        for (cond, code) in [
            ("over_budget", 6),
            ("over_budget_total", reason::OVER_BUDGET),
        ] {
            let cell = format!("llm__{d}__{d}__request__{cond}");
            let rec = owed(&cell);
            let status = rec["status"].as_u64().expect("status") as u16;
            let text = if cond == "over_budget" {
                "Rate limit exceeded (group 'broke': requests per day). Please retry after the indicated time."
            } else {
                "You have exceeded your current quota (group 'broke-quota' budget per day exhausted). Please check your plan and billing details."
            };
            let r = kernel_refusal(HOST, d, code, status, text, 30);
            assert_matches(&cell, &r);
        }
    }
}

#[test]
fn every_member_down_reads_the_overloaded_answer() {
    for d in SIX {
        let cell = format!("llm__{d}__{d}__request__upstream_down");
        let r = kernel_refusal(
            HOST,
            d,
            reason::DESTINATION_UNREACHABLE,
            503,
            "The service is temporarily overloaded. Please retry shortly.",
            2,
        );
        assert_matches(&cell, &r);
    }
}

#[test]
fn a_model_no_rate_prices_reads_the_kernels_no_rate_text() {
    let cell = "http.crosscut__unknown-path__openai-suffix";
    let r = kernel_refusal(
        HOST,
        "openai",
        reason::NO_RATE,
        400,
        "no configured rate for model 'nope'",
        0,
    );
    assert_matches(cell, &r);
}

/// A model that names no pool and no configured model: 1.5.5 answered the dialect's not-found
/// envelope, 404, with its model-not-found sentence (1.5.5 `native_ingress`, the destination miss).
/// No cell records it yet, so the recorded not-found envelope of the same dialect (the unknown-path
/// cell) is the shape, with the model's sentence in it.
#[test]
fn a_model_that_resolves_to_no_destination_reads_the_not_found_answer() {
    let message = busbar_plane_llm::exchange::refuse::model_not_found("nope", None);
    assert_eq!(
        message,
        "The model 'nope' does not exist or you do not have access to it."
    );
    let r = kernel_refusal(HOST, "openai", reason::NO_DESTINATION, 404, &message, 0);
    let mut want = recorded("http.crosscut__unknown-path__bare");
    want["body"]["json"]["error"]["message"] = Value::String(message.clone());
    assert_eq!(r.status, 404);
    let body: Value = serde_json::from_slice(&r.body).expect("the rendered body is JSON");
    assert_eq!(body, want["body"]["json"]);
    // The dialect's own copy, where the path gave one, is the sentence.
    assert_eq!(
        busbar_plane_llm::exchange::refuse::model_not_found("m", Some("models/m is not found")),
        "models/m is not found"
    );
}

fn arrival_refusal(
    method: &str,
    target: &str,
    headers: &[(&'static str, &'static str)],
    body: &[u8],
) -> Rendered {
    let h: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
        .collect();
    let d = busbar_plane_llm::exchange::arrive::arrive(method, target, &h, body, &())
        .expect_err("the arrival is refused");
    busbar_plane_llm::exchange::refuse::declined(HOST, &d)
}

#[test]
fn a_path_no_dialect_serves_reads_the_routers_not_found_in_the_paths_envelope() {
    for (cell, path, headers) in [
        (
            "http.crosscut__unknown-path__bare",
            "/definitely/unknown",
            &[][..],
        ),
        (
            "http.crosscut__unknown-path__anthropic-header",
            "/whatever",
            &[("anthropic-version", "2023-06-01")][..],
        ),
        (
            "http.crosscut__unknown-path__anthropic-beta",
            "/whatever",
            &[("anthropic-beta", "x")][..],
        ),
    ] {
        assert_matches(cell, &arrival_refusal("POST", path, headers, b"{}"));
    }
}

#[test]
fn a_dialect_path_hit_with_another_method_reads_the_405() {
    assert_matches(
        "http.crosscut__wrong-method__GET-messages",
        &arrival_refusal("GET", "/v1/messages", &[], b""),
    );
}

#[test]
fn an_unparseable_body_reads_the_dialects_400() {
    for d in SIX {
        let cell = format!("llm__{d}__{d}__request__malformed");
        let r = arrival_refusal(
            "POST",
            target_of(d),
            &[("content-type", "application/json")],
            b"{not json",
        );
        assert_matches(&cell, &r);
    }
}

// ── rehomed from the legacy engine's refusal tests: literal statuses and bodies ─────────────────

use busbar_contract::abi::plane::{RefusalCode, REFUSAL_ANY_DIALECT};
use busbar_plane_llm::exchange::arrive::{Decline, Declined};
use busbar_plane_llm::exchange::refuse::{declined, model_not_found, render};

/// The google.rpc status word 1.5.5's gemini envelope paired with a status.
fn grpc(status: u16) -> &'static str {
    match status {
        403 => "PERMISSION_DENIED",
        404 => "NOT_FOUND",
        429 => "RESOURCE_EXHAUSTED",
        _ => "INVALID_ARGUMENT",
    }
}

/// The AWS exception 1.5.5's bedrock envelope named for a kind.
fn aws(kind: &str) -> &'static str {
    match kind {
        "not_found_error" => "ResourceNotFoundException",
        "permission_error" | "authentication_error" => "AccessDeniedException",
        "rate_limit_error" => "ThrottlingException",
        "insufficient_quota" => "ServiceQuotaExceededException",
        _ => "ValidationException",
    }
}

/// 1.5.5's refusal body, spelled out per dialect (the shapes of the recorded `malformed` and
/// pool-refusal cells); a dialect the plane does not hold reads the agnostic envelope.
fn native(dialect: &str, status: u16, kind: &str, message: &str) -> Value {
    match dialect {
        "openai" | "responses" => serde_json::json!({
            "error": { "code": null, "message": message, "param": null, "type": kind }
        }),
        "cohere" => serde_json::json!({ "message": message }),
        "gemini" => serde_json::json!({
            "error": { "code": status, "message": message, "status": grpc(status) }
        }),
        "bedrock" => serde_json::json!({ "__type": aws(kind), "message": message }),
        "anthropic" => serde_json::json!({
            "error": { "message": message, "type": kind },
            "request_id": "<ID>",
            "type": "error"
        }),
        _ => serde_json::json!({ "error": { "message": message, "type": kind } }),
    }
}

/// The head field names 1.5.5's refusal carried per dialect (content-length is the transport's).
fn native_names(dialect: &str) -> Vec<&'static str> {
    match dialect {
        "bedrock" => vec!["content-type", "x-amzn-errortype", "x-amzn-requestid"],
        "anthropic" => vec!["content-type", "request-id"],
        _ => vec!["content-type"],
    }
}

fn body_of(r: &Rendered) -> Value {
    let mut body: Value = serde_json::from_slice(&r.body).expect("the rendered body is JSON");
    if let Some(id) = body.get_mut("request_id") {
        *id = Value::String("<ID>".into());
    }
    body
}

fn names_of(r: &Rendered) -> Vec<&str> {
    let mut have: Vec<&str> = r.fields.iter().map(|(n, _)| n.as_str()).collect();
    have.sort_unstable();
    have
}

fn value_of<'a>(r: &'a Rendered, name: &str) -> Option<&'a str> {
    r.fields
        .iter()
        .find(|(n, _)| n == name)
        .and_then(|(_, v)| std::str::from_utf8(v).ok())
}

/// The rendered refusal is 1.5.5's: the status, the body and the head field names, literally.
fn assert_native(dialect: &str, r: &Rendered, status: u16, kind: &str, message: &str) {
    assert_eq!(r.status, status, "{dialect}: status");
    assert_eq!(
        body_of(r),
        native(dialect, status, kind, message),
        "{dialect}: body"
    );
    assert_eq!(
        names_of(r),
        native_names(dialect),
        "{dialect}: head field names"
    );
    assert_eq!(
        value_of(r, "content-type"),
        Some("application/json"),
        "{dialect}"
    );
    if dialect == "bedrock" {
        assert_eq!(
            value_of(r, "x-amzn-errortype"),
            Some(aws(kind)),
            "{dialect}"
        );
    }
}

/// The message a rendered refusal carries, wherever its dialect puts it.
fn message_in(dialect: &str, body: &Value) -> Option<String> {
    let at = match dialect {
        "cohere" | "bedrock" => body.get("message"),
        _ => body.pointer("/error/message"),
    };
    at.and_then(Value::as_str).map(str::to_string)
}

/// Rehomes `crates/busbar-llm/src/engine/tests/auth_native_envelope_tests.rs::test_vendor_auth_failure_message_is_plausible_per_proto`.
/// 1.5.5 behaviour pinned: an authentication refusal reads each vendor's own sentence: anthropic
/// "invalid x-api-key", openai and responses "Incorrect API key provided.", gemini "API key not
/// valid. Please pass a valid API key.", cohere "invalid api token", bedrock none (AWS says it in
/// `__type`), and a dialect the plane does not hold the neutral "authentication failed".
/// RED if any of the seven sentences differs or busbar's own wording appears.
#[test]
fn an_authentication_refusal_reads_each_vendors_own_sentence() {
    for (dialect, status, sentence) in [
        ("anthropic", 401, "invalid x-api-key"),
        ("openai", 401, "Incorrect API key provided."),
        ("responses", 401, "Incorrect API key provided."),
        (
            "gemini",
            400,
            "API key not valid. Please pass a valid API key.",
        ),
        ("cohere", 401, "invalid api token"),
        ("some-future-proto", 401, "authentication failed"),
    ] {
        let r = kernel_refusal(
            HOST,
            dialect,
            reason::UNAUTHENTICATED,
            status,
            "unauthenticated",
            0,
        );
        assert_eq!(r.status, status, "{dialect}");
        assert_eq!(
            message_in(dialect, &body_of(&r)).as_deref(),
            Some(sentence),
            "{dialect}"
        );
    }
    let r = kernel_refusal(
        HOST,
        "bedrock",
        reason::UNAUTHENTICATED,
        403,
        "unauthenticated",
        0,
    );
    let body = body_of(&r);
    assert_eq!(body["__type"], "AccessDeniedException");
    assert_eq!(
        body.get("message")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        "",
        "bedrock carries no sentence of its own"
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_ingress_error_bedrock_amzn_headers`.
/// 1.5.5 behaviour pinned: a bedrock caller's 429 rate-limit refusal carries `x-amzn-requestid` and
/// `x-amzn-errortype: ThrottlingException` (the body's `__type`); an openai caller's 400 carries
/// neither. RED if either field is missing on bedrock, the type differs, or openai carries one.
#[test]
fn a_bedrock_throttle_carries_both_amzn_fields_and_an_openai_refusal_neither() {
    for r in [
        render(HOST, "bedrock", 429, "rate_limit_error", "slow down", 0),
        kernel_refusal(
            HOST,
            "bedrock",
            RefusalCode::RateLimited.code(),
            429,
            "slow down",
            0,
        ),
    ] {
        assert!(value_of(&r, "x-amzn-requestid").is_some());
        assert_eq!(
            value_of(&r, "x-amzn-errortype"),
            Some("ThrottlingException")
        );
        assert_eq!(body_of(&r)["__type"], "ThrottlingException");
    }
    let r = render(HOST, "openai", 400, "invalid_request_error", "x", 0);
    assert!(value_of(&r, "x-amzn-requestid").is_none());
    assert!(value_of(&r, "x-amzn-errortype").is_none());
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_ingress_error_has_amzn_headers`.
/// 1.5.5 behaviour pinned: a bedrock 404 carries a UUID-shaped (8-4-4-4-12, lowercase hex)
/// `x-amzn-requestid` and `x-amzn-errortype: ResourceNotFoundException`.
/// RED if the id is not UUID-shaped or the type differs.
#[test]
fn a_bedrock_not_found_carries_a_uuid_request_id_and_its_exception() {
    let r = render(
        HOST,
        "bedrock",
        404,
        "not_found_error",
        "The model 'x' does not exist or you do not have access to it.",
        0,
    );
    let id = value_of(&r, "x-amzn-requestid").expect("x-amzn-requestid");
    let groups: Vec<usize> = id.split('-').map(str::len).collect();
    assert_eq!(groups, [8, 4, 4, 4, 12], "{id}");
    assert!(
        id.chars()
            .all(|ch| ch == '-' || ch.is_ascii_digit() || ('a'..='f').contains(&ch)),
        "{id}"
    );
    assert_eq!(
        value_of(&r, "x-amzn-errortype"),
        Some("ResourceNotFoundException")
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_errortype_header_matches_body_and_others_omit`.
/// 1.5.5 behaviour pinned: for every refusal kind a bedrock caller can read, `x-amzn-errortype`
/// equals the body's `__type`: invalid request ValidationException, rate limit
/// ThrottlingException, permission AccessDeniedException, quota (1.5.5: 400
/// ServiceQuotaExceededException; 1.6.0 by PR #958, accepted difference C-22: 429
/// ThrottlingException, an error Converse declares);
/// the same holds on the kernel's refusals of those classes; an openai 404 carries neither amzn
/// field. RED if a value differs from its body or the table, or openai carries one.
#[test]
fn a_bedrock_refusals_errortype_is_its_body_type_for_every_kind() {
    for (kind, status, code, expected) in [
        (
            "invalid_request_error",
            400,
            RefusalCode::NoRate.code(),
            "ValidationException",
        ),
        (
            "rate_limit_error",
            429,
            RefusalCode::RateLimited.code(),
            "ThrottlingException",
        ),
        (
            "permission_error",
            403,
            RefusalCode::PoolNotPermitted.code(),
            "AccessDeniedException",
        ),
        (
            "insufficient_quota",
            429,
            RefusalCode::OverBudget.code(),
            "ThrottlingException",
        ),
    ] {
        for r in [
            render(HOST, "bedrock", status, kind, "m", 0),
            kernel_refusal(HOST, "bedrock", code, status, "m", 0),
        ] {
            assert_eq!(value_of(&r, "x-amzn-errortype"), Some(expected), "{kind}");
            assert_eq!(body_of(&r)["__type"], expected, "{kind}");
        }
    }
    let r = render(HOST, "openai", 404, "not_found_error", "m", 0);
    assert!(value_of(&r, "x-amzn-requestid").is_none());
    assert!(value_of(&r, "x-amzn-errortype").is_none());
}

/// The kernel answers a model that names no pool and no configured model with the status this
/// plane states for every dialect: 404.
fn no_destination_status() -> u16 {
    let row = busbar_plane_llm::refusal::REFUSAL_STATUSES
        .iter()
        .find(|r| r.dialect == REFUSAL_ANY_DIALECT && r.reason == reason::NO_DESTINATION)
        .expect("the plane states the no-destination status");
    assert_eq!(row.status, 404);
    404
}

/// The kernel's no-destination refusal for an arrival, in its dialect's words.
fn unknown_model(target: &str, body: &[u8]) -> (String, Rendered) {
    let h: Vec<(&[u8], &[u8])> = vec![(b"content-type".as_slice(), b"application/json".as_slice())];
    let a = busbar_plane_llm::exchange::arrive::arrive("POST", target, &h, body, &())
        .expect("the arrival is read");
    let message = model_not_found(
        &a.model,
        a.path_model
            .as_ref()
            .and_then(|p| p.model_not_found_message.as_deref()),
    );
    let r = kernel_refusal(
        HOST,
        a.dialect,
        reason::NO_DESTINATION,
        no_destination_status(),
        &message,
        0,
    );
    (message, r)
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_gemini_unknown_model_404_native_shape`.
/// 1.5.5 behaviour pinned: a gemini caller naming a model nothing serves reads a 404 in gemini's
/// own envelope, `error.status` NOT_FOUND, with gemini's own sentence for the model.
/// RED if the status, the envelope or the sentence differs.
#[test]
fn a_gemini_unknown_model_reads_gemini_not_found() {
    let (message, r) = unknown_model(
        "/v1beta/models/no-such:generateContent",
        br#"{"contents":[]}"#,
    );
    assert_eq!(
        message,
        "models/no-such is not found for API version v1beta, or is not supported for the task you are trying to perform."
    );
    assert_native("gemini", &r, 404, "not_found_error", &message);
    assert_eq!(body_of(&r)["error"]["status"], "NOT_FOUND");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_bedrock_unknown_model_404_native_shape`.
/// 1.5.5 behaviour pinned: a bedrock caller naming a model nothing serves reads a 404 whose body
/// `__type` and `x-amzn-errortype` are both ResourceNotFoundException.
/// RED if the status, the type or the header differs.
#[test]
fn a_bedrock_unknown_model_reads_resource_not_found() {
    let (message, r) = unknown_model("/model/no-such/converse", br#"{"messages":[]}"#);
    assert_eq!(
        message,
        "The model 'no-such' does not exist or you do not have access to it."
    );
    assert_native("bedrock", &r, 404, "not_found_error", &message);
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_cohere_unknown_model_404_native_shape`.
/// 1.5.5 behaviour pinned: a cohere caller naming a model nothing serves reads a 404 in cohere's
/// bare `{"message": ...}` envelope. RED if the status or the envelope differs.
#[test]
fn a_cohere_unknown_model_reads_coheres_not_found() {
    let (message, r) = unknown_model("/v2/chat", br#"{"model":"no-such-model","messages":[]}"#);
    assert_eq!(
        message,
        "The model 'no-such-model' does not exist or you do not have access to it."
    );
    assert_native("cohere", &r, 404, "not_found_error", &message);
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_responses_unknown_model_404_native_shape`.
/// 1.5.5 behaviour pinned: a responses caller naming a model nothing serves reads a 404 whose
/// `error.type` is `not_found_error`, in the OpenAI-identical envelope.
/// RED if the status, the type or the envelope differs.
#[test]
fn a_responses_unknown_model_reads_not_found_error() {
    let (message, r) = unknown_model(
        "/v1/responses",
        br#"{"model":"no-such-model","input":"hi"}"#,
    );
    assert_native("responses", &r, 404, "not_found_error", &message);
    assert_eq!(body_of(&r)["error"]["type"], "not_found_error");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_no_client_error_message_carries_router_prefix`.
/// 1.5.5 behaviour pinned: no refusal a caller can read on any dialect carries `router:` (a proxy
/// tell): bad JSON, a missing model, an unknown model on openai, cohere, responses, gemini,
/// bedrock and the named anthropic surface, a colon-less gemini path, an unsupported gemini
/// action, and a non-object body on gemini and bedrock. Every legacy case is driven.
/// RED if any body contains `router:`.
#[test]
fn no_refusal_body_carries_the_router_prefix() {
    let json = [("content-type", "application/json")];
    let mut bodies: Vec<(String, Rendered)> = Vec::new();
    for (target, body) in [
        ("/v1/chat/completions", &b"not json{"[..]),
        ("/v1/chat/completions", &br#"{"messages":[]}"#[..]),
        ("/v1beta/models/gemini-flash", &b"{}"[..]),
        ("/v1beta/models/foo:countTokens", &br#"{"contents":[]}"#[..]),
        ("/v1beta/models/foo:generateContent", &b"[1,2]"[..]),
        ("/model/foo/converse", &b"[1,2]"[..]),
    ] {
        bodies.push((
            target.to_string(),
            arrival_refusal("POST", target, &json, body),
        ));
    }
    for (target, body) in [
        (
            "/v1/chat/completions",
            &br#"{"model":"no-such","messages":[]}"#[..],
        ),
        ("/v2/chat", &br#"{"model":"no-such","messages":[]}"#[..]),
        ("/v1/responses", &br#"{"model":"no-such","input":"hi"}"#[..]),
        (
            "/v1beta/models/no-such:generateContent",
            &br#"{"contents":[]}"#[..],
        ),
        ("/model/no-such/converse", &br#"{"messages":[]}"#[..]),
        (
            "/no-such/v1/messages",
            &br#"{"model":"no-such","messages":[],"max_tokens":16}"#[..],
        ),
    ] {
        bodies.push((target.to_string(), unknown_model(target, body).1));
    }
    assert_eq!(bodies.len(), 12, "every legacy case");
    for (target, r) in bodies {
        let text = String::from_utf8_lossy(&r.body);
        assert!(!text.contains("router:"), "{target} ({}): {text}", r.status);
    }
}

/// The kernel's pool refusal (the key may not reach the pool it named), as a dialect renders it.
fn pool_not_permitted(dialect: &str) -> Rendered {
    kernel_refusal(
        HOST,
        dialect,
        RefusalCode::PoolNotPermitted.code(),
        403,
        "Your API key does not have permission to access this resource.",
        0,
    )
}

const NOT_PERMITTED: &str = "Your API key does not have permission to access this resource.";

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_governance_pool_acl_403_cohere_native_envelope`.
/// 1.5.5 behaviour pinned: a cohere caller refused by the pool ACL reads a 403 JSON
/// `{"message": "Your API key does not have permission to access this resource."}`.
/// RED if the status, the envelope or the sentence differs.
#[test]
fn a_cohere_pool_refusal_reads_coheres_403() {
    assert_native(
        "cohere",
        &pool_not_permitted("cohere"),
        403,
        "permission_error",
        NOT_PERMITTED,
    );
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_governance_pool_acl_403_responses_native_envelope`.
/// 1.5.5 behaviour pinned: a responses caller refused by the pool ACL reads a 403 JSON whose
/// `error.type` is `permission_error`. RED if the status, the type or the envelope differs.
#[test]
fn a_responses_pool_refusal_reads_permission_error() {
    let r = pool_not_permitted("responses");
    assert_native("responses", &r, 403, "permission_error", NOT_PERMITTED);
    assert_eq!(body_of(&r)["error"]["type"], "permission_error");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_governance_pool_acl_403_openai_native_envelope`.
/// 1.5.5 behaviour pinned: an openai caller refused by the pool ACL reads a 403 JSON whose
/// `error.type` is `permission_error`. RED if the status, the type or the envelope differs.
#[test]
fn an_openai_pool_refusal_reads_permission_error() {
    let r = pool_not_permitted("openai");
    assert_native("openai", &r, 403, "permission_error", NOT_PERMITTED);
    assert_eq!(body_of(&r)["error"]["type"], "permission_error");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_governance_pool_acl_403_gemini_native_envelope`.
/// 1.5.5 behaviour pinned: a gemini caller refused by the pool ACL reads a 403 JSON with
/// `error.code` 403 and `error.status` PERMISSION_DENIED. RED if any of the three differs.
#[test]
fn a_gemini_pool_refusal_reads_permission_denied() {
    let r = pool_not_permitted("gemini");
    assert_native("gemini", &r, 403, "permission_error", NOT_PERMITTED);
    assert_eq!(body_of(&r)["error"]["code"], 403);
    assert_eq!(body_of(&r)["error"]["status"], "PERMISSION_DENIED");
}

/// Rehomes `crates/busbar-llm/src/engine/tests/ingress_integration_tests.rs::test_governance_pool_acl_403_bedrock_native_envelope`.
/// 1.5.5 behaviour pinned: a bedrock caller refused by the pool ACL reads a 403 JSON whose
/// `__type` and `x-amzn-errortype` are AccessDeniedException, with an `x-amzn-requestid`.
/// RED if the status, the type, either header or the envelope differs.
#[test]
fn a_bedrock_pool_refusal_reads_access_denied() {
    let r = pool_not_permitted("bedrock");
    assert_native("bedrock", &r, 403, "permission_error", NOT_PERMITTED);
    assert_eq!(
        value_of(&r, "x-amzn-errortype"),
        Some("AccessDeniedException")
    );
    assert!(value_of(&r, "x-amzn-requestid").is_some());
}

/// Every dialect, as the arrival refusals are rendered in.
const SIX_AND_NONE: [&str; 7] = [
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
    "no-such-protocol",
];

fn refusal_in(
    envelope: &'static str,
    why: Decline,
    status: u16,
    kind: &'static str,
    message: &'static str,
) -> Rendered {
    declined(
        HOST,
        &Declined {
            why,
            status,
            envelope,
            kind,
            message: message.into(),
            entry: None,
        },
    )
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::a_non_object_body_refuses_with_the_live_arms_bytes`.
/// 1.5.5 behaviour pinned: a body that is JSON but not an object (`[]`, `"a string"`, `7`) on a
/// path-model arrival is refused 400 "Request body must be a JSON object." (not the parse
/// sentence), and that refusal reads 1.5.5's bytes in every dialect's envelope.
/// RED if any of the three bodies is accepted or refused otherwise, or a dialect's bytes differ.
#[test]
fn a_non_object_body_reads_the_released_400_in_every_dialect() {
    let json = [("content-type", "application/json")];
    for body in [&b"[]"[..], &b"\"a string\""[..], &b"7"[..]] {
        for (dialect, target) in [
            ("gemini", "/v1beta/models/m:generateContent"),
            ("bedrock", "/model/m/converse"),
        ] {
            let h: Vec<(&[u8], &[u8])> = json
                .iter()
                .map(|(k, v)| (k.as_bytes(), v.as_bytes()))
                .collect();
            let d = busbar_plane_llm::exchange::arrive::arrive("POST", target, &h, body, &())
                .expect_err("refused");
            assert_eq!(d.why, Decline::NotAnObject, "{dialect}");
            assert_native(
                dialect,
                &arrival_refusal("POST", target, &json, body),
                400,
                "invalid_request_error",
                "Request body must be a JSON object.",
            );
        }
    }
    for dialect in SIX {
        assert_native(
            dialect,
            &refusal_in(
                dialect,
                Decline::NotAnObject,
                400,
                "invalid_request_error",
                "Request body must be a JSON object.",
            ),
            400,
            "invalid_request_error",
            "Request body must be a JSON object.",
        );
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::the_reserialize_guard_renders_the_live_arms_bytes`.
/// 1.5.5 behaviour pinned: the re-serialization guard (unreachable on the request path, so pinned
/// by its rendering) reads 400 "The request body could not be processed." in every dialect's
/// envelope. RED if a dialect's bytes differ.
#[test]
fn the_reserialize_guard_reads_the_released_400_in_every_dialect() {
    for dialect in SIX {
        assert_native(
            dialect,
            &refusal_in(
                dialect,
                Decline::Reserialize,
                400,
                "invalid_request_error",
                "The request body could not be processed.",
            ),
            400,
            "invalid_request_error",
            "The request body could not be processed.",
        );
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::every_arrival_refusal_renders_through_audit_to_the_legacy_bytes`.
/// 1.5.5 behaviour pinned: the whole arrival refusal set (the parse 400, the non-object 400, the
/// re-serialization 400) reads 1.5.5's bytes in every dialect AND in a dialect the plane does not
/// hold (the agnostic envelope), and no refusal grows a head field of its own beyond its dialect's.
/// RED if the set changes size or any cell's status, body or head fields differ.
#[test]
fn every_arrival_refusal_reads_the_released_bytes_in_every_dialect_and_none() {
    let cases = [
        (
            Decline::BodyParse,
            "We could not parse the JSON body of your request.",
        ),
        (Decline::NotAnObject, "Request body must be a JSON object."),
        (
            Decline::Reserialize,
            "The request body could not be processed.",
        ),
    ];
    assert_eq!(cases.len(), 3, "the closed set grew without a case here");
    for dialect in SIX_AND_NONE {
        for (why, message) in cases {
            let r = refusal_in(dialect, why, 400, "invalid_request_error", message);
            assert_native(dialect, &r, 400, "invalid_request_error", message);
        }
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/arrival.rs::a_refusal_renders_even_with_no_dialect_registered`.
/// 1.5.5 behaviour pinned: a parse refusal (400) for a dialect the plane does not hold still renders
/// a 400 with a non-empty envelope (the agnostic one), never a panic or an empty body.
/// RED if the status differs or the body is empty.
#[test]
fn a_parse_refusal_renders_for_a_dialect_the_plane_does_not_hold() {
    let r = refusal_in(
        "no-such-protocol",
        Decline::BodyParse,
        400,
        "invalid_request_error",
        "We could not parse the JSON body of your request.",
    );
    assert_eq!(r.status, 400);
    assert!(!r.body.is_empty());
    assert_eq!(
        body_of(&r),
        serde_json::json!({ "error": {
            "message": "We could not parse the JSON body of your request.",
            "type": "invalid_request_error"
        }})
    );
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::the_missing_model_refusal_carries_the_live_arms_bytes`.
/// 1.5.5 behaviour pinned: the missing-model refusal reads 400 "Missing required parameter:
/// 'model'." in each of the six dialects' envelopes, with the dialect's head fields; the four
/// body-model dialects are driven from a real arrival that names no model.
/// RED if any dialect's status, body or head fields differ.
#[test]
fn the_missing_model_refusal_reads_the_released_bytes_in_every_dialect() {
    let json = [("content-type", "application/json")];
    let message = "Missing required parameter: 'model'.";
    for dialect in ["anthropic", "openai", "responses", "cohere"] {
        let r = arrival_refusal("POST", target_of(dialect), &json, br#"{"messages":[]}"#);
        assert_native(dialect, &r, 400, "invalid_request_error", message);
    }
    for dialect in SIX {
        let r = refusal_in(
            dialect,
            Decline::MissingModel,
            400,
            "invalid_request_error",
            message,
        );
        assert_native(dialect, &r, 400, "invalid_request_error", message);
    }
}

/// Rehomes `crates/busbar-llm/src/unit/tests/decode.rs::every_decode_refusal_renders_through_audit_to_the_legacy_bytes`.
/// 1.5.5 behaviour pinned: the whole decode refusal set, the protocol miss (404 "This protocol
/// does not support that operation."), the endpoint miss (404 "This endpoint does not support
/// that operation.") and the missing model (400), reads 1.5.5's bytes in every dialect and in a
/// dialect the plane does not hold. RED if the set changes size or any cell differs.
#[test]
fn every_decode_refusal_reads_the_released_bytes_in_every_dialect_and_none() {
    let cases = [
        (
            Decline::UnsupportedOperation,
            404,
            "not_found_error",
            "This protocol does not support that operation.",
        ),
        (
            Decline::UnsupportedOperation,
            404,
            "not_found_error",
            "This endpoint does not support that operation.",
        ),
        (
            Decline::MissingModel,
            400,
            "invalid_request_error",
            "Missing required parameter: 'model'.",
        ),
    ];
    assert_eq!(cases.len(), 3, "the closed set grew without a case here");
    for dialect in SIX_AND_NONE {
        for (why, status, kind, message) in cases {
            let r = refusal_in(dialect, why, status, kind, message);
            assert_native(dialect, &r, status, kind, message);
        }
    }
}

/// THE KERNEL-SHAPED REFUSALS, RENDERED BY THE PLANE (ARCHITECT ruling 2026-10-16, 3b B): the kernel
/// decides the reason, the status and the words — a method no route at the path takes
/// (`MethodNotAllowed`, 405), a body over the cap (`BodyTooLarge`, 413) — and the plane renders the
/// body in the dialect its path rule reads off the target, byte for byte the previous release's
/// recorded answer. RED arms: the reason's own word is never the message, and a reason classed
/// otherwise would wear another kind.
#[test]
fn the_kernels_method_and_size_refusals_read_as_the_previous_release_answered() {
    use busbar_contract::abi::plane::reason_code;
    use busbar_contract::caps::ReasonCode;
    const METHOD: &str = "method not allowed for this resource";
    const OVERSIZED: &str = "request body exceeds the maximum allowed size";
    for (cell, target, reason, status, text) in [
        (
            "http.crosscut__wrong-method__GET-messages",
            "/v1/messages",
            ReasonCode::MethodNotAllowed,
            405,
            METHOD,
        ),
        (
            "http.crosscut__413__anthropic",
            "/v1/messages",
            ReasonCode::BodyTooLarge,
            413,
            OVERSIZED,
        ),
        (
            "http.crosscut__413__openai",
            "/v1/chat/completions",
            ReasonCode::BodyTooLarge,
            413,
            OVERSIZED,
        ),
        (
            "http.crosscut__413__gemini-path",
            "/v1beta/models/m-gemini:generateContent",
            ReasonCode::BodyTooLarge,
            413,
            OVERSIZED,
        ),
    ] {
        let r = kernel_refusal(
            HOST,
            envelope_for(target),
            reason_code(reason),
            status,
            text,
            0,
        );
        assert_matches(cell, &r);
        assert!(
            !String::from_utf8_lossy(&r.body).contains(reason.as_str()),
            "{cell}: the kernel's words, not the reason's"
        );
    }
}

/// EVERY DIALECT, AS THE PREVIOUS RELEASE'S KERNEL WROTE IT (ARCHITECT ruling 2026-10-16, 3b B): the
/// previous release answered these three refusals with the dialect's own error writer over
/// `(status, kind, message)` — 405 `invalid_request` "method not allowed for this resource", 413
/// `request_too_large` "request body exceeds the maximum allowed size", and a handler panic's 500
/// `api_error` "internal error". The plane's rendering of the kernel's reason is that same writing,
/// field for field and byte for byte, in all six dialects. RED arm: the reason classes are what pick
/// the kind, so a reason classed otherwise breaks the equality.
#[test]
fn the_kernels_refusals_are_the_previous_releases_writing_in_every_dialect() {
    use busbar_contract::abi::plane::reason_code;
    use busbar_contract::caps::ReasonCode;
    use busbar_contract::protocol::{KIND_API_ERROR, KIND_INVALID_REQUEST, KIND_REQUEST_TOO_LARGE};
    use busbar_plane_llm::exchange::refuse::render;
    for d in SIX {
        for (reason, status, kind, text) in [
            (
                ReasonCode::MethodNotAllowed,
                405,
                KIND_INVALID_REQUEST,
                "method not allowed for this resource",
            ),
            (
                ReasonCode::BodyTooLarge,
                413,
                KIND_REQUEST_TOO_LARGE,
                "request body exceeds the maximum allowed size",
            ),
            (ReasonCode::Internal, 500, KIND_API_ERROR, "internal error"),
        ] {
            let by_reason = kernel_refusal(HOST, d, reason_code(reason), status, text, 0);
            let as_written = render(HOST, d, status, kind, text, 0);
            assert_eq!(by_reason, as_written, "{d} {reason}");
        }
    }
}

/// A REFUSAL BEFORE `arrive` WEARS ITS TARGET'S BAD-CREDENTIAL STATUS: a refusal the kernel decides
/// on a path no route takes at its verb carries no route's dialect, so the target's path rule names
/// both the envelope and the status, each the recorded 1.5.5 unauthenticated cell's, whatever status
/// the kernel handed. Any other reason, and a dialect the plane does not hold, keep the kernel's.
/// RED: a residual bedrock (403) or gemini (400) bad credential answered 401.
#[test]
fn a_refusal_before_arrive_wears_its_targets_bad_credential_status() {
    for dialect in [
        "anthropic",
        "bedrock",
        "cohere",
        "gemini",
        "openai",
        "responses",
    ] {
        let cell = recorded(&format!(
            "llm__{dialect}__{dialect}__request__unauthenticated"
        ));
        assert_eq!(
            Some(u64::from(status_before_arrive(
                dialect,
                reason::UNAUTHENTICATED,
                401
            ))),
            cell["status"].as_u64(),
            "{dialect}"
        );
    }
    assert_eq!(status_before_arrive("bedrock", reason::NO_RATE, 400), 400);
    assert_eq!(
        status_before_arrive("some-future-proto", reason::UNAUTHENTICATED, 401),
        401
    );
}
