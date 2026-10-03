// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refusals, rendered, against the previous release's recorded answers (the shadow oracle's golden
//! cells, read here and never written): the status, the JSON body and the head field names.

use std::path::{Path, PathBuf};

use busbar_plane_llm::exchange::arrive::envelope_for;
use busbar_plane_llm::exchange::refuse::{kernel_refusal, Rendered};
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

/// The host's entropy, so a dialect that mints a request id mints one.
fn entropy() {
    busbar_contract::codec::install_entropy_source(|out| {
        out.fill(7);
        true
    });
}

/// The recorded answer's status, body and head-field names (content-length is the transport's).
fn assert_matches(cell: &str, r: &Rendered) {
    let mut want = recorded(cell);
    // Accepted difference A17 (owner, 2026-09-05): an Anthropic-dialect quota refusal names
    // Anthropic's own `billing_error`, where 1.5.5 named OpenAI's `insufficient_quota`.
    if cell == "llm__anthropic__anthropic__request__over_budget_total" {
        want["body"]["json"]["error"]["type"] = Value::String("billing_error".into());
    }
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
    entropy();
    for d in SIX {
        let cell = format!("llm__{d}__{d}__request__unauthenticated");
        let status = recorded(&cell)["status"].as_u64().expect("status") as u16;
        // Rendered before the plane read the arrival: the envelope comes from the target alone.
        let envelope = envelope_for(target_of(d));
        assert_eq!(envelope, d, "the path rule names {d}");
        let r = kernel_refusal(
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
    entropy();
    for d in SIX {
        for (cond, code) in [
            ("over_budget", 6),
            ("over_budget_total", reason::OVER_BUDGET),
        ] {
            let cell = format!("llm__{d}__{d}__request__{cond}");
            let rec = recorded(&cell);
            let status = rec["status"].as_u64().expect("status") as u16;
            let text = if cond == "over_budget" {
                "Rate limit exceeded (group 'broke': requests per day). Please retry after the indicated time."
            } else {
                "You have exceeded your current quota (group 'broke-quota' budget per day exhausted). Please check your plan and billing details."
            };
            let r = kernel_refusal(d, code, status, text, 30);
            assert_matches(&cell, &r);
        }
    }
}

#[test]
fn every_member_down_reads_the_overloaded_answer() {
    entropy();
    for d in SIX {
        let cell = format!("llm__{d}__{d}__request__upstream_down");
        let r = kernel_refusal(
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
    entropy();
    let cell = "http.crosscut__unknown-path__openai-suffix";
    let r = kernel_refusal(
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
    entropy();
    let message = busbar_plane_llm::exchange::refuse::model_not_found("nope", None);
    assert_eq!(
        message,
        "The model 'nope' does not exist or you do not have access to it."
    );
    let r = kernel_refusal("openai", reason::NO_DESTINATION, 404, &message, 0);
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
    busbar_plane_llm::exchange::refuse::declined(&d)
}

#[test]
fn a_path_no_dialect_serves_reads_the_routers_not_found_in_the_paths_envelope() {
    entropy();
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
    entropy();
    assert_matches(
        "http.crosscut__wrong-method__GET-messages",
        &arrival_refusal("GET", "/v1/messages", &[], b""),
    );
}

#[test]
fn an_unparseable_body_reads_the_dialects_400() {
    entropy();
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
