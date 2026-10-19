//! A refusal wears the dialect's own shape.
//!
//! A client that gets a refusal in a shape its own library does not parse learns nothing from it,
//! so the envelope has to be the dialect's. It is not built here: the dialect's own error writer
//! builds it, through the exchange step the plane's door renders every refusal with
//! (`exchange::refuse::render`), and this file asserts that the writer is the one that built it.

/// The six dialects, and the request target that names each.
const DIALECTS: &[&str] = &[
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

/// Drop the minted identifier from an envelope, so two envelopes can be compared on everything else.
///
/// Used where the two sides mint separately: the rendered refusal and the dialect writer's own
/// envelope each mint an identifier. Both are the same document otherwise, so removing it compares
/// what the test is about, which is that the door picked the status and the kind and the codec
/// wrote every other byte.
fn without_minted_id(bytes: &[u8]) -> String {
    let Ok(mut value) = sonic_rs::from_slice::<serde_json::Value>(bytes) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    if let Some(obj) = value.as_object_mut() {
        obj.remove("request_id");
    }
    sonic_rs::to_string(&value).unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

// ── F25 REHOME: the rendered refusal's status and head (coverage map v2) ─────────────────────────

/// The dialect codec of the dialect named `name`.
fn dialect_codec(name: &str) -> &'static dyn busbar_contract::protocol::DialectCodec {
    busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == name)
        .and_then(|d| d.dialect())
        .unwrap_or_else(|| panic!("{name} declares a dialect codec"))
}

/// The host's entropy, so a dialect that mints a request id mints one (constant bytes, so a test
/// that renders a refusal twice reads the same document twice), and no clock.
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

/// The constant-entropy handle the rendered-refusal tests hand the exchange and the codecs.
const SEVENS: &dyn busbar_contract::codec::CodecHost = &SevensHost;

/// The value of the head field `name` (compared without case), if the refusal carries one.
fn head_value<'a>(fields: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    fields
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// LEGACY `crates/busbar-llm/src/engine/tests/ingress_indistinguishability_tests.rs::test_anthropic_ingress_error_request_id_header_matches_body`
/// (coverage map v2 row 330). 1.5.5: an anthropic-dialect refusal carries a `request-id` head field
/// in Anthropic's `req_` shape, EQUAL to the body's `request_id`; no other dialect's refusal
/// carries a `request-id` field.
///
/// RED: the header and the body mint two different ids, the header goes missing, or another
/// dialect's refusal starts carrying Anthropic's field.
#[test]
fn test_anthropic_ingress_error_request_id_header_matches_body() {
    use busbar_contract::protocol::KIND_INVALID_REQUEST;
    use busbar_plane_llm::exchange::refuse::render;
    let rendered = render(
        SEVENS,
        "anthropic",
        400,
        KIND_INVALID_REQUEST,
        "bad json",
        0,
    );
    let header_rid = std::str::from_utf8(
        head_value(&rendered.fields, "request-id")
            .expect("anthropic error must carry a request-id header"),
    )
    .expect("the request id is text")
    .to_string();
    assert!(
        header_rid.starts_with("req_"),
        "request-id header carries the Anthropic req_ shape; got {header_rid}"
    );
    let body: serde_json::Value =
        sonic_rs::from_slice(&rendered.body).expect("a refusal is a document");
    assert_eq!(
        body["request_id"].as_str(),
        Some(header_rid.as_str()),
        "the request-id header MUST equal the body request_id so they agree"
    );
    for dialect in DIALECTS.iter().filter(|d| **d != "anthropic") {
        let other = render(SEVENS, dialect, 400, KIND_INVALID_REQUEST, "bad json", 0);
        assert_eq!(
            head_value(&other.fields, "request-id"),
            None,
            "a {dialect} refusal carries no Anthropic request-id field"
        );
    }
}

/// LEGACY `crates/busbar-llm/src/unit/tests/audit.rs::every_refusal_class_renders_byte_identically_on_both_paths`
/// (coverage map v2 row 682). 1.5.5: every refusal class (exactly eight: unauth 401, wrong-scope
/// 403, over-budget 429 `insufficient_quota`, rate-limit 429 with `Retry-After: 30`, unpriced 400,
/// no-pool 404, oversize-body 413, context-overflow 400 carrying the breaker's
/// `context_length_exceeded` code) renders in each of the six dialects with its own status, its
/// dialect's native head fields over the very envelope it sends, the dialect writer's own envelope
/// bytes, and a non-empty body.
///
/// RED: a class renders another status, drops or invents `retry-after`, wears head fields that do
/// not belong to its own envelope, leaves the writer's vocabulary (over-budget not
/// `insufficient_quota`, the context-length code reaching an openai caller as a raw `type`), renders
/// an empty body, or a class leaves the table.
#[test]
fn every_refusal_class_renders_byte_identically_on_both_paths() {
    use busbar_contract::protocol::{
        KIND_AUTHENTICATION, KIND_INSUFFICIENT_QUOTA, KIND_INVALID_REQUEST, KIND_NOT_FOUND,
        KIND_PERMISSION, KIND_RATE_LIMIT, KIND_REQUEST_TOO_LARGE, PROVIDER_CODE_CONTEXT_LENGTH,
    };
    use busbar_plane_llm::exchange::refuse::render;
    // (class, status, kind, message, retry-after seconds)
    let classes: [(&str, u16, &str, &str, u32); 8] = [
        (
            "unauth",
            401,
            KIND_AUTHENTICATION,
            "Invalid API key provided.",
            0,
        ),
        (
            "wrong-scope",
            403,
            KIND_PERMISSION,
            "Your API key does not have permission to use pool 'p'.",
            0,
        ),
        (
            "over-budget",
            429,
            KIND_INSUFFICIENT_QUOTA,
            "You have exceeded your current quota (group 'bgrp' budget per total exhausted). \
             Please check your plan and billing details.",
            0,
        ),
        (
            "rate-limit",
            429,
            KIND_RATE_LIMIT,
            "Rate limit exceeded (group 'g': requests per minute). Please retry after the \
             indicated time.",
            30,
        ),
        (
            "unpriced",
            400,
            KIND_INVALID_REQUEST,
            "no configured rate for model 'm'",
            0,
        ),
        (
            "no-pool",
            404,
            KIND_NOT_FOUND,
            "The model 'm' does not exist or you do not have access to it.",
            0,
        ),
        (
            "oversize-body",
            413,
            KIND_REQUEST_TOO_LARGE,
            "Request body is too large.",
            0,
        ),
        (
            "context-overflow",
            400,
            PROVIDER_CODE_CONTEXT_LENGTH,
            "prompt is too long: 300000 tokens > 200000 maximum",
            0,
        ),
    ];
    assert_eq!(classes.len(), 8, "every refusal class stays in the table");
    assert_eq!(PROVIDER_CODE_CONTEXT_LENGTH, "context_length_exceeded");
    for (name, status, kind, message, retry) in classes {
        for dialect in DIALECTS {
            let codec = dialect_codec(dialect);
            let rendered = render(SEVENS, dialect, status, kind, message, retry);
            assert_eq!(
                rendered.status, status,
                "{name}/{dialect} wears its own status"
            );
            assert!(
                !rendered.body.is_empty(),
                "{name}/{dialect} renders an envelope, not an empty body"
            );
            // The body is the dialect writer's own envelope for the class's (status, kind, message).
            let own = sonic_rs::to_vec(&codec.write_error(SEVENS, status, kind, message))
                .expect("the envelope serializes");
            assert_eq!(
                without_minted_id(&rendered.body),
                without_minted_id(&own),
                "{name} on the {dialect} wire is not the dialect's own envelope"
            );
            // The head: the JSON content type, the dialect's native error fields over the very
            // envelope sent (so a minted id in the head is the body's), then the class's own wait.
            let sent: serde_json::Value =
                sonic_rs::from_slice(&rendered.body).expect("a refusal is a document");
            let mut head = vec![("content-type".to_string(), b"application/json".to_vec())];
            head.extend(codec.error_response_fields(SEVENS, kind, &sent));
            if retry != 0 {
                head.push(("retry-after".to_string(), b"30".to_vec()));
            }
            assert_eq!(
                rendered.fields, head,
                "{name} on the {dialect} wire carries other head fields than its own"
            );
            assert_eq!(
                head_value(&rendered.fields, "retry-after"),
                (name == "rate-limit").then_some(b"30".as_slice()),
                "{name}/{dialect}: only the rolling window advises a wait, and it is 30 seconds"
            );
        }
    }
    // The openai wire, read as its SDK reads it: the over-budget class is the native quota type and
    // code, and the breaker's context-length token is projected into the writer's own vocabulary.
    let over = render(SEVENS, "openai", 429, KIND_INSUFFICIENT_QUOTA, "quota", 0);
    let over: serde_json::Value = sonic_rs::from_slice(&over.body).expect("a document");
    assert_eq!(over["error"]["type"], "insufficient_quota");
    assert_eq!(over["error"]["code"], "insufficient_quota");
    let ctx = render(
        SEVENS,
        "openai",
        400,
        PROVIDER_CODE_CONTEXT_LENGTH,
        "too long",
        0,
    );
    let ctx: serde_json::Value = sonic_rs::from_slice(&ctx.body).expect("a document");
    assert_eq!(ctx["error"]["type"], "invalid_request_error");
    let no_pool = render(SEVENS, "openai", 404, KIND_NOT_FOUND, "no pool", 0);
    assert_eq!(no_pool.status, 404);
}
