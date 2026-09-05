//! A refusal wears the dialect's own shape.
//!
//! A client that gets a refusal in a shape its own library does not parse learns nothing from it,
//! so the envelope has to be the dialect's. It is not built here: the dialect's own error writer
//! builds it, and this file asserts that the writer is the one that built it and that the status
//! and kind the plane chose are the ones the existing forward path chooses for the same reason.

mod harness;

use busbar_contract::bounded::Labels;
use busbar_contract::plane::Plane;
use busbar_contract::unit::{Refusal, RefusalReason, Step};
use busbar_plane_llm::LlmPlane;

/// The six dialects, and the request target that names each.
const DIALECTS: &[&str] = &[
    "anthropic",
    "openai",
    "gemini",
    "bedrock",
    "responses",
    "cohere",
];

/// Render one refusal in one dialect.
fn refuse(dialect: &str, reason: RefusalReason) -> Vec<u8> {
    let plane = LlmPlane::EMPTY;
    let arena = harness::LeakArena;
    let config = harness::EmptyConfig;
    let transport = harness::HttpStack::new(harness::path_for(dialect), &[]);
    let labels = Labels::new();
    let ctx = harness::ctx(&arena, &config, &transport, &labels);
    plane
        .encode_refusal(
            &Refusal {
                step: Step::Admit,
                reason,
                retry_after_secs: None,
                stream: None,
                correlates: None,
            },
            None,
            None,
            &ctx,
        )
        .expect("every dialect can express a refusal")
        .as_slice()
        .to_vec()
}

/// Drop the minted identifier from an envelope, so two envelopes can be compared on everything else.
///
/// Used ONLY where the two sides mint from different inputs: the codec's own writer draws its
/// identifier, and the plane builds one from entropy it was handed. Both are the same document
/// otherwise, and the identifier itself is pinned by its own shape and determinism tests above — so
/// removing it here compares what this test is actually about, which is that the plane picked the
/// status and the kind and the codec wrote every other byte.
fn without_minted_id(bytes: &[u8]) -> String {
    let Ok(mut value) = sonic_rs::from_slice::<serde_json::Value>(bytes) else {
        return String::from_utf8_lossy(bytes).into_owned();
    };
    if let Some(obj) = value.as_object_mut() {
        obj.remove("request_id");
    }
    sonic_rs::to_string(&value).unwrap_or_else(|_| String::from_utf8_lossy(bytes).into_owned())
}

/// A refusal built twice from the same inputs is the same refusal. Every byte of it.
///
/// The plane is required to be pure over its inputs, and this is the test that says so without a
/// carve-out. It used to have one: one of the six dialects mints an identifier inside its error
/// envelope, and the envelope came back different on the second call, so the test recorded WHICH
/// dialect did it rather than asserting the plane was deterministic. The minted identifier now takes
/// its entropy as an input — the plane hands the codec bytes from the context, the codec builds the
/// identifier from them and mints nothing of its own — so the carve-out is gone and the assertion is
/// the whole document.
///
/// The identifier is still there, still the native shape, still the native width. What changed is
/// that its bytes are a function of what the kernel handed this call.
#[test]
fn a_refusal_is_the_same_twice() {
    for dialect in DIALECTS {
        let first = refuse(dialect, RefusalReason::CredentialRejected);
        let second = refuse(dialect, RefusalReason::CredentialRejected);
        assert_eq!(
            String::from_utf8_lossy(&first),
            String::from_utf8_lossy(&second),
            "the {dialect} refusal differs between two identical calls, so the plane is not a \
             function of its inputs"
        );
    }
}

/// The one minted identifier still wears its dialect's native shape.
///
/// Determinism would be cheap if the identifier were a constant, and a constant would be a tell: a
/// client that saw the same `request_id` on two refusals would know it was not talking to the
/// upstream. So this pins the shape — the native prefix, the native version marker, the native
/// width, the native alphabet — alongside the determinism above.
#[test]
fn the_minted_identifier_keeps_its_native_shape() {
    let envelope = refuse("anthropic", RefusalReason::CredentialRejected);
    let value: serde_json::Value =
        sonic_rs::from_slice(&envelope).expect("a refusal is a document");
    let id = value
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .expect("the anthropic error envelope carries a request_id");
    assert!(
        id.starts_with("req_01") && id.len() == 30,
        "the minted request id must keep the native `req_01` + 24-character shape, got {id:?}"
    );
    assert!(
        id.as_bytes()[6..].iter().all(u8::is_ascii_alphanumeric),
        "the minted request id's token must be base62, got {id:?}"
    );
}

/// No dialect's refusal envelope is a fixed document.
///
/// The counterpart of the determinism test: the same inputs give the same bytes, and DIFFERENT
/// inputs give different bytes for the dialect that mints. A codec that ignored the entropy it was
/// handed would pass the determinism test and fail this one.
#[test]
fn the_minted_identifier_follows_the_entropy_it_is_handed() {
    let at = |unix_secs: u64| -> Vec<u8> {
        let plane = LlmPlane::EMPTY;
        let arena = harness::LeakArena;
        let config = harness::EmptyConfig;
        let transport = harness::HttpStack::new(harness::path_for("anthropic"), &[]);
        let labels = Labels::new();
        let ctx = harness::ctx_at(&arena, &config, &transport, &labels, unix_secs);
        plane
            .encode_refusal(
                &Refusal {
                    step: Step::Admit,
                    reason: RefusalReason::CredentialRejected,
                    retry_after_secs: None,
                    stream: None,
                    correlates: None,
                },
                None,
                None,
                &ctx,
            )
            .expect("anthropic can express a refusal")
            .as_slice()
            .to_vec()
    };
    assert_ne!(
        String::from_utf8_lossy(&at(1_752_000_000)),
        String::from_utf8_lossy(&at(1_752_000_001)),
        "the minted identifier ignored the entropy it was handed, so it is a constant"
    );
}

/// Every refusal is the bytes the dialect's own error writer produces.
///
/// This is the whole claim of the method: the plane picks the status and the kind, and the codec
/// writes the envelope. If the two ever disagree, a refusal is being written twice.
#[test]
fn every_refusal_is_the_dialects_own_envelope() {
    // (reason, status, kind) — the pairing the existing forward path uses for the same situation.
    let cases: &[(RefusalReason, u16, &str)] = &[
        (
            RefusalReason::CredentialRejected,
            401,
            "authentication_error",
        ),
        (RefusalReason::ScopeMissing, 403, "permission_error"),
        (RefusalReason::BodyTooLarge, 413, "request_too_large"),
        (RefusalReason::OverBudget, 429, "rate_limit_error"),
        (RefusalReason::NoDestination, 400, "invalid_request_error"),
        (
            RefusalReason::DurabilityUnavailable,
            503,
            "overloaded_error",
        ),
    ];
    for dialect in DIALECTS {
        let protocol =
            busbar_llm_codec::proto_codec::protocol_for(dialect).expect("the dialect has a codec");
        for (reason, status, kind) in cases {
            let expected_message = match status {
                401 => "Authentication failed.",
                403 => "Not permitted.",
                413 => "Request too large.",
                429 => "Rate limited.",
                503 => "Temporarily unavailable.",
                _ => "Request rejected.",
            };
            let expected = sonic_rs::to_vec(&protocol.writer().write_error(
                *status,
                kind,
                expected_message,
            ))
            .expect("the envelope serializes");
            assert_eq!(
                without_minted_id(&refuse(dialect, *reason)),
                without_minted_id(&expected),
                "the {dialect} refusal for {reason:?} is not the dialect's own envelope"
            );
        }
    }
}

/// A refusal is a document, in every dialect.
///
/// Weaker than the assertion above and independent of it: it would still catch a serializer that
/// produced something a client cannot parse at all.
#[test]
fn every_refusal_is_a_document() {
    for dialect in DIALECTS {
        let bytes = refuse(dialect, RefusalReason::OverBudget);
        let parsed: serde_json::Value =
            sonic_rs::from_slice(&bytes).expect("a refusal parses as a document");
        assert!(
            parsed.is_object(),
            "the {dialect} refusal is not an object: {}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

/// A refusal never carries the internal reason code.
///
/// The reason is the journal's vocabulary. A client that could read it would learn which ceiling it
/// hit, which is exactly what a refusal is not supposed to tell it.
#[test]
fn a_refusal_never_names_the_internal_reason() {
    let internal = [
        "OverBudget",
        "OverdraftCeiling",
        "InFlightCap",
        "SessionBudget",
        "GroupFrozen",
        "StaleSlice",
        "DurabilityUnavailable",
    ];
    for dialect in DIALECTS {
        for reason in [
            RefusalReason::OverBudget,
            RefusalReason::OverdraftCeiling,
            RefusalReason::InFlightCap,
            RefusalReason::GroupFrozen,
            RefusalReason::StaleSlice,
            RefusalReason::DurabilityUnavailable,
        ] {
            let text = String::from_utf8(refuse(dialect, reason)).expect("valid text");
            for name in internal {
                assert!(
                    !text.contains(name),
                    "the {dialect} refusal for {reason:?} leaks the internal code {name}: {text}"
                );
            }
        }
    }
}
