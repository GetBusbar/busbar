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

/// Replace the freshly minted identifier one dialect stamps on every error envelope.
///
/// One of the six mints a random identifier inside its error envelope, so two refusals built from
/// the same inputs differ in that one member. That is a property of the codec, not of this plane,
/// and it is pinned by its own test below; here it is normalized so the rest of the envelope can be
/// compared byte-for-byte.
fn normalize_minted_id(bytes: &[u8]) -> Vec<u8> {
    let Ok(mut value) = sonic_rs::from_slice::<serde_json::Value>(bytes) else {
        return bytes.to_vec();
    };
    if let Some(obj) = value.as_object_mut() {
        if obj.contains_key("request_id") {
            obj.insert(
                "request_id".to_string(),
                serde_json::Value::String("req_NORMALIZED".to_string()),
            );
        }
    }
    sonic_rs::to_vec(&value).unwrap_or_else(|_| bytes.to_vec())
}

/// A refusal built twice from the same inputs is the same refusal, except for a minted identifier.
///
/// The plane is required to be pure over its inputs, and it is: it reads no clock and no random
/// source. One of the dialects' error writers does, and this test says which and how, so the
/// divergence is a recorded fact rather than a flaky assertion somewhere else.
#[test]
fn a_refusal_is_the_same_twice_apart_from_a_minted_identifier() {
    let mut mints = Vec::new();
    for dialect in DIALECTS {
        let first = refuse(dialect, RefusalReason::CredentialRejected);
        let second = refuse(dialect, RefusalReason::CredentialRejected);
        if first != second {
            mints.push(*dialect);
        }
        assert_eq!(
            normalize_minted_id(&first),
            normalize_minted_id(&second),
            "the {dialect} refusal differs between two identical calls by more than a minted \
             identifier"
        );
    }
    assert_eq!(
        mints,
        vec!["anthropic"],
        "the set of dialects whose error envelope carries a freshly minted identifier changed"
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
                normalize_minted_id(&refuse(dialect, *reason)),
                normalize_minted_id(&expected),
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
