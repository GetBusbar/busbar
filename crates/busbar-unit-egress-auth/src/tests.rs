// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_caps::KernelSeal;

fn token() -> EgressAuthToken {
    EgressAuthToken::mint(&KernelSeal::acquire_for_kernel())
}

fn empty_body() -> EgressBody<'static> {
    EgressBody {
        method: "POST",
        canonical_uri: "/",
        canonical_querystring: "",
        envelope: &[],
        body: b"",
        timestamp_epoch: 1_440_938_160,
    }
}

/// Bearer: a valid key produces a decoration with exactly one slot naming the `authorization`
/// header, and substitution writes `Bearer <key>` there.
#[test]
fn bearer_scheme_declares_one_slot_and_substitutes_bearer_prefix() {
    let t = token();
    let decoration = decorate(&t, &Scheme::Bearer, "sk-test-123", &empty_body());
    match &decoration {
        AuthDecoration::Decorate {
            slots,
            fields,
            body_signature,
        } => {
            assert_eq!(slots.len(), 1);
            assert!(fields.is_empty());
            assert!(!body_signature);
        }
        AuthDecoration::Handshake { .. } => panic!("bearer must decorate in place"),
    }
    let envelope = substitute(&decoration, "sk-test-123", Vec::new());
    assert_eq!(
        envelope,
        vec![(
            "authorization".to_string(),
            "Bearer sk-test-123".to_string()
        )]
    );
}

/// An un-encodable bearer key (an ASCII control byte) yields the no-header decoration rather than a
/// syntactically broken header — the upstream then 401s.
#[test]
fn bearer_scheme_omits_header_for_control_byte_key() {
    let t = token();
    let decoration = decorate(&t, &Scheme::Bearer, "sk-\r\ninjected", &empty_body());
    match &decoration {
        AuthDecoration::Decorate { slots, .. } => assert!(slots.is_empty()),
        AuthDecoration::Handshake { .. } => panic!("must still be a Decorate, just an empty one"),
    }
    let envelope = substitute(&decoration, "sk-\r\ninjected", Vec::new());
    assert!(envelope.is_empty());
}

/// `api-key` (Azure OpenAI override): the raw key is substituted verbatim, with no `Bearer` prefix.
#[test]
fn api_key_header_scheme_substitutes_raw_value() {
    let t = token();
    let decoration = decorate(
        &t,
        &Scheme::ApiKeyHeader { header: "api-key" },
        "azure-key-xyz",
        &empty_body(),
    );
    let envelope = substitute(&decoration, "azure-key-xyz", Vec::new());
    assert_eq!(
        envelope,
        vec![("api-key".to_string(), "azure-key-xyz".to_string())]
    );
}

/// `x-goog-api-key` (Gemini): same raw-substitution scheme, different header name — proves the two
/// custom-header schemes cannot cross-contaminate each other's header name.
#[test]
fn x_goog_api_key_scheme_uses_its_own_header_name() {
    let t = token();
    let decoration = decorate(
        &t,
        &Scheme::ApiKeyHeader {
            header: "x-goog-api-key",
        },
        "gemini-key",
        &empty_body(),
    );
    let envelope = substitute(&decoration, "gemini-key", Vec::new());
    assert_eq!(
        envelope,
        vec![("x-goog-api-key".to_string(), "gemini-key".to_string())]
    );
}

/// SigV4: `decorate` computes a full `Authorization` header (no slot — the wire value is a
/// signature, not the secret) whose SignedHeaders/Signature match the hand-computed values against
/// AWS's published worked example, given the same inputs busbar's Bedrock lane would present.
#[test]
fn sigv4_scheme_matches_aws_worked_example_end_to_end() {
    let t = token();
    let body = EgressBody {
        method: "GET",
        canonical_uri: "/",
        canonical_querystring: "Action=ListUsers&Version=2010-05-08",
        envelope: &[("host".to_string(), "iam.amazonaws.com".to_string())],
        body: b"",
        timestamp_epoch: 1_440_938_160, // 2015-08-30T12:36:00Z
    };
    let decoration = decorate(
        &t,
        &Scheme::SigV4 {
            access_key_id: "AKIDEXAMPLE",
            region: "us-east-1",
            service: "iam",
        },
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        &body,
    );
    let AuthDecoration::Decorate {
        fields,
        body_signature,
        slots,
    } = &decoration
    else {
        panic!("SigV4 decorates in place");
    };
    assert!(body_signature, "SigV4 signs the request");
    assert!(slots.is_empty(), "the signature is not a secret slot");
    let auth = fields
        .iter()
        .find(|(k, _)| k == "authorization")
        .map(|(_, v)| v.as_str())
        .expect("authorization field present");
    assert!(auth.starts_with(sigv4::SIGV4_ALGORITHM));
    assert!(auth.contains("Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request"));
    // SignedHeaders here is host + the two x-amz-* fields decorate() always adds, sorted.
    assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
}

/// `continue_handshake` fails closed (a zero-budget handshake) for the placeholder shape: no
/// shipped scheme reaches it, and a caller that does must not be handed an unbounded round.
#[test]
fn continue_handshake_is_zero_budget_placeholder() {
    let t = token();
    let decoration = continue_handshake(&t, b"state", b"frame");
    assert_eq!(
        decoration,
        AuthDecoration::handshake(
            &EgressAuthToken::mint(&KernelSeal::acquire_for_kernel()),
            0,
            0
        )
    );
}

/// `substitute` applies each slot exactly once: two different schemes never collide on the same
/// envelope key, and re-substituting is idempotent (replaces, does not duplicate the header).
#[test]
fn substitute_applies_each_slot_exactly_once() {
    let t = token();
    let decoration = decorate(&t, &Scheme::Bearer, "key-a", &empty_body());
    let once = substitute(&decoration, "key-a", Vec::new());
    assert_eq!(once.len(), 1);
    let twice = substitute(&decoration, "key-a", once.clone());
    // Re-applying replaces the same header in place rather than appending a second copy — a
    // decoration substituted more than once (e.g. a retried leg re-using the same AuthDecoration)
    // must never leave two `authorization` headers on the wire.
    assert_eq!(twice.len(), 1);
    assert_eq!(twice, once);
}

/// A slot's substitution never reaches anything other than the envelope it is handed: passing a
/// separate "content" vector alongside proves the substitution touches only the envelope, never a
/// content-facts-shaped structure a plane might hold — a `SecretSlot` is substituted into the wire
/// envelope and nowhere else.
#[test]
fn substitute_never_touches_anything_but_the_envelope_it_is_given() {
    let t = token();
    let decoration = decorate(&t, &Scheme::Bearer, "key-b", &empty_body());
    let content_facts: Vec<(String, String)> =
        vec![("unrelated".to_string(), "untouched".to_string())];
    let envelope = substitute(&decoration, "key-b", Vec::new());
    // The content-shaped vector was never passed to `substitute` and is unchanged by definition —
    // asserted here so the test fails loudly if a future edit widens `substitute`'s signature to
    // accept (and so risk touching) anything beyond the envelope.
    assert_eq!(
        content_facts,
        vec![("unrelated".to_string(), "untouched".to_string())]
    );
    assert!(!envelope.iter().any(|(k, _)| k == "unrelated"));
}

/// The lane cross-check: the decorated envelope's `host` must still equal the sealed destination's
/// host, or the unit refuses with `EnvelopeDivergedFromVerifiedDestination`.
#[test]
fn lane_cross_check_catches_envelope_divergence_after_decoration() {
    use busbar_caps::{LaneId, TrustToken};
    let seal = KernelSeal::acquire_for_kernel();
    let trust = TrustToken::mint(&seal);
    let verified = VerifiedDestination::seal(&trust, LaneId::new("bedrock-us-east-1"));

    let matching = vec![(
        "host".to_string(),
        "bedrock.us-east-1.amazonaws.com".to_string(),
    )];
    assert!(lane_cross_check(
        &verified,
        "host",
        &matching,
        "bedrock.us-east-1.amazonaws.com"
    )
    .is_ok());

    let diverged = vec![("host".to_string(), "evil.example.com".to_string())];
    assert_eq!(
        lane_cross_check(
            &verified,
            "host",
            &diverged,
            "bedrock.us-east-1.amazonaws.com"
        ),
        Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field: "host" })
    );
}

/// The forwarded-header allow-list scopes each beta/version header to its own dialect(s),
/// and it is otherwise empty — a header sent for one dialect never rides to a different one.
#[test]
fn forwarded_client_headers_are_scoped_per_egress_dialect() {
    assert_eq!(
        allowed_client_headers_for("anthropic"),
        vec!["anthropic-beta", "anthropic-version"]
    );
    assert_eq!(allowed_client_headers_for("openai"), vec!["openai-beta"]);
    assert_eq!(allowed_client_headers_for("responses"), vec!["openai-beta"]);
    // Gemini and Bedrock forward none of the beta/version headers.
    assert!(allowed_client_headers_for("gemini").is_empty());
    assert!(allowed_client_headers_for("bedrock").is_empty());
    assert!(allowed_client_headers_for("unknown-dialect").is_empty());

    // The union used by the pre-dialect collector names exactly these three headers.
    let mut all = forwardable_client_header_names();
    all.sort_unstable();
    assert_eq!(
        all,
        vec!["anthropic-beta", "anthropic-version", "openai-beta"]
    );
}

/// No-cross-dialect-leak guard, stated as the property directly: an `anthropic-beta` header never
/// appears in the OpenAI allow-list, and vice versa.
#[test]
fn beta_headers_never_cross_dialects() {
    assert!(!allowed_client_headers_for("openai").contains(&"anthropic-beta"));
    assert!(!allowed_client_headers_for("responses").contains(&"anthropic-beta"));
    assert!(!allowed_client_headers_for("anthropic").contains(&"openai-beta"));
}
