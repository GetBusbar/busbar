// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_caps::{KernelSeal, LaneId, TrustToken};

fn token() -> EgressAuthToken {
    EgressAuthToken::mint(&KernelSeal::acquire_for_kernel())
}

fn trust_token() -> TrustToken {
    TrustToken::mint(&KernelSeal::acquire_for_kernel())
}

/// The destination the trust unit judged for the Bedrock lane: the sealed lane is what the
/// envelope's host field must still carry after decoration.
fn sealed_destination() -> VerifiedDestination {
    VerifiedDestination::seal(
        &trust_token(),
        LaneId::new("bedrock.us-east-1.amazonaws.com"),
    )
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

/// THE CUSTOM-HEADER SCHEMES REFUSE AN UN-ENCODABLE KEY TOO, and that arm is a separate one.
///
/// The bearer arm's guard has a test above it; the `ApiKeyHeader` arm's guard is its own `if` and
/// had none, so deleting those three lines left the whole crate green. The value is substituted
/// VERBATIM here — no `Bearer` prefix, no quoting — so an Azure or Gemini key that a config system
/// resolved to text containing CR/LF is a header-split request smuggled upstream: everything after
/// the CRLF is read by the destination as a header of its own, or as the start of a second request.
/// The decoration has to come back empty, exactly as the bearer arm's does, so the upstream answers
/// 401 rather than receiving an injected envelope.
#[test]
fn a_custom_header_scheme_omits_the_header_for_a_key_with_crlf_in_it() {
    let t = token();
    for (header, secret) in [
        ("api-key", "azure-key-\r\nX-Forwarded-For: 10.0.0.1"),
        ("x-goog-api-key", "gemini-key-\r\ninjected"),
        // A bare control byte, which is the other spelling of the same defect.
        ("api-key", "azure-key-\u{0}-nul"),
    ] {
        let decoration = decorate(&t, &Scheme::ApiKeyHeader { header }, secret, &empty_body());
        match &decoration {
            AuthDecoration::Decorate { slots, fields, .. } => {
                assert!(
                    slots.is_empty(),
                    "{header} declared a slot for an un-encodable key"
                );
                assert!(fields.is_empty(), "{header} wrote a field anyway");
            }
            AuthDecoration::Handshake { .. } => {
                panic!("must still be a Decorate, just an empty one")
            }
        }
        assert!(
            substitute(&decoration, secret, Vec::new()).is_empty(),
            "{header} put an un-encodable key on the wire"
        );
    }

    // The control: the same scheme and the same header name still work for an ordinary key, so the
    // guard refuses the injection rather than the scheme.
    let ok = decorate(
        &t,
        &Scheme::ApiKeyHeader { header: "api-key" },
        "azure-key-xyz",
        &empty_body(),
    );
    assert_eq!(
        substitute(&ok, "azure-key-xyz", Vec::new()),
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

    // THE SIGNATURE ITSELF, which this test previously never compared to anything.
    //
    // `sign_v4` is pinned to AWS's published answer by `sigv4::tests`; what was unpinned is the
    // ASSEMBLY around it — that `decorate` threads the region, the service, the method, the URI, the
    // query string, the payload hash and the timestamp into the right parameters. Transposing
    // `region` and `service` at the call site is the sharp case: `Credential=` is built separately
    // from the same two variables so it still reads `us-east-1/iam`, and `SignedHeaders` does not
    // move, so both assertions above stay green while every Bedrock request 403s. The expectation
    // is therefore recomputed here from arguments written out in `sign_v4`'s own parameter order,
    // which is what a transposition inside `decorate` has to disagree with.
    let payload_hash = sigv4::sha256_hex(b"");
    assert_eq!(
        payload_hash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "the empty-body payload hash is the published SHA-256 of the empty string"
    );
    let signed_over = vec![
        ("host".to_string(), "iam.amazonaws.com".to_string()),
        ("x-amz-content-sha256".to_string(), payload_hash.clone()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
    ];
    let (expected_signature, expected_signed_headers) = sigv4::sign_v4(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "iam",
        "GET",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        &signed_over,
        &payload_hash,
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(
        expected_signed_headers,
        "host;x-amz-content-sha256;x-amz-date"
    );
    assert_eq!(
        auth,
        format!(
            "{} Credential=AKIDEXAMPLE/20150830/us-east-1/iam/aws4_request, \
             SignedHeaders={expected_signed_headers}, Signature={expected_signature}",
            sigv4::SIGV4_ALGORITHM
        ),
        "the whole Authorization header, signature included"
    );

    // And the two fields the decoration adds are the ones it signed over, so what goes on the wire
    // is what was signed.
    let field = |name: &str| {
        fields
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("{name} is present"))
    };
    assert_eq!(field("x-amz-date"), "20150830T123600Z");
    assert_eq!(field("x-amz-content-sha256"), payload_hash);
}

/// The two `x-amz-*` fields `decorate` adds are SET on the header set it signs, not appended to it.
///
/// Signing is re-run per attempt, and the envelope handed to a re-sign may already carry the fields
/// a previous decoration wrote — a retried leg, a plane that timestamps its own request. Appending
/// then signs the field twice while `substitute` writes it once, so the bytes on the wire are not
/// the bytes that were signed and the upstream 403s every time.
#[test]
fn sigv4_re_signing_an_already_decorated_envelope_signs_the_fields_once() {
    let t = token();
    let scheme = Scheme::SigV4 {
        access_key_id: "AKIDEXAMPLE",
        region: "us-east-1",
        service: "iam",
    };
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let host = ("host".to_string(), "iam.amazonaws.com".to_string());

    fn body(envelope: &[(String, String)]) -> EgressBody<'_> {
        EgressBody {
            method: "POST",
            canonical_uri: "/",
            canonical_querystring: "",
            envelope,
            body: b"{}",
            timestamp_epoch: 1_440_938_160,
        }
    }
    let authorization = |decoration: &AuthDecoration| match decoration {
        AuthDecoration::Decorate { fields, .. } => fields
            .iter()
            .find(|(k, _)| k == "authorization")
            .map(|(_, v)| v.clone())
            .expect("authorization field present"),
        AuthDecoration::Handshake { .. } => panic!("SigV4 decorates in place"),
    };

    let clean = vec![host.clone()];
    let first = decorate(&t, &scheme, secret, &body(&clean));

    // The envelope a second decoration is handed: the one the first decoration produced, minus the
    // authorization header a re-encode would not carry forward.
    let already: Vec<(String, String)> = substitute(&first, secret, clean.clone())
        .into_iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("authorization"))
        .collect();
    let second = decorate(&t, &scheme, secret, &body(&already));

    assert!(
        authorization(&second).contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date,"),
        "each field is signed once on a re-sign: {}",
        authorization(&second)
    );
    assert_eq!(
        authorization(&second),
        authorization(&first),
        "re-signing the same request over its own decorated envelope must be idempotent"
    );
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

/// A slot's substitution reaches the slot's own field and NOTHING ELSE in the envelope it is
/// handed. Checked against an envelope that already carries the fields encoding wrote — the host,
/// the content type, a forwarded client header — every one of which stays byte-identical while
/// exactly one `authorization` entry appears.
#[test]
fn substitute_touches_only_the_field_the_slot_names() {
    let t = token();
    let decoration = decorate(&t, &Scheme::Bearer, "key-b", &empty_body());
    let before: Vec<(String, String)> = vec![
        ("host".to_string(), "api.openai.com".to_string()),
        ("content-type".to_string(), "application/json".to_string()),
        ("openai-beta".to_string(), "responses=v1".to_string()),
    ];
    let after = substitute(&decoration, "key-b", before.clone());

    let authorization: Vec<_> = after
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
        .collect();
    assert_eq!(authorization.len(), 1, "exactly one credential header");
    assert_eq!(authorization[0].1, "Bearer key-b");

    // Every pair that was already there is the same pair, in the same order: substitution never
    // rewrites, reorders or drops what encoding put on the wire.
    let untouched: Vec<_> = after
        .iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("authorization"))
        .cloned()
        .collect();
    assert_eq!(untouched, before);
    assert_eq!(after.len(), before.len() + 1);
}

/// The lane cross-check: the decorated envelope's `host` must still equal what the trust unit
/// sealed, or the unit refuses with `EnvelopeDivergedFromVerifiedDestination`.
#[test]
fn lane_cross_check_catches_envelope_divergence_after_decoration() {
    use busbar_caps::{LaneId, TrustToken};
    let seal = KernelSeal::acquire_for_kernel();
    let trust = TrustToken::mint(&seal);
    let verified =
        VerifiedDestination::seal(&trust, LaneId::new("bedrock.us-east-1.amazonaws.com"));

    let matching = vec![(
        "host".to_string(),
        "bedrock.us-east-1.amazonaws.com".to_string(),
    )];
    assert!(lane_cross_check(&verified, "host", &matching).is_ok());

    let diverged = vec![("host".to_string(), "evil.example.com".to_string())];
    assert_eq!(
        lane_cross_check(&verified, "host", &diverged),
        Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field: "host" })
    );
}

/// The cross-check has to be against the SEALED lane, not against a value the caller passed in
/// alongside it. When the two disagree — the caller believes one destination, the trust unit
/// sealed another — the envelope agreeing with the caller's belief is not enough: the sealed lane
/// is the authority, and a mismatch against it is a refusal.
#[test]
fn lane_cross_check_is_against_the_sealed_lane_not_the_callers_belief() {
    use busbar_caps::{LaneId, TrustToken};
    let seal = KernelSeal::acquire_for_kernel();
    let trust = TrustToken::mint(&seal);
    let verified = VerifiedDestination::seal(&trust, LaneId::new("bedrock-us-east-1"));

    // The envelope carries a lane the trust unit did NOT seal.
    let diverged = vec![("host".to_string(), "bedrock-eu-west-1".to_string())];
    assert_eq!(
        lane_cross_check(&verified, "host", &diverged),
        Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field: "host" })
    );

    // The envelope carrying the sealed lane is the one case that passes.
    let matching = vec![("host".to_string(), "bedrock-us-east-1".to_string())];
    assert!(lane_cross_check(&verified, "host", &matching).is_ok());

    // A missing field is a mismatch too — there is nothing to check the seal against.
    assert_eq!(
        lane_cross_check(&verified, "host", &[]),
        Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field: "host" })
    );
}

/// The value the check compares against comes from the SEAL and from nowhere else. A
/// destination-changing hook that rewrites `host` after decoration is caught even where the caller
/// read its own idea of the destination out of the same post-hook plan — the reading under which
/// the sealed destination contributes anything at all.
#[test]
fn lane_cross_check_reads_the_sealed_destination_not_the_callers_expectation() {
    let verified = sealed_destination();

    let rewritten_by_a_hook = vec![("host".to_string(), "evil.example.com".to_string())];
    assert_eq!(
        lane_cross_check(&verified, "host", &rewritten_by_a_hook),
        Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field: "host" })
    );

    // The field spelled twice is not a request whose destination can be read at all: refuse rather
    // than answer about whichever copy the transport did not encode.
    let two_spellings = vec![
        (
            "host".to_string(),
            "bedrock.us-east-1.amazonaws.com".to_string(),
        ),
        ("Host".to_string(), "evil.example.com".to_string()),
    ];
    assert_eq!(
        lane_cross_check(&verified, "host", &two_spellings),
        Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field: "host" })
    );

    // And a destination the trust unit sealed with no host of its own compares against the lane it
    // did seal, rather than against anything the caller holds.
    let lane_only = VerifiedDestination::seal(&trust_token(), LaneId::new("bedrock-us-east-1"));
    let named = vec![("lane".to_string(), "bedrock-us-east-1".to_string())];
    assert!(lane_cross_check(&lane_only, "lane", &named).is_ok());
    let renamed = vec![("lane".to_string(), "cheap-lane".to_string())];
    assert!(lane_cross_check(&lane_only, "lane", &renamed).is_err());

    // A decoration that DROPPED the field fails closed: an envelope with no destination in it is
    // not one whose destination was checked.
    assert!(lane_cross_check(&verified, "host", &[]).is_err());
}
