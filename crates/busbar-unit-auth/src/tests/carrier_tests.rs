// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The carriers and their precedence, and the redacting debug output.
//!
//! Every carrier here arrives as a DECLARATION the test composes, exactly as the root composes the
//! set for the dialects it mounts. No test names a dialect, because the unit has no name to be
//! told: a carrier the composed set does not declare is a carrier this unit cannot read.

use super::Headers;
use crate::carrier::{extract_client_token, CallerToken};
use busbar_contract::grammar::ArrivalLocation;
use busbar_contract::ids::SchemeAlt;
use busbar_contract::kinds::{CredentialArrival, CredentialPresentation, CredentialSignature};

/// A signature that arrives on one header behind a scheme word, and presents the same way.
///
/// A macro rather than a function so each arrival slice is a promoted static: a declaration is a
/// static table in production too, and a helper that built one on the stack would be proving the
/// rule against a shape the tree cannot hold.
macro_rules! worded {
    ($header:literal, $word:literal) => {
        CredentialSignature {
            alt: SchemeAlt::new("worded"),
            arrivals: &[CredentialArrival {
                at: ArrivalLocation::Header($header),
                prefix: Some($word),
            }],
            presentation: CredentialPresentation::Header {
                name: $header,
                prefix: Some($word),
            },
        }
    };
}

/// A signature that arrives on one header verbatim, and presents the same way.
macro_rules! verbatim {
    ($header:literal) => {
        CredentialSignature {
            alt: SchemeAlt::new("verbatim"),
            arrivals: &[CredentialArrival {
                at: ArrivalLocation::Header($header),
                prefix: None,
            }],
            presentation: CredentialPresentation::Header {
                name: $header,
                prefix: None,
            },
        }
    };
}

/// A signature whose credential is a request signature: nothing a header view can lift out.
const SIGNED: CredentialSignature = CredentialSignature {
    alt: SchemeAlt::new("request-signature"),
    arrivals: &[CredentialArrival {
        at: ArrivalLocation::Signed {
            over: busbar_contract::grammar::SignedOver::Both,
        },
        prefix: None,
    }],
    presentation: CredentialPresentation::RequestSignature,
};

/// The ladder the shipped build composes: one scheme-worded carrier and two verbatim ones, plus
/// the signed dialect that declares no header carrier at all.
///
/// This is the GOLDEN TABLE. Its rows are the three carriers and the one signature the six
/// shipped dialects declare between them, in the order the root composes them, and every result
/// below is the result the hand-written ladder produced before the declarations existed.
const SHIPPED: &[CredentialSignature] = &[
    verbatim!("x-api-key"),
    worded!("authorization", "Bearer"),
    verbatim!("x-goog-api-key"),
    SIGNED,
];

#[test]
fn a_worded_carrier_yields_the_value_past_the_word() {
    let h = Headers(vec![("authorization", "Bearer abc123")]);
    assert_eq!(
        extract_client_token(&h, SHIPPED),
        Some("abc123".to_string())
    );
}

#[test]
fn the_declared_word_is_matched_case_insensitively() {
    let h = Headers(vec![("authorization", "bEaReR abc123")]);
    assert_eq!(
        extract_client_token(&h, SHIPPED),
        Some("abc123".to_string())
    );
}

#[test]
fn a_different_word_or_an_empty_value_is_not_this_carrier() {
    for value in ["Basic abc123", "Bearer "] {
        let h = Headers(vec![("authorization", value)]);
        assert_eq!(extract_client_token(&h, SHIPPED), None, "{value}");
    }
}

#[test]
fn a_malformed_worded_value_does_not_panic() {
    // A multi-byte character where the word belongs must not land mid-character.
    for value in ["Béarer x", "Bearer", "", "　"] {
        let h = Headers(vec![("authorization", value)]);
        assert_eq!(extract_client_token(&h, SHIPPED), None, "{value:?}");
    }
}

#[test]
fn each_verbatim_carrier_yields_its_whole_value() {
    let h = Headers(vec![("x-api-key", "tok-b")]);
    assert_eq!(extract_client_token(&h, SHIPPED), Some("tok-b".to_string()));
    let h = Headers(vec![("x-goog-api-key", "tok-c")]);
    assert_eq!(extract_client_token(&h, SHIPPED), Some("tok-c".to_string()));
}

#[test]
fn a_scheme_worded_carrier_is_read_before_an_un_worded_one() {
    // Not a ranking of vendors: a value carrying its own scheme word says what it is, and a bare
    // header value does not, so the self-describing carrier is believed first. Note the composed
    // order puts a verbatim carrier FIRST — the band, not the position, decides.
    let h = Headers(vec![
        ("authorization", "Bearer first"),
        ("x-api-key", "second"),
        ("x-goog-api-key", "third"),
    ]);
    assert_eq!(extract_client_token(&h, SHIPPED), Some("first".to_string()));
    let h = Headers(vec![("x-api-key", "second"), ("x-goog-api-key", "third")]);
    assert_eq!(
        extract_client_token(&h, SHIPPED),
        Some("second".to_string())
    );
}

#[test]
fn an_empty_carrier_falls_through() {
    let h = Headers(vec![("x-api-key", ""), ("x-goog-api-key", "third")]);
    assert_eq!(
        extract_client_token(&h, SHIPPED),
        Some("third".to_string()),
        "a blank header must not mask a token in a later carrier"
    );
}

#[test]
fn no_declared_carrier_present_is_no_token() {
    let h = Headers(vec![("content-type", "application/json")]);
    assert_eq!(extract_client_token(&h, SHIPPED), None);
}

#[test]
fn a_value_that_is_not_this_carrier_falls_through_to_the_next() {
    // A request signature in the authorization header is not a token, and the search continues.
    let h = Headers(vec![
        ("authorization", "AWS4-HMAC-SHA256 Credential=…"),
        ("x-api-key", "tok-b"),
    ]);
    assert_eq!(extract_client_token(&h, SHIPPED), Some("tok-b".to_string()));
    let h = Headers(vec![
        ("authorization", "Basic dXNlcjpwYXNz"),
        ("x-goog-api-key", "tok-c"),
    ]);
    assert_eq!(extract_client_token(&h, SHIPPED), Some("tok-c".to_string()));
}

#[test]
fn a_credential_whose_dialect_is_not_mounted_is_refused_by_the_declaration_s_absence() {
    // THE RED-FIRST CELL. The same bytes, the same unit, the same header — the only difference is
    // that the set this unit was composed with carries no declaration naming that carrier. It is
    // refused because nothing declared it, not because the unit recognised it and said no.
    let carried = Headers(vec![("x-goog-api-key", "tok-c")]);
    let without = &[verbatim!("x-api-key"), worded!("authorization", "Bearer")];
    assert_eq!(
        extract_client_token(&carried, without),
        None,
        "an un-mounted dialect's carrier must be unreadable, not merely unpreferred"
    );
    // Mount it and the very same bytes read, which is what proves the refusal above was the
    // absence and not a quirk of the value.
    assert_eq!(
        extract_client_token(&carried, SHIPPED),
        Some("tok-c".to_string())
    );
}

#[test]
fn a_signature_declares_no_header_carrier_and_reads_as_nothing() {
    let h = Headers(vec![("authorization", "AWS4-HMAC-SHA256 Credential=…")]);
    assert_eq!(extract_client_token(&h, &[SIGNED]), None);
}

#[test]
fn an_empty_composition_reads_nothing_at_all() {
    let h = Headers(vec![("authorization", "Bearer abc123")]);
    assert_eq!(extract_client_token(&h, &[]), None);
}

#[test]
fn test_caller_token_debug_redacts_value() {
    let present = format!("{:?}", CallerToken(Some("super-secret".to_string())));
    assert!(
        !present.contains("super-secret"),
        "the token value must never reach a debug rendering: {present}"
    );
    assert!(present.contains("<present>"));
    assert!(format!("{:?}", CallerToken(None)).contains("<absent>"));
}
