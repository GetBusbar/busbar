// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn format_amz_time_known_epoch() {
    // 2015-08-30T12:36:00Z — the timestamp from AWS's worked SigV4 example.
    let (amz, date) = format_amz_time(1_440_938_160);
    assert_eq!(amz, "20150830T123600Z");
    assert_eq!(date, "20150830");
}

#[test]
fn canonicalize_header_value_ascii_space_only() {
    assert_eq!(canonicalize_header_value("a   b    c"), "a b c");
    assert_eq!(canonicalize_header_value("  a b c  "), "a b c");
    assert_eq!(canonicalize_header_value(""), "");
    assert_eq!(canonicalize_header_value("   "), "");
    assert_eq!(canonicalize_header_value("single"), "single");
    assert_eq!(canonicalize_header_value("a\tb"), "a\tb");
    assert_eq!(canonicalize_header_value("a\u{00a0}b"), "a\u{00a0}b");
    assert_eq!(canonicalize_header_value("a\nb"), "a\nb");
    assert_eq!(canonicalize_header_value("a  \t  b"), "a \t b");
    assert_eq!(canonicalize_header_value("\u{00a0}a"), "\u{00a0}a");
}

#[test]
fn sign_v4_collapses_ascii_space_in_header_value() {
    let payload_hash = sha256_hex(b"");
    let mk = |v: &str| {
        sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "GET",
            "/",
            "",
            &[
                ("host".to_string(), "iam.amazonaws.com".to_string()),
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_single, _) = mk("a b");
    let (sig_padded, _) = mk("a    b");
    assert_eq!(sig_single, sig_padded);
}

#[test]
fn sign_v4_does_not_fold_nbsp_or_tab_in_header_value() {
    let payload_hash = sha256_hex(b"");
    let mk = |v: &str| {
        sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "GET",
            "/",
            "",
            &[
                ("host".to_string(), "iam.amazonaws.com".to_string()),
                ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_tab, _) = mk("a\tb");
    let (sig_space, _) = mk("a b");
    assert_ne!(
        sig_tab, sig_space,
        "a tab must not be folded into a space by the signer"
    );
}

/// Per the SigV4 canonicalisation rule, a header name that appears twice is not two lines in the
/// canonical headers block and not two entries in `SignedHeaders` — it is ONE entry whose value is
/// the comma-joined, individually-trimmed values, in their original order. Proven by comparing
/// against the header handed over pre-merged: if the signer folds them the same way itself, the two
/// signatures and `SignedHeaders` strings must match exactly.
#[test]
fn sign_v4_merges_a_duplicate_header_name_by_comma_joining_its_values() {
    let payload_hash = sha256_hex(b"");
    let common = [
        ("host".to_string(), "iam.amazonaws.com".to_string()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
    ];
    let sign = |headers: &[(String, String)]| {
        sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "iam",
            "GET",
            "/",
            "",
            headers,
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };

    let mut duplicated = common.to_vec();
    duplicated.push(("x-custom".to_string(), "  foo  ".to_string()));
    duplicated.push(("x-custom".to_string(), "bar".to_string()));
    let (sig_duplicated, signed_duplicated) = sign(&duplicated);

    let mut premerged = common.to_vec();
    premerged.push(("x-custom".to_string(), "foo,bar".to_string()));
    let (sig_premerged, signed_premerged) = sign(&premerged);

    assert_eq!(
        signed_duplicated, "host;x-amz-date;x-custom",
        "the duplicate name appears once in SignedHeaders, not twice"
    );
    assert_eq!(signed_duplicated, signed_premerged);
    assert_eq!(
        sig_duplicated, sig_premerged,
        "a duplicated header must sign identically to its comma-joined, pre-trimmed equivalent"
    );
}

/// AWS published worked example — GET iam ListUsers, 2015-08-30. If our canonical-request ->
/// string-to-sign -> signature chain reproduces AWS's documented signature, the algorithm is
/// correct.
/// (the AWS General Reference, "Examples of signed Signature Version 4 requests")
#[test]
fn sign_v4_matches_aws_published_example() {
    let headers = vec![
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        ),
        ("host".to_string(), "iam.amazonaws.com".to_string()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
    ];
    let payload_hash = sha256_hex(b"");
    let (sig, signed) = sign_v4(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "iam",
        "GET",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        &headers,
        &payload_hash,
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(signed, "content-type;host;x-amz-date");
    assert_eq!(
        sig,
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );
}

/// The lane credential splits into access key id, secret and an optional session token that keeps
/// every colon after the second; a credential missing either of the first two halves splits into
/// nothing, so it is never signed with.
#[test]
fn split_credential_takes_the_first_two_colons_and_refuses_a_missing_half() {
    assert_eq!(
        split_credential("AKID:SECRET"),
        Some(("AKID", "SECRET", None))
    );
    assert_eq!(
        split_credential("AKID:SECRET:TOKEN:with:colons"),
        Some(("AKID", "SECRET", Some("TOKEN:with:colons")))
    );
    assert_eq!(
        split_credential("AKID:SECRET:"),
        Some(("AKID", "SECRET", Some("")))
    );
    for refused in ["", "AKID", "AKID:", ":SECRET", "::TOKEN"] {
        assert_eq!(split_credential(refused), None, "{refused:?}");
    }
}

/// THE AWS PUBLISHED VECTOR WITH A SESSION TOKEN (BUSBAR-1.6.0.md THE DESIGN, §6's proof: "the AWS SigV4 published
/// vector with a session token"): `post-sts-header-before` from the AWS signing test suite
/// (awslabs/aws-c-auth, tests/aws-signing-test-suite/v4/post-sts-header-before), where the token is
/// sent AND signed. Driven through the request path's own split — the day key from
/// [`signing_key`], then [`sign_v4_with_key`] — so the pre-derived key is what the vector pins.
#[test]
fn the_day_key_path_matches_the_aws_published_session_token_vector() {
    const TOKEN: &str = "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";
    let key = signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20150830",
        "us-east-1",
        "service",
    );
    let headers = vec![
        ("host".to_string(), "example.amazonaws.com".to_string()),
        ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ("x-amz-security-token".to_string(), TOKEN.to_string()),
    ];
    let (sig, signed) = sign_v4_with_key(
        &key,
        "us-east-1",
        "service",
        "POST",
        "/",
        "",
        &headers,
        &sha256_hex(b""),
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(signed, "host;x-amz-date;x-amz-security-token");
    assert_eq!(
        sig,
        "85d96828115b5dc0cfc3bd16ad9e210dd772bbebba041836c64533a82be05ead"
    );
}
