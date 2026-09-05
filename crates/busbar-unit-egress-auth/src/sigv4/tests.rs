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
fn uri_encode_path_bedrock_model() {
    assert_eq!(
        uri_encode_path("/model/anthropic.claude-3:0/converse"),
        "/model/anthropic.claude-3%3A0/converse"
    );
}

#[test]
fn uri_encode_path_assorted_bytes() {
    assert_eq!(uri_encode_path(" "), "%20");
    assert_eq!(uri_encode_path("?a=b&c"), "%3Fa%3Db%26c");
    assert_eq!(uri_encode_path("/"), "/");
    assert_eq!(uri_encode_path("aZ0-_.~"), "aZ0-_.~");
    assert_eq!(uri_encode_path("\u{00c3}"), "%C3%83");
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

/// AWS published worked example — GET iam ListUsers, 2015-08-30. If our canonical-request ->
/// string-to-sign -> signature chain reproduces AWS's documented signature, the algorithm is
/// correct.
/// (https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html)
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
