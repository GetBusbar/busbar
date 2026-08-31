// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/sigv4.rs`.

use super::*;

#[test]
fn test_format_amz_time_known_epoch() {
    // 2015-08-30T12:36:00Z — the timestamp from AWS's worked SigV4 example.
    let (amz, date) = format_amz_time(1_440_938_160);
    assert_eq!(amz, "20150830T123600Z");
    assert_eq!(date, "20150830");
}

/// Table-driven boundary coverage for the inline civil-from-days arithmetic (mirrors
/// `governance::civil_from_days`'s own table-driven test): each mutated `+`/`-`/`*`/`/` in the
/// era/doe/yoe/doy/day/month derivation changes the computed date, so a handful of known
/// epoch<->date pairs spanning the epoch itself, a leap-century Feb 29 (2000, divisible by
/// 400), a non-leap-century Jan 1 (2100, divisible by 100 but not 400), and end-of-day/
/// end-of-year boundaries pins every arithmetic step in the block. Expected values are
/// cross-checked against `date -u -r <epoch>`, not hand-derived, to avoid trusting the same
/// arithmetic the test is meant to catch bugs in.
#[test]
fn test_format_amz_time_known_dates_table() {
    let cases: &[(u64, &str, &str)] = &[
        (0, "19700101T000000Z", "19700101"),
        (86_399, "19700101T235959Z", "19700101"),
        (951_782_400, "20000229T000000Z", "20000229"),
        (1_609_459_199, "20201231T235959Z", "20201231"),
        (1_717_200_000, "20240601T000000Z", "20240601"),
        (4_102_444_800, "21000101T000000Z", "21000101"),
        (1_078_012_800, "20040229T000000Z", "20040229"),
        // A real, previously-LIVE mutant: `doe / 1460 + doe / 36_524` (the era-boundary
        // correction terms) mutated `+` -> `-` shifts `yoe` by `2 * (doe / 36_524)`, which is
        // exactly 0 for every date from 2000-03-01 to 2100-02-28 — so all 7 cases above
        // (chosen mostly from that exact window) coincide under the mutation and miss it. This
        // one doesn't: 1970-03-01 falls before the window, `doe / 36_524 == 0` there too but
        // the correction still isn't degenerate at this boundary (verified by brute-forcing
        // every single-operator variation of the block against this table
        // and confirming this is the unique remaining killer). A March date one full year
        // after the epoch was deliberately avoided as "obviously distinguishing" — this is the
        // FIRST date after 1970-01-01 whose month/day computation actually exercises the
        // correction terms at all.
        (5_097_600, "19700301T000000Z", "19700301"),
    ];
    for (epoch, expected_amz, expected_date) in cases {
        let (amz, date) = format_amz_time(*epoch);
        assert_eq!(amz, *expected_amz, "epoch {epoch}");
        assert_eq!(date, *expected_date, "epoch {epoch}");
    }
}

#[test]
fn test_uri_encode_path_bedrock_model() {
    // Bedrock model IDs contain ':' and '.' — must encode ':' as %3A, keep '.' and '/'.
    assert_eq!(
        uri_encode_path("/model/anthropic.claude-3:0/converse"),
        "/model/anthropic.claude-3%3A0/converse"
    );
}

#[test]
fn test_uri_encode_path_assorted_bytes() {
    // The allocation-free encoder must produce uppercase two-digit hex for every reserved byte
    // (regression for the `format!("%{b:02X}")` → static-table rewrite).
    assert_eq!(uri_encode_path(" "), "%20"); // 0x20
    assert_eq!(uri_encode_path("?a=b&c"), "%3Fa%3Db%26c");
    assert_eq!(uri_encode_path("/"), "/"); // slash preserved
                                           // Unreserved set passes through untouched.
    assert_eq!(uri_encode_path("aZ0-_.~"), "aZ0-_.~");
    // A high byte (0xC3 from the UTF-8 of 'Ã') still encodes uppercase, padded.
    assert_eq!(uri_encode_path("\u{00c3}"), "%C3%83");
}

#[test]
fn test_canonicalize_header_value_ascii_space_only() {
    // Runs of ASCII space (0x20) collapse to one; leading/trailing ASCII space is trimmed.
    assert_eq!(canonicalize_header_value("a   b    c"), "a b c");
    assert_eq!(canonicalize_header_value("  a b c  "), "a b c");
    assert_eq!(canonicalize_header_value(""), "");
    assert_eq!(canonicalize_header_value("   "), "");
    assert_eq!(canonicalize_header_value("single"), "single");

    // ASCII space ONLY. Tab (0x09), NBSP (U+00A0), and newline are NOT whitespace to SigV4 —
    // they must pass through verbatim and must NOT be folded into / collapsed with 0x20 runs.
    // (This is what `split_whitespace` got wrong.)
    assert_eq!(canonicalize_header_value("a\tb"), "a\tb"); // tab preserved
    assert_eq!(canonicalize_header_value("a\u{00a0}b"), "a\u{00a0}b"); // NBSP preserved
    assert_eq!(canonicalize_header_value("a\nb"), "a\nb"); // newline preserved
                                                           // A tab surrounded by ASCII spaces: the spaces collapse, the tab stays put.
    assert_eq!(canonicalize_header_value("a  \t  b"), "a \t b");
    // Leading NBSP is NOT trimmed (only ASCII space is).
    assert_eq!(canonicalize_header_value("\u{00a0}a"), "\u{00a0}a");
}

#[test]
fn test_sign_v4_collapses_ascii_space_in_header_value() {
    // Two requests whose only difference is collapsible runs of ASCII space in a signed header
    // value must produce the SAME signature, because SigV4 collapses 0x20 runs to one space and
    // trims leading/trailing 0x20. (Regression for v.trim()-only canonicalization.)
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
                (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_single, _) = mk("a b c");
    let (sig_double, _) = mk("a   b  c"); // doubled ASCII spaces collapse to single spaces
    assert_eq!(
        sig_single, sig_double,
        "runs of ASCII space must be collapsed before signing"
    );
    // Leading/trailing ASCII space must still be trimmed (the original behavior).
    let (sig_padded, _) = mk("  a b c  ");
    assert_eq!(sig_single, sig_padded);
}

#[test]
fn test_sign_v4_does_not_fold_nbsp_or_tab_in_header_value() {
    // AWS canonicalizes ASCII space ONLY. A header value containing NBSP (U+00A0) or a tab must
    // be signed with those bytes intact — they must NOT be rewritten to a 0x20 space. This is the
    // bug in `split_whitespace().join(" ")`, which folds NBSP/tab into spaces and yields a
    // canonical string that differs from AWS's → SignatureDoesNotMatch (403).
    //
    // Proof: a value with a literal NBSP/tab must sign DIFFERENTLY from the same value with an
    // ASCII space in that position. Under the old (split_whitespace) code these collapsed to the
    // same signature; under the corrected code they diverge.
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
                (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
                ("x-custom".to_string(), v.to_string()),
            ],
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };
    let (sig_space, _) = mk("a b");
    let (sig_nbsp, _) = mk("a\u{00a0}b");
    let (sig_tab, _) = mk("a\tb");
    assert_ne!(
        sig_space, sig_nbsp,
        "NBSP must be preserved verbatim, not folded to an ASCII space"
    );
    assert_ne!(
        sig_space, sig_tab,
        "tab must be preserved verbatim, not folded to an ASCII space"
    );
}

// ====================== INBOUND VERIFY TESTS ======================

/// Build a self-consistent inbound request + parsed header by SIGNING with a known secret, then
/// return everything the verifier needs. This is the round-trip fixture: sign → verify must pass.
/// `now`/`amzdate` default to AWS's example timestamp; callers can tamper individual pieces.
fn signed_fixture(
    secret: &str,
    region: &str,
    service: &str,
    amzdate: &str,
    datestamp: &str,
) -> (ParsedAuthHeader, Vec<(String, String)>, String) {
    let payload_hash = sha256_hex(b"{\"x\":1}");
    let headers = vec![
        (
            "host".to_string(),
            "bedrock-runtime.amazonaws.com".to_string(),
        ),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
    ];
    let (sig, signed_headers) = sign_v4(
        secret,
        region,
        service,
        "POST",
        "/model/anthropic.claude/converse",
        "",
        &headers,
        &payload_hash,
        amzdate,
        datestamp,
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKIAEXAMPLE1234567890".to_string(),
        datestamp: datestamp.to_string(),
        region: region.to_string(),
        service: service.to_string(),
        signed_headers,
        signature: sig,
    };
    (parsed, headers, payload_hash)
}

fn inbound<'a>(
    headers: &'a [(String, String)],
    payload_hash: &'a str,
    amzdate: &'a str,
) -> InboundRequest<'a> {
    InboundRequest {
        method: "POST",
        canonical_uri: "/model/anthropic.claude/converse",
        canonical_querystring: "",
        headers,
        payload_hash,
        amzdate,
    }
}

#[test]
fn test_parse_authorization_header_roundtrip() {
    let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=abc123";
    let p = parse_authorization_header(v).expect("must parse");
    assert_eq!(p.access_key_id, "AKID");
    assert_eq!(p.datestamp, "20150830");
    assert_eq!(p.region, "us-east-1");
    assert_eq!(p.service, "bedrock");
    assert_eq!(p.signed_headers, "host;x-amz-content-sha256;x-amz-date"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(p.signature, "abc123");
}

#[test]
fn test_parse_authorization_header_rejections() {
    // A non-AWS4 scheme is "missing" (so a Bearer falls through cleanly), not malformed.
    assert_eq!(
        parse_authorization_header("Bearer xyz"),
        Err(VerifyError::MissingAuthorization)
    );
    assert_eq!(
        parse_authorization_header(""),
        Err(VerifyError::MissingAuthorization)
    );
    // AWS4 but structurally broken → malformed.
    for bad in [
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock, SignedHeaders=host, Signature=x", // scope not aws4_request (4 parts)
            "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=x", // no Credential
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, Signature=x", // no SignedHeaders
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, SignedHeaders=host", // no Signature
            "AWS4-HMAC-SHA256 Credential=//us-east-1/bedrock/aws4_request, SignedHeaders=host, Signature=x", // empty akid/date
            "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, SignedHeaders=, Signature=x", // empty signed headers
        ] {
            assert_eq!(
                parse_authorization_header(bad),
                Err(VerifyError::MalformedAuthorization),
                "must be malformed: {bad}"
            );
        }
}

#[test]
fn test_parse_amz_date_roundtrips_with_format_amz_time() {
    // parse_amz_date is the inverse of format_amz_time.
    let epoch = 1_440_938_160u64; // 2015-08-30T12:36:00Z
    let (amz, _date) = format_amz_time(epoch);
    assert_eq!(parse_amz_date(&amz), Some(epoch));
    // Bad shapes return None.
    assert_eq!(parse_amz_date("20150830T123600"), None); // no Z
    assert_eq!(parse_amz_date("2015-08-30T12:36:00Z"), None); // extended format
    assert_eq!(parse_amz_date("20150830X123600Z"), None); // wrong sep
    assert_eq!(parse_amz_date("20151330T123600Z"), None); // month 13
    assert_eq!(parse_amz_date(""), None);
}

/// Table-driven EXACT-EPOCH coverage for `parse_amz_date`'s inline `days_from_civil` arithmetic
/// (`year`/`era`/`yoe`/`doy`/`doe`/`days`, lines just above `epoch < 0`) — the inverse of
/// `format_amz_time`'s own `civil_from_days` table, reusing the SAME known-correct (epoch, ymd)
/// pairs (cross-checked against `date -u -r <epoch>` there) so both directions are pinned by
/// the same ground truth. `test_parse_amz_date_componentwise_boundaries` below only asserts
/// `is_some()`/`is_none()` on the FIELD-RANGE guard — it never asserts the computed epoch VALUE
/// and so cannot catch a mutated arithmetic operator inside `days_from_civil` itself (found by
/// adversarial review: 8 real mutants, e.g. `month <= 2` -> `>=`, `year - 1` -> `year + 1`,
/// `yoe / 4 - yoe / 100` -> `+`, `if epoch < 0` -> `<= 0`, all survived until this test). A
/// month<=2 date (year-1 branch) and a month>2 date (year branch) are both required to exercise
/// the `let y = if month <= 2 {...}` split at all; the leap-century/non-leap-century pairs
/// exercise the era/yoe correction terms the same way the format-side table does.
#[test]
fn test_parse_amz_date_known_epochs_table() {
    let cases: &[(u64, &str)] = &[
        (0, "19700101T000000Z"),
        (86_399, "19700101T235959Z"),
        (5_097_600, "19700301T000000Z"),
        (951_782_400, "20000229T000000Z"),
        (1_609_459_199, "20201231T235959Z"),
        (1_717_200_000, "20240601T000000Z"),
        (4_102_444_800, "21000101T000000Z"),
        (1_078_012_800, "20040229T000000Z"),
    ];
    for (epoch, amzdate) in cases {
        assert_eq!(parse_amz_date(amzdate), Some(*epoch), "amzdate {amzdate}");
    }
}

/// Exact componentwise boundaries of `!(1..=12).contains(&month) || !(1..=31).contains(&day)
/// || hour > 23 || min > 59 || sec > 60`. Each case below flips EXACTLY ONE field to its
/// first-invalid value while holding every other field at a valid value — this is what catches
/// a single `||` mutated to `&&` at any one junction (only one sub-condition is true, so a
/// mutated `&&` there would fail to reject) as well as each `>`/`>=`/`==` boundary mutation
/// (the boundary itself, one past it, both checked).
#[test]
fn test_parse_amz_date_componentwise_boundaries() {
    // Valid at the boundary: hour=23, min=59, sec=60 (a real leap second) must all parse.
    assert!(
        parse_amz_date("20150830T235960Z").is_some(),
        "hour 23 must be valid"
    );
    assert!(
        parse_amz_date("20150830T005960Z").is_some(),
        "min 59 must be valid"
    );
    assert!(
        parse_amz_date("20150830T000060Z").is_some(),
        "sec 60 (leap second) must be valid"
    );
    assert!(
        parse_amz_date("20150801T000000Z").is_some(),
        "day 1 must be valid"
    );
    assert!(
        parse_amz_date("20150831T000000Z").is_some(),
        "day 31 must be valid"
    );
    assert!(
        parse_amz_date("20150101T000000Z").is_some(),
        "month 1 must be valid"
    );
    assert!(
        parse_amz_date("20151201T000000Z").is_some(),
        "month 12 must be valid"
    );

    // One past the boundary, every other field valid: each must independently reject.
    assert_eq!(
        parse_amz_date("20150830T240000Z"),
        None,
        "hour 24 must be rejected"
    );
    assert_eq!(
        parse_amz_date("20150830T006000Z"),
        None,
        "min 60 must be rejected"
    );
    assert_eq!(
        parse_amz_date("20150830T000061Z"),
        None,
        "sec 61 must be rejected"
    );
    assert_eq!(
        parse_amz_date("20150800T000000Z"),
        None,
        "day 0 must be rejected"
    );
    assert_eq!(
        parse_amz_date("20150832T000000Z"),
        None,
        "day 32 must be rejected"
    );
    assert_eq!(
        parse_amz_date("20150001T000000Z"),
        None,
        "month 0 must be rejected"
    );
    assert_eq!(
        parse_amz_date("20151300T000000Z"),
        None,
        "month 13 must be rejected"
    );
}

#[test]
fn test_verify_inbound_sigv4_roundtrip_accepts() {
    // The headline: a request signed with a secret VERIFIES against that same secret.
    let secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now), Ok(()));
}

#[test]
fn test_verify_inbound_sigv4_wrong_secret_rejected() {
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(
        "the-real-secret",
        "us-east-1",
        "bedrock",
        amzdate,
        "20150830",
    );
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, "a-DIFFERENT-secret", now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_tampered_signature_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    // Flip the last hex nibble of the signature.
    let mut sig = parsed.signature.clone();
    let last = sig.pop().unwrap();
    sig.push(if last == '0' { '1' } else { '0' });
    parsed.signature = sig;
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_tampered_body_payload_hash_rejected() {
    // A changed payload hash (i.e. a tampered body whose x-amz-content-sha256 no longer matches
    // what was signed) must REJECT: the signed header value differs from the value fed to verify.
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, mut headers, _ph) =
        signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    // Tamper the content-sha256 header (and the payload_hash input) to a DIFFERENT body's hash.
    let tampered = sha256_hex(b"{\"evil\":true}");
    for h in headers.iter_mut() {
        if h.0 == X_AMZ_CONTENT_SHA256 {
            h.1 = tampered.clone();
        }
    }
    let req = inbound(&headers, &tampered, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignatureMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_expired_date_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let signed_epoch = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    let req = inbound(&headers, &ph, amzdate);
    // `now` is 10 minutes after the signature — outside the ±5min window.
    let now = signed_epoch + CLOCK_SKEW_SECS + 60;
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::Expired)
    );
    // Far-future signature (clock ahead) is also rejected (abs diff).
    let now2 = signed_epoch.saturating_sub(CLOCK_SKEW_SECS + 60);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now2),
        Err(VerifyError::Expired)
    );
    // Just inside the window still verifies.
    let now3 = signed_epoch + CLOCK_SKEW_SECS - 1;
    assert_eq!(verify_inbound_sigv4(&parsed, &req, secret, now3), Ok(()));
}

#[test]
fn test_verify_inbound_sigv4_signed_header_missing_rejected() {
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    // Drop x-amz-date from the request's headers — it is in SignedHeaders, so reconstruction fails.
    let pruned: Vec<(String, String)> = headers
        .into_iter()
        .filter(|(k, _)| k != X_AMZ_DATE)
        .collect();
    let req = inbound(&pruned, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignedHeadersMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_host_must_be_signed() {
    // A SignedHeaders list WITHOUT host is rejected even before signature comparison.
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let payload_hash = sha256_hex(b"");
    let headers = vec![
        (X_AMZ_DATE.to_string(), amzdate.to_string()),
        (X_AMZ_CONTENT_SHA256.to_string(), payload_hash.clone()),
    ];
    // Sign WITHOUT host (so the signature is self-consistent for these headers), but host-less.
    let (sig, signed_headers) = sign_v4(
        secret,
        "us-east-1",
        "bedrock",
        "POST",
        "/x",
        "",
        &headers,
        &payload_hash,
        amzdate,
        "20150830",
    );
    let parsed = ParsedAuthHeader {
        access_key_id: "AKID".to_string(),
        datestamp: "20150830".to_string(),
        region: "us-east-1".to_string(),
        service: "bedrock".to_string(),
        signed_headers,
        signature: sig,
    };
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/x",
        canonical_querystring: "",
        headers: &headers,
        payload_hash: &payload_hash,
        amzdate,
    };
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignedHeadersMismatch)
    );
}

#[test]
fn test_verify_inbound_sigv4_datestamp_must_match_amzdate() {
    // A Credential datestamp that disagrees with x-amz-date's date is malformed/forged.
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    parsed.datestamp = "20150831".to_string(); // off by a day
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::MalformedAuthorization)
    );
}

/// AWS published worked example — GET iam ListUsers, 2015-08-30. If our canonical-request →
/// string-to-sign → signature chain reproduces AWS's documented signature, the algorithm is
/// correct. (https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html)
#[test]
fn test_sign_v4_matches_aws_published_example() {
    let headers = vec![
        (
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=utf-8".to_string(),
        ),
        ("host".to_string(), "iam.amazonaws.com".to_string()),
        (X_AMZ_DATE.to_string(), "20150830T123600Z".to_string()),
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
    assert_eq!(signed, "content-type;host;x-amz-date"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(
        sig,
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7" // golden wire-contract literal (kept bare on purpose)
    );
}

// The canonical constant-time-reject dummy secret. In busbar-core this lives at
// `crate::auth::DUMMY_SECRET` (the reject path there uses it); the sigv4 signer now lives in the
// neutral substrate below auth, so this test pins the SAME byte string locally. Used to prove the
// unknown-key path produces an ordinary SignatureMismatch, not a distinct variant.
const DUMMY_SECRET: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";

#[test]
fn test_verify_inbound_sigv4_unknown_key_dummy_secret_is_signature_mismatch() {
    // Dummy-secret guard: a request signed with a REAL secret, verified against the canonical
    // DUMMY secret (the path taken for an unknown AccessKeyId), must fail with the SAME ordinary
    // `SignatureMismatch` a wrong-secret attempt produces — NOT a distinct "key not found" variant.
    // This pins the FUNCTIONAL contract: an unknown AccessKeyId is verified against the canonical
    // dummy secret and returns `Err(SignatureMismatch)`, so the response is the same as a real key
    // with a bad signature — no key-existence enumeration oracle. (Timing-equalization is a design
    // property of always running the HMAC against the dummy secret; this test does not assert
    // timing, only the response contract.)
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(
        "a-real-tenant-secret",
        "us-east-1",
        "bedrock",
        amzdate,
        "20150830",
    );
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, DUMMY_SECRET, now),
        Err(VerifyError::SignatureMismatch),
        "verifying a real-secret signature against the dummy secret must be an ordinary \
             SignatureMismatch, not a distinct key-not-found variant"
    );
}

#[test]
fn test_parse_authorization_header_skips_unknown_sections() {
    // An UNKNOWN section (AWS clients may emit extras) is SKIPPED, not rejected — as long as
    // the three mandatory sections are present and well-formed.
    let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, \
                 SignedHeaders=host;x-amz-date, Signature=abc123, X-Future-Extension=whatever";
    let p = parse_authorization_header(v).expect("unknown section must be skipped, not rejected");
    assert_eq!(p.access_key_id, "AKID");
    assert_eq!(p.signed_headers, "host;x-amz-date"); // golden wire-contract literal (kept bare on purpose)
    assert_eq!(p.signature, "abc123");
    // But a MISSING mandatory section (Signature) with an unknown one present still fails.
    let missing_sig = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_request, \
                           SignedHeaders=host, X-Extra=1";
    assert_eq!(
        parse_authorization_header(missing_sig),
        Err(VerifyError::MalformedAuthorization),
        "an unknown section does not satisfy the mandatory Signature requirement"
    );
}

#[test]
fn test_parse_authorization_header_rejects_five_part_credential_with_wrong_termination() {
    // `parts.len() != 5 || parts[4] != SIGV4_TERMINATION` — a mutated `&&` here would only
    // reject when BOTH sub-conditions hold; a credential with the CORRECT part count (5) but
    // the WRONG final segment (anything other than "aws4_request") would then be silently
    // accepted, since `parts.len() != 5` is false and short-circuits the `&&`. This is
    // distinct from the existing "scope not aws4_request (4 parts)" rejection case, which
    // only exercises the `parts.len() != 5` half.
    let v = "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/bedrock/aws4_bogus, \
                 SignedHeaders=host, Signature=x";
    assert_eq!(
        parse_authorization_header(v),
        Err(VerifyError::MalformedAuthorization),
        "a 5-part credential with the wrong termination segment must still be rejected"
    );
}

#[test]
fn test_verify_inbound_sigv4_signed_headers_claim_stripped_rejected() {
    // An attacker who removes a header NAME from the SignedHeaders CLAIM (without re-signing)
    // must be rejected — the reconstructed SignedHeaders string no longer matches what was signed.
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    // Strip x-amz-content-sha256 from the SignedHeaders claim (host still present so the host check
    // passes and we reach the signature/headers compare). The signature was computed over all three.
    parsed.signed_headers = "host;x-amz-date".to_string();
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignatureMismatch),
        "stripping a header from the SignedHeaders claim must fail-closed"
    );
}

#[test]
fn test_verify_inbound_sigv4_signed_headers_wrong_sort_rejected() {
    // SignedHeaders MUST be sorted (the signer sorts). A claim listing the same names in a
    // non-sorted order diverges from the reconstruction and must be rejected.
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (mut parsed, headers, ph) =
        signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    // Reverse-sorted order (still contains host, so it passes the host-present gate).
    parsed.signed_headers = "x-amz-date;x-amz-content-sha256;host".to_string();
    let req = inbound(&headers, &ph, amzdate);
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::SignatureMismatch),
        "an unsorted SignedHeaders claim must fail-closed"
    );
}

#[test]
fn test_verify_inbound_sigv4_exact_skew_boundary_accepted() {
    // The clock-skew check is `skew > CLOCK_SKEW_SECS` (strict >), so a skew EXACTLY equal to
    // the bound must be ACCEPTED (only strictly-greater is Expired). Pins the boundary.
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let signed_epoch = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    let req = inbound(&headers, &ph, amzdate);
    // Exactly at the boundary (both directions) must verify.
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, signed_epoch + CLOCK_SKEW_SECS),
        Ok(()),
        "skew == CLOCK_SKEW_SECS (ahead) must be accepted under the strict > comparison"
    );
    assert_eq!(
        verify_inbound_sigv4(
            &parsed,
            &req,
            secret,
            signed_epoch.saturating_sub(CLOCK_SKEW_SECS)
        ),
        Ok(()),
        "skew == CLOCK_SKEW_SECS (behind) must be accepted"
    );
}

#[test]
fn test_verify_inbound_sigv4_missing_date_rejected() {
    // A request whose x-amz-date is not a parseable amz timestamp fails with MissingDate,
    // surfaced through verify_inbound_sigv4 itself (not just parse_amz_date in isolation).
    let secret = "the-real-secret";
    let amzdate = "20150830T123600Z";
    let now = parse_amz_date(amzdate).unwrap();
    let (parsed, headers, ph) = signed_fixture(secret, "us-east-1", "bedrock", amzdate, "20150830");
    // Build an InboundRequest carrying an UNPARSEABLE amzdate.
    let req = InboundRequest {
        method: "POST",
        canonical_uri: "/model/anthropic.claude/converse",
        canonical_querystring: "",
        headers: &headers,
        payload_hash: &ph,
        amzdate: "not-a-date",
    };
    assert_eq!(
        verify_inbound_sigv4(&parsed, &req, secret, now),
        Err(VerifyError::MissingDate)
    );
}
