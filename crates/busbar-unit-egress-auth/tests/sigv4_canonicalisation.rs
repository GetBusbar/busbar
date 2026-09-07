// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SigV4 canonicalisation, against a reference written from the AWS specification rather than from
//! the signer.
//!
//! One published worked example fixes one point: one method, one path, one non-empty query, three
//! headers all already lowercase and distinct, an empty payload. Everything the canonicalisation
//! rules exist FOR is off that point — an empty query string, a query carrying the same key twice,
//! unreserved characters that must survive encoding untouched and reserved ones that must not, a
//! header name spelled in mixed case, a header name carried twice, a value padded with runs of
//! spaces. Each of those is a place where signing something subtly different from what the request
//! carries produces a 403 that names nothing.
//!
//! So this file recomputes the whole chain independently — canonical request, string to sign, the
//! four-link key derivation — from the specification's own wording, and requires the signer to
//! agree across a matrix that walks every one of those rules. The reference is itself anchored to
//! AWS's published signature, so "they agree" cannot mean "they are wrong together".

use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use busbar_unit_egress_auth::sigv4::{sha256_hex, sign_v4, uri_encode_path};

type HmacSha256 = Hmac<Sha256>;

fn mac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut m = <HmacSha256 as KeyInit>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

/// Trim and collapse runs of the ASCII space, per "Trim excess white space before and after values
/// and convert sequential spaces to a single space". Only the space character; the specification
/// says nothing about tabs or any other codepoint, so nothing else is touched.
fn spec_trim(v: &str) -> String {
    v.split(' ')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The signature and SignedHeaders string the specification calls for, computed from its own
/// wording: lowercase every header name, trim each value, sort by name, comma-join the values of a
/// name that appears more than once, and assemble the canonical request, the string to sign and the
/// four-link signing key in that order.
#[allow(clippy::too_many_arguments)]
fn reference_sign(
    secret: &str,
    region: &str,
    service: &str,
    method: &str,
    canonical_uri: &str,
    canonical_querystring: &str,
    headers: &[(String, String)],
    payload_hash: &str,
    amzdate: &str,
    datestamp: &str,
) -> (String, String) {
    let mut names: Vec<String> = headers
        .iter()
        .map(|(k, _)| k.to_lowercase())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    names.sort();

    let mut canonical_headers = String::new();
    for name in &names {
        let joined = headers
            .iter()
            .filter(|(k, _)| k.to_lowercase() == *name)
            .map(|(_, v)| spec_trim(v))
            .collect::<Vec<_>>()
            .join(",");
        canonical_headers.push_str(name);
        canonical_headers.push(':');
        canonical_headers.push_str(&joined);
        canonical_headers.push('\n');
    }
    let signed_headers = names.join(";");

    let canonical_request = [
        method,
        canonical_uri,
        canonical_querystring,
        &canonical_headers,
        &signed_headers,
        payload_hash,
    ]
    .join("\n");

    let scope = format!("{datestamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let k_date = mac(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
    let k_region = mac(&k_date, region.as_bytes());
    let k_service = mac(&k_region, service.as_bytes());
    let k_signing = mac(&k_service, b"aws4_request");
    (
        hex::encode(mac(&k_signing, string_to_sign.as_bytes())),
        signed_headers,
    )
}

/// The reference is right where AWS says what right is: its output for the published worked example
/// (GET iam ListUsers, 2015-08-30) is the signature AWS documents. Everything below compares the
/// signer to this reference, which is only worth anything because of this test.
#[test]
fn the_reference_reproduces_the_aws_published_signature() {
    let (sig, signed) = reference_sign(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "us-east-1",
        "iam",
        "GET",
        "/",
        "Action=ListUsers&Version=2010-05-08",
        &[
            (
                "content-type".to_string(),
                "application/x-www-form-urlencoded; charset=utf-8".to_string(),
            ),
            ("host".to_string(), "iam.amazonaws.com".to_string()),
            ("x-amz-date".to_string(), "20150830T123600Z".to_string()),
        ],
        &sha256_hex(b""),
        "20150830T123600Z",
        "20150830",
    );
    assert_eq!(signed, "content-type;host;x-amz-date");
    assert_eq!(
        sig,
        "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7"
    );
}

struct Case {
    what: &'static str,
    method: &'static str,
    uri: &'static str,
    query: &'static str,
    headers: Vec<(String, String)>,
    body: &'static [u8],
}

fn h(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn cases() -> Vec<Case> {
    let host = ("host", "bedrock.us-east-1.amazonaws.com");
    let date = ("x-amz-date", "20150830T123600Z");
    vec![
        Case {
            what: "no query string at all — the canonical request carries an empty line, \
                   not a missing one",
            method: "POST",
            uri: "/model/anthropic.claude/converse",
            query: "",
            headers: h(&[host, date]),
            body: b"{}",
        },
        Case {
            what: "a query string with one key and an empty value",
            method: "GET",
            uri: "/",
            query: "a=",
            headers: h(&[host, date]),
            body: b"",
        },
        Case {
            what: "the same key twice, in the order the caller sorted them — a repeated key is \
                   two entries, never collapsed to one",
            method: "GET",
            uri: "/",
            query: "a=1&a=2",
            headers: h(&[host, date]),
            body: b"",
        },
        Case {
            what: "the same key twice, values the other way round",
            method: "GET",
            uri: "/",
            query: "a=2&a=1",
            headers: h(&[host, date]),
            body: b"",
        },
        Case {
            what: "every unreserved character in a path, which must survive encoding untouched",
            method: "GET",
            uri: "/abcXYZ0189-_.~/",
            query: "",
            headers: h(&[host, date]),
            body: b"",
        },
        Case {
            what: "a path with reserved characters already percent-encoded",
            method: "GET",
            uri: "/model/anthropic.claude-3%3A0/converse",
            query: "",
            headers: h(&[host, date]),
            body: b"",
        },
        Case {
            what: "a header name in mixed case, which is lowercased before signing",
            method: "GET",
            uri: "/",
            query: "",
            headers: h(&[host, date, ("X-Custom-Thing", "value")]),
            body: b"",
        },
        Case {
            what: "header names given out of order, which are sorted before signing",
            method: "GET",
            uri: "/",
            query: "",
            headers: h(&[("zz-last", "z"), date, host, ("aa-first", "a")]),
            body: b"",
        },
        Case {
            what: "one header name carried twice, comma-joined into a single entry",
            method: "GET",
            uri: "/",
            query: "",
            headers: h(&[host, date, ("x-dup", "  first  "), ("x-dup", "second")]),
            body: b"",
        },
        Case {
            what: "the same name twice differing only in case, which is still one name",
            method: "GET",
            uri: "/",
            query: "",
            headers: h(&[host, date, ("X-Dup", "alpha"), ("x-dup", "beta")]),
            body: b"",
        },
        Case {
            what: "a value padded with runs of spaces, collapsed and trimmed",
            method: "GET",
            uri: "/",
            query: "",
            headers: h(&[host, date, ("x-padded", "   a    b   ")]),
            body: b"",
        },
        Case {
            what: "a value that is nothing but spaces, which trims to empty",
            method: "GET",
            uri: "/",
            query: "",
            headers: h(&[host, date, ("x-blank", "    ")]),
            body: b"",
        },
        Case {
            what: "a non-empty payload, whose hash is part of the canonical request",
            method: "POST",
            uri: "/model/anthropic.claude/converse",
            query: "",
            headers: h(&[host, date]),
            body: b"{\"messages\":[]}",
        },
    ]
}

/// The signer agrees with the specification on every canonicalisation rule, one case per rule.
///
/// A disagreement here is a request signed over bytes the wire does not carry: the upstream
/// recomputes the canonical request from what it received, gets a different signature, and answers
/// 403 with nothing on this side to say which of the two disagreed about what.
#[test]
fn the_signer_agrees_with_the_specification_on_every_canonicalisation_rule() {
    for case in cases() {
        let payload_hash = sha256_hex(case.body);
        let got = sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "bedrock",
            case.method,
            case.uri,
            case.query,
            &case.headers,
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        );
        let want = reference_sign(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "bedrock",
            case.method,
            case.uri,
            case.query,
            &case.headers,
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        );
        assert_eq!(got, want, "{}", case.what);
    }
}

/// Every case above signs differently from every other one.
///
/// Agreement with a reference says the signer computes what the specification says. This says the
/// cases are not all the same computation wearing different hats: an empty query and a present one,
/// a repeated key in either order, one name carried twice and two distinct names, all reach
/// distinct signatures, so a rule that stopped being applied would show up above rather than
/// cancelling out on both sides.
#[test]
fn no_two_canonicalisation_cases_collapse_onto_the_same_signature() {
    let mut seen: Vec<(String, &'static str)> = Vec::new();
    for case in cases() {
        let (sig, _) = sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "bedrock",
            case.method,
            case.uri,
            case.query,
            &case.headers,
            &sha256_hex(case.body),
            "20150830T123600Z",
            "20150830",
        );
        if let Some((_, other)) = seen.iter().find(|(s, _)| *s == sig) {
            panic!("`{}` and `{}` sign identically", case.what, other);
        }
        seen.push((sig, case.what));
    }
}

/// The things canonicalisation exists to make NOT matter, do not matter.
///
/// The rules have two directions and only one of them is about distinguishing requests. Lowercasing
/// names, sorting them, trimming values and comma-joining a repeated name all exist so that a
/// request an HTTP stack is free to re-spell — and it is free to re-spell all four of these —
/// signs the same both ways. A signer that skipped one would still agree with the reference on
/// cases that never exercise it, and would produce a 403 only for the caller who happened to hand
/// its headers over in the other spelling.
#[test]
fn the_spellings_canonicalisation_folds_together_all_sign_the_same() {
    let payload_hash = sha256_hex(b"");
    let sign = |headers: &[(String, String)]| {
        sign_v4(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "us-east-1",
            "bedrock",
            "GET",
            "/",
            "",
            headers,
            &payload_hash,
            "20150830T123600Z",
            "20150830",
        )
    };

    let canonical = h(&[
        ("host", "bedrock.us-east-1.amazonaws.com"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-thing", "a b"),
    ]);
    let want = sign(&canonical);

    for (what, respelt) in [
        (
            "header names in mixed case",
            h(&[
                ("Host", "bedrock.us-east-1.amazonaws.com"),
                ("X-Amz-Date", "20150830T123600Z"),
                ("X-Thing", "a b"),
            ]),
        ),
        (
            "header names in a different order",
            h(&[
                ("x-thing", "a b"),
                ("x-amz-date", "20150830T123600Z"),
                ("host", "bedrock.us-east-1.amazonaws.com"),
            ]),
        ),
        (
            "values padded and internally double-spaced",
            h(&[
                ("host", "  bedrock.us-east-1.amazonaws.com "),
                ("x-amz-date", "20150830T123600Z   "),
                ("x-thing", "   a    b   "),
            ]),
        ),
    ] {
        assert_eq!(sign(&respelt), want, "{what} changed the signature");
    }

    // A name carried twice signs as the one comma-joined entry AWS's servers reconstruct, whatever
    // case each copy was spelled in and whatever padding each value carried.
    let pre_joined = h(&[
        ("host", "bedrock.us-east-1.amazonaws.com"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-thing", "a,b"),
    ]);
    let carried_twice = h(&[
        ("host", "bedrock.us-east-1.amazonaws.com"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-thing", "  a  "),
        ("X-Thing", " b "),
    ]);
    assert_eq!(
        sign(&carried_twice),
        sign(&pre_joined),
        "a repeated name must sign as one comma-joined entry"
    );
    assert_eq!(sign(&carried_twice).1, "host;x-amz-date;x-thing");
}

/// Every argument `sign_v4` takes, in the order it takes them, so a test can vary one at a time
/// and leave the other nine alone.
type Inputs = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Vec<(String, String)>,
    String,
    String,
    String,
);

/// Every input the signature is supposed to depend on actually changes it.
///
/// The canonical request, the credential scope and the four-link key derivation between them cover
/// eleven separate inputs. An input dropped from any of those three is a signature that no longer
/// commits to it — a request that can be replayed against a different region, service, day, method,
/// path, query or body and still verify.
#[test]
fn the_signature_commits_to_every_input_it_is_derived_from() {
    let base_headers = h(&[
        ("host", "bedrock.us-east-1.amazonaws.com"),
        ("x-amz-date", "20150830T123600Z"),
    ]);
    let base = (
        "secret-one",
        "us-east-1",
        "bedrock",
        "POST",
        "/model/a/converse",
        "v=1",
        base_headers.clone(),
        sha256_hex(b"{}"),
        "20150830T123600Z".to_string(),
        "20150830".to_string(),
    );
    let sign = |t: &Inputs| sign_v4(t.0, t.1, t.2, t.3, t.4, t.5, &t.6, &t.7, &t.8, &t.9).0;
    let baseline = sign(&base);

    let mut varied = Vec::new();

    let mut t = base.clone();
    t.0 = "secret-two";
    varied.push(("the signing secret", t));
    let mut t = base.clone();
    t.1 = "eu-west-1";
    varied.push(("the region", t));
    let mut t = base.clone();
    t.2 = "s3";
    varied.push(("the service", t));
    let mut t = base.clone();
    t.3 = "GET";
    varied.push(("the method", t));
    let mut t = base.clone();
    t.4 = "/model/b/converse";
    varied.push(("the path", t));
    let mut t = base.clone();
    t.5 = "v=2";
    varied.push(("the query string", t));
    let mut t = base.clone();
    t.5 = "";
    varied.push(("dropping the query string", t));
    let mut t = base.clone();
    t.6 = h(&[
        ("host", "bedrock.eu-west-1.amazonaws.com"),
        ("x-amz-date", "20150830T123600Z"),
    ]);
    varied.push(("a signed header's value", t));
    let mut t = base.clone();
    t.6 = h(&[
        ("host", "bedrock.us-east-1.amazonaws.com"),
        ("x-amz-date", "20150830T123600Z"),
        ("x-extra", "1"),
    ]);
    varied.push(("an added signed header", t));
    let mut t = base.clone();
    t.7 = sha256_hex(b"{\"a\":1}");
    varied.push(("the payload hash", t));
    let mut t = base.clone();
    t.8 = "20150830T123601Z".to_string();
    varied.push(("the amzdate", t));
    let mut t = base.clone();
    t.9 = "20150831".to_string();
    varied.push(("the datestamp", t));

    for (what, t) in varied {
        assert_ne!(
            sign(&t),
            baseline,
            "changing {what} left the signature unchanged"
        );
    }
}

/// The URI encoder, over every byte value there is.
///
/// AWS's rule has exactly two clauses — the unreserved set `A-Za-z0-9-_.~` and the path separator
/// pass through, everything else becomes `%` and two UPPERCASE hex digits. Lowercase hex is a
/// different canonical request from the one the upstream recomputes, and a byte let through
/// unencoded is a path the signature does not cover.
#[test]
fn uri_encoding_is_the_unreserved_set_and_the_separator_and_nothing_else() {
    for b in 0u8..=127 {
        let s = (b as char).to_string();
        let got = uri_encode_path(&s);
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'/');
        if unreserved {
            assert_eq!(got, s, "byte {b:#04x} is unreserved and passes through");
        } else {
            assert_eq!(
                got,
                format!("%{b:02X}"),
                "byte {b:#04x} is encoded, uppercase"
            );
            assert!(
                got.chars().all(|c| !c.is_ascii_lowercase()),
                "the hex digits are uppercase for byte {b:#04x}"
            );
        }
    }

    // Non-ASCII is encoded byte by byte over its UTF-8 encoding, not by codepoint.
    assert_eq!(uri_encode_path("é"), "%C3%A9");
    assert_eq!(uri_encode_path("日"), "%E6%97%A5");
    // A path already carrying a percent is encoded again — the caller encodes once, and doing it
    // twice must be visibly different rather than silently idempotent.
    assert_eq!(uri_encode_path("%3A"), "%253A");
    // The separator survives, and so does an empty path.
    assert_eq!(uri_encode_path("/a/b/c"), "/a/b/c");
    assert_eq!(uri_encode_path(""), "");
}

/// The payload hash is SHA-256 of the exact bytes, and the empty body has the hash AWS's own
/// documentation names.
#[test]
fn the_payload_hash_is_sha256_of_the_exact_bytes() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // A byte added anywhere changes it, including a trailing newline a body must not grow.
    assert_ne!(sha256_hex(b"abc"), sha256_hex(b"abc\n"));
    assert!(sha256_hex(b"abc").chars().all(|c| !c.is_ascii_uppercase()));
}
