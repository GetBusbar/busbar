// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one URL masker: the userinfo cut to the last `@`, secret-looking query and fragment values
//! masked, the rest as given; never a credential in the line.

use super::*;

/// 1.5.5's masked form for an ordinary URL with userinfo: host, port and path kept.
#[test]
fn userinfo_is_masked_as_1_5_5_masked_it() {
    assert_eq!(
        mask_url("https://alice:s3cr3t@collector.example.com:4318/v1/traces"),
        "https://***@collector.example.com:4318/v1/traces"
    );
    assert_eq!(
        mask_url("https://alice@hooks.example.com/in"),
        "https://***@hooks.example.com/in"
    );
}

/// A URL with nothing to mask, and a string with no scheme, are returned as given.
#[test]
fn nothing_to_mask_is_unchanged() {
    for url in [
        "https://collector.example.com:4318/v1/traces",
        "https://h.example/p?page=2&q=x#top",
        "not a url",
        "",
    ] {
        assert_eq!(mask_url(url), url);
    }
}

/// A credential holding an unescaped `/`, `?` or `#` is cut whole: the cut runs to the LAST `@`.
#[test]
fn a_credential_with_delimiters_is_cut_to_the_last_at() {
    for (url, shown) in [
        ("https://tok/en@collector/v1", "https://***@collector/v1"),
        ("https://u:p#w@host/x", "https://***@host/x"),
        ("https://u:a?token=b@host", "https://***@host"),
        (
            "https://u:pw@bad host:99999/x",
            "https://***@bad host:99999/x",
        ),
    ] {
        let masked = mask_url(url);
        assert_eq!(masked, shown, "{url}");
    }
}

/// Every secret-looking query or fragment value is masked, in any case, the rest kept.
#[test]
fn secret_looking_query_and_fragment_values_are_masked() {
    assert_eq!(
        mask_url("https://h/p?api_key=K1&page=2&X-Amz-Signature=S;Token=T#access_token=A&state=s"),
        "https://h/p?api_key=***&page=2&X-Amz-Signature=***;Token=***#access_token=***&state=s"
    );
    assert_eq!(mask_url("https://h/?password="), "https://h/?password=");
    assert_eq!(
        mask_url("https://u:p@h/?code=abc"),
        "https://***@h/?code=***"
    );
}

/// An `@` in the query is over-cut, and what follows it is still read as pairs, so no value that
/// followed it leaks.
#[test]
fn an_at_in_the_query_is_over_cut_never_a_leak() {
    let masked = mask_url("https://h/p?email=a@b.c&token=T");
    assert_eq!(masked, "https://***@b.c&token=***");
    assert!(!masked.contains("=T") && !masked.contains("email"));
}
