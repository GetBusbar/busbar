// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The URL credential pieces, over the vectors the export and hook sinks pin them with
//! (export-otlp `tests.rs`, `door_tests.rs`; export-webhook `tests.rs`; hook-webrequest
//! `wire_tests.rs`). A URL is given as the parts its parser read (`url` 2: the username and
//! password as written, the text from the path on).

use super::*;

#[test]
fn a_percent_escape_decodes_only_with_two_hex_digits() {
    // export-otlp: `%zz`, a trailing `%4` and `%+4` (which `from_str_radix` would take) stay.
    assert_eq!(percent_decode(b"a%20b%zz%4"), b"a b%zz%4");
    assert_eq!(percent_decode(b"ab%+41cd"), b"ab%+41cd");
    assert_eq!(percent_decode(b"%41%6a%6A%"), b"Ajj%");
    assert_eq!(percent_decode(b"p%FFw"), b"p\xFFw");
    assert_eq!(percent_decode(b""), b"");
}

/// export-otlp's userinfo (RFC 7617 octets): both halves, the password alone, the user alone,
/// percent-encoded, an octet that is no UTF-8, and a `%+4` that is no escape.
#[test]
fn a_userinfo_read_as_octets_is_sent_as_it_decodes() {
    for (username, password, sent) in [
        ("alice", Some("s3cr3t"), Some("Basic YWxpY2U6czNjcjN0")),
        ("", Some("topsecret"), Some("Basic OnRvcHNlY3JldA==")),
        ("tokenuser", None, Some("Basic dG9rZW51c2VyOg==")),
        ("u", Some("p%40ss%3Aword"), Some("Basic dTpwQHNzOndvcmQ=")),
        // base64("u:p\xFFw"): the octet as it is, never a lossy UTF-8 reading.
        ("u", Some("p%FFw"), Some("Basic dTpw/3c=")),
        ("u", Some("ab%+41cd"), Some("Basic dTphYiUrNDFjZA==")),
        ("", None, None),
    ] {
        assert_eq!(
            basic_authorization(username, password, Userinfo::Octets).as_deref(),
            sent,
            "{username:?} {password:?}"
        );
    }
}

/// export-webhook's and hook-webrequest's userinfo, as reqwest 0.12 sent it for 1.5.5: a user
/// alone as `{user}:`, a password alone as `:{password}`; a username that does not decode to UTF-8
/// sends no field, and a password that does not is left out.
#[test]
fn a_userinfo_read_as_text_is_sent_as_1_5_5_sent_it() {
    for (username, password, sent) in [
        ("user", Some("pass"), Some("Basic dXNlcjpwYXNz")),
        (
            "Aladdin",
            Some("open%20sesame"),
            Some("Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ),
        ("user", None, Some("Basic dXNlcjo=")),
        ("", Some("pass"), Some("Basic OnBhc3M=")),
        (
            "us%40er",
            Some("p%3Ass%20w"),
            Some("Basic dXNAZXI6cDpzcyB3"),
        ),
        // `jos\u{e9}` as the parser writes it, and as given.
        ("jos%C3%A9", Some("pw"), Some("Basic am9zw6k6cHc=")),
        ("a%zz", Some("b"), Some("Basic YSV6ejpi")),
        ("u", Some("%FF"), Some("Basic dTo=")),
        ("%FF", Some("pw"), None),
        ("", None, None),
        // hook-webrequest `wire_tests.rs`.
        ("u", Some("p"), Some("Basic dTpw")),
    ] {
        assert_eq!(
            basic_authorization(username, password, Userinfo::Utf8).as_deref(),
            sent,
            "{username:?} {password:?}"
        );
    }
}

/// export-otlp and export-webhook (owner ruling 2026-10-24): a url whose `@` comes after its host
/// is refused, its credential cut from the url shown; a credential written as the grammar wants
/// it is not.
#[test]
fn an_ambiguous_url_is_refused_without_its_credential() {
    for (url, from_path, secret) in [
        (
            "https://tok/en@siem.example/in",
            "/en@siem.example/in",
            "tok/en",
        ),
        (
            "https://u:123/x@collector.example/v1/traces",
            "/x@collector.example/v1/traces",
            "u:123/x",
        ),
        ("https://siem.example/in?k=a@b", "/in?k=a@b", "k=a"),
    ] {
        let text = ambiguous_url(url, from_path).expect(url);
        assert!(text.contains("is ambiguous"), "{text}");
        assert!(text.contains("%2F"), "{text}");
        assert!(!text.contains(secret), "{url}: {text}");
    }
    assert_eq!(
        ambiguous_url("https://tok/en@siem.example/in", "/en@siem.example/in").as_deref(),
        Some(
            "settings: url `https://***@siem.example/in` is ambiguous: it has an `@` after its \
             host, so what comes before that `@` would be read as the host and path, not as a \
             credential. Percent-encode a `/`, `?` or `#` inside the credential (`%2F`, `%3F`, \
             `%23`), or write an `@` meant for the path as `%40`"
        )
    );
    for (url, from_path) in [
        ("https://u:p@collector.example/v1/traces", "/v1/traces"),
        ("https://tok%2Fen@siem.example/in", "/in"),
        ("http://127.0.0.1:4318/v1/traces", "/v1/traces"),
        ("https://siem.example/%40in", "/%40in"),
    ] {
        assert_eq!(ambiguous_url(url, from_path), None, "{url}");
    }
}

/// export-otlp: the cut reaches the LAST `@`, so a password holding an unescaped delimiter (or an
/// unparsable port) still leaves nothing of it.
#[test]
fn the_userinfo_cut_reaches_the_last_at() {
    for (url, secret) in [
        ("https://user:ab/cd==@collector.example/v1/traces", "ab/cd"),
        (
            "https://ops:hunter2@collector.example:99999/v1/traces",
            "hunter2",
        ),
    ] {
        assert!(!cut_userinfo(url, "").contains(secret), "{url}");
        assert!(!cut_userinfo(url, "***@").contains(secret), "{url}");
    }
    assert_eq!(
        cut_userinfo(
            "https://ops:hunter2@collector.example:99999/v1/traces",
            "***@"
        ),
        "https://***@collector.example:99999/v1/traces"
    );
    assert_eq!(
        cut_userinfo("https://ops:hunter2@collector.example/v1", ""),
        "https://collector.example/v1"
    );
    assert_eq!(
        cut_userinfo("https://collector.example/v1", "***@"),
        "https://collector.example/v1"
    );
    assert_eq!(cut_userinfo("not a url", "***@"), "not a url");
}

/// export-webhook H3 and hook-webrequest: a host's failure text that quotes the target, or names
/// its parts decoded, keeps none of them.
#[test]
fn a_scrubbed_text_keeps_no_part_of_the_url() {
    let url = "https://ops:hunt%40er@hooks.example/s/SECRET?k=Q%2B1";
    let parts = and_decoded(vec![
        url.to_string(),
        "/s/SECRET".to_string(),
        "k=Q%2B1".to_string(),
        "hunt%40er".to_string(),
        "ops".to_string(),
        String::new(),
    ]);
    assert_eq!(parts.len(), 12, "each part, then each decoded");
    assert_eq!(parts[9], "hunt@er");
    let text = format!("error sending request for url ({url}): hunt@er rejected k=Q+1");
    for quoted in [false, true] {
        assert_eq!(
            scrub(&text, parts.clone(), quoted),
            "error sending request for url (***): *** rejected ***"
        );
    }
}

/// export-webhook `replace_all`: a setting's credential quoted by serde (`{:?}` escapes it) is cut
/// only when the escaped spelling is asked for.
#[test]
fn a_quoted_credential_is_cut_in_its_escaped_spelling_too() {
    let text = r#"settings: unknown value "tok\"en", expected a header"#;
    let secrets = vec![r#"tok"en"#.to_string()];
    assert_eq!(
        scrub(text, secrets.clone(), true),
        r#"settings: unknown value "***", expected a header"#
    );
    assert_eq!(scrub(text, secrets, false), text);
    // The longest is cut first, so a secret holding another is not left half-cut.
    assert_eq!(
        scrub(
            "key abc123 and abc",
            vec!["abc".into(), "abc123".into()],
            false
        ),
        "key *** and ***"
    );
}
