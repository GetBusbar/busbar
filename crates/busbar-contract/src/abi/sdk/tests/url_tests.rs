// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The URL credential pieces, over the vectors the export and hook sinks pin them with

use super::*;

#[test]
fn a_percent_escape_decodes_only_with_two_hex_digits() {
    assert_eq!(percent_decode(b"a%20b%zz%4"), b"a b%zz%4");
    assert_eq!(percent_decode(b"ab%+41cd"), b"ab%+41cd");
    assert_eq!(percent_decode(b"%41%6a%6A%"), b"Ajj%");
    assert_eq!(percent_decode(b"p%FFw"), b"p\xFFw");
    assert_eq!(percent_decode(b""), b"");
}

/// export-otlp's userinfo (RFC 7617 octets): both halves, the password alone, the user alone,
#[test]
fn a_userinfo_read_as_octets_is_sent_as_it_decodes() {
    for (username, password, sent) in [
        ("alice", Some("s3cr3t"), Some("Basic YWxpY2U6czNjcjN0")),
        ("", Some("topsecret"), Some("Basic OnRvcHNlY3JldA==")),
        ("tokenuser", None, Some("Basic dG9rZW51c2VyOg==")),
        ("u", Some("p%40ss%3Aword"), Some("Basic dTpwQHNzOndvcmQ=")),
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
        ("jos%C3%A9", Some("pw"), Some("Basic am9zw6k6cHc=")),
        ("a%zz", Some("b"), Some("Basic YSV6ejpi")),
        ("u", Some("%FF"), Some("Basic dTo=")),
        ("%FF", Some("pw"), None),
        ("", None, None),
        ("u", Some("p"), Some("Basic dTpw")),
    ] {
        assert_eq!(
            basic_authorization(username, password, Userinfo::Utf8).as_deref(),
            sent,
            "{username:?} {password:?}"
        );
    }
}

#[test]
fn a_basic_username_cannot_change_the_user_password_boundary() {
    for read in [Userinfo::Octets, Userinfo::Utf8] {
        for username in ["alice:admin", "alice%3aadmin", "alice%3Aadmin", "%3A", ":"] {
            for password in [None, Some("password-canary"), Some("")] {
                assert!(
                    basic_authorization(username, password, read).is_none(),
                    "a colon in {username:?} must not become a different Basic username"
                );
            }
        }
    }
}

#[test]
fn valid_basic_credentials_keep_their_decoded_wire_octets() {
    for (username, password, read, expected) in [
        (
            "alice%253Aadmin",
            Some("p%3Ass"),
            Userinfo::Octets,
            b"alice%3Aadmin:p:ss".as_slice(),
        ),
        (
            "%FFuser",
            Some("p%FF"),
            Userinfo::Octets,
            b"\xFFuser:p\xFF".as_slice(),
        ),
        (
            "jos%C3%A9",
            Some("p%3Ass"),
            Userinfo::Utf8,
            "josé:p:ss".as_bytes(),
        ),
        ("user", Some("%FF"), Userinfo::Utf8, b"user:".as_slice()),
        ("", Some("p%3Ass"), Userinfo::Utf8, b":p:ss".as_slice()),
        ("user", None, Userinfo::Octets, b"user:".as_slice()),
    ] {
        let field = basic_authorization(username, password, read).expect("valid userinfo");
        let encoded = field.strip_prefix("Basic ").expect("Basic scheme");
        assert_eq!(STANDARD.decode(encoded).expect("standard base64"), expected);
    }
    assert_eq!(basic_authorization("%FF", Some("pw"), Userinfo::Utf8), None);
}

#[test]
fn userinfo_redaction_does_not_depend_on_an_authority_separator() {
    for prefix in [
        "https:",
        "https:/",
        "https://",
        "https:///",
        "http:",
        "ws:/",
        "wss:",
        "ftp:/",
        "file:",
        "https:\\",
        "https:\\\\",
        "https:/\\",
        "https:\\/",
        "\0 \tht\ntp\rs:",
        "\r\nhttps:/",
        "https:\t/\n/",
        "//",
        "",
        "not a URL ",
    ] {
        let url = format!("{prefix}user-canary:password-canary@collector.example/in");
        for replacement in ["", "***@"] {
            let redacted = cut_userinfo(&url, replacement);
            assert!(!redacted.contains("user-canary"), "{url:?}: {redacted:?}");
            assert!(
                !redacted.contains("password-canary"),
                "{url:?}: {redacted:?}"
            );
            assert!(redacted.ends_with("collector.example/in"), "{redacted:?}");
            assert_eq!(
                redacted.matches('@').count(),
                usize::from(!replacement.is_empty())
            );
        }
    }
}

#[test]
fn malformed_and_ambiguous_credentials_are_cut_through_the_last_at() {
    for url in [
        "https:user-canary/password-canary@collector.example/in",
        "https:/user-canary?password-canary@collector.example/in",
        "https:\\user-canary#password-canary@collector.example/in",
        "https://user-canary:first@password-canary@collector.example/in",
        "user-canary:password-canary://bad@collector.example/in",
        "https://user-canary:password-canary@bad://collector.example/in",
    ] {
        let redacted = cut_userinfo(url, "***@");
        let refusal = ambiguous_url(url, "/password-canary@collector.example/in")
            .expect("an at sign after the parsed host is ambiguous");
        for text in [&redacted, &refusal] {
            assert!(!text.contains("user-canary"), "{text}");
            assert!(!text.contains("password-canary"), "{text}");
            assert!(text.contains("collector.example/in"), "{text}");
        }
    }

    for url in [
        "https:collector.example/%40in",
        "https:\\collector.example/in",
    ] {
        assert_eq!(cut_userinfo(url, "***@"), url);
    }
}

/// export-otlp and export-webhook (owner ruling 2026-10-24): a url whose `@` comes after its host
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
#[test]
fn a_quoted_credential_is_cut_in_its_escaped_spelling_too() {
    let text = r#"settings: unknown value "tok\"en", expected a header"#;
    let secrets = vec![r#"tok"en"#.to_string()];
    assert_eq!(
        scrub(text, secrets.clone(), true),
        r#"settings: unknown value "***", expected a header"#
    );
    assert_eq!(scrub(text, secrets, false), text);

    assert_eq!(
        scrub(
            "key abc123 and abc",
            vec!["abc".into(), "abc123".into()],
            false
        ),
        "key *** and ***"
    );
}

pub(super) fn watch_scratch(bytes: &[u8]) {
    // SAFETY: URL instrumentation registers owned allocation bases; each active probe below keeps
    // all those buffers on this thread until they are freed or observation ends.
    unsafe { crate::alloc_counter::watch_initialized_payload(bytes) }
}

fn scratch_probe() -> crate::alloc_counter::InitializedPayloadProbe {
    // SAFETY: these synchronous tests neither move observed allocations across threads nor retype
    // their payloads. Returned public values are wiped and dropped before ending observation.
    unsafe { crate::alloc_counter::InitializedPayloadProbe::start().expect("open memory observer") }
}

fn assert_scratch_wiped(probe: crate::alloc_counter::InitializedPayloadProbe, minimum: usize) {
    let observations = probe.finish();
    assert!(!observations.reentered, "OS read reentered allocator");
    assert!(
        observations.payloads.len() >= minimum,
        "scratch was not observed"
    );
    for record in observations.payloads {
        assert!(
            record.freed,
            "scratch owner did not free its buffer: {record:?}"
        );
        #[cfg(target_os = "linux")]
        {
            assert_eq!(record.read_error, None, "memory observation failed");
            assert!(record.complete_read, "incomplete observation: {record:?}");
            assert_eq!(record.bytes_read, record.len);
            assert!(record.wiped, "URL scratch reached free unwiped: {record:?}");
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(record.read_error, Some(std::io::ErrorKind::Unsupported));
            assert!(!record.complete_read);
        }
    }
}

#[test]
fn basic_scratch_is_wiped_on_success_and_each_refusal() {
    use zeroize::Zeroize;
    for (username, password, read, expected, minimum) in [
        (
            "operator",
            Some("password-canary"),
            Userinfo::Octets,
            Some("Basic b3BlcmF0b3I6cGFzc3dvcmQtY2FuYXJ5"),
            3,
        ),
        (
            "operator",
            Some("%FF"),
            Userinfo::Utf8,
            Some("Basic b3BlcmF0b3I6"),
            3,
        ),
        ("%FFuser", Some("password-canary"), Userinfo::Utf8, None, 2),
        (
            "operator%3Aadmin",
            Some("password-canary"),
            Userinfo::Octets,
            None,
            1,
        ),
    ] {
        let probe = scratch_probe();
        let mut result = basic_authorization(username, password, read);
        assert_eq!(result.as_deref(), expected);
        result.zeroize();
        drop(result);
        assert_scratch_wiped(probe, minimum);
    }
}

#[test]
fn decoded_and_quoted_redaction_scratch_is_wiped_without_changing_words() {
    use zeroize::Zeroize;
    let probe = scratch_probe();
    let mut decoded = and_decoded(vec!["a%20b%FF".to_owned()]);
    assert_eq!(decoded, ["a%20b%FF", "a b\u{fffd}"]);
    decoded.zeroize();
    drop(decoded);
    assert_scratch_wiped(probe, 1);

    let probe = scratch_probe();
    let mut output = scrub(
        "first secret and a\"b and secret",
        vec![
            "secret".to_owned(),
            "a\"b".to_owned(),
            "secret".to_owned(),
            String::new(),
        ],
        true,
    );
    assert_eq!(output, "first *** and *** and ***");
    output.zeroize();
    drop(output);
    assert_scratch_wiped(probe, 7);
}

#[test]
fn url_scratch_observer_detects_unwiped_and_live_buffers() {
    let probe = scratch_probe();
    let unwiped = b"unwiped-url-canary".to_vec();
    watch_scratch(&unwiped);
    drop(unwiped);
    let live = b"still-owned-url-canary".to_vec();
    watch_scratch(&live);
    let observations = probe.finish();
    assert!(!observations.reentered);
    assert_eq!(observations.payloads.len(), 2);
    assert!(observations.payloads[0].freed);
    assert!(
        !observations.payloads[1].freed,
        "a live owner is not a wipe receipt"
    );
    #[cfg(target_os = "linux")]
    {
        let record = &observations.payloads[0];
        assert_eq!(record.read_error, None);
        assert!(record.complete_read);
        assert_eq!(record.bytes_read, record.len);
        assert!(
            !record.wiped,
            "negative control must detect unchanged bytes"
        );
    }
    drop(live);
}
