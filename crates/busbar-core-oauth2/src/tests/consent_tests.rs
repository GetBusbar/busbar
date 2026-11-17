// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::time::Instant;

use super::Sessions;

#[test]
fn a_lapsed_session_takes_its_staked_answers_with_it() {
    let sessions = Sessions::default();
    sessions.open("busbar-operator", "session-1".to_string());
    sessions.stake("session-1", "key-1".to_string(), true);
    {
        let mut inner = sessions.inner.lock().unwrap_or_else(|p| p.into_inner());
        let lapsed = Instant::now();
        inner
            .live
            .get_mut("session-1")
            .expect("the session is open")
            .1 = lapsed;
    }
    sessions.open("busbar-operator", "session-2".to_string());
    let inner = sessions.inner.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        !inner.live.contains_key("session-1"),
        "the lapsed session is kept"
    );
    assert!(
        !inner.staked.contains_key("session-1"),
        "the lapsed session's answers are kept"
    );
}

#[test]
fn a_second_answer_replaces_the_first_and_is_spent_once() {
    let sessions = Sessions::default();
    sessions.open("busbar-operator", "session-1".to_string());
    sessions.stake("session-1", "key-1".to_string(), true);
    sessions.stake("session-1", "key-1".to_string(), false);
    assert_eq!(
        sessions.spend("session-1", "key-1"),
        Some(false),
        "the operator's last answer is the one spent"
    );
    assert_eq!(
        sessions.spend("session-1", "key-1"),
        None,
        "a replaced answer was spent as well"
    );

    sessions.stake("session-1", "key-1".to_string(), true);
    assert_eq!(sessions.spend("session-1", "key-1"), Some(true));
    assert_eq!(sessions.spend("session-1", "key-1"), None);
}

#[test]
fn the_subject_is_the_starting_browsers_session_and_nothing_else() {
    let sessions = std::sync::Arc::new(Sessions::default());
    sessions.open("cookie-operator", "browser-session".to_string());
    let resolve = super::subject_resolver(sessions);
    let headers = axum::http::HeaderMap::new();
    assert_eq!(
        resolve(&headers),
        Some(super::PENDING.to_string()),
        "outside an authorization request no browser is resolved, so nobody is logged in"
    );
    let browser = super::Browser {
        session: "browser-session".to_string(),
        handle: None,
    };
    let resolved = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime")
        .block_on(super::as_browser(browser, async { resolve(&headers) }));
    assert_eq!(resolved, Some("cookie-operator".to_string()));
}

#[test]
fn consent_cookie_fields_preserve_first_match_and_malformed_refusal() {
    for (fields, expected) in [
        (
            vec!["busbar_as_start=first", "busbar_as_start=second"],
            Some("first"),
        ),
        (
            vec![
                "unrelated=x",
                "busbar_as_start=first; busbar_as_start=second",
            ],
            Some("first"),
        ),
        (vec!["busbar_as_start=", "busbar_as_start=second"], Some("")),
        (
            vec!["bad-pair; unrelated=x", " busbar_as_start = value "],
            Some("value"),
        ),
        (vec!["other_busbar_as_start=wrong", "unrelated=x"], None),
    ] {
        let mut headers = axum::http::HeaderMap::new();
        for field in fields {
            headers.append("cookie", field.parse().unwrap());
        }
        assert_eq!(
            super::cookie(&headers, super::START_COOKIE).as_deref(),
            expected
        );
    }
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        "cookie",
        axum::http::HeaderValue::from_bytes(b"unreadable=\x80").unwrap(),
    );
    headers.append("cookie", "busbar_as_start=later".parse().unwrap());
    assert_eq!(super::cookie(&headers, super::START_COOKIE), None);
}

#[test]
fn only_a_minted_start_cookie_names_a_browser() {
    let minted = super::new_handle().expect("entropy");
    assert!(super::is_handle(&minted));
    for (value, named) in [
        (minted.as_str(), true),
        ("", false),
        ("short", false),
        (&"A".repeat(64), false),
        (&"g".repeat(64), false),
        (&"a".repeat(65), false),
    ] {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            format!("busbar_as_start={value}").parse().unwrap(),
        );
        assert_eq!(super::start_of(&headers).is_some(), named, "{value:?}");
    }
    assert_eq!(super::session_of(&minted).len(), 64);
    assert_ne!(
        super::session_of(&minted),
        minted,
        "ref is a digest of S, never S"
    );
}

#[test]
fn the_consent_handle_is_split_off_verbatim_and_only_when_trailing() {
    let t = "0123456789abcdef".repeat(4);
    let target = "/authorize?client_id=c&scope=read%20write&state=s+1";
    let back = format!("{target}&busbar_consent={t}");
    assert_eq!(super::split_handle(&back), Some((target, t.as_str())));
    let bare = format!("/authorize?busbar_consent={t}");
    assert_eq!(super::split_handle(&bare), Some(("/authorize", t.as_str())));
    for refused in [
        target.to_string(),
        format!("{target}&busbar_consent={}", &t[..63]),
        format!("{target}&busbar_consent={}", t.to_uppercase()),
        format!("{target}&xbusbar_consent={t}"),
        format!("{target}busbar_consent={t}"),
        format!("{target}&busbar_consent={t}&state=late"),
    ] {
        assert_eq!(super::split_handle(&refused), None, "{refused}");
    }
}

#[test]
fn a_stake_is_spent_only_with_the_handle_it_was_answered_with() {
    let sessions = Sessions::default();
    sessions.open("busbar-operator", "session-1".to_string());
    let key = super::request_key("client", "/authorize?client_id=client");
    sessions.stake("session-1", super::handled_key(&key, "t-1"), true);
    assert_eq!(sessions.spend("session-1", &key), None);
    assert_eq!(
        sessions.spend("session-1", &super::handled_key(&key, "t-2")),
        None
    );
    assert_eq!(
        sessions.spend("session-1", &super::handled_key(&key, "t-1")),
        Some(true)
    );
    assert_eq!(
        sessions.spend("session-1", &super::handled_key(&key, "t-1")),
        None
    );
}

/// DEPENDENCY-LADDER C6 (percent-encoding) pins the consent link encoder before the hand loop
/// goes: RFC 3986 unreserved bytes stay, everything else is upper-case `%XX`.
#[test]
fn the_consent_encoder_escapes_all_but_the_unreserved_bytes() {
    assert_eq!(
        super::percent_encode("a b/c?d=e&f%g+h~i-j.k_l\u{e9}"),
        "a%20b%2Fc%3Fd%3De%26f%25g%2Bh~i-j.k_l%C3%A9"
    );
    assert_eq!(super::percent_encode(""), "");
}
