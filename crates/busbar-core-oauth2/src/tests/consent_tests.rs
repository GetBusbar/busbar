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
fn a_session_in_a_later_cookie_field_resolves_the_same_subject() {
    let sessions = std::sync::Arc::new(Sessions::default());
    sessions.open("cookie-operator", "split-session".to_string());
    let resolve = super::subject_resolver(sessions);
    let mut split = axum::http::HeaderMap::new();
    split.append("cookie", "unrelated=first".parse().unwrap());
    split.append(
        "cookie",
        "busbar_as_session=split-session; other=last"
            .parse()
            .unwrap(),
    );
    let mut joined = axum::http::HeaderMap::new();
    joined.insert(
        "cookie",
        "unrelated=first; busbar_as_session=split-session; other=last"
            .parse()
            .unwrap(),
    );
    assert_eq!(super::session_id(&split), super::session_id(&joined));
    assert_eq!(resolve(&split), Some("cookie-operator".to_string()));
}

#[test]
fn consent_cookie_fields_preserve_first_match_and_malformed_refusal() {
    for (fields, expected) in [
        (
            vec!["busbar_as_session=first", "busbar_as_session=second"],
            Some("first"),
        ),
        (
            vec![
                "unrelated=x",
                "busbar_as_session=first; busbar_as_session=second",
            ],
            Some("first"),
        ),
        (
            vec!["busbar_as_session=", "busbar_as_session=second"],
            Some(""),
        ),
        (
            vec!["bad-pair; unrelated=x", " busbar_as_session = value "],
            Some("value"),
        ),
        (vec!["other_busbar_as_session=wrong", "unrelated=x"], None),
    ] {
        let mut headers = axum::http::HeaderMap::new();
        for field in fields {
            headers.append("cookie", field.parse().unwrap());
        }
        assert_eq!(super::session_id(&headers).as_deref(), expected);
    }
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        "cookie",
        axum::http::HeaderValue::from_bytes(b"unreadable=\x80").unwrap(),
    );
    headers.append("cookie", "busbar_as_session=later".parse().unwrap());
    assert_eq!(super::session_id(&headers), None);
}
