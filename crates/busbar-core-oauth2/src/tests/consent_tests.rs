// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE IN-PROCESS CONSENT TABLE: what it keeps of a session once the session has lapsed, and how it
//! spends a second answer to one request.

use std::time::Instant;

use super::Sessions;

/// RED (row 159): a lapsed session's staked answers go with it. Before the fix only the eviction at
/// the session bound dropped them, so every lapsed session that had an answer staked or planted
/// left it in the table for the life of the process.
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

/// RED (row 159): a second answer to one request on one session replaces the first, and is spent
/// once, as the deployment's store spends it. Before the fix this table queued both, spending the
/// FIRST answer before the operator's second one, and a store-backed server spent neither the same
/// way.
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
    // A new answer after the spend is its own, spent once.
    sessions.stake("session-1", "key-1".to_string(), true);
    assert_eq!(sessions.spend("session-1", "key-1"), Some(true));
    assert_eq!(sessions.spend("session-1", "key-1"), None);
}
