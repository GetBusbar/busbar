// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The browser exchange's dispatch and its exact-match bypass.

use crate::exchange::{dispatch, is_bypassed, BrowserAction, AUTH_TOKEN_PATH};

fn q(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

#[test]
fn the_bypass_is_an_exact_match_and_nothing_wider() {
    assert!(is_bypassed(AUTH_TOKEN_PATH));
    assert!(!is_bypassed("/auth/token/"));
    assert!(!is_bypassed("/auth/token/steal"));
    assert!(!is_bypassed("/auth/tokens"));
    assert!(!is_bypassed("/auth"));
}

#[test]
fn logout_is_decided_first() {
    // Even with a code and a method also present, sign-out wins.
    let action = dispatch(&q(&[("code", "abc"), ("method", "entra"), ("logout", "1")]));
    assert_eq!(action, BrowserAction::SignedOut);
    // Any value at all, not just "1".
    assert_eq!(dispatch(&q(&[("logout", "")])), BrowserAction::SignedOut);
}

#[test]
fn a_code_is_the_callback() {
    assert_eq!(
        dispatch(&q(&[("code", "abc"), ("state", "s1")])),
        BrowserAction::Callback {
            code: "abc".to_string(),
            state: Some("s1".to_string()),
        }
    );
    assert_eq!(
        dispatch(&q(&[("code", "abc")])),
        BrowserAction::Callback {
            code: "abc".to_string(),
            state: None,
        }
    );
}

#[test]
fn a_named_method_begins_and_the_refresh_flag_is_exactly_one() {
    assert_eq!(
        dispatch(&q(&[("method", "entra")])),
        BrowserAction::Begin {
            method: "entra".to_string(),
            refresh: false,
        }
    );
    assert_eq!(
        dispatch(&q(&[("method", "entra"), ("refresh", "1")])),
        BrowserAction::Begin {
            method: "entra".to_string(),
            refresh: true,
        }
    );
    assert_eq!(
        dispatch(&q(&[("method", "entra"), ("refresh", "true")])),
        BrowserAction::Begin {
            method: "entra".to_string(),
            refresh: false,
        },
        "only the literal 1 rotates"
    );
}

#[test]
fn no_method_renders_the_chooser() {
    assert_eq!(dispatch(&[]), BrowserAction::Chooser);
    assert_eq!(dispatch(&q(&[("state", "s")])), BrowserAction::Chooser);
}
