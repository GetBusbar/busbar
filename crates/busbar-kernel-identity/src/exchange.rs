// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The browser token exchange: the one path the chain does not guard.
//!
//! A developer with no credential has to be able to GET one, and the page that issues it cannot
//! itself require the credential it issues. So this exact path — not a prefix, an exact match — is
//! bypassed by the chain, and its own dispatch decides what happens next from the query alone.
//!
//! The exact-match part is the security-relevant part. A prefix bypass would open every sibling
//! path underneath it; an exact match opens one page.

/// The one bypassed path.
pub const AUTH_TOKEN_PATH: &str = "/auth/token";

/// What the exchange does for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserAction {
    /// Sign out: end the browser view and clear the login cookie. Stateless.
    SignedOut,
    /// The identity provider returned the browser with an authorization code.
    Callback {
        /// The code the provider returned.
        code: String,
        /// The state value it echoed back, when present.
        state: Option<String>,
    },
    /// Begin a login with one named method. A rotate re-mints and retires the prior key.
    Begin {
        /// The login method named in the query.
        method: String,
        /// Whether this is a rotate rather than a first issue.
        refresh: bool,
    },
    /// No method named: render the chooser, one button per method that has a login block.
    Chooser,
}

/// Decide what the exchange does, from the query pairs alone.
///
/// The order is fixed and each step is a reason:
///
/// 1. Sign-out FIRST, so the action that ends a session cannot be shadowed by a stale code or
///    method left in the same query string.
/// 2. Then the callback, because a provider always returns a code, and a code present means the
///    browser is mid-flow whatever else the query says.
/// 3. Then a named method — a rotate when the refresh flag is exactly the string "1", which is what
///    the issued page's own rotate link sends.
/// 4. Otherwise the chooser.
pub fn dispatch(query: &[(String, String)]) -> BrowserAction {
    let get = |k: &str| query.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());

    if get("logout").is_some() {
        return BrowserAction::SignedOut;
    }
    if let Some(code) = get("code") {
        return BrowserAction::Callback {
            code,
            state: get("state"),
        };
    }
    match get("method") {
        Some(method) => BrowserAction::Begin {
            method,
            refresh: get("refresh").as_deref() == Some("1"),
        },
        None => BrowserAction::Chooser,
    }
}

/// Whether the chain bypasses this path. An exact match and nothing wider.
pub fn is_bypassed(path: &str) -> bool {
    path == AUTH_TOKEN_PATH
}
