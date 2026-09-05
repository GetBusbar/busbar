// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Where a client credential is carried, and in what order the carriers are read.
//!
//! Three carriers, one fixed precedence. Native vendor SDKs each send the same busbar token under a
//! different header, so the extractor accepts all three and validates identically whichever one
//! carried it. Two details matter and are easy to get wrong:
//!
//! - A present-but-empty header is treated as absent, so a blank header cannot mask a real token in
//!   a lower-precedence carrier.
//! - A non-bearer authorization header (an AWS signature, say) is not a bearer token and falls
//!   THROUGH to the next carrier rather than terminating the search. Signed requests authenticate
//!   on their own path.

use std::fmt;

/// The header the Anthropic SDK carries its key in.
const X_API_KEY: &str = "x-api-key";
/// The header the Gemini SDK carries its key in.
const X_GOOG_API_KEY: &str = "x-goog-api-key";
/// The authorization header name, lower-cased (header names compare case-insensitively).
const AUTHORIZATION: &str = "authorization";
/// The bearer scheme word, matched case-insensitively.
const AUTH_SCHEME_BEARER: &str = "bearer";

/// The request's headers, as this unit needs to read them.
///
/// A trait rather than a concrete map because the unit must not know which transport delivered the
/// request. Names are compared lower-cased; an implementation over a case-insensitive header map
/// satisfies that for free.
pub trait HeaderView {
    /// The value of one header, or `None` when it is absent or not valid text.
    fn header(&self, name: &str) -> Option<&str>;
}

/// The caller's bearer token, carried alongside the unit so a passthrough route can forward it.
///
/// Its `Debug` prints presence and nothing else. A derived one would print the credential the first
/// time anything formatted the structure that holds it, and even the length is a small oracle.
#[derive(Clone, Default)]
pub struct CallerToken(pub Option<String>);

impl fmt::Debug for CallerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CallerToken")
            .field(&if self.0.is_some() {
                "<present>"
            } else {
                "<absent>"
            })
            .finish()
    }
}

/// Pull the token out of an authorization header value, when the scheme is bearer.
///
/// Splits on the first space rather than slicing by byte offset, so a malformed header with a
/// multi-byte character where the scheme belongs cannot land mid-character and panic.
pub fn extract_bearer_token(auth_header: &str) -> Option<String> {
    let (scheme, token) = auth_header.split_once(' ')?;
    if scheme.eq_ignore_ascii_case(AUTH_SCHEME_BEARER) && !token.is_empty() {
        Some(token.to_string())
    } else {
        None
    }
}

/// Read the client credential from whichever carrier presented it, in the fixed order: the bearer
/// authorization header, then the Anthropic key header, then the Google key header.
pub fn extract_client_token(headers: &dyn HeaderView) -> Option<String> {
    if let Some(t) = headers
        .header(AUTHORIZATION)
        .and_then(extract_bearer_token)
    {
        return Some(t);
    }
    if let Some(t) = headers.header(X_API_KEY).filter(|t| !t.is_empty()) {
        return Some(t.to_string());
    }
    if let Some(t) = headers.header(X_GOOG_API_KEY).filter(|t| !t.is_empty()) {
        return Some(t.to_string());
    }
    None
}
