// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The RFC 6750 `WWW-Authenticate` challenge, for ingresses that are OAuth 2.1 RESOURCE SERVERS.
//!
//! ## Why this is not `unauthorized_response`
//!
//! The data plane's 401 shaper (`super::unauthorized_response`) deliberately impersonates the vendor
//! whose dialect the caller spoke: an OpenAI SDK gets OpenAI's copy, a Bedrock SDK gets
//! `AccessDeniedException`. That is right for a gateway pretending to be six vendors, and it is
//! exactly wrong here. An audience-bound plane's caller is not an LLM SDK; it is an OAuth client
//! that has been TOLD, by RFC 6750 and RFC 9728, that a `401` carries a machine-readable challenge
//! naming where to go and get a token. Hand it a vendor-shaped JSON body with no
//! `WWW-Authenticate` header and the discovery loop simply does not close: the client has no way to
//! find the authorization server, because the only place that URL was ever going to come from is the
//! header we did not send.
//!
//! This is the whole of the MCP bootstrap story, and it is the reason an agent can log into busbar
//! with no prior configuration: connect with no credential, read `resource_metadata` out of the
//! challenge, fetch the protected-resource metadata document, discover the operator's authorization
//! server, do ordinary OAuth, come back with a token.
//!
//! ## Why the parameters are built rather than formatted inline
//!
//! `WWW-Authenticate` is `#auth-param` — comma-separated `key="value"` pairs with quoted-string
//! values. A quote or a backslash inside a value would terminate or escape out of the string and let
//! an operator-configured URL rewrite the rest of the header, which is header injection with extra
//! steps. Values here are operator config rather than caller input, so this is defence in depth
//! rather than the last line, but the cost of doing it correctly once is a single function.

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// The `error` code of a challenge, per RFC 6750 §3.1. The set is closed on purpose: these three are
/// the only codes that RFC defines for a bearer-token resource server, and inventing a fourth would
/// produce a challenge no compliant client knows how to act on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChallengeError {
    /// No credential was presented at all. RFC 6750 §3.1 is explicit that this case omits `error`
    /// entirely — the bare challenge means "authenticate", where `error="invalid_token"` would mean
    /// "you tried and the token was bad". Clients branch on the difference, so we do too.
    Absent,
    /// A credential was presented and did not verify: expired, wrong signature, unknown key, or —
    /// the case this plane exists for — minted for a different audience. The RFC 8707 rejection
    /// lands here.
    InvalidToken,
    /// The token verified and its grant does not cover what was asked. Carried on a `403`, never a
    /// `401`: re-authenticating cannot help, so telling the client to try again would send it round
    /// a loop it cannot exit.
    InsufficientScope,
}

impl ChallengeError {
    /// The RFC 6750 `error` code, or `None` for the bare challenge.
    fn code(self) -> Option<&'static str> {
        match self {
            ChallengeError::Absent => None,
            ChallengeError::InvalidToken => Some("invalid_token"),
            ChallengeError::InsufficientScope => Some("insufficient_scope"),
        }
    }

    /// The status this error is carried on. `insufficient_scope` is a `403` per RFC 6750 §3.1; the
    /// other two are `401`.
    fn status(self) -> StatusCode {
        match self {
            ChallengeError::Absent | ChallengeError::InvalidToken => StatusCode::UNAUTHORIZED,
            ChallengeError::InsufficientScope => StatusCode::FORBIDDEN,
        }
    }
}

/// Build the `WWW-Authenticate` header value for a bearer challenge.
///
/// `resource_metadata` is the RFC 9728 §5.1 parameter: the absolute URL of this resource's
/// protected-resource metadata. It is present on EVERY challenge, including `insufficient_scope`,
/// because a client that guessed the wrong scope needs the same document to learn the right one.
///
/// `description` is optional and advisory. It never carries the reason a token failed in any detail
/// a caller could use to probe — "the audience does not match" is safe (the caller knows its own
/// token's audience), "no key with id 7fa3" is not.
pub fn www_authenticate(
    error: ChallengeError,
    resource_metadata: &str,
    description: Option<&str>,
    scope: Option<&str>,
) -> String {
    let mut params: Vec<String> = Vec::with_capacity(4);
    params.push(format!(
        "resource_metadata=\"{}\"",
        quoted(resource_metadata)
    ));
    if let Some(code) = error.code() {
        params.push(format!("error=\"{code}\""));
    }
    if let Some(d) = description {
        params.push(format!("error_description=\"{}\"", quoted(d)));
    }
    // RFC 6750 §3.1: `scope` names what WOULD have been sufficient. Only meaningful alongside
    // `insufficient_scope` — on a bare or invalid-token challenge it would be advice about a request
    // the caller has not yet been allowed to make.
    if let Some(s) = scope.filter(|_| error == ChallengeError::InsufficientScope) {
        params.push(format!("scope=\"{}\"", quoted(s)));
    }
    format!("Bearer {}", params.join(", "))
}

/// Escape a value for an RFC 7230 `quoted-string`: backslash and double-quote are the only two
/// characters that can escape the string, and both are escaped rather than stripped so the value a
/// client reads back is the value the operator configured.
///
/// Control characters are DROPPED rather than escaped: `quoted-string` has no escape form for CR or
/// LF, and passing either through would split the header. Dropping is the only option that neither
/// injects nor silently succeeds at emitting an invalid header.
fn quoted(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {}
            c => out.push(c),
        }
    }
    out
}

/// The full refusal: the right status, the `WWW-Authenticate` challenge, and a small JSON body.
///
/// The body is OAuth-shaped (`{"error": …, "error_description": …}`), NOT vendor-shaped, for the
/// reason in the module header — and it is small on purpose. Every fact in it is already in the
/// header; the body exists so a human reading a `curl` sees something, not so a client parses it.
pub fn refuse(
    error: ChallengeError,
    resource_metadata: &str,
    description: &str,
    scope: Option<&str>,
) -> Response {
    let challenge = www_authenticate(error, resource_metadata, Some(description), scope);
    let body = serde_json::json!({
        "error": error.code().unwrap_or("unauthorized"),
        "error_description": description,
    });
    let mut resp = (error.status(), axum::Json(body)).into_response();
    // A header value that will not build is a programming error in the value we constructed, not a
    // caller-triggerable condition — `quoted` has already removed everything that could make one
    // invalid. Fall back to the bare scheme rather than panicking on a request path: a 401 with a
    // useless challenge is recoverable for the caller, a panic is not.
    let hv =
        HeaderValue::from_str(&challenge).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
    resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    resp
}
