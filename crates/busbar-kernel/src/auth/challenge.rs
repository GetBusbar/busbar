// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    fn code(self) -> Option<&'static str> {
        match self {
            ChallengeError::Absent => None,
            ChallengeError::InvalidToken => Some("invalid_token"),
            ChallengeError::InsufficientScope => Some("insufficient_scope"),
        }
    }

    fn status(self) -> StatusCode {
        match self {
            ChallengeError::Absent | ChallengeError::InvalidToken => StatusCode::UNAUTHORIZED,
            ChallengeError::InsufficientScope => StatusCode::FORBIDDEN,
        }
    }
}

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
    if let Some(d) = description.filter(|_| error != ChallengeError::Absent) {
        params.push(format!("error_description=\"{}\"", quoted(d)));
    }

    if let Some(s) = scope.filter(|_| error == ChallengeError::InsufficientScope) {
        params.push(format!("scope=\"{}\"", quoted(s)));
    }
    format!("Bearer {}", params.join(", "))
}

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

pub fn refuse(
    error: ChallengeError,
    resource_metadata: &str,
    description: &str,
    scope: Option<&str>,
) -> Response {
    let challenge = www_authenticate(error, resource_metadata, Some(description), scope);
    let mut body = serde_json::json!({
        "error": error.code().unwrap_or("unauthorized"),
    });
    if error != ChallengeError::Absent {
        body["error_description"] = serde_json::json!(description);
    }
    let mut resp = (error.status(), axum::Json(body)).into_response();

    let hv =
        HeaderValue::from_str(&challenge).unwrap_or_else(|_| HeaderValue::from_static("Bearer"));
    resp.headers_mut().insert(header::WWW_AUTHENTICATE, hv);
    resp
}
