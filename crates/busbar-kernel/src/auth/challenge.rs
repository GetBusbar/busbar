// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use axum::http::{HeaderValue, StatusCode};
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

pub(crate) fn www_authenticate(
    error: ChallengeError,
    resource_metadata: &str,
    description: Option<&str>,
    scope: Option<&str>,
) -> String {
    let description = description.filter(|_| error != ChallengeError::Absent);
    let scope = scope.filter(|_| error == ChallengeError::InsufficientScope);
    // The challenge head of a refused request: cold text, written out of line.
    crate::cold::auth::keys::www_authenticate(error.code(), resource_metadata, description, scope)
}

/// A quoted-string's content: `"` and `\` escaped, control characters dropped.
pub(crate) struct Quoted<'a>(pub(crate) &'a str);

impl std::fmt::Display for Quoted<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        for c in self.0.chars() {
            match c {
                '"' | '\\' => {
                    f.write_char('\\')?;
                    f.write_char(c)?;
                }
                c if (c as u32) < 0x20 || c as u32 == 0x7f => {}
                c => f.write_char(c)?,
            }
        }
        Ok(())
    }
}

/// The JSON body of a challenge: `{"error":..}` and, unless the credential was absent, its
/// `error_description`.
#[derive(serde::Serialize)]
struct ChallengeBody<'a> {
    error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<&'a str>,
}

pub fn render(
    error: ChallengeError,
    resource_metadata: &str,
    description: &str,
    scope: Option<&str>,
) -> crate::plane_driver::Rendered {
    let challenge = www_authenticate(error, resource_metadata, Some(description), scope);
    let body = ChallengeBody {
        error: error.code().unwrap_or("unauthorized"),
        error_description: (error != ChallengeError::Absent).then_some(description),
    };
    let fields = crate::cold::auth::keys::challenge_fields(challenge);
    let mut rendered = crate::plane_driver::Rendered {
        status: u32::from(error.status().as_u16()),
        fields,
        body: Vec::with_capacity(128),
    };
    busbar_contract::json::to_writer(&mut rendered.body, &body).expect("the challenge is a JSON value");
    rendered
}

pub fn refuse(
    error: ChallengeError,
    resource_metadata: &str,
    description: &str,
    scope: Option<&str>,
) -> Response {
    let rendered = render(error, resource_metadata, description, scope);
    let mut response = (error.status(), rendered.body).into_response();
    for (name, value) in rendered.fields {
        if let (Ok(name), Ok(value)) = (
            axum::http::HeaderName::from_bytes(&name),
            HeaderValue::from_bytes(&value),
        ) {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
