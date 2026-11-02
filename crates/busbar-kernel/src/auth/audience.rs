// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use base64::Engine as _;

/// What could be established about a presented bearer's RFC 8707 audience binding — the outcome of
/// the audience pre-filter (`crate::auth::audience::inspect_bearer`), for credentials busbar did
/// not mint. The JUDGEMENT ([`inspect_bearer`]) stays here beside it, since it reaches core's
/// governance token prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Binding {
    /// A busbar-signed token. The real audience check happens in the verifier, which has the
    /// signature and the claims; the pre-filter must not pre-judge it.
    Deferred,
    /// A JWT whose `aud` includes the expected value. Not an admission — the chain still verifies it.
    Bound,
    /// A JWT whose `aud` does not include the expected value, or which carries no `aud` at all. Both
    /// are refused for the same reason: minted for someone else, or for nobody in particular.
    Mismatch,
    /// Not a JWT and not a busbar token: nothing to read. Refused.
    Opaque,
}

pub fn inspect_bearer(token: &str, expected_aud: &str) -> Binding {
    Bearer::read(token).binding(expected_aud)
}

/// What the kernel reads of a bearer, its JWT payload decoded ONCE per request: the audience
/// pre-filter ([`Bearer::binding`]) and the DPoP binding check (`auth::dpop`) both read it.
#[derive(Debug)]
pub enum Bearer {
    /// A busbar-signed token: never parsed here.
    Busbar,
    /// Not a three-segment JWS with a JSON payload: nothing to read.
    Opaque,
    /// A JWT's payload.
    Jwt(serde_json::Value),
}

impl Bearer {
    #[must_use]
    pub fn read(token: &str) -> Bearer {
        if token.starts_with(crate::governance::signing::TOKEN_PREFIX) {
            return Bearer::Busbar;
        }

        let mut parts = token.split('.');
        let (Some(_header), Some(payload), Some(_sig), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Bearer::Opaque;
        };
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .map_or(Bearer::Opaque, Bearer::Jwt)
    }

    #[must_use]
    pub fn binding(&self, expected_aud: &str) -> Binding {
        let claims = match self {
            Bearer::Busbar => return Binding::Deferred,
            Bearer::Opaque => return Binding::Opaque,
            Bearer::Jwt(claims) => claims,
        };
        match claims.get("aud") {
            Some(serde_json::Value::String(s)) if s == expected_aud => Binding::Bound,
            Some(serde_json::Value::Array(vs)) => {
                if vs.iter().any(|v| v.as_str() == Some(expected_aud)) {
                    Binding::Bound
                } else {
                    Binding::Mismatch
                }
            }

            _ => Binding::Mismatch,
        }
    }

    #[must_use]
    pub fn dpop_bound(&self) -> bool {
        matches!(self, Bearer::Jwt(claims) if claims["cnf"]["jkt"].is_string())
    }
}

pub(crate) const MISMATCH_DESCRIPTION: &str =
    "The access token's audience does not identify this resource. Request a token whose \
     `resource` (RFC 8707) is this server's canonical URI.";

pub(crate) const OPAQUE_DESCRIPTION: &str =
    "This credential carries no readable audience, so it cannot be shown to have been issued \
     for this resource. A JWT access token is required here.";

#[cfg(test)]
#[path = "tests/audience_tests.rs"]
mod audience_tests;
