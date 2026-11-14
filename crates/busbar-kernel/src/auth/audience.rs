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
    /// A JWT's payload: checked once to be one JSON value, its claims read in place on demand.
    Jwt(JwtPayload),
}

/// A JWT payload known to be one well-formed JSON value. Only the claims the kernel judges are
/// read out of it, in place; no document is built.
#[derive(Debug)]
pub struct JwtPayload(Vec<u8>);

/// What a payload's `cnf.jkt` is: present (of any JSON type) and, if so, whether a string.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Jkt {
    pub(crate) present: bool,
    pub(crate) string: bool,
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
            .filter(|bytes| serde_json::from_slice::<claims::Checked>(bytes).is_ok())
            .map_or(Bearer::Opaque, |bytes| Bearer::Jwt(JwtPayload(bytes)))
    }

    #[must_use]
    pub fn binding(&self, expected_aud: &str) -> Binding {
        match self {
            Bearer::Busbar => Binding::Deferred,
            Bearer::Opaque => Binding::Opaque,
            Bearer::Jwt(claims) => claims.binding(expected_aud),
        }
    }

    /// Whether the token is DPoP-bound: any `cnf.jkt`, whatever its type. A malformed jkt must not
    /// turn a sender-constrained credential into an ordinary bearer; it can only ever be refused,
    /// since proving it needs a string thumbprint.
    #[must_use]
    pub fn dpop_bound(&self) -> bool {
        matches!(self, Bearer::Jwt(claims) if claims["cnf"].get("jkt").is_some())
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
