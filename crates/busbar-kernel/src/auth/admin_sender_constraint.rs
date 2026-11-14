// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refuse a DPoP access token downgraded to an admin bearer credential.
//!
//! This only removes authority after the provider identified the caller. Decoded claims never
//! authenticate a caller. A proof header beside a Bearer credential does not change its scheme:
//! RFC 9449 requires a DPoP presentation, whose proof remains the auth provider's responsibility.

use super::{audience::Bearer, App, AuthMiddleware, HeaderMap, HeaderName, AUTHORIZATION};

pub(super) fn downgraded(app: &App, provider: &str, headers: &HeaderMap) -> bool {
    let module = app
        .admin_modules
        .modules
        .get(provider)
        .map(|module| module.calls.carriers())
        .unwrap_or_default();
    // Authorization is also relevant when the provider's candidate came from another carrier.
    let carriers = (app.admin_modules.operator.carriers().iter())
        .chain(&module)
        .map(String::as_str)
        .chain([AUTHORIZATION.as_str()]);
    downgraded_in(headers, carriers)
}

fn downgraded_in<S: AsRef<str>>(
    headers: &HeaderMap,
    carriers: impl IntoIterator<Item = S>,
) -> bool {
    carriers.into_iter().any(|name| {
        let Ok(name) = HeaderName::from_bytes(name.as_ref().as_bytes()) else {
            return false;
        };
        // Inspect every occurrence: choosing only the first lets duplicate carriers hide a bound
        // credential from this guard while the auth provider reads a different occurrence.
        headers.get_all(&name).iter().any(|value| {
            let Ok(value) = value.to_str() else {
                return false;
            };
            if name == AUTHORIZATION {
                AuthMiddleware::extract_bearer_token(value).is_some_and(requires_proof)
            } else {
                requires_proof(value)
            }
        })
    })
}

fn requires_proof(token: &str) -> bool {
    // A malformed jkt must not turn a sender-constrained credential into an ordinary bearer.
    matches!(Bearer::read(token), Bearer::Jwt(claims) if claims.cnf_jkt().present)
}

#[cfg(test)]
#[path = "tests/admin_sender_constraint.rs"]
mod tests;
