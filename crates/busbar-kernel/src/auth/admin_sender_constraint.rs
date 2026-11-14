// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refuse a DPoP access token downgraded to an admin bearer credential.
//!
//! This only removes authority after the provider identified the caller. Decoded claims never
//! authenticate a caller. A proof header beside a Bearer credential does not change its scheme:
//! RFC 9449 requires a DPoP presentation, whose proof remains the auth provider's responsibility.
//! The "is bound" predicate and the every-occurrence scan are the data plane's own
//! (`auth::dpop::carries_bound`), so the two can never disagree.

use super::{App, HeaderMap, HeaderName, AUTHORIZATION};

pub(super) fn downgraded(app: &App, provider: &str, headers: &HeaderMap) -> bool {
    let mut carriers = app.admin_modules.operator.carriers().to_vec();
    if let Some(module) = app.admin_modules.modules.get(provider) {
        carriers.extend(module.calls.carriers());
    }
    // Authorization is also relevant when the provider's candidate came from another carrier.
    carriers.push(AUTHORIZATION.as_str().to_owned());
    downgraded_in(headers, &carriers)
}

fn downgraded_in(headers: &HeaderMap, carriers: &[String]) -> bool {
    let carriers: Vec<HeaderName> = carriers
        .iter()
        .filter_map(|name| HeaderName::from_bytes(name.as_bytes()).ok())
        .collect();
    super::dpop::carries_bound(headers, &carriers)
}

#[cfg(test)]
#[path = "tests/admin_sender_constraint.rs"]
mod tests;
