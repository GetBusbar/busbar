// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Refuse a DPoP access token downgraded to an admin bearer credential.
//!
//! This only removes authority after the provider identified the caller. Decoded claims never
//! authenticate a caller. A proof header beside a Bearer credential does not change its scheme:
//! RFC 9449 requires a DPoP presentation, whose proof remains the auth provider's responsibility.
//! The "is bound" predicate and the every-occurrence scan are the data plane's own
//! (`auth::dpop::carrier_bound`), so the two can never disagree.

use super::{App, HeaderMap, HeaderName, AUTHORIZATION};

pub(super) fn downgraded(app: &App, provider: &str, headers: &HeaderMap) -> bool {
    let module = app
        .admin_modules
        .modules
        .get(provider)
        .map(|module| module.calls.carriers())
        .unwrap_or_default();
    // Authorization is also relevant when the provider's candidate came from another carrier.
    let carriers = (app.admin_modules.operator.carriers().iter())
        .chain(module.iter())
        .map(String::as_str)
        .chain([AUTHORIZATION.as_str()]);
    downgraded_in(headers, carriers)
}

pub(super) fn downgraded_in<S: AsRef<str>>(
    headers: &HeaderMap,
    carriers: impl IntoIterator<Item = S>,
) -> bool {
    carriers
        .into_iter()
        .filter_map(|name| HeaderName::from_bytes(name.as_ref().as_bytes()).ok())
        .any(|name| super::dpop::carrier_bound(headers, &name))
}

#[cfg(test)]
#[path = "tests/admin_sender_constraint.rs"]
mod tests;
