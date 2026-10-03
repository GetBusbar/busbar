// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DEPLOYMENT'S PUBLIC BASE, READ ONE WAY: the absolute URLs this plane publishes (its
//! audience, its protected-resource metadata document, its rewritten card endpoints) all come from
//! the operator's `public_url` through [`absolute`].

/// One reading of `public_url`: parse it, replace the path wholesale, drop query and fragment.
///
/// The path is REPLACED rather than joined, so a `public_url` carrying a path of its own cannot
/// produce `/some/prefix/a2a/agents/x` here while the router serves `/a2a/agents/x` — two spellings
/// of one endpoint, one of which 404s.
///
/// `None` when `public_url` is not a URL.
pub fn absolute(public_url: &str, path: &str) -> Option<String> {
    let mut u = url::Url::parse(public_url).ok()?;
    u.set_path(path);
    u.set_query(None);
    u.set_fragment(None);
    Some(u.to_string())
}

#[cfg(test)]
#[path = "tests/public_tests.rs"]
mod public_tests;
