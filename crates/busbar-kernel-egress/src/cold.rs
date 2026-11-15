// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS CRATE'S COLD CODE (LINT-RULES LR-167): refusal text and rare owned copies its
//! request-path modules reach only off the priced path, out of line.

/// A pool's name, owned: a walk marks a pool visited only when it exhausts it or spills from it.
#[cold]
pub(crate) fn visited_pool(pool: &str) -> String {
    pool.to_string()
}

/// One upstream head field, owned: written only when a build chooses an upstream encoding that
/// adds a field (1.6.0's adds none).
#[cold]
pub(crate) fn push_field(fields: &mut Vec<(Vec<u8>, Vec<u8>)>, name: &[u8], value: &[u8]) {
    fields.push((name.to_vec(), value.to_vec()));
}

/// The URL as a refusal may repeat it: everything an authority put before its last `@` replaced by a
/// marker.
#[cold]
pub fn redact_userinfo(url: &str) -> String {
    let (prefix, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (&url[..scheme.len() + 3], rest),
        None => ("", url),
    };
    let authority_end = rest.find(['/', '?', '#', '\\']).unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{prefix}<redacted>@{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// The scheme a string CLAIMS, for a refusal message. Nothing is decided from it.
#[cold]
pub(crate) fn scheme_of(url: &str) -> String {
    match url.split_once(':') {
        Some((s, _)) if !s.is_empty() && !s.contains('/') => s.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// `scheme://rest`, owned: a provider base URL whose authority carried userinfo, stripped of it.
#[cold]
pub(crate) fn without_userinfo(scheme: &str, rest: &str) -> String {
    format!("{scheme}://{rest}")
}
