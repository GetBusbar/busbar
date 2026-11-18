// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS CRATE'S COLD CODE (LINT-RULES LR-167): refusal text and rare owned copies its
//! request-path modules reach only off the priced path, out of line.

/// The scheme a string CLAIMS, for a refusal message. Nothing is decided from it.
#[cold]
pub(crate) fn scheme_of(url: &str) -> String {
    match url.split_once(':') {
        Some((s, _)) if !s.is_empty() && !s.contains('/') => s.to_ascii_lowercase(),
        _ => String::new(),
    }
}

/// A URL as a refusal repeats it, owned, through core's one redactor (`abi::host::scrub::mask_url`,
/// IF §12.16): spelled only when a URL is refused, or once when configuration is checked.
#[cold]
pub(crate) fn redact_userinfo(url: &str) -> String {
    busbar_plugin_abi::host_side::scrub::mask_url(url).into_owned()
}
