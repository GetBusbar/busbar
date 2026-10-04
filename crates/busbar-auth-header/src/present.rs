// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HEADER PRESENTATION: `bearer`, `api-key`, `x-goog-api-key`, and a dialect's credential-family
//! table. MOVED VERBATIM from the identity unit's `egress_auth/mod.rs` in the kernel (the header builders
//! and their one legality rule) and `.../declared.rs` (the credential-family presentation,
//! `presentation`/`present`), staged `busbar-auth-outbound::present` (KERNEL<>PLUGINS step 22), then
//! here (AUTH-SPLIT: bearer/api-key/x-goog-api-key are one mechanism, header presentation, and this
//! is its own crate). The legality rule itself, [`is_legal_header_value`](busbar_contract::header::is_legal_header_value),
//! lives in `busbar-contract` now, a shared pure helper: `busbar-auth-sigv4` and
//! `busbar-auth-oauth` need the same byte rule.
//!
//! What did NOT move: the `Grant<Sign>` / `SecretSlot` / `substitute` indirection. It existed so the
//! kernel could write a secret onto a request without a plane ever holding it; the auth plugin
//! holds the credential itself (BUSBAR-1.6.0.md THE DESIGN, §6: "The auth plugin holds it"), so the header is built
//! here directly — the same bytes `decorate` + `substitute` wrote, which the ported
//! `*_builder_and_decorated_slot_agree_on_every_key` vectors pin.

use busbar_contract::header::{is_legal_header_value, token_value};
use serde::Deserialize;

/// The static bearer credential: `authorization: Bearer <key>`, or NO header when the key carries a
/// byte that is not a legal header value (the upstream then answers 401). The omission is the whole
/// policy; reporting it is the caller's ([`crate::envelope`]), and the key is never logged.
pub fn bearer_auth_headers(key: &str) -> Vec<(String, String)> {
    if !is_legal_header_value(key) {
        return Vec::new();
    }
    vec![("authorization".to_string(), token_value(key))]
}

/// The static custom-header credential (`api-key`, `x-goog-api-key`, …) carrying the raw key
/// verbatim, or NO header when the key carries a byte that is not a legal header value. `header` is
/// the lowercase header name the style presents under.
pub fn api_key_auth_headers(header: &str, key: &str) -> Vec<(String, String)> {
    if !is_legal_header_value(key) {
        return Vec::new();
    }
    vec![(header.to_string(), key.to_string())]
}

/// How one static credential is presented (the contract's `CredentialHeader`, as settings data):
/// `authorization: Bearer <credential>` (`header` absent), or the credential verbatim in `header`,
/// leading whitespace trimmed first when `trim_start`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    /// The raw header; absent = bearer.
    #[serde(default)]
    pub header: Option<String>,
    /// Trim the credential's leading whitespace before presenting it raw.
    #[serde(default)]
    pub trim_start: bool,
}

impl Presentation {
    /// `authorization: Bearer <credential>`.
    pub const BEARER: Presentation = Presentation {
        header: None,
        trim_start: false,
    };

    /// The credential verbatim in `header`.
    pub fn raw(header: &str) -> Self {
        Self {
            header: Some(header.to_string()),
            trim_start: false,
        }
    }
}

/// One credential-family row (the contract's `CredentialFamily`): a credential starting with
/// `prefix` (leading whitespace trimmed) is presented as `presented`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Family {
    /// The credential prefix.
    pub prefix: String,
    /// How a credential of the family is presented.
    #[serde(flatten)]
    pub presented: Presentation,
}

/// The mode a credential is presented in: the binding's own, or a forwarded caller credential
/// ([`busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The credential the binding was opened with.
    Own,
    /// The caller's verified credential.
    Passthrough,
}

/// A static style's whole presentation (the contract's `EgressScheme::Static`): the family table,
/// then the presentation by mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScheme {
    /// The credential-family table, in precedence order (may be empty).
    pub families: Vec<Family>,
    /// How an own credential that matches no family is presented.
    pub own: Presentation,
    /// How a forwarded caller credential that matches no family is presented.
    pub passthrough: Presentation,
}

impl StaticScheme {
    /// The same presentation whatever the credential or mode.
    pub fn uniform(p: Presentation) -> Self {
        Self {
            families: Vec::new(),
            own: p.clone(),
            passthrough: p,
        }
    }

    /// How `credential` is presented in `mode`: the first credential-family row whose prefix the
    /// credential (leading whitespace trimmed) starts with, else the presentation for the mode.
    pub fn presentation(&self, credential: &str, mode: Mode) -> &Presentation {
        let trimmed = credential.trim_start();
        self.families
            .iter()
            .find(|family| trimmed.starts_with(family.prefix.as_str()))
            .map(|family| &family.presented)
            .unwrap_or(match mode {
                Mode::Own => &self.own,
                Mode::Passthrough => &self.passthrough,
            })
    }

    /// Present `credential` in `mode`: the header pairs to attach, or NONE when the credential
    /// cannot be presented (a byte that is not a legal header value).
    pub fn present(&self, credential: &str, mode: Mode) -> Vec<(String, String)> {
        match self.presentation(credential, mode) {
            Presentation {
                header: Some(header),
                trim_start,
            } => api_key_auth_headers(
                header,
                if *trim_start {
                    credential.trim_start()
                } else {
                    credential
                },
            ),
            Presentation { header: None, .. } => bearer_auth_headers(credential),
        }
    }
}

#[cfg(test)]
#[path = "tests/present_tests.rs"]
mod tests;
