// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY REFUSAL THIS CRATE MAKES, as the contract's one structured error, and the catalog that
//! templates each of them beside the claims.
//!
//! What `oauth-as` answers on the wire is NOT here: those bytes are fixed by the RFCs and forwarded
//! unchanged. What is here is what busbar itself refuses — the consent screen's four refusals, the
//! `oauth_as:` block's five boot refusals, and the three ways the running server fails to build —
//! each a [`PluginError`] under an `oauth2.*` code the host renders by READING a template, never by
//! calling into this crate.

use busbar_contract::bounded::BoundedVec;
use busbar_contract::error::{Catalog, CatalogEntry, ErrorClass, PluginError, Template};

/// The default locale every code below is templated in.
pub const LOCALE: &str = "en";

// ── consent ───────────────────────────────────────────────────────────────────────────────────
/// The consent screen was reached with no pending authorization request (a bookmark, a refresh).
pub const CONSENT_NO_REQUEST: &str = "oauth2.consent.no_request";
/// The approval was submitted without a live session cookie.
pub const CONSENT_NO_SESSION: &str = "oauth2.consent.no_session";
/// The platform RNG failed, so no session could be opened.
pub const CONSENT_NO_ENTROPY: &str = "oauth2.consent.no_entropy";
/// The operator's `issuer` path cannot be expressed as a `Set-Cookie` header value.
pub const CONSENT_NOT_REPRESENTABLE: &str = "oauth2.consent.not_representable";
// ── the `oauth_as:` block ─────────────────────────────────────────────────────────────────────
/// `issuer` is empty.
pub const CONFIG_MISSING_ISSUER: &str = "oauth2.config.missing_issuer";
/// `issuer` is not an absolute `http(s)` URL.
pub const CONFIG_ISSUER_NOT_ABSOLUTE: &str = "oauth2.config.issuer_not_absolute";
/// `issuer` carries a query or a fragment.
pub const CONFIG_ISSUER_HAS_QUERY_OR_FRAGMENT: &str = "oauth2.config.issuer_has_query_or_fragment";
/// `issuer` ends in `/`.
pub const CONFIG_ISSUER_HAS_TRAILING_SLASH: &str = "oauth2.config.issuer_has_trailing_slash";
/// `default_grant` names something that is not an RFC 6749 §3.3 scope token.
pub const CONFIG_SCOPE_NOT_A_TOKEN: &str = "oauth2.config.scope_not_a_token";
// ── build ─────────────────────────────────────────────────────────────────────────────────────
/// The configured signing key could not be loaded.
pub const BUILD_SIGNING_KEY: &str = "oauth2.build.signing_key";
/// The signing key material did not decode as base64 PKCS#8.
pub const BUILD_SIGNING_KEY_MATERIAL: &str = "oauth2.build.signing_key_material";
/// `oauth-as` refused to build its service.
pub const BUILD_SERVICE: &str = "oauth2.build.service";

/// One refusal, classed and coded, with the crate's own words for the log.
#[must_use]
pub fn refuse(class: ErrorClass, code: &str, developer_message: impl Into<String>) -> PluginError {
    PluginError::new(class, code).with_message(developer_message)
}

/// THE CATALOG: every code above, templated in [`LOCALE`]. Read by the host once; checked by the
/// crate's own test to be well-formed and to name exactly the codes this crate can emit.
#[must_use]
pub fn catalog() -> Catalog {
    let mut catalog = Catalog::empty(LOCALE);
    for (code, text) in ENTRIES {
        let mut templates = BoundedVec::new();
        let _ = templates.push(Template {
            locale: LOCALE.to_string(),
            text: (*text).to_string(),
        });
        let _ = catalog.entries.push(CatalogEntry {
            code: (*code).to_string(),
            templates,
        });
    }
    catalog
}

/// Code → template, the data the catalog is built from.
pub const ENTRIES: &[(&str, &str)] = &[
    (
        CONSENT_NO_REQUEST,
        "There is no authorization request waiting. Start the login from your agent.",
    ),
    (
        CONSENT_NO_SESSION,
        "The approval arrived without a consent session. Start the login from your agent.",
    ),
    (
        CONSENT_NO_ENTROPY,
        "This server could not start a session. Try again, and tell your operator if it persists.",
    ),
    (
        CONSENT_NOT_REPRESENTABLE,
        "This server could not start a session: the issuer's path cannot be carried in a cookie.",
    ),
    (
        CONFIG_MISSING_ISSUER,
        "oauth_as.issuer is required: the value a client compares against the `iss` of every response (RFC 9207), and the base every endpoint is derived from.",
    ),
    (
        CONFIG_ISSUER_NOT_ABSOLUTE,
        "oauth_as.issuer `{issuer}` is not an absolute http(s) URL.",
    ),
    (
        CONFIG_ISSUER_HAS_QUERY_OR_FRAGMENT,
        "oauth_as.issuer `{issuer}` carries a query or a fragment; RFC 8414 section 2 allows neither.",
    ),
    (
        CONFIG_ISSUER_HAS_TRAILING_SLASH,
        "oauth_as.issuer `{issuer}` ends in `/`; every endpoint is derived as `{{issuer}}/name`, so write it without the slash.",
    ),
    (
        CONFIG_SCOPE_NOT_A_TOKEN,
        "oauth_as.default_grant entry `{scope}` is not an RFC 6749 section 3.3 scope token.",
    ),
    (
        BUILD_SIGNING_KEY,
        "oauth_as.signing_key could not be loaded: {error}",
    ),
    (
        BUILD_SIGNING_KEY_MATERIAL,
        "oauth_as.signing_key is not a base64-encoded PKCS#8 v1 DER P-256 private key: {error}",
    ),
    (
        BUILD_SERVICE,
        "oauth_as: the authorization service refused to build: {error}",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_catalog_is_well_formed_and_every_code_is_namespaced() {
        let c = catalog();
        c.check().expect("well-formed");
        assert_eq!(c.entries.as_slice().len(), ENTRIES.len());
        for (code, _) in ENTRIES {
            assert!(code.starts_with("oauth2."), "{code}");
            assert!(
                c.template(code, "de").is_some(),
                "{code} falls back to the default locale"
            );
        }
    }
}
