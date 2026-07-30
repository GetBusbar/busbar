// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **OIDC auth module as a droppable busbar plugin** — a `cdylib` that exports the auth C ABI
//! ([`busbar_plugin_abi::auth`]). Build it, drop the resulting `.so`/`.dll`/`.dylib` into the engine's
//! plugins folder, add `oidc` to `auth.chain`, and configure `auth.modules.oidc.config`; the engine
//! loads it in-process at boot over the auth ABI.
//!
//! All the OIDC logic (JWKS, JWT verification on `ring`, claim policy) lives in the `busbar-auth-oidc`
//! `lib` crate (which a custom build can also link statically). Here we only adapt the engine's JSON
//! config into an `OidcModule` — resolving the JWKS url (explicit or via OIDC discovery) with a real
//! HTTPS fetcher — and hand the trait object to the SDK, which emits the five extern-C symbols the
//! loader resolves.

use busbar_api::AuthModule;
use busbar_auth_oidc::{resolve_jwks_url, OidcConfig, OidcModule, ReqwestFetcher};
use std::time::Duration;

/// The bound on a JWKS / discovery HTTP fetch. Generous enough for a cold DNS + TLS handshake to a
/// public IdP, short enough that a hung endpoint can't wedge boot or the (cached) auth path.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Construct an OIDC auth module from the JSON config the engine passes through `open`. Shape:
///
/// ```json
/// {
///   "issuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
///   "audience": "api://<client-id>",
///   "jwks_url": "https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys",
///   "role_claim": "groups"
/// }
/// ```
///
/// `jwks_url` is optional — when omitted it is discovered from the issuer's OIDC discovery document.
fn open(cfg: &str) -> Result<Box<dyn AuthModule>, String> {
    let cfg: OidcConfig = if cfg.trim().is_empty() {
        return Err("oidc plugin requires config (issuer, audience); none provided".to_string());
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid oidc plugin config: {e}"))?
    };

    // The fetcher used both for discovery (if needed) and for JWKS refreshes.
    let fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT, cfg.ca_cert_pem.as_deref())?;
    // Resolve the JWKS url at construction (fail boot loudly if discovery can't find it), so the hot
    // path never does discovery.
    let jwks_url = resolve_jwks_url(&cfg, &fetcher)?;
    // A SECOND fetcher instance for the live cache (the first was a borrow for discovery).
    let cache_fetcher = ReqwestFetcher::new(JWKS_FETCH_TIMEOUT, cfg.ca_cert_pem.as_deref())?;
    Ok(Box::new(OidcModule::new(
        &cfg,
        jwks_url,
        Box::new(cache_fetcher),
    )))
}

busbar_plugin_sdk::export_auth_plugin!(open);

// ── unit tests for THIS crate's own responsibility: adapting the engine's JSON config into a real
// OIDC module. Hermetic — no network. The underlying verification logic (JWKS/JWT/claims) is
// `busbar-auth-oidc`'s own job and is covered by that crate's 28 tests; these only cover what `open`
// itself does with the config before handing off. The real over-the-ABI, real-network-fixture success
// path lives in `busbar-plugin-loader`'s `load_and_exercise_auth_oidc_plugin` test.
#[cfg(test)]
mod tests {
    use super::open;
    use busbar_api::AuthModule;

    /// `open` returns `Result<Box<dyn AuthModule>, String>`, and `dyn AuthModule` is not `Debug` (it
    /// carries no such bound), so the standard `.unwrap_err()` doesn't compile here. This is the
    /// equivalent for this specific `Result` shape.
    fn expect_err(result: Result<Box<dyn AuthModule>, String>) -> String {
        match result {
            Ok(_) => panic!("expected open() to fail, but it succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn empty_config_is_rejected() {
        let err = expect_err(open(""));
        assert!(
            err.contains("config"),
            "error should name that config is required: {err}"
        );
    }

    #[test]
    fn whitespace_only_config_is_rejected() {
        let err = expect_err(open("   \n\t  "));
        assert!(err.contains("config"), "got: {err}");
    }

    #[test]
    fn malformed_json_is_rejected() {
        let err = expect_err(open("{ this is not json"));
        assert!(
            err.contains("invalid oidc plugin config"),
            "error should name the config as invalid: {err}"
        );
    }

    #[test]
    fn config_missing_issuer_is_rejected() {
        // `issuer` has no `#[serde(default)]` in `OidcConfig` — it is required. `deny_unknown_fields`
        // is also on, so this proves the missing-required-field path specifically, not a stray typo.
        let err = expect_err(open(r#"{"audience":"api://busbar"}"#));
        assert!(err.contains("invalid oidc plugin config"), "got: {err}");
    }

    #[test]
    fn config_missing_audience_is_rejected() {
        let err = expect_err(open(r#"{"issuer":"https://idp.example/v2.0"}"#));
        assert!(err.contains("invalid oidc plugin config"), "got: {err}");
    }

    #[test]
    fn unknown_config_field_is_rejected() {
        // `OidcConfig` is `#[serde(deny_unknown_fields)]` — a typo'd or stray operator key must fail
        // loud at boot, not be silently ignored.
        let err = expect_err(open(
            r#"{"issuer":"https://idp.example/v2.0","audience":"a","jwks_url":"https://idp.example/keys","bogus_field":true}"#,
        ));
        assert!(err.contains("invalid oidc plugin config"), "got: {err}");
    }

    #[test]
    fn explicit_jwks_url_skips_discovery_and_open_succeeds_without_network() {
        // `jwks_url` is present, so `resolve_jwks_url` returns it immediately without ever calling
        // out — discovery is skipped entirely. `open()` itself only builds HTTP clients and resolves
        // the JWKS url; it does NOT eagerly fetch the JWKS document (that's lazy, on first
        // `authenticate()`, via `JwksCache`). So this succeeds fully hermetically, proving the
        // "explicit jwks_url" success-shaped path with zero network I/O, even though the issuer host
        // below does not exist.
        let cfg = r#"{
            "issuer": "https://issuer.invalid.example",
            "audience": "api://busbar-client",
            "jwks_url": "https://issuer.invalid.example/keys"
        }"#;
        let module = open(cfg).expect("explicit jwks_url must skip discovery and succeed");
        assert_eq!(module.name(), "oidc");
        assert!(module.cacheable());
    }

    #[test]
    fn missing_jwks_url_with_malformed_issuer_fails_fast_without_network() {
        // No `jwks_url` ⇒ discovery is attempted from `issuer`. An issuer with no URL scheme produces
        // a discovery URL reqwest cannot even parse — the failure is a client-side URL-parse error
        // raised before any socket/DNS activity, so this is still hermetic (no real network access),
        // while genuinely exercising the "discovery required, resolution fails" path.
        let cfg = r#"{
            "issuer": "not-a-valid-url-at-all",
            "audience": "api://busbar-client"
        }"#;
        let err = expect_err(open(cfg));
        assert!(
            !err.is_empty(),
            "expected a descriptive discovery failure, got empty string"
        );
    }
}
