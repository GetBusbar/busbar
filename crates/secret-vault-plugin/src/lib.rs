// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **Vault secret module as a droppable busbar plugin** — a `cdylib` that exports the secret C
//! ABI (`busbar_plugin_abi::kind::SECRET`). Build it, drop the resulting `.so`/`.dll`/`.dylib` into
//! the engine's plugins folder, give it a module NAME under `secrets:` (its open-time config — the
//! Vault address + token), and reference it from any secret field: `{ module: <alias>, settings: {
//! path: "kv/data/openai#api_key" } }`.
//!
//! All the Vault logic (the KV v2 HTTP client, field addressing, error classification) lives in the
//! `busbar-secret-vault` `lib` crate (usable statically too). Here we only adapt the engine's JSON
//! open-time config into a `VaultConfig` and hand the trait object to the SDK, which emits the
//! extern-C symbols the loader resolves — mirroring `busbar-auth-oidc-plugin`'s `open()` exactly.

use busbar_api::SecretModule;
use busbar_secret_vault::{VaultConfig, VaultSecretModule};

/// Construct a Vault secret module from the JSON config the engine passes through `open` — the
/// `secrets.<module>.settings` map. Shape:
///
/// ```json
/// {
///   "addr": "https://vault.internal:8200",
///   "token": "s.xxxxxxxx",
///   "ca_cert_pem": null,
///   "timeout_secs": 10
/// }
/// ```
///
/// `addr` and `token` are required; `ca_cert_pem` and `timeout_secs` are optional. An empty config is
/// rejected: a Vault module with no address or token can never resolve anything, so failing at
/// `open()` (a boot-time error naming the reference) is strictly better than deferring the same
/// failure to every `resolve()` call.
fn open(cfg: &str) -> Result<Box<dyn SecretModule>, String> {
    let cfg: VaultConfig = if cfg.trim().is_empty() {
        return Err("secret-vault plugin requires config (addr, token); none provided".to_string());
    } else {
        serde_json::from_str(cfg).map_err(|e| format!("invalid secret-vault plugin config: {e}"))?
    };
    Ok(Box::new(VaultSecretModule::new(&cfg)?))
}

busbar_plugin_sdk::export_secret_plugin!(open);

// ── unit tests for THIS crate's own responsibility: adapting the engine's JSON config into a real
// Vault module. Hermetic — no network (a valid `addr`/`token` pair only builds an HTTP client; it
// never connects until `resolve()` is called). Mirrors `busbar-auth-oidc-plugin`'s 8 tests: this crate
// owns config-parsing coverage only, not the Vault HTTP/KV-v2 logic itself, which is
// `busbar-secret-vault`'s own job (covered by that crate's `parse_reference`/`read_capped` unit tests
// plus its real-Vault-gated `roundtrip_against_live_vault` test). The real over-the-ABI, real-Vault
// success path lives in `busbar-plugin-loader`'s `load_and_exercise_secret_vault_plugin` test.
#[cfg(test)]
mod tests {
    use super::open;
    use busbar_api::SecretModule;

    /// `open` returns `Result<Box<dyn SecretModule>, String>`, and `dyn SecretModule` is not `Debug`
    /// (it carries no such bound), so the standard `.unwrap_err()` doesn't compile here. This is the
    /// equivalent for this specific `Result` shape — mirrors `auth-oidc-plugin`'s `expect_err`.
    fn expect_err(result: Result<Box<dyn SecretModule>, String>) -> String {
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
            err.contains("invalid secret-vault plugin config"),
            "error should name the config as invalid: {err}"
        );
    }

    #[test]
    fn config_missing_addr_is_rejected() {
        // `addr` has no `#[serde(default)]` in `VaultConfig` — it is required. `deny_unknown_fields`
        // is also on, so this proves the missing-required-field path specifically, not a stray typo.
        let err = expect_err(open(r#"{"token":"root"}"#));
        assert!(
            err.contains("invalid secret-vault plugin config"),
            "got: {err}"
        );
    }

    #[test]
    fn config_missing_token_is_rejected() {
        let err = expect_err(open(r#"{"addr":"http://127.0.0.1:8200"}"#));
        assert!(
            err.contains("invalid secret-vault plugin config"),
            "got: {err}"
        );
    }

    #[test]
    fn unknown_config_field_is_rejected() {
        // `VaultConfig` is `#[serde(deny_unknown_fields)]` — a typo'd or stray operator key must fail
        // loud at boot, not be silently ignored.
        let err = expect_err(open(
            r#"{"addr":"http://127.0.0.1:8200","token":"root","bogus_field":true}"#,
        ));
        assert!(
            err.contains("invalid secret-vault plugin config"),
            "got: {err}"
        );
    }

    #[test]
    fn minimal_valid_config_succeeds_without_network() {
        // `open()` only builds an HTTP client and stores the address/token; it never connects until
        // `resolve()` is called, so this succeeds fully hermetically even though nothing is listening
        // on this address.
        let module = open(r#"{"addr":"http://127.0.0.1:8200","token":"root"}"#)
            .expect("minimal valid config must succeed without network");
        // No further trait surface to assert on hermetically — `resolve()` would need real network.
        let _: &dyn SecretModule = module.as_ref();
    }

    #[test]
    fn full_config_with_optional_fields_succeeds_without_network() {
        let module = open(
            r#"{"addr":"https://vault.internal:8200/","token":"s.xxx","ca_cert_pem":null,"timeout_secs":5}"#,
        )
        .expect("full config with optional fields must succeed without network");
        let _: &dyn SecretModule = module.as_ref();
    }
}
