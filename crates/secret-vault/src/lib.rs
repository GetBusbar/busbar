// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **HashiCorp Vault** backend for busbar's `kind: secret` plugin family — the real thing
//! `busbar-secret-example-plugin` stands in for (that crate is a hermetic in-memory-map TEST fixture,
//! never a backend to run in production; see its doc comment). This crate is the reusable LOGIC
//! (usable statically); the dynamic `cdylib` that exports the secret C ABI is the sibling
//! `busbar-secret-vault-plugin` crate — the same split `busbar-auth-oidc` / `busbar-auth-oidc-plugin`
//! already establishes for the auth seam.
//!
//! ## What it does
//!
//! Reads one field out of a Vault [KV v2 secrets
//! engine](https://developer.hashicorp.com/vault/docs/secrets/kv/kv-v2) entry over Vault's HTTP API:
//!
//! ```text
//! GET {addr}/v1/{path}          Header: X-Vault-Token: <token>
//! ⇒ { "data": { "data": { "<field>": "...", ... }, "metadata": {...} } }
//! ```
//!
//! `path` is the FULL v1 API path including the KV v2 `data/` segment the engine requires (e.g.
//! `kv/data/openai` for a `kv/` mount holding a secret at `openai`) — this crate does not itself
//! prepend a mount or a `data/` segment; the operator's `path` is used verbatim after `{addr}/v1/`.
//! Vault's own docs use exactly this convention, so an operator copying a path out of the Vault UI
//! or `vault kv get` output can drop it in unchanged.
//!
//! A Vault KV v2 entry commonly holds MULTIPLE key/value pairs (e.g. `kv/data/openai` might hold both
//! `api_key` and `org_id`), so a reference must name which field to extract. Two ways to say that, on
//! the per-reference `settings` map `SecretModule::resolve` receives:
//!
//! - `{ "path": "kv/data/openai#api_key" }` — the `#field` suffix convention `docs/plugins.md`
//!   already publishes as its Vault example. Matched here exactly: `path` is split on the LAST `#`.
//! - `{ "path": "kv/data/openai", "field": "api_key" }` — the same thing spelled as two keys, for
//!   operators/tooling that would rather not embed `#` inside a single string. When both `field` and
//!   a `#`-suffixed `path` are given, `field` wins (see [`parse_reference`]).
//!
//! ## Auth
//!
//! Vault has many auth methods (AppRole, Kubernetes, LDAP, …). This crate implements exactly ONE,
//! deliberately: a pre-obtained token sent as `X-Vault-Token` — Vault's simplest and most universal
//! scheme, and the right initial scope (a dev-mode root token, or a real AppRole/Kubernetes-issued
//! token an operator already holds and hands to busbar via `secrets.<module>.settings.token`, itself
//! a secret reference resolved against the built-in `env`/`file` modules before it reaches here — see
//! `busbar_config::SecretModuleCfg`). Implementing the AppRole login flow, Kubernetes auth, or any
//! other method that itself needs a login round-trip is real scope creep for a first version and is
//! left as a natural extension of THIS crate (`busbar-secret-vault`) — not the thin ABI adapter
//! (`busbar-secret-vault-plugin`), which should stay a pass-through of whatever this crate grows.
//!
//! ## Errors
//!
//! Fail-closed and specific, matching the rest of this codebase: a 404 (no secret at that path), a
//! 403 (bad token / missing Vault policy), and a 5xx (Vault itself unhealthy) are surfaced as
//! distinct, human-readable errors — never collapsed into a generic "resolve failed", and never an
//! empty `Ok`.

use busbar_api::{SecretError, SecretModule, SecretResult};
use serde::Deserialize;
use std::io::Read;
use std::time::Duration;

/// Upper bound on a Vault KV v2 response body. A KV v2 entry is typically a handful of short fields
/// (API keys, connection strings, small PEM blobs); this is generous headroom while still bounding
/// the allocation against a hostile or misbehaving Vault endpoint.
const MAX_VAULT_RESPONSE_BYTES: usize = 1024 * 1024;

/// Default HTTP timeout (connect + total) for a Vault request. Secret resolution runs once per
/// reference at boot/config-apply, off the request hot path, so a few seconds of headroom for a
/// slow/cold Vault is fine — but it must still be BOUNDED so a hung Vault cannot hang boot forever.
fn default_timeout_secs() -> u64 {
    10
}

/// The `busbar-secret-vault-plugin`'s open-time config — the `secrets.<module>.settings` map
/// `docs/plugins.md` describes as "the vault address + auth", passed through verbatim as JSON at
/// `open()`. Distinct from the per-REFERENCE `settings` [`parse_reference`] parses.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultConfig {
    /// The Vault server address, e.g. `https://vault.internal:8200` (or `http://127.0.0.1:8200` for a
    /// local dev-mode server). No trailing slash is required or stripped-twice; a trailing slash is
    /// tolerated (trimmed at request time).
    pub addr: String,
    /// The Vault token sent as `X-Vault-Token` on every read. A real deployment should deliver this
    /// as a secret reference in `config.yaml` (e.g. `{ env: VAULT_TOKEN }`), never a plaintext literal
    /// — busbar's config layer resolves it against the built-in env/file modules before this struct
    /// ever sees it (module-level settings cannot reference ANOTHER secret plugin — a bootstrap
    /// cycle — only the built-ins).
    pub token: String,
    /// An ADDITIONAL trusted root CA certificate (PEM), layered on top of the built-in public root
    /// store — mirrors `busbar_auth_oidc::OidcConfig::ca_cert_pem` exactly (same rationale: a
    /// self-hosted Vault behind a corporate/internal CA whose TLS cert doesn't chain to a public
    /// root). Never disables certificate validation, only widens the trusted-root set.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// HTTP timeout (connect + total), in seconds. Default 10.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
}

/// Read `r` into a `Vec<u8>`, refusing anything over `cap` bytes. `take(cap + 1)`: read one byte past
/// the cap so "exactly at the cap" and "over the cap" are distinguishable without trusting
/// Content-Length (which a hostile or chunked response need not supply honestly). Mirrors
/// `busbar_auth_oidc::reqwest_fetcher::read_capped`.
fn read_capped(r: impl Read, cap: usize) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    r.take(cap as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading Vault response body failed: {e}"))?;
    if buf.len() > cap {
        return Err(format!("Vault response body exceeds the {cap}-byte cap"));
    }
    Ok(buf)
}

/// Split a per-reference `settings` map into `(vault_path, field)`. See the crate doc for the two
/// accepted shapes. Fail-closed: a missing `path`, or a `path` with no `#field` suffix and no
/// separate `field` key, is an `Err` naming exactly what's missing.
pub fn parse_reference(
    settings: &serde_json::Map<String, serde_json::Value>,
) -> SecretResult<(String, String)> {
    let path = settings
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            SecretError("missing or non-string `path` in secret reference settings".to_string())
        })?;

    // Explicit `field` wins over any `#` embedded in `path` — the two-key spelling is meant to be
    // usable even against a path that (unusually) contains a literal `#`.
    if let Some(field) = settings.get("field").and_then(|v| v.as_str()) {
        if field.is_empty() {
            return Err(SecretError(
                "`field` in secret reference settings must not be empty".to_string(),
            ));
        }
        return Ok((path.to_string(), field.to_string()));
    }

    match path.rsplit_once('#') {
        Some((p, f)) if !p.is_empty() && !f.is_empty() => Ok((p.to_string(), f.to_string())),
        _ => Err(SecretError(format!(
            "vault secret reference must name a field to extract: either add a `field` key, or \
             suffix `path` with `#<field>` (e.g. \"kv/data/openai#api_key\"); got path {path:?}"
        ))),
    }
}

/// The real Vault-backed [`SecretModule`]: one HTTP client, the resolved `addr`, and the token, built
/// once at `open()` and reused for every `resolve()` call (module instances are stateless per call,
/// but the connection/config is not — see `busbar_api::SecretModule`'s doc).
pub struct VaultSecretModule {
    client: reqwest::blocking::Client,
    addr: String,
    token: String,
}

impl VaultSecretModule {
    /// Build the module from parsed config. Fails closed on a malformed `ca_cert_pem` or an
    /// unbuildable HTTP client — never returns a module that would silently no-op.
    pub fn new(cfg: &VaultConfig) -> Result<Self, String> {
        let timeout = Duration::from_secs(cfg.timeout_secs);
        let mut builder = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout);
        if let Some(pem) = &cfg.ca_cert_pem {
            let cert = reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|e| format!("invalid ca_cert_pem: {e}"))?;
            builder = builder.add_root_certificate(cert);
        }
        let client = builder
            .build()
            .map_err(|e| format!("failed to build Vault HTTP client: {e}"))?;
        Ok(Self {
            client,
            addr: cfg.addr.trim_end_matches('/').to_string(),
            token: cfg.token.clone(),
        })
    }

    /// Read one field out of a Vault KV v2 entry at `vault_path` (the full v1 API path, `data/`
    /// segment included — see the crate doc). Distinct status codes get distinct, specific errors:
    /// 404 (no secret there), 403 (bad token / missing policy), 5xx (Vault itself unhealthy), any
    /// other non-2xx (surfaced verbatim with the status and a body excerpt).
    fn read_field(&self, vault_path: &str, field: &str) -> SecretResult<Vec<u8>> {
        let url = format!("{}/v1/{}", self.addr, vault_path.trim_start_matches('/'));
        let resp = self
            .client
            .get(&url)
            .header("X-Vault-Token", &self.token)
            .send()
            .map_err(|e| SecretError(format!("request to Vault ({url}) failed: {e}")))?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(SecretError(format!(
                "Vault has no secret at path {vault_path:?} (404 from {url})"
            )));
        }
        if status == reqwest::StatusCode::FORBIDDEN {
            return Err(SecretError(format!(
                "Vault denied reading path {vault_path:?} (403 from {url}): check the token is \
                 valid and its policy grants read on this path"
            )));
        }
        if status.is_server_error() {
            return Err(SecretError(format!(
                "Vault server error reading path {vault_path:?}: HTTP {status} from {url}"
            )));
        }

        let body = read_capped(resp, MAX_VAULT_RESPONSE_BYTES)
            .map_err(|e| SecretError(format!("{e} (path {vault_path:?}, {url})")))?;

        if !status.is_success() {
            let excerpt: String = String::from_utf8_lossy(&body).chars().take(300).collect();
            return Err(SecretError(format!(
                "Vault returned HTTP {status} reading path {vault_path:?} ({url}): {excerpt}"
            )));
        }

        let v: serde_json::Value = serde_json::from_slice(&body).map_err(|e| {
            SecretError(format!(
                "Vault response for path {vault_path:?} is not valid JSON: {e}"
            ))
        })?;
        let data = v
            .get("data")
            .and_then(|d| d.get("data"))
            .and_then(|d| d.as_object())
            .ok_or_else(|| {
                SecretError(format!(
                    "Vault response for path {vault_path:?} has no `data.data` object (not a KV v2 \
                     read? check the path includes the `data/` segment, e.g. \"mount/data/name\")"
                ))
            })?;

        let value = data.get(field).ok_or_else(|| {
            let available: Vec<&str> = data.keys().map(String::as_str).collect();
            SecretError(format!(
                "Vault secret at path {vault_path:?} has no field {field:?}; available fields: \
                 {available:?}"
            ))
        })?;

        match value {
            serde_json::Value::String(s) => Ok(s.clone().into_bytes()),
            other => Ok(other.to_string().into_bytes()),
        }
    }
}

impl SecretModule for VaultSecretModule {
    fn resolve(
        &self,
        settings: &serde_json::Map<String, serde_json::Value>,
    ) -> SecretResult<Vec<u8>> {
        let (path, field) = parse_reference(settings)?;
        self.read_field(&path, &field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settings(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn hash_suffix_addressing_matches_the_published_doc_convention() {
        let s = settings(json!({ "path": "kv/data/openai#api_key" }));
        let (path, field) = parse_reference(&s).unwrap();
        assert_eq!(path, "kv/data/openai");
        assert_eq!(field, "api_key");
    }

    #[test]
    fn explicit_field_key_is_accepted() {
        let s = settings(json!({ "path": "kv/data/openai", "field": "api_key" }));
        let (path, field) = parse_reference(&s).unwrap();
        assert_eq!(path, "kv/data/openai");
        assert_eq!(field, "api_key");
    }

    #[test]
    fn explicit_field_wins_over_a_hash_in_path() {
        // Deliberately adversarial: a `#` that is not the intended split point.
        let s = settings(json!({ "path": "kv/data/weird#name", "field": "real_field" }));
        let (path, field) = parse_reference(&s).unwrap();
        assert_eq!(path, "kv/data/weird#name");
        assert_eq!(field, "real_field");
    }

    #[test]
    fn missing_path_is_rejected() {
        let s = settings(json!({ "field": "api_key" }));
        let err = parse_reference(&s).unwrap_err();
        assert!(err.0.contains("path"), "{}", err.0);
    }

    #[test]
    fn path_with_no_field_and_no_hash_is_rejected() {
        let s = settings(json!({ "path": "kv/data/openai" }));
        let err = parse_reference(&s).unwrap_err();
        assert!(err.0.contains("field to extract"), "{}", err.0);
    }

    #[test]
    fn empty_field_after_hash_is_rejected() {
        let s = settings(json!({ "path": "kv/data/openai#" }));
        let err = parse_reference(&s).unwrap_err();
        assert!(err.0.contains("field to extract"), "{}", err.0);
    }

    #[test]
    fn empty_explicit_field_is_rejected() {
        let s = settings(json!({ "path": "kv/data/openai", "field": "" }));
        let err = parse_reference(&s).unwrap_err();
        assert!(err.0.contains("must not be empty"), "{}", err.0);
    }

    #[test]
    fn read_capped_refuses_over_the_cap_and_accepts_at_the_cap() {
        let cap = 16usize;
        let over = std::io::repeat(b'x').take(cap as u64 * 2);
        assert!(read_capped(over, cap).is_err());
        let at = std::io::repeat(b'x').take(cap as u64);
        assert_eq!(read_capped(at, cap).unwrap().len(), cap);
    }

    /// End-to-end against a REAL Vault dev-mode server, gated on `BUSBAR_TEST_VAULT_ADDR` +
    /// `BUSBAR_TEST_VAULT_TOKEN` — mirrors `store-postgres`'s `BUSBAR_TEST_POSTGRES_URL` pattern
    /// exactly, including the hard-fail-under-CI guard: skips cleanly when unset LOCALLY, but a
    /// missing var under `CI` is a hard failure, not a silent skip, so this — the only live coverage
    /// of the real Vault HTTP client — cannot quietly vanish.
    ///
    /// Start a real Vault first:
    /// ```sh
    /// docker run --rm -p 8200:8200 --cap-add=IPC_LOCK -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault
    /// BUSBAR_TEST_VAULT_ADDR=http://127.0.0.1:8200 BUSBAR_TEST_VAULT_TOKEN=root cargo test -p busbar-secret-vault
    /// ```
    ///
    /// Vault dev mode auto-mounts a `kv-v2` engine at `secret/`, so the test seeds
    /// `secret/data/busbar-test` directly via a raw HTTP PUT (a read-only client can't test itself
    /// without something to read) and reads it back through [`VaultSecretModule`], asserting BOTH
    /// field-addressing forms and the fail-closed 404 path.
    #[test]
    fn roundtrip_against_live_vault() {
        let (addr, token) = match (
            std::env::var("BUSBAR_TEST_VAULT_ADDR"),
            std::env::var("BUSBAR_TEST_VAULT_TOKEN"),
        ) {
            (Ok(addr), Ok(token)) => (addr, token),
            _ if std::env::var_os("CI").is_some() => {
                panic!(
                    "BUSBAR_TEST_VAULT_ADDR / BUSBAR_TEST_VAULT_TOKEN are unset under CI: a Vault \
                     dev-mode service container must provision them (see .github/workflows/ci.yml). \
                     Refusing to silently skip the only live-Vault coverage in CI."
                );
            }
            _ => {
                eprintln!(
                    "skip: set BUSBAR_TEST_VAULT_ADDR + BUSBAR_TEST_VAULT_TOKEN to run the live \
                     Vault test (docker run --rm -p 8200:8200 --cap-add=IPC_LOCK \
                     -e VAULT_DEV_ROOT_TOKEN_ID=root hashicorp/vault)"
                );
                return;
            }
        };

        // Seed a real secret with two fields directly via Vault's KV v2 write endpoint — this test's
        // own setup, not part of the crate's (read-only) public API.
        let seed = reqwest::blocking::Client::new();
        let put_body =
            json!({ "data": { "api_key": "sk-live-abc123", "org_id": "org-xyz" } }).to_string();
        let put_resp = seed
            .post(format!("{addr}/v1/secret/data/busbar-test"))
            .header("X-Vault-Token", &token)
            .header("Content-Type", "application/json")
            .body(put_body)
            .send()
            .expect("seed PUT to Vault failed (is the dev server running and reachable?)");
        assert!(
            put_resp.status().is_success(),
            "seeding the test secret failed: HTTP {}",
            put_resp.status()
        );

        let module = VaultSecretModule::new(&VaultConfig {
            addr: addr.clone(),
            token: token.clone(),
            ca_cert_pem: None,
            timeout_secs: 10,
        })
        .expect("build VaultSecretModule");

        // `#field` addressing (the published doc convention).
        let hash_settings = settings(json!({ "path": "secret/data/busbar-test#api_key" }));
        let got = module.resolve(&hash_settings).expect("resolve api_key");
        assert_eq!(got, b"sk-live-abc123");

        // Explicit `field` key addressing the SECOND field in the same entry.
        let explicit_settings =
            settings(json!({ "path": "secret/data/busbar-test", "field": "org_id" }));
        let got = module.resolve(&explicit_settings).expect("resolve org_id");
        assert_eq!(got, b"org-xyz");

        // A wrong path is a distinct, loud 404 — never an empty Ok.
        let missing = settings(json!({ "path": "secret/data/no-such-secret#x" }));
        let err = module.resolve(&missing).unwrap_err();
        assert!(
            err.0.contains("404"),
            "expected a 404 error, got: {}",
            err.0
        );

        // A wrong field on a REAL path is also a distinct, loud error naming the field.
        let bad_field = settings(json!({ "path": "secret/data/busbar-test#no_such_field" }));
        let err = module.resolve(&bad_field).unwrap_err();
        assert!(
            err.0.contains("no_such_field"),
            "expected the error to name the missing field, got: {}",
            err.0
        );

        // A bad token is a distinct, loud 403 — never conflated with the 404 path.
        let bad_token_module = VaultSecretModule::new(&VaultConfig {
            addr,
            token: "not-a-real-token".to_string(),
            ca_cert_pem: None,
            timeout_secs: 10,
        })
        .expect("build VaultSecretModule with a bad token");
        let err = bad_token_module.resolve(&hash_settings).unwrap_err();
        assert!(
            err.0.contains("403"),
            "expected a 403 error, got: {}",
            err.0
        );
    }
}
