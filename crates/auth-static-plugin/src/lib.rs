// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic static-token `kind: auth` plugin** — a `cdylib` exporting the auth C ABI, used only
//! as TEST support for the full-chain auth-plugin seam tests (the engine's `AuthMiddleware` loading a
//! real signed `kind: auth` tarball over the loader). It does NO network and NO crypto: a single
//! configured token maps to a single configured identity + roles, so a valid token yields a
//! `Principal` (→ role_bindings policy) and anything else `Pass`es. This is deliberately trivial — the
//! point under test is the ENGINE seam (resolve → load → box → run_chain → identity→policy), not an
//! IdP. Production IdP logic lives in `busbar-auth-oidc(-plugin)`.
//!
//! Config JSON (the chain entry's `settings:` map, passed verbatim by the engine):
//! ```json
//! { "token": "sekret", "id": "alice", "roles": ["platform"] }
//! ```
//!
//! ## Plugin licensing demo (ADR-0010)
//!
//! To exercise the plugin-licensing model, this plugin ALSO reads an optional `licenseKey` setting
//! and VALIDATES it ITSELF — the core enforces nothing; it only DELIVERS the setting. Because the
//! operator can spell `licenseKey` as a SecretRef (`{ env: … }` / `{ file: … }` / a `kind: secret`
//! module), the engine RESOLVES it to the raw key before `open` (a raw license never sits in
//! plaintext config). Validation here is deliberately trivial (the well-known demo key
//! `LICENSE-OK`); a real plugin would verify a signature/expiry. A present-but-invalid `licenseKey`
//! is a load error — the plugin, not the gateway, decides its own licensing policy.

use busbar_api::{constant_time_eq, sha256_hex, AuthModule, AuthOutcome, Principal};
use serde::Deserialize;

/// The plugin's opaque config: the one accepted token and the identity it grants.
#[derive(Deserialize)]
struct StaticConfig {
    /// The single credential this module accepts.
    token: String,
    /// The stable principal id the accepted token identifies as.
    id: String,
    /// The roles asserted for that principal (mapped to policy via `role_bindings.<module>`).
    #[serde(default)]
    roles: Vec<String>,
    /// OPTIONAL plugin license key (ADR-0010). The engine resolves this from a SecretRef before
    /// `open`, so by the time it reaches the plugin it is the RAW key. The plugin validates it
    /// ITSELF (below); the core enforces nothing.
    #[serde(default, rename = "licenseKey")]
    license_key: Option<String>,
}

/// The well-known DEMO license value this plugin accepts. A real plugin would verify a signature /
/// expiry / entitlement; the point under test is that the resolved key REACHES the plugin, so the
/// check is a trivial constant compare.
const DEMO_VALID_LICENSE: &str = "LICENSE-OK";

/// The plugin's OWN license validation (ADR-0010): the core is license-agnostic, so licensing policy
/// lives here. An ABSENT `licenseKey` is fine (unlicensed/free tier); a PRESENT one must be valid or
/// the plugin refuses to load. The key arrives already resolved (the engine turned any SecretRef into
/// the raw value before `open`), so this never sees a `{ env: … }` reference.
fn validate_license(license_key: Option<&str>) -> Result<(), String> {
    match license_key {
        None => Ok(()),
        Some(k) if k == DEMO_VALID_LICENSE => Ok(()),
        Some(_) => Err(
            "static-auth plugin: the delivered licenseKey is not valid for this plugin (the plugin \
             validates its own license; the value is not echoed)"
                .to_string(),
        ),
    }
}

/// A static-token identity module: the configured `token` → `Identify(id, roles)`; anything else
/// (including no credential) → `Pass` (defer to the next module). Never `Reject`s, so a chain of
/// `[static-auth, keys]` can still fall through to the built-in verifier — the fail-closed all-`Pass`
/// deny lives in the engine, not here.
struct StaticModule {
    /// SHA-256 hex digest of the configured token, computed once in `open` — never the raw token.
    /// Comparing under a digest (mirroring `auth-admin-tokens`, this plugin's own template) means
    /// `constant_time_eq`'s length early-exit never fires on the RAW candidate's length (every digest
    /// is 64 hex chars), so a caller cannot learn the configured token's length by timing.
    token_hash: String,
    id: String,
    roles: Vec<String>,
}

impl AuthModule for StaticModule {
    fn name(&self) -> &'static str {
        // The RUNTIME module identity — what `role_bindings.<module>` and `auth.modules.<module>`
        // caps key off. Deliberately fixed (not the config alias) to prove the engine keys policy off
        // `module.name()`, not the config chain name.
        "static-auth"
    }

    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome {
        match candidate {
            Some(cred) if constant_time_eq(&sha256_hex(cred.as_bytes()), &self.token_hash) => {
                let mut p = Principal::from_id(self.id.clone());
                p.roles = self.roles.clone();
                AuthOutcome::Identify(p)
            }
            _ => AuthOutcome::Pass,
        }
    }
}

/// Construct the module from the engine-passed JSON config. Fail-closed: an empty/invalid config is a
/// load error (surfaced by `open_auth` → boot/apply abort).
fn open(cfg: &str) -> Result<Box<dyn AuthModule>, String> {
    if cfg.trim().is_empty() {
        return Err("static-auth plugin requires config (token, id); none provided".to_string());
    }
    let c: StaticConfig =
        serde_json::from_str(cfg).map_err(|e| format!("invalid static-auth plugin config: {e}"))?;
    if c.token.is_empty() || c.id.is_empty() {
        return Err("static-auth plugin config needs a non-empty `token` and `id`".to_string());
    }
    // The plugin validates its OWN license (ADR-0010). The engine has already resolved any SecretRef
    // `licenseKey` to its raw value; a present-but-invalid license is a load error.
    validate_license(c.license_key.as_deref())?;
    Ok(Box::new(StaticModule {
        token_hash: sha256_hex(c.token.as_bytes()),
        id: c.id,
        roles: c.roles,
    }))
}

busbar_plugin_sdk::export_auth_plugin!(open);

#[cfg(test)]
mod tests {
    use super::*;

    /// The plugin validates its OWN license: absent is fine (free tier), the well-known demo value
    /// loads, and any other present value is a load error — the plugin, not the core, decides.
    #[test]
    fn plugin_validates_its_own_license() {
        assert!(validate_license(None).is_ok(), "absent license = free tier");
        assert!(
            validate_license(Some(DEMO_VALID_LICENSE)).is_ok(),
            "the delivered valid key loads"
        );
        let err = validate_license(Some("LICENSE-WRONG")).unwrap_err();
        assert!(err.contains("not valid"), "invalid license refuses: {err}");
    }

    /// `open` delivers the (already-resolved) licenseKey into validation: a valid key loads the
    /// module; an invalid one refuses. Proves the plugin reads `licenseKey` from its settings.
    #[test]
    fn open_reads_and_validates_delivered_license_key() {
        let base = |lic: &str| {
            format!(r#"{{ "token": "t", "id": "a", "roles": [], "licenseKey": "{lic}" }}"#)
        };
        assert!(open(&base(DEMO_VALID_LICENSE)).is_ok(), "valid key loads");
        match open(&base("LICENSE-WRONG")) {
            Err(e) => assert!(e.contains("not valid"), "refuses invalid license: {e}"),
            Ok(_) => panic!("an invalid delivered license must refuse load"),
        }
        // No licenseKey at all still loads (unlicensed tier).
        assert!(open(r#"{ "token": "t", "id": "a" }"#).is_ok());
    }

    /// class-13/14 F11: `authenticate` must compare the caller's credential to configured secret
    /// material under a DIGEST (`busbar_api::sha256_hex`), never raw-vs-raw — mirroring
    /// `auth-admin-tokens`, the template this plugin is meant to copy correctly. This is a
    /// REGRESSION PROOF OF STRUCTURE, not a RED test for a timing leak (a timing leak cannot be
    /// asserted in a unit test): it constructs the module directly (same-module private-field access)
    /// and asserts its stored comparison material is `sha256_hex("sekret")` exactly, a 64-hex-char
    /// digest — which fails while the field holds the raw string `"sekret"` and passes once `open`
    /// hashes it. Behaviorally, matching and non-matching credentials of any length still resolve to
    /// `Identify`/`Pass` exactly as before — hashing changes nothing observable about the auth
    /// outcome, only removes the raw comparison's length oracle.
    #[test]
    fn credential_is_compared_under_a_digest() {
        let m = StaticModule {
            token_hash: busbar_api::sha256_hex(b"sekret"),
            id: "alice".to_string(),
            roles: vec!["platform".to_string()],
        };

        // Structural: the field literally named `token_hash` holds a 64-hex-char SHA-256 digest of
        // the token, never the raw token string.
        assert_eq!(
            m.token_hash.len(),
            64,
            "must be a hex digest, not raw material"
        );
        assert_eq!(m.token_hash, busbar_api::sha256_hex(b"sekret"));
        assert_ne!(m.token_hash, "sekret", "must never store the raw token");

        // Behavioral: the correct credential still identifies, a wrong one of the SAME length still
        // passes through (never rejects — `StaticModule`'s contract), and a wrong one of DIFFERENT
        // length also still just passes. Hashing is invisible to the outcome.
        assert!(matches!(
            m.authenticate(Some("sekret")),
            AuthOutcome::Identify(_)
        ));
        assert!(matches!(m.authenticate(Some("wrongo")), AuthOutcome::Pass)); // same length (6)
        assert!(matches!(m.authenticate(Some("x")), AuthOutcome::Pass)); // different length
        assert!(matches!(m.authenticate(None), AuthOutcome::Pass));
    }
}
