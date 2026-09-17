// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The NEUTRAL plugin-settings secret-classification/resolution helpers (1.6.0 hooks seam).
//!
//! `classify_setting` / `resolve_settings` / [`SettingShape`] are pure data-shape logic over
//! `serde_json` + `busbar_api::{SecretRef, SecretResolve}` — no engine, no `App`, no I/O of their
//! own (resolution is delegated through the neutral `SecretResolve` trait). They moved DOWN here off
//! `busbar_core::config::secret` so the hook-dispatch home (`busbar-core-hooks`) — the caller that
//! resolves a plugin's `settings:` at `open` and classifies them WITHOUT resolving on the drift READ
//! path — can name them via the substrate ABI instead of reaching back into `busbar-core`.
//!
//! `busbar-core` re-exports each at its historical `config::secret::` path, so its composition root,
//! preflight/appbuild/auth call sites and tests are unchanged. The engine-specific `SecretResolver`
//! (built-in `env`/`file` I/O + `kind: secret` plugin dispatch) stays in `busbar-core`.

use busbar_api::{SecretRef, SecretResolve};

/// The reserved wrapper key that OPTS A PLUGIN SETTING OUT of secret-reference interpretation:
/// `{ literal: <value> }` delivers `<value>` to the plugin verbatim. The escape hatch for the
/// genuinely ambiguous case where a plugin's own config happens to be shaped like a reference (a
/// `{ file: … }` path, an `{ env: … }` variable name the plugin reads itself) — see
/// [`resolve_settings`]. NOT part of `SecretRef` (see `busbar_secret_ref`'s crate docs): this key is
/// interpreted one layer above `SecretRef` parsing, here, not inside the shared type.
pub const SETTING_LITERAL_KEY: &str = "literal";

/// The well-known plugin-settings keys carrying a LICENSE credential (1.5.0 plugin-licensing
/// convention, ADR-0010). The core does NOT enforce licensing - a plugin validates its OWN license.
/// These names exist only so operators have a documented, first-class spelling; like any other
/// setting they MAY be a [`SecretRef`], which [`resolve_settings`] resolves to the raw key before it
/// crosses the ABI, so a license key never has to sit in plaintext config.
pub const PLUGIN_LICENSE_KEYS: &[&str] = &["license", "licenseKey"];

/// What ONE unresolved plugin-settings value is, decided WITHOUT any I/O. The single classifier
/// both [`resolve_settings`] (which then resolves the reference) and the drift READ path (which
/// must not) share, so the two can never disagree about which fields are references.
pub enum SettingShape<'a> {
    /// Delivered to the plugin exactly as this value — an ordinary setting, or the inner value of
    /// a `{ literal: … }` escape hatch already unwrapped.
    Verbatim(&'a serde_json::Value),
    /// A secret reference: what the plugin receives is the RESOLVED string, which is not knowable
    /// without performing the resolution.
    Reference(SecretRef),
}

/// Classify one settings value by SHAPE alone — no environment read, no file read, no plugin call.
///
/// Mirrors, and is the sole definition of, the interpretation [`resolve_settings`] applies: a
/// single-key `{ literal: … }` wrapper unwraps verbatim; anything else that parses as a whole
/// [`SecretRef`] is a reference; everything else passes through.
pub fn classify_setting(value: &serde_json::Value) -> SettingShape<'_> {
    // A ref is always a JSON object; skip scalars/arrays without an allocating round-trip.
    if let serde_json::Value::Object(obj) = value {
        // THE LITERAL ESCAPE HATCH. Ref-shape is a HEURISTIC: a plugin whose own settings
        // legitimately contain `{ file: /var/lib/db }` or `{ env: HOME }` — a path or a variable
        // NAME the plugin means to read itself — was silently swapped for the CONTENTS of that
        // file / the value of that variable, with no diagnostic anywhere. The shapes are genuinely
        // ambiguous and always will be, so give the operator a way to say "this object is data, not
        // a reference": `{ literal: <anything> }` passes the inner value through verbatim,
        // untouched and un-resolved.
        if obj.len() == 1 {
            if let Some(inner) = obj.get(SETTING_LITERAL_KEY) {
                return SettingShape::Verbatim(inner);
            }
        }
        if let Ok(secret) = serde_json::from_value::<SecretRef>(value.clone()) {
            return SettingShape::Reference(secret);
        }
    }
    SettingShape::Verbatim(value)
}

/// Walk a plugin's opaque `settings:` map and RESOLVE any [`SecretRef`]-shaped value in place,
/// substituting the resolved UTF-8 secret string, so the plugin receives the real value (e.g. its
/// `licenseKey`) and never a reference it cannot dereference. Non-ref values (strings, numbers,
/// nested config the plugin documents) pass through VERBATIM - a value only resolves if it parses as
/// a full secret reference (`{ env: … }` / `{ file: … }` / `{ module: …, settings: … }`); an
/// ordinary settings object like `{ db_path: … }` is not a ref (its keys aren't a ref's keys) and is
/// left untouched.
///
/// Runs CORE-SIDE at every `open` (boot, config apply/reload, AND hot plugin reload) BEFORE the
/// settings JSON crosses the ABI - it does not touch the wire ABI or the manifest signature. The
/// input `settings` (kept in the overlay/config) still holds the `SecretRef`, never the resolved
/// bytes; only the returned map carries the secret, and only long enough to hand it to the plugin.
///
/// FAIL-CLOSED: an unresolvable ref (unknown module, unset env, missing/empty file, plugin error) is
/// a hard `Err` that must fail the plugin load/reload - the plugin is NEVER handed an unresolved ref
/// or a silently-empty value. `field` names the settings key in the error (never the secret value).
pub fn resolve_settings(
    settings: &serde_json::Map<String, serde_json::Value>,
    resolver: &dyn SecretResolve,
) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    let mut out = serde_json::Map::with_capacity(settings.len());
    for (field, value) in settings {
        match classify_setting(value) {
            SettingShape::Verbatim(v) => {
                out.insert(field.clone(), v.clone());
            }
            SettingShape::Reference(secret) => {
                // NEVER silent: say which setting was interpreted as a reference and where it
                // points (never its value), so a coercion the operator did not intend is visible in
                // the boot log instead of surfacing as a corrupt setting inside the plugin.
                //
                // This log — and this whole function — belongs to the CONFIGURE PUSH (boot / apply /
                // hot reload), NOT to any read path: it does blocking I/O (a `kind: secret` plugin
                // is a synchronous FFI call) and names a secret reference on every invocation. A
                // per-request caller would turn both into a per-request cost; see
                // `hooks::settings_drift_keys`, which classifies WITHOUT resolving for exactly that
                // reason.
                tracing::info!(
                    setting = field.as_str(),
                    reference = %secret.describe(),
                    "plugin setting resolved as a SECRET REFERENCE; if this object was meant as \
                     literal plugin config, wrap it as `{{ literal: … }}` to pass it through verbatim"
                );
                let resolved = resolver.resolve_string(&secret).map_err(|e| {
                    format!(
                        "plugin setting '{field}' is a secret reference that did not resolve: {e}"
                    )
                })?;
                out.insert(field.clone(), serde_json::Value::String(resolved));
            }
        }
    }
    // License-agnostic ergonomic breadcrumb: if the settings carry a well-known license key, note at
    // INFO that a license credential is being DELIVERED to the plugin (which validates it itself; the
    // core enforces nothing). NEVER logs the value - only that the key is present and whether it was a
    // resolved secret reference. Lets an operator confirm the license wiring without exposing the key.
    for key in PLUGIN_LICENSE_KEYS {
        if out.contains_key(*key) {
            let via_secret_ref = settings.get(*key).map(|v| v.is_object()).unwrap_or(false);
            tracing::info!(
                license_key = key,
                via_secret_ref,
                "delivering a plugin license credential to the plugin (the plugin validates its own \
                 license; the core enforces nothing)"
            );
        }
    }
    Ok(out)
}
