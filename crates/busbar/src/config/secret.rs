// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET REFERENCE type (CLEAN-CONFIG rule): every secret/external value in the config is
//! `{ module: <secret-module>, settings: {…} }` - a reference to a SECRET MODULE (`kind: secret`
//! plugin), never the secret itself. The built-in modules are `env` (settings.key names an
//! environment variable) and `file` (settings.path names a file whose contents are the secret);
//! third-party modules (vault, cloud secret managers, …) load through the plugin system.
//!
//! Two ergonomic SUGAR spellings desugar to the built-ins so the common cases stay one-liners:
//!
//! ```yaml
//! api_key: { env: ANTHROPIC_API_KEY }          # ⇒ { module: env,  settings: { key: ANTHROPIC_API_KEY } }
//! cert:    { file: /run/secrets/tls-cert.pem } # ⇒ { module: file, settings: { path: /run/secrets/tls-cert.pem } }
//! ```
//!
//! A `SecretRef` holds NO secret material - only the module name and its opaque settings - so it is
//! safe to derive `Debug`/`Clone` on it and on every struct embedding it. Resolution (turning the
//! ref into bytes) happens at boot/first-use through the secret-resolver seam and is FAIL-CLOSED:
//! an unknown module or a failed resolution is a hard error, never an empty secret.

/// `SecretRef` (the `{module, settings}` + `env`/`file` sugar type) and its `Deserialize` impl now
/// live in the standalone `busbar-secret-ref` crate — it used to be defined here `pub(crate)`,
/// unreachable from `busbar-plugin-pack` or any future schema-generation tooling. Re-exported so
/// every call site in this crate is unchanged; `busbar` still owns
/// `SecretResolver`/`resolve_settings`/the built-in
/// `env`/`file` resolution, which are genuinely engine-specific (I/O, plugin dispatch) rather than
/// part of the reference SHAPE.
pub(crate) use busbar_secret_ref::{SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE};

/// The reserved wrapper key that OPTS A PLUGIN SETTING OUT of secret-reference interpretation:
/// `{ literal: <value> }` delivers `<value>` to the plugin verbatim. The escape hatch for the
/// genuinely ambiguous case where a plugin's own config happens to be shaped like a reference (a
/// `{ file: … }` path, an `{ env: … }` variable name the plugin reads itself) — see
/// [`resolve_settings`]. NOT part of `SecretRef` (see `busbar_secret_ref`'s crate docs): this key is
/// interpreted one layer above `SecretRef` parsing, here, not inside the shared type.
pub(crate) const SETTING_LITERAL_KEY: &str = "literal";

/// The engine-facing SECRET RESOLVER seam: the engine holds a `SecretResolver` and asks it to
/// turn a [`SecretRef`] into bytes, never touching a secret module's implementation. The built-in
/// `env` / `file` modules resolve inline (no plugin needed, so a zero-plugin deployment still has
/// secrets); any OTHER module name is delegated to a `kind: secret` plugin loaded through the
/// normal trust pipeline. FAIL-CLOSED at every branch: an unknown module or a resolution failure
/// is a hard error, never an empty secret.
///
/// The plugin lookup is a boxed closure so `config`/`tls` stay free of a `plugin-loader`
/// dependency (the engine wires the registry in at `build_app`); `None` = no plugin subsystem, so
/// only the built-ins resolve.
pub(crate) struct SecretResolver {
    /// Resolve one non-built-in reference through a loaded `kind: secret` plugin: given the module
    /// name + its settings JSON, return the secret bytes (or a fail-closed error). `None` when no
    /// plugin registry is available (built-ins only).
    plugin: Option<PluginResolveFn>,
}

/// The boxed closure a [`SecretResolver`] delegates a non-built-in module to: `(module, settings
/// JSON) -> secret bytes` (fail-closed on error). Boxed so `config` stays free of a `plugin-loader`
/// dependency (the engine wires the registry in at `build_app`).
pub(crate) type PluginResolveFn = Box<dyn Fn(&str, &str) -> Result<Vec<u8>, String> + Send + Sync>;

impl SecretResolver {
    /// A built-ins-only resolver (no plugin subsystem): `env` / `file` resolve, everything else is
    /// fail-closed. The zero-plugin resolver used by tests and any path with no registry.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn builtins_only() -> Self {
        Self { plugin: None }
    }

    /// A resolver whose non-built-in modules resolve through `plugin` (a `kind: secret` plugin
    /// loader). Built-ins still short-circuit to the inline `env` / `file` path.
    pub(crate) fn with_plugin(plugin: PluginResolveFn) -> Self {
        Self {
            plugin: Some(plugin),
        }
    }

    /// Resolve a reference to raw bytes. `env` / `file` are built in; any other module delegates to
    /// the plugin resolver (fail-closed if none is wired or it fails).
    pub(crate) fn resolve(&self, secret: &SecretRef) -> Result<Vec<u8>, String> {
        match secret.module.as_str() {
            SECRET_MODULE_ENV | SECRET_MODULE_FILE => resolve_builtin(secret),
            module => match &self.plugin {
                Some(f) => {
                    let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
                    let bytes = f(module, &settings).map_err(|e| {
                        format!(
                            "secret module '{module}' (a kind: secret plugin) failed to resolve \
                             {}: {e}",
                            secret.describe()
                        )
                    })?;
                    if bytes.is_empty() {
                        return Err(format!(
                            "secret module '{module}' resolved {} to an EMPTY value; a secret must \
                             be non-empty (fail-closed)",
                            secret.describe()
                        ));
                    }
                    Ok(bytes)
                }
                None => Err(format!(
                    "secret module '{module}' is not a built-in (`env` / `file`) and the plugin \
                     subsystem is not enabled, so no secret plugin can resolve {}; a secret that \
                     cannot resolve is a hard error (fail-closed)",
                    secret.describe()
                )),
            },
        }
    }

    /// Resolve to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or empty).
    /// The string-secret convenience twin of [`Self::resolve`], mirroring [`resolve_builtin_string`].
    pub(crate) fn resolve_string(&self, secret: &SecretRef) -> Result<String, String> {
        let bytes = self.resolve(secret)?;
        let s = String::from_utf8(bytes).map_err(|_| {
            format!(
                "secret {} resolved to non-UTF-8 bytes where a text secret is required",
                secret.describe()
            )
        })?;
        let trimmed = s.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            return Err(format!(
                "secret {} resolved to an empty value after trimming trailing newlines \
                 (fail-closed)",
                secret.describe()
            ));
        }
        Ok(trimmed.to_string())
    }
}

/// The well-known plugin-settings keys carrying a LICENSE credential (1.5.0 plugin-licensing
/// convention, ADR-0010). The core does NOT enforce licensing - a plugin validates its OWN license.
/// These names exist only so operators have a documented, first-class spelling; like any other
/// setting they MAY be a [`SecretRef`], which [`resolve_settings`] resolves to the raw key before it
/// crosses the ABI, so a license key never has to sit in plaintext config.
pub(crate) const PLUGIN_LICENSE_KEYS: &[&str] = &["license", "licenseKey"];

/// What ONE unresolved plugin-settings value is, decided WITHOUT any I/O. The single classifier
/// both [`resolve_settings`] (which then resolves the reference) and the drift READ path (which
/// must not) share, so the two can never disagree about which fields are references.
pub(crate) enum SettingShape<'a> {
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
pub(crate) fn classify_setting(value: &serde_json::Value) -> SettingShape<'_> {
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
pub(crate) fn resolve_settings(
    settings: &serde_json::Map<String, serde_json::Value>,
    resolver: &SecretResolver,
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

/// BUILT-IN resolution of a secret reference to its raw bytes: `env` reads the
/// environment variable; `file` reads the file. Any other module name is FAIL-CLOSED here - the
/// full secret-plugin resolver (third-party `kind: secret` modules through the plugin trust
/// pipeline) is layered on top of this by [`SecretResolver`], which falls back to these built-ins
/// by these exact names.
pub(crate) fn resolve_builtin(secret: &SecretRef) -> Result<Vec<u8>, String> {
    if let Some(var) = self_env_var_checked(secret)? {
        return match std::env::var(&var) {
            Ok(v) if !v.is_empty() => Ok(v.into_bytes()),
            Ok(_) => Err(format!(
                "secret env:{var} resolved to an EMPTY value; a secret must be non-empty \
                 (fail-closed)"
            )),
            Err(_) => Err(format!(
                "secret env:{var} cannot resolve: environment variable '{var}' is unset"
            )),
        };
    }
    if let Some(path) = self_file_path_checked(secret)? {
        return match std::fs::read(&path) {
            Ok(bytes) if !bytes.is_empty() => Ok(bytes),
            Ok(_) => Err(format!(
                "secret file:{path} resolved to an EMPTY file; a secret must be non-empty \
                 (fail-closed)"
            )),
            Err(e) => Err(format!("secret file:{path} cannot resolve: {e}")),
        };
    }
    Err(format!(
        "secret module '{}' is not a built-in (`env` / `file`) and no secret plugin provides it; \
         a secret that cannot resolve is a hard error (fail-closed)",
        secret.module
    ))
}

/// The `env` module's variable name, validating the settings shape (a malformed built-in ref must
/// fail loudly, not fall through to "unknown module").
fn self_env_var_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_ENV {
        return Ok(None);
    }
    match secret.env_var() {
        Some(v) if !v.trim().is_empty() => Ok(Some(v.to_string())),
        _ => Err(
            "secret module 'env' requires settings.key naming the environment variable \
             (e.g. `{ env: MY_VAR }` or `{ module: env, settings: { key: MY_VAR } }`)"
                .to_string(),
        ),
    }
}

/// The `file` module's path, validating the settings shape.
fn self_file_path_checked(secret: &SecretRef) -> Result<Option<String>, String> {
    if secret.module != SECRET_MODULE_FILE {
        return Ok(None);
    }
    match secret.file_path() {
        Some(p) if !p.trim().is_empty() => Ok(Some(p.to_string())),
        _ => Err(
            "secret module 'file' requires settings.path naming the file \
             (e.g. `{ file: /run/secrets/x }` or `{ module: file, settings: { path: /run/secrets/x } }`)"
                .to_string(),
        ),
    }
}

/// Resolve a secret reference to a UTF-8 STRING (trailing newline trimmed - the universal
/// file-delivered-secret convention). Fail-closed on non-UTF-8.
pub(crate) fn resolve_builtin_string(secret: &SecretRef) -> Result<String, String> {
    let bytes = resolve_builtin(secret)?;
    let s = String::from_utf8(bytes).map_err(|_| {
        format!(
            "secret {} resolved to non-UTF-8 bytes where a text secret is required",
            secret.describe()
        )
    })?;
    let trimmed = s.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err(format!(
            "secret {} resolved to an empty value after trimming trailing newlines (fail-closed)",
            secret.describe()
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
#[path = "tests/secret_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/resolver_tests.rs"]
mod resolver_tests;

#[cfg(test)]
#[path = "tests/settings_resolution_tests.rs"]
mod settings_resolution_tests;
