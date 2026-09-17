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
//! api_key: { env: SOME_API_KEY }               # ⇒ { module: env,  settings: { key: SOME_API_KEY } }
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
pub use busbar_secret_ref::{SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE, SECRET_MODULE_NONE};

// The plugin-settings RESOLVE helper is neutral `serde_json` + `busbar_api::{SecretRef,
// SecretResolve}` shape logic with no engine coupling — it (with `classify_setting`/`SettingShape`)
// moved DOWN to `busbar_substrate::config::secret` (1.6.0 hooks seam) so the hook-dispatch home
// (`busbar-core-hooks`) names them via the ABI. `resolve_settings` is re-exported here at its
// historical `config::secret::` path so this crate's preflight/appbuild/auth call sites and tests are
// unchanged (the classify shape helper is now used only by the moved dispatch code). The
// engine-specific `SecretResolver` (built-in `env`/`file` I/O + `kind: secret` plugin dispatch) below
// stays in this crate.
pub(crate) use busbar_substrate::config::secret::resolve_settings;

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
pub struct SecretResolver {
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
    pub fn builtins_only() -> Self {
        Self { plugin: None }
    }

    /// A resolver whose non-built-in modules resolve through `plugin` (a `kind: secret` plugin
    /// loader). Built-ins still short-circuit to the inline `env` / `file` path.
    pub fn with_plugin(plugin: PluginResolveFn) -> Self {
        Self {
            plugin: Some(plugin),
        }
    }

    /// Resolve a reference to raw bytes. `env` / `file` are built in; any other module delegates to
    /// the plugin resolver (fail-closed if none is wired or it fails).
    pub(crate) fn resolve(&self, secret: &SecretRef) -> Result<Vec<u8>, String> {
        match secret.module.as_str() {
            // `none` routes to the built-in resolver too, which refuses it: it declares the
            // ABSENCE of a credential, so it must never be mistaken for a plugin module name and
            // dispatched to a `kind: secret` plugin that happens to be called `none`.
            SECRET_MODULE_ENV | SECRET_MODULE_FILE | SECRET_MODULE_NONE => resolve_builtin(secret),
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

/// The NEUTRAL secret-resolver SEAM: `SecretResolver` implements `busbar_api::SecretResolve` by
/// delegating to its own `pub(crate)` resolution (allowed — same crate), so `&SecretResolver` is
/// usable as `&dyn busbar_api::SecretResolve`. An extracted plane names the trait, never this
/// engine-specific struct. The methods forward verbatim; the error is already a neutral `String`.
impl busbar_api::SecretResolve for SecretResolver {
    fn resolve(&self, secret: &SecretRef) -> Result<Vec<u8>, String> {
        SecretResolver::resolve(self, secret)
    }

    fn resolve_string(&self, secret: &SecretRef) -> Result<String, String> {
        SecretResolver::resolve_string(self, secret)
    }
}

/// BUILT-IN resolution of a secret reference to its raw bytes (`env` / `file`) and its UTF-8-string
/// twin now live in the dependency-light `busbar-api` contract crate — they are pure
/// `std::env`/`std::fs` + `busbar_secret_ref::SecretRef`, with no engine coupling, so a plane crate
/// can resolve a built-in ref without reaching into `busbar`. Re-exported so every in-crate call
/// site (the [`SecretResolver`] built-in fallback below) is unchanged.
pub(crate) use busbar_api::resolve_builtin;
pub use busbar_api::resolve_builtin_string;

#[cfg(test)]
#[path = "tests/secret_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/resolver_tests.rs"]
mod resolver_tests;

#[cfg(test)]
#[path = "tests/settings_resolution_tests.rs"]
mod settings_resolution_tests;
