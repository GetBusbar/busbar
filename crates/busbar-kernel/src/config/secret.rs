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
/// live in `busbar_contract::secret_ref` (DECISIONS #83) — it used to be defined here `pub(crate)`,
/// unreachable from `busbar-plugin-pack` or any future schema-generation tooling. Re-exported so
/// every call site in this crate is unchanged; `busbar` still owns
/// `SecretResolver`/`resolve_settings`/the built-in
/// `env`/`file` resolution, which are genuinely engine-specific (I/O, plugin dispatch) rather than
/// part of the reference SHAPE.
pub use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE};

/// The reserved wrapper key that OPTS A PLUGIN SETTING OUT of secret-reference interpretation:
/// `{ literal: <value> }` delivers `<value>` to the plugin verbatim. The escape hatch for the
/// genuinely ambiguous case where a plugin's own config happens to be shaped like a reference (a
/// `{ file: … }` path, an `{ env: … }` variable name the plugin reads itself) — see
/// [`resolve_settings`]. NOT part of `SecretRef` (see `busbar_contract::secret_ref`): this key is
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
pub struct SecretResolver {
    /// Resolve one non-built-in reference through a loaded `kind: secret` plugin: given the module
    /// name + its settings JSON, return the secret bytes (or a fail-closed error). `None` when no
    /// plugin registry is available (built-ins only).
    plugin: Option<ScopedPluginResolveFn>,
}

/// The boxed closure a [`SecretResolver`] delegates a non-built-in module to: `(module, settings
/// JSON) -> secret bytes` (fail-closed on error). Boxed so `config` stays free of a `plugin-loader`
/// dependency (the engine wires the registry in at `build_app`).
pub(crate) type PluginResolveFn = Box<dyn Fn(&str, &str) -> Result<Held, String> + Send + Sync>;

/// THE KERNEL'S HOLDER OF RESOLVED BYTES (the credential chip, row 6: host-owned secret bytes): the zeroizing
/// holder the secret plugin wrote the value into, moved here and never copied into a `Vec` or a
/// `String`; read only under the kernel's seal, wiped when it drops.
pub type Held = busbar_contract::redacted::Secret<Vec<u8>>;

/// [`Held`]'s text form: the same bytes, moved, their trailing newline trimmed.
pub type HeldText = busbar_contract::redacted::Secret<String>;

/// [`PluginResolveFn`] handed the config-time proof when the caller holds one (THE DESIGN §11.11
/// R4): a dropped-in source that reads the disk resolves only with it. Its refusal keeps the
/// plugin's `error_kind`.
pub(crate) type ScopedPluginResolveFn = Box<
    dyn Fn(
            &str,
            &str,
            Option<&busbar_contract::config_time::ConfigScope>,
        ) -> Result<Held, SecretRefused>
        + Send
        + Sync,
>;

/// A refusal of the kernel's resolver: the source's `abi::secret::ERROR_KIND_*` code and the text.
pub use busbar_contract::secret::SecretRefused;

/// A refusal with `error_kind` and `text`.
fn refusal(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

impl SecretResolver {
    /// A resolver over the linked secret plugins alone (no cold lane): what the build links (`env`
    /// / `file` in the default build) resolves, everything else is fail-closed.
    pub fn builtins_only() -> Self {
        Self { plugin: None }
    }

    /// A resolver whose non-built-in modules resolve through `plugin` (a `kind: secret` plugin
    /// loader). Built-ins still short-circuit to the inline `env` / `file` path.
    pub fn with_plugin(plugin: PluginResolveFn) -> Self {
        Self {
            plugin: Some(Box::new(
                move |module: &str,
                      settings: &str,
                      _: Option<&busbar_contract::config_time::ConfigScope>| {
                    // A plain-text plugin resolver names no code: its refusal is INTERNAL.
                    plugin(module, settings).map_err(|text| {
                        refusal(busbar_contract::abi::secret::ERROR_KIND_INTERNAL, text)
                    })
                },
            )),
        }
    }

    /// [`Self::with_plugin`], the plugin handed the caller's config-time proof when it holds one.
    pub(crate) fn with_scoped_plugin(plugin: ScopedPluginResolveFn) -> Self {
        Self {
            plugin: Some(plugin),
        }
    }

    /// Resolve a reference to raw bytes. A module the build LINKS (`env` / `file` in the default
    /// build) resolves through the root's secret axis, on its one shared instance; any other module
    /// delegates to the plugin resolver (fail-closed if none is wired or it fails).
    pub(crate) fn resolve(&self, secret: &SecretRef) -> Result<Held, String> {
        self.resolve_with(secret, None).map_err(|r| r.text)
    }

    /// [`Self::resolve`] at CONFIG TIME, with its proof: the one way a reference to a secret source
    /// that reads the disk resolves (THE DESIGN §11.11 R4, OWNER 2026-10-13).
    pub(crate) fn resolve_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<Held, String> {
        self.resolve_with(secret, Some(scope)).map_err(|r| r.text)
    }

    /// [`Self::resolve_string`] at CONFIG TIME, with its proof.
    pub(crate) fn resolve_string_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<HeldText, String> {
        Self::text_of(secret, self.resolve_at_config(secret, scope)?)
    }

    /// The one resolution, with or without a config-time proof: the material, or the refusal with
    /// the source's `error_kind` kept.
    pub(crate) fn resolve_with(
        &self,
        secret: &SecretRef,
        scope: Option<&busbar_contract::config_time::ConfigScope>,
    ) -> Result<Held, SecretRefused> {
        use busbar_contract::abi::secret::{ERROR_KIND_INTERNAL, ERROR_KIND_INVALID};
        let module = secret.module.as_str();
        // `none` declares the ABSENCE of a credential, so it is never looked up as a module: asking
        // for its bytes is a category error, refused rather than resolved to empty.
        if module == busbar_contract::secret_ref::SECRET_MODULE_NONE {
            return Err(refusal(ERROR_KIND_INVALID, NONE_HAS_NO_VALUE.to_string()));
        }
        let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
        let empty = || {
            refusal(
                ERROR_KIND_INVALID,
                format!(
                    "secret module '{module}' resolved {} to an EMPTY value; a secret must be \
                     non-empty (fail-closed)",
                    secret.describe()
                ),
            )
        };
        if let Some(axis) = axis().filter(|a| a.linked(module)) {
            let shared = axis
                .shared(module)
                .map_err(|text| refusal(ERROR_KIND_INTERNAL, text))?;
            let material = match scope {
                Some(scope) => shared.resolve_at_config(settings.as_bytes(), scope),
                None => shared.resolve(settings.as_bytes()),
            }?;
            // The plugin's holder itself, moved: the bytes are never copied out of it.
            if material.expose(&crate::seal::lend()).is_empty() {
                return Err(empty());
            }
            return Ok(material);
        }
        let Some(f) = &self.plugin else {
            return Err(refusal(ERROR_KIND_INVALID, format!(
                "secret module '{module}' is not a built-in (`env` / `file`) and the plugin \
                 subsystem is not enabled, so no secret plugin can resolve {}; a secret that \
                 cannot resolve is a hard error (fail-closed)",
                secret.describe()
            )));
        };
        let bytes = f(module, &settings, scope).map_err(|r| {
            refusal(
                r.error_kind,
                format!(
                    "secret module '{module}' (a kind: secret plugin) failed to resolve {}: {}",
                    secret.describe(),
                    r.text
                ),
            )
        })?;
        if bytes.expose(&crate::seal::lend()).is_empty() {
            return Err(empty());
        }
        Ok(bytes)
    }

    /// Resolve to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or empty).
    /// The string-secret convenience twin of [`Self::resolve`], mirroring [`resolve_linked_string`].
    pub(crate) fn resolve_string(&self, secret: &SecretRef) -> Result<HeldText, String> {
        Self::text_of(secret, self.resolve(secret)?)
    }

    /// Resolved bytes as the UTF-8 text a text secret is (trailing newline trimmed; fail-closed
    /// on non-UTF-8 or empty): the same holder's bytes, moved, never copied into a plain `String`.
    fn text_of(secret: &SecretRef, bytes: Held) -> Result<HeldText, String> {
        bytes.into_text().map_err(|e| match e {
            busbar_contract::redacted::NotText::NotUtf8 => format!(
                "secret {} resolved to non-UTF-8 bytes where a text secret is required",
                secret.describe()
            ),
            busbar_contract::redacted::NotText::Empty => format!(
                "secret {} resolved to an empty value after trimming trailing newlines \
                 (fail-closed)",
                secret.describe()
            ),
        })
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

/// Walk a plugin's opaque `settings:` map and RESOLVE the [`SecretRef`]-shaped values at the
/// positions the plugin DECLARED secret (`declared`: its Statement's `secret_refs`, `.`-separated
/// paths, `*` = any key or index) in place, substituting the resolved UTF-8 secret string, so the
/// plugin receives the real value and never a reference it cannot dereference. Non-ref values
/// (strings, numbers, nested config the plugin documents) pass through VERBATIM; a top-level
/// `{ literal: … }` wrapper is unwrapped.
///
/// A reference at a position the plugin did NOT declare secret is REFUSED, wherever it sits
/// (OWNER RULING, CHIP-REVIEW-v4 change 2, overturning Q123): the sentence names the field and
/// `plugin`, and says to write the value itself. Core's own typed fields are not plugin settings
/// and never come here.
///
/// EVERY SECRET IS A REFERENCE, NEVER A LITERAL (security.md:316): a value at a declared path,
/// EXACT or WILDCARD (`servers.*.env.*`, lead ruling item 7b), that is not a reference (a string, a
/// number, a `{ literal: … }` wrapper) is REFUSED in the words a core secret field answers
/// ([`busbar_contract::secret_fields::declared_literal_refusal`]), naming the setting's position and
/// never a byte of the value. An unset (or `null`) declared position is not a literal.
///
/// REFERENCE-CAPABLE, NOT-SECRET FIELDS (lead ruling item 7a): at a position the plugin names in its
/// Statement's reference-capable list (`reference`: its extensions' `reference_fields`, a store,
/// exporter or hook `url`), a reference is resolved in place to its string by the same resolver and
/// a literal passes as written; the value is never treated as a secret (no literal refusal). A path
/// in both lists is refused ([`busbar_contract::secret_fields::contradiction_refusal`]).
///
/// Runs CORE-SIDE at every `open` (boot, config apply/reload, AND hot plugin reload) BEFORE the
/// settings JSON crosses the ABI - it does not touch the wire ABI or the manifest signature. The
/// input `settings` (kept in the overlay/config) still holds the `SecretRef`, never the resolved
/// bytes; only the returned [`ResolvedSettings`] carries the secret, and it overwrites every string
/// in it with zeroes when it drops (security.md:318), so busbar's copy lives only as long as the
/// caller holds it to hand it to `open`.
///
/// FAIL-CLOSED: an unresolvable ref (unknown module, unset env, missing/empty file, plugin error) is
/// a hard `Err` that must fail the plugin load/reload - the plugin is NEVER handed an unresolved ref
/// or a silently-empty value. The error names the settings path (never the secret value).
pub(crate) fn resolve_settings(
    settings: &serde_json::Map<String, serde_json::Value>,
    declared: &[String],
    reference: &[String],
    plugin: &str,
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<ResolvedSettings, String> {
    use busbar_contract::secret_fields;
    if let Some(path) = secret_fields::contradiction(declared, reference) {
        return Err(secret_fields::contradiction_refusal(&path, plugin));
    }
    let mut held = ResolvedSettings(serde_json::Value::Object(settings.clone()));
    let tree = &mut held.0;
    if let Some(at) = secret_fields::undeclared_reference(tree, &[declared, reference].concat()) {
        return Err(secret_fields::undeclared_refusal(
            &format!("settings.{at}"),
            plugin,
        ));
    }
    if let Some(at) = secret_fields::declared_literal(tree, declared) {
        return Err(secret_fields::declared_literal_refusal(
            &format!("settings.{at}"),
            plugin,
        ));
    }
    for path in declared {
        for at in secret_fields::declared_references(tree, path) {
            let field = at.join(".");
            let Some(slot) = secret_fields::value_at_mut(tree, &at) else {
                continue;
            };
            let SettingShape::Reference(secret) = classify_setting(slot) else {
                continue;
            };
            // NEVER silent: say which setting was resolved as a reference and where it points
            // (never its value).
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
                "plugin setting resolved as a SECRET REFERENCE at a field the plugin declares secret"
            );
            let resolved = resolver
                .resolve_string_at_config(&secret, scope)
                .map_err(|e| {
                    format!(
                        "plugin setting '{field}' is a secret reference that did not resolve: {e}"
                    )
                })?;
            // The plugin is handed it inline, in its settings, as a JSON string (1.5.5's shape):
            // MOVED out of the resolver's holder into the bag, never copied; the bag wipes it when
            // it drops (`ResolvedSettings`).
            *slot = serde_json::Value::String(resolved.into_exposed(&crate::seal::lend()));
        }
    }
    // The REFERENCE-CAPABLE positions (not secret): each reference resolved in place by the same
    // resolver; a literal there is left as written.
    secret_fields::resolve_references(tree, declared, reference, |field, secret| {
        tracing::info!(
            setting = field,
            reference = %secret.describe(),
            "plugin setting resolved as a REFERENCE at a field the plugin declares \
             reference-capable (not secret)"
        );
        resolver
            .resolve_string_at_config(secret, scope)
            // Moved into the bag, never copied (as a declared secret is above).
            .map(|value| value.into_exposed(&crate::seal::lend()))
            .map_err(|e| {
                format!("plugin setting '{field}' is a reference that did not resolve: {e}")
            })
    })?;
    // A top-level `{ literal: … }` wrapper is unwrapped in place (moved, never copied).
    if let serde_json::Value::Object(map) = tree {
        for value in map.values_mut() {
            if let serde_json::Value::Object(obj) = value {
                if obj.len() == 1 {
                    if let Some(inner) = obj.get_mut(SETTING_LITERAL_KEY) {
                        *value = std::mem::take(inner);
                    }
                }
            }
        }
    }
    // License-agnostic ergonomic breadcrumb: if the settings carry a well-known license key, note at
    // INFO that a license credential is being DELIVERED to the plugin (which validates it itself; the
    // core enforces nothing). NEVER logs the value - only that the key is present and whether it was a
    // resolved secret reference. Lets an operator confirm the license wiring without exposing the key.
    for key in PLUGIN_LICENSE_KEYS {
        if held.contains_key(*key) {
            let via_secret_ref = settings.get(*key).map(|v| v.is_object()).unwrap_or(false);
            tracing::info!(
                license_key = key,
                via_secret_ref,
                "delivering a plugin license credential to the plugin (the plugin validates its own \
                 license; the core enforces nothing)"
            );
        }
    }
    Ok(held)
}

/// A plugin's settings with its declared secret references RESOLVED ([`resolve_settings`]): the
/// bag busbar hands the plugin's `open` (or re-pushes a hook's `configure`). It holds the plaintext
/// of every resolved secret, so it is a HOLDER, not a value: every string in it is overwritten with
/// zeroes when it drops (security.md:318, "overwriting its own copies with zeroes once the plugin
/// has them"), its `Debug` shows key names only, and it is read in place ([`Self::as_value`]),
/// never moved out into a plain `serde_json::Value`.
/// Always a JSON object: built only from a settings map and changed only in place.
#[derive(Clone)]
pub struct ResolvedSettings(serde_json::Value);

/// What [`ResolvedSettings`] always holds.
const ALWAYS_AN_OBJECT: &str = "resolved settings are built from a settings map";

impl ResolvedSettings {
    /// The bag as the one JSON object the plugin is handed (borrowed: the holder keeps it).
    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

    /// The bag's top-level settings, to read or to add one the plugin is handed beside them.
    pub fn map_mut(&mut self) -> &mut serde_json::Map<String, serde_json::Value> {
        self.0.as_object_mut().expect(ALWAYS_AN_OBJECT)
    }
}

impl Default for ResolvedSettings {
    fn default() -> Self {
        Self(serde_json::Value::Object(serde_json::Map::new()))
    }
}

impl std::ops::Deref for ResolvedSettings {
    type Target = serde_json::Map<String, serde_json::Value>;

    fn deref(&self) -> &Self::Target {
        self.0.as_object().expect(ALWAYS_AN_OBJECT)
    }
}

impl zeroize::Zeroize for ResolvedSettings {
    fn zeroize(&mut self) {
        wipe_strings(&mut self.0);
    }
}

impl Drop for ResolvedSettings {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for ResolvedSettings {}

impl std::fmt::Debug for ResolvedSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedSettings")
            .field("keys", &self.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

/// Overwrite every string under `v` with zeroes (its whole allocation) and empty it.
pub(crate) fn wipe_strings(v: &mut serde_json::Value) {
    use zeroize::Zeroize as _;
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        serde_json::Value::Object(map) => map.values_mut().for_each(wipe_strings),
        _ => {}
    }
}

/// The NEUTRAL secret-resolver SEAM: `SecretResolver` implements `busbar_contract::secret::SecretResolve` by
/// delegating to its own `pub(crate)` resolution (allowed — same crate), so `&SecretResolver` is
/// usable as `&dyn busbar_contract::secret::SecretResolve`. An extracted plane names the trait, never this
/// engine-specific struct. The methods forward verbatim; the error is already a neutral `String`.
impl busbar_contract::secret::SecretResolve for SecretResolver {
    fn resolve(&self, secret: &SecretRef) -> Result<Held, String> {
        SecretResolver::resolve(self, secret)
    }

    fn resolve_string(&self, secret: &SecretRef) -> Result<HeldText, String> {
        SecretResolver::resolve_string(self, secret)
    }

    fn resolve_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<Held, String> {
        SecretResolver::resolve_at_config(self, secret, scope)
    }

    fn resolve_string_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<HeldText, String> {
        SecretResolver::resolve_string_at_config(self, secret, scope)
    }

    fn resolve_refusing(
        &self,
        secret: &SecretRef,
        scope: Option<&busbar_contract::config_time::ConfigScope>,
    ) -> Result<Held, SecretRefused> {
        self.resolve_with(secret, scope)
    }
}

/// The refusal a `none` reference answers when asked for its bytes (1.5.5's words).
const NONE_HAS_NO_VALUE: &str = "the `none` secret reference declares that there is NO credential, \
     so it has no value to resolve; it is accepted only where an absent credential is meaningful (a \
     provider `api_key` for a keyless upstream such as ollama or vLLM)";

/// The secret axis the composition root installed (a test build answers it with the in-crate
/// secret double, `test_support::secrets`).
/// The kernel names none of the plugins behind it.
pub(crate) fn axis() -> Option<&'static dyn busbar_contract::secret::SecretAxis> {
    crate::preflight::root_rows().secret_axis
}

/// Whether a secret plugin the build LINKS answers `module` (a reference to it needs no `secrets:`
/// block and no plugins directory).
pub(crate) fn is_linked_secret(module: &str) -> bool {
    axis().is_some_and(|a| a.linked(module))
}

/// The SUGARS the loaded secret plugins' Statements declare (audit contract-admin #10, Law 1): the
/// shorthand each answers to, the settings key its value lands under and what a refusal says that
/// value names. The kernel reads them here and spells none; no axis installed, none is declared.
pub(crate) fn sugars() -> busbar_contract::secret_ref::Sugars {
    axis().map(|a| a.sugars()).unwrap_or_default()
}

/// Resolve `secret` to a UTF-8 string through the linked secret plugins alone (no `secrets:` block,
/// no cold lane). OWED: a plane still calls this (the mcp stdio child's environment and its
/// token-exchange subject token) until those sites move to host-held replacements; the
/// plane-secret-blindness gate lists them.
pub fn resolve_linked_string(secret: &SecretRef) -> Result<HeldText, String> {
    SecretResolver::builtins_only().resolve_string(secret)
}

/// [`resolve_linked_string`] at CONFIG TIME, with its proof (`--validate`, the config checks).
pub fn resolve_linked_string_at_config(
    secret: &SecretRef,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<HeldText, String> {
    SecretResolver::builtins_only().resolve_string_at_config(secret, scope)
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

#[cfg(test)]
#[path = "tests/linked_secret_hardening_tests.rs"]
mod linked_secret_hardening_tests;
