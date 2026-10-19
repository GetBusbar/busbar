// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The SECRET REFERENCE type (CLEAN-CONFIG rule): every secret/external value in the config is
//! `{ module: <secret-module>, settings: {…} }` - a reference to a SECRET MODULE (`kind: secret`
//! plugin), never the secret itself.
//!
//! The one-key SUGAR spellings (`{ <word>: X }`) are what the loaded secret plugins' Statements
//! declare (OWNER LAW 2026-09-27: the kernel knows zero plugin names; the sugar is a shorthand the
//! plugins declare and the kernel resolves generically). The kernel reads every reference in its
//! configuration against them ([`declared`], [`sugars`]): a word no loaded Statement declares is
//! refused where it stands, and every refusal that lists the sugars lists the declared ones. This
//! module names no plugin and no sugar word.
//!
//! A `SecretRef` holds NO secret material - only the module name and its opaque settings - so it is
//! safe to derive `Debug`/`Clone` on it and on every struct embedding it. Resolution (turning the
//! ref into bytes) happens at boot/first-use through the secret-resolver seam and is FAIL-CLOSED:
//! an unknown module or a failed resolution is a hard error, never an empty secret.

/// `SecretRef` and its readings live in `busbar_contract::secret_ref` (DECISIONS #83), re-exported
/// so every call site in this crate is unchanged; `SecretResolver`/`resolve_settings` stay here.
pub use busbar_contract::secret_ref::SecretRef;

/// THE SUGARS THE LOADED SECRET PLUGINS DECLARE: the secret axis the composition root installed
/// (its linked rows and the dropped-in ones it admitted; a test build's in-crate double). No axis,
/// no sugar: nothing but the core grammar reads.
#[must_use]
pub fn sugars() -> busbar_contract::secret_ref::Sugars {
    axis().map(|a| a.sugars()).unwrap_or_default()
}

/// Read a configuration's secret reference against the declared [`sugars`] — what every
/// `SecretRef` field of the kernel's configuration is read with
/// (`#[serde(deserialize_with = "crate::config::secret::declared")]`), so a refusal carries its
/// path and line and column exactly as it did when the sugars were core grammar.
///
/// # Errors
///
/// The shape is not a secret reference, or it spells a sugar no loaded Statement declares.
pub fn declared<'de, D>(deserializer: D) -> Result<SecretRef, D::Error>
where
    D: serde::Deserializer<'de>,
{
    SecretRef::deserialize_declared(deserializer, &sugars())
}

/// [`declared`] for an optional reference: `null` (or the key left out, with `#[serde(default)]`)
/// is `None`.
///
/// # Errors
///
/// As [`declared`].
pub fn declared_opt<'de, D>(deserializer: D) -> Result<Option<SecretRef>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct Opt;
    impl<'de> serde::de::Visitor<'de> for Opt {
        type Value = Option<SecretRef>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an optional secret reference")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            declared(deserializer).map(Some)
        }
    }
    deserializer.deserialize_option(Opt)
}

/// A reference's short display form for an error message, its declared sugar's reference read
/// `<word>:<value>` whichever way it was spelled ([`busbar_contract::secret_ref::Sugars::describe`]).
#[must_use]
pub fn describe(secret: &SecretRef) -> String {
    sugars().describe(secret)
}

/// The reference a config `${VAR}` names: `{ <fill>: VAR }`, through the sugar whose declared role
/// is the fill ([`busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL`]). `None` when no loaded
/// Statement declares one (nothing then resolves it: fail-closed).
#[must_use]
pub fn fill_reference(var: &str) -> Option<SecretRef> {
    sugars()
        .with_role(busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL)
        .map(|s| s.reference(var))
}

/// The reference a credential naming a key FILE stands for: `{ <path>: FILE }`, through the sugar
/// whose declared role is the path ([`busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH`]).
/// `None` when no loaded Statement declares one.
#[must_use]
pub fn path_reference(path: &str) -> Option<SecretRef> {
    sugars()
        .with_role(busbar_contract::abi::mechanism::door::SUGAR_ROLE_PATH)
        .map(|s| s.reference(path))
}

/// A refusal's example reference over `var`: `{ <fill>: <var> }` through the fill sugar, else the
/// canonical form.
#[must_use]
pub fn example_reference(var: &str) -> String {
    match sugars().with_role(busbar_contract::abi::mechanism::door::SUGAR_ROLE_FILL) {
        Some(s) => format!("{{ {}: {var} }}", s.word),
        None => "{ module: <secret-module>, settings: {…} }".to_string(),
    }
}

/// The declared sugar words as a refusal lists the built-in sources: `` `a` <sep> `b` ``.
#[must_use]
pub fn sugar_words(sep: &str) -> String {
    sugars()
        .iter()
        .map(|s| format!("`{}`", s.word))
        .collect::<Vec<_>>()
        .join(sep)
}

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
pub(crate) type PluginResolveFn = Box<
    dyn Fn(&str, &str) -> Result<busbar_contract::secret::Resolved<Vec<u8>>, String> + Send + Sync,
>;

/// [`PluginResolveFn`] handed the config-time proof when the caller holds one (THE DESIGN §11.11
/// R4): a dropped-in source that reads the disk resolves only with it.
pub(crate) type ScopedPluginResolveFn = Box<
    dyn Fn(
            &str,
            &str,
            Option<&busbar_contract::config_time::ConfigScope>,
        ) -> Result<busbar_contract::secret::Resolved<Vec<u8>>, String>
        + Send
        + Sync,
>;

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
                    plugin(module, settings)
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
    pub(crate) fn resolve(
        &self,
        secret: &SecretRef,
    ) -> Result<busbar_contract::secret::Resolved<Vec<u8>>, String> {
        self.resolve_with(secret, None)
    }

    /// [`Self::resolve`] at CONFIG TIME, with its proof: the one way a reference to a secret source
    /// that reads the disk resolves (THE DESIGN §11.11 R4, OWNER 2026-10-13).
    pub(crate) fn resolve_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::secret::Resolved<Vec<u8>>, String> {
        self.resolve_with(secret, Some(scope))
    }

    /// [`Self::resolve_string`] at CONFIG TIME, with its proof.
    pub(crate) fn resolve_string_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::secret::Resolved<String>, String> {
        Self::text_of(secret, self.resolve_at_config(secret, scope)?)
    }

    /// The one resolution, with or without a config-time proof.
    fn resolve_with(
        &self,
        secret: &SecretRef,
        scope: Option<&busbar_contract::config_time::ConfigScope>,
    ) -> Result<busbar_contract::secret::Resolved<Vec<u8>>, String> {
        // `none` declares the ABSENCE of a credential, so it is never looked up as a module: asking
        // for its bytes is a category error, refused rather than resolved to empty.
        if secret.is_none() {
            return Err(NONE_HAS_NO_VALUE.to_string());
        }
        // A sugar read without the table (a plugin's own settings, handed back) lands on its
        // declaring plugin's settings key here, as the configuration's own references already do.
        let secret = &sugars().canonical(secret);
        let module = secret.module.as_str();
        let settings = serde_json::Value::Object(secret.settings.clone()).to_string();
        if let Some(axis) = axis().filter(|a| a.linked(module)) {
            let shared = axis.shared(module)?;
            let material = match scope {
                Some(scope) => shared.resolve_at_config(settings.as_bytes(), scope),
                None => shared.resolve(settings.as_bytes()),
            };
            return material
                .map(|m| busbar_contract::secret::Resolved::of_kernel(m, &crate::seal::lend()))
                .map_err(|r| r.text);
        }
        let Some(f) = &self.plugin else {
            return Err(format!(
                "secret module '{module}' is not a built-in ({}) and the plugin subsystem is not \
                 enabled, so no secret plugin can resolve {}; a secret that cannot resolve is a \
                 hard error (fail-closed)",
                sugar_words(" / "),
                describe(secret)
            ));
        };
        let bytes = f(module, &settings, scope).map_err(|e| {
            format!(
                "secret module '{module}' (a kind: secret plugin) failed to resolve {}: {e}",
                describe(secret)
            )
        })?;
        if bytes.is_empty() {
            return Err(format!(
                "secret module '{module}' resolved {} to an EMPTY value; a secret must be \
                 non-empty (fail-closed)",
                describe(secret)
            ));
        }
        Ok(bytes)
    }

    /// Resolve to a UTF-8 STRING (trailing newline trimmed; fail-closed on non-UTF-8 or empty).
    /// The string-secret convenience twin of [`Self::resolve`], mirroring [`resolve_linked_string`].
    pub(crate) fn resolve_string(
        &self,
        secret: &SecretRef,
    ) -> Result<busbar_contract::secret::Resolved<String>, String> {
        Self::text_of(secret, self.resolve(secret)?)
    }

    /// Resolved bytes as the UTF-8 string a text secret is (trailing newline trimmed; fail-closed
    /// on non-UTF-8 or empty).
    fn text_of(
        secret: &SecretRef,
        bytes: busbar_contract::secret::Resolved<Vec<u8>>,
    ) -> Result<busbar_contract::secret::Resolved<String>, String> {
        bytes.into_text().map_err(|why| match why {
            busbar_contract::secret::NotText::NotUtf8 => format!(
                "secret {} resolved to non-UTF-8 bytes where a text secret is required",
                describe(secret)
            ),
            busbar_contract::secret::NotText::Empty => format!(
                "secret {} resolved to an empty value after trimming trailing newlines \
                 (fail-closed)",
                describe(secret)
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
        if let Ok(secret) = SecretRef::from_value_declared(value.clone(), &sugars()) {
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
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
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
                    reference = %describe(&secret),
                    "plugin setting resolved as a SECRET REFERENCE; if this object was meant as \
                     literal plugin config, wrap it as `{{ literal: … }}` to pass it through verbatim"
                );
                let resolved = resolver
                    .resolve_string_at_config(&secret, scope)
                    .map_err(|e| {
                        format!(
                        "plugin setting '{field}' is a secret reference that did not resolve: {e}"
                    )
                    })?;
                out.insert(
                    field.clone(),
                    serde_json::Value::String(handed_on(resolved)),
                );
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

/// The NEUTRAL secret-resolver SEAM: `SecretResolver` implements `busbar_contract::secret::SecretResolve` by
/// delegating to its own `pub(crate)` resolution (allowed — same crate), so `&SecretResolver` is
/// usable as `&dyn busbar_contract::secret::SecretResolve`. An extracted plane names the trait, never this
/// engine-specific struct. The methods forward verbatim; the error is already a neutral `String`.
impl busbar_contract::secret::SecretResolve for SecretResolver {
    fn resolve(
        &self,
        secret: &SecretRef,
    ) -> Result<busbar_contract::secret::Resolved<Vec<u8>>, String> {
        SecretResolver::resolve(self, secret)
    }

    fn resolve_string(
        &self,
        secret: &SecretRef,
    ) -> Result<busbar_contract::secret::Resolved<String>, String> {
        SecretResolver::resolve_string(self, secret)
    }

    fn resolve_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::secret::Resolved<Vec<u8>>, String> {
        SecretResolver::resolve_at_config(self, secret, scope)
    }

    fn resolve_string_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<busbar_contract::secret::Resolved<String>, String> {
        SecretResolver::resolve_string_at_config(self, secret, scope)
    }
}

/// AUDIT POINT (Part 2 #54): a sealed answer revealed under the kernel's seal and handed on to the
/// one carrier that still takes its plaintext (a lane's credential, a plane's settings, a plugin's
/// `open` settings). Every caller is such a place, by name; nothing else reads an answer bare.
pub(crate) fn handed_on<T: zeroize::Zeroize + Default + Clone>(
    answer: busbar_contract::secret::Resolved<T>,
) -> T {
    answer.sealed().expose(&crate::seal::lend()).clone()
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

/// Resolve `secret` to a UTF-8 string through the linked secret plugins alone (no `secrets:` block,
/// no cold lane). OWED: a plane still calls this (the mcp stdio child's environment and its
/// token-exchange subject token) until those sites move to host-held replacements; the
/// plane-secret-blindness gate lists them.
pub fn resolve_linked_string(
    secret: &SecretRef,
) -> Result<busbar_contract::secret::Resolved<String>, String> {
    SecretResolver::builtins_only().resolve_string(secret)
}

/// [`resolve_linked_string`] at CONFIG TIME, with its proof (`--validate`, the config checks).
pub fn resolve_linked_string_at_config(
    secret: &SecretRef,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<busbar_contract::secret::Resolved<String>, String> {
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

#[cfg(test)]
#[path = "tests/sugar_tests.rs"]
mod sugar_tests;
