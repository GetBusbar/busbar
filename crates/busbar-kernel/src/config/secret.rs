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

pub use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE};

pub(crate) const SETTING_LITERAL_KEY: &str = "literal";

pub struct SecretResolver {
    plugin: Option<ScopedPluginResolveFn>,
}

pub(crate) type PluginResolveFn = Box<dyn Fn(&str, &str) -> Result<Held, String> + Send + Sync>;

pub type Held = busbar_contract::redacted::Secret<Vec<u8>>;

pub type HeldText = busbar_contract::redacted::Secret<String>;

pub(crate) type ScopedPluginResolveFn = Box<
    dyn Fn(
            &str,
            &str,
            Option<&busbar_contract::config_time::ConfigScope>,
        ) -> Result<Held, SecretRefused>
        + Send
        + Sync,
>;

pub use busbar_contract::secret::SecretRefused;

fn refusal(error_kind: u32, text: String) -> SecretRefused {
    SecretRefused { error_kind, text }
}

impl SecretResolver {
    pub fn builtins_only() -> Self {
        Self { plugin: None }
    }

    pub fn with_plugin(plugin: PluginResolveFn) -> Self {
        Self {
            plugin: Some(Box::new(
                move |module: &str,
                      settings: &str,
                      _: Option<&busbar_contract::config_time::ConfigScope>| {
                    plugin(module, settings).map_err(|text| {
                        refusal(busbar_contract::abi::secret::ERROR_KIND_INTERNAL, text)
                    })
                },
            )),
        }
    }

    pub(crate) fn with_scoped_plugin(plugin: ScopedPluginResolveFn) -> Self {
        Self {
            plugin: Some(plugin),
        }
    }

    pub(crate) fn resolve(&self, secret: &SecretRef) -> Result<Held, String> {
        self.resolve_with(secret, None).map_err(|r| r.text)
    }

    pub(crate) fn resolve_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<Held, String> {
        self.resolve_with(secret, Some(scope)).map_err(|r| r.text)
    }

    pub(crate) fn resolve_string_at_config(
        &self,
        secret: &SecretRef,
        scope: &busbar_contract::config_time::ConfigScope,
    ) -> Result<HeldText, String> {
        Self::text_of(secret, self.resolve_at_config(secret, scope)?)
    }

    pub(crate) fn resolve_with(
        &self,
        secret: &SecretRef,
        scope: Option<&busbar_contract::config_time::ConfigScope>,
    ) -> Result<Held, SecretRefused> {
        use busbar_contract::abi::secret::{ERROR_KIND_INTERNAL, ERROR_KIND_INVALID};
        let module = secret.module.as_str();

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

            if material.expose(&crate::seal::lend()).is_empty() {
                return Err(empty());
            }
            return Ok(material);
        }
        let Some(f) = &self.plugin else {
            return Err(refusal(
                ERROR_KIND_INVALID,
                format!(
                    "secret module '{module}' is not a built-in (`env` / `file`) and the plugin \
                 subsystem is not enabled, so no secret plugin can resolve {}; a secret that \
                 cannot resolve is a hard error (fail-closed)",
                    secret.describe()
                ),
            ));
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

    pub(crate) fn resolve_string(&self, secret: &SecretRef) -> Result<HeldText, String> {
        Self::text_of(secret, self.resolve(secret)?)
    }

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

pub(crate) const PLUGIN_LICENSE_KEYS: &[&str] = &["license", "licenseKey"];

pub(crate) enum SettingShape<'a> {
    Verbatim(&'a serde_json::Value),

    Reference(SecretRef),
}

pub(crate) fn classify_setting(value: &serde_json::Value) -> SettingShape<'_> {
    if let serde_json::Value::Object(obj) = value {
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

pub(crate) fn resolve_settings(
    settings: &serde_json::Map<String, serde_json::Value>,
    declared: &[String],
    reference: &[String],
    plugin: &str,
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<ResolvedSettings, String> {
    resolve_settings_with_literals(
        settings, declared, reference, plugin, resolver, scope, false,
    )
}

pub(crate) fn resolve_export_settings(
    settings: &serde_json::Map<String, serde_json::Value>,
    declared: &[String],
    reference: &[String],
    plugin: &str,
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<ResolvedSettings, String> {
    resolve_settings_with_literals(settings, declared, reference, plugin, resolver, scope, true)
}

fn resolve_settings_with_literals(
    settings: &serde_json::Map<String, serde_json::Value>,
    declared: &[String],
    reference: &[String],
    plugin: &str,
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
    allow_declared_literals: bool,
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
    if !allow_declared_literals {
        if let Some(at) = secret_fields::declared_literal(tree, declared) {
            return Err(secret_fields::declared_literal_refusal(
                &format!("settings.{at}"),
                plugin,
            ));
        }
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

            *slot = serde_json::Value::String(resolved.into_exposed(&crate::seal::lend()));
        }
    }

    secret_fields::resolve_references(tree, declared, reference, |field, secret| {
        tracing::info!(
            setting = field,
            reference = %secret.describe(),
            "plugin setting resolved as a REFERENCE at a field the plugin declares \
             reference-capable (not secret)"
        );
        resolver
            .resolve_string_at_config(secret, scope)
            .map(|value| value.into_exposed(&crate::seal::lend()))
            .map_err(|e| {
                format!("plugin setting '{field}' is a reference that did not resolve: {e}")
            })
    })?;

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

const ALWAYS_AN_OBJECT: &str = "resolved settings are built from a settings map";

impl ResolvedSettings {
    pub(crate) fn from_map(settings: serde_json::Map<String, serde_json::Value>) -> Self {
        Self(serde_json::Value::Object(settings))
    }

    pub fn as_value(&self) -> &serde_json::Value {
        &self.0
    }

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

pub(crate) fn wipe_strings(v: &mut serde_json::Value) {
    use zeroize::Zeroize as _;
    match v {
        serde_json::Value::String(s) => s.zeroize(),
        serde_json::Value::Array(items) => items.iter_mut().for_each(wipe_strings),
        serde_json::Value::Object(map) => map.values_mut().for_each(wipe_strings),
        _ => {}
    }
}

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

const NONE_HAS_NO_VALUE: &str = "the `none` secret reference declares that there is NO credential, \
     so it has no value to resolve; it is accepted only where an absent credential is meaningful (a \
     provider `api_key` for a keyless upstream such as ollama or vLLM)";

pub(crate) fn axis() -> Option<&'static dyn busbar_contract::secret::SecretAxis> {
    crate::preflight::root_rows().secret_axis
}

pub(crate) fn is_linked_secret(module: &str) -> bool {
    axis().is_some_and(|a| a.linked(module))
}

pub(crate) fn sugars() -> busbar_contract::secret_ref::Sugars {
    axis().map(|a| a.sugars()).unwrap_or_default()
}

pub fn resolve_linked_string(secret: &SecretRef) -> Result<HeldText, String> {
    SecretResolver::builtins_only().resolve_string(secret)
}

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

#[cfg(test)]
#[path = "tests/loader_declared_settings.rs"]
mod loader_declared_settings;

#[cfg(test)]
#[path = "tests/actual_product_resolver.rs"]
mod actual_product_resolver;

#[cfg(test)]
pub(crate) fn actual_product_resolver() -> SecretResolver {
    actual_product_resolver::resolver()
}

#[cfg(test)]
pub(crate) fn install_normal_root_metadata() {
    super::tests::install_normal_root_metadata();
}
