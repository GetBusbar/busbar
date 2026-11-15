// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Guarded source resolution through admitted secret owners.
//! Source settings remain opaque until the owning plugin receives the kind boundary encoding.

pub use busbar_contract::secret_ref::SecretRef;

/// The marker every blank-secret refusal carries, so a caller can keep its own operator text.
pub(crate) const BLANK_MARKER: &str = "(BLANK)";

/// A value with no content: empty, or valid UTF-8 that is only (Unicode) whitespace. Bytes that
/// are not UTF-8 (a raw binary key) are never blank.
fn is_blank(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|s| s.trim().is_empty())
}

/// Cheap to clone: a clone shares the one plugin resolver (and the instances it opened), so a
/// re-lend poll re-resolves through exactly what the build resolved through.
#[derive(Clone)]
pub struct SecretResolver {
    plugin: Option<std::sync::Arc<ScopedPluginResolve>>,
}

pub(crate) type PluginResolveFn = Box<
    dyn Fn(&str, &busbar_contract::plugin_settings::Settings) -> Result<Held, String> + Send + Sync,
>;

pub type Held = busbar_contract::redacted::Secret<Vec<u8>>;

pub type HeldText = busbar_contract::redacted::Secret<String>;

pub(crate) type ScopedPluginResolve = dyn Fn(
        &str,
        &busbar_contract::plugin_settings::Settings,
        Option<&busbar_contract::config_time::ConfigScope>,
    ) -> Result<Held, SecretRefused>
    + Send
    + Sync;

pub(crate) type ScopedPluginResolveFn = Box<ScopedPluginResolve>;

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
            plugin: Some(std::sync::Arc::new(
                move |module: &str,
                      settings: &busbar_contract::plugin_settings::Settings,
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
            plugin: Some(std::sync::Arc::from(plugin)),
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
        if secret.is_none() {
            return Err(refusal(ERROR_KIND_INVALID, NONE_HAS_NO_VALUE.to_string()));
        }
        if matches!(secret, SecretRef::Template(_)) {
            use busbar_contract::secret_ref::TemplateRefused;
            return secret
                .resolve_template_typed(&|reference| {
                    let bytes = self.resolve_with(reference, scope)?;
                    Self::text_of(reference, bytes)
                        .map_err(|text| refusal(ERROR_KIND_INVALID, text))
                })
                .map(|text| text.into_bytes())
                .map_err(|error| match error {
                    TemplateRefused::Source(error) => error,
                    TemplateRefused::TooLarge => {
                        refusal(ERROR_KIND_INVALID, "resolved template is too large".into())
                    }
                });
        }
        let source = secret.source().expect("non-template, non-keyless source");
        let module = source.module.as_str();
        let blank = || {
            refusal(
                ERROR_KIND_INVALID,
                format!(
                    "{} resolved to an EMPTY or whitespace-only {BLANK_MARKER} value; a secret \
                     must have content (fail-closed)",
                    secret.describe()
                ),
            )
        };
        if let Some(axis) = axis().filter(|a| a.linked(module)) {
            let settings = source.settings.encode().map_err(|_| {
                refusal(
                    ERROR_KIND_INVALID,
                    "source settings could not be encoded".into(),
                )
            })?;
            let seal = crate::seal::lend();
            let settings = settings.expose(&seal);
            let shared = axis
                .shared(module)
                .map_err(|text| refusal(ERROR_KIND_INTERNAL, text))?;
            let material = match scope {
                Some(scope) => shared.resolve_at_config(settings, scope),
                None => shared.resolve(settings),
            }?;

            if is_blank(material.expose(&crate::seal::lend())) {
                return Err(blank());
            }
            return Ok(material);
        }
        let Some(f) = &self.plugin else {
            return Err(refusal(
                ERROR_KIND_INVALID,
                format!(
                    "secret module '{module}' is not admitted and no plugin resolver is enabled, \
                 so no source can resolve {}; a secret that \
                 cannot resolve is a hard error (fail-closed)",
                    secret.describe()
                ),
            ));
        };
        let bytes = f(module, &source.settings, scope).map_err(|r| {
            refusal(
                r.error_kind,
                format!(
                    "secret module '{module}' (a kind: secret plugin) failed to resolve {}: {}",
                    secret.describe(),
                    r.text
                ),
            )
        })?;
        if is_blank(bytes.expose(&crate::seal::lend())) {
            return Err(blank());
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

pub use busbar_contract::plugin_settings::ResolvedSettings;

pub(crate) fn resolve_settings(
    settings: &busbar_contract::plugin_settings::Settings,
    declared: &[String],
    reference: &[String],
    plugin: &str,
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<ResolvedSettings, String> {
    settings.resolve(
        &busbar_contract::plugin_settings::Resolution {
            owner: plugin,
            secrets: declared,
            references: reference,
            sources: &admitted_sugars(),
        },
        resolver,
        scope,
    )
}

pub(crate) fn resolve_export_settings(
    settings: &busbar_contract::plugin_settings::Settings,
    declared: &[String],
    reference: &[String],
    plugin: &str,
    resolver: &dyn busbar_contract::secret::SecretResolve,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<ResolvedSettings, String> {
    busbar_contract::export_calls::ExportOpening::new(settings.clone()).resolve(
        &busbar_contract::plugin_settings::Resolution {
            owner: plugin,
            secrets: declared,
            references: reference,
            sources: &admitted_sugars(),
        },
        resolver,
        scope,
    )
}

#[cfg(test)]
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
     provider `api_key` for a keyless upstream)";

pub(crate) fn axis() -> Option<&'static dyn busbar_contract::secret::SecretAxis> {
    crate::preflight::root_rows().secret_axis
}

/// The live secret axis, for a check that judges references against what admission published
/// (a build): [`crate::config_validate::Check::secret_axis`].
#[must_use]
pub fn live_axis() -> Option<&'static dyn busbar_contract::secret::SecretAxis> {
    axis()
}

pub(crate) fn is_linked_secret(module: &str) -> bool {
    axis().is_some_and(|a| a.linked(module))
}

/// The shorthand the LIVE secret axis declares: the set the last admission published. Only for a
/// reader past admission (request-path opens, readback of the serving generation, settings a
/// build resolves after `admit_secrets`), never to parse a document: a read parses under its own
/// grammar ([`super::grammar::grammar_for`]), whatever the axis holds.
pub(crate) fn admitted_sugars() -> busbar_contract::secret_ref::Sugars {
    axis().map(|a| a.sugars()).unwrap_or_default()
}

/// THE ONE TEXT-AND-BYTES RULE for a credential the host re-resolves on a lease: resolve with the
/// typed refusal kind, apply the text rule ([`SecretResolver::resolve_string`]'s: UTF-8, trailing
/// `\r`/`\n` trimmed, an empty value refused as `INVALID`) and hand back the text's bytes. A build
/// and every later refresh of the same reference go through this one function, so a value read
/// twice unchanged is the same bytes twice (a file ending in a newline never looks rotated).
pub fn resolve_text_refusing(
    resolver: &dyn busbar_contract::secret::SecretResolve,
    secret: &SecretRef,
    scope: &busbar_contract::config_time::ConfigScope,
) -> Result<Held, SecretRefused> {
    let bytes = resolver.resolve_refusing(secret, Some(scope))?;
    SecretResolver::text_of(secret, bytes)
        .map(busbar_contract::redacted::Secret::into_bytes)
        .map_err(|text| refusal(busbar_contract::abi::secret::ERROR_KIND_INVALID, text))
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
pub(crate) fn install_normal_root_metadata() {
    super::tests::install_normal_root_metadata();
}

#[cfg(test)]
pub(crate) fn test_settings(
    map: &serde_json::Map<String, serde_json::Value>,
) -> busbar_contract::plugin_settings::Settings {
    map.clone().into()
}
#[cfg(test)]
pub(crate) fn test_settings_value(
    value: &serde_json::Value,
) -> busbar_contract::plugin_settings::Settings {
    serde_json::from_value(value.clone()).expect("fixture settings are an object")
}
#[cfg(test)]
pub(crate) fn test_resolved_value(settings: &ResolvedSettings) -> serde_json::Value {
    let encoded = settings.encode().expect("fixture settings encode");
    serde_json::from_slice(encoded.expose(&crate::seal::lend())).expect("fixture settings decode")
}

#[cfg(test)]
pub(crate) fn fixed_reference(label: &str) -> SecretRef {
    SecretRef::Source(busbar_contract::secret_ref::SourceReference {
        module: label.to_owned(),
        settings: Default::default(),
    })
}

/// Fixed guarded answers for kernel custody tests; no backend semantics or settings inspection.
#[cfg(test)]
pub(crate) fn fixed_resolver(
    bindings: Vec<(SecretRef, Result<Held, SecretRefused>)>,
) -> SecretResolver {
    SecretResolver::with_scoped_plugin(Box::new(move |module, settings, _scope| {
        bindings
            .iter()
            .find(|(reference, _)| {
                reference
                    .source()
                    .is_some_and(|source| source.module == module && &source.settings == settings)
            })
            .map(|(_, answer)| answer.clone())
            .unwrap_or_else(|| {
                Err(SecretRefused {
                    error_kind: busbar_contract::abi::secret::ERROR_KIND_NOT_FOUND,
                    text: "fixed source has no bound answer (fail-closed)".into(),
                })
            })
    }))
}

#[cfg(test)]
pub(crate) fn fixed_value(label: &str, value: &[u8]) -> SecretResolver {
    fixed_resolver(vec![(
        fixed_reference(label),
        Ok(Held::new(value.to_vec())),
    )])
}

#[cfg(test)]
pub(crate) fn descriptor_reference(value: &str) -> SecretRef {
    SecretRef::Source(busbar_contract::secret_ref::SourceReference {
        module: "fixture-source".into(),
        settings: [("slot".to_owned(), serde_json::Value::from(value))]
            .into_iter()
            .collect::<serde_json::Map<_, _>>()
            .into(),
    })
}

#[cfg(test)]
pub(crate) fn fixture_sources() -> busbar_contract::secret_ref::Sugars {
    use busbar_contract::abi::mechanism::door::{
        REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
    };
    let mut sources = busbar_contract::secret_ref::Sugars::default();
    for (word, owner, role) in [
        ("lookup", "first-source", SUGAR_ROLE_FILL),
        ("artifact", "second-source", SUGAR_ROLE_PATH),
    ] {
        sources
            .declare(
                owner,
                &[
                    (REWRITE_SUGAR, word.into(), "slot".into()),
                    (REWRITE_SUGAR_ROLE, word.into(), role.into()),
                ],
            )
            .unwrap();
    }
    sources
}
#[cfg(test)]
pub(crate) fn fixture_authored(yaml: &str) -> Result<SecretRef, busbar_contract::yaml::Error> {
    let sources = fixture_sources();
    busbar_contract::yaml::with_deserializer(yaml, |d| {
        busbar_contract::secret_ref::context::deserialize(d, &sources)
    })
}
