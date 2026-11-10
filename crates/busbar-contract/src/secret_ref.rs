// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Source references, explicit keyless declarations, and core interpolation templates.
//! A source is always `{module, settings}`. Shorthand belongs to admitted source declarations
//! and requires [`context`]; the context-free parser never infers a source owner.
//! Templates retain the fill source selected at admission, without pretending to be a plugin.

use crate::plugin_settings::Settings;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::Zeroizing;

pub mod context;

/// The explicit keyless scalar spelling.
pub const SECRET_MODULE_NONE: &str = "none";
const NON_BLANK: &str = r"\S";

/// An admitted source's module identity and opaque authored settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceReference {
    /// The source owner's module identity.
    pub module: String,
    /// Settings interpreted only by that source owner.
    pub settings: Settings,
}

/// The fixed source declaration captured by a template at admission.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FillSource {
    module: String,
    setting: String,
}
impl FillSource {
    fn reference(&self, value: &str) -> SecretRef {
        SecretRef::Source(SourceReference {
            module: self.module.clone(),
            settings: serde_json::Map::from_iter([(self.setting.clone(), value.into())]).into(),
        })
    }
}

/// Core interpolation with guarded text and one immutable admitted source declaration.
/// No text accessor or caller-selected lookup is exposed.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TemplateReference {
    #[serde(deserialize_with = "template_text")]
    text: Zeroizing<String>,
    source: FillSource,
}
fn template_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    let mut held = crate::plugin_settings::Tree::deserialize(deserializer)?;
    match &mut held.0 {
        serde_json::Value::String(text) => Ok(Zeroizing::new(std::mem::take(text))),
        _ => Err(de::Error::custom(
            "template text must be a string (value not echoed)",
        )),
    }
}
impl fmt::Debug for TemplateReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TemplateReference")
            .field("source", &self.source.module)
            .finish_non_exhaustive()
    }
}

/// A credential position names a source, a core template, or explicitly no credential.
///
/// ```compile_fail
/// let reference = busbar_contract::secret_ref::SecretRef::none();
/// let _ = serde_json::to_value(&reference);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// An opaque source reference; canonical wire shape is `{module, settings}`.
    Source(SourceReference),
    /// Core interpolation; wire shape is `{template: {text, source: {module, setting}}}`.
    Template(TemplateReference),
    /// An explicit anonymous/keyless declaration.
    None,
}
/// A core template refusal preserves the source's error unchanged.
#[derive(Debug)]
pub enum TemplateRefused<E> {
    /// The selected source refused a fragment.
    Source(E),
    /// The composed output exceeds the addressable allocation bound.
    TooLarge,
}

/// An exact authoring view borrowed under concrete kernel authority.
///
/// ```compile_fail
/// let reference = busbar_contract::secret_ref::SecretRef::None;
/// let _ = busbar_contract::secret_ref::Authoring { reference: &reference };
/// ```
#[derive(Debug)]
pub struct Authoring<'a> {
    reference: &'a SecretRef,
}

impl SecretRef {
    /// Borrow the authored reference shape for a privileged document operation.
    ///
    /// ```compile_fail
    /// fn read(reference: &busbar_contract::secret_ref::SecretRef, seal: &dyn busbar_contract::plugin::KernelSeal) {
    ///     let _ = reference.authoring(seal);
    /// }
    /// ```
    pub fn authoring<'a>(&'a self, _seal: &'a crate::caps::KernelSeal) -> Authoring<'a> {
        self.writing()
    }
    pub(crate) fn writing(&self) -> Authoring<'_> {
        Authoring { reference: self }
    }

    /// A template bound to the one source whose admitted declaration owns the fill role.
    pub fn template(text: impl Into<String>, sources: &Sugars) -> Result<Self, String> {
        let source = sources
            .with_role(crate::abi::mechanism::door::SUGAR_ROLE_FILL)
            .ok_or("no admitted source declares the template fill role")?;
        Ok(Self::Template(TemplateReference {
            text: Zeroizing::new(text.into()),
            source: FillSource {
                module: source.plugin.clone(),
                setting: source.setting.clone(),
            },
        }))
    }
    /// Explicitly declare no credential.
    pub fn none() -> Self {
        Self::None
    }
    /// Whether this is the explicit keyless declaration.
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
    /// Source metadata and its opaque settings; templates are a separate core operation.
    pub fn source(&self) -> Option<&SourceReference> {
        match self {
            Self::Source(source) => Some(source),
            _ => None,
        }
    }
    /// The source dependency, including a template's captured fill source.
    pub fn source_module(&self) -> Option<&str> {
        match self {
            Self::Source(source) => Some(&source.module),
            Self::Template(template) => Some(&template.source.module),
            Self::None => None,
        }
    }
    /// A diagnostic naming only source metadata, never authored settings or template text.
    pub fn describe(&self) -> String {
        match self {
            Self::None => SECRET_MODULE_NONE.into(),
            Self::Source(source) => format!("secret module '{}'", source.module),
            Self::Template(template) => {
                format!("template using secret module '{}'", template.source.module)
            }
        }
    }
    /// Ask the admitted source axis to validate each canonical input without resolving it.
    pub fn check_sources(&self, axis: &dyn crate::secret::SecretAxis) -> Result<(), Vec<String>> {
        match self {
            Self::None => Ok(()),
            Self::Source(source) => axis.check(&source.module, &source.settings),
            Self::Template(template) => {
                let mut rest = template.text.as_str();
                while let Some(at) = rest.find("${") {
                    let after = &rest[at + 2..];
                    match after.find('}') {
                        Some(end) if end > 0 => {
                            template
                                .source
                                .reference(&after[..end])
                                .check_sources(axis)?;
                            rest = &after[end + 1..];
                        }
                        _ => rest = after,
                    }
                }
                Ok(())
            }
        }
    }
    pub(super) fn admitted_template(&self, sources: &Sugars) -> Result<(), &'static str> {
        let Self::Template(template) = self else {
            return Ok(());
        };
        let source = sources
            .with_role(crate::abi::mechanism::door::SUGAR_ROLE_FILL)
            .ok_or("no admitted source declares the template fill role")?;
        if template.source.module != source.plugin || template.source.setting != source.setting {
            return Err("template source differs from the admitted fill source declaration");
        }
        Ok(())
    }
    /// Resolve a source or interpolate a template through its captured source declaration.
    /// Every fragment and the final result retain guarded custody, including on failure.
    pub fn resolve_template(
        &self,
        resolve: &dyn Fn(&SecretRef) -> Result<crate::Secret<String>, String>,
    ) -> Result<crate::Secret<String>, String> {
        self.resolve_template_typed(resolve)
            .map_err(|error| match error {
                TemplateRefused::Source(error) => error,
                TemplateRefused::TooLarge => "resolved template is too large".to_owned(),
            })
    }
    /// Resolve while preserving the source resolver's original refusal taxonomy.
    pub fn resolve_template_typed<E>(
        &self,
        resolve: &dyn Fn(&SecretRef) -> Result<crate::Secret<String>, E>,
    ) -> Result<crate::Secret<String>, TemplateRefused<E>> {
        let Self::Template(template) = self else {
            return resolve(self).map_err(TemplateRefused::Source);
        };
        let mut parts = Vec::new();
        let mut rest = template.text.as_str();
        while let Some(at) = rest.find("${") {
            parts.push(crate::Secret::new(rest[..at].to_owned()));
            let after = &rest[at + 2..];
            match after.find('}') {
                Some(end) if end > 0 => {
                    parts.push(
                        resolve(&template.source.reference(&after[..end]))
                            .map_err(TemplateRefused::Source)?,
                    );
                    rest = &after[end + 1..];
                }
                _ => {
                    parts.push(crate::Secret::new("${".to_owned()));
                    rest = after;
                }
            }
        }
        parts.push(crate::Secret::new(rest.to_owned()));
        let capacity = parts
            .iter()
            .try_fold(0usize, |n, part| n.checked_add(part.0.len()))
            .ok_or(TemplateRefused::TooLarge)?;
        let mut joined = crate::Secret::new(String::with_capacity(capacity));
        for part in parts {
            joined.0.push_str(&part.0);
        }
        Ok(joined)
    }
}
impl Serialize for Authoring<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        match self.reference {
            SecretRef::None => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("module", SECRET_MODULE_NONE)?;
                map.serialize_entry("settings", &Settings::default().writing())?;
                map.end()
            }
            SecretRef::Source(source) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("module", &source.module)?;
                map.serialize_entry("settings", &source.settings.writing())?;
                map.end()
            }
            SecretRef::Template(template) => {
                #[derive(Serialize)]
                struct Template<'a> {
                    text: &'a str,
                    source: &'a FillSource,
                }
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry(
                    "template",
                    &Template {
                        text: &template.text,
                        source: &template.source,
                    },
                )?;
                map.end()
            }
        }
    }
}
/// Fixed non-echoing refusal for inline credential literals.
pub const INLINE_LITERAL_REFUSAL: &str = "a secret value must be a REFERENCE, never an inline literal (the value is not echoed); use { module: <secret-module>, settings: {…} }, an admitted source shorthand, or the bare scalar `none` to declare an upstream needs no credential";

impl<'de> Deserialize<'de> for SecretRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Reference;
        impl<'de> Visitor<'de> for Reference {
            type Value = SecretRef;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a secret reference map {module, settings}, an explicit {template: …}, or the bare scalar `none`")
            }
            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                d: D,
            ) -> Result<SecretRef, D::Error> {
                d.deserialize_any(self)
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<SecretRef, E> {
                if value == SECRET_MODULE_NONE {
                    Ok(SecretRef::None)
                } else {
                    Err(E::custom(INLINE_LITERAL_REFUSAL))
                }
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> Result<SecretRef, E> {
                Err(E::custom(INLINE_LITERAL_REFUSAL))
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> Result<SecretRef, E> {
                Err(E::custom(INLINE_LITERAL_REFUSAL))
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> Result<SecretRef, E> {
                Err(E::custom(INLINE_LITERAL_REFUSAL))
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> Result<SecretRef, E> {
                Err(E::custom(INLINE_LITERAL_REFUSAL))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SecretRef, A::Error> {
                let mut module: Option<String> = None;
                let mut settings: Option<Settings> = None;
                let mut template: Option<TemplateReference> = None;
                while let Some(key) = map.next_key::<Zeroizing<String>>()? {
                    match key.as_str() {
                        "module" if module.is_none() => {
                            let mut value: crate::plugin_settings::Tree = map.next_value()?;
                            let serde_json::Value::String(text) = &mut value.0 else {
                                return Err(de::Error::custom("a reference module must be a string naming a source (value not echoed)"));
                            };
                            module = Some(std::mem::take(text));
                        }
                        "settings" if settings.is_none() => {
                            settings = Some(map.next_value().map_err(|_| de::Error::custom(INLINE_LITERAL_REFUSAL))?);
                        }
                        "template" if template.is_none() => {
                            template = Some(map.next_value().map_err(|_| de::Error::custom("malformed core template (value not echoed)"))?);
                        }
                        "module" => return Err(de::Error::duplicate_field("module")),
                        "settings" => return Err(de::Error::duplicate_field("settings")),
                        "template" => return Err(de::Error::duplicate_field("template")),
                        _ => return Err(de::Error::custom("unknown reference member: shorthand requires an admitted source declaration (value not echoed)")),
                    }
                }
                if let Some(template) = template {
                    if module.is_some() || settings.is_some() {
                        return Err(de::Error::custom(
                            "a template and a source reference cannot be combined",
                        ));
                    }
                    if template.source.module.trim().is_empty()
                        || template.source.setting.trim().is_empty()
                    {
                        return Err(de::Error::custom("template source metadata is incomplete"));
                    }
                    return Ok(SecretRef::Template(template));
                }
                let module = module.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
                    de::Error::custom("a source reference needs a nonempty module")
                })?;
                if module == SECRET_MODULE_NONE {
                    return Ok(SecretRef::None);
                }
                Ok(SecretRef::Source(SourceReference {
                    module,
                    settings: settings.unwrap_or_default(),
                }))
            }
        }
        deserializer.deserialize_newtype_struct(context::REFERENCE, Reference)
    }
}

/// The canonical reference grammar; source shorthand is supplied only by owner metadata.
pub fn oneof_schema() -> serde_json::Value {
    serde_json::json!({"oneOf":[
        {"const":SECRET_MODULE_NONE},
        {"type":"object","properties":{"module":{"type":"string","pattern":NON_BLANK},"settings":{"type":"object"}},"required":["module"],"additionalProperties":false},
        {"type":"object","properties":{"template":{"type":"object","properties":{
            "text":{"type":"string"},"source":{"type":"object","properties":{"module":{"type":"string","pattern":NON_BLANK},"setting":{"type":"string","pattern":NON_BLANK}},"required":["module","setting"],"additionalProperties":false}
        },"required":["text","source"],"additionalProperties":false}},"required":["template"],"additionalProperties":false}
    ]})
}

/// The reference keys that are core secret-reference grammar, which no plugin may declare as its
const CORE_WORDS: [&str; 5] = [
    "module",
    "settings",
    SECRET_MODULE_NONE,
    "literal",
    "template",
];

/// ONE DECLARED SUGAR, as a secret plugin's Statement states it (its `REWRITE_SUGAR*` rewrites):
/// the shorthand `{ word: X }` the plugin answers to (audit contract-admin #10, Law 1: the plugin
/// declares it, the host names none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sugar {
    /// The reference key: the `k` in `{ k: X }`.
    pub word: String,
    /// The plugin whose Statement declares it.
    pub plugin: String,
    /// The settings key the value lands under (`REWRITE_SUGAR`'s `to`).
    pub setting: String,
    /// The placeholder its refusals show for the value (`REWRITE_SUGAR_SHOWN`; the settings key
    /// when unstated).
    pub shown: String,
    /// What the value names, in the refusal of a reference that does not set it
    /// (`REWRITE_SUGAR_NAMES`; `the <key>` when unstated).
    pub names: String,
}

impl Sugar {
    /// Validate only the scalar source position this owner explicitly declared.
    /// The result names declaration metadata, never the configured value.
    pub fn reference_refusal(&self, source: &SourceReference) -> Option<String> {
        if self.plugin != source.module {
            return None;
        }
        match source
            .settings
            .0
             .0
            .get(&self.setting)
            .and_then(serde_json::Value::as_str)
        {
            None => Some(format!(
                "secret module '{}' requires settings.{} ({})",
                source.module, self.setting, self.names
            )),
            Some(value) if value.trim().is_empty() => Some(format!(
                "secret module '{}' requires a NON-EMPTY settings.{} ({})",
                source.module, self.setting, self.names
            )),
            Some(_) => None,
        }
    }

    /// Build the canonical reference named by this admitted owner's declaration.
    pub fn reference(&self, value: impl Into<String>) -> SecretRef {
        SecretRef::Source(SourceReference {
            module: self.plugin.clone(),
            settings: serde_json::Map::from_iter([(
                self.setting.clone(),
                serde_json::Value::String(value.into()),
            )])
            .into(),
        })
    }
}

/// THE SUGARS THE LOADED STATEMENTS DECLARE, in word order: what the host reads secret references
/// against. Built only from Statements ([`Sugars::declare`]); empty, no shorthand is declared.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sugars {
    sugars: Vec<Sugar>,
    /// `(role, word)`: each role at most once.
    roles: Vec<(String, String)>,
}

impl Sugars {
    /// Construct a canonical reference from one admitted core grammar role.
    pub fn reference_for_role(
        &self,
        role: &str,
        value: impl Into<String>,
    ) -> Result<SecretRef, String> {
        self.with_role(role)
            .map(|source| source.reference(value))
            .ok_or_else(|| format!("no admitted source declares the '{role}' role"))
    }

    /// Declare every sugar `plugin`'s Statement rewrites state (`(class, from, to)`, as a Statement
    pub fn declare(
        &mut self,
        plugin: &str,
        rewrites: &[(u32, String, String)],
    ) -> Result<(), String> {
        use crate::abi::mechanism::door::{
            REWRITE_SUGAR, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE, REWRITE_SUGAR_SHOWN,
            SUGAR_ROLE_FILL, SUGAR_ROLE_PATH,
        };
        let mut mine: Vec<Sugar> = Vec::new();
        for (class, from, to) in rewrites {
            if *class != REWRITE_SUGAR {
                continue;
            }
            if CORE_WORDS.contains(&from.as_str()) {
                return Err(format!(
                    "plugin '{plugin}' declares the sugar `{from}:`, but `{from}` is core \
                     secret-reference grammar and no plugin may claim it"
                ));
            }
            if to.trim().is_empty() {
                return Err(format!(
                    "plugin '{plugin}' declares the sugar `{from}:` with no settings key \
                     for its value"
                ));
            }
            if let Some(other) = self
                .sugars
                .iter()
                .chain(mine.iter())
                .find(|s| s.word == *from)
            {
                return Err(format!(
                    "plugin claim conflict: the sugar `{from}:` is declared by both '{}' and \
                     '{plugin}' - a reference key must name one plugin; remove one",
                    other.plugin
                ));
            }
            mine.push(Sugar {
                word: from.clone(),
                plugin: plugin.to_string(),
                setting: to.clone(),
                shown: to.clone(),
                names: format!("the {to}"),
            });
        }
        let mut roles: Vec<(String, String)> = Vec::new();
        for (class, from, to) in rewrites {
            if ![REWRITE_SUGAR_SHOWN, REWRITE_SUGAR_NAMES, REWRITE_SUGAR_ROLE].contains(class) {
                continue;
            }
            let Some(sugar) = mine.iter_mut().find(|s| s.word == *from) else {
                return Err(format!(
                    "plugin '{plugin}' states a fact about the sugar `{from}:`, which its \
                     Statement does not declare"
                ));
            };
            match *class {
                REWRITE_SUGAR_SHOWN => sugar.shown = to.clone(),
                REWRITE_SUGAR_NAMES => sugar.names = to.clone(),
                _ => {
                    if ![SUGAR_ROLE_FILL, SUGAR_ROLE_PATH].contains(&to.as_str()) {
                        return Err(format!(
                            "plugin '{plugin}' gives the sugar `{from}:` the role '{to}', \
                             which the core grammar does not name"
                        ));
                    }
                    if let Some((_, word)) = self
                        .roles
                        .iter()
                        .chain(roles.iter())
                        .find(|(role, _)| role == to)
                    {
                        let other = self
                            .sugars
                            .iter()
                            .chain(mine.iter())
                            .find(|s| s.word == *word)
                            .map_or(plugin, |s| s.plugin.as_str());
                        return Err(format!(
                            "plugin claim conflict: the sugar role '{to}' is claimed by \
                             both '{other}' (`{word}:`) and '{plugin}' (`{from}:`) - a role names \
                             one sugar; remove one"
                        ));
                    }
                    roles.push((to.clone(), from.clone()));
                }
            }
        }
        self.sugars.extend(mine);
        self.sugars.sort_by(|a, b| a.word.cmp(&b.word));
        self.roles.extend(roles);
        Ok(())
    }

    /// Whether no sugar is declared.
    pub fn is_empty(&self) -> bool {
        self.sugars.is_empty()
    }

    /// The declared sugars, in word order.
    pub fn iter(&self) -> impl Iterator<Item = &Sugar> {
        self.sugars.iter()
    }

    /// The sugar `word` declares.
    pub fn get(&self, word: &str) -> Option<&Sugar> {
        self.sugars.iter().find(|s| s.word == word)
    }

    /// The sugar the core grammar's `role` names ([`SUGAR_ROLE_FILL`], [`SUGAR_ROLE_PATH`]).
    pub fn with_role(&self, role: &str) -> Option<&Sugar> {
        self.roles
            .iter()
            .find(|(r, _)| r == role)
            .and_then(|(_, word)| self.get(word))
    }
}

#[cfg(test)]
#[path = "tests/secret_ref_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/sugars_tests.rs"]
mod sugars_tests;

#[cfg(test)]
#[path = "tests/secret_ref_mutation_hardening.rs"]
mod mutation_hardening;
