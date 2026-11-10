// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Opaque configuration custody. Interpretation belongs to the receiving plugin.
//! Document serialization requires the kernel's concrete authoring authority. Settings themselves
//! have no serialization or readable-value interface.

mod owned;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An operator's settings object. Debug reveals names only, and every owned string is wiped.
/// No map/value accessor or typed owner-schema decoder is available to host code.
///
/// ```compile_fail
/// let settings = busbar_contract::plugin_settings::Settings::default();
/// let _ = serde_json::to_value(&settings);
/// ```
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Settings(pub(crate) Tree);

/// Resolved owner settings. Only a guarded boundary encoding leaves this holder.
///
/// ```compile_fail
/// let held = busbar_contract::plugin_settings::ResolvedSettings::default();
/// let _ = held.get("password");
/// ```
/// ```compile_fail
/// let held = busbar_contract::plugin_settings::ResolvedSettings::default();
/// let _ = serde_json::to_value(&held);
/// ```
#[derive(Clone, Default)]
pub struct ResolvedSettings(Tree);

/// Field metadata admitted from the receiving owner's declaration.
#[derive(Debug)]
pub struct Resolution<'a> {
    /// Receiving owner, for diagnostics.
    pub owner: &'a str,
    /// Paths which must carry references rather than inline secret values.
    pub secrets: &'a [String],
    /// Paths which may carry references or ordinary values.
    pub references: &'a [String],
    /// Source shorthand declared by admitted source owners.
    pub sources: &'a crate::secret_ref::Sugars,
}

/// Resolver for a typed source reference; its answer retains sealed custody.
pub type ReferenceResolver<'a> =
    dyn Fn(&crate::secret_ref::SecretRef) -> Result<crate::Secret<Vec<u8>>, String> + 'a;
/// Settings and ordered sealed credential slots prepared for a kind's lending ABI.
pub type LentSettings = (ResolvedSettings, Vec<crate::Secret<Vec<u8>>>);

pub(crate) enum ReferenceDelivery<'a> {
    Retain,
    Strip(&'a str),
}

/// A borrowed document view issued only with concrete kernel authority.
/// The view preserves authored JSON; creating it grants access equivalent to a guarded-byte borrow.
///
/// ```compile_fail
/// let settings = busbar_contract::plugin_settings::Settings::default();
/// let _ = busbar_contract::plugin_settings::Authoring { settings: &settings };
/// ```
#[derive(Debug)]
pub struct Authoring<'a> {
    settings: &'a Settings,
}

impl Settings {
    /// Borrow the original document shape for an authorized persistence or admin operation.
    /// A generic transport grant or caller-implemented seal is insufficient.
    ///
    /// ```compile_fail
    /// fn read(settings: &busbar_contract::plugin_settings::Settings, seal: &dyn busbar_contract::plugin::KernelSeal) {
    ///     let _ = settings.authoring(seal);
    /// }
    /// ```
    pub fn authoring<'a>(&'a self, _seal: &'a crate::caps::KernelSeal) -> Authoring<'a> {
        self.writing()
    }
    // Only fixed SDK encoders and guarded normalization use this internal view.
    pub(crate) fn writing(&self) -> Authoring<'_> {
        Authoring { settings: self }
    }
    /// Public configuration member names, for diagnostics and redacted admin projections.
    pub fn key_names(&self) -> Vec<String> {
        self.0
             .0
            .as_object()
            .expect("settings object")
            .keys()
            .cloned()
            .collect()
    }
    /// Whether the settings object has no members.
    pub fn is_empty(&self) -> bool {
        self.0 .0.as_object().expect("settings object").is_empty()
    }
    /// Apply explicit top-level document edits; omitted keys retain their guarded values.
    pub fn edit(&self, set: &Self, remove: &[String]) -> Result<Self, String> {
        let additions = set.0 .0.as_object().expect("settings object");
        if remove.iter().any(|key| additions.contains_key(key)) {
            return Err("a settings edit cannot both set and remove the same key".into());
        }
        let mut edited = self.clone();
        let object = edited.0 .0.as_object_mut().expect("settings object");
        for key in remove {
            if let Some((mut key, mut value)) = object.remove_entry(key) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        for (key, value) in additions {
            if let Some(slot) = object.get_mut(key) {
                wipe(slot);
                *slot = value.clone();
            } else {
                object.insert(key.clone(), value.clone());
            }
        }
        Ok(edited)
    }

    /// Encode for the kind boundary, keeping the output in kernel custody.
    pub fn encode(&self) -> Result<crate::Secret<Vec<u8>>, serde_json::Error> {
        self.0.encode()
    }

    /// Retain the written configuration for the owner's validation call, without resolving it.
    pub fn prepare(&self) -> ResolvedSettings {
        ResolvedSettings(self.0.clone())
    }

    /// Resolve only fields admitted by owner metadata, retaining all resulting material.
    pub fn resolve(
        &self,
        rules: &Resolution<'_>,
        resolver: &dyn crate::secret::SecretResolve,
        scope: &crate::config_time::ConfigScope,
    ) -> Result<ResolvedSettings, String> {
        self.resolve_with_literals(rules, resolver, scope, false)
    }

    pub(crate) fn resolve_with_literals(
        &self,
        rules: &Resolution<'_>,
        resolver: &dyn crate::secret::SecretResolve,
        scope: &crate::config_time::ConfigScope,
        allow_literals: bool,
    ) -> Result<ResolvedSettings, String> {
        use crate::secret_fields as fields;
        if let Some(path) = fields::contradiction(rules.secrets, rules.references) {
            return Err(fields::contradiction_refusal(&path, rules.owner));
        }
        let mut held = ResolvedSettings(self.0.clone());
        canonicalize(&mut held.0 .0, rules.sources)?;
        let paths = [rules.secrets, rules.references].concat();
        if let Some(at) = fields::undeclared_reference(&held.0 .0, &paths) {
            return Err(fields::undeclared_refusal(
                &format!("settings.{at}"),
                rules.owner,
            ));
        }
        if !allow_literals {
            if let Some(at) = fields::declared_literal(&held.0 .0, rules.secrets) {
                return Err(fields::declared_literal_refusal(
                    &format!("settings.{at}"),
                    rules.owner,
                ));
            }
        }
        for path in &paths {
            for at in fields::declared_references(&held.0 .0, path) {
                let slot = fields::value_at_mut(&mut held.0 .0, &at).expect("matched position");
                let reference: crate::secret_ref::SecretRef =
                    crate::secret_ref::context::deserialize(Tree(slot.clone()), rules.sources)
                        .map_err(|_| "invalid secret reference (value not echoed)".to_owned())?;
                let field = at.join(".");
                let secret = rules.secrets.contains(path);
                if secret {
                    tracing::info!(setting = field.as_str(), reference = %reference.describe(),
                        "plugin setting resolved as a SECRET REFERENCE at a field the plugin declares secret");
                } else {
                    tracing::info!(setting = field.as_str(), reference = %reference.describe(),
                        "plugin setting resolved as a REFERENCE at a field the plugin declares reference-capable (not secret)");
                }
                let mut value = resolver
                    .resolve_string_at_config(&reference, scope)
                    .map_err(|error| {
                        format!(
                            "plugin setting '{field}' is a {}reference that did not resolve: {error}",
                            if secret { "secret " } else { "" }
                        )
                    })?;
                wipe(slot);
                *slot = Value::String(std::mem::take(&mut value.0));
            }
        }
        for value in held
            .0
             .0
            .as_object_mut()
            .expect("settings object")
            .values_mut()
        {
            if let Value::Object(object) = value {
                if object.len() == 1 {
                    if let Some(inner) = object.get_mut(fields::LITERAL_KEY) {
                        let inner = std::mem::take(inner);
                        wipe(value);
                        *value = inner;
                    }
                }
            }
        }
        Ok(held)
    }

    /// Project only fields the owner declares public, for generic admin rendering.
    /// The host must authorize the field selection; a caller cannot declare arbitrary values public.
    ///
    /// ```compile_fail
    /// let settings = busbar_contract::plugin_settings::Settings::default();
    /// let _ = settings.public_view(&Default::default());
    /// ```
    /// ```compile_fail
    /// fn project(settings: &busbar_contract::plugin_settings::Settings,
    ///            seal: &dyn busbar_contract::plugin::KernelSeal) {
    ///     let _ = settings.public_view(seal, &Default::default());
    /// }
    /// ```
    pub fn public_view(
        &self,
        _seal: &crate::caps::KernelSeal,
        public: &std::collections::BTreeSet<String>,
    ) -> RedactedSettings {
        RedactedSettings(crate::settings_public::public_view(
            self.0 .0.as_object().expect("settings object"),
            public,
        ))
    }

    /// Resolve declared reference slots into sealed credential arguments for a kind boundary.
    pub fn lend_references(
        &self,
        declared: &[String],
        sources: &crate::secret_ref::Sugars,
        owner: &str,
        resolve: &ReferenceResolver<'_>,
    ) -> Result<LentSettings, String> {
        self.prepare().lend_references_with(
            declared,
            sources,
            owner,
            resolve,
            ReferenceDelivery::Retain,
        )
    }

    /// Public generation snapshot, additionally excluding credential-like keys and references.
    ///
    /// ```compile_fail
    /// let settings = busbar_contract::plugin_settings::Settings::default();
    /// let _ = settings.snapshot_view(&Default::default(), &Default::default());
    /// ```
    /// ```compile_fail
    /// fn project(settings: &busbar_contract::plugin_settings::Settings,
    ///            seal: &dyn busbar_contract::plugin::KernelSeal) {
    ///     let _ = settings.snapshot_view(seal, &Default::default(), &Default::default());
    /// }
    /// ```
    pub fn snapshot_view(
        &self,
        _seal: &crate::caps::KernelSeal,
        public: &std::collections::BTreeSet<String>,
        sources: &crate::secret_ref::Sugars,
    ) -> RedactedSettings {
        fn safe(key: &str, value: &Value, sources: &crate::secret_ref::Sugars) -> bool {
            let lower = key.to_ascii_lowercase();
            if [
                "token",
                "secret",
                "password",
                "credential",
                "private_key",
                "api_key",
            ]
            .iter()
            .any(|word| lower.contains(word))
            {
                return false;
            }
            match value {
                Value::Object(map) => {
                    !map.contains_key(crate::secret_fields::LITERAL_KEY)
                        && !(map.contains_key("module") && map.contains_key("settings"))
                        && !map.keys().any(|key| sources.get(key).is_some())
                        && map.iter().all(|(key, value)| safe(key, value, sources))
                }
                Value::Array(values) => values.iter().all(|value| safe("", value, sources)),
                _ => true,
            }
        }
        RedactedSettings(
            self.0
                 .0
                .as_object()
                .expect("settings object")
                .iter()
                .filter(|(key, value)| public.contains(*key) && safe(key, value, sources))
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        )
    }

    /// Source module identities referenced at owner-declared positions, for bootstrap ordering.
    pub fn reference_modules(
        &self,
        declared: &[String],
        sources: &crate::secret_ref::Sugars,
    ) -> Result<std::collections::BTreeSet<String>, String> {
        let mut tree = self.0.clone();
        canonicalize(&mut tree.0, sources)?;
        let mut modules = std::collections::BTreeSet::new();
        for path in declared {
            for at in crate::secret_fields::declared_references(&tree.0, path) {
                if let Some(value) = crate::secret_fields::value_at_mut(&mut tree.0, &at) {
                    let reference = crate::secret_ref::context::deserialize::<
                        crate::secret_ref::SecretRef,
                        _,
                    >(Tree(value.clone()), sources)
                    .map_err(|_| {
                        "invalid declared source reference (value not echoed)".to_owned()
                    })?;
                    if let Some(module) = reference.source_module() {
                        modules.insert(module.to_owned());
                    }
                }
            }
        }
        Ok(modules)
    }

    /// Find a reference outside the receiving owner's declared paths without exposing values.
    pub fn undeclared_reference(
        &self,
        declared: &[String],
        sources: &crate::secret_ref::Sugars,
    ) -> Result<Option<String>, String> {
        let mut tree = self.0.clone();
        canonicalize(&mut tree.0, sources)?;
        Ok(crate::secret_fields::undeclared_reference(
            &tree.0, declared,
        ))
    }

    /// Report changed non-reference keys for generic configuration drift diagnostics.
    /// Reference values are never compared with the resolved values a plugin reports.
    pub fn drift_keys(
        &self,
        observed: &Settings,
        sources: &crate::secret_ref::Sugars,
    ) -> Vec<String> {
        let observed = observed.0 .0.as_object().expect("settings object");
        self.0
             .0
            .as_object()
            .expect("settings object")
            .iter()
            .filter_map(|(key, written)| {
                let expected = match written {
                    Value::Object(object)
                        if object.len() == 1
                            && object.contains_key(crate::secret_fields::LITERAL_KEY) =>
                    {
                        &object[crate::secret_fields::LITERAL_KEY]
                    }
                    value
                        if value.is_object()
                            && crate::secret_ref::context::deserialize::<
                                crate::secret_ref::SecretRef,
                                _,
                            >(Tree(value.clone()), sources)
                            .is_ok() =>
                    {
                        return None
                    }
                    value => value,
                };
                (observed.get(key) != Some(expected)).then(|| key.clone())
            })
            .collect()
    }
}

/// An explicitly public admin projection, separated from the original settings holder.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(transparent)]
pub struct RedactedSettings(Map<String, Value>);

impl From<Value> for ResolvedSettings {
    fn from(value: Value) -> Self {
        Self(Tree(value))
    }
}

impl ResolvedSettings {
    pub(crate) fn lend_references_with(
        &self,
        declared: &[String],
        sources: &crate::secret_ref::Sugars,
        owner: &str,
        resolve: &ReferenceResolver<'_>,
        delivery: ReferenceDelivery<'_>,
    ) -> Result<LentSettings, String> {
        let prefix = match delivery {
            ReferenceDelivery::Retain => format!("secrets.{owner}.settings"),
            ReferenceDelivery::Strip(_) => "settings".to_owned(),
        };
        let mut settings = self.0.clone();
        canonicalize(&mut settings.0, sources)?;
        if let Some(at) = crate::secret_fields::undeclared_reference(&settings.0, declared) {
            return Err(crate::secret_fields::undeclared_refusal(
                &format!(
                    "{}.{at}",
                    match delivery {
                        ReferenceDelivery::Retain => prefix.as_str(),
                        ReferenceDelivery::Strip(base) => base,
                    }
                ),
                owner,
            ));
        }
        let reference = |at: &str, value: Value| {
            let value = Tree(value);
            let reference = crate::secret_ref::context::deserialize::<
                crate::secret_ref::SecretRef,
                _,
            >(value, sources)
            .map_err(|_| {
                format!("{prefix}.{at}: not a secret reference: a field is missing or has the wrong type (the decoder's text is withheld)")
            })?;
            resolve(&reference)
                .map_err(|error| format!("{prefix}.{at}: the secret did not resolve: {error}"))
        };
        let secrets = crate::secret_fields::lend(
            &mut settings.0,
            declared,
            matches!(delivery, ReferenceDelivery::Retain),
            |at, value| value.map_or(Ok(crate::Secret::default()), |value| reference(at, value)),
            reference,
        )?;
        Ok((ResolvedSettings(settings), secrets))
    }

    /// Encode the resolved settings for the receiving kind boundary.
    pub fn encode(&self) -> Result<crate::Secret<Vec<u8>>, serde_json::Error> {
        self.0.encode()
    }
    /// Separate declared credential slots for a kind's credential lending ABI.
    /// Both the remaining document and every extracted value retain sealed custody.
    pub fn lend_secrets(&self, declared: &[String]) -> (Self, Vec<crate::Secret<Vec<u8>>>) {
        let mut remaining = self.clone();
        let held = |value: Option<Value>| {
            let mut value = Tree(value.unwrap_or(Value::Null));
            let bytes = match &mut value.0 {
                Value::String(text) => std::mem::take(text).into_bytes(),
                _ => Vec::new(),
            };
            crate::Secret::from(bytes)
        };
        let secrets = crate::secret_fields::lend(
            &mut remaining.0 .0,
            declared,
            false,
            |_, value| Ok::<_, std::convert::Infallible>(held(value)),
            |_, value| Ok(held(Some(value))),
        )
        .unwrap_or_else(|error| match error {});
        (remaining, secrets)
    }

    /// Add a kind-owned public default without reading owner settings.
    pub fn default_text(&mut self, key: &str, value: String) {
        use serde_json::map::Entry;
        match self
            .0
             .0
            .as_object_mut()
            .expect("settings object")
            .entry(key)
        {
            Entry::Vacant(slot) => {
                slot.insert(Value::String(value));
            }
            Entry::Occupied(_) => {
                let mut value = value;
                value.zeroize();
            }
        }
    }
    /// Lend an already guarded credential to an exact path declared by its receiving owner.
    /// The receiving field must appear in its admitted secret declaration.
    pub fn insert_secret(
        &mut self,
        path: &str,
        declared: &[String],
        mut value: crate::Secret<String>,
    ) -> Result<(), String> {
        if path.is_empty()
            || crate::secret_fields::is_wildcard(path)
            || !declared.iter().any(|p| p == path)
        {
            return Err("an injected credential requires one exact declared settings path".into());
        }
        let segments: Vec<_> = path.split('.').collect();
        let mut target = &mut self.0 .0;
        for segment in &segments[..segments.len() - 1] {
            target = target
                .as_object_mut()
                .ok_or("credential path crosses a non-object")?
                .entry(*segment)
                .or_insert_with(|| Value::Object(Map::new()));
        }
        let slot = target
            .as_object_mut()
            .ok_or("credential path crosses a non-object")?
            .entry(*segments.last().expect("nonempty path"))
            .or_insert(Value::Null);
        wipe(slot);
        *slot = Value::String(std::mem::take(&mut value.0));
        Ok(())
    }
}
impl fmt::Debug for ResolvedSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResolvedSettings(<redacted>)")
    }
}
impl Zeroize for ResolvedSettings {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for ResolvedSettings {}

fn canonicalize(tree: &mut Value, sources: &crate::secret_ref::Sugars) -> Result<(), String> {
    match tree {
        Value::Object(object) => {
            if object.len() == 1 && object.contains_key(crate::secret_fields::LITERAL_KEY) {
                return Ok(());
            }
            if object.len() == 1
                && object
                    .keys()
                    .next()
                    .is_some_and(|key| sources.get(key).is_some())
            {
                let reference: crate::secret_ref::SecretRef =
                    crate::secret_ref::context::deserialize(Tree(tree.clone()), sources).map_err(
                        |_| "invalid declared source reference (value not echoed)".to_owned(),
                    )?;
                let canonical = serde_json::to_value(reference.writing())
                    .map_err(|_| "cannot encode source reference".to_owned())?;
                wipe(tree);
                *tree = canonical;
            } else if !(object.contains_key("module")
                && object
                    .keys()
                    .all(|key| key == "module" || key == "settings"))
            {
                for child in object.values_mut() {
                    canonicalize(child, sources)?;
                }
            }
        }
        Value::Array(items) => {
            for child in items {
                canonicalize(child, sources)?;
            }
        }
        _ => {}
    }
    Ok(())
}
impl From<Map<String, Value>> for Settings {
    fn from(map: Map<String, Value>) -> Self {
        Self(Tree(Value::Object(map)))
    }
}
impl fmt::Debug for Settings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("keys", &self.key_names())
            .finish_non_exhaustive()
    }
}
impl Serialize for Authoring<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.settings.0 .0.serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Settings {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let tree = Tree::deserialize(deserializer)?;
        if !tree.0.is_object() {
            return Err(de::Error::custom(
                "plugin settings must be an object (values not echoed)",
            ));
        }
        Ok(Self(tree))
    }
}
impl Zeroize for Settings {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl ZeroizeOnDrop for Settings {}

/// An owned JSON tree whose partially constructed values remain guarded on serde errors.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Tree(pub(crate) Value);
impl Default for Tree {
    fn default() -> Self {
        Self(Value::Object(Map::new()))
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Zeroize for Tree {
    fn zeroize(&mut self) {
        wipe(&mut self.0);
    }
}
impl Tree {
    pub(crate) fn encode(&self) -> Result<crate::Secret<Vec<u8>>, serde_json::Error> {
        let mut output = Wiping(Zeroizing::new(Vec::new()));
        serde_json::to_writer(&mut output, &self.0)?;
        Ok(crate::Secret::new(std::mem::take(&mut *output.0)))
    }
    fn take(&mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}
fn wipe(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(values) => values.iter_mut().for_each(wipe),
        Value::Object(map) => {
            for (mut key, mut value) in std::mem::take(map) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        _ => {}
    }
}
impl<'de> Deserialize<'de> for Tree {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Capture;
        impl<'de> Visitor<'de> for Capture {
            type Value = Tree;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON-compatible settings")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Tree, E> {
                Ok(Tree(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Tree, E> {
                self.visit_unit()
            }
            fn visit_bool<E: de::Error>(self, value: bool) -> Result<Tree, E> {
                Ok(Tree(Value::Bool(value)))
            }
            fn visit_i64<E: de::Error>(self, value: i64) -> Result<Tree, E> {
                Ok(Tree(value.into()))
            }
            fn visit_u64<E: de::Error>(self, value: u64) -> Result<Tree, E> {
                Ok(Tree(value.into()))
            }
            fn visit_f64<E: de::Error>(self, value: f64) -> Result<Tree, E> {
                serde_json::Number::from_f64(value)
                    .map(|v| Tree(Value::Number(v)))
                    .ok_or_else(|| de::Error::custom("a settings number must be finite"))
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Tree, E> {
                self.visit_string(value.to_owned())
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<Tree, E> {
                Ok(Tree(Value::String(value)))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Tree, A::Error> {
                let mut tree = Tree(Value::Array(Vec::new()));
                while let Some(mut value) = sequence.next_element::<Tree>()? {
                    tree.0.as_array_mut().expect("array").push(value.take());
                }
                Ok(tree)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Tree, A::Error> {
                let mut tree = Tree(Value::Object(Map::new()));
                while let Some((mut key, mut value)) =
                    map.next_entry::<Zeroizing<String>, Tree>()?
                {
                    let object = tree.0.as_object_mut().expect("object");
                    if let Some(replaced) = object.get_mut(key.as_str()) {
                        wipe(replaced);
                        *replaced = value.take();
                    } else {
                        object.insert(std::mem::take(&mut *key), value.take());
                    }
                }
                Ok(tree)
            }
        }
        // serde_json represents exact numbers as synthetic maps in deserialize_any.
        // Request its raw-token protocol first so a physical object containing the
        // number marker is never mistaken for that transport. Other formats enter
        // through the ordinary newtype visitor and keep their native scalar types.
        struct Format;
        impl<'de> Visitor<'de> for Format {
            type Value = Tree;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON-compatible settings document")
            }
            fn visit_newtype_struct<D: Deserializer<'de>>(self, de: D) -> Result<Tree, D::Error> {
                de.deserialize_any(Capture)
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Tree, A::Error> {
                let key = map.next_key::<Zeroizing<String>>()?;
                if key.as_deref().map(String::as_str) != Some(RAW_JSON_TOKEN) {
                    return Err(de::Error::custom("invalid raw settings document"));
                }
                let tree = map.next_value_seed(RawTree)?;
                if map.next_key::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("invalid raw settings document"));
                }
                Ok(tree)
            }
        }
        deserializer.deserialize_newtype_struct(RAW_JSON_TOKEN, Format)
    }
}

// The serde_json RawValue newtype protocol, also used by our guarded owned deserializer.
const RAW_JSON_TOKEN: &str = "$serde_json::private::RawValue";

struct RawTree;
impl<'de> DeserializeSeed<'de> for RawTree {
    type Value = Tree;
    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Tree, D::Error> {
        de.deserialize_str(self)
    }
}
impl<'de> Visitor<'de> for RawTree {
    type Value = Tree;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("raw settings JSON")
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<Tree, E> {
        // This parser uses input-span provenance to distinguish real object keys
        // from numeric transport tags; decoded strings and partial trees are wiped.
        let mut held = crate::abi::sdk::cred::protected_json::document(text.as_bytes(), false)
            .map_err(|_| E::custom("invalid settings JSON (values not echoed)"))?;
        Ok(Tree(std::mem::take(&mut held.0)))
    }
    fn visit_string<E: de::Error>(self, text: String) -> Result<Tree, E> {
        self.visit_str(&Zeroizing::new(text))
    }
}

#[cfg(test)]
mod exact_number_tests {
    use super::*;

    #[test]
    fn settings_keep_exact_json_numbers_and_physical_marker_keys() {
        let raw = r#"{"$serde_json::private::Number":"123","n":1e999,"fraction":1.00000000000000001,"wide":18446744073709551616,"nested":{"$serde_json::private::Number":"456","other":true},"duplicate":"old-secret","duplicate":"new-secret"}"#;
        let settings: Settings = serde_json::from_str(raw).unwrap();
        let expected = crate::json_grammar::parse_value(raw.as_bytes()).unwrap();
        assert_eq!(serde_json::to_value(settings.writing()).unwrap(), expected);

        // Value-backed deserialization must keep a real marker object as an object too.
        let settings: Settings = serde_json::from_value(expected.clone()).unwrap();
        assert_eq!(serde_json::to_value(settings.writing()).unwrap(), expected);
        let escaped: Settings =
            serde_json::from_str(r#"{"\u0024serde_json::private::Number":"123"}"#).unwrap();
        assert_eq!(escaped.key_names(), ["$serde_json::private::Number"]);
        assert_eq!(
            serde_json::to_value(escaped.writing()).unwrap(),
            serde_json::json!({"$serde_json::private::Number":"123"})
        );
    }

    #[test]
    fn yaml_markers_are_ordinary_settings_and_nonfinite_numbers_are_refused() {
        let yaml = "'$serde_json::private::Number': '123'\n'$serde_json::private::RawValue': 'null'\nnested: {a: 1.5, b: 18446744073709551615}\n";
        let expected = serde_json::json!({
            "$serde_json::private::Number": "123",
            "$serde_json::private::RawValue": "null",
            "nested": {"a": 1.5, "b": u64::MAX},
        });
        let direct: Settings = serde_yaml::from_str(yaml).unwrap();
        let value: Settings = serde_yaml::from_value(serde_yaml::from_str(yaml).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(direct.writing()).unwrap(), expected);
        assert_eq!(serde_json::to_value(value.writing()).unwrap(), expected);
        assert!(serde_yaml::from_str::<Settings>("value: .inf").is_err());
    }
}

/// Growth moves into a new guarded allocation and wipes the previous block before freeing it.
struct Wiping(Zeroizing<Vec<u8>>);
impl std::io::Write for Wiping {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.capacity() - self.0.len() < bytes.len() {
            let size = self
                .0
                .len()
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("settings too large"))?;
            let mut next = Zeroizing::new(Vec::with_capacity(
                size.max(self.0.capacity().saturating_mul(2)),
            ));
            next.extend_from_slice(&self.0);
            self.0 = next;
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Resolver;
    impl crate::secret::SecretResolve for Resolver {
        fn resolve(
            &self,
            _: &crate::secret_ref::SecretRef,
        ) -> Result<crate::Secret<Vec<u8>>, String> {
            Ok(crate::Secret::new(b"resolved-canary".to_vec()))
        }
        fn resolve_string(
            &self,
            _: &crate::secret_ref::SecretRef,
        ) -> Result<crate::Secret<String>, String> {
            Ok(crate::Secret::new("resolved-canary".to_owned()))
        }
    }

    #[test]
    fn resolution_retains_custody_and_enforces_owner_declarations() {
        let mut sources = crate::secret_ref::Sugars::default();
        sources
            .declare(
                "source-owner",
                &[(
                    crate::abi::mechanism::door::REWRITE_SUGAR,
                    "cabinet".into(),
                    "entry".into(),
                )],
            )
            .unwrap();
        let secrets = vec!["nested.password".into()];
        let references = vec!["destination".into()];
        let rules = Resolution {
            owner: "receiving-owner",
            secrets: &secrets,
            references: &references,
            sources: &sources,
        };
        let original = serde_json::json!({"module":"ordinary-data", "nested":{"password":{"cabinet":"descriptor"}},"destination":{"cabinet":"public-location"},"literal":{"literal":{"cabinet":"owner-data"}}});
        let settings: Settings = serde_json::from_value(original.clone()).unwrap();
        let mut resolved = settings
            .resolve(
                &rules,
                &Resolver,
                &crate::config_time::ConfigScope::config_time(),
            )
            .unwrap();
        assert!(!format!("{resolved:?}").contains("resolved-canary"));
        let bytes = resolved.encode().unwrap();
        let wire: Value = serde_json::from_slice(&bytes.0).unwrap();
        assert_eq!(wire["nested"]["password"], "resolved-canary");
        assert_eq!(wire["destination"], "resolved-canary");
        assert_eq!(wire["literal"]["cabinet"], "owner-data");
        assert_eq!(serde_json::to_value(settings.writing()).unwrap(), original);
        assert!(resolved
            .insert_secret(
                "undeclared",
                &secrets,
                crate::Secret::new("not-injected".into())
            )
            .is_err());
        resolved
            .insert_secret(
                "nested.password",
                &secrets,
                crate::Secret::new("replacement-canary".into()),
            )
            .unwrap();
        let wire: Value = serde_json::from_slice(&resolved.encode().unwrap().0).unwrap();
        assert_eq!(wire["nested"]["password"], "replacement-canary");
        let unlisted: Settings =
            serde_json::from_value(serde_json::json!({"other":{"cabinet":"descriptor"}})).unwrap();
        assert!(unlisted
            .resolve(
                &rules,
                &Resolver,
                &crate::config_time::ConfigScope::config_time()
            )
            .unwrap_err()
            .contains("did not declare"));
        let inline: Settings =
            serde_json::from_value(serde_json::json!({"nested":{"password":"inline-canary"}}))
                .unwrap();
        let refused = inline
            .resolve(
                &rules,
                &Resolver,
                &crate::config_time::ConfigScope::config_time(),
            )
            .unwrap_err();
        assert!(!refused.contains("inline-canary"));
        assert!(refused.contains("REFERENCE"));
    }
    /// A resolver whose config-time text comes from an allocation it records: where the value it
    /// handed out lives.
    #[derive(Default)]
    struct Recorded(std::sync::Mutex<Vec<usize>>);

    impl busbar_contract::secret::SecretResolve for Recorded {
        fn resolve(
            &self,
            _secret: &crate::secret_ref::SecretRef,
        ) -> Result<busbar_contract::redacted::Secret<Vec<u8>>, String> {
            Err("refused off config time".to_string())
        }

        fn resolve_string(
            &self,
            _secret: &crate::secret_ref::SecretRef,
        ) -> Result<busbar_contract::redacted::Secret<String>, String> {
            Err("refused off config time".to_string())
        }

        fn resolve_string_at_config(
            &self,
            _secret: &crate::secret_ref::SecretRef,
            _scope: &busbar_contract::config_time::ConfigScope,
        ) -> Result<busbar_contract::redacted::Secret<String>, String> {
            let text = String::from("MOVED-NEVER-COPIED");
            self.0.lock().unwrap().push(text.as_ptr() as usize);
            Ok(busbar_contract::redacted::Secret::new(text))
        }
    }

    #[test]
    fn a_resolved_setting_is_moved_into_the_bag_never_copied() {
        let reference =
            serde_json::json!({"module":"allocation-source","settings":{"slot":"unused"}});
        let settings: Settings = serde_json::from_value(
            serde_json::json!({"licenseKey":reference.clone(),"url":reference}),
        )
        .unwrap();
        let resolver = Recorded::default();
        let out = settings
            .resolve(
                &Resolution {
                    owner: "test-plugin",
                    secrets: &["licenseKey".into()],
                    references: &["url".into()],
                    sources: &crate::secret_ref::Sugars::default(),
                },
                &resolver,
                &crate::config_time::ConfigScope::config_time(),
            )
            .expect("resolves");
        let handed = resolver.0.lock().unwrap().clone();
        let held: Vec<usize> = ["licenseKey", "url"]
            .iter()
            .map(|k| out.0 .0[*k].as_str().expect("a string").as_ptr() as usize)
            .collect();
        assert_eq!(held, handed, "each value is the resolver's own allocation");
    }

    #[test]
    fn explicit_edits_and_lending_preserve_custody_and_document_semantics() {
        let original: Settings = serde_json::from_value(serde_json::json!({
            "password":"credential-canary", "retained":"private-canary", "removed":"erase-canary", "nullable":7
        })).unwrap();
        let set: Settings = serde_json::from_value(serde_json::json!({"nullable":null})).unwrap();
        let edited = original.edit(&set, &["removed".into()]).unwrap();
        assert_eq!(
            serde_json::to_value(edited.writing()).unwrap(),
            serde_json::json!({
                "password":"credential-canary", "retained":"private-canary", "nullable":null
            })
        );
        assert!(original.edit(&set, &["nullable".into()]).is_err());
        let (remaining, secrets) = edited.prepare().lend_secrets(&["password".into()]);
        assert_eq!(secrets.len(), 1);
        assert_eq!(secrets[0].0, b"credential-canary");
        let remaining: Value = serde_json::from_slice(&remaining.encode().unwrap().0).unwrap();
        assert_eq!(remaining["retained"], "private-canary");
        assert!(!remaining.to_string().contains("credential-canary"));
        assert!(!format!("{edited:?} {secrets:?}").contains("credential-canary"));
    }

    #[test]
    fn settings_round_trip_without_debug_or_readable_map_access() {
        let original =
            serde_json::json!({"password":"secret-canary","nested":{"value":"other-canary"}});
        let settings: Settings = serde_json::from_value(original.clone()).unwrap();
        assert_eq!(serde_json::to_value(settings.writing()).unwrap(), original);
        assert_eq!(settings.key_names(), ["nested", "password"]);
        let shown = format!("{settings:?}");
        assert!(!shown.contains("secret-canary"));
        assert!(!shown.contains("other-canary"));
        assert_eq!(
            serde_json::from_slice::<Value>(&settings.encode().unwrap().0).unwrap(),
            original
        );
        assert!(Settings::default().is_empty());
        assert!(serde_json::from_str::<Settings>(r#"["secret-canary"]"#).is_err());
    }
}

#[cfg(test)]
mod template_admission_tests {
    use super::*;
    struct MustNotResolve;
    impl crate::secret::SecretResolve for MustNotResolve {
        fn resolve(
            &self,
            _: &crate::secret_ref::SecretRef,
        ) -> Result<crate::Secret<Vec<u8>>, String> {
            panic!("unadmitted template reached its resolver")
        }
        fn resolve_string(
            &self,
            _: &crate::secret_ref::SecretRef,
        ) -> Result<crate::Secret<String>, String> {
            panic!("unadmitted template reached its resolver")
        }
    }
    #[test]
    fn forged_template_source_refuses_before_resolution_or_dependency_selection() {
        use crate::abi::mechanism::door::{REWRITE_SUGAR, REWRITE_SUGAR_ROLE, SUGAR_ROLE_FILL};
        let mut sources = crate::secret_ref::Sugars::default();
        sources
            .declare(
                "admitted-source",
                &[
                    (REWRITE_SUGAR, "lookup".into(), "slot".into()),
                    (REWRITE_SUGAR_ROLE, "lookup".into(), SUGAR_ROLE_FILL.into()),
                ],
            )
            .unwrap();
        for (owner, setting) in [
            ("unadmitted-source", "slot"),
            ("admitted-source", "other-slot"),
        ] {
            let settings: Settings =
                serde_json::from_value(serde_json::json!({"token":{"template":{
                    "text":"private-canary ${A}", "source":{"module":owner,"setting":setting}
                }}}))
                .unwrap();
            let paths = ["token".to_owned()];
            let error = settings
                .resolve(
                    &Resolution {
                        owner: "receiving-owner",
                        secrets: &paths,
                        references: &[],
                        sources: &sources,
                    },
                    &MustNotResolve,
                    &crate::config_time::ConfigScope::config_time(),
                )
                .unwrap_err();
            assert!(error.contains("invalid secret reference"), "{error}");
            assert!(!error.contains("private-canary"));
            assert!(settings.reference_modules(&paths, &sources).is_err());
        }
    }
}
