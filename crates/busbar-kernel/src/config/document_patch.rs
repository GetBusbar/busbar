// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Lowest-precedence, boot-shaped document edits. Sequence edits use strict indices
//! from the request snapshot. No field is presumed safe to print.

use std::fmt;

use serde::Deserialize;
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

#[path = "document_source.rs"]
mod source;

/// Private composition metadata; never serialized or exposed as an admin digest. Hash only the
/// exact preprocessed operator text consumed by the loader, before durable stages are applied.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SourceFingerprints {
    config: [u8; 32],
    catalog: [u8; 32],
}
impl fmt::Debug for SourceFingerprints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceFingerprints([PRIVATE])")
    }
}
impl SourceFingerprints {
    /// Private binding for startup/recovery custody, never an admin-visible digest.
    pub fn binding_digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut digest = sha2::Sha256::new();
        digest.update(b"busbar.configuration.sources.1\0");
        digest.update(self.config);
        digest.update(self.catalog);
        digest.finalize().into()
    }

    pub fn from_sources(config: &str, catalog: &str) -> Self {
        Self {
            config: source_digest(config),
            catalog: source_digest(catalog),
        }
    }
}
fn source_digest(text: &str) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(text.as_bytes()).into()
}

/// A loader-local refusal flag lets the admin boundary distinguish source drift (409) from
/// invalid configuration (400), without comparing error strings or revealing source hashes.
pub struct SourceAdmission {
    expected: SourceFingerprints,
    config: bool,
    catalog: bool,
    drifted: bool,
}
impl SourceAdmission {
    pub fn new(expected: SourceFingerprints, config: bool, catalog: bool) -> Self {
        Self {
            expected,
            config,
            catalog,
            drifted: false,
        }
    }
    pub fn drifted(&self) -> bool {
        self.drifted
    }
    pub(crate) fn check_config(&mut self, text: &str) -> Result<(), String> {
        self.check(!self.config || self.expected.config == source_digest(text))
    }
    pub(crate) fn check_catalog(&mut self, text: &str) -> Result<(), String> {
        self.check(!self.catalog || self.expected.catalog == source_digest(text))
    }
    fn check(&mut self, matches: bool) -> Result<(), String> {
        if matches {
            return Ok(());
        }
        self.drifted = true;
        Err("operator source changed since the installed generation; reload and refresh before indexed edits".into())
    }
}

/// A raw patch whose strings (including object keys) are wiped on drop.
///
/// Wire form: `{"set":{"/path":value},"remove":["/other/path"]}`.
/// Omitted fields are untouched; setting null never means removal. Paths use
/// RFC 6901 escaping and must name a member below the document root.
/// The kernel owns this type; it must never appear in a public config response.
pub struct DocumentPatch(Value);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PatchError {
    Shape,
    Path,
    Overlap,
    Traversal,
    Encoding,
    Limit,
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Shape => "invalid document patch shape",
            Self::Path => "invalid document patch pointer",
            Self::Overlap => "overlapping document patch paths",
            Self::Traversal => "document patch target or sequence index is invalid",
            Self::Encoding => "document patch encoding failed",
            Self::Limit => {
                "document patch exceeds bounded history, operation, depth, or byte limit"
            }
        })
    }
}

impl std::error::Error for PatchError {}

impl fmt::Debug for DocumentPatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DocumentPatch([REDACTED])")
    }
}

impl Drop for DocumentPatch {
    fn drop(&mut self) {
        wipe_json(&mut self.0);
    }
}

impl Clone for DocumentPatch {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl serde::Serialize for DocumentPatch {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for DocumentPatch {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_stored_value(Value::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl DocumentPatch {
    /// Field paths present in a typed overlay's serialized shape. The temporary values may
    /// contain secrets, so only keys escape their wiping guard. Serde's skip-none policy is the
    /// authority for which optional patch fields actually override their base values.
    pub fn object_field_paths<T: serde::Serialize>(
        root: &str,
        value: &T,
    ) -> Result<Vec<String>, PatchError> {
        let value = WipedYaml(serde_yaml::to_value(value).map_err(|_| PatchError::Encoding)?);
        let map = value.0.as_mapping().ok_or(PatchError::Shape)?;
        map.keys()
            .map(|key| {
                let key = key.as_str().ok_or(PatchError::Shape)?;
                Ok(format!(
                    "{root}/{}",
                    key.replace('~', "~0").replace('/', "~1")
                ))
            })
            .collect()
    }

    /// Takes ownership before validation, so rejected values are also wiped.
    pub fn from_value(value: Value) -> Result<Self, PatchError> {
        let patch = Self(value);
        patch.validate()?;
        Ok(patch)
    }

    /// Public requests never accept the internal ordered Store representation.
    pub fn deserialize_request<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        Self::from_value(Value::deserialize(de)?).map_err(serde::de::Error::custom)
    }

    pub fn deserialize_optional_request<'de, D: serde::Deserializer<'de>>(
        de: D,
    ) -> Result<Option<Self>, D::Error> {
        Option::<Value>::deserialize(de)?
            .map(Self::from_value)
            .transpose()
            .map_err(serde::de::Error::custom)
    }

    fn from_stored_value(value: Value) -> Result<Self, PatchError> {
        let patch = Self(value);
        if let Some(stages) = patch.0.get("$stages") {
            if patch.0.as_object().is_none_or(|map| map.len() != 1) {
                return Err(PatchError::Shape);
            }
            let stages = stages.as_array().ok_or(PatchError::Shape)?;
            patch.check_limits()?;
            for stage in stages {
                validate_stage(stage)?;
                if stage_paths(stage).next().is_none() {
                    return Err(PatchError::Shape);
                }
            }
        } else {
            patch.validate()?;
        }
        Ok(patch)
    }

    fn stages(&self) -> impl Iterator<Item = &Value> {
        let staged = self.0.get("$stages").and_then(Value::as_array);
        std::iter::once(&self.0)
            .filter(move |_| staged.is_none())
            .chain(staged.into_iter().flatten())
    }

    fn check_limits(&self) -> Result<(), PatchError> {
        if self.paths().count() > 4096 || self.stages().count() > 4096 {
            return Err(PatchError::Limit);
        }
        struct BoundedBytes(usize);
        impl std::io::Write for BoundedBytes {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.saturating_add(bytes.len());
                if self.0 > 1024 * 1024 {
                    return Err(std::io::Error::other("patch size limit"));
                }
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(BoundedBytes(0), &self.0).map_err(|_| PatchError::Limit)
    }

    /// Compact only with the actual preprocessed operator source. Array cycles are removed
    /// only when the guarded emitted subtree is byte-identical, including scalar/key spellings.
    pub fn compacted_against_yaml(&self, yaml: &str) -> Result<Self, String> {
        source::compact(self, yaml)
    }

    fn remove_below(&mut self, prefix: &[String]) -> Result<(), PatchError> {
        let paths = Zeroizing::new(
            self.paths()
                .filter_map(|path| {
                    pointer(path)
                        .ok()
                        .filter(|parts| parts.starts_with(prefix))
                        .map(|_| path.to_owned())
                })
                .collect::<Vec<_>>(),
        );
        for path in &*paths {
            self.remove_operation(path);
        }
        Ok(())
    }

    /// Returns secret-bearing Store bytes under zeroizing ownership.
    pub fn to_json_bytes(&self) -> Result<Zeroizing<Vec<u8>>, PatchError> {
        let mut bytes = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *bytes, &self.0).map_err(|_| PatchError::Encoding)?;
        Ok(bytes)
    }

    /// Encoded paths only. Callers must not log paths: keys may be sensitive.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.stages().flat_map(stage_paths)
    }

    /// Conservative index detection also fences numeric map keys; it never guesses a sequence
    /// from a resolved pool. All actual traversal is still validated against consumed source.
    pub fn has_indexed_paths(&self) -> bool {
        self.paths().any(indexed_path)
    }

    /// True for an identical, ancestor, or descendant pointer.
    pub fn overlaps_path(&self, path: &str) -> Result<bool, PatchError> {
        let target = pointer(path)?;
        for existing in self.paths() {
            let existing = pointer(existing)?;
            if overlaps(&existing, &target) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Reset exactly the named operations. Unknown pointers are no-ops;
    /// descendants are retained unless explicitly named as well.
    pub fn without_paths(&self, paths: &[String]) -> Result<Self, PatchError> {
        for path in paths {
            pointer(path)?;
        }
        let mut result = self.clone();
        for path in paths {
            result.remove_operation(path);
        }
        Ok(result)
    }

    fn remove_operation(&mut self, path: &str) {
        if let Some(stages) = self.0.get_mut("$stages").and_then(Value::as_array_mut) {
            for stage in stages {
                let mut patch = Self(std::mem::take(stage));
                patch.remove_operation(path);
                *stage = std::mem::take(&mut patch.0);
            }
            return;
        }
        let root = self.0.as_object_mut().expect("validated shape");
        if let Some(set) = root.get_mut("set").and_then(Value::as_object_mut) {
            if let Some((mut key, mut value)) = set.remove_entry(path) {
                key.zeroize();
                wipe_json(&mut value);
            }
        }
        if let Some(remove) = root.get_mut("remove").and_then(Value::as_array_mut) {
            if let Some(index) = remove.iter().position(|v| v.as_str() == Some(path)) {
                let mut old = remove.remove(index);
                wipe_json(&mut old);
            }
        }
    }

    /// Preserve legacy object-only exact-path merging. Index-bearing requests use ordered
    /// stages so each request addresses the current authored document, including after restart.
    pub fn updated(&self, next: &Self) -> Result<Self, PatchError> {
        if self.0.get("$stages").is_some()
            || next.0.get("$stages").is_some()
            || next.paths().any(indexed_path)
        {
            let mut result = Self(serde_json::json!({"$stages": []}));
            let stages = result
                .0
                .get_mut("$stages")
                .and_then(Value::as_array_mut)
                .expect("stages");
            stages.extend(
                self.stages()
                    .filter(|stage| stage_paths(stage).next().is_some())
                    .cloned(),
            );
            for stage in next
                .stages()
                .filter(|stage| stage_paths(stage).next().is_some())
            {
                // Exact independent edits can dominate the preceding edit, but never compact
                // across an append/removal that changes current-view indices.
                let merged = stages
                    .last()
                    .filter(|prior| !shifts_indices(prior) && !shifts_indices(stage))
                    .and_then(|prior| Self(prior.clone()).updated_flat(&Self(stage.clone())).ok());
                if let Some(mut merged) = merged {
                    let mut old = stages.pop().expect("last stage");
                    wipe_json(&mut old);
                    stages.push(std::mem::take(&mut merged.0));
                } else {
                    stages.push(stage.clone());
                }
            }
            result.compact_dominated()?;
            result.check_limits()?;
            return Ok(result);
        }
        self.updated_flat(next)
    }

    fn compact_dominated(&mut self) -> Result<(), PatchError> {
        let Some(stages) = self.0.get_mut("$stages").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        for index in 0..stages.len() {
            let paths = Zeroizing::new(
                stage_paths(&stages[index])
                    .filter(|path| !indexed_path(path))
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            );
            for path in &*paths {
                let prefix = pointer(path)?;
                for prior in &mut stages[..index] {
                    let mut prior_patch = Self(std::mem::take(prior));
                    prior_patch.remove_below(&prefix)?;
                    *prior = std::mem::take(&mut prior_patch.0);
                }
            }
        }
        stages.retain_mut(|stage| {
            if stage_paths(stage).next().is_some() {
                true
            } else {
                wipe_json(stage);
                false
            }
        });
        Ok(())
    }

    fn updated_flat(&self, next: &Self) -> Result<Self, PatchError> {
        for path in next.paths() {
            let decoded = pointer(path)?;
            for prior in self.paths() {
                let prior = pointer(prior)?;
                if *prior != *decoded && overlaps(&prior, &decoded) {
                    return Err(PatchError::Overlap);
                }
            }
        }
        let mut merged = self.clone();
        for path in next.paths() {
            merged.remove_operation(path);
        }
        let root = merged.0.as_object_mut().expect("validated shape");
        if let Some(set) = next.0.get("set").and_then(Value::as_object) {
            let target = root
                .entry("set")
                .or_insert_with(|| Value::Object(Default::default()))
                .as_object_mut()
                .expect("validated shape");
            for (path, value) in set {
                target.insert(path.clone(), value.clone());
            }
        }
        if let Some(remove) = next.0.get("remove").and_then(Value::as_array) {
            root.entry("remove")
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .expect("validated shape")
                .extend(remove.iter().cloned());
        }
        merged.check_limits()?;
        Ok(merged)
    }

    fn validate(&self) -> Result<(), PatchError> {
        self.check_limits()?;
        validate_stage(&self.0)
    }

    /// Parse a patched source through the shared streaming boot reader. Both the transient
    /// source tree and serialized bytes are guarded and wiped on success and error paths.
    /// A borrowed YAML Value reader is not equivalent: it refuses scalar-to-string coercions
    /// that the file reader accepts, and has different null/default handling.
    pub fn parse_deploy_yaml(&self, yaml: &str) -> Result<super::DeployCfg, String> {
        self.parse_deploy_yaml_checked(yaml, |_| Ok(()))
    }

    /// Catalog edits share the exact reader used for the operator's providers.yaml.
    pub fn parse_catalog_yaml(
        &self,
        yaml: &str,
    ) -> Result<std::collections::HashMap<String, super::ProviderDef>, String> {
        let mut document = source::SourceDocument::parse(yaml)?;
        document.apply(self)?;
        let bytes = document.to_yaml_bytes()?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "patched provider catalog encoding failed".to_owned())?;
        super::providers::catalog_from_str(text)
            .map_err(|_| "patched provider catalog failed boot parsing".to_owned())
    }

    /// Deployment values have established precedence over catalog defaults. Refuse a catalog
    /// edit that overlaps one rather than claim the shadowed value was installed. No raw copied
    /// deployment leaves the wiping guard, including credential references.
    pub fn shadowed_catalog_path(
        &self,
        deployments: &std::collections::HashMap<String, super::ProviderDeploy>,
    ) -> Result<Option<String>, PatchError> {
        for path in self.paths() {
            let parts = pointer(path)?;
            let Some(deploy) = deployments.get(&parts[0]) else {
                continue;
            };
            let typed = WipedYaml(
                serde_yaml::to_value(deploy.authoring(&crate::seal::acquire()))
                    .map_err(|_| PatchError::Encoding)?,
            );
            let typed = typed.0.as_mapping().ok_or(PatchError::Encoding)?;
            let overrides = typed
                .iter()
                .filter_map(|(key, value)| {
                    let key = key.as_str()?;
                    (key != "api_key" && !value.is_null()).then_some(key)
                })
                .chain(deploy.options.keys().map(String::as_str));
            for key in overrides {
                if parts.len() == 1 || parts[1] == key {
                    return Ok(Some(path.to_owned()));
                }
            }
        }
        Ok(None)
    }

    /// Check the effective top-level keys before constructing typed config.
    /// Key references borrow the guarded tree and must not be retained.
    pub fn parse_deploy_yaml_checked(
        &self,
        yaml: &str,
        check_keys: impl FnOnce(&[&str]) -> Result<(), String>,
    ) -> Result<super::DeployCfg, String> {
        let mut document = source::SourceDocument::parse(yaml)?;
        document.apply(self)?;
        let mapping = document
            .value
            .0
            .as_mapping()
            .ok_or_else(|| "configuration document must be an object".to_owned())?;
        let keys = mapping
            .keys()
            .map(|key| {
                key.as_str()
                    .ok_or_else(|| "configuration keys must be strings".to_owned())
            })
            .collect::<Result<Vec<_>, _>>()?;
        check_keys(&keys)?;
        let bytes = document.to_yaml_bytes()?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| "patched configuration encoding failed".to_owned())?;
        super::deploy_from_yaml_str(text)
            .map_err(|_| "patched configuration failed boot parsing".to_owned())
    }

    /// Validate and prepare every edit before mutation. Sequence indices address the input
    /// snapshot: sets replace existing elements, terminal `-` appends, and removals run in
    /// descending index order after sets. Missing object parents are created; missing array
    /// indices, leading zeroes, signed indices, and traversal through `-` are refused.
    pub fn apply_to(&self, document: &mut serde_yaml::Value) -> Result<(), PatchError> {
        if self.0.get("$stages").is_some() {
            let mut guarded = WipedYaml(document.clone());
            for stage in self.stages() {
                Self(stage.clone())
                    .prepare(&guarded.0)?
                    .apply(&mut guarded.0);
            }
            wipe_yaml(document);
            *document = std::mem::take(&mut guarded.0);
        } else {
            self.prepare(document)?.apply(document);
        }
        Ok(())
    }

    fn prepare(&self, document: &serde_yaml::Value) -> Result<Prepared, PatchError> {
        let mut prepared = Prepared {
            set: Vec::new(),
            remove: Vec::new(),
        };
        if let Some(set) = self.0.get("set").and_then(Value::as_object) {
            for (path, value) in set {
                let mut path = pointer(path)?;
                check_target(document, &mut path, true)?;
                prepared.set.push((path, WipedYaml(json_to_yaml(value)?)));
            }
        }
        if let Some(remove) = self.0.get("remove").and_then(Value::as_array) {
            for path in remove {
                let mut path = pointer(path.as_str().ok_or(PatchError::Shape)?)?;
                check_target(document, &mut path, false)?;
                prepared.remove.push(path);
            }
        }
        // At the first different segment, numeric order preserves original sequence indices.
        // Object key removal order is immaterial. Ancestor overlaps were already rejected.
        prepared.remove.sort_by(|a, b| {
            for (a, b) in a.iter().zip(b.iter()) {
                let order = match (sequence_index(a), sequence_index(b)) {
                    (Ok(a), Ok(b)) => b.cmp(&a),
                    (Ok(_), Err(_)) => std::cmp::Ordering::Less,
                    (Err(_), Ok(_)) => std::cmp::Ordering::Greater,
                    (Err(_), Err(_)) => b.cmp(a),
                };
                if !order.is_eq() {
                    return order;
                }
            }
            b.len().cmp(&a.len())
        });
        Ok(prepared)
    }
}

fn stage_paths(value: &Value) -> impl Iterator<Item = &str> {
    value
        .get("set")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|map| map.keys().map(String::as_str))
        .chain(
            value
                .get("remove")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str),
        )
}

fn indexed_path(path: &str) -> bool {
    path.split('/')
        .skip(1)
        .any(|part| part == "-" || sequence_index(part).is_ok())
}

fn shifts_indices(stage: &Value) -> bool {
    stage
        .get("set")
        .and_then(Value::as_object)
        .is_some_and(|map| map.keys().any(|path| path.ends_with("/-")))
        || stage
            .get("remove")
            .and_then(Value::as_array)
            .is_some_and(|paths| {
                paths.iter().filter_map(Value::as_str).any(|path| {
                    path.rsplit('/')
                        .next()
                        .is_some_and(|last| sequence_index(last).is_ok())
                })
            })
}

fn validate_stage(value: &Value) -> Result<(), PatchError> {
    let root = value.as_object().ok_or(PatchError::Shape)?;
    if root.keys().any(|key| key != "set" && key != "remove")
        || root.get("set").is_some_and(|v| !v.is_object())
        || root.get("remove").is_some_and(|v| {
            v.as_array()
                .is_none_or(|items| items.iter().any(|v| !v.is_string()))
        })
    {
        return Err(PatchError::Shape);
    }
    let mut seen = Vec::new();
    for path in stage_paths(value) {
        let decoded = pointer(path)?;
        if seen
            .iter()
            .any(|prior: &Zeroizing<Vec<String>>| overlaps(prior, &decoded))
        {
            return Err(PatchError::Overlap);
        }
        seen.push(decoded);
    }
    Ok(())
}

fn pointer(path: &str) -> Result<Zeroizing<Vec<String>>, PatchError> {
    let tail = path.strip_prefix('/').ok_or(PatchError::Path)?;
    let mut parts = Zeroizing::new(Vec::new());
    for part in tail.split('/') {
        if parts.len() == 128 {
            return Err(PatchError::Limit);
        }
        let mut decoded = Zeroizing::new(String::new());
        let mut chars = part.chars();
        while let Some(ch) = chars.next() {
            decoded.push(match ch {
                '~' => match chars.next() {
                    Some('0') => '~',
                    Some('1') => '/',
                    _ => return Err(PatchError::Path),
                },
                ch => ch,
            });
        }
        parts.push(std::mem::take(&mut *decoded));
    }
    Ok(parts)
}

fn overlaps(a: &[String], b: &[String]) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

struct Prepared {
    set: Vec<(Zeroizing<Vec<String>>, WipedYaml)>,
    remove: Vec<Zeroizing<Vec<String>>>,
}
impl Prepared {
    fn apply(mut self, document: &mut serde_yaml::Value) {
        for (path, value) in &mut self.set {
            set_at(document, path, &mut value.0);
        }
        for path in &self.remove {
            remove_at(document, path);
        }
    }
}

fn sequence_index(key: &str) -> Result<usize, PatchError> {
    if key.is_empty()
        || (key.len() > 1 && key.starts_with('0'))
        || !key.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(PatchError::Traversal);
    }
    key.parse().map_err(|_| PatchError::Traversal)
}

fn check_target(
    mut document: &serde_yaml::Value,
    path: &mut [String],
    set: bool,
) -> Result<(), PatchError> {
    let last = path.len() - 1;
    for (depth, key) in path.iter_mut().enumerate() {
        if let Some(map) = document.as_mapping() {
            match map.get(key.as_str()) {
                Some(value) => document = value,
                None => return Ok(()),
            }
        } else if let Some(seq) = document.as_sequence() {
            if set && depth == last && key == "-" {
                key.zeroize();
                *key = seq.len().to_string();
                return Ok(());
            }
            document = seq.get(sequence_index(key)?).ok_or(PatchError::Traversal)?;
        } else {
            return Err(PatchError::Traversal);
        }
    }
    Ok(())
}

fn set_at(document: &mut serde_yaml::Value, path: &[String], value: &mut serde_yaml::Value) {
    if let Some(seq) = document.as_sequence_mut() {
        let index = sequence_index(&path[0]).expect("index checked");
        if path.len() == 1 {
            if index == seq.len() {
                seq.push(std::mem::take(value));
            } else {
                wipe_yaml(&mut seq[index]);
                seq[index] = std::mem::take(value);
            }
        } else {
            set_at(&mut seq[index], &path[1..], value);
        }
        return;
    }
    let map = document.as_mapping_mut().expect("traversal checked");
    if path.len() == 1 {
        if let Some(old) = map.get_mut(path[0].as_str()) {
            wipe_yaml(old);
            *old = std::mem::take(value);
        } else {
            map.insert(
                serde_yaml::Value::String(path[0].clone()),
                std::mem::take(value),
            );
        }
    } else {
        if !map.contains_key(path[0].as_str()) {
            map.insert(
                serde_yaml::Value::String(path[0].clone()),
                serde_yaml::Value::Mapping(Default::default()),
            );
        }
        set_at(
            map.get_mut(path[0].as_str()).expect("parent inserted"),
            &path[1..],
            value,
        );
    }
}

fn remove_at(document: &mut serde_yaml::Value, path: &[String]) {
    if let Some(seq) = document.as_sequence_mut() {
        let index = sequence_index(&path[0]).expect("index checked");
        if path.len() == 1 {
            wipe_yaml(&mut seq.remove(index));
        } else {
            remove_at(&mut seq[index], &path[1..]);
        }
        return;
    }
    let Some(map) = document.as_mapping_mut() else {
        return;
    };
    if path.len() == 1 {
        for (mut key, mut value) in std::mem::take(map) {
            if key.as_str() == Some(path[0].as_str()) {
                wipe_yaml(&mut key);
                wipe_yaml(&mut value);
            } else {
                map.insert(key, value);
            }
        }
    } else if let Some(child) = map.get_mut(path[0].as_str()) {
        remove_at(child, &path[1..]);
    }
}

// serde_json's arbitrary_precision feature serializes numbers through a private map marker.
// Convert the data model directly; each partially built container stays under wiping custody.
fn json_to_yaml(value: &Value) -> Result<serde_yaml::Value, PatchError> {
    use serde_yaml::Value as Yaml;
    Ok(match value {
        Value::Null => Yaml::Null,
        Value::Bool(value) => Yaml::Bool(*value),
        Value::Number(value) => {
            // The streaming bridge retains the exact numeric text separately. Its intermediate
            // tree needs only a scalar; it must not reject or round a wider integer on the wire.
            if let Some(value) = value.as_u64() {
                Yaml::Number(value.into())
            } else if let Some(value) = value.as_i64() {
                Yaml::Number(value.into())
            } else if let Some(value) = value.as_f64().filter(|value| value.is_finite()) {
                Yaml::Number(value.into())
            } else {
                Yaml::String(value.to_string())
            }
        }
        Value::String(value) => Yaml::String(value.clone()),
        Value::Array(values) => {
            let mut result = WipedYaml(Yaml::Sequence(Vec::with_capacity(values.len())));
            for value in values {
                result
                    .0
                    .as_sequence_mut()
                    .expect("sequence")
                    .push(json_to_yaml(value)?);
            }
            std::mem::take(&mut result.0)
        }
        Value::Object(values) => {
            let mut result = WipedYaml(Yaml::Mapping(Default::default()));
            for (key, value) in values {
                let value = json_to_yaml(value)?;
                result
                    .0
                    .as_mapping_mut()
                    .expect("mapping")
                    .insert(Yaml::String(key.clone()), value);
            }
            std::mem::take(&mut result.0)
        }
    })
}

struct WipedYaml(serde_yaml::Value);
impl Zeroize for WipedYaml {
    fn zeroize(&mut self) {
        wipe_yaml(&mut self.0);
    }
}
impl Drop for WipedYaml {
    fn drop(&mut self) {
        self.zeroize();
    }
}

fn wipe_json(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe_json),
        Value::Object(map) => {
            for (mut key, mut value) in std::mem::take(map) {
                key.zeroize();
                wipe_json(&mut value);
            }
        }
        _ => {}
    }
}

fn wipe_yaml(value: &mut serde_yaml::Value) {
    match value {
        serde_yaml::Value::String(text) => text.zeroize(),
        serde_yaml::Value::Sequence(items) => items.iter_mut().for_each(wipe_yaml),
        serde_yaml::Value::Mapping(map) => {
            for (mut key, mut value) in std::mem::take(map) {
                wipe_yaml(&mut key);
                wipe_yaml(&mut value);
            }
        }
        serde_yaml::Value::Tagged(tagged) => wipe_yaml(&mut tagged.value),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn explicit_numeric_edits_preserve_wide_integer_precision_for_the_boot_reader() {
        for text in ["18446744073709551617", "-0", "1e3"] {
            let number: Value = serde_json::from_str(text).unwrap();
            let expected = number.to_string();
            let edited = patch(json!({"set": {"/admin_listen": number}}))
                .parse_deploy_yaml("providers: {}\nmodels: {}\n")
                .unwrap();
            assert_eq!(edited.admin_listen, expected);
        }
        let base = "providers: {}\nmodels: {}\ngroups:\n  '18446744073709551617': {}\n  child:\n    parent: 18446744073709551617\n";
        let original = super::super::deploy_from_yaml_str(base).unwrap();
        let edited = patch(json!({"set": {"/per_request_fee": 3}}))
            .parse_deploy_yaml(base)
            .unwrap();
        assert_eq!(
            edited.groups["child"].parent,
            original.groups["child"].parent
        );
    }

    #[test]
    fn source_bridge_preserves_scalar_types_empty_nodes_sequences_and_tags() {
        let base = "flag: TRUE\nnumber: 0x10\nempty:\nseq:\n  - TRUE\n  - 0x20\n  -\nquoted: \"TRUE\"\ntagged: !Variant TRUE\n!Key 'name: part': value\n";
        let mut document = source::SourceDocument::parse(base).unwrap();
        document
            .apply(&patch(json!({"set": {"/added": 8}})))
            .unwrap();
        let bytes = document.to_yaml_bytes().unwrap();
        let mut expected: serde_yaml::Value = serde_yaml::from_str(base).unwrap();
        expected.as_mapping_mut().unwrap().insert(
            serde_yaml::Value::String("added".into()),
            serde_yaml::Value::Number(8.into()),
        );
        let actual: serde_yaml::Value = serde_yaml::from_slice(&bytes).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn unrelated_edits_preserve_implicit_scalar_string_spellings_and_aliases() {
        let base = "providers: {}\nmodels: {}\npublic_url: TRUE\nadmin_listen: 0x10\ngroups:\n  TRUE: {}\n  0x20: {}\n";
        let original = super::super::deploy_from_yaml_str(base).unwrap();
        let edited = patch(json!({"set": {"/per_request_fee": 3}}))
            .parse_deploy_yaml(base)
            .unwrap();
        assert_eq!(original.public_url.as_deref(), Some("TRUE"));
        assert_eq!(original.admin_listen, "0x10");
        assert_eq!(edited.public_url, original.public_url);
        assert_eq!(edited.admin_listen, original.admin_listen);
        assert_eq!(
            edited.groups.keys().collect::<Vec<_>>(),
            original.groups.keys().collect::<Vec<_>>()
        );
        assert!(edited.groups.contains_key("TRUE"));
        assert!(edited.groups.contains_key("0x20"));
        assert_eq!(edited.per_request_fee, 3);
        let changed = patch(json!({"set": {"/admin_listen": 32}}))
            .parse_deploy_yaml(base)
            .unwrap();
        assert_eq!(
            changed.admin_listen, "32",
            "an explicit edit replaces the old scalar spelling"
        );
    }

    #[test]
    fn catalog_edits_preserve_implicit_alias_and_omitted_scalar_spellings() {
        let base = "TRUE:\n  protocol: TRUE\n  base_url: 0x10\n  path: 0x20\n";
        let original = super::super::providers::catalog_from_str(base).unwrap();
        let edited = patch(json!({"set": {"/TRUE/scope": "updated"}}))
            .parse_catalog_yaml(base)
            .unwrap();
        assert_eq!(edited["TRUE"].protocol, original["TRUE"].protocol);
        assert_eq!(edited["TRUE"].base_url, "0x10");
        assert_eq!(edited["TRUE"].path.as_deref(), Some("0x20"));
        assert_eq!(edited["TRUE"].scope.as_deref(), Some("updated"));
    }

    #[test]
    fn catalog_edits_use_boot_grammar_and_preserve_omitted_fields() {
        let patch = super::DocumentPatch::from_value(serde_json::json!({
            "set": {"/example/base_url": "opaque:edited"}
        }))
        .unwrap();
        let catalog = patch
            .parse_catalog_yaml(
                "example:\n  protocol: test-wire\n  base_url: opaque:base\n  path: /kept\n",
            )
            .unwrap();
        assert_eq!(catalog["example"].base_url, "opaque:edited");
        assert_eq!(catalog["example"].path.as_deref(), Some("/kept"));
        assert!(super::DocumentPatch::from_value(serde_json::json!({
            "remove": ["/example/protocol"]
        }))
        .unwrap()
        .parse_catalog_yaml("example:\n  protocol: test-wire\n  base_url: opaque:base\n",)
        .is_err());
    }

    #[test]
    fn catalog_edits_refuse_shadowed_deployment_fields_without_exposing_credentials() {
        let deploy = super::super::deploy_from_yaml_str(
            "providers:\n  example:\n    api_key: {module: fixture-source, settings: {slot: PRIVATE_KEY}}\n    base_url: opaque:deployment\nmodels: {}\n",
        ).unwrap();
        let patch = |path: &str| {
            super::DocumentPatch::from_value(serde_json::json!({"set": {path: "opaque:catalog"}}))
                .unwrap()
        };
        assert_eq!(
            patch("/example/base_url")
                .shadowed_catalog_path(&deploy.providers)
                .unwrap()
                .as_deref(),
            Some("/example/base_url")
        );
        assert_eq!(
            patch("/example/path")
                .shadowed_catalog_path(&deploy.providers)
                .unwrap(),
            None
        );
        assert_eq!(
            patch("/unused/base_url")
                .shadowed_catalog_path(&deploy.providers)
                .unwrap(),
            None
        );
    }
    use super::*;
    use serde_json::json;

    fn patch(value: Value) -> DocumentPatch {
        DocumentPatch::from_value(value).unwrap()
    }
    fn yaml(text: &str) -> serde_yaml::Value {
        serde_yaml::from_str(text).unwrap()
    }

    #[test]
    fn config_admin_parity_keeps_every_boot_field_on_the_generic_document_route() {
        let frozen: Value =
            serde_json::from_str(include_str!("config-schema.snapshot.json")).unwrap();
        let mut fields: std::collections::BTreeSet<String> = frozen["types"]["DeployCfg"]["fields"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        // Include new fields immediately, before anyone updates a schema inventory. Skipped
        // internal carriers are harmless: both front doors must refuse their non-wire names.
        let source = include_str!("mod.rs");
        let deploy = source
            .split_once("pub struct DeployCfg {")
            .unwrap()
            .1
            .split_once("\n}")
            .unwrap()
            .0;
        for line in deploy.lines() {
            if let Some(field) = line
                .trim()
                .strip_prefix("pub ")
                .and_then(|line| line.split_once(':').map(|(name, _)| name))
            {
                fields.insert(field.to_owned());
            }
        }
        fields.extend(
            super::super::plane_sections::config_sections()
                .into_iter()
                .map(str::to_owned),
        );
        assert!(
            fields.len() > 25,
            "the parity gate must enumerate the real config surface"
        );
        let mut accepted = 0;
        for field in fields {
            for value in [
                Value::Null,
                json!(true),
                json!(17),
                json!([]),
                json!({}),
                json!("127.0.0.1:8088"),
            ] {
                let mut direct = json!({"providers": {}, "models": {}});
                direct[&field] = value.clone();
                let mut base = yaml("providers: {}\nmodels: {}\n");
                let edit = patch(
                    json!({"set": {format!("/{}", field.replace('~', "~0").replace('/', "~1")): value}}),
                );
                edit.apply_to(&mut base).unwrap();
                assert_eq!(
                    serde_json::to_value(&base).unwrap(),
                    direct,
                    "admin path dropped or rewrote config field {field}"
                );
                // Boot consumes YAML text, not serde_json's in-memory representation (whose
                // arbitrary_precision numbers use a private map marker). JSON text is a YAML
                // subset and gives an independent file-side input without using our converter.
                let file_text = serde_json::to_string(&direct).unwrap();
                let boot = super::super::deploy_from_yaml_str(&file_text).is_ok();
                let admin = edit
                    .parse_deploy_yaml("providers: {}\nmodels: {}\n")
                    .is_ok();
                assert_eq!(admin, boot, "file/admin schema drift for {field}");
                accepted += usize::from(boot);
            }
        }
        assert!(
            accepted > 20,
            "unregistered or wholly refused fixtures cannot prove parity"
        );
    }

    #[test]
    fn omission_preserves_secret_and_null_is_not_removal() {
        let mut doc = yaml("pool:\n  secret: keep-me\n  timeout: 2\n  stale: true\n");
        patch(json!({"set":{"/pool/timeout":null},"remove":["/pool/stale"]}))
            .apply_to(&mut doc)
            .unwrap();
        assert_eq!(doc["pool"]["secret"].as_str(), Some("keep-me"));
        let pool = doc["pool"].as_mapping().unwrap();
        assert!(pool.contains_key("timeout"));
        assert_eq!(doc["pool"]["timeout"], serde_yaml::Value::Null);
        assert!(!pool.contains_key("stale"));
    }

    #[test]
    fn pointers_escape_segments_and_create_missing_objects() {
        let mut doc = yaml("{}");
        patch(json!({"set":{"/a~1b/~0key":7,"/":true}}))
            .apply_to(&mut doc)
            .unwrap();
        assert_eq!(doc["a/b"]["~key"].as_u64(), Some(7));
        assert_eq!(doc[""].as_bool(), Some(true));
    }

    #[test]
    fn invalid_shapes_and_overlapping_paths_are_rejected() {
        for value in [
            json!([]),
            json!({"unknown":true}),
            json!({"set":[]}),
            json!({"remove":[4]}),
            json!({"set":{"":1}}),
            json!({"set":{"/bad~2":1}}),
        ] {
            assert!(DocumentPatch::from_value(value).is_err());
        }
        for value in [
            json!({"set":{"/a":1,"/a/b":2}}),
            json!({"set":{"/a":1},"remove":["/a"]}),
            json!({"remove":["/a","/a"]}),
            json!({"set":{"/a/b":1},"remove":["/a"]}),
        ] {
            assert_eq!(
                DocumentPatch::from_value(value).unwrap_err(),
                PatchError::Overlap
            );
        }
        assert!(DocumentPatch::from_value(json!({"set":{"/a":1,"/ab":2}})).is_ok());
    }

    #[test]
    fn whole_array_replacements_and_failed_traversal_remain_atomic() {
        let mut doc = yaml("a: 1\nz: [old]\nn: null");
        let before = doc.clone();
        assert_eq!(
            patch(json!({"set":{"/a":2,"/z/9":"new"}})).apply_to(&mut doc),
            Err(PatchError::Traversal)
        );
        assert_eq!(doc, before);
        assert_eq!(
            patch(json!({"set":{"/n/child":1}})).apply_to(&mut doc),
            Err(PatchError::Traversal)
        );
        patch(json!({"set":{"/z":["new"]},"remove":["/missing/child"]}))
            .apply_to(&mut doc)
            .unwrap();
        assert_eq!(doc["z"][0].as_str(), Some("new"));
    }

    #[test]
    fn sequence_member_edits_preserve_hidden_fields_and_strict_indices() {
        let base = "members: [{model: first, weight: 1, tags: {private: CANARY}}, {model: second}]";
        let mut doc = yaml(base);
        patch(json!({"set": {"/members/0/weight": 3, "/members/-": {"model": "third"}}}))
            .apply_to(&mut doc)
            .unwrap();
        assert_eq!(doc["members"][0]["weight"].as_u64(), Some(3));
        assert_eq!(
            doc["members"][0]["tags"]["private"].as_str(),
            Some("CANARY")
        );
        assert_eq!(doc["members"][2]["model"].as_str(), Some("third"));
        for path in [
            "/members/01",
            "/members/-1",
            "/members/+1",
            "/members/3",
            "/members/184467440737095516160",
            "/members/-/model",
        ] {
            let before = doc.clone();
            assert_eq!(
                patch(json!({"set": {"/unrelated": true, path: null}})).apply_to(&mut doc),
                Err(PatchError::Traversal)
            );
            assert_eq!(doc, before);
        }
        for path in ["/members/-", "/members/3"] {
            let before = doc.clone();
            assert_eq!(
                patch(json!({"remove": [path]})).apply_to(&mut doc),
                Err(PatchError::Traversal)
            );
            assert_eq!(doc, before);
        }
    }

    #[test]
    fn multiple_sequence_removals_use_original_snapshot_indices() {
        let mut doc = yaml("members: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]");
        patch(json!({"set": {"/members/3": 30, "/members/-": 12}, "remove": ["/members/1", "/members/10", "/members/2"]}))
            .apply_to(&mut doc).unwrap();
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({"members": [0, 30, 4, 5, 6, 7, 8, 9, 11, 12]})
        );
        assert!(DocumentPatch::from_value(
            json!({"set": {"/members/1/weight": 2}, "remove": ["/members/1"]})
        )
        .is_err());
    }

    fn source_text(patch: &DocumentPatch, base: &str) -> Zeroizing<Vec<u8>> {
        let mut source = source::SourceDocument::parse(base).unwrap();
        source.apply(patch).unwrap();
        source.to_yaml_bytes().unwrap()
    }

    #[test]
    fn sequence_shifts_keep_untouched_scalar_and_key_spellings() {
        let base = "members:\n  - {name: removed}\n  - name: TRUE\n    code: 0x10\n    wide: 18446744073709551617\n    tags: {TRUE: CANARY}\n  - {name: third}\n";
        let edit = patch(
            json!({"set": {"/members/1/weight": 3, "/members/-": {"name": "fourth", "wide": serde_json::from_str::<Value>("18446744073709551619").unwrap()}}, "remove": ["/members/0"]}),
        );
        let bytes = source_text(&edit, base);
        let text = std::str::from_utf8(&bytes).unwrap();
        #[derive(serde::Deserialize)]
        struct Member {
            name: String,
            code: Option<String>,
            wide: Option<String>,
            tags: Option<std::collections::BTreeMap<String, String>>,
        }
        #[derive(serde::Deserialize)]
        struct Members {
            members: Vec<Member>,
        }
        let parsed: Members = serde_yaml::from_str(text).unwrap();
        assert_eq!(parsed.members[0].name, "TRUE");
        assert_eq!(parsed.members[0].code.as_deref(), Some("0x10"));
        assert_eq!(
            parsed.members[0].wide.as_deref(),
            Some("18446744073709551617")
        );
        assert_eq!(parsed.members[0].tags.as_ref().unwrap()["TRUE"], "CANARY");
        assert_eq!(
            parsed.members[2].wide.as_deref(),
            Some("18446744073709551619")
        );
    }

    #[test]
    fn persisted_sequence_stages_address_current_members_after_restart() {
        let base = "members: [{model: first}, {model: second, tags: {private: CANARY}, code: 0x10}]\nhooks: [one, two]";
        let mut edit = patch(json!({}));
        for next in [
            json!({"set": {"/members/-": {"model": "third", "weight": 1}}}),
            json!({"set": {"/members/2/weight": 7}}),
            json!({"set": {"/members/-": {"model": "fourth"}}}),
            json!({"remove": ["/members/0"]}),
            json!({"set": {"/members/0/weight": 9, "/hooks/0": "two", "/hooks/1": "one"}}),
        ] {
            edit = edit
                .updated(&patch(next))
                .unwrap()
                .compacted_against_yaml(base)
                .unwrap();
            // Every request boundary is also a restart boundary: use exactly the Store codec.
            edit = serde_json::from_slice(&edit.to_json_bytes().unwrap()).unwrap();
        }
        let bytes = source_text(&edit, base);
        let doc: serde_yaml::Value = serde_yaml::from_slice(&bytes).unwrap();
        assert_eq!(doc["members"].as_sequence().unwrap().len(), 3);
        assert_eq!(doc["members"][0]["model"].as_str(), Some("second"));
        assert_eq!(doc["members"][0]["weight"].as_u64(), Some(9));
        assert_eq!(
            doc["members"][0]["tags"]["private"].as_str(),
            Some("CANARY")
        );
        assert_eq!(doc["members"][1]["weight"].as_u64(), Some(7));
        assert_eq!(doc["members"][2]["model"].as_str(), Some("fourth"));
        assert_eq!(doc["hooks"], yaml("[two, one]"));
        assert!(std::str::from_utf8(&bytes).unwrap().contains("0x10"));
    }

    #[test]
    fn late_sequence_failure_is_atomic_for_values_and_lexical_source() {
        let base = "members: [{name: TRUE, secret: CANARY}]";
        let first = patch(json!({"set": {"/members/-": {"name": "second"}}}));
        let edit = first
            .updated(&patch(json!({"set": {"/members/9/name": "bad"}})))
            .unwrap();
        let mut doc = yaml(base);
        let before = doc.clone();
        assert_eq!(edit.apply_to(&mut doc), Err(PatchError::Traversal));
        assert_eq!(doc, before);
        let mut source = source::SourceDocument::parse(base).unwrap();
        let before = source.to_yaml_bytes().unwrap();
        assert!(source.apply(&edit).is_err());
        assert_eq!(source.to_yaml_bytes().unwrap(), before);
        assert!(edit.compacted_against_yaml(base).is_err());
    }

    #[test]
    fn routine_sequence_cycles_compact_without_lifetime_edit_quota() {
        let base = "members: [{name: TRUE, secret: CANARY, code: 0x10}]";
        let mut edit = patch(json!({}));
        let baseline = source_text(&edit, base);
        for _ in 0..160 {
            for next in [
                json!({"set": {"/members/-": {"name": "temporary"}}}),
                json!({"set": {"/members/1/name": "changed"}}),
                json!({"remove": ["/members/1"]}),
            ] {
                edit = edit
                    .updated(&patch(next))
                    .unwrap()
                    .compacted_against_yaml(base)
                    .unwrap();
            }
            assert_eq!(source_text(&edit, base), baseline);
            assert_eq!(edit.paths().count(), 0);
            assert!(edit.to_json_bytes().unwrap().len() < 32);
        }
        for weight in 0..160 {
            edit = edit
                .updated(&patch(json!({"set": {"/members/0/weight": weight}})))
                .unwrap();
        }
        assert_eq!(edit.paths().count(), 1);
        let replaced = edit
            .updated(&patch(json!({"set": {"/members": []}})))
            .unwrap();
        assert_eq!(replaced.paths().count(), 1);
        assert_eq!(
            source_text(&replaced, base),
            source_text(&patch(json!({"set": {"/members": []}})), base)
        );
    }

    #[test]
    fn source_admission_binds_consumed_text_without_exposing_digest() {
        let fingerprints = SourceFingerprints::from_sources("members: [a, b]", "catalog: original");
        assert_eq!(format!("{fingerprints:?}"), "SourceFingerprints([PRIVATE])");
        let mut check = SourceAdmission::new(fingerprints, true, true);
        check.check_config("members: [a, b]").unwrap();
        check.check_catalog("catalog: original").unwrap();
        assert!(!check.drifted());
        assert!(check.check_config("members: [b, a]").is_err());
        assert!(check.drifted());
        let mut check = SourceAdmission::new(fingerprints, false, true);
        check.check_config("unindexed source may change").unwrap();
        assert!(check.check_catalog("catalog: changed").is_err());
        let refreshed = SourceFingerprints::from_sources("members: [b, a]", "catalog: changed");
        let mut check = SourceAdmission::new(refreshed, true, true);
        check.check_config("members: [b, a]").unwrap();
        check.check_catalog("catalog: changed").unwrap();
    }

    #[test]
    fn internal_stage_wire_and_patch_budgets_are_checked() {
        assert!(DocumentPatch::from_value(json!({"$stages": []})).is_err());
        assert!(
            serde_json::from_value::<DocumentPatch>(json!({"$stages": [{"$stages": []}]})).is_err()
        );
        assert!(serde_json::from_value::<DocumentPatch>(
            json!({"$stages": [{"set": {"/a": 1}}], "set": {}})
        )
        .is_err());
        assert_eq!(
            DocumentPatch::from_value(json!({"set": {"/a": "x".repeat(1024 * 1024)}})).unwrap_err(),
            PatchError::Limit
        );
        assert_eq!(
            DocumentPatch::from_value(json!({"remove": vec!["/a"; 4097]})).unwrap_err(),
            PatchError::Limit
        );
        assert_eq!(
            DocumentPatch::from_value(
                json!({"set": {format!("/{}", vec!["a"; 129].join("/")): null}})
            )
            .unwrap_err(),
            PatchError::Limit
        );
    }

    #[test]
    fn sequential_updates_preserve_unrelated_edits_and_replace_exact_paths() {
        let first = patch(json!({"set":{"/a":"secret","/b":2},"remove":["/c"]}));
        let next = patch(json!({"set":{"/c":null},"remove":["/a"]}));
        let merged = first.updated(&next).unwrap();
        let mut doc = yaml("a: old\nc: old\nd: keep");
        merged.apply_to(&mut doc).unwrap();
        assert!(!doc.as_mapping().unwrap().contains_key("a"));
        assert_eq!(doc["b"].as_u64(), Some(2));
        assert!(doc.as_mapping().unwrap().contains_key("c"));
        assert_eq!(doc["d"].as_str(), Some("keep"));
        assert!(first
            .updated(&patch(json!({"set":{"/a/child":1}})))
            .is_err());
        assert!(first
            .updated(&patch(json!({"remove":["/b/child"]})))
            .is_err());
    }

    #[test]
    fn store_roundtrip_and_debug_redaction() {
        let original = patch(json!({"set":{"/secret":"CANARY","/nested":{"key":["CANARY"]}}}));
        assert_eq!(format!("{original:?}"), "DocumentPatch([REDACTED])");
        let bytes = original.to_json_bytes().unwrap();
        let decoded: DocumentPatch = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(&*bytes, &*decoded.to_json_bytes().unwrap());
        assert!(decoded.overlaps_path("/nested/key").unwrap());
        assert!(!decoded.overlaps_path("/nested-other").unwrap());
        assert!(decoded.overlaps_path("/bad~").is_err());
    }

    #[test]
    fn patched_yaml_uses_shared_boot_types_and_safe_diagnostics() {
        let patch = patch(json!({"set":{"/listen":"127.0.0.1:9876"}}));
        // This kernel-only fixture declares no plane sections. Its base must independently
        // pass boot before the test can attribute any failure to the document edit.
        let base = "providers: {}\nmodels: {}\n";
        super::super::deploy_from_yaml_str(base).expect("boot accepts the kernel-only base");
        let deploy = patch
            .parse_deploy_yaml(base)
            .expect("shared deployment reader");
        assert_eq!(deploy.listen, "127.0.0.1:9876");
        assert!(deploy.listen_explicit);
        for malformed in [
            "providers: {}\nmodels: {}\nadmin_require_mtls: CANARY\n",
            "providers: [CANARY",
        ] {
            let error = patch.parse_deploy_yaml(malformed).unwrap_err();
            assert!(!error.contains("CANARY"));
            assert!(
                error == "invalid configuration YAML"
                    || error == "patched configuration failed boot parsing"
            );
        }
    }

    #[test]
    fn explicit_reset_allows_child_edit_and_keeps_unrelated_secret() {
        let prior = patch(json!({"set":{"/parent":{"old":true},"/secret":"KEEP"},
            "remove":["/stale"]}));
        let reset = prior
            .without_paths(&["/parent".into(), "/missing".into(), "/stale".into()])
            .unwrap();
        let updated = reset
            .updated(&patch(json!({"set":{"/parent/child":true}})))
            .unwrap();
        let mut doc = yaml("parent: {}\nstale: keep");
        updated.apply_to(&mut doc).unwrap();
        assert_eq!(doc["parent"]["child"].as_bool(), Some(true));
        assert_eq!(doc["secret"].as_str(), Some("KEEP"));
        assert_eq!(doc["stale"].as_str(), Some("keep"));
        assert!(prior.without_paths(&["invalid".into()]).is_err());
        assert!(prior.paths().any(|path| path == "/parent"));
    }

    #[test]
    fn patched_keys_are_checked_before_typed_parsing() {
        let edits = patch(json!({"set":{"/new_section":{}},"remove":["/old_section"]}));
        let mut checked = false;
        let result = edits.parse_deploy_yaml_checked(
            "old_section: {}\nadmin_require_mtls: invalid",
            |keys| {
                checked = true;
                assert!(keys.contains(&"new_section"));
                assert!(!keys.contains(&"old_section"));
                Err("key policy refused".into())
            },
        );
        assert!(checked);
        assert_eq!(result.unwrap_err(), "key policy refused");
    }

    #[test]
    fn yaml_guard_uses_recursive_wiping() {
        let mut document = WipedYaml(yaml("secret-key: [CANARY, {inner: CANARY}]"));
        document.zeroize();
        assert!(document.0.as_mapping().unwrap().is_empty());
        // Drop uses the same operation and remains safe after an explicit wipe.
        drop(document);
    }

    #[test]
    fn recursive_wipe_clears_string_values_and_object_keys() {
        let mut value = json!({"secret-key":["CANARY",{"inner":"CANARY"}]});
        wipe_json(&mut value);
        assert_eq!(value, json!({}));
        let mut value = yaml("secret-key: [CANARY, {inner: CANARY}]");
        wipe_yaml(&mut value);
        assert!(value.as_mapping().unwrap().is_empty());
        let mut value = Value::Array(vec![Value::String("CANARY".into())]);
        wipe_json(&mut value);
        assert_eq!(value, json!([""]));
    }
}
