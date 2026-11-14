// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Transient source spelling custody for document edits. YAML's streaming reader can deserialize
//! an implicit scalar as a String, so normalizing TRUE or 0x10 changes an omitted String value.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use busbar_contract::secure::{SecureString, SecureVec};
use busbar_contract::yaml::{MappingExt, Value, ValueExt};
use serde::de::{DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use zeroize::Zeroize;

use super::{wipe_yaml, DocumentPatch, WipedYaml};

struct PathMap<T: Zeroize>(BTreeMap<Vec<String>, T>);
impl<T: Zeroize> Default for PathMap<T> {
    fn default() -> Self {
        Self(BTreeMap::new())
    }
}
impl<T: Zeroize> Drop for PathMap<T> {
    fn drop(&mut self) {
        for (mut path, mut value) in std::mem::take(&mut self.0) {
            path.zeroize();
            value.zeroize();
        }
    }
}

#[derive(Default)]
struct Spellings {
    values: PathMap<SecureString>,
    keys: PathMap<SecureString>,
    /// Application tags (`!Name`) on values and on keys, by path, carried through an edit.
    value_tags: PathMap<SecureString>,
    key_tags: PathMap<SecureString>,
    map_names: PathMap<Vec<SecureString>>,
}

pub(super) struct SourceDocument {
    pub value: WipedYaml,
    spellings: Spellings,
}

impl SourceDocument {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut wide = HashSet::new();
        let value = busbar_contract::yaml::with_deserializer(text, |d| {
            ReadShape { wide: &mut wide }.deserialize(d)
        })
        .map_err(|_| "invalid configuration YAML".to_owned())?;
        let mut source = Self {
            value,
            spellings: Spellings::default(),
        };
        let mut path = Vec::<String>::new();
        let read = busbar_contract::yaml::with_deserializer(text, |d| {
            TagFirst(ReadSource {
                shape: &source.value.0,
                path: &mut path,
                spellings: &mut source.spellings,
                wide: &wide,
            })
            .deserialize(d)
        });
        if read.is_err() {
            path.zeroize();
            return Err("invalid configuration YAML".to_owned());
        }
        normalize_keys(&mut source.value.0, &mut path, &source.spellings);
        path.zeroize();
        Ok(source)
    }

    pub fn apply(&mut self, patch: &DocumentPatch) -> Result<(), String> {
        if patch.0.get("$stages").is_some() {
            // A rejected late stage cannot partially mutate this source or escape its wiping
            // custody. Validate the entire replay on a guarded tree before moving any spelling.
            let mut checked = WipedYaml(self.value.0.clone());
            patch
                .apply_to(&mut checked.0)
                .map_err(|error| error.to_string())?;
            for stage in patch.stages() {
                self.apply(&DocumentPatch(stage.clone()))?;
            }
            return Ok(());
        }
        let prepared = patch
            .prepare(&self.value.0)
            .map_err(|error| error.to_string())?;
        let mut changed = PathMap::<()>::default();
        for (path, _) in &prepared.set {
            changed.0.insert(plain(path), ());
        }
        for path in &prepared.remove {
            changed.0.insert(plain(path), ());
        }
        forget(&mut self.spellings.values, &changed, false);
        forget(&mut self.spellings.keys, &changed, true);
        forget(&mut self.spellings.value_tags, &changed, false);
        forget(&mut self.spellings.key_tags, &changed, true);
        // Record explicit numeric spelling at the resolved append index before removals shift it.
        if let Some(set) = patch.0.get("set").and_then(serde_json::Value::as_object) {
            for ((_, value), (path, _)) in set.iter().zip(&prepared.set) {
                let mut path = plain(path);
                collect_numbers(value, &mut path, &mut self.spellings.values);
                path.zeroize();
            }
        }
        // Removals use original-snapshot paths. Mirror the same descending traversal for every
        // retained spelling so surviving members keep their own lexemes, key tags and secrets.
        for path in &prepared.remove {
            if sequence_parent(&self.value.0, path) {
                shift_after_remove(&mut self.spellings.values, path);
                shift_after_remove(&mut self.spellings.keys, path);
                shift_after_remove(&mut self.spellings.value_tags, path);
                shift_after_remove(&mut self.spellings.key_tags, path);
            }
        }
        prepared.apply(&mut self.value.0);
        Ok(())
    }

    pub fn to_yaml_bytes(&self) -> Result<SecureVec, String> {
        let mut bytes = SecureVec::new();
        if let Some(tag) = self.spellings.value_tags.0.get(&Vec::<String>::new()) {
            write_tag(&mut bytes, tag);
            if container(&self.value.0) {
                bytes.extend_from_slice(b"\n");
            }
        }
        let mut path = Vec::<String>::new();
        let emitted = emit(&self.value.0, &mut path, 0, &self.spellings, &mut bytes);
        path.zeroize();
        emitted.map_err(|_| "patched document encoding failed".to_owned())?;
        Ok(bytes)
    }
}

/// Remove append/edit/remove cycles without reconstructing hidden array members as JSON.
/// Checkpoints contain only guarded emitted subtrees and are discarded after this transaction.
pub(super) fn compact(patch: &DocumentPatch, yaml: &str) -> Result<DocumentPatch, String> {
    if patch.0.get("$stages").is_none() {
        return Ok(patch.clone());
    }
    struct Checkpoint {
        prefix: Vec<SecureString>,
        first_stage: usize,
        bytes: SecureVec,
    }
    let mut document = SourceDocument::parse(yaml)?;
    let mut result = patch.clone();
    let mut checkpoints: Vec<Checkpoint> = Vec::new();
    for (index, stage) in patch.stages().enumerate() {
        for path in super::stage_paths(stage).filter(|path| path.ends_with("/-")) {
            let path = super::pointer(path).map_err(|error| error.to_string())?;
            if let Some(prefix) = first_sequence(&document.value.0, &path) {
                if !checkpoints
                    .iter()
                    .any(|checkpoint| checkpoint.prefix == prefix)
                {
                    if let Some(bytes) = subtree_bytes(&document, &prefix)? {
                        checkpoints.push(Checkpoint {
                            prefix,
                            first_stage: index,
                            bytes,
                        });
                    }
                }
            }
        }
        document.apply(&DocumentPatch(stage.clone()))?;
        let mut keep = Vec::new();
        for checkpoint in checkpoints {
            if subtree_bytes(&document, &checkpoint.prefix)?.as_deref()
                == Some(checkpoint.bytes.as_slice())
            {
                let stages = result
                    .0
                    .get_mut("$stages")
                    .and_then(serde_json::Value::as_array_mut)
                    .expect("stages");
                for prior in &mut stages[checkpoint.first_stage..=index] {
                    let mut prior_patch = DocumentPatch(std::mem::take(prior));
                    prior_patch
                        .remove_below(&checkpoint.prefix)
                        .map_err(|error| error.to_string())?;
                    *prior = std::mem::take(&mut prior_patch.0);
                }
            } else {
                keep.push(checkpoint);
            }
        }
        checkpoints = keep;
    }
    result
        .compact_dominated()
        .map_err(|error| error.to_string())?;
    // Bind compaction to the full source semantics, including lexical spellings. A candidate
    // that cannot replay identically is discarded; the original bounded patch remains valid.
    let mut replay = SourceDocument::parse(yaml)?;
    if replay.apply(&result).is_err()
        || replay.to_yaml_bytes()?.as_slice() != document.to_yaml_bytes()?.as_slice()
    {
        return Ok(patch.clone());
    }
    result.check_limits().map_err(|error| error.to_string())?;
    Ok(result)
}

fn first_sequence(mut value: &Value, path: &[SecureString]) -> Option<Vec<SecureString>> {
    for (depth, key) in path.iter().enumerate() {
        if value.as_sequence().is_some() {
            return Some(path[..depth].to_vec());
        }
        value = value.as_mapping()?.get_key(key.as_str())?;
    }
    None
}

fn subtree_bytes(
    document: &SourceDocument,
    prefix: &[SecureString],
) -> Result<Option<SecureVec>, String> {
    let mut value = &document.value.0;
    for key in prefix {
        let Some(child) = value.as_mapping().and_then(|map| map.get_key(key.as_str())) else {
            return Ok(None);
        };
        value = child;
    }
    let mut bytes = SecureVec::new();
    let mut path = plain(prefix);
    let emitted = emit(value, &mut path, 0, &document.spellings, &mut bytes);
    path.zeroize();
    emitted.map_err(|_| "configuration sequence checkpoint encoding failed".to_owned())?;
    Ok(Some(bytes))
}

/// A decoded pointer as the plain path keys the spelling maps use (they wipe their keys).
fn plain(path: &[SecureString]) -> Vec<String> {
    path.iter().map(|part| part.as_str().to_owned()).collect()
}

fn sequence_parent(mut value: &Value, path: &[SecureString]) -> bool {
    for key in &path[..path.len() - 1] {
        if let Some(map) = value.as_mapping() {
            let Some(child) = map.get_key(key.as_str()) else {
                return false;
            };
            value = child;
        } else if let Some(seq) = value.as_sequence() {
            let Ok(index) = super::sequence_index(key) else {
                return false;
            };
            let Some(child) = seq.get(index) else {
                return false;
            };
            value = child;
        } else {
            return false;
        }
    }
    value.as_sequence().is_some()
}

fn shift_after_remove<T: Zeroize>(map: &mut PathMap<T>, removed: &[SecureString]) {
    let depth = removed.len() - 1;
    let index = super::sequence_index(&removed[depth]).expect("validated index");
    for (mut path, mut value) in std::mem::take(&mut map.0) {
        if path.len() > depth
            && path[..depth]
                .iter()
                .zip(&removed[..depth])
                .all(|(a, b)| a.as_str() == b.as_str())
        {
            let member = super::sequence_index(&path[depth]).expect("sequence spelling index");
            if member == index {
                path.zeroize();
                value.zeroize();
                continue;
            }
            if member > index {
                path[depth].zeroize();
                path[depth] = (member - 1).to_string();
            }
        }
        map.0.insert(path, value);
    }
}

fn collect_numbers(
    value: &serde_json::Value,
    path: &mut Vec<String>,
    values: &mut PathMap<SecureString>,
) {
    match value {
        serde_json::Value::Number(number) => {
            values.0.insert(
                path.clone(),
                SecureString::from_args(format_args!("{number}")),
            );
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                path.push(key.clone());
                collect_numbers(value, path, values);
                path.pop().expect("path member").zeroize();
            }
        }
        serde_json::Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                path.push(index.to_string());
                collect_numbers(value, path, values);
                path.pop().expect("path member").zeroize();
            }
        }
        _ => {}
    }
}

fn forget<T: Zeroize>(map: &mut PathMap<T>, changed: &PathMap<()>, key: bool) {
    for (mut path, mut value) in std::mem::take(&mut map.0) {
        let depth = path.len().saturating_sub(usize::from(key));
        if (1..=depth).any(|n| changed.0.contains_key(&path[..n])) {
            path.zeroize();
            value.zeroize();
        } else {
            map.0.insert(path, value);
        }
    }
}

// The standard YAML Value visitor refuses u128/i128 outright. Keep such scalars in owned
// string buffers until the spelling pass reads them. Buffer identities are never dereferenced;
// moving a String into the shape does not move its allocation, and the set dies before edits.
struct ReadShape<'a> {
    wide: &'a mut HashSet<usize>,
}
impl<'de> DeserializeSeed<'de> for ReadShape<'_> {
    type Value = WipedYaml;
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<WipedYaml, D::Error> {
        de.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for ReadShape<'_> {
    type Value = WipedYaml;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a YAML value")
    }
    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::Bool(value)))
    }
    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::from(value)))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::from(value)))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::Float(value)))
    }
    fn visit_i128<E: serde::de::Error>(self, value: i128) -> Result<WipedYaml, E> {
        let text = value.to_string();
        self.wide.insert(text.as_ptr() as usize);
        Ok(WipedYaml(Value::Text(text)))
    }
    fn visit_u128<E: serde::de::Error>(self, value: u128) -> Result<WipedYaml, E> {
        let text = value.to_string();
        self.wide.insert(text.as_ptr() as usize);
        Ok(WipedYaml(Value::Text(text)))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::Text(value.to_owned())))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::Text(value)))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::Null))
    }
    fn visit_none<E: serde::de::Error>(self) -> Result<WipedYaml, E> {
        self.visit_unit()
    }
    fn visit_some<D: serde::Deserializer<'de>>(self, de: D) -> Result<WipedYaml, D::Error> {
        self.deserialize(de)
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<WipedYaml, S::Error> {
        let mut value = WipedYaml(Value::Array(Vec::new()));
        while let Some(mut child) = seq.next_element_seed(ReadShape { wide: self.wide })? {
            value
                .0
                .as_sequence_mut()
                .expect("sequence")
                .push(std::mem::replace(&mut child.0, Value::Null));
        }
        Ok(value)
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<WipedYaml, M::Error> {
        let mut value = WipedYaml(Value::Map(Vec::new()));
        while let Some(mut key) = map.next_key_seed(ReadShape { wide: self.wide })? {
            if value.0.as_mapping().expect("mapping").contains_key(&key.0) {
                return Err(serde::de::Error::custom("duplicate source map key"));
            }
            let mut child = map.next_value_seed(ReadShape { wide: self.wide })?;
            value.0.as_mapping_mut().expect("mapping").insert_key(
                std::mem::replace(&mut key.0, Value::Null),
                std::mem::replace(&mut child.0, Value::Null),
            );
        }
        Ok(value)
    }
}

struct ReadSource<'a> {
    shape: &'a Value,
    path: &'a mut Vec<String>,
    spellings: &'a mut Spellings,
    wide: &'a HashSet<usize>,
}
impl<'de> DeserializeSeed<'de> for ReadSource<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        match self.shape {
            Value::Map(_) => de.deserialize_map(self),
            Value::Array(_) => de.deserialize_seq(self),
            // The reader refuses null into a string, and every null spelling means the same
            // null, so no spelling is kept: it is written back as the emitter's null.
            Value::Null => serde::de::IgnoredAny::deserialize(de).map(|_| ()),
            Value::Text(value) if !self.wide.contains(&(value.as_ptr() as usize)) => {
                // Decoded string content is already retained by the wiping source tree.
                let _text = SecureString::deserialize(de)?;
                Ok(())
            }
            _ => {
                let text = SecureString::deserialize(de)?;
                self.spellings.values.0.insert(self.path.clone(), text);
                Ok(())
            }
        }
    }
}

/// serde-saphyr's newtype name for its public `serde_saphyr::Tagged<T>` wrapper: a deserializer
/// asked for it hands the visitor the node as the sequence `[value, tag?]`. Any other
/// deserializer calls `visit_newtype_struct`, and the node reads as untagged.
const TAGGED: &str = "__yaml_tagged";

/// An application tag worth carrying (`!Name`, or a non-core URI); core-schema tags
/// (`tag:yaml.org,2002:*`) only restate how the scalar resolves and are not kept.
fn application_tag(tag: String) -> Option<String> {
    (!tag.starts_with("tag:yaml.org,2002:")).then_some(tag)
}

/// Read one node's tag, then the node itself through `ReadSource`.
struct TagFirst<'a>(ReadSource<'a>);
impl<'de> DeserializeSeed<'de> for TagFirst<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        de.deserialize_newtype_struct(TAGGED, self)
    }
}
impl<'de> Visitor<'de> for TagFirst<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a possibly tagged source node")
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(self, de: D) -> Result<(), D::Error> {
        self.0.deserialize(de)
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        let ReadSource {
            shape,
            path,
            spellings,
            wide,
        } = self.0;
        seq.next_element_seed(ReadSource {
            shape,
            path: &mut *path,
            spellings: &mut *spellings,
            wide,
        })?
        .ok_or_else(|| serde::de::Error::custom("source node changed"))?;
        if let Some(tag) = seq.next_element::<String>()?.and_then(application_tag) {
            spellings
                .value_tags
                .0
                .insert(path.clone(), SecureString::from(tag));
        }
        Ok(())
    }
}

/// Read a map key's text and its tag.
struct TaggedKey;
impl<'de> DeserializeSeed<'de> for TaggedKey {
    type Value = (String, Option<String>);
    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<Self::Value, D::Error> {
        de.deserialize_newtype_struct(TAGGED, self)
    }
}
impl<'de> Visitor<'de> for TaggedKey {
    type Value = (String, Option<String>);
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a possibly tagged source key")
    }
    fn visit_newtype_struct<D: serde::Deserializer<'de>>(
        self,
        de: D,
    ) -> Result<Self::Value, D::Error> {
        Ok((String::deserialize(de)?, None))
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let name: String = seq
            .next_element()?
            .ok_or_else(|| serde::de::Error::custom("source key changed"))?;
        let tag = seq.next_element::<String>()?.and_then(application_tag);
        Ok((name, tag))
    }
}

struct Names(HashSet<String>);
impl Drop for Names {
    fn drop(&mut self) {
        for mut name in self.0.drain() {
            name.zeroize();
        }
    }
}

impl<'de> Visitor<'de> for ReadSource<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the same source document shape")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<(), M::Error> {
        let shape = self.shape.as_mapping().expect("mapping shape");
        let mut names = Vec::with_capacity(shape.len());
        let mut seen = Names(HashSet::new());
        for (key, value) in shape {
            let (name, key_tag) = map
                .next_key_seed(TaggedKey)?
                .ok_or_else(|| serde::de::Error::custom("source map changed"))?;
            let name = SecureString::from(name);
            let key_tag = key_tag.map(SecureString::from);
            if !seen.0.insert(name.as_str().to_owned()) {
                return Err(serde::de::Error::custom("duplicate source map key"));
            }
            self.path.push(name.as_str().to_owned());
            if let Some(tag) = key_tag {
                self.spellings.key_tags.0.insert(self.path.clone(), tag);
            }
            if !key.is_string() {
                self.spellings
                    .keys
                    .0
                    .insert(self.path.clone(), name.clone());
            }
            map.next_value_seed(TagFirst(ReadSource {
                shape: value,
                path: self.path,
                spellings: self.spellings,
                wide: self.wide,
            }))?;
            self.path.pop().expect("path member").zeroize();
            names.push(name);
        }
        if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("source map changed"));
        }
        self.spellings.map_names.0.insert(self.path.clone(), names);
        Ok(())
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<(), S::Error> {
        for (index, value) in self
            .shape
            .as_sequence()
            .expect("sequence shape")
            .iter()
            .enumerate()
        {
            self.path.push(index.to_string());
            seq.next_element_seed(TagFirst(ReadSource {
                shape: value,
                path: self.path,
                spellings: self.spellings,
                wide: self.wide,
            }))?
            .ok_or_else(|| serde::de::Error::custom("source sequence changed"))?;
            self.path.pop().expect("path member").zeroize();
        }
        if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
            return Err(serde::de::Error::custom("source sequence changed"));
        }
        Ok(())
    }
}

fn normalize_keys(value: &mut Value, path: &mut Vec<String>, spellings: &Spellings) {
    match value {
        Value::Map(map) => {
            let names = &spellings.map_names.0[path.as_slice()];
            for ((mut key, mut value), name) in std::mem::take(map).into_iter().zip(names) {
                wipe_yaml(&mut key);
                path.push(name.as_str().to_owned());
                normalize_keys(&mut value, path, spellings);
                path.pop().expect("path member").zeroize();
                map.insert_key(Value::Text(name.as_str().to_owned()), value);
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                path.push(index.to_string());
                normalize_keys(value, path, spellings);
                path.pop().expect("path member").zeroize();
            }
        }
        _ => {}
    }
}

fn indent(bytes: &mut SecureVec, n: usize) {
    for _ in 0..n {
        bytes.extend_from_slice(b" ");
    }
}
fn quoted(bytes: &mut SecureVec, text: &str) -> Result<(), ()> {
    serde_json::to_writer(bytes, text).map_err(|_| ())
}
fn container(value: &Value) -> bool {
    match value {
        Value::Map(map) => !map.is_empty(),
        Value::Array(seq) => !seq.is_empty(),
        _ => false,
    }
}
/// Write a carried tag and the space after it: a local `!Name` as written, a URI as `!<uri>`.
fn write_tag(bytes: &mut SecureVec, tag: &str) {
    if tag.starts_with('!') {
        bytes.extend_from_slice(tag.as_bytes());
    } else {
        bytes.extend_from_slice(b"!<");
        bytes.extend_from_slice(tag.as_bytes());
        bytes.extend_from_slice(b">");
    }
    bytes.extend_from_slice(b" ");
}
fn after_marker(
    value: &Value,
    path: &mut Vec<String>,
    depth: usize,
    spellings: &Spellings,
    bytes: &mut SecureVec,
) -> Result<(), ()> {
    bytes.extend_from_slice(b" ");
    if let Some(tag) = spellings.value_tags.0.get(path.as_slice()) {
        write_tag(bytes, tag);
    }
    if container(value) {
        bytes.extend_from_slice(b"\n");
        emit(value, path, depth + 2, spellings, bytes)
    } else {
        scalar(value, path, spellings, bytes)?;
        bytes.extend_from_slice(b"\n");
        Ok(())
    }
}
fn emit(
    value: &Value,
    path: &mut Vec<String>,
    depth: usize,
    spellings: &Spellings,
    bytes: &mut SecureVec,
) -> Result<(), ()> {
    match value {
        Value::Map(map) if !map.is_empty() => {
            for (key, value) in map {
                let key = key.as_str().ok_or(())?;
                path.push(key.to_owned());
                indent(bytes, depth);
                if let Some(tag) = spellings.key_tags.0.get(path.as_slice()) {
                    write_tag(bytes, tag);
                }
                if let Some(raw) = spellings.keys.0.get(path.as_slice()) {
                    bytes.extend_from_slice(raw.as_bytes());
                } else {
                    quoted(bytes, key)?;
                }
                bytes.extend_from_slice(b":");
                after_marker(value, path, depth, spellings, bytes)?;
                path.pop().expect("path member").zeroize();
            }
        }
        Value::Array(values) if !values.is_empty() => {
            for (index, value) in values.iter().enumerate() {
                path.push(index.to_string());
                indent(bytes, depth);
                bytes.extend_from_slice(b"-");
                after_marker(value, path, depth, spellings, bytes)?;
                path.pop().expect("path member").zeroize();
            }
        }
        _ => {
            indent(bytes, depth);
            scalar(value, path, spellings, bytes)?;
            bytes.extend_from_slice(b"\n");
        }
    }
    Ok(())
}
fn scalar(
    value: &Value,
    path: &[String],
    spellings: &Spellings,
    bytes: &mut SecureVec,
) -> Result<(), ()> {
    if let Some(raw) = spellings.values.0.get(path) {
        bytes.extend_from_slice(raw.as_bytes());
        return Ok(());
    }
    match value {
        Value::Text(text) => quoted(bytes, text),
        _ => {
            let mut encoded = SecureVec::new();
            busbar_contract::yaml::to_writer(&mut encoded, value).map_err(|_| ())?;
            let kept = encoded
                .iter()
                .rposition(|byte| !byte.is_ascii_whitespace())
                .map_or(0, |last| last + 1);
            encoded.truncate(kept);
            bytes.extend_from_slice(&encoded);
            Ok(())
        }
    }
}
