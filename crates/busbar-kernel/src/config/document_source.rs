// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Transient source spelling custody for document edits. YAML's streaming reader can deserialize
//! an implicit scalar as a String, so normalizing TRUE or 0x10 changes an omitted String value.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use serde::de::{DeserializeSeed, EnumAccess, MapAccess, SeqAccess, VariantAccess, Visitor};
use serde::Deserialize;
use serde_yaml::Value;
use zeroize::{Zeroize, Zeroizing};

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
    values: PathMap<Zeroizing<String>>,
    keys: PathMap<Zeroizing<String>>,
    key_tags: PathMap<WipedYaml>,
    map_names: PathMap<Vec<Zeroizing<String>>>,
}

pub(super) struct SourceDocument {
    pub value: WipedYaml,
    spellings: Spellings,
}

impl SourceDocument {
    pub fn parse(text: &str) -> Result<Self, String> {
        let mut wide = HashSet::new();
        let value = ReadShape { wide: &mut wide }
            .deserialize(serde_yaml::Deserializer::from_str(text))
            .map_err(|_| "invalid configuration YAML".to_owned())?;
        let mut source = Self {
            value,
            spellings: Spellings::default(),
        };
        let mut path = Zeroizing::new(Vec::new());
        ReadSource {
            shape: &source.value.0,
            path: &mut path,
            spellings: &mut source.spellings,
            wide: &wide,
        }
        .deserialize(serde_yaml::Deserializer::from_str(text))
        .map_err(|_| "invalid configuration YAML".to_owned())?;
        normalize_keys(&mut source.value.0, &mut path, &source.spellings);
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
            changed.0.insert((**path).clone(), ());
        }
        for path in &prepared.remove {
            changed.0.insert((**path).clone(), ());
        }
        forget(&mut self.spellings.values, &changed, false);
        forget(&mut self.spellings.keys, &changed, true);
        forget(&mut self.spellings.key_tags, &changed, true);
        // Record explicit numeric spelling at the resolved append index before removals shift it.
        if let Some(set) = patch.0.get("set").and_then(serde_json::Value::as_object) {
            for ((_, value), (path, _)) in set.iter().zip(&prepared.set) {
                let mut path = path.clone();
                collect_numbers(value, &mut path, &mut self.spellings.values);
            }
        }
        // Removals use original-snapshot paths. Mirror the same descending traversal for every
        // retained spelling so surviving members keep their own lexemes, key tags and secrets.
        for path in &prepared.remove {
            if sequence_parent(&self.value.0, path) {
                shift_after_remove(&mut self.spellings.values, path);
                shift_after_remove(&mut self.spellings.keys, path);
                shift_after_remove(&mut self.spellings.key_tags, path);
            }
        }
        prepared.apply(&mut self.value.0);
        Ok(())
    }

    pub fn to_yaml_bytes(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut bytes = Zeroizing::new(Vec::new());
        emit(
            &self.value.0,
            &mut Zeroizing::new(Vec::new()),
            0,
            &self.spellings,
            &mut bytes,
        )
        .map_err(|_| "patched document encoding failed".to_owned())?;
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
        prefix: Zeroizing<Vec<String>>,
        first_stage: usize,
        bytes: Zeroizing<Vec<u8>>,
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
            if subtree_bytes(&document, &checkpoint.prefix)?.as_deref() == Some(&*checkpoint.bytes)
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
    if replay.apply(&result).is_err() || replay.to_yaml_bytes()? != document.to_yaml_bytes()? {
        return Ok(patch.clone());
    }
    result.check_limits().map_err(|error| error.to_string())?;
    Ok(result)
}

fn first_sequence(mut value: &Value, path: &[String]) -> Option<Zeroizing<Vec<String>>> {
    for (depth, key) in path.iter().enumerate() {
        if value.as_sequence().is_some() {
            return Some(Zeroizing::new(path[..depth].to_vec()));
        }
        value = value.as_mapping()?.get(key.as_str())?;
    }
    None
}

fn subtree_bytes(
    document: &SourceDocument,
    prefix: &[String],
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let mut value = &document.value.0;
    for key in prefix {
        let Some(child) = value.as_mapping().and_then(|map| map.get(key.as_str())) else {
            return Ok(None);
        };
        value = child;
    }
    let mut bytes = Zeroizing::new(Vec::new());
    emit(
        value,
        &mut Zeroizing::new(prefix.to_vec()),
        0,
        &document.spellings,
        &mut bytes,
    )
    .map_err(|_| "configuration sequence checkpoint encoding failed".to_owned())?;
    Ok(Some(bytes))
}

fn sequence_parent(mut value: &Value, path: &[String]) -> bool {
    for key in &path[..path.len() - 1] {
        if let Some(map) = value.as_mapping() {
            let Some(child) = map.get(key.as_str()) else {
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

fn shift_after_remove<T: Zeroize>(map: &mut PathMap<T>, removed: &[String]) {
    let depth = removed.len() - 1;
    let index = super::sequence_index(&removed[depth]).expect("validated index");
    for (mut path, mut value) in std::mem::take(&mut map.0) {
        if path.len() > depth && path[..depth] == removed[..depth] {
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
    values: &mut PathMap<Zeroizing<String>>,
) {
    match value {
        serde_json::Value::Number(number) => {
            values
                .0
                .insert(path.clone(), Zeroizing::new(number.to_string()));
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
        Ok(WipedYaml(Value::Number(value.into())))
    }
    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::Number(value.into())))
    }
    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::Number(value.into())))
    }
    fn visit_i128<E: serde::de::Error>(self, value: i128) -> Result<WipedYaml, E> {
        let text = value.to_string();
        self.wide.insert(text.as_ptr() as usize);
        Ok(WipedYaml(Value::String(text)))
    }
    fn visit_u128<E: serde::de::Error>(self, value: u128) -> Result<WipedYaml, E> {
        let text = value.to_string();
        self.wide.insert(text.as_ptr() as usize);
        Ok(WipedYaml(Value::String(text)))
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::String(value.to_owned())))
    }
    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<WipedYaml, E> {
        Ok(WipedYaml(Value::String(value)))
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
        let mut value = WipedYaml(Value::Sequence(Vec::new()));
        while let Some(mut child) = seq.next_element_seed(ReadShape { wide: self.wide })? {
            value
                .0
                .as_sequence_mut()
                .expect("sequence")
                .push(std::mem::take(&mut child.0));
        }
        Ok(value)
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<WipedYaml, M::Error> {
        let mut value = WipedYaml(Value::Mapping(Default::default()));
        while let Some(mut key) = map.next_key_seed(ReadShape { wide: self.wide })? {
            if value.0.as_mapping().expect("mapping").contains_key(&key.0) {
                return Err(serde::de::Error::custom("duplicate source map key"));
            }
            let mut child = map.next_value_seed(ReadShape { wide: self.wide })?;
            value
                .0
                .as_mapping_mut()
                .expect("mapping")
                .insert(std::mem::take(&mut key.0), std::mem::take(&mut child.0));
        }
        Ok(value)
    }
    fn visit_enum<A: EnumAccess<'de>>(self, data: A) -> Result<WipedYaml, A::Error> {
        let (tag, variant) = data.variant::<String>()?;
        let mut value = variant.newtype_variant_seed(ReadShape { wide: self.wide })?;
        Ok(WipedYaml(Value::Tagged(Box::new(
            serde_yaml::value::TaggedValue {
                tag: serde_yaml::value::Tag::new(tag),
                value: std::mem::take(&mut value.0),
            },
        ))))
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
            Value::Tagged(tag) => ReadSource {
                shape: &tag.value,
                ..self
            }
            .deserialize(de),
            Value::Mapping(_) => de.deserialize_map(self),
            Value::Sequence(_) => de.deserialize_seq(self),
            Value::String(value) if !self.wide.contains(&(value.as_ptr() as usize)) => {
                // Decoded string content is already retained by the wiping source tree.
                let _text = Zeroizing::new(String::deserialize(de)?);
                Ok(())
            }
            _ => {
                let text = Zeroizing::new(String::deserialize(de)?);
                self.spellings.values.0.insert(self.path.clone(), text);
                Ok(())
            }
        }
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
            let name = Zeroizing::new(
                map.next_key::<String>()?
                    .ok_or_else(|| serde::de::Error::custom("source map changed"))?,
            );
            if !seen.0.insert((*name).clone()) {
                return Err(serde::de::Error::custom("duplicate source map key"));
            }
            self.path.push((*name).clone());
            if matches!(key, Value::Tagged(_)) {
                self.spellings
                    .key_tags
                    .0
                    .insert(self.path.clone(), WipedYaml(key.clone()));
            }
            if !key.is_string() {
                self.spellings
                    .keys
                    .0
                    .insert(self.path.clone(), name.clone());
            }
            map.next_value_seed(ReadSource {
                shape: value,
                path: self.path,
                spellings: self.spellings,
                wide: self.wide,
            })?;
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
            seq.next_element_seed(ReadSource {
                shape: value,
                path: self.path,
                spellings: self.spellings,
                wide: self.wide,
            })?
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
        Value::Tagged(tag) => normalize_keys(&mut tag.value, path, spellings),
        Value::Mapping(map) => {
            let names = &spellings.map_names.0[path.as_slice()];
            for ((mut key, mut value), name) in std::mem::take(map).into_iter().zip(names) {
                wipe_yaml(&mut key);
                path.push((**name).clone());
                normalize_keys(&mut value, path, spellings);
                path.pop().expect("path member").zeroize();
                map.insert(Value::String((**name).clone()), value);
            }
        }
        Value::Sequence(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                path.push(index.to_string());
                normalize_keys(value, path, spellings);
                path.pop().expect("path member").zeroize();
            }
        }
        _ => {}
    }
}

fn indent(bytes: &mut Vec<u8>, n: usize) {
    bytes.extend(std::iter::repeat_n(b' ', n));
}
fn quoted(bytes: &mut Vec<u8>, text: &str) -> Result<(), ()> {
    serde_json::to_writer(bytes, text).map_err(|_| ())
}
fn container(value: &Value) -> bool {
    match value {
        Value::Mapping(map) => !map.is_empty(),
        Value::Sequence(seq) => !seq.is_empty(),
        Value::Tagged(tag) => container(&tag.value),
        _ => false,
    }
}
fn tags<'a>(mut value: &'a Value, bytes: &mut Vec<u8>) -> Result<&'a Value, ()> {
    while let Value::Tagged(tagged) = value {
        // Let the YAML emitter encode tag URIs; the dummy scalar contains no source value.
        let dummy = Value::Tagged(Box::new(serde_yaml::value::TaggedValue {
            tag: tagged.tag.clone(),
            value: Value::Null,
        }));
        let mut encoded = Zeroizing::new(Vec::new());
        serde_yaml::to_writer(&mut *encoded, &dummy).map_err(|_| ())?;
        let end = encoded
            .iter()
            .position(|byte| byte.is_ascii_whitespace())
            .ok_or(())?;
        bytes.extend_from_slice(&encoded[..end]);
        bytes.push(b' ');
        value = &tagged.value;
    }
    Ok(value)
}
fn after_marker(
    value: &Value,
    path: &mut Vec<String>,
    depth: usize,
    spellings: &Spellings,
    bytes: &mut Vec<u8>,
) -> Result<(), ()> {
    bytes.push(b' ');
    let untagged = tags(value, bytes)?;
    if container(untagged) {
        bytes.push(b'\n');
        emit(untagged, path, depth + 2, spellings, bytes)
    } else {
        scalar(untagged, path, spellings, bytes)?;
        bytes.push(b'\n');
        Ok(())
    }
}
fn emit(
    value: &Value,
    path: &mut Vec<String>,
    depth: usize,
    spellings: &Spellings,
    bytes: &mut Vec<u8>,
) -> Result<(), ()> {
    let tagged_container = matches!(value, Value::Tagged(_)) && container(value);
    let value = tags(value, bytes)?;
    if tagged_container {
        bytes.push(b'\n');
    }
    match value {
        Value::Mapping(map) if !map.is_empty() => {
            for (key, value) in map {
                let key = key.as_str().ok_or(())?;
                path.push(key.to_owned());
                indent(bytes, depth);
                if let Some(tagged) = spellings.key_tags.0.get(path.as_slice()) {
                    tags(&tagged.0, bytes)?;
                }
                if let Some(raw) = spellings.keys.0.get(path.as_slice()) {
                    bytes.extend_from_slice(raw.as_bytes());
                } else {
                    quoted(bytes, key)?;
                }
                bytes.push(b':');
                after_marker(value, path, depth, spellings, bytes)?;
                path.pop().expect("path member").zeroize();
            }
        }
        Value::Sequence(values) if !values.is_empty() => {
            for (index, value) in values.iter().enumerate() {
                path.push(index.to_string());
                indent(bytes, depth);
                bytes.push(b'-');
                after_marker(value, path, depth, spellings, bytes)?;
                path.pop().expect("path member").zeroize();
            }
        }
        _ => {
            indent(bytes, depth);
            scalar(value, path, spellings, bytes)?;
            bytes.push(b'\n');
        }
    }
    Ok(())
}
fn scalar(
    value: &Value,
    path: &[String],
    spellings: &Spellings,
    bytes: &mut Vec<u8>,
) -> Result<(), ()> {
    if let Some(raw) = spellings.values.0.get(path) {
        bytes.extend_from_slice(raw.as_bytes());
        return Ok(());
    }
    match value {
        Value::String(text) => quoted(bytes, text),
        _ => {
            let mut encoded = Zeroizing::new(Vec::new());
            serde_yaml::to_writer(&mut *encoded, value).map_err(|_| ())?;
            while encoded
                .last()
                .is_some_and(|byte| byte.is_ascii_whitespace())
            {
                encoded.pop();
            }
            bytes.extend_from_slice(&encoded);
            Ok(())
        }
    }
}
