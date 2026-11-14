// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SETTINGS DOCUMENT READ WITH GUARDED STRINGS: configure-time JSON, parsed once per validate,
//! open or refresh through the protected reader's masked view ([`super::protected_json`]).

use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_json::Value;
use zeroize::Zeroize;

use super::protected_json::{masked, AnyKey, Custody, Doc, Held, NumberText, ObjectKey, Unwatched};
use super::JsonReplyError;

/// A settings JSON value whose strings and object keys wipe on drop, including partially parsed
/// trees and replaced duplicate values. This is for readable configuration, not extracted secret
/// responses (those use [`super::SelectedJson`]). Numeric scratch in serde_json is not zeroized.
#[derive(Clone)]
pub struct SettingsValue(pub(crate) Value);

impl std::fmt::Debug for SettingsValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SettingsValue(<redacted>)")
    }
}

impl std::ops::Deref for SettingsValue {
    type Target = Value;
    fn deref(&self) -> &Value {
        &self.0
    }
}

impl From<Value> for SettingsValue {
    fn from(value: Value) -> Self {
        Self(value)
    }
}

impl SettingsValue {
    /// Mutably visit a configuration value by JSON pointer. Any value moved out must be put
    /// into another wiping owner by the caller; dropping this document only wipes what remains.
    pub fn pointer_mut(&mut self, pointer: &str) -> Option<&mut Value> {
        self.0.pointer_mut(pointer)
    }

    fn object() -> Self {
        Self(Value::Object(serde_json::Map::new()))
    }
    fn put(&mut self, key: &mut String, value: &mut Value) {
        if let Value::Object(items) = &mut self.0 {
            if let Some(previous) = items.get_mut(key.as_str()) {
                std::mem::swap(previous, value);
            } else {
                items.insert(std::mem::take(key), std::mem::take(value));
            }
        }
    }
    fn push(&mut self, value: &mut Value) {
        if let Value::Array(items) = &mut self.0 {
            items.push(std::mem::take(value));
        }
    }
    /// Move a configuration member out, leaving null under its wiping key.
    pub fn take(&mut self, key: &str) -> Option<Self> {
        self.0.get_mut(key).map(|value| Self(std::mem::take(value)))
    }
    /// Move a configuration string out. The caller owns its cleanup from here.
    pub fn into_string(mut self) -> Option<String> {
        match &mut self.0 {
            Value::String(s) => Some(std::mem::take(s)),
            _ => None,
        }
    }
}

impl Drop for SettingsValue {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

pub(crate) fn wipe(v: &mut Value) {
    match v {
        Value::String(s) => s.zeroize(),
        Value::Number(_) => *v = Value::from(0u64),
        Value::Bool(b) => *b = false,
        Value::Array(items) => items.iter_mut().for_each(wipe),
        Value::Object(map) => {
            for (mut key, mut value) in std::mem::take(map) {
                key.zeroize();
                wipe(&mut value);
            }
        }
        Value::Null => {}
    }
}

/// Read a configuration document with guarded strings, rejecting duplicate top-level members.
/// Schema and value policy belong to the caller. Nested objects retain last-duplicate-wins
/// semantics. Entire input validation and serde's ordinary nesting bound apply.
pub fn settings_document(body: &[u8]) -> Result<SettingsValue, JsonReplyError> {
    document(body, true).map_err(JsonReplyError::from)
}

pub(crate) fn document(body: &[u8], unique_root: bool) -> Result<SettingsValue, serde_json::Error> {
    let view = masked(body, Unwatched);
    let doc = Doc {
        body,
        view: &view,
        custody: Unwatched,
    };
    let mut de = serde_json::Deserializer::from_slice(&view);
    Tree(doc, unique_root)
        .deserialize(&mut de)
        .and_then(|value| de.end().map(|()| value))
}

/// Any value, kept whole (the token's reference).
struct Tree<'a, C>(Doc<'a, C>, bool);

impl<'de, C: Custody> DeserializeSeed<'de> for Tree<'_, C> {
    type Value = SettingsValue;

    fn deserialize<D: serde::Deserializer<'de>>(self, de: D) -> Result<SettingsValue, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de, C: Custody> Visitor<'de> for Tree<'_, C> {
    type Value = SettingsValue;

    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_unit<E: Error>(self) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::Null))
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::Bool(value)))
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::from(value)))
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::from(value)))
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<SettingsValue, E> {
        Ok(SettingsValue(Value::from(value)))
    }

    fn visit_borrowed_str<E: Error>(self, value: &'de str) -> Result<SettingsValue, E> {
        let text = self.0.decoded::<E>(value, Held::Value)?;
        Ok(SettingsValue(Value::String(text.into_string())))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SettingsValue, A::Error> {
        let mut items = SettingsValue(Value::Array(Vec::new()));
        while let Some(mut item) = seq.next_element_seed(Tree(self.0, false))? {
            items.push(&mut item.0);
        }
        Ok(items)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<SettingsValue, A::Error> {
        let mut tree = SettingsValue::object();
        while let Some(key) = map.next_key_seed(AnyKey(self.0))? {
            let ObjectKey::Text(key) = key else {
                return Ok(SettingsValue(Value::Number(
                    map.next_value_seed(NumberText)?,
                )));
            };
            if self.1 && tree.0.get(key.as_str()).is_some() {
                return Err(A::Error::custom("duplicate configuration field"));
            }
            let mut value = map.next_value_seed(Tree(self.0, false))?;
            let mut key = key.into_string();
            tree.put(&mut key, &mut value.0);
            // A duplicate leaves the key here: wipe it on the way out.
            drop(crate::secure::SecureString::from(key));
        }
        Ok(tree)
    }
}

impl super::Cred {
    /// Take a credential setting out of a parsed settings document, wiping the string where it
    pub fn take(v: &mut Value) -> Option<Self> {
        let Value::String(s) = v else {
            return None;
        };
        let bytes = crate::secure::SecureVec::from(core::mem::take(s).into_bytes());
        *v = Value::Null;
        Some(Self::from_bytes(bytes))
    }
}
