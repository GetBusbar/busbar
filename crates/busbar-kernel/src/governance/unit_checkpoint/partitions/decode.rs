// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Reject oversized selected collections before the typed decoder allocates them. The signed
//! payload is already byte-bounded; this pass owns no quantity values or alternate JSON tree.

use std::{collections::BTreeSet, fmt};

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};

use super::*;

#[derive(Clone, Copy)]
struct Shape {
    sequence: usize,
    classes: bool,
}

impl Shape {
    fn member(name: &str) -> Self {
        Self {
            sequence: match name {
                "attempts" => MAX_PREPARATIONS,
                "targets" => MAX_TARGETS,
                "terminal" => MAX_TERMINAL_EVENTS,
                "audit" => MAX_AUDIT_BYTES,
                "payload" => MAX_CHECKPOINT_BYTES,
                _ => MAX_CLASSES,
            },
            classes: matches!(
                name,
                "classes" | "declared_classes" | "attempt_classes" | "physical_classes"
            ),
        }
    }
}

pub(crate) fn check_encoded(bytes: &[u8]) -> RecordStoreResult<()> {
    if bytes.len() > MAX_CHECKPOINT_BYTES
        || busbar_contract::spans::exceeds_max_depth(bytes, busbar_contract::spans::MAX_JSON_DEPTH)
    {
        return Err(invalid("selected checkpoint exceeds encoded limits"));
    }
    let mut decoder = busbar_contract::json::Deserializer::from_slice(bytes);
    Shape::member("root")
        .deserialize(&mut decoder)
        .map_err(|_| invalid("selected checkpoint collection or text bound is invalid"))?;
    decoder
        .end()
        .map_err(|_| invalid("selected checkpoint has trailing bytes"))
}

impl<'de> DeserializeSeed<'de> for Shape {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<(), D::Error> {
        decoder.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Shape {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded selected checkpoint value")
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_i128<E: de::Error>(self, _: i128) -> Result<(), E> {
        Ok(())
    }
    fn visit_u128<E: de::Error>(self, _: u128) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, text: &str) -> Result<(), E> {
        if text.len() > if self.classes { 64 } else { MAX_IDENTITY_BYTES } {
            Err(E::custom("selected checkpoint text exceeds its bound"))
        } else {
            Ok(())
        }
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        if self.classes {
            let mut classes = BTreeSet::new();
            while let Some(class) = values.next_element_seed(Name { class: true })? {
                if classes.len() == MAX_CLASSES || !classes.insert(class) {
                    return Err(de::Error::custom(
                        "selected class declaration is repeated or overbound",
                    ));
                }
            }
            return Ok(());
        }
        let mut count = 0;
        while values.next_element_seed(self)?.is_some() {
            count += 1;
            if count > self.sequence {
                return Err(de::Error::custom(
                    "selected checkpoint array exceeds its bound",
                ));
            }
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut values: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = values.next_key_seed(Name {
            class: self.classes,
        })? {
            if keys.len() == MAX_CLASSES || !keys.insert(key.clone()) {
                return Err(de::Error::custom(
                    "selected checkpoint object is overbound or repeats a key",
                ));
            }
            values.next_value_seed(Shape::member(&key))?;
        }
        Ok(())
    }
}

struct Name {
    class: bool,
}
impl<'de> DeserializeSeed<'de> for Name {
    type Value = String;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<String, D::Error> {
        decoder.deserialize_str(self)
    }
}
impl Visitor<'_> for Name {
    type Value = String;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a bounded field name")
    }
    fn visit_str<E: de::Error>(self, key: &str) -> Result<String, E> {
        if key.len() > 64 || (self.class && !class_name(key)) {
            return Err(E::custom("selected checkpoint field name is invalid"));
        }
        Ok(key.to_owned())
    }
}
