// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Canonical member-name checks over stored JSON record bytes, streamed straight from the bytes:
//! no JSON DOM is built. A record that fails a check is corrupt; the typed decode that follows reads
//! the same bytes.

use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use std::fmt;

/// Which member names one object level may carry.
#[derive(Clone, Copy)]
pub(super) enum Allowed<'a> {
    /// Any member name.
    Any,
    /// Exactly these names (a subset may be present).
    List(&'a [&'a str]),
    /// Names this predicate accepts.
    Pred(&'a dyn Fn(&str) -> bool),
}

/// One object level: its allowed member names and, optionally, one member that must be present
/// and is checked one level deeper.
#[derive(Clone, Copy)]
pub(super) struct Level<'a> {
    pub allowed: Allowed<'a>,
    pub required: Option<(&'a str, Member<'a>)>,
}

/// The shape of a required member.
#[derive(Clone, Copy)]
pub(super) enum Member<'a> {
    /// An object checked with the nested level.
    Object(&'a Level<'a>),
    /// An array whose every element is an object checked with the nested level.
    Array(&'a Level<'a>),
}

/// Whether `bytes` is one JSON object of the given shape (and nothing after it).
pub(super) fn check(bytes: &[u8], level: &Level<'_>) -> bool {
    let mut de = busbar_contract::json::Deserializer::from_slice(bytes);
    level.deserialize(&mut de).is_ok() && de.end().is_ok()
}

impl<'de> DeserializeSeed<'de> for &Level<'_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for &Level<'_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a canonical record object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = false;
        while let Some(key) = map.next_key_seed(KeySeed(self))? {
            match key {
                Some(Member::Object(nested)) => {
                    seen = true;
                    map.next_value_seed(nested)?;
                }
                Some(Member::Array(nested)) => {
                    seen = true;
                    map.next_value_seed(ArraySeed(nested))?;
                }
                None => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if self.required.is_some() && !seen {
            return Err(de::Error::custom("required member absent"));
        }
        Ok(())
    }
}

/// Reads one member name: refuses a name the level does not allow, and names the required member.
struct KeySeed<'l, 'a>(&'l Level<'a>);

impl<'de, 'a> DeserializeSeed<'de> for KeySeed<'_, 'a> {
    type Value = Option<Member<'a>>;

    fn deserialize<D: de::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> Result<Option<Member<'a>>, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de, 'a> Visitor<'de> for KeySeed<'_, 'a> {
    type Value = Option<Member<'a>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a member name")
    }

    fn visit_str<E: de::Error>(self, name: &str) -> Result<Option<Member<'a>>, E> {
        let allowed = match self.0.allowed {
            Allowed::Any => true,
            Allowed::List(names) => names.contains(&name),
            Allowed::Pred(accepts) => accepts(name),
        };
        if !allowed {
            return Err(E::custom("member not in the canonical set"));
        }
        Ok(match self.0.required {
            Some((required, member)) if required == name => Some(member),
            _ => None,
        })
    }
}

struct ArraySeed<'l, 'a>(&'l Level<'a>);

impl<'de> DeserializeSeed<'de> for ArraySeed<'_, '_> {
    type Value = ();

    fn deserialize<D: de::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ArraySeed<'_, '_> {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an array of canonical objects")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(self.0)?.is_some() {}
        Ok(())
    }
}
