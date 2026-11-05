// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Optional, allowlisted source provenance for editing routing arrays. This reader is never a
//! configuration validator. The normal boot parser runs first; failure here only hides provenance.
//! Unknown fields and tag values are consumed with IgnoredAny, never retained in a raw document.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::marker::PhantomData;

use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::PoolsCfg;

/// Only already-projected public values survive parsing. The private payload cannot acquire raw
/// YAML through a caller, and is never used to reconstruct a configuration document.
#[derive(Clone, Debug, Serialize)]
#[serde(transparent)]
pub struct AuthoredRouting(Value);

#[derive(Default)]
enum List<T> {
    #[default]
    Absent,
    Null,
    Entries(Vec<T>),
}
impl<'de, T: Deserialize<'de>> Deserialize<'de> for List<T> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct ListVisitor<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for ListVisitor<T> {
            type Value = List<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a list or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(List::Null)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(List::Null)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = seq.next_element()? {
                    entries.push(entry);
                }
                Ok(List::Entries(entries))
            }
        }
        de.deserialize_any(ListVisitor(PhantomData))
    }
}
impl<T> List<T> {
    fn state(&self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Null => "null",
            Self::Entries(_) => "list",
        }
    }
    fn entries(&self) -> &[T] {
        match self {
            Self::Entries(entries) => entries,
            _ => &[],
        }
    }
}

#[derive(Default)]
struct MemberSource {
    object: bool,
    fields: BTreeSet<&'static str>,
}
impl<'de> Deserialize<'de> for MemberSource {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct MemberVisitor;
        impl<'de> Visitor<'de> for MemberVisitor {
            type Value = MemberSource;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a member name or object")
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> Result<Self::Value, E> {
                Ok(MemberSource::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut source = MemberSource {
                    object: true,
                    ..Default::default()
                };
                while let Some(key) = map.next_key::<String>()? {
                    let field = match key.as_str() {
                        "model" => Some("model"),
                        "weight" => Some("weight"),
                        "context_max" => Some("context_max"),
                        "tier" => Some("tier"),
                        "attempt_timeout_ms" => Some("attempt_timeout_ms"),
                        "reasoning" => Some("reasoning"),
                        "tags" => Some("tags"),
                        _ => None,
                    };
                    if let Some(field) = field {
                        source.fields.insert(field);
                    }
                    map.next_value::<IgnoredAny>()?;
                }
                Ok(source)
            }
        }
        de.deserialize_any(MemberVisitor)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(untagged, deny_unknown_fields)]
enum HookSource {
    Name(String),
    Strategy { strategy: String },
}

#[derive(Default, Deserialize)]
struct PoolSource {
    #[serde(default)]
    members: List<MemberSource>,
    #[serde(default)]
    hooks: List<HookSource>,
}

#[derive(Default)]
struct SectionSource {
    state: &'static str,
    hooks: List<String>,
    pools: BTreeMap<String, Option<PoolSource>>,
}
impl<'de> Deserialize<'de> for SectionSource {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct SectionVisitor;
        impl<'de> Visitor<'de> for SectionVisitor {
            type Value = SectionSource;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a routing section")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
                Ok(SectionSource {
                    state: "null",
                    ..Default::default()
                })
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut source = SectionSource {
                    state: "object",
                    ..Default::default()
                };
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "hooks" => source.hooks = map.next_value()?,
                        "upstream_credentials" => {
                            map.next_value::<IgnoredAny>()?;
                        }
                        _ => {
                            source.pools.insert(key, map.next_value()?);
                        }
                    }
                }
                Ok(source)
            }
        }
        de.deserialize_any(SectionVisitor)
    }
}

#[derive(Default, Deserialize)]
struct Source {
    #[serde(default)]
    pools: SectionSource,
}

fn escaped(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

fn hook_view<T: Serialize>(hooks: &List<T>, path: &str) -> Value {
    json!({"state":hooks.state(),"path":path,"entries":hooks.entries().iter().enumerate()
        .map(|(index, entry)|json!({"index":index,"path":format!("{path}/{index}"),"entry":entry}))
        .collect::<Vec<_>>()})
}

/// Capture only routing syntax whose exact typed values have already been accepted. Failure to
/// read optional source provenance never changes whether the normal configuration parser succeeds.
pub(super) fn capture(text: &str, parsed: &PoolsCfg) -> Option<AuthoredRouting> {
    let source: Source = serde_yaml::from_str(text).ok()?;
    if source.pools.pools.len() != parsed.pools.len()
        || source.pools.hooks.entries() != parsed.all_pool_hooks.as_slice()
    {
        return None;
    }
    let mut pools = BTreeMap::new();
    for (name, raw) in &source.pools.pools {
        let typed = parsed.pools.get(name)?;
        let empty = PoolSource::default();
        let fields = raw.as_ref().unwrap_or(&empty);
        if fields.members.entries().len() != typed.members.len() {
            return None;
        }
        let path = format!("/pools/{}", escaped(name));
        let members: Vec<_> = fields
            .members
            .entries()
            .iter()
            .zip(&typed.members)
            .enumerate()
            .map(|(index, (source, member))| {
                json!({
                    "index":index,"path":format!("{path}/members/{index}"),
                    "form":if source.object { "object" } else { "bare" },
                    "model":member.model,"declared_fields":source.fields,
                    "values":{"weight":member.weight,"context_max":member.context_max,
                        "tier":member.tier,"attempt_timeout_ms":member.attempt_timeout_ms,
                        "reasoning":member.reasoning},
                    "tags":{"state":if source.fields.contains("tags") {"hidden"} else {"absent"},
                        "count":member.tags.len()}
                })
            })
            .collect();
        pools.insert(name, json!({"state":if raw.is_some() {"object"} else {"null"},"path":path,
            "members":{"state":fields.members.state(),"path":format!("{path}/members"),"entries":members},
            "hooks":hook_view(&fields.hooks,&format!("{path}/hooks"))}));
    }
    Some(AuthoredRouting(
        json!({"state":"available","source":"authored_generation",
        "section_state":if source.pools.state.is_empty() {"absent"} else {source.pools.state},
        "index_semantics":"Indices refer to this configuration generation's authored sequence. Use its ETag with If-Match; never reuse indices after a generation change.",
        "hooks":hook_view(&source.pools.hooks,"/pools/hooks"),"definitions":pools}),
    ))
}

#[cfg(test)]
#[path = "tests/authored_routing_tests.rs"]
mod tests;
