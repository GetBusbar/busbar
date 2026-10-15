// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROVIDER-KEY DESCRIPTOR'S DRIFT GUARD (row 155 B1c): the llm plane's declared provider keys
//! (`busbar_plane_llm::meta::PROVIDER_KEYS`) are, form by form, the frozen grammar's own keys with
//! the kernel's left out, in the frozen serde field order, each required exactly when the frozen
//! grammar refuses an entry without it, each read in its declared shape, each `one-of` the frozen
//! enum's spellings in their order, and each form and nested table refusing an unknown key exactly
//! when the frozen grammar does. The frozen grammar is the catalog definition (`ProviderDef`), the
//! operator deployment (`ProviderDeploy`) and the resolved entry (`ProviderCfg`); this crate is
//! where both it and the plane are reachable. A descriptor that drifts from it fails here, before
//! a parse driven by the descriptor could answer differently from the previous release.

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde_json::{json, Map, Value};

use busbar_contract::provider_keys::{decode, ProviderKeys, Shape, Table};
use busbar_plane_llm::meta::PROVIDER_KEYS;

use crate::engine::build_runtime::{ProviderCfg, ProviderDef, ProviderDeploy};

/// The keys the kernel owns in every form of a provider entry (its destination, its credential and
/// outbound-auth binding, its health block and its metadata allowance): never a plane's to declare.
const CORE: &[&str] = &[
    "base_url",
    "path",
    "path_base",
    "api_key",
    "auth",
    "token_url",
    "scope",
    "subject",
    "health",
    "allow_metadata_hosts",
];

/// A deserializer that answers nothing and records the field list a derived struct reader asks
/// for: the frozen serde field order, read off the frozen type itself.
struct FieldProbe<'a>(&'a mut &'static [&'static str]);

impl<'de> Deserializer<'de> for FieldProbe<'_> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
        Err(de::Error::custom(
            "the probe reads a struct's field list only",
        ))
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        _: &'static str,
        fields: &'static [&'static str],
        _: V,
    ) -> Result<V::Value, Self::Error> {
        *self.0 = fields;
        Err(de::Error::custom("probed"))
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string bytes byte_buf
        option unit unit_struct newtype_struct seq tuple tuple_struct map enum identifier
        ignored_any
    }
}

/// `T`'s serde field names, in its declared order.
fn frozen_fields<T: for<'de> Deserialize<'de>>() -> &'static [&'static str] {
    let mut fields: &'static [&'static str] = &[];
    let _ = T::deserialize(FieldProbe(&mut fields));
    fields
}

/// `doc` read as `T`: `Ok`, or serde's words.
fn read_as<T: for<'de> Deserialize<'de>>(doc: Value) -> Result<(), String> {
    serde_json::from_value::<T>(doc)
        .map(drop)
        .map_err(|e| e.to_string())
}

/// One form: its name, its declared table, its frozen field list, the kernel keys an entry of it
/// must write, and its frozen reader.
struct Form<'a> {
    name: &'static str,
    table: &'a Table,
    frozen: &'static [&'static str],
    core: Value,
    read: fn(Value) -> Result<(), String>,
}

fn forms(keys: &ProviderKeys) -> [Form<'_>; 3] {
    let url = json!("https://upstream.invalid");
    let credential = json!({ "env": "PROVIDER_CREDENTIAL" });
    [
        Form {
            name: "catalog",
            table: &keys.catalog,
            frozen: frozen_fields::<ProviderDef>(),
            core: json!({ "base_url": url }),
            read: read_as::<ProviderDef>,
        },
        Form {
            name: "deployment",
            table: &keys.deployment,
            frozen: frozen_fields::<ProviderDeploy>(),
            core: json!({ "api_key": credential }),
            read: read_as::<ProviderDeploy>,
        },
        Form {
            name: "entry",
            table: &keys.entry,
            frozen: frozen_fields::<ProviderCfg>(),
            core: json!({ "base_url": url, "api_key": credential }),
            read: read_as::<ProviderCfg>,
        },
    ]
}

fn declared() -> ProviderKeys {
    decode(PROVIDER_KEYS.as_bytes()).expect("the plane's provider keys are a neutral descriptor")
}

/// A value of `shape`.
fn sample(shape: &Shape) -> Value {
    match shape {
        Shape::Str => json!("word"),
        Shape::Int => json!(1),
        Shape::Bool => json!(true),
        Shape::StrMap => json!({ "word": "word" }),
        Shape::OneOf(words) => Value::String(words[0].clone()),
        Shape::List(of) => Value::Array(vec![sample(of)]),
        Shape::Table(t) => Value::Object(
            t.keys
                .iter()
                .map(|k| (k.name.clone(), sample(&k.shape)))
                .collect(),
        ),
    }
}

/// `t`'s required keys, each a value of its shape.
fn required(t: &Table) -> Map<String, Value> {
    t.keys
        .iter()
        .filter(|k| k.required)
        .map(|k| (k.name.clone(), sample(&k.shape)))
        .collect()
}

fn with(mut m: Map<String, Value>, key: &str, v: Value) -> Map<String, Value> {
    m.insert(key.to_string(), v);
    m
}

/// serde's words for what it expected (`serde::de::OneOf`).
fn expected(names: &[&str]) -> String {
    match names {
        [one] => format!("expected `{one}`"),
        [a, b] => format!("expected `{a}` or `{b}`"),
        _ => format!(
            "expected one of {}",
            names
                .iter()
                .map(|n| format!("`{n}`"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Judge `table` against the frozen reader `place` reaches it through (`place` writes a table
/// object where the table sits in a whole entry and reads the entry). `whole`: the table holds every
/// key its frozen struct reads (a nested table), so an unknown key's refusal lists exactly its keys.
fn judge(
    at: &str,
    table: &Table,
    whole: bool,
    place: &dyn Fn(Map<String, Value>) -> Result<(), String>,
) {
    let req = required(table);
    if let Err(e) = place(req.clone()) {
        panic!("{at}: an entry writing only the declared required keys is refused: {e}");
    }
    for k in table.keys.iter().filter(|k| k.required) {
        let mut less = req.clone();
        less.remove(&k.name);
        let Err(err) = place(less) else {
            panic!(
                "{at}.{}: declared required, yet an entry without it is read",
                k.name
            );
        };
        assert!(
            err.contains(&format!("missing field `{}`", k.name)),
            "{at}.{}: {err}",
            k.name
        );
    }
    let every: Map<String, Value> = table
        .keys
        .iter()
        .map(|k| (k.name.clone(), sample(&k.shape)))
        .collect();
    if let Err(e) = place(every) {
        panic!("{at}: every declared key written in its declared shape is refused: {e}");
    }
    let unknown = place(with(req.clone(), "bogus_key", json!(1)));
    if table.deny_unknown {
        let Err(err) = unknown else {
            panic!("{at}: declared to refuse an unknown key, yet one is read");
        };
        let names: Vec<&str> = table.keys.iter().map(|k| k.name.as_str()).collect();
        let want = if whole {
            format!("unknown field `bogus_key`, {}", expected(&names))
        } else {
            "unknown field `bogus_key`".to_string()
        };
        assert!(err.contains(&want), "{at}: {err}");
    } else {
        assert!(
            unknown.is_ok(),
            "{at}: declared to pass an unknown key over: {unknown:?}"
        );
    }
    for k in &table.keys {
        let key = format!("{at}.{}", k.name);
        match &k.shape {
            Shape::OneOf(words) => {
                for w in words {
                    assert!(
                        place(with(req.clone(), &k.name, json!(w))).is_ok(),
                        "{key}: `{w}` is refused"
                    );
                }
                let names: Vec<&str> = words.iter().map(String::as_str).collect();
                let Err(err) = place(with(req.clone(), &k.name, json!("bogus_word"))) else {
                    panic!("{key}: a word outside the one-of is read");
                };
                assert!(
                    err.contains(&format!(
                        "unknown variant `bogus_word`, {}",
                        expected(&names)
                    )),
                    "{key}: {err}"
                );
            }
            Shape::List(of) => {
                if let Shape::Table(inner) = of.as_ref() {
                    let (req, name) = (req.clone(), k.name.clone());
                    judge(&format!("{key}[]"), inner, true, &|m| {
                        place(with(
                            req.clone(),
                            &name,
                            Value::Array(vec![Value::Object(m)]),
                        ))
                    });
                }
            }
            Shape::Table(inner) => {
                let (req, name) = (req.clone(), k.name.clone());
                judge(&key, inner, true, &|m| {
                    place(with(req.clone(), &name, Value::Object(m)))
                });
            }
            Shape::Str | Shape::Int | Shape::Bool | Shape::StrMap => {}
        }
    }
}

/// THE DRIFT GUARD: each form's declared keys are its frozen grammar's keys, the kernel's left out,
/// in the frozen serde field order.
#[test]
fn each_forms_declared_keys_are_its_frozen_grammars_plane_keys_in_frozen_order() {
    let keys = declared();
    for form in forms(&keys) {
        let frozen: Vec<&str> = form
            .frozen
            .iter()
            .copied()
            .filter(|k| !CORE.contains(k))
            .collect();
        let declared: Vec<&str> = form.table.keys.iter().map(|k| k.name.as_str()).collect();
        assert!(!frozen.is_empty(), "{}: the probe read no field", form.name);
        assert_eq!(
            declared, frozen,
            "{}: the declared keys are not the frozen grammar's, in its order",
            form.name
        );
    }
}

/// Each declared key's required flag, shape and one-of words, and each table's unknown-key rule,
/// are the frozen grammar's, at every depth.
#[test]
fn each_declared_key_reads_as_the_frozen_grammar_reads_it() {
    let keys = declared();
    for form in forms(&keys) {
        let Value::Object(core) = form.core.clone() else {
            unreachable!("a form's kernel keys are an object")
        };
        let read = form.read;
        judge(form.name, form.table, false, &|m| {
            let mut doc = core.clone();
            doc.extend(m);
            read(Value::Object(doc))
        });
    }
}
