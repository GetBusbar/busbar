// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Views (ADMIN-API-1.6 §5.5): generic tabular data an instance offers, with no per-kind code in
//! core.
//!
//! A descriptor is `{view, title, shape, fields[], default_sort, filters[], time, step_options[]}`;
//! every field is `{name, label, type, unit, format, role}`. The vocabularies are closed, and a
//! `measure` field carries a unit from the closed list. A descriptor outside them is invalid: the
//! view is dropped (display data, never a reason to refuse an instance) and the caller raises the
//! `plugin.view_invalid` diagnostic.
//!
//! Rows are positional arrays in `fields` order, each cell in its type's one wire encoding: `int`
//! a JSON integer (a `format: "u64"` int a decimal string), `float` a number, `money_micros` the
//! exact decimal string `spend_micros` uses, `time` integer Unix milliseconds, `bool` and `string`
//! themselves. A cell the source does not hold in its type is `null`.

use busbar_contract::json::{JsonContainerTrait, JsonValueTrait, Map, Value};

/// The closed `shape` vocabulary.
pub(crate) const SHAPES: [&str; 4] = ["table", "timeseries", "stat", "list"];
/// The closed field `type` vocabulary.
pub(crate) const TYPES: [&str; 6] = ["string", "int", "float", "bool", "time", "money_micros"];
/// The closed field `role` vocabulary.
pub(crate) const ROLES: [&str; 5] = ["dimension", "measure", "time", "id", "status"];
/// The closed `unit` list (C3); required on every `measure`.
pub(crate) const UNITS: [&str; 8] = [
    "count", "us", "ms", "s", "bytes", "percent", "ratio", "micros",
];

/// Why a descriptor is invalid, in core's words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invalid(pub(crate) String);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Type {
    String,
    Int,
    Float,
    Bool,
    Time,
    MoneyMicros,
}

impl Type {
    fn of(word: &str) -> Option<Self> {
        Some(match word {
            "string" => Type::String,
            "int" => Type::Int,
            "float" => Type::Float,
            "bool" => Type::Bool,
            "time" => Type::Time,
            "money_micros" => Type::MoneyMicros,
            _ => return None,
        })
    }
}

/// One validated field.
#[derive(Debug, Clone)]
pub(crate) struct Field {
    pub(crate) name: String,
    kind: Type,
    decimal: bool,
    role: String,
}

impl Field {
    /// Whether `filter=<field>:<value>` may name this field: dimensions and ids only.
    pub(crate) fn filterable(&self) -> bool {
        self.role == "dimension" || self.role == "id"
    }
}

/// A validated descriptor and the object it is served as.
#[derive(Debug, Clone)]
pub(crate) struct Descriptor {
    pub(crate) view: String,
    pub(crate) fields: Vec<Field>,
    pub(crate) served: Value,
}

/// A view or kind id: `[a-z][a-z0-9_]{0,31}`.
pub(crate) fn is_id(word: &str) -> bool {
    let mut chars = word.chars();
    word.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn text<'a>(object: &'a Map, key: &str) -> Option<&'a str> {
    object.get(&key).and_then(|v| v.as_str())
}

/// Validate `descriptor` against the closed vocabularies.
pub(crate) fn validate(descriptor: &Value) -> Result<Descriptor, Invalid> {
    let invalid = |why: String| Err(Invalid(why));
    let Some(object) = descriptor.as_object() else {
        return invalid("a view descriptor is an object".into());
    };
    let Some(view) = text(object, "view").filter(|v| is_id(v)) else {
        return invalid("`view` is an id matching [a-z][a-z0-9_]{0,31}".into());
    };
    if text(object, "title").is_none() {
        return invalid(format!("view `{view}`: `title` is a string"));
    }
    match text(object, "shape") {
        Some(shape) if SHAPES.contains(&shape) => {}
        _ => return invalid(format!("view `{view}`: `shape` is one of {SHAPES:?}")),
    }
    let Some(listed) = object
        .get(&"fields")
        .and_then(|f| f.as_array())
        .filter(|f| !f.is_empty())
    else {
        return invalid(format!("view `{view}`: `fields` is a non-empty list"));
    };
    let mut fields: Vec<Field> = Vec::with_capacity(listed.len());
    for field in listed.iter() {
        let Some(field) = field.as_object() else {
            return invalid(format!("view `{view}`: every field is an object"));
        };
        let Some(name) = text(field, "name").filter(|n| !n.is_empty()) else {
            return invalid(format!("view `{view}`: every field has a `name`"));
        };
        if fields.iter().any(|f| f.name == name) {
            return invalid(format!("view `{view}`: field `{name}` is listed twice"));
        }
        if text(field, "label").is_none() {
            return invalid(format!("view `{view}`: field `{name}` has a `label`"));
        }
        let Some(kind) = text(field, "type").and_then(Type::of) else {
            return invalid(format!(
                "view `{view}`: field `{name}`: `type` is one of {TYPES:?}"
            ));
        };
        let Some(role) = text(field, "role").filter(|r| ROLES.contains(r)) else {
            return invalid(format!(
                "view `{view}`: field `{name}`: `role` is one of {ROLES:?}"
            ));
        };
        match field.get(&"unit") {
            None => {}
            Some(unit) if unit.is_null() => {}
            Some(unit) if !unit.as_str().is_some_and(|u| UNITS.contains(&u)) => {
                return invalid(format!(
                    "view `{view}`: field `{name}`: `unit` is one of {UNITS:?}"
                ));
            }
            Some(_) => {}
        }
        if role == "measure" && text(field, "unit").is_none() {
            return invalid(format!(
                "view `{view}`: measure `{name}` carries a `unit` from {UNITS:?}"
            ));
        }
        let format = field.get(&"format");
        if format.is_some_and(|f| !f.is_null() && !f.is_str()) {
            return invalid(format!(
                "view `{view}`: field `{name}`: `format` is a string"
            ));
        }
        fields.push(Field {
            name: name.to_owned(),
            kind,
            decimal: kind == Type::Int && text(field, "format") == Some("u64"),
            role: role.to_owned(),
        });
    }
    let named = |key: &str, ok: &dyn Fn(&Field) -> bool| -> Result<(), Invalid> {
        match object.get(&key) {
            None => Ok(()),
            Some(value) if value.is_null() => Ok(()),
            Some(value) => match value.as_str() {
                Some(name) if fields.iter().any(|f| f.name == name && ok(f)) => Ok(()),
                _ => Err(Invalid(format!(
                    "view `{view}`: `{key}` names one of its fields"
                ))),
            },
        }
    };
    named("default_sort", &|_| true)?;
    named("time", &|f| f.role == "time")?;
    if let Some(filters) = object.get(&"filters").filter(|f| !f.is_null()) {
        let ok = filters.as_array().is_some_and(|names| {
            names.iter().all(|name| {
                name.as_str()
                    .is_some_and(|n| fields.iter().any(|f| f.name == n && f.filterable()))
            })
        });
        if !ok {
            return invalid(format!(
                "view `{view}`: `filters` lists its dimension and id fields"
            ));
        }
    }
    if let Some(steps) = object.get(&"step_options").filter(|s| !s.is_null()) {
        let ok = steps
            .as_array()
            .is_some_and(|steps| steps.iter().all(|s| s.as_u64().is_some_and(|s| s > 0)));
        if !ok {
            return invalid(format!(
                "view `{view}`: `step_options` lists positive step seconds"
            ));
        }
    }
    Ok(Descriptor {
        view: view.to_owned(),
        fields,
        served: descriptor.clone(),
    })
}

/// The descriptors among `declared` that validate; each invalid one is dropped and reported.
pub(crate) fn admitted(declared: &[Value]) -> (Vec<Descriptor>, Vec<Invalid>) {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for descriptor in declared {
        match validate(descriptor) {
            Ok(d) if kept.iter().any(|k: &Descriptor| k.view == d.view) => {
                dropped.push(Invalid(format!("view `{}` is declared twice", d.view)));
            }
            Ok(d) => kept.push(d),
            Err(why) => dropped.push(why),
        }
    }
    (kept, dropped)
}

fn decimal(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// The exact decimal string of `spend_micros`: digits with at most three fractional places.
fn money(text: &str) -> bool {
    match text.split_once('.') {
        None => decimal(text),
        Some((whole, places)) => {
            decimal(whole)
                && !places.is_empty()
                && places.len() <= 3
                && places.bytes().all(|b| b.is_ascii_digit())
        }
    }
}

/// One cell in its field's wire encoding.
fn cell(field: &Field, value: Option<&Value>) -> Value {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Value::new_null();
    };
    let integer = || {
        value
            .as_u64()
            .map(Value::from)
            .or_else(|| value.as_i64().map(Value::from))
            .or_else(|| {
                value
                    .as_str()
                    .filter(|t| decimal(t))
                    .and_then(|t| t.parse::<i64>().ok())
                    .map(Value::from)
            })
    };
    let shown = match field.kind {
        Type::String => value.as_str().map(Value::from),
        Type::Bool => value.as_bool().map(Value::from),
        Type::Float => value.as_f64().and_then(Value::new_f64),
        Type::Time => integer(),
        Type::Int if field.decimal => value
            .as_u64()
            .map(|n| Value::from(n.to_string().as_str()))
            .or_else(|| {
                value
                    .as_str()
                    .filter(|t| decimal(t) && !t.starts_with('-'))
                    .map(Value::from)
            }),
        Type::Int => integer(),
        Type::MoneyMicros => value
            .as_str()
            .filter(|t| money(t))
            .map(Value::from)
            .or_else(|| value.as_u64().map(|n| Value::from(n.to_string().as_str())))
            .or_else(|| value.as_i64().map(|n| Value::from(n.to_string().as_str()))),
    };
    shown.unwrap_or_else(Value::new_null)
}

/// One source item as a positional row, in `descriptor.fields` order.
pub(crate) fn row(descriptor: &Descriptor, item: &Value) -> Value {
    let cells: Vec<Value> = descriptor
        .fields
        .iter()
        .map(|field| cell(field, item.get(field.name.as_str())))
        .collect();
    Value::from(cells)
}

/// Whether `row` satisfies every `(field, value)` filter: an exact match on the cell's text.
pub(crate) fn matches(row: &Value, filters: &[(usize, String)]) -> bool {
    filters.iter().all(|(at, wanted)| {
        let Some(cell) = row.as_array().and_then(|cells| cells.get(*at)) else {
            return false;
        };
        match cell.as_str() {
            Some(text) => text == wanted,
            None => !cell.is_null() && displays_as(cell, wanted),
        }
    })
}

/// Parse the `filter=<field>:<value>` pairs against `descriptor`: each names a dimension or id
/// field. `Err` names the offending filter.
pub(crate) fn filters(
    descriptor: &Descriptor,
    pairs: &[(String, String)],
) -> Result<Vec<(usize, String)>, String> {
    pairs
        .iter()
        .filter(|(name, _)| name == "filter")
        .map(|(_, raw)| {
            let (field, value) = raw
                .split_once(':')
                .ok_or_else(|| format!("filter `{raw}`: expected <field>:<value>"))?;
            descriptor
                .fields
                .iter()
                .position(|f| f.name == field && f.filterable())
                .map(|at| (at, value.to_owned()))
                .ok_or_else(|| format!("filter `{raw}`: `{field}` is not a dimension or id field"))
        })
        .collect()
}

/// Whether `value`'s `Display` text is exactly `wanted`, compared as it is written (no `String` built).
fn displays_as(value: &Value, wanted: &str) -> bool {
    use std::fmt::Write as _;
    struct Matching<'a>(&'a str);
    impl std::fmt::Write for Matching<'_> {
        fn write_str(&mut self, piece: &str) -> std::fmt::Result {
            self.0 = self.0.strip_prefix(piece).ok_or(std::fmt::Error)?;
            Ok(())
        }
    }
    let mut rest = Matching(wanted);
    write!(rest, "{value}").is_ok() && rest.0.is_empty()
}


#[cfg(test)]
#[path = "tests/views_tests.rs"]
mod tests;
