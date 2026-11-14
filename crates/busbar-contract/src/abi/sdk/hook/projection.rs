// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use super::{Bucket, Decoded, DecodedCandidate, Stage, User};
use crate::signal::SignalValue;

enum Field<'a> {
    EmptyObject,
    Text(&'a str),
    U64(u64),
    Usize(usize),
    I64(i64),
    Float(f64),
    Bool(bool),
    Signal(&'a SignalValue),
    Signals(Vec<&'a SignalValue>),
    Extra(&'a serde_json::Value),
    Request(&'a Decoded<'a>),
    Candidates(&'a [DecodedCandidate<'a>]),
    Context(&'a Decoded<'a>),
    Messages(&'a [(std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>)]),
    User(&'a User<'a>),
    Tags(&'a [std::borrow::Cow<'a, str>]),
    Budget(&'a [Bucket<'a>]),
    Stage(&'a Stage<'a>),
}

impl Serialize for Field<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::EmptyObject => serializer.serialize_map(Some(0))?.end(),
            Self::Text(v) => v.serialize(serializer),
            Self::U64(v) => v.serialize(serializer),
            Self::Usize(v) => v.serialize(serializer),
            Self::I64(v) => v.serialize(serializer),
            Self::Float(v) => v.serialize(serializer),
            Self::Bool(v) => v.serialize(serializer),
            Self::Signal(v) => v.serialize(serializer),
            Self::Signals(v) => v.serialize(serializer),
            Self::Extra(v) => v.serialize(serializer),
            Self::Request(v) => request(v).serialize(serializer),
            Self::Candidates(v) => {
                let mut seq = serializer.serialize_seq(Some(v.len()))?;
                for candidate in *v {
                    seq.serialize_element(&candidate_fields(candidate))?;
                }
                seq.end()
            }
            // Each object below is written with its keys in byte order, as the BTreeMap the 1.5.5
            // projection used would write them, absent members skipped: no map is built.
            Self::Context(v) => {
                let mut map = serializer.serialize_map(None)?;
                if !v.budget.is_empty() {
                    map.serialize_entry("budget", &Self::Budget(&v.budget))?;
                }
                if let Some(remaining) = v.budget_remaining {
                    map.serialize_entry("budget_remaining", &remaining)?;
                }
                map.end()
            }
            Self::Messages(v) => {
                let mut seq = serializer.serialize_seq(Some(v.len()))?;
                for (role, text) in *v {
                    seq.serialize_element(&Message(role, text))?;
                }
                seq.end()
            }
            Self::User(v) => {
                let mut map = serializer.serialize_map(None)?;
                for (name, value) in [
                    ("key_id", v.key_id.as_deref()),
                    ("key_name", v.key_name.as_deref()),
                    ("user", v.user.as_deref()),
                ] {
                    if let Some(value) = value {
                        map.serialize_entry(name, value)?;
                    }
                }
                map.end()
            }
            Self::Tags(v) => v.serialize(serializer),
            Self::Budget(v) => {
                let mut seq = serializer.serialize_seq(Some(v.len()))?;
                for bucket in *v {
                    seq.serialize_element(&BucketFields(bucket))?;
                }
                seq.end()
            }
            Self::Stage(v) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("at", v.at)?;
                if let Some(attempt) = v.attempt_number {
                    map.serialize_entry("attempt_number", &u64::from(attempt))?;
                }
                for (name, value) in [
                    ("model", v.model.as_deref()),
                    ("outcome", v.outcome.as_deref()),
                    ("previous_failure", v.previous_failure.as_deref()),
                ] {
                    if let Some(value) = value {
                        map.serialize_entry(name, value)?;
                    }
                }
                if let Some(remaining) = v.remaining_candidates {
                    map.serialize_entry("remaining_candidates", &remaining)?;
                }
                if let Some(status) = v.status {
                    map.serialize_entry("status", &u64::from(status))?;
                }
                map.end()
            }
        }
    }
}

/// One prompt message: `{"role":..,"text":..}`.
struct Message<'a>(&'a str, &'a str);

impl Serialize for Message<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("role", self.0)?;
        map.serialize_entry("text", self.1)?;
        map.end()
    }
}

/// One budget bucket, its keys in byte order (`pool` only when it has one).
struct BucketFields<'a>(&'a Bucket<'a>);

impl Serialize for BucketFields<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let bucket = self.0;
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("bucket_id", &*bucket.bucket_id)?;
        map.serialize_entry("budget_group", &bucket.budget_group.as_deref())?;
        map.serialize_entry("budget_period", &*bucket.budget_period)?;
        if let Some(pool) = bucket.pool.as_deref() {
            map.serialize_entry("pool", pool)?;
        }
        map.serialize_entry("remaining_micros", &bucket.remaining_micros)?;
        map.serialize_entry(
            "spend_micros_at_current_rate",
            &bucket.spend_micros_at_current_rate,
        )?;
        map.serialize_entry("window_start", &bucket.window_start)?;
        map.end()
    }
}

fn request<'a>(view: &'a Decoded<'a>) -> BTreeMap<&'a str, Field<'a>> {
    let mut fields = BTreeMap::from([
        ("request_id", Field::U64(view.request_id)),
        ("pool", Field::Text(&view.pool)),
        ("ingress_protocol", Field::Text(&view.ingress_dialect)),
        ("message_count", Field::Usize(view.message_count as usize)),
        ("has_tools", Field::Bool(view.has_tools)),
        ("total_chars", Field::Usize(view.total_chars as usize)),
        ("stream", Field::Bool(view.stream)),
    ]);
    if let Some(tokens) = view.max_tokens {
        fields.insert("max_tokens", Field::U64(u64::from(tokens)));
    }
    if let Some(prompt) = &view.prompt {
        if let Some(system) = prompt.system.as_deref() {
            fields.insert("system", Field::Text(system));
        }
        fields.insert("messages", Field::Messages(&prompt.messages));
    }
    if let Some(user) = &view.user {
        fields.insert("user", Field::User(user));
    }
    insert_signals(&mut fields, &view.signals);
    fields
}

/// The signal bag as [`crate::signal::SignalBag`]'s own serialization states it: a signal pushed
/// more than once is one key whose value is the array of its values in push order.
fn insert_signals<'a>(
    fields: &mut BTreeMap<&'a str, Field<'a>>,
    signals: &'a crate::signal::SignalBag,
) {
    for (signal, value) in signals.iter() {
        match fields.get_mut(signal.name()) {
            Some(Field::Signal(first)) => {
                let first = *first;
                fields.insert(signal.name(), Field::Signals(vec![first, value]));
            }
            Some(Field::Signals(values)) => values.push(value),
            _ => {
                fields.insert(signal.name(), Field::Signal(value));
            }
        }
    }
}

fn candidate_fields<'a>(view: &'a DecodedCandidate<'a>) -> BTreeMap<&'a str, Field<'a>> {
    let mut fields = BTreeMap::from([
        ("idx", Field::Usize(view.idx)),
        ("model", Field::Text(&view.model)),
        ("provider", Field::Text(&view.provider)),
        ("weight", Field::U64(u64::from(view.weight))),
        (
            "available_concurrency",
            Field::Usize(view.available_concurrency),
        ),
    ]);
    if let Some(context) = view.context_max {
        fields.insert("context_max", Field::Usize(context));
    }
    if let Some(tier) = view.tier.as_deref() {
        fields.insert("tier", Field::Text(tier));
    }
    for (name, value) in [
        ("cost_per_mtok", view.cost_per_mtok),
        ("latency_ms", view.latency_ms),
        ("rate_headroom", view.rate_headroom),
    ] {
        if let Some(value) = value {
            fields.insert(name, Field::Float(value));
        }
    }
    if let Some(remaining) = view.budget_remaining {
        fields.insert("budget_remaining", Field::I64(remaining));
    }
    if !view.tags.is_empty() {
        fields.insert("tags", Field::Tags(&view.tags));
    }
    insert_signals(&mut fields, &view.signals);
    fields
}

struct Envelope<'a> {
    view: &'a Decoded<'a>,
    stage: Option<&'a Stage<'a>>,
    tap: bool,
    op: &'a str,
    extra: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

impl Serialize for Envelope<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = BTreeMap::from([
            (
                "candidates",
                Field::Candidates(if self.tap { &[] } else { &self.view.candidates }),
            ),
            (
                "context",
                if self.tap {
                    Field::EmptyObject
                } else {
                    Field::Context(self.view)
                },
            ),
            ("request", Field::Request(self.view)),
        ]);
        if let Some(stage) = self.stage {
            fields.insert("stage", Field::Stage(stage));
        }
        if let Some(extra) = self.extra {
            for (name, value) in extra {
                if name != "op" {
                    fields.insert(name, Field::Extra(value));
                }
            }
        }
        let mut map = serializer.serialize_map(Some(fields.len() + 1))?;
        for (name, value) in fields {
            map.serialize_entry(name, &value)?;
        }
        map.serialize_entry("op", self.op)?;
        map.end()
    }
}

pub(super) fn write(
    view: &Decoded<'_>,
    stage: Option<&Stage<'_>>,
    tap: bool,
    op: &str,
    extra: Option<&serde_json::Map<String, serde_json::Value>>,
    out: &mut Vec<u8>,
) -> Result<(), serde_json::Error> {
    serde_json::to_writer(
        out,
        &Envelope {
            view,
            stage,
            tap,
            op,
            extra,
        },
    )
}
