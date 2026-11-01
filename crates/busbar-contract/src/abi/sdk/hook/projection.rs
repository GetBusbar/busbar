// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;

use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};

use super::{Bucket, Decoded, DecodedCandidate, Stage, User};
use crate::signal::SignalValue;

// The old JSON value sorted every object and kept the last duplicate signal. These maps contain
// borrowed serialization descriptors only; prompt text, signal values and candidates stay borrowed.
enum Field<'a> {
    EmptyObject,
    Text(&'a str),
    U64(u64),
    Usize(usize),
    I64(i64),
    Float(f64),
    Bool(bool),
    Signal(&'a SignalValue),
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
            Self::Extra(v) => v.serialize(serializer),
            Self::Request(v) => request(v).serialize(serializer),
            Self::Candidates(v) => {
                let mut seq = serializer.serialize_seq(Some(v.len()))?;
                for candidate in *v {
                    seq.serialize_element(&candidate_fields(candidate))?;
                }
                seq.end()
            }
            Self::Context(v) => {
                let mut fields = BTreeMap::new();
                if !v.budget.is_empty() {
                    fields.insert("budget", Self::Budget(&v.budget));
                }
                if let Some(remaining) = v.budget_remaining {
                    fields.insert("budget_remaining", Self::I64(remaining));
                }
                fields.serialize(serializer)
            }
            Self::Messages(v) => {
                let mut seq = serializer.serialize_seq(Some(v.len()))?;
                for (role, text) in *v {
                    let fields =
                        BTreeMap::from([("role", Self::Text(role)), ("text", Self::Text(text))]);
                    seq.serialize_element(&fields)?;
                }
                seq.end()
            }
            Self::User(v) => {
                let mut fields = BTreeMap::new();
                for (name, value) in [
                    ("key_id", v.key_id.as_deref()),
                    ("key_name", v.key_name.as_deref()),
                    ("user", v.user.as_deref()),
                ] {
                    if let Some(value) = value {
                        fields.insert(name, Self::Text(value));
                    }
                }
                fields.serialize(serializer)
            }
            Self::Tags(v) => v.serialize(serializer),
            Self::Budget(v) => {
                let mut seq = serializer.serialize_seq(Some(v.len()))?;
                for bucket in *v {
                    let mut fields = BTreeMap::from([
                        ("bucket_id", Self::Text(&bucket.bucket_id)),
                        ("budget_period", Self::Text(&bucket.budget_period)),
                        (
                            "spend_micros_at_current_rate",
                            Self::I64(bucket.spend_micros_at_current_rate),
                        ),
                        ("window_start", Self::U64(bucket.window_start)),
                    ]);
                    if let Some(group) = bucket.budget_group.as_deref() {
                        fields.insert("budget_group", Self::Text(group));
                    }
                    if let Some(pool) = bucket.pool.as_deref() {
                        fields.insert("pool", Self::Text(pool));
                    }
                    if let Some(remaining) = bucket.remaining_micros {
                        fields.insert("remaining_micros", Self::I64(remaining));
                    }
                    seq.serialize_element(&fields)?;
                }
                seq.end()
            }
            Self::Stage(v) => {
                let mut fields = BTreeMap::from([("at", Self::Text(v.at))]);
                for (name, value) in [
                    ("model", v.model.as_deref()),
                    ("outcome", v.outcome.as_deref()),
                    ("previous_failure", v.previous_failure.as_deref()),
                ] {
                    if let Some(value) = value {
                        fields.insert(name, Self::Text(value));
                    }
                }
                if let Some(attempt) = v.attempt_number {
                    fields.insert("attempt_number", Self::U64(u64::from(attempt)));
                }
                if let Some(remaining) = v.remaining_candidates {
                    fields.insert("remaining_candidates", Self::Usize(remaining));
                }
                if let Some(status) = v.status {
                    fields.insert("status", Self::U64(u64::from(status)));
                }
                fields.serialize(serializer)
            }
        }
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
    for (signal, value) in view.signals.iter() {
        fields.insert(signal.name(), Field::Signal(value));
    }
    fields
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
    for (signal, value) in view.signals.iter() {
        fields.insert(signal.name(), Field::Signal(value));
    }
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
