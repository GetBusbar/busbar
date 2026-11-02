// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::projection::{ProjectedRecord, Projection};
use busbar_contract::abi::export::{ExportField as F, ExportStream::Traces};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Instant, UNIX_EPOCH};
use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

pub fn layer<S: Subscriber + for<'a> LookupSpan<'a>>(floor: LevelFilter) -> Option<impl Layer<S>> {
    let wanted = move |m: &tracing::Metadata<'_>| {
        let subscribed = |s: &super::plugin::PluginSink| s.projection.wants_stream(Traces);
        let records = |s: &super::plugin::PluginSink| subscribed(s) && s.span_record;
        *m.level() <= floor
            && if m.is_span() {
                super::plugin::sinks().any(subscribed)
            } else {
                super::plugin::sinks().any(records)
            }
    };
    let filter = tracing_subscriber::filter::filter_fn(wanted).with_max_level_hint(floor);
    let producer = Producer(deliver, records_wanted).with_filter(filter);
    super::plugin::axis().map(|_| producer)
}

fn deliver(facts: &[(F, Value)], span: Option<&Value>) {
    let ingress = facts.iter().find(|(f, _)| *f == F::Ingress);
    let ingress = ingress.and_then(|(_, v)| v.as_str()).unwrap_or_default();
    if tokio::runtime::Handle::try_current().is_ok() {
        super::plugin::deliver_to(Traces, ingress, |p, takes| {
            record(p, facts, span.filter(|_| takes))
        });
    }
}

fn record(projection: Projection, facts: &[(F, Value)], span: Option<&Value>) -> Arc<Value> {
    let mut rec = ProjectedRecord::new(projection, Traces);
    facts.iter().for_each(|(f, v)| _ = rec.set(*f, v.clone()));
    let mut line = rec.finish();
    if let (Some(span), Value::Object(members)) = (span, &mut line) {
        members.insert(SPAN_MEMBER.to_string(), span.clone());
    }
    Arc::new(line)
}

pub(crate) const SPAN_MEMBER: &str = "span";

struct Opened(Instant, u64, Fields, u64, Option<SpanRecord>);

static NEXT_ID: std::sync::LazyLock<std::sync::atomic::AtomicU64> =
    std::sync::LazyLock::new(|| {
        std::sync::atomic::AtomicU64::new(crate::state::seed_request_id_counter())
    });

fn next_id() -> u64 {
    loop {
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

struct Fields(Vec<(F, Value)>);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_str(field, &format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fact(field, Value::from(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fact(field, Value::from(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fact(field, Value::from(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fact(field, Value::from(value));
    }
}

impl Fields {
    fn fact(&mut self, field: &tracing::field::Field, value: Value) {
        let traced = F::from_token(field.name()).filter(|f| Traces.default_fields().contains(f));
        self.0.extend(traced.map(|f| (f, value)));
    }
}

fn now_ns() -> u64 {
    u64::try_from(UNIX_EPOCH.elapsed().unwrap_or_default().as_nanos()).unwrap_or(u64::MAX)
}

const OTEL_NAME: &str = "otel.name";
const OTEL_KIND: &str = "otel.kind";
const OTEL_STATUS_CODE: &str = "otel.status_code";
const OTEL_STATUS_MESSAGE: &str = "otel.status_message";

const EVENT_EXCEPTION: &str = "exception";
const EXCEPTION_MESSAGE: &str = "exception.message";
const EXCEPTION_STACKTRACE: &str = "exception.stacktrace";

thread_local! {
    /// This thread's id as 0.33 wrote it: the integer inside `ThreadId(n)`.
    static THREAD_ID: i64 = {
        let id = format!("{:?}", std::thread::current().id());
        id.trim_start_matches("ThreadId(")
            .trim_end_matches(')')
            .parse::<i64>()
            .unwrap_or_default()
    };
}

struct SpanRecord {
    start_ns: u64,
    end_ns: Option<u64>,
    attributes: Vec<(String, Value)>,
    events: Vec<Value>,

    status: Option<String>,
    busy: i64,
    idle: i64,
    last: Instant,
    entered: u64,
}

impl SpanRecord {
    fn open(meta: &tracing::Metadata<'_>, attrs: &Attributes<'_>) -> Self {
        let mut attributes: Vec<(String, Value)> = Vec::new();
        if let Some(file) = meta.file() {
            attributes.push(("code.file.path".into(), Value::from(file)));
        }
        if let Some(module) = meta.module_path() {
            attributes.push(("code.module.name".into(), Value::from(module)));
        }
        if let Some(line) = meta.line() {
            attributes.push(("code.line.number".into(), Value::from(i64::from(line))));
        }
        THREAD_ID.with(|id| attributes.push(("thread.id".into(), Value::from(*id))));
        if let Some(name) = std::thread::current().name() {
            attributes.push(("thread.name".into(), Value::from(name)));
        }
        attributes.push(("target".into(), Value::from(meta.target())));
        let mut record = SpanRecord {
            start_ns: now_ns(),
            end_ns: None,
            attributes,
            events: Vec::new(),
            status: None,
            busy: 0,
            idle: 0,
            last: Instant::now(),
            entered: 0,
        };
        attrs.record(&mut Attrs(&mut record));
        record
    }

    fn finish(self, ids: (u64, u64, Option<u64>), name: &str) -> Value {
        let hex = |id: u64| Value::from(format!("{id:016x}"));
        let (trace, own, parent) = ids;
        let mut attributes = self.attributes;
        attributes.push(("busy_ns".into(), Value::from(self.busy)));
        attributes.push(("idle_ns".into(), Value::from(self.idle)));
        let mut span = serde_json::Map::new();
        span.insert("trace_id".into(), hex(trace));
        span.insert("span_id".into(), hex(own));
        if let Some(parent) = parent {
            span.insert("parent_span_id".into(), hex(parent));
        }
        span.insert("name".into(), Value::from(name));
        span.insert("start_ns".into(), Value::from(self.start_ns));
        span.insert(
            "end_ns".into(),
            Value::from(self.end_ns.unwrap_or_else(now_ns)),
        );
        span.insert("attributes".into(), key_values(attributes));
        span.insert("events".into(), Value::Array(self.events));
        let status = match self.status {
            Some(message) => serde_json::json!({"code": "error", "message": message}),
            None => serde_json::json!({"code": "unset", "message": ""}),
        };
        span.insert("status".into(), status);
        Value::Object(span)
    }
}

fn key_values(attributes: Vec<(String, Value)>) -> Value {
    Value::Array(
        attributes
            .into_iter()
            .map(|(key, value)| serde_json::json!({"key": key, "value": value}))
            .collect(),
    )
}

struct Attrs<'a>(&'a mut SpanRecord);

impl Attrs<'_> {
    fn push(&mut self, key: &str, value: Value) {
        self.0.attributes.push((key.to_string(), value));
    }

    fn text(&mut self, key: &str, value: String) {
        match key {
            OTEL_NAME | OTEL_KIND => {}
            OTEL_STATUS_CODE => {
                if value.eq_ignore_ascii_case("error") {
                    self.0.status.get_or_insert_with(String::new);
                } else {
                    self.0.status = None;
                }
            }
            OTEL_STATUS_MESSAGE => self.0.status = Some(value),
            _ => self.push(key, Value::from(value)),
        }
    }
}

impl tracing::field::Visit for Attrs<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.text(field.name(), format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.text(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push(field.name(), Value::from(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push(field.name(), Value::from(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.push(field.name(), Value::from(value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        let chain = source_chain(value);
        let message = value.to_string();
        self.push(EXCEPTION_MESSAGE, Value::from(message.clone()));
        self.push(EXCEPTION_STACKTRACE, chain.clone());
        self.push(field.name(), Value::from(message));
        self.push(&format!("{}.chain", field.name()), chain);
    }
}

fn source_chain(value: &(dyn std::error::Error + 'static)) -> Value {
    let mut chain = Vec::new();
    let mut next = value.source();
    while let Some(err) = next {
        chain.push(Value::from(err.to_string()));
        next = err.source();
    }
    Value::Array(chain)
}

struct EventFields<'a> {
    name: String,
    attributes: &'a mut Vec<(String, Value)>,
    status: Option<String>,
}

impl EventFields<'_> {
    fn text(&mut self, key: &str, value: String) {
        match key {
            "message" => self.name = value,
            "error" if self.name.is_empty() => {
                let message = format!("{value:?}");
                self.status = Some(message.clone());
                self.name = EVENT_EXCEPTION.to_string();
                self.attributes
                    .push((EXCEPTION_MESSAGE.to_string(), Value::from(message)));
            }
            key if key.starts_with("log.") => {}
            key => self.attributes.push((key.to_string(), Value::from(value))),
        }
    }

    fn typed(&mut self, key: &str, value: Value) {
        match key {
            "message" => self.name = value.to_string(),
            key if key.starts_with("log.") => {}
            key => self.attributes.push((key.to_string(), value)),
        }
    }
}

impl tracing::field::Visit for EventFields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let text = format!("{value:?}");
        match field.name() {
            "error" if self.name.is_empty() => {
                self.status = Some(text.clone());
                self.name = EVENT_EXCEPTION.to_string();
                self.attributes
                    .push((EXCEPTION_MESSAGE.to_string(), Value::from(text)));
            }
            key => self.text(key, text),
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.text(field.name(), value.to_string());
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.typed(field.name(), Value::from(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.typed(field.name(), Value::from(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.typed(field.name(), Value::from(value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        let chain = source_chain(value);
        let message = value.to_string();
        self.attributes
            .push((EXCEPTION_MESSAGE.to_string(), Value::from(message.clone())));
        self.attributes
            .push((EXCEPTION_STACKTRACE.to_string(), chain.clone()));
        self.attributes
            .push((field.name().to_string(), Value::from(message)));
        self.attributes
            .push((format!("{}.chain", field.name()), chain));
    }
}

fn records_wanted() -> bool {
    super::plugin::sinks().any(|s| s.projection.wants_stream(Traces) && s.span_record)
}

struct Producer(fn(&[(F, Value)], Option<&Value>), fn() -> bool);

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Producer {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut fields = Fields(Vec::new());
        attrs.record(&mut fields);
        let epoch = UNIX_EPOCH.elapsed().unwrap_or_default().as_micros() as u64;
        let own = next_id();
        let full = (self.1)().then(|| SpanRecord::open(attrs.metadata(), attrs));
        span.extensions_mut()
            .insert(Opened(Instant::now(), epoch, fields, own, full));
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut recorded = Fields(Vec::new());
        values.record(&mut recorded);
        let mut extensions = span.extensions_mut();
        let Some(Opened(_, _, Fields(facts), _, full)) = extensions.get_mut::<Opened>() else {
            return;
        };
        for (field, value) in recorded.0 {
            facts.retain(|(f, _)| *f != field);
            facts.push((field, value));
        }
        if let Some(full) = full {
            values.record(&mut Attrs(full));
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut extensions = span.extensions_mut();
        if let Some(Opened(_, _, _, _, Some(full))) = extensions.get_mut::<Opened>() {
            if full.entered == 0 {
                let now = Instant::now();
                full.idle += i64::try_from((now - full.last).as_nanos()).unwrap_or(i64::MAX);
                full.last = now;
            }
            full.entered += 1;
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut extensions = span.extensions_mut();
        if let Some(Opened(_, _, _, _, Some(full))) = extensions.get_mut::<Opened>() {
            full.end_ns = Some(now_ns());
            full.entered = full.entered.saturating_sub(1);
            if full.entered == 0 {
                let now = Instant::now();
                full.busy += i64::try_from((now - full.last).as_nanos()).unwrap_or(i64::MAX);
                full.last = now;
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        let span = event.parent().and_then(|id| ctx.span(id)).or_else(|| {
            event
                .is_contextual()
                .then(|| ctx.lookup_current())
                .flatten()
        });
        let Some(span) = span else { return };
        let meta = event.metadata();
        let mut attributes = vec![
            ("level".to_string(), Value::from(meta.level().as_str())),
            ("target".to_string(), Value::from(meta.target())),
        ];
        let mut fields = EventFields {
            name: String::new(),
            attributes: &mut attributes,
            status: None,
        };
        event.record(&mut fields);
        let (mut name, status) = (fields.name, fields.status);
        if name.is_empty() {
            name = meta.name().to_string();
        }
        if let Some(file) = meta.file() {
            attributes.push(("code.file.path".into(), Value::from(file)));
        }
        if let Some(module) = meta.module_path() {
            attributes.push(("code.module.name".into(), Value::from(module)));
        }
        if let Some(line) = meta.line() {
            attributes.push(("code.line.number".into(), Value::from(i64::from(line))));
        }
        let mut extensions = span.extensions_mut();
        let Some(Opened(_, _, _, _, Some(full))) = extensions.get_mut::<Opened>() else {
            return;
        };
        if full.status.is_none() && *meta.level() == tracing::Level::ERROR {
            full.status = Some(String::new());
        }
        if let Some(message) = status {
            full.status = Some(message);
        }
        full.events.push(serde_json::json!({
            "name": name,
            "time_ns": now_ns(),
            "attributes": key_values(attributes),
        }));
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(Opened(start, epoch, Fields(mut facts), own, full)) =
            span.extensions_mut().remove()
        else {
            return;
        };
        let hex = |id: u64| Value::from(format!("{id:016x}"));

        let export_id = |s: &tracing_subscriber::registry::SpanRef<'_, S>| {
            s.extensions()
                .get::<Opened>()
                .map_or_else(|| s.id().into_u64(), |o| o.3)
        };
        let parent = span.parent().map(|p| export_id(&p));
        let root = span
            .scope()
            .last()
            .filter(|r| r.id() != id)
            .map_or(own, |r| export_id(&r));
        let lasted = start.elapsed().as_micros() as u64;
        facts.extend(
            parent
                .map(|p| (F::ParentSpanId, hex(p)))
                .into_iter()
                .chain([
                    (F::TraceId, hex(root)),
                    (F::SpanId, hex(own)),
                    (F::Name, Value::from(span.name())),
                    (F::Start, Value::from(epoch)),
                    (F::DurationUs, Value::from(lasted)),
                ]),
        );
        let full = full.map(|f| f.finish((root, own, parent), span.name()));
        (self.0)(&facts, full.as_ref());
    }
}

#[cfg(test)]
#[path = "tests/traces_tests.rs"]
mod tests;
