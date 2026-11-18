// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::projection::{FieldValue, JsonOut, ProjectedRecord, Projection, Rendered};
use busbar_contract::abi::export::ExportField as F;
use busbar_contract::export_stream::ExportStream::Traces;
use std::fmt::Write as _;
use tracing::span::{Attributes, Id};
use tracing::subscriber::Interest;
use tracing::Subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

type Delivery = Box<dyn Fn(&Fields, Option<&[u8]>) + Send + Sync>;
type WantsRecords = Box<dyn Fn() -> bool + Send + Sync>;
type WantsMetadata = Box<dyn Fn(&tracing::Metadata<'_>) -> bool + Send + Sync>;
type ExportLayer = tracing_subscriber::filter::Filtered<
    Producer<Delivery, WantsRecords>,
    SinkFilter,
    tracing_subscriber::Registry,
>;

/// Root-owned activation of the process subscriber. Its stderr layer is already live during
/// boot; the export layer receives one completed registry before serving workers start.
pub struct TracePublisher {
    handle: tracing_subscriber::reload::Handle<ExportLayer, tracing_subscriber::Registry>,
    floor: LevelFilter,
}

/// The export layer could not be put in place; the reload handle said why.
#[derive(Debug)]
pub struct ActivationRefused(tracing_subscriber::reload::Error);

impl std::fmt::Display for ActivationRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "export tracing activation: {}", self.0)
    }
}

impl TracePublisher {
    pub fn publish(
        self,
        exports: std::sync::Arc<super::plugin::Exports>,
    ) -> Result<(), ActivationRefused> {
        let (producer, filter) = producers(self.floor, exports);
        self.handle
            .modify(|layer| {
                // Preserve Filtered's registered filter identity when replacing its contents.
                *layer.inner_mut() = producer;
                *layer.filter_mut() = filter;
            })
            .map_err(ActivationRefused)
    }
}

pub(crate) fn dormant(
    floor: LevelFilter,
) -> (impl Layer<tracing_subscriber::Registry>, TracePublisher) {
    let (producer, filter) = producers(floor, std::sync::Arc::default());
    let (layer, handle) = tracing_subscriber::reload::Layer::new(producer.with_filter(filter));
    (layer, TracePublisher { handle, floor })
}

fn producers(
    floor: LevelFilter,
    exports: std::sync::Arc<super::plugin::Exports>,
) -> (Producer<Delivery, WantsRecords>, SinkFilter) {
    let traces = exports
        .sinks
        .iter()
        .any(|s| s.projection.wants_stream(Traces));
    let records = exports
        .sinks
        .iter()
        .any(|s| s.projection.wants_stream(Traces) && s.span_record);
    let wanted: WantsMetadata =
        Box::new(move |m| *m.level() <= floor && if m.is_span() { traces } else { records });
    let deliver: Delivery = Box::new(move |facts, span| {
        let ingress = first_text(facts, F::Ingress).unwrap_or_default();
        if tokio::runtime::Handle::try_current().is_ok() {
            super::plugin::deliver_to(&exports, Traces, ingress, |p, takes| {
                record(p, facts, span.filter(|_| takes))
            });
        }
    });
    let records: WantsRecords = Box::new(move || records);
    (
        Producer(deliver, records),
        SinkFilter {
            wanted,
            floor,
            traces,
        },
    )
}

struct SinkFilter {
    wanted: WantsMetadata,
    floor: LevelFilter,
    traces: bool,
}

impl<S> tracing_subscriber::layer::Filter<S> for SinkFilter {
    fn enabled(&self, meta: &tracing::Metadata<'_>, _: &Context<'_, S>) -> bool {
        meta.target() != crate::diagnostics::EXPORT_LOSS_TARGET && (self.wanted)(meta)
    }

    fn callsite_enabled(&self, meta: &'static tracing::Metadata<'static>) -> Interest {
        if meta.target() != crate::diagnostics::EXPORT_LOSS_TARGET && (self.wanted)(meta) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(if self.traces {
            self.floor
        } else {
            LevelFilter::OFF
        })
    }
}

fn record(projection: Projection, facts: &Fields, span: Option<&[u8]>) -> Rendered {
    let mut rec = ProjectedRecord::new(projection, Traces);
    for (field, fact) in &facts.facts {
        rec.set(*field, facts.value(*fact));
    }
    if let Some(span) = span {
        rec.span(span);
    }
    rec.finish()
}

/// The first fact recorded for `field`, when it is text.
fn first_text(facts: &Fields, field: F) -> Option<&str> {
    let (_, fact) = facts.facts.iter().find(|(f, _)| *f == field)?;
    match facts.value(*fact) {
        FieldValue::Str(text) => Some(text),
        _ => None,
    }
}

/// A span's opening: its monotonic start, its epoch start (µs), its facts, its export id, and its
/// full record when a sink takes one.
struct Opened(u64, u64, Fields, u64, Option<SpanRecord>);

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

/// One fact's value. Text is a range of its span's own text buffer.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Fact {
    Text(usize, usize),
    Static(&'static str),
    I64(i64),
    Bool(bool),
    F64(f64),
    U64(u64),
    Hex(u64),
}

/// A span's facts, their text written into one buffer the span owns.
#[derive(Debug, Default)]
struct Fields {
    facts: Vec<(F, Fact)>,
    text: String,
}

impl Fields {
    fn value(&self, fact: Fact) -> FieldValue<'_> {
        match fact {
            Fact::Text(at, end) => FieldValue::Str(self.text.get(at..end).unwrap_or_default()),
            Fact::Static(text) => FieldValue::Str(text),
            Fact::I64(n) => FieldValue::I64(n),
            Fact::Bool(b) => FieldValue::Bool(b),
            Fact::F64(v) => FieldValue::F64(v),
            Fact::U64(n) => FieldValue::U64(n),
            Fact::Hex(id) => FieldValue::Hex(id),
        }
    }

    /// The traced field `field` names, if it is one of the stream's fields.
    fn traced(field: &tracing::field::Field) -> Option<F> {
        F::from_token(field.name()).filter(|f| Traces.default_fields().contains(f))
    }

    fn fact(&mut self, field: &tracing::field::Field, value: Fact) {
        if let Some(traced) = Self::traced(field) {
            set_fact(&mut self.facts, traced, value);
        }
    }

    /// A text fact, written into the span's text only when the field is traced.
    fn text_fact(&mut self, field: &tracing::field::Field, write: impl FnOnce(&mut String)) {
        if let Some(traced) = Self::traced(field) {
            let at = self.text.len();
            write(&mut self.text);
            set_fact(&mut self.facts, traced, Fact::Text(at, self.text.len()));
        }
    }
}

/// Record `value` for `field`: a later value replaces the earlier one.
fn set_fact(facts: &mut Vec<(F, Fact)>, field: F, value: Fact) {
    match facts.iter_mut().find(|(f, _)| *f == field) {
        Some(slot) => slot.1 = value,
        None => facts.push((field, value)),
    }
}

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.text_fact(field, |text| {
            let _ = write!(text, "{value:?}");
        });
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.text_fact(field, |text| text.push_str(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fact(field, Fact::I64(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fact(field, Fact::Bool(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fact(field, Fact::F64(value));
    }
}

const OTEL_NAME: &str = "otel.name";
const OTEL_KIND: &str = "otel.kind";
const OTEL_STATUS_CODE: &str = "otel.status_code";
const OTEL_STATUS_MESSAGE: &str = "otel.status_message";

const EVENT_EXCEPTION: &str = "exception";
const EXCEPTION_MESSAGE: &str = "exception.message";
const EXCEPTION_STACKTRACE: &str = "exception.stacktrace";

/// This thread's id as 0.33 wrote it: the integer inside `ThreadId(n)`, read off its `Debug`
/// text in a stack buffer.
struct ThreadIdText {
    buf: [u8; 48],
    len: usize,
}

impl std::fmt::Write for ThreadIdText {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        let room = self.buf.len() - self.len;
        let take = s.len().min(room);
        self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

impl ThreadIdText {
    fn number(&self) -> i64 {
        std::str::from_utf8(&self.buf[..self.len])
            .unwrap_or_default()
            .trim_start_matches("ThreadId(")
            .trim_end_matches(')')
            .parse::<i64>()
            .unwrap_or_default()
    }
}

thread_local! {
    /// This thread's id as 0.33 wrote it: the integer inside `ThreadId(n)`.
    static THREAD_ID: i64 = {
        let mut text = ThreadIdText { buf: [0; 48], len: 0 };
        let _ = write!(text, "{:?}", std::thread::current().id());
        text.number()
    };
}

/// An attribute key: a field or fixed name, or a field's `<name>.chain`.
#[derive(Clone, Copy, Debug)]
enum Key {
    Static(&'static str),
    Chain(&'static str),
}

impl Key {
    fn same(self, other: Key) -> bool {
        match (self, other) {
            (Key::Static(a), Key::Static(b)) | (Key::Chain(a), Key::Chain(b)) => a == b,
            (Key::Static(full), Key::Chain(name)) | (Key::Chain(name), Key::Static(full)) => {
                full.strip_suffix(".chain") == Some(name)
            }
        }
    }

    fn write(self, out: &mut JsonOut) {
        match self {
            Key::Static(name) => out.str(name),
            Key::Chain(name) => {
                out.str(name);
                out.0.pop();
                out.raw(b".chain\"");
            }
        }
    }
}

/// An attribute value. Text is a range of its bag's text; a chain is a range of its bag's chains.
#[derive(Clone, Copy, Debug)]
enum Attr {
    Text(usize, usize),
    Static(&'static str),
    I64(i64),
    Bool(bool),
    F64(f64),
    Chain(usize, usize),
}

/// One record's attributes, with the text they point into: a span's own, or an event's scratch
/// that is cleared and reused for the next event.
#[derive(Debug, Default)]
struct Bag {
    text: String,
    chains: Vec<(usize, usize)>,
    attrs: Vec<(Key, Attr)>,
}

impl Bag {
    fn clear(&mut self) {
        self.text.clear();
        self.chains.clear();
        self.attrs.clear();
    }

    fn slice(&self, (at, end): (usize, usize)) -> &str {
        self.text.get(at..end).unwrap_or_default()
    }

    fn write(&mut self, write: impl FnOnce(&mut String)) -> (usize, usize) {
        let at = self.text.len();
        write(&mut self.text);
        (at, self.text.len())
    }

    fn push(&mut self, key: Key, value: Attr) {
        self.attrs.push((key, value));
    }

    /// The error's source chain: each source's text, in order.
    fn chain(&mut self, value: &(dyn std::error::Error + 'static)) -> Attr {
        let first = self.chains.len();
        let mut next = value.source();
        while let Some(err) = next {
            let source = self.write(|text| {
                let _ = write!(text, "{err}");
            });
            self.chains.push(source);
            next = err.source();
        }
        Attr::Chain(first, self.chains.len())
    }

    /// An error recorded as an attribute: its text and source chain, under the exception names
    /// and the field's own name.
    fn error(&mut self, field: &'static str, value: &(dyn std::error::Error + 'static)) {
        let chain = self.chain(value);
        let (at, end) = self.write(|text| {
            let _ = write!(text, "{value}");
        });
        self.push(Key::Static(EXCEPTION_MESSAGE), Attr::Text(at, end));
        self.push(Key::Static(EXCEPTION_STACKTRACE), chain);
        self.push(Key::Static(field), Attr::Text(at, end));
        self.push(Key::Chain(field), chain);
    }
}

fn write_attr(out: &mut JsonOut, bag: &Bag, value: Attr) {
    match value {
        Attr::Text(at, end) => out.str(bag.slice((at, end))),
        Attr::Static(text) => out.str(text),
        Attr::I64(n) => out.i64(n),
        Attr::Bool(b) => out.bool(b),
        Attr::F64(v) => out.f64(v),
        Attr::Chain(first, end) => {
            out.byte(b'[');
            for (i, source) in bag
                .chains
                .get(first..end)
                .unwrap_or_default()
                .iter()
                .enumerate()
            {
                if i > 0 {
                    out.byte(b',');
                }
                out.str(bag.slice(*source));
            }
            out.byte(b']');
        }
    }
}

/// The bag's attributes as `[{"key":..,"value":..}, ..]`: each key once, at its first position,
/// carrying its last value.
fn write_key_values(out: &mut JsonOut, bag: &Bag) {
    out.byte(b'[');
    let mut written = false;
    for (at, (key, _)) in bag.attrs.iter().enumerate() {
        if bag.attrs[..at]
            .iter()
            .any(|(earlier, _)| earlier.same(*key))
        {
            continue;
        }
        let Some((_, value)) = bag.attrs[at..].iter().rev().find(|(k, _)| k.same(*key)) else {
            continue;
        };
        if written {
            out.byte(b',');
        }
        written = true;
        out.byte(b'{');
        out.key("key");
        key.write(out);
        out.byte(b',');
        out.key("value");
        write_attr(out, bag, *value);
        out.byte(b'}');
    }
    out.byte(b']');
}

/// A typed value's JSON text, as an event name taken from a typed `message` carries it.
fn write_json_text(text: &mut String, value: Attr) {
    match value {
        Attr::I64(n) => {
            let _ = write!(text, "{n}");
        }
        Attr::Bool(b) => text.push_str(if b { "true" } else { "false" }),
        Attr::F64(v) if v.is_finite() => {
            let _ = busbar_contract::json::to_writer(TextSink(text), &v);
        }
        Attr::F64(v) => {
            let _ = write!(text, "{{\"$busbar_f64\":\"{v}\"}}");
        }
        Attr::Text(..) | Attr::Static(_) | Attr::Chain(..) => {}
    }
}

/// The JSON facade's output appended to a text buffer (it writes whole UTF-8 tokens).
struct TextSink<'a>(&'a mut String);

impl std::io::Write for TextSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let text = std::str::from_utf8(buf).map_err(std::io::Error::other)?;
        self.0.push_str(text);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct SpanRecord {
    start_ns: u64,
    end_ns: Option<u64>,
    bag: Bag,
    /// The events, each already one JSON object, comma-separated.
    events: JsonOut,
    /// One event's attributes while it is recorded; cleared for the next.
    scratch: Bag,
    /// The error status message, a range of `bag`'s text (empty: an error without a message).
    status: Option<(usize, usize)>,
    busy: i64,
    idle: i64,
    /// The monotonic reading the span last entered or exited at.
    last: u64,
    entered: u64,
}

const NO_MESSAGE: (usize, usize) = (0, 0);

impl SpanRecord {
    fn open(
        meta: &'static tracing::Metadata<'static>,
        attrs: &Attributes<'_>,
        at: crate::store::Stamp,
    ) -> Self {
        let mut record = SpanRecord {
            start_ns: at.wall_ns,
            end_ns: None,
            bag: Bag::default(),
            events: JsonOut(Vec::new()),
            scratch: Bag::default(),
            status: None,
            busy: 0,
            idle: 0,
            last: at.mono_ns,
            entered: 0,
        };
        let bag = &mut record.bag;
        if let Some(file) = meta.file() {
            bag.push(Key::Static("code.file.path"), Attr::Static(file));
        }
        if let Some(module) = meta.module_path() {
            bag.push(Key::Static("code.module.name"), Attr::Static(module));
        }
        if let Some(line) = meta.line() {
            bag.push(Key::Static("code.line.number"), Attr::I64(i64::from(line)));
        }
        THREAD_ID.with(|id| bag.push(Key::Static("thread.id"), Attr::I64(*id)));
        if let Some(name) = std::thread::current().name() {
            let (at, end) = bag.write(|text| text.push_str(name));
            bag.push(Key::Static("thread.name"), Attr::Text(at, end));
        }
        bag.push(Key::Static("target"), Attr::Static(meta.target()));
        attrs.record(&mut Attrs(&mut record));
        record
    }

    /// One event, rendered into the span's events as it happens.
    fn event(&mut self, event: &tracing::Event<'_>, time_ns: u64) {
        let meta = event.metadata();
        self.scratch.clear();
        self.scratch
            .push(Key::Static("level"), Attr::Static(meta.level().as_str()));
        self.scratch
            .push(Key::Static("target"), Attr::Static(meta.target()));
        let mut fields = EventFields {
            bag: &mut self.scratch,
            name: EventName::Unset,
            status: None,
        };
        event.record(&mut fields);
        let (name, status) = (fields.name, fields.status);
        if let Some(file) = meta.file() {
            self.scratch
                .push(Key::Static("code.file.path"), Attr::Static(file));
        }
        if let Some(module) = meta.module_path() {
            self.scratch
                .push(Key::Static("code.module.name"), Attr::Static(module));
        }
        if let Some(line) = meta.line() {
            self.scratch
                .push(Key::Static("code.line.number"), Attr::I64(i64::from(line)));
        }
        if self.status.is_none() && *meta.level() == tracing::Level::ERROR {
            self.status = Some(NO_MESSAGE);
        }
        if let Some(message) = status {
            let scratch = &self.scratch;
            self.status = Some(self.bag.write(|text| text.push_str(scratch.slice(message))));
        }
        let events = &mut self.events;
        if !events.0.is_empty() {
            events.byte(b',');
        }
        events.byte(b'{');
        events.key("attributes");
        write_key_values(events, &self.scratch);
        events.byte(b',');
        events.key("name");
        match name {
            EventName::Text(at, end) if at != end => events.str(self.scratch.slice((at, end))),
            EventName::Static(text) if !text.is_empty() => events.str(text),
            _ => events.str(meta.name()),
        }
        events.byte(b',');
        events.key("time_ns");
        events.u64(time_ns);
        events.byte(b'}');
    }

    /// The full span record, one JSON object.
    fn finish(self, ids: (u64, u64, Option<u64>), name: &str) -> Vec<u8> {
        let (trace, own, parent) = ids;
        let forced = name == "forward_once" || name == "request_attempts";
        let end_ns = match self.end_ns {
            Some(end) if !forced => end,
            _ => crate::store::now_ns(),
        };
        let SpanRecord {
            start_ns,
            mut bag,
            events,
            status,
            busy,
            idle,
            ..
        } = self;
        bag.push(Key::Static("busy_ns"), Attr::I64(busy));
        bag.push(Key::Static("idle_ns"), Attr::I64(idle));
        let mut out = JsonOut(Vec::with_capacity(256 + bag.text.len() + events.0.len()));
        out.byte(b'{');
        out.key("attributes");
        write_key_values(&mut out, &bag);
        out.byte(b',');
        out.key("end_ns");
        out.u64(end_ns);
        out.byte(b',');
        out.key("events");
        out.byte(b'[');
        out.raw(&events.0);
        out.byte(b']');
        out.byte(b',');
        out.key("name");
        out.str(name);
        out.byte(b',');
        if let Some(parent) = parent {
            out.key("parent_span_id");
            out.hex(parent);
            out.byte(b',');
        }
        out.key("span_id");
        out.hex(own);
        out.byte(b',');
        out.key("start_ns");
        out.u64(start_ns);
        out.byte(b',');
        out.key("status");
        out.byte(b'{');
        out.key("code");
        out.str(if status.is_some() { "error" } else { "unset" });
        out.byte(b',');
        out.key("message");
        out.str(status.map_or("", |message| bag.slice(message)));
        out.byte(b'}');
        out.byte(b',');
        out.key("trace_id");
        out.hex(trace);
        out.byte(b'}');
        out.0
    }
}

struct Attrs<'a>(&'a mut SpanRecord);

impl Attrs<'_> {
    /// A text attribute just written at `(at, end)` of the span's text: the OpenTelemetry name
    /// and kind are dropped, the status code and message set the status, the rest are attributes.
    fn text(&mut self, key: &'static str, (at, end): (usize, usize)) {
        let record = &mut *self.0;
        match key {
            OTEL_NAME | OTEL_KIND => record.bag.text.truncate(at),
            OTEL_STATUS_CODE => {
                let error = record.bag.slice((at, end)).eq_ignore_ascii_case("error");
                record.bag.text.truncate(at);
                if error {
                    record.status.get_or_insert(NO_MESSAGE);
                } else {
                    record.status = None;
                }
            }
            OTEL_STATUS_MESSAGE => record.status = Some((at, end)),
            _ => record.bag.push(Key::Static(key), Attr::Text(at, end)),
        }
    }
}

impl tracing::field::Visit for Attrs<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let written = self.0.bag.write(|text| {
            let _ = write!(text, "{value:?}");
        });
        self.text(field.name(), written);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let written = self.0.bag.write(|text| text.push_str(value));
        self.text(field.name(), written);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.bag.push(Key::Static(field.name()), Attr::I64(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0
            .bag
            .push(Key::Static(field.name()), Attr::Bool(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.0.bag.push(Key::Static(field.name()), Attr::F64(value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.0.bag.error(field.name(), value);
    }
}

/// An event's name: unset until a `message` (or an unnamed error) gives it one.
#[derive(Clone, Copy)]
enum EventName {
    Unset,
    Text(usize, usize),
    Static(&'static str),
}

struct EventFields<'a> {
    bag: &'a mut Bag,
    name: EventName,
    status: Option<(usize, usize)>,
}

impl EventFields<'_> {
    fn unnamed(&self) -> bool {
        match self.name {
            EventName::Unset => true,
            EventName::Text(at, end) => at == end,
            EventName::Static(text) => text.is_empty(),
        }
    }

    /// An unnamed event's `error` field: it names the event an exception and sets its status.
    fn exception(&mut self, message: (usize, usize)) {
        self.status = Some(message);
        self.name = EventName::Static(EVENT_EXCEPTION);
        self.bag.push(
            Key::Static(EXCEPTION_MESSAGE),
            Attr::Text(message.0, message.1),
        );
    }

    /// A text field just written at `(at, end)` of the event's text.
    fn text(&mut self, key: &'static str, (at, end): (usize, usize)) {
        match key {
            "message" => self.name = EventName::Text(at, end),
            key if key.starts_with("log.") => self.bag.text.truncate(at),
            key => self.bag.push(Key::Static(key), Attr::Text(at, end)),
        }
    }

    fn typed(&mut self, key: &'static str, value: Attr) {
        match key {
            "message" => {
                let (at, end) = self.bag.write(|text| write_json_text(text, value));
                self.name = EventName::Text(at, end);
            }
            key if key.starts_with("log.") => {}
            key => self.bag.push(Key::Static(key), value),
        }
    }
}

impl tracing::field::Visit for EventFields<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let written = self.bag.write(|text| {
            let _ = write!(text, "{value:?}");
        });
        match field.name() {
            "error" if self.unnamed() => self.exception(written),
            key => self.text(key, written),
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        match field.name() {
            "message" => {
                let written = self.bag.write(|text| text.push_str(value));
                self.name = EventName::Text(written.0, written.1);
            }
            "error" if self.unnamed() => {
                let written = self.bag.write(|text| {
                    let _ = write!(text, "{value:?}");
                });
                self.exception(written);
            }
            key if key.starts_with("log.") => {}
            key => {
                let written = self.bag.write(|text| text.push_str(value));
                self.bag
                    .push(Key::Static(key), Attr::Text(written.0, written.1));
            }
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.typed(field.name(), Attr::I64(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.typed(field.name(), Attr::Bool(value));
    }

    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.typed(field.name(), Attr::F64(value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.bag.error(field.name(), value);
    }
}

struct Producer<D, W>(D, W);

impl<S, D, W> Layer<S> for Producer<D, W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    D: Fn(&Fields, Option<&[u8]>) + Send + Sync + 'static,
    W: Fn() -> bool + Send + Sync + 'static,
{
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        if attrs.metadata().target() == crate::diagnostics::EXPORT_LOSS_TARGET {
            return;
        }
        let Some(span) = ctx.span(id) else { return };
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        let at = crate::store::Stamp::now();
        let epoch = at.wall_ns / 1_000;
        let own = next_id();
        let full = (self.1)().then(|| SpanRecord::open(attrs.metadata(), attrs, at));
        span.extensions_mut()
            .insert(Opened(at.mono_ns, epoch, fields, own, full));
    }

    fn on_record(&self, id: &Id, values: &tracing::span::Record<'_>, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut extensions = span.extensions_mut();
        let Some(Opened(_, _, facts, _, full)) = extensions.get_mut::<Opened>() else {
            return;
        };
        values.record(facts);
        if let Some(full) = full {
            values.record(&mut Attrs(full));
        }
    }

    fn on_enter(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut extensions = span.extensions_mut();
        if let Some(Opened(_, _, _, _, Some(full))) = extensions.get_mut::<Opened>() {
            if full.entered == 0 {
                let now = crate::store::monotonic_ns();
                full.idle += i64::try_from(now.saturating_sub(full.last)).unwrap_or(i64::MAX);
                full.last = now;
            }
            full.entered += 1;
        }
    }

    fn on_exit(&self, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut extensions = span.extensions_mut();
        if let Some(Opened(_, _, _, _, Some(full))) = extensions.get_mut::<Opened>() {
            let at = crate::store::Stamp::now();
            full.end_ns = Some(at.wall_ns);
            full.entered = full.entered.saturating_sub(1);
            if full.entered == 0 {
                full.busy +=
                    i64::try_from(at.mono_ns.saturating_sub(full.last)).unwrap_or(i64::MAX);
                full.last = at.mono_ns;
            }
        }
    }

    fn on_event(&self, event: &tracing::Event<'_>, ctx: Context<'_, S>) {
        if event.metadata().target() == crate::diagnostics::EXPORT_LOSS_TARGET {
            return;
        }
        let span = event.parent().and_then(|id| ctx.span(id)).or_else(|| {
            event
                .is_contextual()
                .then(|| ctx.lookup_current())
                .flatten()
        });
        let Some(span) = span else { return };
        let mut extensions = span.extensions_mut();
        let Some(Opened(_, _, _, _, Some(full))) = extensions.get_mut::<Opened>() else {
            return;
        };
        full.event(event, crate::store::now_ns());
    }

    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(Opened(start, epoch, mut facts, own, full)) = span.extensions_mut().remove()
        else {
            return;
        };

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
        let lasted = crate::store::monotonic_ns().saturating_sub(start) / 1_000;
        if let Some(parent) = parent {
            set_fact(&mut facts.facts, F::ParentSpanId, Fact::Hex(parent));
        }
        set_fact(&mut facts.facts, F::TraceId, Fact::Hex(root));
        set_fact(&mut facts.facts, F::SpanId, Fact::Hex(own));
        set_fact(&mut facts.facts, F::Name, Fact::Static(span.name()));
        set_fact(&mut facts.facts, F::Start, Fact::U64(epoch));
        set_fact(&mut facts.facts, F::DurationUs, Fact::U64(lasted));
        let full = full.map(|f| f.finish((root, own, parent), span.name()));
        (self.0)(&facts, full.as_deref());
    }
}

#[cfg(test)]
#[path = "tests/traces_tests.rs"]
mod tests;
