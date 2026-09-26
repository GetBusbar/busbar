// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRACES PRODUCER (K9a S7; BUSBAR-1.6.0 18b(d)) — the `traces` record stream, built by the
//! kernel from its own tracing spans and delivered to the export-axis sinks that subscribe to it.
//!
//! `traces` has always been in the export vocabulary and in the projection mask, but nothing built
//! a traces RECORD: spans left the process only through the `otlp` module's `tracing-opentelemetry`
//! layer, installed once at boot. This layer is the record producer that was missing. Each span it
//! sees closing becomes one record of the stream's documented fields — `trace_id` (the root span's
//! id), `span_id`, `parent_span_id`, `name`, `start` (epoch microseconds), `duration_us`, and the
//! span's own `pool` / `ingress` / `op` / `lane` / `provider` / `model` where it carries them —
//! built TO each subscribed sink's projection ([`super::projection::ProjectedRecord`]), off the
//! span's thread, bounded per sink exactly as `logs` is.
//!
//! COST. The layer exists only when an export axis is installed, and its per-layer filter answers
//! per span CALLSITE — cached, asked again once when the axis opens its sinks — whether any opened
//! sink subscribes to `traces`: a deployment with no such sink creates no span it did not create
//! before and builds no record. Events are never its business, and nothing above `floor` is.

use super::projection::{ProjectedRecord, Projection};
use busbar_plugin_loader::{ExportField as F, ExportStream::Traces};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Instant, UNIX_EPOCH};
use tracing::span::{Attributes, Id};
use tracing::Subscriber;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::registry::LookupSpan;

/// The producer, when an export axis is installed: a SPAN at or under `floor` (the level the span
/// exporter has always taken — `observability::log_levels`), while some opened sink subscribes to
/// `traces`. The answer is per CALLSITE and cached, so the axis re-asks once its sinks are open.
pub fn layer<S: Subscriber + for<'a> LookupSpan<'a>>(floor: LevelFilter) -> Option<impl Layer<S>> {
    let wanted = move |m: &tracing::Metadata<'_>| {
        let subscribed = |s: &super::plugin::PluginSink| s.projection.wants_stream(Traces);
        m.is_span() && *m.level() <= floor && super::plugin::sinks().any(subscribed)
    };
    let filter = tracing_subscriber::filter::filter_fn(wanted).with_max_level_hint(floor);
    let producer = Producer(deliver).with_filter(filter);
    super::plugin::AXIS.get().map(|_| producer)
}

/// Hand one closed span's record to every opened sink subscribed to `traces`, built to that sink's
/// own projection, off the span's thread — never from a thread with no runtime to hand it to.
fn deliver(facts: &[(F, Value)]) {
    let ingress = facts.iter().find(|(f, _)| *f == F::Ingress);
    let ingress = ingress.and_then(|(_, v)| v.as_str()).unwrap_or_default();
    if tokio::runtime::Handle::try_current().is_ok() {
        super::plugin::deliver(Traces, ingress, |p| record(p, facts));
    }
}

/// One sink's record: the span's facts, each written only if the sink's projection grants it.
fn record(projection: Projection, facts: &[(F, Value)]) -> Arc<Value> {
    let mut rec = ProjectedRecord::new(projection, Traces);
    facts.iter().for_each(|(f, v)| _ = rec.set(*f, v.clone()));
    Arc::new(rec.finish())
}

/// A span as it opened: when (monotonic, and epoch microseconds), and the stream's fields it
/// carries.
struct Opened(Instant, u64, Fields);

/// The `traces` fields a span records, by the field's own name — and only those: a span field that
/// shares a name with another stream's field (`key_id`, say) is not a traces fact.
struct Fields(Vec<(F, Value)>);

impl tracing::field::Visit for Fields {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.record_str(field, &format!("{value:?}"));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        let traced = F::from_token(field.name()).filter(|f| Traces.default_fields().contains(f));
        self.0.extend(traced.map(|f| (f, Value::from(value))));
    }
}

/// The producer, handing each closed span's record facts to its sink (the export axis's delivery).
struct Producer(fn(&[(F, Value)]));

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for Producer {
    fn on_new_span(&self, attrs: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(id) else { return };
        let mut fields = Fields(Vec::new());
        attrs.record(&mut fields);
        let epoch = UNIX_EPOCH.elapsed().unwrap_or_default().as_micros() as u64;
        span.extensions_mut()
            .insert(Opened(Instant::now(), epoch, fields));
    }

    /// The span's record: its facts, its parent's id, its ROOT's id as the trace id (a root is its
    /// own trace), its own id and name, when it opened and how long it stayed open.
    fn on_close(&self, id: Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else { return };
        let Some(Opened(start, epoch, Fields(mut facts))) = span.extensions_mut().remove() else {
            return;
        };
        let hex = |id: &Id| Value::from(format!("{:016x}", id.into_u64()));
        let parent = span.parent().map(|p| (F::ParentSpanId, hex(&p.id())));
        let root = span.scope().last().map_or(id.clone(), |r| r.id());
        let lasted = start.elapsed().as_micros() as u64;
        facts.extend(parent.into_iter().chain([
            (F::TraceId, hex(&root)),
            (F::SpanId, hex(&id)),
            (F::Name, Value::from(span.name())),
            (F::Start, Value::from(epoch)),
            (F::DurationUs, Value::from(lasted)),
        ]));
        (self.0)(&facts);
    }
}

#[cfg(test)]
#[path = "tests/traces_tests.rs"]
mod tests;
