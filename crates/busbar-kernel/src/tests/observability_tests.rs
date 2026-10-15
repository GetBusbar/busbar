// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/observability.rs`.

use super::*;

/// A span-name capture layer, standing in for the OTLP export layer: it records exactly the
/// spans a layer at its position would export.
#[derive(Clone, Default)]
struct SpanCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<S> tracing_subscriber::Layer<S> for SpanCapture
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        _id: &tracing::span::Id,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Ok(mut v) = self.0.lock() {
            v.push(attrs.metadata().name().to_string());
        }
    }
}

/// OTLP must export the request-path spans, which are all `debug`, without the operator having
/// to set `RUST_LOG=debug` and flood stderr. So the OTLP filter floors at DEBUG and is never
/// less verbose than the stderr one.
#[test]
fn otlp_level_floors_at_debug_and_never_trails_stderr() {
    let (stderr, otlp) = log_levels();
    assert!(
        otlp >= tracing_subscriber::filter::LevelFilter::DEBUG,
        "OTLP must capture debug spans; got {otlp:?}"
    );
    assert!(
        otlp >= stderr,
        "OTLP must never be less verbose than stderr; got otlp={otlp:?} stderr={stderr:?}"
    );
}

/// The filters must be attached PER LAYER. A bare `LevelFilter` added to the registry itself is
/// a global filter that gates callsite enablement for every layer, so a more-verbose OTLP filter
/// underneath one records nothing. Both halves are asserted: the correct shape exports the debug
/// span, and the shape this replaced does not.
#[test]
fn a_registry_level_filter_gates_the_otlp_layer() {
    use tracing_subscriber::filter::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;

    let per_layer = SpanCapture::default();
    {
        let subscriber = tracing_subscriber::registry()
            .with(SpanCapture::default().with_filter(LevelFilter::INFO))
            .with(per_layer.clone().with_filter(LevelFilter::DEBUG));
        let _g = tracing::subscriber::set_default(subscriber);
        let _s = tracing::debug_span!("forward").entered();
    }
    assert_eq!(
        *per_layer.0.lock().unwrap(),
        vec!["forward".to_string()],
        "per-layer filters must let the OTLP layer see debug spans the stderr layer skips"
    );

    let under_global = SpanCapture::default();
    {
        let subscriber = tracing_subscriber::registry()
            .with(LevelFilter::INFO)
            .with(under_global.clone().with_filter(LevelFilter::DEBUG));
        let _g = tracing::subscriber::set_default(subscriber);
        let _s = tracing::debug_span!("forward").entered();
    }
    assert!(
        under_global.0.lock().unwrap().is_empty(),
        "a registry-level filter suppresses the callsite for every layer beneath it"
    );
}
