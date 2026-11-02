// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn percent_decoding_preserves_components_that_would_be_invalid_utf8() {
    for encoded in ["%FF", "%C3", "ok%20%FF", "%E2%82"] {
        assert_eq!(percent_decode(encoded), encoded);
    }
    assert_eq!(percent_decode("%E2%82%AC"), "€");
    assert_eq!(percent_decode("%2541"), "%41");
    assert_eq!(percent_decode("naïve%20x"), "naïve x");
    assert_eq!(percent_decode("%Q1%"), "%Q1%");
}

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
