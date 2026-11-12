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
    let (stderr, otlp) = log_levels().expect("the test environment's RUST_LOG is a filter");
    let stderr =
        tracing_subscriber::layer::Filter::<tracing_subscriber::Registry>::max_level_hint(&stderr)
            .expect("a Targets filter states its max level");
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

use tracing::Level;
use tracing_subscriber::filter::LevelFilter;

fn hint(t: &tracing_subscriber::filter::Targets) -> LevelFilter {
    tracing_subscriber::layer::Filter::<tracing_subscriber::Registry>::max_level_hint(t)
        .expect("a Targets filter states its max level")
}

/// Every target the console must treat alike under a bare level: busbar's own, its dependencies',
/// and an event bridged from a plugin.
const TARGETS: &[&str] = &[
    "busbar::proxy::engine",
    "busbar_kernel::plane_driver",
    "busbar::request",
    "hyper::proto",
    "rustls::conn",
    "plugin_loader::dispatch",
];

#[test]
fn an_unset_or_blank_rust_log_is_info_for_every_target() {
    for raw in [None, Some(""), Some("   ")] {
        let t = console_filter(raw).expect("unset is the default");
        assert_eq!(hint(&t), LevelFilter::INFO, "{raw:?}");
        for target in TARGETS {
            assert!(t.would_enable(target, &Level::INFO), "{raw:?} {target}");
            assert!(!t.would_enable(target, &Level::DEBUG), "{raw:?} {target}");
        }
    }
}

#[test]
fn every_bare_level_1_5_x_accepted_reads_exactly_as_it_did() {
    // 1.5.x: `RUST_LOG.trim().parse::<tracing::Level>()`, the one level for every target.
    for raw in [
        "error", "warn", "info", "debug", "trace", "DEBUG", "Info", " warn ", "1", "2", "3", "4",
        "5",
    ] {
        let was: Level = raw.trim().parse().expect("1.5.x accepted it");
        let t = console_filter(Some(raw)).expect("still accepted");
        assert_eq!(hint(&t), LevelFilter::from_level(was), "RUST_LOG={raw}");
        for target in TARGETS {
            for level in [
                Level::ERROR,
                Level::WARN,
                Level::INFO,
                Level::DEBUG,
                Level::TRACE,
            ] {
                assert_eq!(
                    t.would_enable(target, &level),
                    level <= was,
                    "RUST_LOG={raw} target={target} level={level}"
                );
            }
        }
    }
}

#[test]
fn off_is_now_honoured_rather_than_read_as_info() {
    for raw in ["off", "OFF", "0"] {
        let t = console_filter(Some(raw)).expect("off is a level");
        assert_eq!(hint(&t), LevelFilter::OFF, "RUST_LOG={raw}");
        assert!(!t.would_enable("busbar::proxy::engine", &Level::ERROR));
    }
}

#[test]
fn directive_syntax_filters_per_target_over_an_info_default() {
    let t = console_filter(Some("busbar=debug,hyper=warn")).expect("documented syntax");
    assert!(t.would_enable("busbar::proxy::engine", &Level::DEBUG));
    assert!(t.would_enable("busbar_kernel::plane_driver", &Level::DEBUG));
    assert!(t.would_enable("busbar::request", &Level::DEBUG));
    assert!(!t.would_enable("busbar::request", &Level::TRACE));
    assert!(!t.would_enable("hyper::proto", &Level::INFO));
    assert!(t.would_enable("hyper::proto", &Level::WARN));
    // A target no directive names keeps the default: naming one never silences the rest.
    assert!(t.would_enable("rustls::conn", &Level::INFO));
    assert!(!t.would_enable("rustls::conn", &Level::DEBUG));
    assert_eq!(hint(&t), LevelFilter::DEBUG);

    let t = console_filter(Some("warn, busbar::request = debug")).expect("spaces are trimmed");
    assert!(t.would_enable("busbar::request", &Level::DEBUG));
    assert!(!t.would_enable("busbar::proxy::engine", &Level::INFO));
    assert!(t.would_enable("busbar::proxy::engine", &Level::WARN));
}

#[test]
fn an_unreadable_rust_log_is_an_error_naming_the_value_never_a_fallback() {
    for raw in [
        "debgu",
        "verbose",
        "busbar",
        "busbar=loud",
        "busbar=",
        "=debug",
        "debug,",
        ",",
        "debug,info",
        "[forward]=debug",
        "busbar[forward]=debug",
        "busbar{request_id}=debug",
        "busbar=debug=trace",
    ] {
        let err = console_filter(Some(raw)).expect_err(raw);
        let shown = err.to_string();
        assert!(
            shown.contains(&format!("{raw:?}")),
            "the error names the value: {shown}"
        );
        assert!(
            shown.contains("busbar=debug"),
            "the error shows the syntax: {shown}"
        );
        assert_eq!(
            log_levels_from(Some(raw)).err(),
            Some(err),
            "boot refuses {raw}"
        );
    }
}

#[test]
fn otlp_still_floors_at_debug_and_follows_a_more_verbose_directive() {
    let otlp = |raw: &str| log_levels_from(Some(raw)).expect(raw).1;
    assert_eq!(otlp("info"), LevelFilter::DEBUG);
    assert_eq!(otlp("off"), LevelFilter::DEBUG);
    assert_eq!(otlp("busbar=warn"), LevelFilter::DEBUG);
    assert_eq!(otlp("trace"), LevelFilter::TRACE);
    assert_eq!(otlp("info,busbar::proxy=trace"), LevelFilter::TRACE);
}

#[test]
fn the_console_filter_stays_on_its_layer_so_otlp_sees_debug_spans() {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;

    let otlp_side = SpanCapture::default();
    {
        let console = console_filter(Some("busbar=warn")).expect("valid");
        let subscriber = tracing_subscriber::registry()
            .with(SpanCapture::default().with_filter(console))
            .with(otlp_side.clone().with_filter(LevelFilter::DEBUG));
        let _g = tracing::subscriber::set_default(subscriber);
        let _s = tracing::debug_span!(target: "busbar::proxy::engine", "forward").entered();
    }
    assert_eq!(*otlp_side.0.lock().unwrap(), vec!["forward".to_string()]);
}
