// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the observation source (`metrics/source.rs`): what it snapshots is what 1.5.5's recorder
//! (`metrics-exporter-prometheus` 0.18.3, kept here as a dev-dependency and nowhere else) held, so the
//! scrape sink renders the 1.5.5 exposition from it byte for byte, order included.

use super::*;
use busbar_contract::abi::sdk::{MetricFamily, MetricSample};
use metrics_exporter_prometheus::formatting as reference;

/// The scrape sink's rendering of `families` — the bytes an operator scrapes.
fn rendered(families: &[Family]) -> String {
    let families: Vec<MetricFamily> = families
        .iter()
        .map(|f| MetricFamily {
            name: f.name.clone(),
            kind: busbar_contract::export_calls::type_word(f.kind)
                .expect("a kind in the vocabulary")
                .to_string(),
            help: f.help.clone(),
            samples: f
                .samples
                .iter()
                .map(|s| MetricSample {
                    name: s.name.clone(),
                    labels: s.labels.clone(),
                    value: s.value.clone(),
                })
                .collect(),
        })
        .collect();
    busbar_export_prometheus::render(&families)
}

/// One workload, every shape the emit sites write: described and undescribed counters, labelled
/// and not, label values and HELP text that need escaping, a name the data model must sanitize,
/// gauges of every magnitude, and distributions with many samples.
fn workload() {
    metrics::describe_counter!(
        "busbar_eq_requests_total",
        "requests, by \"pool\"\nand \\ outcome"
    );
    metrics::describe_gauge!("busbar_eq_gauge", metrics::Unit::Count, "a gauge");
    metrics::describe_histogram!(
        "busbar_eq_duration_seconds",
        metrics::Unit::Seconds,
        "latency"
    );
    for (pool, n) in [("a\"b\\c\nd", 3), ("plain", 1), ("back\\\\slash", 2)] {
        metrics::counter!("busbar_eq_requests_total", "pool" => pool, "outcome" => "ok")
            .increment(n);
    }
    metrics::counter!("busbar_eq_unlabelled_total").absolute(0);
    metrics::counter!("busbar.eq-dotted:name", "9key" => "v").increment(5);
    for (key, v) in [
        ("a", 1.5),
        ("b", 0.0),
        ("c", 1e21),
        ("d", -3.0),
        ("e", 0.1 + 0.2),
    ] {
        metrics::gauge!("busbar_eq_gauge", "key" => key).set(v);
    }
    metrics::gauge!("busbar_eq_big", "key" => "max").set(i64::MAX as f64);
    for (pool, xs) in [("p", vec![0.001, 0.25, 0.5, 2.0]), ("q", vec![7.0])] {
        for x in xs {
            metrics::histogram!("busbar_eq_duration_seconds", "pool" => pool).record(x);
        }
    }
    let _registered_only = metrics::histogram!("busbar_eq_idle_seconds");
}

/// THE BYTE PROOF: the same workload written to 1.5.5's recorder and to the source renders, through
/// the scrape sink, to the same exposition — every family, series, label, value and HELP line, in
/// the same order. The 1.5.5 side is its own text read back through the snapshot reader; the sink
/// orders both the same stable way, so this compares what the recorders HOLD, not their hash order.
#[test]
fn the_source_holds_what_1_5_5s_recorder_held() {
    let width = Duration::from_secs(20);
    let old = metrics_exporter_prometheus::PrometheusBuilder::new()
        .set_bucket_duration(width)
        .expect("a bucket width")
        .set_bucket_count(std::num::NonZeroU32::new(3).expect("non-zero"))
        .idle_timeout(
            metrics_util::MetricKindMask::GAUGE,
            Some(Duration::from_secs(60)),
        )
        .build_recorder();
    let source: &'static Source = Box::leak(Box::new(Source::new(
        width,
        std::num::NonZeroU32::new(3).expect("non-zero"),
        Duration::from_secs(60),
    )));
    metrics::with_local_recorder(&old, workload);
    metrics::with_local_recorder(&source, workload);

    let text = old.handle().render();
    let was = busbar_contract::export_calls::parse_families(&text).expect("1.5.5's text snapshots");
    let now = source.snapshot();
    assert_eq!(rendered(&now), rendered(&was), "1.5.5 wrote:\n{text}");
    assert!(
        rendered(&now).contains("quantile=\"0.999\"") && now.len() >= 6,
        "the proof is not vacuous:\n{}",
        rendered(&now)
    );
    let kinds: Vec<u8> = now.iter().map(|f| f.kind).collect();
    assert!(
        kinds.windows(2).all(|w| w[0] <= w[1]),
        "the snapshot is kind then name: {kinds:?}"
    );
}

/// The escaping and sanitizing are 1.5.5's own, character for character, over the inputs that
/// differ: quotes, line feeds, lone, doubled and trailing backslashes, and names outside the model.
#[test]
fn escapes_and_names_are_1_5_5s() {
    for s in [
        "",
        "plain",
        "a\"b",
        "a\\b",
        "a\\\\b",
        "a\\\"b",
        "a\\nb",
        "line\nfeed",
        "trailing\\",
        "\\\\\\",
        "\\\n",
        "ünï\"cødé\\",
    ] {
        assert_eq!(
            escaped(s, true),
            reference::sanitize_label_value(s),
            "{s:?}"
        );
        assert_eq!(
            escaped(s, false),
            reference::sanitize_description(s),
            "{s:?}"
        );
    }
    for s in [
        "busbar_ok",
        "busbar:ok",
        "9lead",
        "a.b-c",
        ":colon",
        "ü",
        "",
    ] {
        assert_eq!(
            sanitized(s, true),
            reference::sanitize_metric_name(s),
            "{s:?}"
        );
        assert_eq!(
            sanitized(s, false),
            reference::sanitize_label_key(s),
            "{s:?}"
        );
    }
}

/// THE ROLLING WINDOW: a sample older than every span still counts toward `_count` and `_sum` but
/// leaves the quantiles once its span is past the window; a sample inside the newest span is placed
/// there.
#[test]
fn the_window_rolls_while_count_and_sum_never_reset() {
    let (width, n) = (Duration::from_secs(10), 3);
    let t0 = Instant::now();
    let mut d = Rolling::default();
    d.add(100.0, t0, width, n);
    d.add(1.0, t0 + width * 4, width, n);
    d.add(2.0, t0 + width * 4 + Duration::from_secs(1), width, n);
    let window = d.window(t0 + width * 4 + Duration::from_secs(2), width, n);
    assert_eq!((d.count, d.sum), (3, 103.0));
    assert_eq!(window.count(), 2, "the first span is past the window");
    assert_eq!(window.quantile(1.0), Some(2.0));
    assert_eq!(d.buckets.len(), 1, "the expired span was dropped");
    d.add(5.0, t0, width, n);
    assert_eq!(
        (d.count, d.buckets.len()),
        (4, 1),
        "a sample older than every span is counted, not placed"
    );
}
