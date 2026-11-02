use super::*;
use metrics_exporter_prometheus::formatting as reference;

fn ordered_families(families: &[Family]) -> Vec<Family> {
    let mut ordered = families.to_vec();
    ordered.sort_by(|a, b| a.kind.cmp(&b.kind).then_with(|| a.name.cmp(&b.name)));
    for family in &mut ordered {
        let mut series: std::collections::BTreeMap<Vec<(String, String)>, Vec<_>> =
            std::collections::BTreeMap::new();
        for sample in std::mem::take(&mut family.samples) {
            let key = sample
                .labels
                .iter()
                .filter(|(k, _)| k != "le" && k != "quantile")
                .cloned()
                .collect();
            series.entry(key).or_default().push(sample);
        }
        family.samples = series.into_values().flatten().collect();
    }
    ordered
}

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
    assert_eq!(
        ordered_families(&now),
        ordered_families(&was),
        "1.5.5 wrote:\n{text}"
    );
    assert!(
        now.iter().flat_map(|family| &family.samples).any(|sample| {
            sample
                .labels
                .iter()
                .any(|(key, value)| key == "quantile" && value == "0.999")
        }) && now.len() >= 6,
        "the proof is not vacuous:\n{now:?}"
    );
    let kinds: Vec<u8> = now.iter().map(|f| f.kind).collect();
    assert!(
        kinds.windows(2).all(|w| w[0] <= w[1]),
        "the snapshot is kind then name: {kinds:?}"
    );
}

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

fn identity_source() -> &'static Source {
    Box::leak(Box::new(Source::new(
        crate::snapshot::GAUGE_IDLE_TIMEOUT,
        crate::snapshot::SUMMARY_BUCKETS,
        crate::snapshot::GAUGE_IDLE_TIMEOUT,
    )))
}

fn identity_values(families: &[Family], sample_name: &str) -> Vec<String> {
    let mut values: Vec<_> = families
        .iter()
        .flat_map(|family| &family.samples)
        .filter(|sample| sample.name == sample_name)
        .map(|sample| sample.value.clone())
        .collect();
    values.sort();
    values
}

#[test]
fn raw_label_values_that_share_presentation_keep_both_series() {
    const COUNTER: &str = "busbar_identity_counter";
    const GAUGE: &str = "busbar_identity_gauge";
    const SUMMARY: &str = "busbar_identity_summary";
    const SUMMARY_SUM: &str = "busbar_identity_summary_sum";
    const SUMMARY_COUNT: &str = "busbar_identity_summary_count";
    for (left, right) in [("\\", "\\\\"), ("\"", "\\\"")] {
        assert_ne!(left, right);
        assert_eq!(
            reference::sanitize_label_value(left),
            reference::sanitize_label_value(right),
            "the historical presentation collision is the fixture's premise"
        );
        let source = identity_source();
        let (counters, gauges, histograms) = metrics::with_local_recorder(&source, || {
            let counters =
                [left, right].map(|label| metrics::counter!(COUNTER, "identity" => label));
            let gauges = [left, right].map(|label| metrics::gauge!(GAUGE, "identity" => label));
            let histograms =
                [left, right].map(|label| metrics::histogram!(SUMMARY, "identity" => label));
            (counters, gauges, histograms)
        });
        for (at, value) in [17, 23].into_iter().enumerate() {
            counters[at].increment(value);
            gauges[at].set(value as f64);
            histograms[at].record(value as f64);
        }
        let first = source.snapshot();
        assert_eq!(identity_values(&first, COUNTER), ["17", "23"]);
        assert_eq!(identity_values(&first, GAUGE), ["17", "23"]);
        assert_eq!(identity_values(&first, SUMMARY_SUM), ["17", "23"]);
        assert_eq!(identity_values(&first, SUMMARY_COUNT), ["1", "1"]);
        let summary = first.iter().find(|family| family.name == SUMMARY).unwrap();

        let expected_names: Vec<_> = [17, 23]
            .iter()
            .flat_map(|_| {
                std::iter::repeat_n(SUMMARY, QUANTILES.len()).chain([SUMMARY_SUM, SUMMARY_COUNT])
            })
            .collect();
        assert_eq!(
            summary
                .samples
                .iter()
                .map(|sample| sample.name.as_str())
                .collect::<Vec<_>>(),
            expected_names
        );
        let again = source.snapshot();
        assert_eq!(identity_values(&again, COUNTER), ["17", "23"]);
        assert_eq!(identity_values(&again, SUMMARY_COUNT), ["1", "1"]);
        std::thread::scope(|threads| {
            threads.spawn(|| counters[0].increment(5));
            threads.spawn(|| counters[1].increment(7));
        });
        gauges[0].set(41.0);
        histograms[1].record(7.0);
        let updated = source.snapshot();
        assert_eq!(identity_values(&updated, COUNTER), ["22", "30"]);
        assert_eq!(identity_values(&updated, GAUGE), ["23", "41"]);
        assert_eq!(identity_values(&updated, SUMMARY_SUM), ["17", "30"]);
        assert_eq!(identity_values(&updated, SUMMARY_COUNT), ["1", "2"]);
    }
}

#[test]
fn raw_duplicate_labels_keep_registry_identity_and_existing_display_semantics() {
    const COUNTER: &str = "busbar_identity_duplicate_labels";
    let source = identity_source();
    metrics::with_local_recorder(&source, || {
        let duplicate = vec![
            metrics::Label::new("key", "first"),
            metrics::Label::new("other", "middle"),
            metrics::Label::new("key", "last"),
        ];
        let displayed = vec![
            metrics::Label::new("key", "last"),
            metrics::Label::new("other", "middle"),
        ];
        metrics::counter!(COUNTER, duplicate.clone()).increment(5);
        metrics::counter!(COUNTER, displayed).increment(11);
        metrics::counter!(COUNTER, duplicate).increment(2);
    });
    let families = source.snapshot();
    assert_eq!(identity_values(&families, COUNTER), ["11", "7"]);
    let family = families
        .iter()
        .find(|family| family.name == COUNTER)
        .unwrap();
    let expected = vec![
        ("key".to_string(), "last".to_string()),
        ("other".to_string(), "middle".to_string()),
    ];
    assert!(
        family
            .samples
            .iter()
            .all(|sample| sample.labels == expected),
        "first label position and last duplicate value remain the presentation"
    );
}

#[test]
fn series_order_remains_presentation_order_with_deterministic_raw_ties() {
    const COUNTER: &str = "busbar_identity_order";
    let source = identity_source();

    metrics::with_local_recorder(&source, || {
        for (label, value) in [("\n", 19), ("\"", 17), ("\\\\", 23), ("\\", 31)] {
            metrics::counter!(COUNTER, "identity" => label).increment(value);
        }
    });
    for _ in [(), ()] {
        let families = source.snapshot();
        let family = families
            .iter()
            .find(|family| family.name == COUNTER)
            .unwrap();
        let values: Vec<_> = family
            .samples
            .iter()
            .map(|sample| sample.value.as_str())
            .collect();
        assert_eq!(values, ["17", "31", "23", "19"]);
    }
}
