use super::*;

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
    let recording: Vec<serde_json::Value> =
        serde_json::from_str(busbar_contract::abi::sdk::test_support::metrics::RECORDING)
            .expect("the kind's neutral recording");
    for record in recording {
        let name = record["name"].as_str().unwrap().to_owned();
        let labels: Vec<(String, String)> = record["labels"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_owned(),
                    pair[1].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        match record["op"].as_str().unwrap() {
            "describe" => {
                let help = record["help"].as_str().unwrap().to_owned();
                match record["kind"].as_str().unwrap() {
                    "counter" => metrics::describe_counter!(name, help),
                    "gauge" => metrics::describe_gauge!(name, help),
                    "histogram" => metrics::describe_histogram!(name, help),
                    other => panic!("unknown recording kind: {other}"),
                }
            }
            "counter" => {
                metrics::counter!(name, &labels).increment(record["value"].as_u64().unwrap())
            }
            "gauge" => metrics::gauge!(name, &labels).set(record["value"].as_f64().unwrap()),
            "histogram" => {
                metrics::histogram!(name, &labels).record(record["value"].as_f64().unwrap())
            }
            "register_histogram" => {
                let _registered = metrics::histogram!(name, &labels);
            }
            other => panic!("unknown recording operation: {other}"),
        }
    }
}

#[test]
fn source_preserves_the_kinds_raw_metric_vector() {
    let source: &'static Source = Box::leak(Box::new(Source::new(
        Duration::from_secs(20),
        std::num::NonZeroU32::new(3).unwrap(),
        Duration::from_secs(60),
    )));
    metrics::with_local_recorder(&source, workload);
    let expected: Vec<Family> =
        serde_json::from_str(busbar_contract::abi::sdk::test_support::metrics::SNAPSHOT)
            .expect("the kind's raw snapshot vector");
    let actual = source.snapshot();
    assert_eq!(ordered_families(&actual), ordered_families(&expected));
    assert_eq!(
        actual.len(),
        7,
        "all recorded metric families, including idle histogram"
    );
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
fn raw_label_values_keep_distinct_exported_series() {
    const COUNTER: &str = "busbar_identity_counter";
    const GAUGE: &str = "busbar_identity_gauge";
    const SUMMARY: &str = "busbar_identity_summary";
    const SUMMARY_SUM: &str = "busbar_identity_summary_sum";
    const SUMMARY_COUNT: &str = "busbar_identity_summary_count";
    for (left, right) in [("\\", "\\\\"), ("\"", "\\\"")] {
        assert_ne!(left, right);
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
        for name in [COUNTER, GAUGE, SUMMARY_SUM, SUMMARY_COUNT] {
            let mut identities: Vec<_> = first
                .iter()
                .flat_map(|family| &family.samples)
                .filter(|sample| sample.name == name)
                .map(|sample| {
                    let label = sample
                        .labels
                        .iter()
                        .find(|(key, _)| key == "identity")
                        .unwrap();
                    (label.1.clone(), sample.value.as_str())
                })
                .collect();
            identities.sort();
            let values = if name == SUMMARY_COUNT {
                ["1", "1"]
            } else {
                ["17", "23"]
            };
            let mut expected = vec![(left.to_owned(), values[0]), (right.to_owned(), values[1])];
            expected.sort();
            assert_eq!(identities, expected, "exported identity and value: {name}");
        }
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
fn series_order_uses_raw_labels_without_wire_encoding() {
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
        assert_eq!(values, ["19", "17", "31", "23"]);
    }
}
