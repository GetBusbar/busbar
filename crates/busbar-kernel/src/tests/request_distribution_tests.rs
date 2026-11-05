// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn key() -> Key {
    Key::from_parts(
        crate::telemetry::REQUEST_PHASE_DURATION,
        vec![
            metrics::Label::new("plane", "synthetic"),
            metrics::Label::new("phase", "MountedResponseReady"),
            metrics::Label::new("pool", "unresolved"),
            metrics::Label::new("ingress_protocol", "test-wire"),
        ],
    )
}

fn outcome_key(outcome: &'static str) -> Key {
    let mut labels: Vec<_> = key().labels().cloned().collect();
    labels.push(metrics::Label::new("outcome", outcome));
    Key::from_parts(crate::telemetry::REQUEST_PHASE_DURATION, labels)
}

fn make_source() -> &'static Source {
    Box::leak(Box::new(Source::new(
        Duration::from_millis(1),
        std::num::NonZeroU32::new(1).unwrap(),
        Duration::from_secs(60),
    )))
}

fn value(families: &[Family], name: &str) -> u64 {
    families
        .iter()
        .flat_map(|family| &family.samples)
        .filter(|sample| sample.name == name)
        .map(|sample| sample.value.parse::<u64>().unwrap())
        .sum()
}

#[test]
fn exclusive_bins_include_upper_edge_and_never_double_count() {
    let mut distribution = RequestDistribution::default();
    distribution.add(0.0, "ok").unwrap();
    for (i, bound) in REQUEST_BOUNDS_MS.iter().enumerate() {
        distribution.add(*bound as f64 / 1000.0, "ok").unwrap();
        assert_eq!(distribution.bins[i], if i == 0 { 2 } else { 1 });
    }
    distribution.add(120.000_001, "ok").unwrap();
    assert_eq!(distribution.bins[15], 1);
    assert_eq!(distribution.count, 17);
    assert_eq!(distribution.bins.iter().sum::<u64>(), distribution.count);
    assert_eq!(
        distribution.sum_us,
        REQUEST_BOUNDS_MS.iter().sum::<u64>() * 1000 + 120_000_001
    );
}

#[test]
fn conversion_and_overflow_refuse_the_whole_observation() {
    let mut distribution = RequestDistribution::default();
    distribution.add(0.000_001_9, "ok").unwrap();
    assert_eq!(distribution.sum_us, 1);
    for seconds in [
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
        -1.0,
        u64::MAX as f64 / 1_000_000.0,
    ] {
        assert_eq!(distribution.add(seconds, "ok"), Err(0));
    }
    assert_eq!(distribution.count, 1);
    assert_eq!(distribution.bins.iter().sum::<u64>(), 1);
    distribution.sum_us = u64::MAX;
    assert_eq!(distribution.add(0.001, "ok"), Err(1));
    assert_eq!(distribution.count, 1);
    assert_eq!(distribution.bins.iter().sum::<u64>(), 1);
    distribution.count = u64::MAX;
    assert_eq!(distribution.add(0.0, "ok"), Err(1));
    assert_eq!(distribution.bins.iter().sum::<u64>(), 1);
}

#[test]
fn integer_samples_are_exact_above_f64_integer_precision() {
    let source = make_source();
    let count = (1u64 << 53) + 1;
    let mut bins = [0; 16];
    bins[0] = count;
    lock(&source.request_distributions).series.insert(
        key(),
        RequestDistribution {
            count,
            errors: count,
            client_errors: 0,
            sum_us: count,
            bins,
        },
    );
    let snapshot = source.snapshot();
    assert_eq!(value(&snapshot, REQUEST_COUNT), count);
    assert_eq!(value(&snapshot, REQUEST_SUM), count);
    assert_eq!(value(&snapshot, REQUEST_BIN), count);
    assert_eq!(value(&snapshot, REQUEST_ERRORS), count);
    assert_eq!(value(&snapshot, REQUEST_CLIENT_ERRORS), 0);
}

#[test]
fn snapshots_remain_cumulative_across_drains_and_expired_summary_windows() {
    let source = make_source();
    let histogram = source.register_histogram(
        &outcome_key("ok"),
        &metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!())),
    );
    histogram.record(0.001);
    let before = source.snapshot();
    let labels = &before
        .iter()
        .find(|f| f.name == REQUEST_COUNT)
        .unwrap()
        .samples[0]
        .labels;
    let nonce = labels
        .iter()
        .find(|(name, _)| name == "process_boot_nonce")
        .unwrap();
    assert_eq!(nonce.1.len(), 32);
    assert_eq!(Some(nonce.1.as_str()), process_boot_nonce());
    assert_eq!(make_source().process_boot_nonce, source.process_boot_nonce);
    std::thread::sleep(Duration::from_millis(3));
    histogram.record(0.005);
    source.drain();
    let after = source.snapshot();
    assert_eq!(value(&before, REQUEST_COUNT), 1);
    assert_eq!(value(&after, REQUEST_COUNT), 2);
    assert_eq!(value(&after, REQUEST_SUM), 6000);
    assert_eq!(value(&after, REQUEST_BIN), 2);
    assert_eq!(value(&source.snapshot(), REQUEST_COUNT), 2);
    assert!(!after
        .iter()
        .any(|family| family.name == crate::telemetry::REQUEST_PHASE_DURATION));
    assert_eq!(
        after
            .iter()
            .find(|f| f.name == REQUEST_BIN)
            .unwrap()
            .samples
            .len(),
        16
    );
}

#[test]
fn concurrent_recording_and_snapshots_keep_count_sum_and_bins_together() {
    let source = make_source();
    let histogram = source.register_histogram(
        &outcome_key("error"),
        &metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!())),
    );
    let writer = std::thread::spawn(move || {
        for _ in 0..2000 {
            histogram.record(0.001);
        }
    });
    for _ in 0..20 {
        let snapshot = source.snapshot();
        let count = value(&snapshot, REQUEST_COUNT);
        assert_eq!(value(&snapshot, REQUEST_BIN), count);
        assert_eq!(value(&snapshot, REQUEST_ERRORS), count);
        assert_eq!(value(&snapshot, REQUEST_CLIENT_ERRORS), 0);
        assert_eq!(value(&snapshot, REQUEST_SUM), count * 1000);
    }
    writer.join().unwrap();
    assert_eq!(value(&source.snapshot(), REQUEST_COUNT), 2000);
}

#[test]
fn missing_nonce_capacity_and_invalid_samples_have_bounded_drop_reasons() {
    let mut state = RequestDistributions::default();
    state.add(&key(), 1.0, "ok", false);
    assert!(state.series.is_empty());
    assert_eq!(state.dropped[3], 1);
    state.add(&key(), f64::NAN, "ok", true);
    assert_eq!(state.dropped[0], 1);
    for i in 1..REQUEST_SERIES_LIMIT {
        let key = Key::from_parts(
            crate::telemetry::REQUEST_PHASE_DURATION,
            vec![metrics::Label::new("pool", i.to_string())],
        );
        state.add(&key, 0.0, "ok", true);
    }
    state.add(
        &Key::from_name(crate::telemetry::REQUEST_PHASE_DURATION),
        0.0,
        "ok",
        true,
    );
    assert_eq!(state.series.len(), REQUEST_SERIES_LIMIT);
    assert_eq!(state.dropped[2], 1);
    let mut out = Building::new();
    state.put(&mut out, None);
    assert_eq!(out.len(), 1);
    assert_eq!(out.values().next().unwrap().len(), 3);
}

#[test]
fn bounded_projection_selects_stable_labels_and_reports_all_omissions() {
    let source = make_source();
    for i in (0..40).rev() {
        let key = Key::from_parts(
            crate::telemetry::REQUEST_PHASE_DURATION,
            vec![
                metrics::Label::new("plane", "synthetic"),
                metrics::Label::new("phase", "MountedResponseReady"),
                metrics::Label::new("pool", format!("pool-{i:02}")),
                metrics::Label::new("ingress_protocol", "test-wire"),
            ],
        );
        lock(&source.request_distributions).add(&key, 0.001, "ok", true);
    }
    let oversized = Key::from_parts(
        crate::telemetry::REQUEST_PHASE_DURATION,
        vec![
            metrics::Label::new("plane", "synthetic"),
            metrics::Label::new("phase", "MountedResponseReady"),
            metrics::Label::new("pool", "x".repeat(257)),
            metrics::Label::new("ingress_protocol", "test-wire"),
        ],
    );
    lock(&source.request_distributions).add(&oversized, 0.001, "ok", true);
    let snapshot = source.request_snapshot(usize::MAX).unwrap();
    assert_eq!(snapshot.identities.len(), 32);
    assert_eq!(snapshot.omitted_identities, 9);
    assert_eq!(snapshot.identities[0].pool, "pool-00");
    assert_eq!(snapshot.identities[31].pool, "pool-31");
    for identity in &snapshot.identities {
        assert_eq!(identity.count, identity.bins.iter().sum::<u64>());
        assert_eq!(identity.sum_us, identity.count * 1000);
    }
    assert_eq!(snapshot.process_boot_nonce, process_boot_nonce().unwrap());
    let later = source.request_snapshot(1).unwrap();
    assert_eq!(later.identities.len(), 1);
    assert_eq!(later.omitted_identities, 40);
    assert!(later.uptime_ms >= snapshot.uptime_ms);
    let empty = source.request_snapshot(0).unwrap();
    assert!(empty.identities.is_empty());
    assert_eq!(empty.omitted_identities, 41);
}

#[test]
fn outcomes_fold_into_one_cohort_and_refused_events_do_not_increment_errors() {
    let source = make_source();
    for (outcome, count) in [
        ("ok", 1),
        ("exhausted", 2),
        ("client_error", 3),
        ("error", 4),
    ] {
        let histogram = source.register_histogram(
            &outcome_key(outcome),
            &metrics::Metadata::new(module_path!(), metrics::Level::INFO, Some(module_path!())),
        );
        for _ in 0..count {
            histogram.record(0.001);
        }
        histogram.record(f64::NAN);
    }
    let before_capture = unix_millis(SystemTime::now()).unwrap();
    let snapshot = source.request_snapshot(32).unwrap();
    let after_capture = unix_millis(SystemTime::now()).unwrap();
    assert!((before_capture..=after_capture).contains(&snapshot.captured_at_unix_ms));
    assert_eq!(snapshot.identities.len(), 1);
    let identity = &snapshot.identities[0];
    assert_eq!(
        (identity.count, identity.errors, identity.client_errors),
        (10, 6, 3)
    );
    assert_eq!(identity.sum_us, 10_000);
    assert_eq!(identity.bins.iter().sum::<u64>(), 10);
    assert_eq!(snapshot.dropped[0], 4);
    let mut d = RequestDistribution {
        sum_us: u64::MAX,
        ..RequestDistribution::default()
    };
    assert_eq!(d.add(1.0, "error"), Err(1));
    assert_eq!((d.count, d.errors, d.client_errors), (0, 0, 0));
    assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_millis(1)), None);
    assert_eq!(unix_millis(UNIX_EPOCH), Some(0));
}
