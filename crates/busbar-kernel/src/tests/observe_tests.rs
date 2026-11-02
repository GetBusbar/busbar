// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_registered_code_resolves_to_the_catalogue_entry() {
    let d = crate::diagnostics::PLUGINS_DIR_FINGERPRINT_FAILED;
    let banner = format!("BUSBAR-{}", d.code);
    let got = resolve_code(crate::diagnostics::Catalogue::NEUTRAL, &banner)
        .expect("a registered code resolves");
    assert_eq!(got.code, d.code);
    assert_eq!(got.slug, d.slug);
}

#[test]
fn an_unregistered_code_is_refused() {
    assert!(resolve_code(crate::diagnostics::Catalogue::NEUTRAL, "BUSBAR-65535").is_none());
}

#[test]
fn a_malformed_code_is_refused() {
    for bad in [
        "",
        "1234",
        "BUSBAR1234",
        "busbar-1234",
        "BUSBAR-",
        "BUSBAR-abc",
        "BUSBAR-99999999",
        "BUSBAR-1234 ",
    ] {
        assert!(
            resolve_code(crate::diagnostics::Catalogue::NEUTRAL, bad).is_none(),
            "{bad} must not resolve"
        );
    }
}

#[test]
fn a_benign_recurring_condition_cannot_be_escalated() {
    use busbar_contract::abi::mechanism::observe::DiagLevel;
    for claimed in [
        DiagLevel::Error,
        DiagLevel::Warn,
        DiagLevel::Info,
        DiagLevel::Debug,
    ] {
        assert_eq!(
            clamp_level(claimed, crate::diagnostics::Severity::BenignRecurring),
            DiagLevel::Debug
        );
    }
}

#[test]
fn an_actionable_condition_keeps_the_reported_level() {
    use busbar_contract::abi::mechanism::observe::DiagLevel;
    for claimed in [DiagLevel::Error, DiagLevel::Warn, DiagLevel::Debug] {
        assert_eq!(
            clamp_level(claimed, crate::diagnostics::Severity::Actionable),
            claimed
        );
        assert_eq!(
            clamp_level(claimed, crate::diagnostics::Severity::Fatal),
            claimed
        );
    }
}

#[test]
fn the_provenance_label_cannot_be_shadowed() {
    let m: busbar_contract::hook_wire::reply::HookMetric =
        serde_json::from_value(serde_json::json!({
            "name": "x_total",
            "type": "counter",
            "labels": {"plugin": "somebody-else", "sink": "audit"}
        }))
        .expect("decode");
    let labels = labels_for(Some("the-real-name"), &m);
    let plugin_labels: Vec<_> = labels
        .iter()
        .filter(|l| l.key() == PLUGIN_LABEL)
        .map(|l| l.value())
        .collect();
    assert_eq!(plugin_labels, vec!["the-real-name"]);
    assert!(labels.iter().any(|l| l.key() == "sink"));
}

#[test]
fn a_plugins_own_labels_are_carried() {
    let m: busbar_contract::hook_wire::reply::HookMetric =
        serde_json::from_value(serde_json::json!({
            "name": "x_total",
            "type": "counter",
            "labels": {"sink": "audit", "reason": "full"}
        }))
        .expect("decode");
    let labels = labels_for(Some("p"), &m);
    assert_eq!(labels.len(), 3);
}

#[test]
fn observer_histograms_reserve_generated_quantiles_before_cardinality_and_snapshot() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    for (plugin, name, granted) in [
        ("quantile-third-party", "quantile_observer_seconds", false),
        (
            "quantile-first-party",
            "busbar_quantile_observer_seconds",
            true,
        ),
    ] {
        forget_cardinality(plugin);
        if granted {
            grant(plugin, &[SeriesDecl::new(name, "histogram")]);
        }
        let source: &'static crate::snapshot::Source =
            Box::leak(Box::new(crate::snapshot::Source::new(
                crate::snapshot::GAUGE_IDLE_TIMEOUT,
                crate::snapshot::SUMMARY_BUCKETS,
                crate::snapshot::GAUGE_IDLE_TIMEOUT,
            )));
        let entry = |dimension: &str, claim: usize| {
            serde_json::json!({
                "name": name, "type": "histogram", "value": 2,
                "labels": {"plugin": format!("forged-{claim}"),
                    "quantile": claim.to_string(), "sink": dimension}
            })
        };
        metrics::with_local_recorder(&source, || {
            let observe = |metric| {
                OBSERVER.observe(
                    &*TEST_GRANTS,
                    plugin,
                    busbar_contract::abi::mechanism::kind::EXPORT,
                    &[metric],
                    &[],
                );
            };

            for claim in 0..=MAX_LABEL_SETS_PER_SERIES {
                observe(entry("audit", claim));
            }
            for dimension in 1..MAX_LABEL_SETS_PER_SERIES {
                observe(entry(&dimension.to_string(), 0));
            }
            observe(entry("over-budget", 0));
            observe(entry("audit", 0));
        });
        let families = source.snapshot();
        let family = families.iter().find(|family| family.name == name).unwrap();
        assert_eq!(
            family.kind,
            busbar_contract::abi::export::SCRAPE_KIND_SUMMARY
        );
        assert_eq!(family.samples.len(), MAX_LABEL_SETS_PER_SERIES * 9);
        for sample in &family.samples {
            let keys: std::collections::HashSet<_> =
                sample.labels.iter().map(|(key, _)| key).collect();
            assert_eq!(keys.len(), sample.labels.len(), "{sample:?}");
            let provenance: Vec<_> = sample
                .labels
                .iter()
                .filter(|(key, _)| key == PLUGIN_LABEL)
                .map(|(_, value)| value.as_str())
                .collect();
            assert_eq!(provenance, if granted { vec![] } else { vec![plugin] });
            assert!(!sample
                .labels
                .iter()
                .any(|(_, value)| value == "over-budget"));
            let quantiles: Vec<_> = sample
                .labels
                .iter()
                .filter(|(key, _)| key == super::super::source::QUANTILE_LABEL)
                .map(|(_, value)| value.as_str())
                .collect();
            if sample.name == name {
                assert_eq!(quantiles.len(), 1, "{sample:?}");
                assert!(["0", "0.5", "0.9", "0.95", "0.99", "0.999", "1"].contains(&quantiles[0]));

                let value: f64 = sample.value.parse().expect("a numeric quantile");
                assert!((value - 2.0).abs() <= 2.0 * 0.0001, "{sample:?}");
            } else {
                assert!(quantiles.is_empty(), "{sample:?}");
                let audit = sample
                    .labels
                    .iter()
                    .any(|(key, value)| key == "sink" && value == "audit");
                let count = if audit {
                    MAX_LABEL_SETS_PER_SERIES + 2
                } else {
                    1
                };
                let value = if sample.name == format!("{name}_count") {
                    count
                } else {
                    assert_eq!(sample.name, format!("{name}_sum"));
                    count * 2
                };
                assert_eq!(sample.value, value.to_string());
            }
        }
        forget_cardinality(plugin);
    }
}

#[test]
fn observer_counters_and_gauges_keep_their_quantile_dimension() {
    let plugin = "quantile-scalar-control";
    forget_cardinality(plugin);
    let source: &'static crate::snapshot::Source =
        Box::leak(Box::new(crate::snapshot::Source::new(
            crate::snapshot::GAUGE_IDLE_TIMEOUT,
            crate::snapshot::SUMMARY_BUCKETS,
            crate::snapshot::GAUGE_IDLE_TIMEOUT,
        )));
    metrics::with_local_recorder(&source, || {
        for kind in ["counter", "gauge"] {
            OBSERVER.observe(
                &*TEST_GRANTS,
                plugin,
                busbar_contract::abi::mechanism::kind::EXPORT,
                &[
                    serde_json::json!({"name": format!("quantile_control_{kind}"),
                    "type": kind, "value": 3, "labels": {"quantile": "reported"}}),
                ],
                &[],
            );
        }
    });
    let families = source.snapshot();
    assert_eq!(families.len(), 2);
    for family in families {
        assert_eq!(family.samples.len(), 1);
        assert_eq!(family.samples[0].value, "3");
        assert_eq!(
            family.samples[0].labels,
            [
                (PLUGIN_LABEL.to_string(), plugin.to_string()),
                ("quantile".to_string(), "reported".to_string()),
            ]
        );
    }
    forget_cardinality(plugin);
}

/// A THREAD-LOCAL capture of what the fold REGISTERS — every series key it asked a recorder for,
/// rendered `name{k=v,…}` — so the fold runs for real under `metrics::with_local_recorder` without
/// touching the process-global recorder no unit test may install into.
#[derive(Default)]
struct Registered(std::sync::Mutex<Vec<String>>);

impl Registered {
    fn note(&self, key: &metrics::Key) {
        let labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        let mut seen = self.0.lock().unwrap_or_else(|e| e.into_inner());
        seen.push(format!("{}{{{}}}", key.name(), labels.join(",")));
    }
}

impl metrics::Recorder for Registered {
    fn describe_counter(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_gauge(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn describe_histogram(
        &self,
        _: metrics::KeyName,
        _: Option<metrics::Unit>,
        _: metrics::SharedString,
    ) {
    }
    fn register_counter(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Counter {
        self.note(key);
        metrics::Counter::noop()
    }
    fn register_gauge(&self, key: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        self.note(key);
        metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        key: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        self.note(key);
        metrics::Histogram::noop()
    }
}

#[test]
fn a_granted_first_party_series_renders_as_declared_and_nothing_else_is_granted() {
    use busbar_contract::abi::mechanism::observe::SeriesDecl;
    let declared = [SeriesDecl::new("busbar_s1_fold_total", "counter")];
    grant("s1-first-party", &declared);
    let entry =
        |name: &str, kind: &str| serde_json::json!({"name": name, "type": kind, "value": 1});
    let recorder = Registered::default();
    metrics::with_local_recorder(&recorder, || {
        fold_metrics(
            &*TEST_GRANTS,
            "s1-first-party",
            &[
                entry("busbar_s1_fold_total", "counter"),
                entry("busbar_s1_undeclared_total", "counter"),
                entry("busbar_s1_fold_total", "gauge"),
                entry("s1_own_total", "counter"),
            ],
        );
        fold_metrics(
            &*TEST_GRANTS,
            "s1-third-party",
            &[entry("busbar_s1_fold_total", "counter")],
        );
    });
    let seen = recorder.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
    assert_eq!(
        seen,
        vec![
            "busbar_s1_fold_total{}".to_string(),
            "s1_own_total{plugin=s1-first-party}".to_string(),
        ]
    );
}

#[test]
fn a_reported_metric_name_keeps_one_type_across_plugins_and_label_sets() {
    let name = "fold_type_custody_total";
    let first = "fold-type-owner";
    let second = "fold-type-other";
    forget_cardinality(first);
    forget_cardinality(second);
    let entry = |kind: &str, dimension: &str| {
        serde_json::json!({"name": name, "type": kind, "value": 2,
            "labels": {"dimension": dimension}})
    };
    let recorder = Registered::default();
    metrics::with_local_recorder(&recorder, || {
        fold_metrics(&*TEST_GRANTS, first, &[entry("counter", "first")]);
        fold_metrics(&*TEST_GRANTS, first, &[entry("gauge", "first")]);
        fold_metrics(&*TEST_GRANTS, first, &[entry("histogram", "second")]);
        fold_metrics(&*TEST_GRANTS, second, &[entry("gauge", "third")]);
        fold_metrics(&*TEST_GRANTS, second, &[entry("counter", "third")]);
        fold_metrics(&*TEST_GRANTS, first, &[entry("counter", "first")]);
    });
    let seen = recorder.0.lock().unwrap_or_else(|e| e.into_inner()).clone();
    forget_cardinality(first);
    forget_cardinality(second);
    assert_eq!(
        seen,
        [
            "fold_type_custody_total{plugin=fold-type-owner,dimension=first}",
            "fold_type_custody_total{plugin=fold-type-other,dimension=third}",
            "fold_type_custody_total{plugin=fold-type-owner,dimension=first}",
        ]
    );
}

#[test]
fn the_reserved_namespace_is_refused() {
    let recorder = Registered::default();
    metrics::with_local_recorder(&recorder, || {
        fold_metrics(
            &*TEST_GRANTS,
            "reserved-namespace-witness",
            &[
                serde_json::json!({"name": "busbar_file_logs_rotated_total", "type": "counter", "value": 1}),
                serde_json::json!({"name": "file_logs_rotated_total", "type": "counter", "value": 1}),
            ],
        );
    });
    assert_eq!(
        *recorder.0.lock().unwrap_or_else(|e| e.into_inner()),
        vec!["file_logs_rotated_total{plugin=reserved-namespace-witness}".to_string()]
    );
}

#[test]
fn the_fold_validates_through_the_one_hook_validator() {
    let raw = vec![
        // Valid.
        serde_json::json!({"name": "good_total", "type": "counter", "value": 1}),
        // Invalid NAME charset — dropped whole.
        serde_json::json!({"name": "Bad-Name", "type": "counter", "value": 1}),
        // Unknown TYPE — dropped whole.
        serde_json::json!({"name": "other_total", "type": "summary", "value": 1}),
        // Non-finite value cannot even be expressed in JSON, so the validator's finiteness rule is
        // exercised by its own tests; here the missing `type` stands for a structurally bad entry.
        serde_json::json!({"name": "no_type_total"}),
    ];
    let kept = busbar_contract::hook_wire::reply::parse_status_metrics(&raw);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].name, "good_total");
}

#[test]
fn the_cold_lane_bounds_series_cardinality() {
    const PLUGIN: &str = "cold-cardinality-plugin";
    forget_cardinality(PLUGIN);

    for _ in 0..(MAX_SERIES_PER_PLUGIN * 4) {
        assert!(admits_cardinality(PLUGIN, "steady_total", 0));
    }

    let mut admitted = 1usize;
    for i in 0..(MAX_SERIES_PER_PLUGIN * 2) {
        if admits_cardinality(PLUGIN, &format!("churn_{i}_total"), 0) {
            admitted += 1;
        }
    }
    assert_eq!(admitted, MAX_SERIES_PER_PLUGIN);

    assert!(admits_cardinality(PLUGIN, "steady_total", 0));
}

#[test]
fn the_cold_lane_bounds_label_set_cardinality() {
    const PLUGIN: &str = "cold-label-plugin";
    forget_cardinality(PLUGIN);
    let mut admitted = 0usize;
    for i in 0..(MAX_LABEL_SETS_PER_SERIES * 3) {
        let labels: std::collections::BTreeMap<String, String> =
            [("request_id".to_string(), i.to_string())]
                .into_iter()
                .collect();
        if admits_cardinality(PLUGIN, "one_series_total", fingerprint_pairs(Some(&labels))) {
            admitted += 1;
        }
    }
    assert_eq!(
        admitted, MAX_LABEL_SETS_PER_SERIES,
        "labelling by request id must hit a ceiling, not explode the registry"
    );
}

#[test]
fn an_identical_label_set_fingerprints_identically() {
    let a: std::collections::BTreeMap<String, String> = [
        ("model".to_string(), "m".to_string()),
        ("strategy".to_string(), "dedupe".to_string()),
    ]
    .into_iter()
    .collect();
    let b: std::collections::BTreeMap<String, String> = [
        ("strategy".to_string(), "dedupe".to_string()),
        ("model".to_string(), "m".to_string()),
    ]
    .into_iter()
    .collect();
    assert_eq!(fingerprint_pairs(Some(&a)), fingerprint_pairs(Some(&b)));

    let c: std::collections::BTreeMap<String, String> =
        [("model".to_string(), "other".to_string())]
            .into_iter()
            .collect();
    assert_ne!(fingerprint_pairs(Some(&a)), fingerprint_pairs(Some(&c)));

    assert_ne!(fingerprint_pairs(None), fingerprint_pairs(Some(&a)));
}

#[test]
fn one_plugins_flood_does_not_spend_anothers_budget() {
    const NOISY: &str = "noisy-plugin";
    const QUIET: &str = "quiet-plugin";
    forget_cardinality(NOISY);
    forget_cardinality(QUIET);
    for i in 0..(MAX_SERIES_PER_PLUGIN * 2) {
        admits_cardinality(NOISY, &format!("n_{i}_total"), 0);
    }
    assert!(!admits_cardinality(NOISY, "one_more_total", 0));
    assert!(admits_cardinality(QUIET, "polite_total", 0));
}

#[test]
fn hook_envelope_metrics_are_carried_but_not_folded() {
    let entries = vec![
        serde_json::json!({"name": "hook_freeze_control_total", "type": "counter", "value": 1}),
    ];
    let recorder = Registered::default();
    metrics::with_local_recorder(&recorder, || {
        OBSERVER.observe(
            &*TEST_GRANTS,
            "hook-freeze-witness",
            busbar_contract::abi::mechanism::kind::HOOK,
            &entries,
            &[],
        );
        assert!(
            recorder
                .0
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "the hook's envelope metrics must not be registered"
        );
        OBSERVER.observe(
            &*TEST_GRANTS,
            "export-freeze-control",
            busbar_contract::abi::mechanism::kind::EXPORT,
            &entries,
            &[],
        );
    });
    assert_eq!(
        *recorder.0.lock().unwrap_or_else(|e| e.into_inner()),
        vec!["hook_freeze_control_total{plugin=export-freeze-control}".to_string()]
    );
}

#[test]
fn a_hooks_diagnostic_is_emitted_while_its_metrics_stay_frozen() {
    use std::io::Write;
    #[derive(Clone, Default)]
    struct HookLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for HookLog {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let d = crate::diagnostics::PLUGINS_DIR_FINGERPRINT_FAILED;
    let banner = format!("BUSBAR-{}", d.code);
    let cap = HookLog::default();
    let writer = cap.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        OBSERVER.observe(
            &*TEST_GRANTS,
            "some-hook",
            busbar_contract::abi::mechanism::kind::HOOK,
            &[serde_json::json!({"name": "x_total", "type": "counter", "value": 1})],
            &[serde_json::json!({
                "code": banner,
                "message": "hook-raised-condition-556",
            })],
        );
    });
    let text = String::from_utf8(cap.0.lock().unwrap().clone()).unwrap();
    assert!(
        text.contains("hook-raised-condition-556"),
        "a hook's registered diagnostic must reach the operator's log; captured: {:?}",
        text
    );
}

#[test]
fn a_first_party_plugins_diagnostic_is_written_as_the_hosts_own_line() {
    use std::io::Write;
    #[derive(Clone, Default)]
    struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let d = *crate::diagnostics::REGISTRY
        .iter()
        .find(|d| d.severity == crate::diagnostics::Severity::Actionable)
        .expect("an actionable code");
    grant("k9c-first-party", &[]);
    let entry = serde_json::to_value(
        busbar_contract::abi::mechanism::observe::PluginDiagnostic::warn(
            format!("BUSBAR-{}", d.code),
            "it broke",
        )
        .field("webhook_url", "\"https://a/\"")
        .field("status", "503"),
    )
    .unwrap();
    let buf = Buf::default();
    let writer = buf.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let url = String::from("https://a/");
        crate::diagnostics::diag_warn!(d, webhook_url = url, status = 503u16, "it broke");
        OBSERVER.observe(
            &*TEST_GRANTS,
            "k9c-first-party",
            "export",
            &[],
            std::slice::from_ref(&entry),
        );
        OBSERVER.observe(&*TEST_GRANTS, "k9c-third-party", "export", &[], &[entry]);
    });
    let text = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "{text}");
    assert_eq!(lines[0], lines[1], "the first-party line is the host's own");
    assert!(lines[2].contains("plugin=k9c-third-party"), "{text}");
}

/// What the loader granted at open, as these tests state it: the composition root hands the
/// loader's own answers to every observe call in a booted process; these tests hand this one. A plugin not named
/// here (a third party) is granted nothing.
#[derive(Default)]
struct TestGrants(std::sync::Mutex<std::collections::HashMap<String, Vec<(String, String)>>>);

impl Grants for TestGrants {
    fn first_party(&self, plugin: &str) -> bool {
        self.0.lock().unwrap().contains_key(plugin)
    }
    fn first_party_series(&self, plugin: &str, name: &str, kind: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(plugin)
            .is_some_and(|s| s.iter().any(|(n, k)| n == name && k == kind))
    }
}

const OBSERVER: KernelPluginObserver =
    KernelPluginObserver::lent(crate::diagnostics::Catalogue::NEUTRAL);

static TEST_GRANTS: std::sync::LazyLock<TestGrants> = std::sync::LazyLock::new(TestGrants::default);

fn grant(plugin: &str, declared: &[busbar_contract::abi::mechanism::observe::SeriesDecl]) {
    TEST_GRANTS.0.lock().unwrap().insert(
        plugin.to_string(),
        declared
            .iter()
            .map(|d| (d.name.clone(), d.kind.clone()))
            .collect(),
    );
}

#[test]
fn two_observers_lent_two_catalogues_each_emit_only_their_own_roots_codes() {
    use std::io::Write;
    #[derive(Clone, Default)]
    struct Buf(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    static OWN: crate::diagnostics::Diagnostic = crate::diagnostics::Diagnostic {
        code: 7995,
        class: crate::diagnostics::Class::Plane,
        slug: "lent-observer-own",
        title: "A plane-contributed condition",
        severity: crate::diagnostics::Severity::Actionable,
        summary: "A test plane's own condition, folded into one root's catalogue only.",
        action: "None: a test entry.",
        since: "1.6.0",
        retired: false,
    };
    let folded =
        KernelPluginObserver::lent(crate::diagnostics::Catalogue::lent(Box::leak(Box::new([
            &OWN,
        ]))));
    let other = KernelPluginObserver::lent(crate::diagnostics::Catalogue::lent(&[]));
    grant("lent-observer-plugin", &[]);
    let entry = serde_json::to_value(
        busbar_contract::abi::mechanism::observe::PluginDiagnostic::warn(
            "BUSBAR-7995".to_string(),
            "the plane's own condition",
        ),
    )
    .unwrap();
    let emitted = |observer: KernelPluginObserver| {
        let buf = Buf::default();
        let writer = buf.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || writer.clone())
            .with_ansi(false)
            .without_time()
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            observer.observe(
                &*TEST_GRANTS,
                "lent-observer-plugin",
                "export",
                &[],
                std::slice::from_ref(&entry),
            );
        });
        let bytes = buf.0.lock().unwrap().clone();
        String::from_utf8(bytes).unwrap()
    };
    let own = emitted(folded);
    assert!(
        own.contains("BUSBAR-7995"),
        "the folding root's observer emits its code: {own}"
    );
    let theirs = emitted(other);
    assert!(
        theirs.is_empty(),
        "the other root's observer holds no such code: {theirs}"
    );
}
