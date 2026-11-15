// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Every counted `busbar_plugin_text_cut_total{plugin,field}` value, by its (plugin, field).
type Counters = Arc<Mutex<HashMap<(String, String), Arc<AtomicU64>>>>;

/// What a run under [`probe`] logged and counted: the formatted tracing lines and every
/// `busbar_plugin_text_cut_total{plugin,field}` value.
#[derive(Clone, Default)]
pub(crate) struct Probe {
    log: Arc<Mutex<Vec<u8>>>,
    counters: Counters,
}

impl std::io::Write for Probe {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.log.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Probe {
    /// Every logged line.
    pub(crate) fn lines(&self) -> Vec<String> {
        String::from_utf8(self.log.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The logged lines carrying BUSBAR-6013.
    pub(crate) fn cut_warns(&self) -> Vec<String> {
        self.lines()
            .into_iter()
            .filter(|l| l.contains("diag=BUSBAR-6013"))
            .collect()
    }

    /// `busbar_plugin_text_cut_total{plugin, field}`.
    pub(crate) fn counter(&self, plugin: &str, field: TextField) -> u64 {
        self.counters
            .lock()
            .unwrap()
            .get(&(plugin.to_string(), field.as_str().to_string()))
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }
}

impl metrics::Recorder for Probe {
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
        if key.name() != crate::snapshot::PLUGIN_TEXT_CUT_TOTAL {
            return metrics::Counter::noop();
        }
        let label = |name: &str| {
            key.labels()
                .find(|l| l.key() == name)
                .map(|l| l.value().to_string())
                .unwrap_or_default()
        };
        let cell = Arc::clone(
            self.counters
                .lock()
                .unwrap()
                .entry((label("plugin"), label("field")))
                .or_default(),
        );
        metrics::Counter::from_arc(cell)
    }
    fn register_gauge(&self, _: &metrics::Key, _: &metrics::Metadata<'_>) -> metrics::Gauge {
        metrics::Gauge::noop()
    }
    fn register_histogram(
        &self,
        _: &metrics::Key,
        _: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

/// Runs `f` with this thread's tracing and metrics captured into a fresh [`Probe`].
pub(crate) fn probe<T>(f: impl FnOnce() -> T) -> (T, Probe) {
    let probe = Probe::default();
    let writer = probe.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .finish();
    let out = tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        metrics::with_local_recorder(&probe, f)
    });
    (out, probe)
}

#[test]
fn hook_status_cuts_are_reported_once_per_field_and_counted_every_time() {
    // T3: one #[test] for every tracing case (the latch is process-global; names are unique).
    let euro = "€".repeat(400);
    let raw = [serde_json::json!({
        "name": "ok_total", "type": "counter", "value": 1.0,
        "help": euro, "label": euro, "unit": euro
    })];

    let (first, seen) = probe(|| parse_hook_status_metrics("acme-status", &raw));
    assert_eq!(first.len(), 1);
    assert_eq!(
        first[0].help.as_deref(),
        Some("€".repeat(MAX_METRIC_HELP_CHARS).as_str())
    );
    assert_eq!(
        first[0].label.as_deref(),
        Some("€".repeat(MAX_METRIC_LABEL_CHARS).as_str())
    );
    assert_eq!(
        first[0].unit.as_deref(),
        Some("€".repeat(MAX_METRIC_UNIT_CHARS).as_str())
    );
    let warns = seen.cut_warns();
    assert_eq!(warns.len(), 3, "one BUSBAR-6013 per cut field: {warns:#?}");
    for (field, cap) in [
        (TextField::MetricHelp, MAX_METRIC_HELP_CHARS),
        (TextField::MetricLabel, MAX_METRIC_LABEL_CHARS),
        (TextField::MetricUnit, MAX_METRIC_UNIT_CHARS),
    ] {
        let line = warns
            .iter()
            .find(|l| l.contains(&format!("field={}", field.as_str())))
            .unwrap_or_else(|| panic!("no warning for {}: {warns:#?}", field.as_str()));
        assert!(line.contains("plugin=acme-status"), "{line}");
        assert!(line.contains(&format!("cap={cap}")), "{line}");
        assert!(line.contains("sanitised_chars=400"), "{line}");
        assert_eq!(seen.counter("acme-status", field), 1);
    }

    let (again, seen) = probe(|| parse_hook_status_metrics("acme-status", &raw));
    assert_eq!(again[0].help, first[0].help, "the bytes do not change");
    assert!(
        seen.cut_warns().is_empty(),
        "the latch holds: {:#?}",
        seen.cut_warns()
    );
    assert_eq!(seen.counter("acme-status", TextField::MetricHelp), 1);

    let (reported, seen) = probe(|| {
        [
            report("acme-report", TextField::DiagField, 64, 3, 90),
            report("acme-report", TextField::DiagField, 64, 2, 70),
            report("acme-report", TextField::DiagMessage, 300, 1, 301),
        ]
    });
    assert_eq!(
        reported,
        [Reported::Warned, Reported::Counted, Reported::Warned],
        "the latch is per (plugin, field)"
    );
    assert_eq!(seen.counter("acme-report", TextField::DiagField), 5);
    assert_eq!(seen.counter("acme-report", TextField::DiagMessage), 1);
    assert_eq!(seen.cut_warns().len(), 2);
}
