// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
struct Probe {
    log: Arc<Mutex<Vec<u8>>>,
    cuts: Arc<Mutex<HashMap<String, Arc<AtomicU64>>>>,
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
    fn cut_warns(&self) -> Vec<String> {
        String::from_utf8(self.log.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|l| l.contains("diag=BUSBAR-6013"))
            .map(str::to_string)
            .collect()
    }
    fn total(&self) -> u64 {
        self.cuts
            .lock()
            .unwrap()
            .values()
            .map(|c| c.load(Ordering::Relaxed))
            .sum()
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
        if key.name() != busbar_kernel::snapshot::PLUGIN_TEXT_CUT_TOTAL {
            return metrics::Counter::noop();
        }
        let labels: Vec<String> = key
            .labels()
            .map(|l| format!("{}={}", l.key(), l.value()))
            .collect();
        let cell = Arc::clone(
            self.cuts
                .lock()
                .unwrap()
                .entry(labels.join(","))
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

#[test]
fn a_third_party_plugins_cuts_warn_once_per_field_naming_it_and_count_every_time() {
    // T2, root half: every tracing case in one #[test]; the plugin name is unique.
    let plugin = "acme-store";
    let d = *busbar_kernel::diagnostics::REGISTRY
        .iter()
        .find(|d| d.severity == busbar_kernel::diagnostics::Severity::Actionable)
        .expect("an actionable code");
    let metrics = [serde_json::json!({
        "name": "acme_cut_total", "type": "counter", "value": 1,
        "help": "h".repeat(300), "label": "b".repeat(100), "unit": "u".repeat(30),
        "labels": {"k": "v".repeat(100)},
    })];
    let diagnostics = [serde_json::to_value(
        busbar_contract::abi::mechanism::observe::PluginDiagnostic::warn(
            format!("BUSBAR-{}", d.code),
            "m".repeat(400),
        )
        .field("f", "w".repeat(100)),
    )
    .unwrap()];
    let observer = KernelPluginObserver::lent(busbar_kernel::diagnostics::Catalogue::NEUTRAL);
    let owner = ObservationOwner::default();
    let probe = Probe::default();
    let writer = probe.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_target(false)
        .with_ansi(false)
        .without_time()
        .finish();
    let observe = || {
        observer.observe(
            &LoaderGrants {
                plugin,
                owner: &owner,
            },
            &Output(plugin, KindCode::Store.word()),
            KindCode::Store,
            &metrics,
            &diagnostics,
        );
    };
    tracing::subscriber::with_default(subscriber, || {
        tracing::callsite::rebuild_interest_cache();
        metrics::with_local_recorder(&probe, || {
            observe();
            let warns = probe.cut_warns();
            assert_eq!(warns.len(), 6, "one warning per cut field: {warns:#?}");
            for field in [
                "metric_help",
                "metric_label",
                "metric_unit",
                "metric_label_value",
                "diag_message",
                "diag_field",
            ] {
                assert!(
                    warns.iter().any(|l| l.contains("plugin=acme-store")
                        && l.contains(&format!("field={field}"))),
                    "{field}: {warns:#?}"
                );
            }
            assert_eq!(probe.total(), 6);
            observe();
            assert_eq!(
                probe.cut_warns().len(),
                6,
                "the second reply logs nothing new"
            );
            assert_eq!(probe.total(), 12, "the counter doubles");
        });
    });
}
