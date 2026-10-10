// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN IN-MEMORY `metrics` RECORDER for plane tests: installs once as the process-global recorder the
//! `metrics::counter!` macros emit into, and renders what landed as Prometheus-style exposition lines
//! (`name{label="value",...} count`), so a plane asserts its emits on a real scrape without naming
//! core's exporter. In a plane crate's own test binary nothing else installs a recorder, so the
//! capture IS the process recorder.

use metrics::{
    Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

#[derive(Default)]
struct Store {
    counters: Mutex<BTreeMap<String, u64>>,
}

static STORE: OnceLock<Arc<Store>> = OnceLock::new();

fn store() -> &'static Arc<Store> {
    STORE.get_or_init(|| Arc::new(Store::default()))
}

/// The rendered series identity: the metric name plus its labels in the order they were emitted.
fn series_of(key: &Key) -> String {
    let mut labels = key.labels().peekable();
    if labels.peek().is_none() {
        return key.name().to_string();
    }
    let rendered: Vec<String> = labels
        .map(|l| format!("{}=\"{}\"", l.key(), l.value()))
        .collect();
    format!("{}{{{}}}", key.name(), rendered.join(","))
}

struct CounterCell {
    store: Arc<Store>,
    series: String,
}

impl CounterFn for CounterCell {
    fn increment(&self, value: u64) {
        let mut counters = self.store.counters.lock().unwrap();
        *counters.entry(self.series.clone()).or_insert(0) += value;
    }
    fn absolute(&self, value: u64) {
        let mut counters = self.store.counters.lock().unwrap();
        counters.insert(self.series.clone(), value);
    }
}

struct CaptureRecorder(Arc<Store>);

impl Recorder for CaptureRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(CounterCell {
            store: Arc::clone(&self.0),
            series: series_of(key),
        }))
    }
    fn register_gauge(&self, _key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::noop()
    }
    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::noop()
    }
}

/// Install the capture as the process-global recorder. Idempotent: a second call (or one after another
/// recorder already took the slot) is a no-op, and [`render`] reads whatever this capture holds.
pub fn install() {
    let _ = metrics::set_global_recorder(CaptureRecorder(Arc::clone(store())));
}

/// Every counter series that landed since [`install`], one `name{labels} value` line each, sorted.
pub fn render() -> String {
    let counters = store().counters.lock().unwrap();
    let mut out = String::new();
    for (series, value) in counters.iter() {
        out.push_str(series);
        out.push(' ');
        out.push_str(&value.to_string());
        out.push('\n');
    }
    out
}
