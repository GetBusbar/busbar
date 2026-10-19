// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for the usage-tap fault count in `handlers/mod.rs`.

/// THE USAGE-TAP COUNT, KERNEL STEP (#83a SD-3, architect ruling R-USAGE; row 155): every usage-tap
/// fault a plane's answer carries is counted by the kernel as ONE increment of
/// `busbar_billing_tap_decode_fail_total{protocol,reason}`, and warned once per `(protocol, reason)`.
/// The LLM plane's suite pins which fault each tap path returns; this pins what one fault counts.
#[test]
fn a_usage_tap_fault_counts_one_increment_under_its_reason() {
    use metrics::{
        Counter, CounterFn, Gauge, Histogram, Key, KeyName, Metadata, Recorder, SharedString, Unit,
    };
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};
    type Counts = Arc<Mutex<BTreeMap<String, u64>>>;
    struct Cell(Counts, String);
    impl CounterFn for Cell {
        fn increment(&self, value: u64) {
            *self.0.lock().unwrap().entry(self.1.clone()).or_insert(0) += value;
        }
        fn absolute(&self, value: u64) {
            self.0.lock().unwrap().insert(self.1.clone(), value);
        }
    }
    struct Local(Counts);
    impl Recorder for Local {
        fn describe_counter(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_gauge(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn describe_histogram(&self, _: KeyName, _: Option<Unit>, _: SharedString) {}
        fn register_counter(&self, key: &Key, _: &Metadata<'_>) -> Counter {
            let labels: Vec<String> = key
                .labels()
                .map(|l| format!("{}={}", l.key(), l.value()))
                .collect();
            let series = format!("{}{{{}}}", key.name(), labels.join(","));
            Counter::from_arc(Arc::new(Cell(Arc::clone(&self.0), series)))
        }
        fn register_gauge(&self, _: &Key, _: &Metadata<'_>) -> Gauge {
            Gauge::noop()
        }
        fn register_histogram(&self, _: &Key, _: &Metadata<'_>) -> Histogram {
            Histogram::noop()
        }
    }
    let counts = Counts::default();
    let proto = "sd3-armed-tap-protocol";
    let (first, second) = metrics::with_local_recorder(&Local(Arc::clone(&counts)), || {
        let first = crate::handlers::usage_tap_decode_fail_should_warn(proto, "bad_json");
        let second = crate::handlers::usage_tap_decode_fail_should_warn(proto, "bad_json");
        crate::handlers::usage_tap_fault(proto, "decode");
        (first, second)
    });
    assert!(
        first && !second,
        "the first fault of a (protocol, reason) warns; later ones do not"
    );
    let series = |reason: &str| {
        format!("busbar_billing_tap_decode_fail_total{{protocol={proto},reason={reason}}}")
    };
    let counts = counts.lock().unwrap().clone();
    assert_eq!(counts.get(&series("bad_json")), Some(&2));
    assert_eq!(counts.get(&series("decode")), Some(&1));
}
