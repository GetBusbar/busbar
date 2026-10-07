// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The codec host services the kernel arms ([`super::arm_codec_host_services`]).

/// THE USAGE-TAP COUNT, HOST STEP (#83a SD-3, architect ruling R-USAGE): the host services the
/// kernel arms (`arm_codec_host_services`, re-homed from the deleted protocol registry's
/// `installed_tests.rs`) count every usage-tap fault a codec reports — through the latch (a
/// codec's own reason) or through the decode reporter (a cell's default tap) — as ONE increment of
/// `busbar_billing_tap_decode_fail_total{protocol,reason}`, and warn once per `(protocol, reason)`.
/// The LLM plane's suite pins which reports each tap path makes; this pins what one report counts.
#[test]
fn an_armed_usage_tap_report_counts_one_increment_under_its_reason() {
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
    // What boot and every App build run to arm the host's services.
    super::arm_codec_host_services();
    let counts = Counts::default();
    let proto = "sd3-armed-tap-protocol";
    let (first, second) = metrics::with_local_recorder(&Local(Arc::clone(&counts)), || {
        let first = busbar_contract::codec::usage_tap_fault_should_warn(proto, "bad_json");
        let second = busbar_contract::codec::usage_tap_fault_should_warn(proto, "bad_json");
        busbar_contract::codec::report_usage_tap_decode_failure(
            proto,
            &busbar_contract::codec::CodecError::Malformed("x".into()),
        );
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
