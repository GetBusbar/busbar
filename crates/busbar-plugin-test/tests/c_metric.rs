// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-METRIC (ABI-MIN3-INTERFACE §14): Declared metrics recorded and kept across reconfigure; undeclared and
//! over-cardinality dropped and audited.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use std::sync::Arc;

use busbar_kernel::recorder::{MetricDeclIn, Observed, Recorder, Scope, Value, MAX_LABEL_SETS};
use busbar_plugin_abi::records::metric::{MX_ADD, MX_COUNTER};
use busbar_plugin_abi::types::KindCode;

const HITS: MetricDeclIn<'static> = MetricDeclIn {
    id: 1,
    kind: MX_COUNTER,
    name: "hits_total",
    label_keys: &["route"],
};

#[test]
fn declared_metrics_survive_reconfigure() {
    let recorder = Recorder::new();
    let m = recorder
        .declare(KindCode::Store, "main", &[HITS])
        .expect("declare");
    assert_eq!(m.observe(1, MX_ADD, 2.0, &["a"]), Observed::Recorded);
    // An undeclared id is dropped.
    assert_eq!(m.observe(9, MX_ADD, 1.0, &["a"]), Observed::Undeclared);

    // A reconfigure that keeps the name keeps the series.
    let again = recorder
        .declare(KindCode::Store, "main", &[HITS])
        .expect("redeclare");
    assert!(Arc::ptr_eq(&m, &again));
    assert_eq!(again.observe(1, MX_ADD, 3.0, &["a"]), Observed::Recorded);
    let snap = recorder.snapshot(Scope::Metrics);
    let hits = snap
        .iter()
        .find(|f| f.name == "hits_total")
        .expect("family");
    assert_eq!(hits.samples.len(), 1);
    assert_eq!(hits.samples[0].value, Value::Counter(5.0));
    assert_eq!(
        hits.samples[0].labels,
        vec![
            ("kind".to_string(), "store".to_string()),
            ("instance".to_string(), "main".to_string()),
            ("route".to_string(), "a".to_string()),
        ]
    );
    // There is no `plugin` label on any sample.
    assert!(snap
        .iter()
        .flat_map(|f| &f.samples)
        .all(|s| s.labels.iter().all(|(k, _)| k != "plugin")));

    // A hook's metrics are served at SCOPE_HOOKS only.
    recorder
        .declare(KindCode::Hook, "gate", &[HITS])
        .expect("declare hook");
    assert!(recorder
        .snapshot(Scope::Hooks)
        .iter()
        .flat_map(|f| &f.samples)
        .all(|s| s.labels.iter().any(|(k, v)| k == "kind" && v == "hook")));

    // Over-cardinality: label set 257 is dropped, the first drop is the audited one, existing sets still record.
    let wide = recorder
        .declare(KindCode::Store, "wide", &[HITS])
        .expect("declare wide");
    for i in 0..MAX_LABEL_SETS {
        let label = format!("r{i}");
        assert_eq!(
            wide.observe(1, MX_ADD, 1.0, &[label.as_str()]),
            Observed::Recorded
        );
    }
    assert_eq!(
        wide.observe(1, MX_ADD, 1.0, &["over"]),
        Observed::Capped { first: true }
    );
    assert_eq!(
        wide.observe(1, MX_ADD, 1.0, &["over-again"]),
        Observed::Capped { first: false }
    );
    assert_eq!(wide.observe(1, MX_ADD, 1.0, &["r0"]), Observed::Recorded);
}
