// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! FU2 (B32): `/metrics/hooks` across reload, IF §12.17. Counters keyed by instance name survive a reload that
//! still names the instance; a removed instance's series are dropped at that reload.

use busbar_kernel::recorder::{MetricDeclIn, Recorder, Scope, Value};
use busbar_plugin_abi::records::metric::{MX_ADD, MX_COUNTER};
use busbar_plugin_abi::types::KindCode;

const CALLS: MetricDeclIn<'static> = MetricDeclIn {
    id: 1,
    kind: MX_COUNTER,
    name: "calls_total",
    label_keys: &[],
};

fn open(r: &Recorder, kind: KindCode, instance: &str, value: f64) {
    let m = r.declare(kind, instance, &[CALLS]).expect("declare");
    m.observe(1, MX_ADD, value, &[]);
}

fn total(r: &Recorder, scope: Scope, instance: &str) -> Option<f64> {
    r.snapshot(scope)
        .into_iter()
        .filter(|f| f.name == "calls_total")
        .flat_map(|f| f.samples)
        .find(|s| {
            s.labels
                .iter()
                .any(|(k, v)| k == "instance" && v == instance)
        })
        .map(|s| match s.value {
            Value::Counter(v) => v,
            other => panic!("not a counter: {other:?}"),
        })
}

#[test]
fn counters_survive_reload_of_same_name_and_removed_instance_is_dropped() {
    let r = Recorder::new();
    open(&r, KindCode::Hook, "headroom", 1.0);
    open(&r, KindCode::Hook, "headroom", 2.0);
    open(&r, KindCode::Hook, "ranking", 5.0);
    assert_eq!(total(&r, Scope::Hooks, "headroom"), Some(3.0));

    // Reload keeps `headroom` only.
    r.reconfigure(&[(KindCode::Hook, "headroom")]);
    assert_eq!(
        total(&r, Scope::Hooks, "headroom"),
        Some(3.0),
        "same name survives the reload"
    );
    assert_eq!(
        total(&r, Scope::Hooks, "ranking"),
        None,
        "removed instance's series are dropped"
    );

    // Counting continues on the survivor; a re-added name starts from zero.
    open(&r, KindCode::Hook, "headroom", 1.0);
    assert_eq!(total(&r, Scope::Hooks, "headroom"), Some(4.0));
    open(&r, KindCode::Hook, "ranking", 1.0);
    assert_eq!(total(&r, Scope::Hooks, "ranking"), Some(1.0));
}

#[test]
fn reload_does_not_touch_other_kinds_series_of_a_kept_name() {
    let r = Recorder::new();
    open(&r, KindCode::Hook, "x", 1.0);
    open(&r, KindCode::Export, "x", 1.0);
    r.reconfigure(&[(KindCode::Hook, "x")]);
    assert_eq!(total(&r, Scope::Hooks, "x"), Some(1.0));
    assert_eq!(
        total(&r, Scope::Metrics, "x"),
        None,
        "an owner is (kind, name): the export `x` was not named"
    );
}
