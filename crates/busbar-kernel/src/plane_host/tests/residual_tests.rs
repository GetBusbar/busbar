// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SETTLE STEP'S RESIDUAL ROW (MONEY LAW, owner 2026-10-02): a usage count no billing class
//! records gets one `usage.residual` audit row, written by the kernel, naming the unit, count,
//! plane, dialect and request id. Never billed.

use crate::plane::calllog::CallInput;
use crate::plane_host::{JournalHost, USAGE_RESIDUAL_ACTION};
use std::collections::BTreeMap;
use std::sync::Mutex;

/// One `(action, resource, outcome, principal)` audit row.
type Row = (String, String, String, String);

/// A journal that keeps every audit row it is handed, and nothing else.
#[derive(Default)]
struct Rows(Mutex<Vec<Row>>);

impl JournalHost for Rows {
    fn audit_emit(&self, _action: &str, _resource: &str, _outcome: &str, _principal: &str) {}

    fn audit_record(&self, action: &str, resource: &str, outcome: &'static str, principal: &str) {
        self.0.lock().expect("rows").push((
            action.to_string(),
            resource.to_string(),
            outcome.to_string(),
            principal.to_string(),
        ));
    }

    fn call_log_emit(&self, _principal: &str, _input: CallInput) {}

    fn call_log_emit_hostless(&self, _principal: &str, _input: CallInput) {}
}

/// ONE ROW PER NON-EMPTY MAP, naming every unit and count, the plane, the dialect, the lane and
/// the request id, outcome `unbilled`, against the settling principal. An empty map writes none.
/// RED when the settle step stops writing the row or drops a fact from it.
#[test]
fn a_residual_settles_as_one_unbilled_audit_row() {
    let rows = Rows::default();
    rows.settle_residual(
        &BTreeMap::new(),
        "plane-a",
        "dialect-a",
        "lane-a",
        42,
        "key-1",
    );
    assert!(
        rows.0.lock().expect("rows").is_empty(),
        "an empty residual map writes no row"
    );
    let residual = BTreeMap::from([
        ("usage.stated_total_gap".to_string(), 7),
        ("policy.units".to_string(), 14),
    ]);
    rows.settle_residual(&residual, "plane-a", "dialect-a", "lane-a", 42, "key-1");
    assert_eq!(
        *rows.0.lock().expect("rows"),
        vec![(
            USAGE_RESIDUAL_ACTION.to_string(),
            "plane=plane-a dialect=dialect-a lane=lane-a request=42 \
             units=policy.units=14,usage.stated_total_gap=7"
                .to_string(),
            busbar_contract::vocab::OUTCOME_UNBILLED.to_string(),
            "key-1".to_string(),
        )],
        "one usage.residual row, naming every unit and count, the plane, dialect and request id"
    );
    assert_eq!(USAGE_RESIDUAL_ACTION, "usage.residual");
}
