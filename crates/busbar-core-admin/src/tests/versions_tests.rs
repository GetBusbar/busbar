// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn reg(names: &[&str]) -> serde_json::Value {
    serde_json::Value::Object(
        names
            .iter()
            .map(|n| {
                (
                    n.to_string(),
                    serde_json::json!({"kind": "tap", "module": format!("test-hook-{n}")}),
                )
            })
            .collect(),
    )
}

#[test]
fn record_list_get_and_bound() {
    let log = VersionLog::default();
    log.record(1, "admin", "hook.register hook:a", reg(&["a"]), &[]);
    log.record(2, "admin", "hook.register hook:b", reg(&["a", "b"]), &[]);
    let listed = log.list(0, 10);
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].version, 2, "newest first");
    assert_eq!(listed[0].principal, "admin");
    let v1 = log.get(1).expect("v1 retained");
    assert_eq!(v1.hook_registry.as_object().map(|o| o.len()), Some(1));
    assert!(log.get(99).is_none(), "unknown version is None");

    log.record(2, "admin", "hook.register hook:b2", reg(&["b"]), &[]);
    assert_eq!(log.list(0, 10).len(), 2);
    assert_eq!(log.get(2).unwrap().summary, "hook.register hook:b2");

    for v in 3..(MAX_VERSIONS as u64 + 5) {
        log.record(v, "admin", "s", reg(&[]), &[]);
    }
    let all = log.list(0, usize::MAX);
    assert_eq!(all.len(), MAX_VERSIONS);
    assert!(log.get(1).is_none(), "oldest pruned");
}
