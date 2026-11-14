// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{policy_timeout, same_call_inputs};

#[test]
fn timeout_only_changes_refuse_the_old_instance_in_every_reuse_path() {
    let settings: busbar_contract::plugin_settings::Settings =
        serde_json::json!({"url": "http://127.0.0.1:1/"})
            .as_object()
            .unwrap()
            .clone()
            .into();
    assert!(same_call_inputs(
        "webrequest",
        &settings,
        policy_timeout(11),
        "webrequest",
        &settings,
        || policy_timeout(11)
    ));
    assert!(!same_call_inputs(
        "webrequest",
        &settings,
        policy_timeout(11),
        "webrequest",
        &settings,
        || policy_timeout(29)
    ));
    assert!(!same_call_inputs(
        "webrequest",
        &settings,
        policy_timeout(11),
        "ranking",
        &settings,
        || policy_timeout(11)
    ));
    let changed: busbar_contract::plugin_settings::Settings =
        serde_json::json!({"url": "http://127.0.0.1:2/"})
            .as_object()
            .unwrap()
            .clone()
            .into();
    assert!(!same_call_inputs(
        "webrequest",
        &settings,
        policy_timeout(11),
        "webrequest",
        &changed,
        || policy_timeout(11)
    ));
}

#[test]
fn implicit_and_explicit_default_reuse_the_same_effective_budget() {
    let settings = Default::default();
    let default = crate::limits::default_policy_timeout_ms();
    assert!(same_call_inputs(
        "hook",
        &settings,
        policy_timeout(0),
        "hook",
        &settings,
        || policy_timeout(default)
    ));
    assert!(same_call_inputs(
        "hook",
        &settings,
        policy_timeout(default),
        "hook",
        &settings,
        || policy_timeout(0)
    ));
}
