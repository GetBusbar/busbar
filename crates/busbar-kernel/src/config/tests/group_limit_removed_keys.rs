// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2f: the 1.6.0 pre-release group-limit keys `tokens_input`, `tokens_output`, `tokens_cache_read`,
//! `tokens_cache_write`, `admission` and `on_exhaustion` are removed; a config that sets one is
//! refused as an unknown key. The 1.5.5 limit shapes keep parsing.

use super::*;

const REMOVED_METRICS: [&str; 4] = [
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];

const REMOVED_BUDGET_OPTIONS: [(&str, &str); 4] = [
    ("admission", "exact"),
    ("admission", "estimate"),
    ("on_exhaustion", "finish-unit"),
    ("on_exhaustion", "cut-stream"),
];

fn refused(yaml: &str, key: &str) {
    let err = match busbar_contract::yaml::from_str::<GroupCfg>(yaml) {
        Ok(ok) => panic!("`{key}` must be refused, parsed {ok:?}"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains(&format!("unknown field `{key}`")),
        "`{key}` must be refused as an unknown key: {err}"
    );
}

#[test]
fn removed_token_class_metrics_are_refused_as_unknown() {
    for key in REMOVED_METRICS {
        let own = format!("limits:\n  - {{ {key}: 7, per: day }}\n");
        refused(&own, key);
        let template = format!("child_default:\n  limits:\n    - {{ {key}: 7, per: day }}\n");
        refused(&template, key);
    }
}

#[test]
fn removed_budget_options_are_refused_as_unknown() {
    for (key, value) in REMOVED_BUDGET_OPTIONS {
        let own = format!("limits:\n  - {{ budget: 5, per: day, {key}: {value} }}\n");
        refused(&own, key);
        let template =
            format!("child_default:\n  limits:\n    - {{ budget: 5, per: day, {key}: {value} }}\n");
        refused(&template, key);
    }
}

#[test]
fn a_1_5_5_shaped_group_still_parses() {
    let group: GroupCfg = busbar_contract::yaml::from_str(
        "limits:\n  - { requests: 500, per: minute }\n  - { tokens: 20000000, per: day }\n  \
         - { budget: 1000, per: month, pool: cheap, on_exhaust: downgrade, downgrade_to: value }\n  \
         - { concurrent: 5 }\n",
    )
    .expect("1.5.5's four metrics and its on_exhaust / downgrade_to still parse");
    let metrics: Vec<&str> = group.limits.iter().map(|l| l.metric.as_str()).collect();
    assert_eq!(metrics, ["requests", "tokens", "budget", "concurrent"]);
}
