// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::config::{OnExhaustedCfg, PoolCfg};

#[test]
fn current_exhaustion_keywords_reach_the_canonical_parser() {
    for (keyword, expected) in [
        ("reject", OnExhaustedCfg::Reject),
        ("least_bad", OnExhaustedCfg::LeastBad),
    ] {
        let document: Value = busbar_contract::yaml::from_str(&format!(
            "pools: {{op: {{members: [], on_exhausted: {keyword}}}}}"
        ))
        .unwrap();
        assert!(detect_legacy_markers(&document).is_empty());
        let pool: PoolCfg =
            busbar_contract::yaml::from_value(document.at("pools").at("op").clone()).unwrap();
        assert_eq!(pool.on_exhausted, Some(expected));
    }
    let document: Value =
        busbar_contract::yaml::from_str("pools: {op: {members: [], on_exhausted: invalid_mode}}")
            .unwrap();
    assert!(detect_legacy_markers(&document).is_empty());
    let error = busbar_contract::yaml::from_value::<PoolCfg>(document.at("pools").at("op").clone())
        .unwrap_err();
    assert!(error.to_string().contains("unknown on_exhausted keyword"));
}

#[test]
fn a_1_5_5_config_overlay_selector_is_refused_by_name() {
    // A valid 1.5.5 deployment naming its file overlay. Serde alone answers "unknown field
    // `overlay`, expected `locked`"; the current reader must say what retired it and the way out.
    let document: Value = busbar_contract::yaml::from_str(include_str!(
        "../../../../busbar/src/root/tests/fixtures/config_overlay_1_5_5.yaml"
    ))
    .unwrap();
    let refused = legacy_config_error(&detect_legacy_markers(&document));
    for want in [
        "`config.overlay`",
        "retired in 1.6.0",
        "Store",
        "busbar --migrate-config",
        "--migrate-overlay",
    ] {
        assert!(
            refused.contains(want),
            "the current reader's refusal does not say `{want}`:\n{refused}"
        );
    }
    let current: Value = busbar_contract::yaml::from_str("config: {locked: true}\n").unwrap();
    assert!(
        detect_legacy_markers(&current).is_empty(),
        "the current `config:` block is not refused"
    );
}
