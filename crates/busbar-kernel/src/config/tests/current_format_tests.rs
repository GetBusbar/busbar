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
