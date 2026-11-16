// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W2f: a 1.5.5-shaped group limit still parses and enforces after the 1.6.0 pre-release group-limit
//! keys are removed.

use super::*;
use crate::config::groups::GroupCfg;
use crate::cost::CostModel;
use std::collections::BTreeMap;

#[tokio::test]
async fn a_1_5_5_shaped_group_limit_parses_and_enforces() {
    let groups: BTreeMap<String, GroupCfg> = busbar_contract::yaml::from_str(
        "team:\n  limits:\n    - { requests: 2, per: minute }\n    - { tokens: 100, per: minute }\n    \
         - { budget: 1000, per: month }\n    - { concurrent: 3 }\n",
    )
    .expect("a 1.5.5-shaped groups block parses");
    let cm = CostModel::resolve_parts(None, 0, &groups);
    let key = VirtualKey {
        id: "vk_w2f".to_string(),
        generation_hash: "h:vk_w2f".to_string(),
        name: "vk_w2f".to_string(),
        enabled: true,
        group: Some("team".to_string()),
        revision: 1,
        ..Default::default()
    };
    let g = GovState::new_with_core(crate::real_store::core().await, None, None)
        .await
        .expect("native Store constructs");
    let now = 1_700_000_000;
    g.try_admit(&cm, &key, "", now).expect("first request fits");
    g.try_admit(&cm, &key, "", now)
        .expect("second request fits");
    match g.try_admit(&cm, &key, "", now).unwrap_err() {
        LimitBlocked::Limit {
            metric: "requests", ..
        } => {}
        other => panic!("the third request in the minute is refused on requests, got {other:?}"),
    }
}
