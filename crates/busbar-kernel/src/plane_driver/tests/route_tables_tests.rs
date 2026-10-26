// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's own tables view over the `pools:`/`models:` sections it resolved: the read seam's
//! answer when no plane contributes a runtime, so it must project exactly what the sections say.

use std::collections::HashMap;

use super::{ConfigTables, EngineTablesView};
use crate::plane_driver::route_input::{LaneInput, OnExhaustedInput, PoolInput, PoolMemberInput};

fn lane(model: &str, provider: &str) -> LaneInput {
    LaneInput {
        model: model.to_string(),
        provider: provider.to_string(),
        base_url: format!("https://{provider}.invalid"),
        max_concurrent: 1,
    }
}

fn member(lane_idx: usize, weight: u32) -> PoolMemberInput {
    PoolMemberInput { lane_idx, weight }
}

fn pool(name: &str, members: Vec<PoolMemberInput>, on_exhausted: OnExhaustedInput) -> PoolInput {
    PoolInput {
        name: name.to_string(),
        members,
        on_exhausted,
        breaker: None,
    }
}

#[test]
fn the_tables_project_the_resolved_sections_in_lane_order() {
    let lanes = vec![lane("m-a", "pa"), lane("m-b", "pb")];
    let pools = vec![
        pool(
            "primary",
            vec![member(0, 3), member(1, 1)],
            OnExhaustedInput::FallbackPool("spare".to_string()),
        ),
        pool("spare", vec![member(1, 1)], OnExhaustedInput::default()),
    ];
    let by_model: HashMap<String, usize> = [("m-a".to_string(), 0), ("m-b".to_string(), 1)].into();
    let t = ConfigTables::of(
        &lanes,
        &pools,
        &by_model,
        busbar_contract::config::UpstreamCreds::Passthrough,
    );
    assert_eq!(t.lane_count(), 2);
    let b = t.lane_view(1).expect("lane 1");
    assert_eq!(
        (b.model, b.provider, b.base_url),
        ("m-b", "pb", "https://pb.invalid")
    );
    assert!(t.lane_view(2).is_none());
    assert_eq!(t.model_index("m-a"), Some(0));
    assert!(t.pool_exists("primary") && !t.pool_exists("m-a"));
    assert_eq!(t.pool_members("primary"), vec![(0, 3), (1, 1)]);
    assert_eq!(t.on_exhausted_fallback("primary").as_deref(), Some("spare"));
    assert_eq!(t.on_exhausted_fallback("spare"), None);
    assert_eq!(
        t.upstream_creds(),
        busbar_contract::config::UpstreamCreds::Passthrough
    );
    let mut pools_seen: Vec<(&str, Vec<usize>)> = t.pools();
    pools_seen.sort();
    assert_eq!(
        pools_seen,
        vec![("primary", vec![0, 1]), ("spare", vec![1])]
    );
}

#[test]
fn the_queue_depth_is_the_one_the_walk_reports() {
    let t = ConfigTables::default();
    assert_eq!(t.queued_depth("config-tables-q"), 0);
    super::set_pool_queued_depth("config-tables-q", 2);
    assert_eq!(t.queued_depth("config-tables-q"), 2);
    super::set_pool_queued_depth("config-tables-q", 0);
    assert_eq!(t.queued_depth("config-tables-q"), 0);
}
