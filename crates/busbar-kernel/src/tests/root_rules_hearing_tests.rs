// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::appbuild::RootRules;
use std::sync::Arc;

#[test]
fn boot_builds_a_pool_of_nine_unbounded_lanes_without_overflowing_its_banner() {
    crate::test_support::register_neutral_test_plane();
    crate::snapshot::init_for_test(std::time::Duration::from_secs(3600));
    let mut cfg = crate::test_support::cfg_with_provider_api_key(crate::config::SecretRef::none());
    let members: Vec<_> = (0..9).map(|index| format!("unbounded-{index}")).collect();
    for name in &members {
        let model: crate::config::ModelCfg =
            serde_json::from_value(serde_json::json!({"provider":"acme"})).unwrap();
        assert_eq!(
            model.max_concurrent, None,
            "the ordinary omitted concurrency limit"
        );
        cfg.models.insert(name.clone(), model);
    }
    cfg.pools.insert(
        "wide".into(),
        serde_json::from_value(serde_json::json!({"members":members})).unwrap(),
    );
    let rules: Arc<dyn RootRules> = Arc::new(crate::appbuild::AcceptAll);
    let app = crate::test_support::build_once_under(cfg, None, &rules)
        .expect("an aggregate display wider than usize must not prevent boot");
    assert_eq!(app.engine_tables_view().lane_count(), 9);
    assert_eq!(app.engine_tables_view().pool_members("wide").len(), 9);
}
