// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
#[test]
fn mutable_management_selects_store_and_locked_refuses_mutation() {
    let mutable = resolve_backend(&ConfigMgmtCfg::default());
    assert!(mutable.enabled);
    assert!(!mutable.locked);
    let locked = resolve_backend(&ConfigMgmtCfg { locked: true });
    assert!(locked.locked);
    assert!(!locked.enabled);
}
#[tokio::test]
async fn f_every_persist_entry_point_refuses_a_none_locked_overlay() {
    let empty_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    assert!(
        persist_async(
            None,
            &HashMap::<String, HookCfg>::new(),
            &[],
            None,
            None,
            &empty_names,
        )
        .await
        .is_err(),
        "persist(None) must refuse (hooks)"
    );
    assert!(
        persist_groups_async(
            None,
            &BTreeMap::<String, GroupCfg>::new(),
            None,
            None,
            &empty_names,
        )
        .await
        .is_err(),
        "persist_groups(None) must refuse (groups)"
    );
    assert!(
        persist_root_async(None, &RootSettings::default())
            .await
            .is_err(),
        "persist_root(None) must refuse (settings)"
    );
    assert!(
        clear_section_async(None, OverlaySection::Hooks)
            .await
            .is_err(),
        "clear_section(None) must refuse (per-section reset)"
    );
    assert!(
        try_persist_plugin_versions_async(None, &BTreeMap::<String, String>::new())
            .await
            .is_err(),
        "try_persist_plugin_versions(None) must refuse (rollback pin)"
    );
}
