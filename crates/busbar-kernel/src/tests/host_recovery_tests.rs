// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn recovery_external_binding_preserves_expiry_and_rechecks_current_roles() {
    let mut bindings = crate::config::RoleBindings::new();
    bindings.insert(
        "idp".into(),
        [("reader".into(), crate::config::RoleBindingCfg::default())].into(),
    );
    let principal = crate::auth::Principal {
        id: "alice".into(),
        name: None,
        roles: vec!["reader".into()],
        ttl_secs: Some(9999),
    };
    let key = crate::governance::synthesize_bound_key("idp", &principal, &bindings).unwrap();
    let mut work = RecoveryWork {
        instance: "plane".into(),
        reference: [1; 16],
        target: "/jobs/1".into(),
        active: Arc::default(),
        binding: crate::host_work::RecoveryBinding {
            principal: key.id.clone(),
            generation: key.generation_hash.clone(),
            created_at: 0,
            expires_at: Some(100),
        },
    };
    assert_eq!(
        work.restore_bound(&bindings, 99).unwrap().expires_at,
        Some(100)
    );
    assert!(work.restore_bound(&bindings, 100).is_none());
    bindings.get_mut("idp").unwrap().clear();
    assert!(work.restore_bound(&bindings, 99).is_none());
    bindings.get_mut("idp").unwrap().insert(
        "different-role".into(),
        crate::config::RoleBindingCfg::default(),
    );
    assert!(work.restore_bound(&bindings, 99).is_none());
    bindings
        .get_mut("idp")
        .unwrap()
        .insert("reader".into(), crate::config::RoleBindingCfg::default());
    work.binding.expires_at = None;
    assert!(
        work.restore_bound(&bindings, 99).is_none(),
        "cache TTL grants no recovery lifetime"
    );
}
