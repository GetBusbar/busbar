// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::sync::Arc;

#[test]
fn both_abi_lanes_ask_the_same_metric_name_question() {
    assert!(crate::snapshot::observe::admits_metric_name(
        "plane_host_test"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name(
        "busbar_anything"
    ));
    assert!(!crate::snapshot::observe::admits_metric_name("Bad-Name"));
    assert!(!crate::snapshot::observe::admits_metric_name(""));
}

#[test]
fn a_role_bound_standing_is_rechecked_against_the_live_snapshot_bindings() {
    let mut roles = std::collections::BTreeMap::new();
    roles.insert("eng".to_string(), crate::config::RoleBindingCfg::default());
    let mut rb = crate::config::RoleBindings::new();
    rb.insert("idp".to_string(), roles);
    let principal = crate::auth::Principal {
        id: "alice@example.com".to_string(),
        name: None,
        roles: vec!["eng".to_string()],
        ttl_secs: None,
    };
    let key = crate::governance::synthesize_bound_key("idp", &principal, &rb).expect("bound");
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::test_support::TestApp::new()
            .role_bindings(rb)
            .build(),
    ));
    let standing = live_standing(Arc::clone(&handle));

    let now = standing(&key, 1_700_000_000).expect("the binding stands");
    assert_eq!(now.id, "alice@example.com");

    handle.swap(crate::test_support::TestApp::new().build());
    assert!(
        standing(&key, 1_700_000_000).is_none(),
        "the binding is gone from the live snapshot, so the principal no longer stands"
    );
}

fn hook_accesses_under(
    journal: &crate::audit::amend::NodeAmendments,
    op: &str,
) -> Vec<crate::audit::amend::Access> {
    journal
        .recent()
        .into_iter()
        .filter_map(|a| match a.body {
            crate::audit::amend::AmendBody::Access(x) if x.op_class.as_str() == op => Some(x),
            _ => None,
        })
        .collect()
}

#[test]
fn the_host_hook_read_port_seals_one_access_amendment_on_the_node_journal() {
    const OP: &str = "access-host-port";
    let app = crate::test_support::TestApp::new().build();
    let other = crate::test_support::TestApp::new().build();
    let host = crate::test_support::engine_host(&app);
    host.hook_read("port-hook", Some("key-1"), OP, true);
    assert!(
        hook_accesses_under(&other.amendments, OP).is_empty(),
        "another node's journal recorded this node's hook read"
    );
    let seen = hook_accesses_under(&app.amendments, OP);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].name, "port-hook");
    assert_eq!(
        seen[0].subject,
        crate::audit::amend::Subject::PrincipalId("key-1".to_string())
    );
    assert_eq!(
        seen[0].fields,
        vec!["content".to_string(), "identity".to_string()]
    );
}
