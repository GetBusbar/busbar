// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/v1/json/handlers.rs`.

use super::merge_group_patch;
use crate::config::groups::{ChildDefault, LimitMetric, LimitWindow};
use crate::config::{GroupCfg, LimitCfg};

fn budget(cents: u64) -> LimitCfg {
    LimitCfg {
        metric: LimitMetric::Budget,
        amount: cents,
        per: Some(LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

/// The raise-a-budget path: patching only `limits` replaces them and PRESERVES parent + enabled.
#[test]
fn patch_limits_preserves_other_fields() {
    let base = GroupCfg {
        parent: Some("team".into()),
        enabled: true,
        limits: vec![budget(3_000)],
        child_default: None,
    };
    let out = merge_group_patch(base, None, None, Some(vec![budget(5_000)]), None);
    assert_eq!(out.parent.as_deref(), Some("team"));
    assert!(out.enabled);
    assert_eq!(out.limits.len(), 1);
    assert_eq!(out.limits[0].amount, 5_000);
    assert!(out.child_default.is_none());
}

/// Freezing a group: patching only `enabled` flips it, leaving limits + parent intact.
#[test]
fn patch_enabled_only_freezes_without_touching_limits() {
    let base = GroupCfg {
        parent: Some("team".into()),
        enabled: true,
        limits: vec![budget(3_000)],
        child_default: Some(ChildDefault {
            limits: vec![budget(500)],
        }),
    };
    let out = merge_group_patch(base, None, Some(false), None, None);
    assert!(!out.enabled);
    assert_eq!(out.limits[0].amount, 3_000);
    assert_eq!(out.parent.as_deref(), Some("team"));
    let cd = out.child_default.expect("child_default preserved");
    assert_eq!(cd.limits[0].amount, 500);
}

/// An empty patch (all None) is an identity: nothing changes.
#[test]
fn empty_patch_is_identity() {
    let base = GroupCfg {
        parent: Some("p".into()),
        enabled: false,
        limits: vec![budget(1)],
        child_default: None,
    };
    let out = merge_group_patch(base.clone(), None, None, None, None);
    assert_eq!(out, base);
}
