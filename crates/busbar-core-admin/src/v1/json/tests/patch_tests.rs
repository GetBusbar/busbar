// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::merge_group_patch;
use busbar_kernel::config::groups::{ChildDefault, LimitMetric, LimitWindow};
use busbar_kernel::config::{GroupCfg, LimitCfg};

#[test]
fn datagram_line_memory_limit_applies_to_new_connections_without_restart() {
    for value in [serde_json::json!(12345), serde_json::Value::Null] {
        let settings: busbar_kernel::config::overlay::RootSettings =
            serde_json::from_value(serde_json::json!({
                "limits": {
                    "datagram_line_memory_bytes": value,
                    "pool_idle_timeout_secs": 17
                }
            }))
            .expect("settings accept setting or disabling the optional limit");
        assert_eq!(
            super::reload_to_apply_fields(&settings),
            ["limits.pool_idle_timeout_secs"],
            "the new-pairing limit must not be classified as requiring a restart"
        );
    }
}

fn budget(cents: u64) -> LimitCfg {
    LimitCfg {
        metric: LimitMetric::Budget,
        amount: cents,
        per: Some(LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

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

#[test]
fn group_explicit_clear_preserves_legacy_null_and_distinguishes_empty_template() {
    use super::GroupPatchReq;
    let base = GroupCfg {
        parent: Some("parent".into()),
        child_default: Some(ChildDefault {
            limits: vec![budget(7)],
        }),
        ..Default::default()
    };
    for body in [
        r#"{}"#,
        r#"{"parent":null,"child_default":null,"limits":null,"enabled":null}"#,
    ] {
        let patch: GroupPatchReq = serde_json::from_str(body).unwrap();
        assert_eq!(patch.apply(base.clone()).unwrap(), base);
    }
    let patch: GroupPatchReq =
        serde_json::from_str(r#"{"clear":["parent","child_default"]}"#).unwrap();
    let cleared = patch.apply(base.clone()).unwrap();
    assert!(cleared.parent.is_none());
    assert!(cleared.child_default.is_none());
    assert_eq!(cleared.limits, base.limits);
    let patch: GroupPatchReq = serde_json::from_str(r#"{"child_default":{}}"#).unwrap();
    assert_eq!(
        patch.apply(base.clone()).unwrap().child_default,
        Some(ChildDefault::default())
    );
    for body in [
        r#"{"parent":"new","clear":["parent"]}"#,
        r#"{"child_default":{},"clear":["child_default"]}"#,
    ] {
        let patch: GroupPatchReq = serde_json::from_str(body).unwrap();
        assert!(patch.apply(base.clone()).is_err());
    }
    assert!(serde_json::from_str::<GroupPatchReq>(r#"{"clear":["enabled"]}"#).is_err());
}

#[test]
fn hook_explicit_edit_preserves_private_settings_and_replacement_remains_explicit() {
    use super::PatchSettingsReq;
    use serde_json::json;
    let existing = json!({"credential":{"env":"PRIVATE"},"visible":1,"remove_me":true})
        .as_object()
        .unwrap()
        .clone();
    let request: PatchSettingsReq = serde_json::from_value(
        json!({"edit":{"set":{"visible":2,"nullable":null},"remove":["remove_me"]}}),
    )
    .unwrap();
    let edited = request.apply(existing.clone()).unwrap();
    assert_eq!(edited["credential"], existing["credential"]);
    assert_eq!(edited["visible"], 2);
    assert!(edited["nullable"].is_null());
    assert!(!edited.contains_key("remove_me"));
    let request: PatchSettingsReq =
        serde_json::from_value(json!({"settings":{"visible":3}})).unwrap();
    assert_eq!(
        request.apply(existing.clone()).unwrap(),
        json!({"visible":3}).as_object().unwrap().clone()
    );
    for body in [
        json!({}),
        json!({"settings":{},"edit":{}}),
        json!({"edit":{"set":{"credential":null},"remove":["credential"]}}),
    ] {
        let request: PatchSettingsReq = serde_json::from_value(body).unwrap();
        assert!(request.apply(existing.clone()).is_err());
    }
    for body in [
        json!({"settings":null}),
        json!({"settings":{},"edit":null}),
        json!({"edit":{"unknown":true}}),
    ] {
        assert!(serde_json::from_value::<PatchSettingsReq>(body).is_err());
    }
}

#[test]
fn group_budget_readback_preserves_all_authored_policy_and_exact_u64_wire() {
    use crate::v1::contract::GroupView;
    let cfg: GroupCfg = serde_json::from_str(r#"{"limits":[{"budget":9007199254740993,"per":"month","admission":"estimate","on_exhaustion":"cut-stream"}],"child_default":{"limits":[{"budget":7,"per":"day","admission":"exact","on_exhaustion":"finish-unit"}]}}"#).unwrap();
    let view = GroupView::from_cfg("group", &cfg);
    let encoded = serde_json::to_string(&view).unwrap();
    assert!(encoded.contains("9007199254740993"));
    assert_eq!(view.limits[0].admission, Some("estimate"));
    assert_eq!(view.limits[0].on_exhaustion, Some("cut-stream"));
    let template = view.child_default.unwrap();
    assert_eq!(template[0].admission, Some("exact"));
    assert_eq!(template[0].on_exhaustion, Some("finish-unit"));
}

#[test]
fn hook_admin_writes_require_canonical_module_and_phase() {
    let canonical = serde_json::json!({"kind":"tap","module":"observer","phase":["response"]});
    let register: super::RegisterHookReq = serde_json::from_value(serde_json::json!({
        "name":"observer", "config":canonical,
    }))
    .unwrap();
    assert_eq!(
        register.config.resolved_stages(),
        vec![busbar_kernel::config::HookStage::Response]
    );
    for retired in [
        serde_json::json!({"kind":"tap","module":"observer","at":"response"}),
        serde_json::json!({"kind":"tap","plugin":"observer","phase":["response"]}),
    ] {
        assert!(
            serde_json::from_value::<super::RegisterHookReq>(serde_json::json!({
                "name":"observer", "config":retired,
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<super::PutHookReq>(serde_json::json!({
                "config":retired,
            }))
            .is_err()
        );
    }
}
