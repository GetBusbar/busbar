// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn parse(args: &[&str]) -> Result<Option<Command>, &'static str> {
    command(args.iter().map(|arg| (*arg).to_owned()))
}

#[test]
fn cold_flags_accept_config_locations_and_require_a_fresh_apply_attestation() {
    let parsed = parse(&[
        "--config",
        "deploy.yaml",
        "--transition-action=apply",
        "--providers=catalog.yaml",
        "--principal-transition",
        "plan.json",
        "--transition-attestation",
        "cold.json",
    ])
    .unwrap()
    .unwrap();
    assert_eq!(parsed.action, Action::Apply);
    assert_eq!(parsed.input, Path::new("plan.json"));
    assert_eq!(parsed.attestation.as_deref(), Some(Path::new("cold.json")));
    assert!(parsed.validate_overlay_mode(true, false).is_err());
    assert!(parsed.validate_overlay_mode(false, true).is_ok());
    assert!(parse(&[INPUT_FLAG, "plan.json", ACTION_FLAG, "apply"]).is_err());
    assert!(parse(&[
        INPUT_FLAG,
        "plan.json",
        ACTION_FLAG,
        "check",
        ATTESTATION_FLAG,
        "cold.json"
    ])
    .is_err());
    assert!(parse(&[INPUT_FLAG, "plan.json", ACTION_FLAG, "check", "--safe-mode"]).is_err());
    assert!(parse(&[INPUT_FLAG, "plan.json", ACTION_FLAG, "check", "--validate"]).is_err());
    assert!(parse(&[ACTION_FLAG, "check"]).is_err());
    assert!(parse(&[
        INPUT_FLAG,
        "a.json",
        INPUT_FLAG,
        "b.json",
        ACTION_FLAG,
        "check"
    ])
    .is_err());
    assert!(parse(&[INPUT_FLAG, "plan.json", ACTION_FLAG, "check", "--config"]).is_err());
    assert!(parse(&[
        INPUT_FLAG,
        "plan.json",
        ACTION_FLAG,
        "check",
        "-c=ignored.yaml"
    ])
    .is_err());
    assert!(parse(&["--validate"]).unwrap().is_none());
    assert_eq!(
        parse(&[INPUT_FLAG, "-", ACTION_FLAG, "inspect"])
            .unwrap()
            .unwrap()
            .action,
        Action::Inspect
    );
    assert!(parse(&[INPUT_FLAG, "plan.json", ACTION_FLAG, "inspect"]).is_err());
}

#[test]
fn only_explicit_ephemeral_initialization_continues_ordinary_boot() {
    let start = parse(&[
        "--config=deploy.yaml",
        "--principal-transition=fresh.json",
        "--transition-action=initialize-fresh-and-serve",
    ])
    .unwrap()
    .unwrap();
    assert!(start.continues_serving());
    assert_eq!(start.input, Path::new("fresh.json"));
    assert!(start.validate_overlay_mode(true, false).is_ok());
    assert!(start.validate_overlay_mode(true, true).is_err());
    assert!(parse(&[
        INPUT_FLAG,
        "fresh.json",
        ACTION_FLAG,
        "initialize-fresh-and-serve",
        ATTESTATION_FLAG,
        "cold.json"
    ])
    .is_err());
    assert!(parse(&[
        INPUT_FLAG,
        "fresh.json",
        ACTION_FLAG,
        "initialize-fresh-and-serve",
        "--safe-mode"
    ])
    .is_err());
    for action in [
        "prepare",
        "check",
        "apply",
        "verify",
        "initialize-fresh",
        "reauthorize",
    ] {
        let mut args = vec![INPUT_FLAG, "receipt.json", ACTION_FLAG, action];
        if action == "apply" {
            args.extend([ATTESTATION_FLAG, "cold.json"]);
        }
        assert!(!parse(&args).unwrap().unwrap().continues_serving());
    }
    assert!(!parse(&[INPUT_FLAG, "-", ACTION_FLAG, "inspect"])
        .unwrap()
        .unwrap()
        .continues_serving());
}

#[test]
fn fresh_receipt_cannot_omit_namespace_creation_assertion() {
    let mut receipt = serde_json::json!({
        "version": 1,
        "store_config_sha256": "a".repeat(64),
        "requirements": [],
        "witness": null,
        "creation_evidence_sha256": "b".repeat(64),
        "sender_quiesced": true,
        "backend_quiesced": true,
        "ephemeral_instance": true,
        "exclusive_instance": true,
        "actor": "test owner",
        "reason": "explicit fresh instance"
    });
    assert!(serde_json::from_value::<transition::FreshNamespace>(receipt.clone()).is_err());
    receipt["newly_created_namespace"] = serde_json::Value::Bool(true);
    let explicit: transition::FreshNamespace = serde_json::from_value(receipt.clone()).unwrap();
    assert!(
        explicit.newly_created_namespace
            && explicit.ephemeral_instance
            && explicit.exclusive_instance
    );
    receipt
        .as_object_mut()
        .unwrap()
        .remove("exclusive_instance");
    let missing_exclusive: transition::FreshNamespace = serde_json::from_value(receipt).unwrap();
    assert!(!missing_exclusive.exclusive_instance);
}

#[test]
fn config_location_scanner_skips_transition_input_values() {
    // A filename equal to a flag must never retarget the real configuration scanner.
    let args = [INPUT_FLAG, "--config", ACTION_FLAG, "check"];
    assert_eq!(
        super::super::cli::value_flag(args.into_iter().map(str::to_owned), "--config", Some("-c")),
        None
    );
}

#[test]
fn fingerprint_is_stable_after_own_group_overlay_but_binds_other_settings() {
    let before = effective_fingerprint("source", None).unwrap();
    let mut after = OverlayDoc::default();
    after
        .groups
        .insert("self_new".into(), serde_json::from_str("{}").unwrap());
    after.version = config::overlay::OVERLAY_VERSION;
    assert_eq!(
        before,
        effective_fingerprint("source", Some(&after)).unwrap()
    );
    assert_ne!(
        before,
        effective_fingerprint("different-source", Some(&after)).unwrap()
    );
    after
        .named_maps
        .entry("identity-providers".into())
        .or_default()
        .insert("issuer".into(), serde_json::json!({"module": "changed"}));
    assert_ne!(
        before,
        effective_fingerprint("source", Some(&after)).unwrap()
    );
}

#[test]
fn runtime_groups_allow_only_the_plans_exact_personal_group_additions() {
    let deploy = config::deploy_from_yaml_str("store: { module: memory }\n").unwrap();
    let mut cfg = config::resolve(&deploy, &Default::default()).unwrap();
    let prefix = busbar_kernel::governance::SELF_KEY_GROUP_PREFIX;
    let old = format!("{prefix}old");
    let new = format!("{prefix}new");
    cfg.groups
        .insert(old.clone(), serde_json::from_str("{}").unwrap());
    cfg.groups
        .insert("shared".into(), serde_json::from_str("{}").unwrap());
    let plan: transition::Plan = serde_json::from_value(serde_json::json!({
        "specification": {
            "version": 1, "id": "group-binding-test",
            "bindings": [{"old_principal": "old", "new_principal": "new", "provider": "identity",
                "historical_provenance_sha256": "unused", "old_product_sha256": "unused"}],
            "complete_legacy_inventory_sha256": "unused", "requirements": [],
            "store_config_sha256": "unused", "effective_config_sha256": "unused",
            "witness": {"schema": "unused", "key_hex": "", "value_hex": ""}, "cutover": 1
        },
        "keys_before": [], "denylist_before": [], "groups_before": cfg.groups,
        "overlay_before": null, "carry": []
    }))
    .unwrap();
    check_groups(&plan, &cfg).unwrap();
    check_references(&plan.specification.bindings, &cfg).unwrap();
    let mut auth = config::AuthCfg::default_none();
    auth.role_bindings.insert(
        "identity".into(),
        std::collections::BTreeMap::from([(
            "member".into(),
            config::RoleBindingCfg {
                group: Some(old.clone()),
                ..Default::default()
            },
        )]),
    );
    cfg.auth = Some(auth);
    assert!(check_references(&plan.specification.bindings, &cfg).is_err());
    cfg.auth = None;
    cfg.groups.insert(new.clone(), cfg.groups[&old].clone());
    check_groups(&plan, &cfg).unwrap();
    cfg.groups.get_mut(&new).unwrap().enabled = false;
    assert!(check_groups(&plan, &cfg).is_err());
    cfg.groups.insert(new, cfg.groups[&old].clone());
    cfg.groups.get_mut("shared").unwrap().enabled = false;
    assert!(check_groups(&plan, &cfg).is_err());
}

#[test]
fn source_binding_rejects_changed_consumed_text_and_input_is_bounded() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-transition-input-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(dir.clone());
    let deploy = dir.join("config.yaml");
    let catalog = dir.join("providers.yaml");
    std::fs::write(&deploy, "listen: 127.0.0.1:8080\n").unwrap();
    std::fs::write(&catalog, "providers: {}\n").unwrap();
    let expected = Some(config::document_patch::SourceFingerprints::from_sources(
        "listen: 127.0.0.1:8080\n",
        "providers: {}\n",
    ));
    assert!(source_fingerprint(&deploy, &catalog, expected).is_ok());
    std::fs::write(&deploy, "listen: 127.0.0.1:9090\n").unwrap();
    assert!(source_fingerprint(&deploy, &catalog, expected).is_err());
    let oversized = std::fs::File::create(&deploy).unwrap();
    oversized.set_len(MAX_INPUT_BYTES + 1).unwrap();
    assert!(bounded_bytes(&deploy).is_err());
    assert!(bounded_bytes(&dir).is_err());
}

#[test]
fn cold_role_inventory_cannot_be_omitted_or_changed_and_own_overlay_remains_bound() {
    let deploy = config::deploy_from_yaml_str("store: { module: memory }\n").unwrap();
    let mut cfg = config::resolve(&deploy, &Default::default()).unwrap();
    let mut plan: transition::Plan = serde_json::from_value(serde_json::json!({
        "specification": {
            "version": 1, "id": "role-binding-test", "bindings": [],
            "complete_legacy_inventory_sha256": "a".repeat(64),
            "requirements": [{"provider": "identity", "plugin": "test.auth", "format": "v2",
                "domain_sha256": "a".repeat(64), "settings_sha256": "a".repeat(64), "product_sha256": "a".repeat(64)}],
            "store_config_sha256": "a".repeat(64), "effective_config_sha256": "a".repeat(64),
            "witness": {"schema": "test", "key_hex": "00", "value_hex": "01"}, "cutover": 1,
            "role_bindings_before": {"identity": {"old-role": {"allowed_pools": [], "admin_scope": "read-only"}}},
            "role_dispositions": [{"provider": "identity", "old_role": "old-role", "new_role": "new-role",
                "historical_provenance_sha256": "a".repeat(64), "old_product_sha256": "a".repeat(64)}]
        },
        "keys_before": [], "denylist_before": [], "groups_before": {}, "overlay_before": null, "carry": []
    })).unwrap();
    let mut auth = config::AuthCfg::default_none();
    auth.role_bindings = plan.specification.role_bindings_before.clone();
    cfg.auth = Some(auth);
    check_roles(&plan.specification, &cfg, false).unwrap();
    let after = transition::after_overlay(&plan).unwrap();
    assert_eq!(
        plan_effective_fingerprint("source", Some(&after), &plan).unwrap(),
        effective_fingerprint("source", None).unwrap()
    );
    assert_ne!(
        plan_effective_fingerprint("changed source", Some(&after), &plan).unwrap(),
        effective_fingerprint("source", None).unwrap()
    );
    cfg.auth.as_mut().unwrap().role_bindings =
        transition::role_bindings_after(&plan.specification).unwrap();
    check_roles(&plan.specification, &cfg, true).unwrap();
    assert!(check_roles(&plan.specification, &cfg, false).is_err());
    cfg.auth
        .as_mut()
        .unwrap()
        .role_bindings
        .get_mut("identity")
        .unwrap()
        .get_mut("new-role")
        .unwrap()
        .admin_scope = Some("full".into());
    assert!(check_roles(&plan.specification, &cfg, true).is_err());
    let mut changed_overlay = after.clone();
    changed_overlay
        .plugin_versions
        .insert("other".into(), "1.0.0".into());
    assert!(plan_effective_fingerprint("source", Some(&changed_overlay), &plan).is_err());
    let mut empty_overlay = OverlayDoc::default();
    empty_overlay.document_patch = Some(
        config::document_patch::DocumentPatch::from_value(serde_json::json!({"set": {}})).unwrap(),
    );
    plan.overlay_before = Some(empty_overlay);
    assert!(transition::after_overlay(&plan).is_ok());
    plan.specification.role_bindings_before.clear();
    plan.specification.role_dispositions.clear();
    assert!(check_roles(&plan.specification, &cfg, true).is_err());
}

#[test]
fn record_bootstrap_is_explicit_and_only_allowed_on_same_open_fresh_start() {
    let args = [
        INPUT_FLAG,
        "fresh.json",
        ACTION_FLAG,
        "initialize-fresh-and-serve",
        RECORD_BOOTSTRAP_FLAG,
        "a2a",
    ];
    let parsed = parse(&args).unwrap().unwrap();
    assert_eq!(parsed.record_bootstrap.as_deref(), Some("a2a"));
    assert!(parse(&[RECORD_BOOTSTRAP_FLAG, "a2a"]).is_err());
    for action in [
        "inspect",
        "initialize-fresh",
        "prepare",
        "verify",
        "reauthorize",
    ] {
        assert!(parse(&[
            INPUT_FLAG,
            "fresh.json",
            ACTION_FLAG,
            action,
            RECORD_BOOTSTRAP_FLAG,
            "a2a"
        ])
        .is_err());
    }
    let mut duplicate = args.to_vec();
    duplicate.extend([RECORD_BOOTSTRAP_FLAG, "another"]);
    assert!(parse(&duplicate).is_err());
}
