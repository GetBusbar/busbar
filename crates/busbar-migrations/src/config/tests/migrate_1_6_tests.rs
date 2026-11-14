// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::migrate::migrate_config;

fn doc(yaml: &str) -> serde_yaml::Value {
    let body: String = yaml
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    serde_yaml::from_str(&body).expect("the migrated document parses")
}

#[test]
fn a_metadata_entry_naming_no_host_is_removed_and_reported() {
    let out = migrate_config(
        "store: { module: memory }\n\
         security:\n  blocked_metadata_hosts: ['169.254.169.254', 'db.1', 'metadata.corp']\n  \
         allow_metadata_hosts: ['1.2.3.4.5']\n",
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    let blocked = &d["security"]["blocked_metadata_hosts"];
    assert_eq!(
        blocked,
        &serde_yaml::from_str::<serde_yaml::Value>("['169.254.169.254', 'metadata.corp']").unwrap(),
        "{}",
        out.yaml
    );
    assert_eq!(
        d["security"]["allow_metadata_hosts"],
        serde_yaml::from_str::<serde_yaml::Value>("[]").unwrap()
    );
    for (key, entry) in [
        ("security.blocked_metadata_hosts", "db.1"),
        ("security.allow_metadata_hosts", "1.2.3.4.5"),
    ] {
        let lines: Vec<_> = out
            .changes
            .iter()
            .filter(|c| c.starts_with(&format!("{key}: removed entry '{entry}'")))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "one change line for {entry}: {:?}",
            out.changes
        );
        assert!(lines[0].contains("never matched any destination on 1.5.5"));
    }
}

#[test]
fn a_provider_1_5_5_admitted_ungoverned_gains_the_ungoverned_binding_and_a_warning() {
    let out = migrate_config(
        "store: { module: memory }\n\
         identity-providers:\n  corp: { module: header, settings: {} }\n  sso: { module: oidc }\n\
         auth:\n  chain: [keys, corp, sso]\n  \
         role_bindings:\n    sso:\n      eng: { allowed_pools: [fast] }\n",
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    let rb = &d["auth"]["role_bindings"];
    assert!(
        rb["keys"].is_null(),
        "the signed-key verifier needs no binding: {}",
        out.yaml
    );
    assert_eq!(
        rb["corp"]["*"],
        serde_yaml::Value::Mapping(Default::default()),
        "{}",
        out.yaml
    );
    assert_eq!(
        rb["sso"]["*"],
        serde_yaml::Value::Mapping(Default::default())
    );
    assert_eq!(
        rb["sso"]["eng"]["allowed_pools"],
        serde_yaml::from_str::<serde_yaml::Value>("[fast]").unwrap(),
        "an operator's own binding is kept as written"
    );
    assert!(out
        .changes
        .iter()
        .any(|c| c.starts_with("auth.role_bindings.corp.\"*\": added")
            && c.contains("every principal it identifies")));
    assert!(out
        .changes
        .iter()
        .any(|c| c.starts_with("auth.role_bindings.sso.\"*\": added")
            && c.contains("asserts no roles")));
    assert_eq!(
        out.warnings
            .iter()
            .filter(|w| w.contains("keep 1.5.5's access") && w.contains("Tighten it"))
            .count(),
        2,
        "{:?}",
        out.warnings
    );
    assert!(out
        .yaml
        .contains("# WARNING(migrate): auth.role_bindings.corp"));

    let again = migrate_config(&out.yaml).expect("migrates again");
    assert!(
        !again.changes.iter().any(|c| c.contains("role_bindings")),
        "{:?}",
        again.changes
    );
}

fn principal(roles: &[&str]) -> busbar_kernel::auth::Principal {
    busbar_kernel::auth::Principal {
        id: "u-1".into(),
        name: None,
        roles: roles.iter().map(|r| r.to_string()).collect(),
        ttl_secs: None,
    }
}

fn bindings(yaml: &str) -> busbar_kernel::config::RoleBindings {
    serde_yaml::from_str(yaml).expect("bindings parse")
}

#[test]
fn the_ungoverned_role_binds_exactly_whom_1_5_5_admitted_ungoverned() {
    use busbar_kernel::governance::synthesize_bound_key;

    let only = bindings("corp: { '*': {} }");
    for roles in [&[][..], &["eng"][..]] {
        let key = synthesize_bound_key("corp", &principal(roles), &only)
            .unwrap_or_else(|| panic!("roles {roles:?} are admitted"));
        assert!(key.group.is_none(), "no group, no budget");
    }

    let mixed = bindings("sso: { eng: { allowed_pools: [fast] }, '*': {} }");
    assert!(synthesize_bound_key("sso", &principal(&[]), &mixed).is_some());
    let eng = synthesize_bound_key("sso", &principal(&["eng"]), &mixed).expect("eng admitted");
    let narrow = synthesize_bound_key(
        "sso",
        &principal(&["eng"]),
        &bindings("sso: { eng: { allowed_pools: [fast] } }"),
    )
    .expect("eng admitted");
    assert_eq!(
        eng.allowed_scopes, narrow.allowed_scopes,
        "eng keeps exactly its own grant"
    );
    assert!(
        synthesize_bound_key("sso", &principal(&["ops"]), &mixed).is_none(),
        "1.5.5 refused a principal whose roles the table does not bind; so does this"
    );

    assert!(synthesize_bound_key("sso", &principal(&[]), &bindings("sso: { eng: {} }")).is_none());
}

/// A root `rate_card.<model>.cache_write_utok: 0` is 1.5.5's "no separate write tariff": every YAML
/// path removes it (writes then price at `input_utok`, never 0) with one change line and one
/// notice. `cache_read_utok: 0`, an explicit write rate and a plane block are left as written.
#[test]
fn unfold_zero_cache_write_on_every_yaml_path() {
    use crate::config::migrate::{migrate_config_with, MigrateOutput};
    use crate::config::migrate_plugins::NoPlugins;
    const LINE: &str = "rate_card.m.cache_write_utok: 0 removed (1.5.5 spelling of 'no separate \
                        write tariff'); cache writes price at input_utok";
    const CARD: &str = "rate_card:\n  m: {input_utok: 2.5, output_utok: 10, cache_read_utok: 0, \
                        cache_write_utok: 0}\n";
    let unfolded = |path: &str, out: &MigrateOutput| {
        let d = doc(&out.yaml);
        let entry = &d["rate_card"]["m"];
        assert!(
            entry.get("cache_write_utok").is_none(),
            "{path}: the 1.5.5 zero is removed:\n{}",
            out.yaml
        );
        assert_eq!(
            entry["cache_read_utok"],
            serde_yaml::Value::from(0),
            "{path}"
        );
        assert_eq!(entry["input_utok"], serde_yaml::Value::from(2.5), "{path}");
        assert_eq!(
            out.changes.iter().filter(|c| *c == LINE).count(),
            1,
            "{path}: one change line: {:?}",
            out.changes
        );
        assert_eq!(out.notices, [LINE], "{path}: one notice");
    };

    let memory = format!("store: {{ module: memory }}\n{CARD}");
    let out = migrate_config_with(&memory, &NoPlugins).expect("migrates");
    unfolded("--migrate-config", &out);
    let out = crate::config::normalize_authored_with_detection(&memory, None, &NoPlugins)
        .expect("fast path normalizes");
    unfolded("startup fast path", &out);
    let out =
        crate::config::normalize_authored(CARD, &NoPlugins).expect("structural branch normalizes");
    unfolded("startup structural branch", &out);
    let legacy =
        format!("config: {{ overlay: overlay.json }}\nstore: {{ module: memory }}\n{CARD}");
    let proof = crate::config::recognize_authored_schema(&legacy)
        .expect("detects")
        .expect("a legacy root grammar");
    let out = crate::config::normalize_historical_config(&proof, &legacy, &NoPlugins)
        .expect("historical normalizes");
    unfolded("startup legacy root", &out);

    // A rerun on the output is a no-op; a re-stated 0 is removed again with the same line.
    let first = migrate_config_with(&memory, &NoPlugins).expect("migrates");
    let again = migrate_config_with(&first.yaml, &NoPlugins).expect("reruns");
    assert!(
        !again.changes.iter().any(|c| c.contains("cache_write_utok")),
        "{:?}",
        again.changes
    );
    assert!(again.notices.is_empty());
    let restated = migrate_config_with(&memory, &NoPlugins).expect("reruns a re-stated zero");
    unfolded("rerun on a re-stated 0", &restated);

    // An explicit write rate and a plane `rate_card:` block are untouched.
    let out = migrate_config_with(
        "store: { module: memory }\n\
         rate_card:\n  m: {input_utok: 2.5, output_utok: 10, cache_write_utok: 3.125}\n\
         llm:\n  rate_card:\n    m: {input_utok: 2.5, cache_write_utok: 0}\n",
        &NoPlugins,
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["rate_card"]["m"]["cache_write_utok"],
        serde_yaml::Value::from(3.125)
    );
    assert_eq!(
        d["llm"]["rate_card"]["m"]["cache_write_utok"],
        serde_yaml::Value::from(0)
    );
    assert!(out.notices.is_empty(), "{:?}", out.notices);
}
