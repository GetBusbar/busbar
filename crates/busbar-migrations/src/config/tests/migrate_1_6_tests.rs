// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::config::migrate::migrate_config;
use busbar_contract::yaml::{self, prelude::*};

fn doc(text: &str) -> Value {
    let body: String = text
        .lines()
        .filter(|l| !l.starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    yaml::from_str(&body).expect("the migrated document parses")
}

#[test]
fn a_metadata_entry_naming_no_host_is_removed_and_reported() {
    let out = migrate_config(
        "store: { module: memory }\n\
         security:\n  blocked_metadata_hosts: ['169.254.169.254', 'db.1', 'metadata.corp']\n",
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["security"]["blocked_metadata_hosts"],
        serde_yaml::from_str::<serde_yaml::Value>("['169.254.169.254', 'metadata.corp']").unwrap(),
        "{}",
        out.yaml
    );
    let lines: Vec<_> = out
        .changes
        .iter()
        .filter(|c| c.starts_with("security.blocked_metadata_hosts: removed entry 'db.1'"))
        .collect();
    assert_eq!(lines.len(), 1, "{:?}", out.changes);
    assert!(lines[0].contains("never matched any destination on 1.5.5"));
}

/// BUSBAR-3411: the retired 1.5.5 cloud-metadata carve-outs are removed whatever they hold, every
/// entry that admitted something named in a warning; `blocked_metadata_hosts` stays.
#[test]
fn the_retired_metadata_carve_outs_are_removed_and_each_entry_is_named() {
    let out = migrate_config(
        "store: { module: memory }\n\
         security:\n  blocked_metadata_hosts: ['10.9.9.9']\n  \
         allow_metadata_hosts: ['169.254.169.254', 'imds.corp']\n  allow_all_metadata: true\n\
         providers:\n  gemini:\n    allow_metadata_hosts: ['169.254.170.2']\n  \
         other:\n    allow_metadata_hosts: []\n",
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    assert!(d["security"].get("allow_metadata_hosts").is_none(), "{}", out.yaml);
    assert!(d["security"].get("allow_all_metadata").is_none(), "{}", out.yaml);
    assert_eq!(d["security"]["blocked_metadata_hosts"][0], "10.9.9.9");
    for provider in ["gemini", "other"] {
        assert!(
            d["providers"][provider].get("allow_metadata_hosts").is_none(),
            "{}",
            out.yaml
        );
    }
    for (path, entry) in [
        ("security.allow_metadata_hosts", "169.254.169.254"),
        ("security.allow_metadata_hosts", "imds.corp"),
        ("security.allow_all_metadata", "true"),
        ("providers.gemini.allow_metadata_hosts", "169.254.170.2"),
    ] {
        assert!(
            out.warnings.iter().any(|w| w
                .starts_with(&format!("BUSBAR-3411: {path}: removed entry '{entry}'"))),
            "{path} {entry}: {:?}",
            out.warnings
        );
    }
    assert!(
        out.changes
            .iter()
            .any(|c| c.starts_with("BUSBAR-3411: providers.other.allow_metadata_hosts: removed")),
        "{:?}",
        out.changes
    );
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
    let rb = d.at("auth").at("role_bindings");
    assert!(
        rb.at("keys").is_null(),
        "the signed-key verifier needs no binding: {}",
        out.yaml
    );
    assert_eq!(
        rb.at("corp").at("*"),
        &Value::Map(Mapping::new().into()),
        "{}",
        out.yaml
    );
    assert_eq!(rb.at("sso").at("*"), &Value::Map(Mapping::new().into()));
    assert_eq!(
        rb.at("sso").at("eng").at("allowed_pools"),
        &yaml::from_str::<Value>("[fast]").unwrap(),
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
    let code = busbar_kernel::diagnostics::MIGRATE_UNGOVERNED_BINDING_ADDED.banner();
    assert!(out.yaml.contains(&format!(
        "# WARNING(migrate): {code}: auth.role_bindings.corp"
    )));

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

fn bindings(text: &str) -> busbar_kernel::config::RoleBindings {
    yaml::from_str(text).expect("bindings parse")
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

/// `allow_private: true` becomes an `advanced.allow_destinations` entry for exactly the hosts that
/// registration dials (its url and its token endpoint), never a wildcard or a network; the key is
/// gone, and the report says what replaced it.
#[test]
fn allow_private_becomes_exactly_the_registrations_hosts_in_the_one_allowlist() {
    let out = migrate_config(
        "store: { module: memory }\n\
         advanced:\n  allow_destinations: ['already.internal']\n\
         tools:\n  hooks: [pii-guard]\n  search:\n    url: https://MCP.tools.internal./mcp\n    \
         allow_private: true\n    token_exchange: { token_url: 'https://10.1.2.3:8443/token' }\n  \
         other:\n    url: https://already.internal/mcp\n    allow_private: true\n  \
         public:\n    url: https://mcp.example.com/mcp\n    allow_private: false\n\
         agents:\n  planner:\n    url: 'http://[fd00::7]:8080/a2a'\n    allow_private: true\n",
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["advanced"]["allow_destinations"],
        serde_yaml::from_str::<serde_yaml::Value>(
            "['already.internal', 'mcp.tools.internal', '10.1.2.3', 'fd00::7']"
        )
        .unwrap(),
        "{}",
        out.yaml
    );
    for at in [
        "tools.search",
        "tools.other",
        "tools.public",
        "agents.planner",
    ] {
        let (section, name) = at.split_once('.').unwrap();
        assert!(
            d[section][name].get("allow_private").is_none(),
            "{at}: {}",
            out.yaml
        );
    }
    assert_eq!(d["tools"]["hooks"][0], "pii-guard");
    let report = out.changes.join("\n");
    assert!(
        report.contains("BUSBAR-3410: tools.search.allow_private: replaced by advanced.allow_destinations: 'mcp.tools.internal'"),
        "{report}"
    );
    assert!(
        report.contains("BUSBAR-3410: tools.other.allow_private: removed; 'already.internal' is already listed"),
        "{report}"
    );
    assert!(
        report.contains("BUSBAR-3410: tools.public.allow_private: removed (it was not `true`"),
        "{report}"
    );
    assert!(
        out.warnings
            .iter()
            .any(|w| w.starts_with("BUSBAR-3410: agents.planner: `http://[fd00::7]:8080/a2a` is plaintext")
                && w.contains("refused at GA; use https")),
        "{:?}",
        out.warnings
    );
    assert!(
        !out.yaml.contains("*."),
        "no wildcard is ever written: {}",
        out.yaml
    );
}

/// A registration whose `allow_private` reached a cloud-metadata host keeps it refused: nothing is
/// listed, and the operator is told why.
#[test]
fn allow_private_never_lists_a_metadata_host() {
    let out = migrate_config(
        "store: { module: memory }\n\
         agents:\n  imds:\n    url: http://169.254.169.254/latest\n    allow_private: true\n  \
         gce:\n    url: https://metadata.google.internal/a2a\n    allow_private: true\n",
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    assert!(
        d.get("advanced")
            .and_then(|a| a.get("allow_destinations"))
            .is_none(),
        "{}",
        out.yaml
    );
    for name in ["imds", "gce"] {
        assert!(d["agents"][name].get("allow_private").is_none());
        assert!(
            out.warnings.iter().any(|w| w
                .starts_with(&format!("BUSBAR-3410: agents.{name}.allow_private: removed; "))
                && w.contains("cloud-metadata")),
            "{name}: {:?}",
            out.warnings
        );
    }
}

/// A plaintext registration to LOOPBACK keeps working at GA (the planes admit `http://` to loopback
/// only), so its host is listed with no plaintext warning; every line the retirement writes carries
/// BUSBAR-3410.
#[test]
fn allow_private_on_a_loopback_http_registration_lists_it_without_a_plaintext_warning() {
    let out = migrate_config(
        "store: { module: memory }\n\
         agents:\n  local:\n    url: 'http://127.0.0.1:9100/a2a'\n    allow_private: true\n\
         tools:\n  dev:\n    url: 'http://localhost:9200/mcp'\n    allow_private: true\n",
    )
    .expect("migrates");
    let d = doc(&out.yaml);
    assert_eq!(
        d["advanced"]["allow_destinations"],
        serde_yaml::from_str::<serde_yaml::Value>("['localhost', '127.0.0.1']").unwrap(),
        "{}",
        out.yaml
    );
    assert!(
        !out.warnings.iter().any(|w| w.contains("plaintext")),
        "{:?}",
        out.warnings
    );
    assert!(
        out.changes
            .iter()
            .filter(|c| c.contains("allow_private"))
            .all(|c| c.starts_with("BUSBAR-3410: ")),
        "{:?}",
        out.changes
    );
}
