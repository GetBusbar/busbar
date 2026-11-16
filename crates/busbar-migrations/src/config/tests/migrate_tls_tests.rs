// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

struct Run {
    yaml: Value,
    changes: Vec<String>,
    todos: Vec<String>,
}

fn run(yaml: &str) -> Run {
    let mut root: Pairs = busbar_contract::yaml::mapping_from_str(yaml)
        .expect("yaml")
        .into();
    let (mut changes, mut todos, mut failures) = (Vec::new(), Vec::new(), Vec::new());
    apply(
        &mut root,
        &mut Ledger {
            changes: &mut changes,
            todos: &mut todos,
            failures: &mut failures,
        },
    );
    assert!(failures.is_empty(), "{failures:?}");
    Run {
        yaml: Value::Map(root),
        changes,
        todos,
    }
}

fn dests(r: &Run) -> Vec<Value> {
    r.yaml
        .get(key("advanced"))
        .and_then(|a| a.get(key("tls")))
        .and_then(|t| t.get(key("destinations")))
        .and_then(Value::as_sequence)
        .cloned()
        .unwrap_or_default()
}

const PEM: &str = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";

#[test]
fn each_plugin_ca_becomes_an_exact_host_destination_entry() {
    let r = run(&format!(
        "identity-providers:\n  corp:\n    module: ldap\n    url: ldaps://ldap.corp.internal:636\n    ca_cert_pem: {PEM:?}\n  gh:\n    module: github\n    api_base: https://ghe.corp.internal/api/v3\n    authorize_base: https://ghe.corp.internal\n    ca_cert_pem: {PEM:?}\nsecrets:\n  v:\n    module: vault\n    settings: {{ addr: 'https://vault.corp.internal:8200', ca_cert_pem: {PEM:?} }}\n"
    ));
    let d = dests(&r);
    let matches: Vec<&str> = d
        .iter()
        .filter_map(|e| e.get(key("match")).and_then(Value::as_str))
        .collect();
    assert_eq!(
        matches,
        [
            "ldap.corp.internal",
            "ghe.corp.internal",
            "vault.corp.internal"
        ]
    );
    assert!(
        r.changes.iter().all(|c| c.starts_with("BUSBAR-3415")),
        "{:?}",
        r.changes
    );
    let ldap = r
        .yaml
        .at("identity-providers")
        .at("corp")
        .as_mapping()
        .expect("map");
    assert!(
        ldap.get_key(key("ca_cert_pem")).is_none(),
        "the plugin key is removed"
    );
    let again = run(&busbar_contract::yaml::to_string(&r.yaml).expect("yaml"));
    assert!(again.changes.is_empty(), "idempotent: {:?}", again.changes);
    assert_eq!(dests(&again).len(), 3);
}

#[test]
fn a_referenced_ca_and_oidc_discovered_hosts_become_todos() {
    let r = run(
        "identity-providers:\n  sso:\n    module: oidc\n    issuer: https://login.corp.internal\n    ca_cert_pem: \"-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----\\n\"\n  ref:\n    module: ldap\n    url: ldaps://ldap.corp.internal\n    ca_cert_pem: { env: LDAP_CA }\n",
    );
    assert!(
        r.todos.iter().any(|t| t.starts_with("BUSBAR-3416")),
        "{:?}",
        r.todos
    );
    assert!(
        r.todos
            .iter()
            .any(|t| t.starts_with("BUSBAR-3415") && t.contains("reference")),
        "{:?}",
        r.todos
    );
    assert_eq!(dests(&r).len(), 1, "only the literal CA is copied");
}

#[test]
fn ldap_insecure_transport_is_removed_with_a_todo() {
    let r = run("identity-providers:\n  corp:\n    module: ldap\n    url: ldap://ldap.corp.internal\n    allow_insecure_transport: true\n");
    assert!(r
        .yaml
        .at("identity-providers")
        .at("corp")
        .get(key("allow_insecure_transport"))
        .is_none());
    assert!(
        r.todos.iter().any(|t| t.starts_with("BUSBAR-3417")),
        "{:?}",
        r.todos
    );
}

#[test]
fn postgres_opportunistic_sslmode_becomes_require_and_disable_gets_a_plaintext_entry() {
    for (url, want) in [
        (
            "postgres://u:p\x40db.internal:5432/busbar",
            "postgres://u:p\x40db.internal:5432/busbar?sslmode=require",
        ),
        (
            "postgres://u:p\x40db.internal/busbar?sslmode=prefer&x=1",
            "postgres://u:p\x40db.internal/busbar?x=1&sslmode=require",
        ),
        (
            "postgres://u:p\x40db.internal/busbar?sslmode=verify-full",
            "postgres://u:p\x40db.internal/busbar?sslmode=verify-full",
        ),
    ] {
        let r = run(&format!(
            "store:\n  module: postgres\n  settings: {{ url: '{url}' }}\n"
        ));
        assert_eq!(
            r.yaml.at("store").at("settings").at("url").as_str(),
            Some(want),
            "{url}"
        );
    }
    let r = run("store:\n  module: postgres\n  settings: { url: 'postgres://u@\x310.0.0.9/busbar?sslmode=disable' }\n");
    assert!(
        r.changes.iter().any(|c| c.starts_with("BUSBAR-3414")),
        "{:?}",
        r.changes
    );
    assert_eq!(dests(&r)[0].at("match").as_str(), Some("\x310.0.0.9"));
    let r = run("store:\n  module: postgres\n  settings: { url: 'postgres://u@127.0.0.1/busbar?sslmode=disable' }\n");
    assert!(dests(&r).is_empty(), "loopback needs no entry");
    let r = run("store:\n  module: postgres\n  settings: { url: { env: PG_URL } }\n");
    assert!(
        r.todos.iter().any(|t| t.starts_with("BUSBAR-3412")),
        "{:?}",
        r.todos
    );
}

#[test]
fn valkey_insecure_is_removed_and_a_credentialed_plaintext_url_is_a_todo() {
    let r = run("store:\n  module: valkey\n  settings: { url: 'rediss://cache.internal:6380/0#insecure' }\n");
    assert_eq!(
        r.yaml.at("store").at("settings").at("url").as_str(),
        Some("rediss://cache.internal:6380/0")
    );
    assert!(
        r.changes.iter().any(|c| c.starts_with("BUSBAR-3413")),
        "{:?}",
        r.changes
    );
    let r = run(
        "store:\n  module: valkey\n  settings: { url: 'redis://:pw\x40cache.internal:6379/0' }\n",
    );
    assert!(
        r.todos.iter().any(|t| t.starts_with("BUSBAR-3146")),
        "{:?}",
        r.todos
    );
    assert!(dests(&r).is_empty());
    let r =
        run("store:\n  module: valkey\n  settings: { url: 'redis://\x310.255.255.1:6379/0' }\n");
    assert!(
        r.todos.iter().any(|t| t.starts_with("BUSBAR-3141")),
        "{:?}",
        r.todos
    );
    assert!(dests(&r).is_empty());
}

#[test]
fn mcp_tool_ca_moves_and_its_client_identity_stays() {
    let r = run(&format!(
        "tools:\n  t:\n    url: https://mcp.corp.internal/mcp\n    tls: {{ ca_cert_pem: {PEM:?}, client_identity: {{ cert: x, key: y }} }}\n"
    ));
    assert_eq!(dests(&r)[0].at("match").as_str(), Some("mcp.corp.internal"));
    assert!(r
        .yaml
        .at("tools")
        .at("t")
        .at("tls")
        .get(key("client_identity"))
        .is_some());
    assert!(r
        .yaml
        .at("tools")
        .at("t")
        .at("tls")
        .get(key("ca_cert_pem"))
        .is_none());
}
