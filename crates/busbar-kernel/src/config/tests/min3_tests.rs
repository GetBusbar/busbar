// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::host_side::caller::Accept;

fn limits(yaml: &str) -> Result<InstanceLimitsCfg, String> {
    let doc: LimitsDoc = busbar_contract::yaml::from_str(yaml).map_err(|e| e.to_string())?;
    doc.resolve("store.main")
}

fn transport(yaml: &str) -> Result<InsecureTransport, String> {
    let doc: InsecureTransportDoc =
        busbar_contract::yaml::from_str(yaml).map_err(|e| e.to_string())?;
    doc.resolve("auth.corp-ldap")
}

#[test]
fn limits_parse_every_key() {
    let l = limits(
        "{ timeout_ms: 10000, connect_timeout_ms: 3000, max_inflight: 64, stream_stall_ms: 5000 }",
    )
    .expect("parses");
    assert_eq!(
        l,
        InstanceLimitsCfg {
            timeout_ms: 10_000,
            connect_timeout_ms: 3_000,
            max_inflight: 64,
            stream_stall_ms: 5_000
        }
    );
    assert_eq!(limits("{}").expect("empty"), InstanceLimitsCfg::default());
}

#[test]
fn limits_bounds_refuse_naming_the_key() {
    let err = limits("{ timeout_ms: 600001 }").expect_err("over 600,000 ms");
    assert!(err.contains("store.main.limits.timeout_ms"), "{err}");
    let err = limits("{ connect_timeout_ms: 700000 }").expect_err("over 600,000 ms");
    assert!(err.contains("limits.connect_timeout_ms"), "{err}");
    let err = limits("{ max_inflight: 65536 }").expect_err("over 65,535");
    assert!(err.contains("limits.max_inflight"), "{err}");
    assert_eq!(
        limits("{ max_inflight: 65535 }")
            .expect("limit")
            .max_inflight,
        65_535
    );
    let err = limits("{ stream_stall_ms: 999 }").expect_err("under 1,000");
    assert!(err.contains("limits.stream_stall_ms"), "{err}");
}

#[test]
fn limits_has_no_plaintext_key() {
    let err = limits("{ plaintext: deny }").expect_err("the row is deleted");
    assert!(err.contains("unknown field"), "{err}");
}

#[test]
fn insecure_transport_accepts_one_word_or_a_list() {
    let t = transport("{ accept: plaintext, reason: \"legacy db, CHG-12\" }").expect("parses");
    assert_eq!(t.accept, Accept(Accept::PLAINTEXT));
    assert_eq!(t.accept_words(), ["plaintext"]);
    let t = transport("{ accept: [plaintext, unverified_tls], reason: r }").expect("both");
    assert_eq!(t.accept, Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS));
    let t = transport("{ accept: [unverified_tls], reason: r }").expect("list of one");
    assert_eq!(t.accept, Accept(Accept::UNVERIFIED_TLS));
}

#[test]
fn insecure_transport_refusals_are_busbar_3163_naming_the_key() {
    for (yaml, key) in [
        ("{ accept: [], reason: r }", "accept"),
        ("{ accept: [plaintext, plaintext], reason: r }", "accept"),
        ("{ accept: plaintext }", "reason"),
        ("{ accept: plaintext, reason: \"\" }", "reason"),
        ("{ accept: plaintext, reason: \"  \" }", "reason"),
        (
            "{ accept: plaintext, reason: \"<why this instance needs it>\" }",
            "reason",
        ),
        ("{ accept: plaintext, reason: \"two\\nlines\" }", "reason"),
    ] {
        let err = transport(yaml).expect_err(yaml);
        assert!(err.starts_with("BUSBAR-3163"), "{yaml}: {err}");
        assert!(
            err.contains(&format!("auth.corp-ldap.insecure_transport.{key}")),
            "{yaml}: {err}"
        );
    }
    let long = format!("{{ accept: plaintext, reason: \"{}\" }}", "x".repeat(257));
    assert!(transport(&long).expect_err("257").contains("256"));
    let ok = format!("{{ accept: plaintext, reason: \"{}\" }}", "x".repeat(256));
    transport(&ok).expect("256 is the limit");
}

#[test]
fn insecure_transport_refuses_bad_words_and_unknown_keys() {
    assert!(transport("{ accept: yes, reason: r }").is_err());
    assert!(transport("{ accept: plaintext, reason: r, extra: 1 }")
        .expect_err("unknown key")
        .contains("unknown field"));
    assert!(transport("{ reason: r }").is_err(), "accept is required");
}

#[test]
fn the_warning_line_carries_the_instance_reason_and_removal_advice() {
    let t =
        transport("{ accept: unverified_tls, reason: \"AD DC cert expired\" }").expect("parses");
    let line = t.warning_line(
        "auth.corp-ldap",
        "ldap",
        &["dc1.corp:636 (tcp+tls, certificate not verified)".to_owned()],
    );
    assert!(line.starts_with("BUSBAR-3162: auth.corp-ldap (module ldap) runs with insecure_transport: accept unverified_tls for dc1.corp:636"), "{line}");
    assert!(line.contains("Reason: \"AD DC cert expired\"."), "{line}");
    assert!(
        line.ends_with(
            "Remove auth.corp-ldap.insecure_transport once the server offers verifiable TLS."
        ),
        "{line}"
    );
    let none = t.warning_line("auth.corp-ldap", "ldap", &[]);
    assert!(
        none.contains("no declared endpoint uses this yet"),
        "{none}"
    );
}

fn deploy(yaml: &str) -> crate::config::DeployCfg {
    crate::config::deploy_from_yaml_str(yaml, &crate::config::Grammar::empty())
        .unwrap_or_else(|e| panic!("the config parses: {e}"))
}

fn key(section: &str, name: &str) -> (Box<str>, Box<str>) {
    (section.into(), name.into())
}

const EVERY_KIND: &str = r#"
providers: {}
models: {}
store:
  module: postgres
  settings: { url: "postgres://db.internal/busbar" }
  limits: { timeout_ms: 5000, max_inflight: 32 }
secrets:
  vault:
    settings: { addr: "https://vault.internal:8200" }
    limits: { connect_timeout_ms: 2000 }
identity-providers:
  corp-ldap:
    module: ldap
    limits: { timeout_ms: 10000 }
hooks:
  pii:
    module: pii-scan
    limits: { max_inflight: 4 }
export:
  traces:
    module: otlp
    limits: { timeout_ms: 3000 }
"#;

/// IF §12.22: `limits` sits beside `module` in an instance block of any kind and is parsed per (section, name).
#[test]
fn parse_min3_reads_limits_beside_module_on_every_instance_kind() {
    let min3 = parse_min3(&deploy(EVERY_KIND)).expect("in bounds");
    let at = |section: &str, name: &str| min3.limits.get(&key(section, name)).copied();
    assert_eq!(
        at("store", "store"),
        Some(InstanceLimitsCfg {
            timeout_ms: 5_000,
            max_inflight: 32,
            ..InstanceLimitsCfg::default()
        })
    );
    assert_eq!(
        at("secrets", "vault").map(|l| l.connect_timeout_ms),
        Some(2_000)
    );
    assert_eq!(
        at("identity-providers", "corp-ldap").map(|l| l.timeout_ms),
        Some(10_000)
    );
    assert_eq!(at("hooks", "pii").map(|l| l.max_inflight), Some(4));
    assert_eq!(at("export", "traces").map(|l| l.timeout_ms), Some(3_000));
    assert_eq!(min3.limits.len(), 5);
}

/// IF §12.22 and TRANSPORT-SECURITY-POLICY §4: every refusal names the instance's path in the file and the key;
/// an `insecure_transport` refusal is BUSBAR-3163. One load reports every instance's refusal.
#[test]
fn limits_and_insecure_transport_refusals_name_the_instance_path() {
    let refused = parse_min3(&deploy(
        r#"
providers: {}
models: {}
store:
  module: postgres
  insecure_transport: { accept: plaintext }
secrets:
  far:
    limits: { timeout_ms: 700000 }
  plain:
    limits: { plaintext: deny }
hooks:
  web:
    module: webrequest
    insecure_transport: { accept: yes, reason: "loopback test hook" }
export:
  siem:
    module: otlp
    insecure_transport: { accept: plaintext, reason: "collector sidecar", until: 2027 }
"#,
    ))
    .err()
    .expect("refused");
    let has = |want: &str| refused.iter().any(|r| r.contains(want));
    assert!(has("secrets.far.limits.timeout_ms"), "{refused:?}");
    assert!(
        refused
            .iter()
            .any(|r| r.contains("secrets.plain.limits") && r.contains("plaintext")),
        "{refused:?}"
    );
    for want in [
        "BUSBAR-3163: store.insecure_transport.reason",
        "BUSBAR-3163: hooks.web.insecure_transport.accept",
        "BUSBAR-3163: export.siem.insecure_transport.until",
    ] {
        assert!(
            refused.iter().any(|r| r.starts_with(want)),
            "{want}: {refused:?}"
        );
    }
}

/// Policy §4: the acceptance lands in the instance's `InstanceLimits.accept` beside its limits, and neither key
/// reaches the plugin: the bag it is bound from is `settings` alone.
#[test]
fn insecure_transport_is_the_instance_s_accept_and_never_its_settings() {
    let deploy = deploy(
        r#"
providers: {}
models: {}
store:
  module: postgres
  settings: { url: "postgres://db.internal/busbar?sslmode=disable" }
  limits: { timeout_ms: 4000 }
  insecure_transport: { accept: plaintext, reason: "pg sidecar on the pod network, INFRA-142" }
secrets:
  vault:
    insecure_transport: { accept: [plaintext, unverified_tls], reason: "dev vault, CHG-9" }
"#,
    );
    let cfg = crate::config::resolve(&deploy, &std::collections::HashMap::new()).expect("resolves");
    let store = crate::appbuild::instance_limits(&cfg, "store", "store");
    assert_eq!(store.accept, Accept(Accept::PLAINTEXT));
    assert_eq!(store.timeout_ms, 4_000);
    let vault = crate::appbuild::instance_limits(&cfg, "secrets", "vault");
    assert_eq!(
        vault.accept,
        Accept(Accept::PLAINTEXT | Accept::UNVERIFIED_TLS)
    );
    assert_eq!(
        crate::appbuild::instance_limits(&cfg, "secrets", "other").accept,
        Accept::default(),
        "absent = verified TLS only"
    );
    assert_eq!(
        cfg.store.as_ref().expect("store").settings.key_names(),
        ["url"],
        "limits and insecure_transport are stripped before binding"
    );
}

const UPSTREAMS: &str = r#"
providers: {}
models: {}
upstreams:
  docs:
    url: https://docs.example/mcp
    auth: corp-outbound
    upstream_credentials: passthrough
  agent:
    url: https://agent.example/a2a
    auth: { bearer: { module: file, settings: { path: /run/agent-token } }, cache_max_s: 300 }
  search:
    url: https://search.example/api
    auth: { api_key: { header: X-Api-Key, secret: { module: file, settings: { path: /run/search-key } } } }
  local:
    command: { argv: [/opt/mcp/server] }
"#;

/// IF §12.1, §12.18: the top-level `upstreams:` section is config grammar, and each entry's `auth` and
/// `upstream_credentials` are parsed into the upstream's binding (the rest of the entry is W1-K1's).
#[test]
fn declared_registration_entries_carry_their_binding() {
    let upstreams = parsed_registrations(UPSTREAMS).expect("parses");
    let docs = &upstreams["docs"];
    assert!(
        matches!(
            &docs.auth,
            Some(UpstreamAuthCfg { form: UpstreamAuthForm::Instance(name), cache_max_s: None })
                if &**name == "corp-outbound"
        ),
        "the operator form names an auth instance"
    );
    assert_eq!(docs.upstream_credentials, Some(UpstreamCreds::Passthrough));
    assert!(matches!(
        &upstreams["agent"].auth,
        Some(UpstreamAuthCfg {
            form: UpstreamAuthForm::Bearer(SecretRef::Source(_)),
            cache_max_s: Some(300)
        })
    ));
    assert!(matches!(
        &upstreams["search"].auth,
        Some(UpstreamAuthCfg {
            form: UpstreamAuthForm::ApiKey { header, secret: SecretRef::Source(_) },
            cache_max_s: None
        }) if &**header == "X-Api-Key"
    ));
    assert!(
        upstreams["local"].auth.is_none(),
        "an upstream with neither key has no binding"
    );
}

/// IF §12.18: `auth` is an instance name or exactly one core-vocabulary form; anything else is refused naming
/// the upstream.
#[test]
fn an_upstream_auth_with_two_forms_or_an_unknown_one_is_refused() {
    let refused = parsed_registrations(
        r#"
providers: {}
models: {}
upstreams:
  two:
    url: https://two.example
    auth: { bearer: { module: file, settings: { path: /run/a } }, api_key: { header: X-Key, secret: { module: file, settings: { path: /run/b } } } }
  odd:
    url: https://odd.example
    auth: { basic: someone }
  creds:
    url: https://creds.example
    upstream_credentials: borrowed
"#,
    )
    .err()
    .expect("refused");
    for want in [
        "upstreams.two.auth",
        "upstreams.odd.auth",
        "upstreams.creds.upstream_credentials",
    ] {
        assert!(
            refused.iter().any(|r| r.contains(want)),
            "{want}: {refused:?}"
        );
    }
}

/// IF §12.1: a bad `upstreams.<name>` entry refuses the config at load (and so at `--validate`), not first at boot.
#[test]
fn a_bad_upstream_entry_refuses_the_config_at_load() {
    let refused = crate::upstreams::declared(
        "plane",
        &busbar_contract::json::json!({"servers":{"nowhere":{}}}),
        &["/servers/*"],
        &crate::plugin_config::upstream_anchor,
    )
    .err()
    .expect("refused at load");
    assert!(
        refused
            .iter()
            .any(|r| r.contains("plane/servers/nowhere") && r.contains("url:")),
        "{refused:?}"
    );
}

// These fixtures exercise core entry grammar; the former top-level section is no longer admitted.
fn parsed_registrations(yaml: &str) -> Result<BTreeMap<Box<str>, UpstreamCfg>, Vec<String>> {
    let doc: busbar_contract::yaml::Value = busbar_contract::yaml::from_str(yaml).unwrap();
    let section = busbar_contract::json::to_value(doc.get("upstreams").unwrap()).unwrap();
    let mut out = BTreeMap::new();
    let mut refused = Vec::new();
    for (name, entry) in section.as_object().unwrap() {
        match parse_upstream_entry(&format!("upstreams.{name}"), entry) {
            Ok(cfg) => {
                out.insert(Box::<str>::from(name), cfg);
            }
            Err(mut errors) => refused.append(&mut errors),
        }
    }
    if refused.is_empty() {
        Ok(out)
    } else {
        Err(refused)
    }
}

#[test]
fn top_level_upstreams_is_refused_with_registration_guidance() {
    let errors = crate::config::deploy_from_yaml_str(UPSTREAMS, &crate::config::Grammar::empty())
        .err()
        .expect("retired core key");
    assert!(errors.to_string().contains("registration"));
}

/// PRD-4: a 1.5.5-shaped config (every instance block with only its 1.5.5 keys) parses unchanged and carries no
/// MIN-3 key; every new key is additive.
#[test]
fn a_1_5_5_shaped_config_parses_and_carries_no_min3_keys() {
    let deploy = deploy(
        r#"
providers: {}
models: {}
store:
  module: sqlite
  settings: { db_path: /var/lib/busbar/busbar.db }
secrets:
  vault:
    settings: { addr: "https://vault.internal:8200" }
identity-providers:
  corp-ldap:
    module: ldap
    settings: { url: "ldaps://dc1.corp:636" }
hooks:
  pii:
    module: pii-scan
    timeout_ms: 20
export:
  metrics:
    module: prometheus
"#,
    );
    let min3 = parse_min3(&deploy).expect("nothing to refuse");
    assert!(min3 == Min3Config::default(), "no MIN-3 key was written");
}
