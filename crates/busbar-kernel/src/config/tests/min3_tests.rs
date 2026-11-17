// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::json::JsonValueTrait as _;
use busbar_plugin_abi::host_side::caller::Accept;

#[test]
fn outbound_credential_policy_uses_adopted_defaults_and_retains_overrides() {
    assert_eq!(
        parse_min3(&deploy("providers: {}\nmodels: {}\n"))
            .unwrap()
            .outbound,
        crate::custody::CredPolicy::DEFAULT
    );
    let cfg = deploy("providers: {}\nmodels: {}\nauth: {outbound: {refresh_ahead_s: 0, min_mint_interval_s: 60, mint_deadline_s: 120, max_keys_per_instance: 17, max_hold_s: 604800}}\n");
    let policy = parse_min3(&cfg).unwrap().outbound;
    assert_eq!(policy.refresh_ahead_s, 0);
    assert_eq!(policy.min_mint_interval_s, 60);
    assert_eq!(policy.mint_deadline_s, 120);
    assert_eq!(policy.max_keys_per_instance, 17);
    assert_eq!(policy.max_hold_s, 604800);
    let mut errors = Vec::new();
    let auth = crate::config::resolve_auth(
        cfg.auth.as_ref().unwrap(),
        &cfg.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty());
    let authored = serde_json::to_value(auth.authoring(&crate::seal::acquire())).unwrap();
    assert_eq!(
        authored["outbound"],
        serde_json::json!({"refresh_ahead_s":0,"min_mint_interval_s":60,"mint_deadline_s":120,"max_keys_per_instance":17,"max_hold_s":604800})
    );
    let partial = parse_min3(&deploy(
        "providers: {}\nmodels: {}\nauth: {outbound: {max_keys_per_instance: 2}}\n",
    ))
    .unwrap();
    assert_eq!(
        partial.outbound.refresh_ahead_s,
        crate::custody::CredPolicy::DEFAULT.refresh_ahead_s
    );
}

#[test]
fn outbound_credential_policy_refuses_invalid_types_and_adopted_bounds() {
    for value in [
        "null",
        "[]",
        "{refresh_ahead_s: -1}",
        "{mint_deadline_s: 1.5}",
        "{max_hold_s: null}",
        "{unknown: 1}",
        "{max_keys_per_instance: 4294967296}",
    ] {
        let yaml = format!("providers: {{}}\nmodels: {{}}\nauth: {{outbound: {value}}}\n");
        assert!(
            crate::config::deploy_from_yaml_str(&yaml, &crate::config::Grammar::empty()).is_err(),
            "{value}"
        );
    }
    for (key, value) in [
        ("refresh_ahead_s", 3601),
        ("min_mint_interval_s", 0),
        ("min_mint_interval_s", 61),
        ("mint_deadline_s", 0),
        ("mint_deadline_s", 121),
        ("max_keys_per_instance", 0),
        ("max_hold_s", 59),
        ("max_hold_s", 604801),
    ] {
        let yaml =
            format!("providers: {{}}\nmodels: {{}}\nauth: {{outbound: {{{key}: {value}}}}}\n");
        let errors = parse_min3(&deploy(&yaml))
            .err()
            .expect("invalid range refused");
        assert!(errors
            .iter()
            .any(|why| why.contains(&format!("auth.outbound.{key}"))));
    }
}

#[test]
fn unknown_key_refresh_policy_keeps_adopted_default_and_minimum() {
    assert_eq!(
        parse_min3(&deploy("providers: {}\nmodels: {}\n"))
            .unwrap()
            .unknown_key_refresh_s,
        30
    );
    for (written, expected) in [(0, 5), (4, 5), (5, 5), (17, 17)] {
        let cfg = deploy(&format!(
            "providers: {{}}\nmodels: {{}}\nauth: {{unknown_key_refresh_s: {written}}}\n"
        ));
        assert_eq!(parse_min3(&cfg).unwrap().unknown_key_refresh_s, expected);
    }
    for value in ["null", "-1", "1.5", "[]"] {
        let yaml =
            format!("providers: {{}}\nmodels: {{}}\nauth: {{unknown_key_refresh_s: {value}}}\n");
        assert!(
            crate::config::deploy_from_yaml_str(&yaml, &crate::config::Grammar::empty()).is_err()
        );
    }
}

#[test]
fn issued_kind_grants_are_explicit_per_configured_provider() {
    let cfg = deploy("providers: {}\nmodels: {}\nidentity-providers:\n  none: {module: verifier}\n  empty: {module: verifier, issued_kinds: []}\n  allowed: {module: verifier, issued_kinds: [signed]}\n");
    let parsed = parse_min3(&cfg).unwrap();
    assert!(!parsed.issued_kinds.contains_key("none"));
    assert!(parsed.issued_kinds.get("empty").unwrap().is_empty());
    assert_eq!(
        parsed
            .issued_kinds
            .get("allowed")
            .unwrap()
            .iter()
            .map(AsRef::as_ref)
            .collect::<Vec<&str>>(),
        ["signed"]
    );
    let authored =
        serde_json::to_value(cfg.identity_providers["allowed"].authoring(&crate::seal::acquire()))
            .unwrap();
    assert_eq!(authored["issued_kinds"], serde_json::json!(["signed"]));
    assert!(authored["settings"].get("issued_kinds").is_none());
}

#[test]
fn issued_kind_grants_reject_null_nontext_blank_and_duplicates() {
    for value in ["null", "signed", "[null]", "[1]", "{}"] {
        let yaml = format!("providers: {{}}\nmodels: {{}}\nidentity-providers:\n  verifier: {{module: verifier, issued_kinds: {value}}}\n");
        assert!(
            crate::config::deploy_from_yaml_str(&yaml, &crate::config::Grammar::empty()).is_err(),
            "{value}"
        );
    }
    for value in ["['']", "['  ']", "[signed, signed]"] {
        let yaml = format!("providers: {{}}\nmodels: {{}}\nidentity-providers:\n  verifier: {{module: verifier, issued_kinds: {value}}}\n");
        let errors = parse_min3(&deploy(&yaml))
            .err()
            .expect("invalid grant refused");
        assert!(errors
            .iter()
            .any(|why| why.contains("identity-providers.verifier.issued_kinds")));
    }
}

#[test]
fn verdict_cache_policy_uses_adopted_defaults_and_explicit_overrides() {
    let defaults = parse_min3(&deploy("providers: {}\nmodels: {}\n")).unwrap();
    assert_eq!(
        defaults.verdict_cache,
        crate::auth::verdicts::VerdictPolicy::DEFAULT
    );
    let configured = parse_min3(&deploy(
        "providers: {}\nmodels: {}\nauth:\n  verdict_cache:\n    default_ttl_s: 17\n    max_ttl_s: 40\n    max_entries: 0\n    max_identity_bytes: 1024\n",
    ))
    .unwrap();
    assert_eq!(configured.verdict_cache.default_ttl_s, 17);
    assert_eq!(configured.verdict_cache.max_ttl_s, 40);
    assert_eq!(configured.verdict_cache.max_entries, 0);
    assert_eq!(configured.verdict_cache.max_identity_bytes, 1024);
    let partial = parse_min3(&deploy(
        "providers: {}\nmodels: {}\nauth: {verdict_cache: {max_entries: 13}}\n",
    ))
    .unwrap();
    assert_eq!(partial.verdict_cache.max_entries, 13);
    assert_eq!(partial.verdict_cache.default_ttl_s, 300);
    assert_eq!(partial.verdict_cache.max_ttl_s, 3600);
    assert_eq!(partial.verdict_cache.max_identity_bytes, 8192);
}

#[test]
fn verdict_cache_policy_rejects_invalid_types_keys_and_ttl_range() {
    for value in [
        "null",
        "[]",
        "{max_entries: -1}",
        "{max_entries: 1.5}",
        "{max_entries: 4294967296}",
        "{max_entries: null}",
        "{unexpected: 1}",
    ] {
        let yaml = format!("providers: {{}}\nmodels: {{}}\nauth: {{verdict_cache: {value}}}\n");
        assert!(
            crate::config::deploy_from_yaml_str(&yaml, &crate::config::Grammar::empty()).is_err(),
            "invalid cache policy must refuse: {value}"
        );
    }
    for max in [0, 86_401] {
        let yaml = format!(
            "providers: {{}}\nmodels: {{}}\nauth: {{verdict_cache: {{max_ttl_s: {max}}}}}\n"
        );
        let errors = parse_min3(&deploy(&yaml)).err().expect("TTL range refused");
        assert!(errors
            .iter()
            .any(|error| error.contains("auth.verdict_cache.max_ttl_s")));
    }
}

#[test]
fn verdict_cache_overrides_survive_resolved_auth_authoring() {
    let deploy = deploy(
        "providers: {}\nmodels: {}\nauth: {chain: [], admin_auth: [], verdict_cache: {default_ttl_s: 0, max_ttl_s: 86400, max_entries: 7, max_identity_bytes: 512}}\n",
    );
    let mut errors = Vec::new();
    let auth = crate::config::resolve_auth(
        deploy.auth.as_ref().expect("auth configured"),
        &deploy.identity_providers,
        &mut errors,
    );
    assert!(errors.is_empty());
    let authored = serde_json::to_value(auth.authoring(&crate::seal::acquire())).unwrap();
    assert_eq!(
        authored["verdict_cache"],
        serde_json::json!({
            "default_ttl_s": 0,
            "max_ttl_s": 86400,
            "max_entries": 7,
            "max_identity_bytes": 512
        })
    );
}

fn transport(yaml: &str) -> Result<InsecureTransport, String> {
    let doc: InsecureTransportDoc =
        busbar_contract::yaml::from_str(yaml).map_err(|e| e.to_string())?;
    doc.resolve("auth.corp-ldap")
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

/// TRANSPORT-SECURITY-POLICY §4: every refusal names the instance's path in the file and the key;
/// an `insecure_transport` refusal is BUSBAR-3163. One load reports every instance's refusal.
#[test]
fn insecure_transport_refusals_name_the_instance_path() {
    let refused = parse_min3(&deploy(
        r#"
providers: {}
models: {}
store:
  module: postgres
  insecure_transport: { accept: plaintext }
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

/// Policy §4: the acceptance lands in the instance's `InstanceLimits.accept`, and the key
/// never reaches the plugin: the bag it is bound from is `settings` alone.
#[test]
fn insecure_transport_is_the_instance_s_accept_and_never_its_settings() {
    let deploy = deploy(
        r#"
providers: {}
models: {}
store:
  module: postgres
  settings: { url: "postgres://db.internal/busbar?sslmode=disable" }
  insecure_transport: { accept: plaintext, reason: "pg sidecar on the pod network, INFRA-142" }
secrets:
  vault:
    insecure_transport: { accept: [plaintext, unverified_tls], reason: "dev vault, CHG-9" }
"#,
    );
    let cfg = crate::config::resolve(&deploy, &std::collections::HashMap::new()).expect("resolves");
    let store = crate::appbuild::instance_limits(&cfg, "store", "store");
    assert_eq!(store.accept, Accept(Accept::PLAINTEXT));
    assert_eq!(store.timeout_ms, 0, "no limits key: the kind's default");
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
        "insecure_transport is stripped before binding"
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

/// `<kind>.<name>.limits` is not a config key: an instance block of every kind that carries it is refused as an
/// unknown field naming `limits` (an instance runs at its kind's defaults; `insecure_transport` stays).
#[test]
fn a_limits_key_on_any_instance_is_refused_as_unknown() {
    for (kind, block) in [
        (
            "store",
            "store:\n  module: sqlite\n  limits: { timeout_ms: 5000 }\n",
        ),
        (
            "secrets",
            "secrets:\n  vault:\n    limits: { connect_timeout_ms: 2000 }\n",
        ),
        (
            "identity-providers",
            "identity-providers:\n  corp-ldap:\n    module: ldap\n    limits: { max_inflight: 4 }\n",
        ),
        (
            "hooks",
            "hooks:\n  pii:\n    module: pii-scan\n    limits: { stream_stall_ms: 5000 }\n",
        ),
        (
            "export",
            "export:\n  traces:\n    module: otlp\n    limits: { timeout_ms: 3000 }\n",
        ),
    ] {
        let yaml = format!("providers: {{}}\nmodels: {{}}\n{block}");
        let refused = crate::config::deploy_from_yaml_str(&yaml, &crate::config::Grammar::empty())
            .err()
            .unwrap_or_else(|| panic!("{kind}: `limits` is accepted"));
        let text = refused.to_string();
        assert!(
            text.contains("limits") && text.contains("unknown field"),
            "{kind}: {text}"
        );
    }
}

/// A 1.5.5-shaped config still parses with the key gone: the hook keeps its 1.5.5 `timeout_ms`, and
/// `insecure_transport` (kept) lands in the instance's `accept` while every number stays the kind's default.
#[test]
fn a_1_5_5_shaped_config_with_hook_timeout_ms_parses_and_instances_run_at_kind_defaults() {
    let deploy = deploy(
        r#"
providers: {}
models: {}
store:
  module: sqlite
  settings: { db_path: /var/lib/busbar/busbar.db }
hooks:
  pii:
    module: pii-scan
    timeout_ms: 20
"#,
    );
    assert_eq!(deploy.hooks["pii"].timeout_ms, Some(20));
    let cfg = crate::config::resolve(&deploy, &std::collections::HashMap::new()).expect("resolves");
    let store = crate::appbuild::instance_limits(&cfg, "store", "store");
    assert_eq!(
        (
            store.timeout_ms,
            store.connect_timeout_ms,
            store.max_inflight
        ),
        (0, 0, 0),
        "0 is the kind's default in every number"
    );
}

fn provisioning_deploy(block: &str) -> crate::config::DeployCfg {
    deploy(&format!(
        "identity-providers:\n  scim:\n    module: directory\n    provisioning: {block}\n"
    ))
}

#[test]
fn provisioning_reads_clients_link_and_guard_outside_plugin_settings() {
    let deploy = provisioning_deploy("{clients: ['Client A'], link: {index: email, auth: [corp], refresh_ms: 1000}, guard: {max: 50, window_s: 3600}}");
    let parsed = parse_provisioning(&deploy).expect("approved provisioning grammar");
    assert_eq!(parsed.len(), 1);
    let cfg = parsed.get("scim").expect("configured instance");
    assert_eq!(cfg.clients, vec![Box::<str>::from("Client A")]);
    assert_eq!(
        cfg.guard,
        ProvisioningGuard {
            max: 50,
            window_s: 3600
        }
    );
    assert_eq!(
        cfg.link,
        Some(ProvisioningLink {
            index: "email".into(),
            auth: vec!["corp".into()],
            refresh_ms: 1000
        })
    );
    assert!(deploy.identity_providers["scim"].settings.is_empty());
}

#[test]
fn provisioning_without_link_is_explicitly_unlinked() {
    let parsed = parse_provisioning(&provisioning_deploy(
        "{clients: [client], guard: {max: 1, window_s: 60}}",
    ))
    .expect("link is optional");
    assert!(parsed["scim"].link.is_none());
}

#[test]
fn provisioning_refuses_invalid_policy_with_the_configured_key() {
    for (block, key) in [
        ("{clients: [], guard: {max: 1, window_s: 60}}", "clients"),
        ("{clients: [''], guard: {max: 1, window_s: 60}}", "clients[0]"),
        ("{clients: [client], guard: {max: 0, window_s: 60}}", "guard.max"),
        ("{clients: [client], guard: {max: 1, window_s: 59}}", "guard.window_s"),
        ("{clients: [client], link: {index: email, auth: [], refresh_ms: 1000}, guard: {max: 1, window_s: 60}}", "link.auth"),
        ("{clients: [client], link: {index: email, auth: [corp], refresh_ms: 249}, guard: {max: 1, window_s: 60}}", "link.refresh_ms"),
    ] {
        let why = parse_provisioning(&provisioning_deploy(block)).expect_err("invalid policy");
        let path = format!("identity-providers.scim.provisioning.{key}");
        assert!(why.iter().any(|reason| reason.contains(&path)), "{why:?}");
    }
}

#[test]
fn provisioning_rejects_unknown_keys_and_missing_required_fields() {
    for block in [
        "{clients: [client], surprise: true, guard: {max: 1, window_s: 60}}",
        "{clients: [client], guard: {max: 1, window_s: 60, enabled: false}}",
        "{clients: [client], link: {index: email, auth: [corp], refresh_ms: 1000, extra: true}, guard: {max: 1, window_s: 60}}",
        "{guard: {max: 1, window_s: 60}}",
        "{clients: [client]}",
        "null",
    ] {
        let why = parse_provisioning(&provisioning_deploy(block)).expect_err("invalid grammar");
        assert!(why.iter().all(|reason| reason.contains("identity-providers.scim.provisioning")), "{why:?}");
    }
}
