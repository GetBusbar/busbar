use super::*;

use crate::config;

fn make_root_cfg(
    providers: HashMap<String, config::ProviderCfg>,
    models: HashMap<String, config::ModelCfg>,
    pools: HashMap<String, config::PoolCfg>,
) -> RootCfg {
    config::RootCfg {
        plane_defs: Default::default(),
        plane_pools: Default::default(),
        plane_sections: Default::default(),
        listen: crate::config::DEFAULT_LISTEN_ADDR.into(),

        endpoint_resources: Default::default(),
        oauth_as: None,
        credentials: Default::default(),
        public_url: None,
        tls: None,
        admin_listen: crate::config::DEFAULT_ADMIN_LISTEN_ADDR.to_string(),
        admin_tls: None,
        auth: None,

        providers: providers
            .into_iter()
            .map(|(name, p)| (name, p.into()))
            .collect(),
        models,
        pools,
        upstream_credentials: crate::auth::UpstreamCreds::Own,
        hooks: HashMap::new(),
        admin_auth: config::default_admin_auth_names(),
        groups: std::collections::BTreeMap::new(),
        rate_card: None,
        per_request_fee: 0,
        plane_fees: Default::default(),
        store: Some(config::StoreCfg {
            module: "inert-store-metadata".into(),
            settings: Default::default(),
        }),
        secrets: std::collections::BTreeMap::new(),
        global_hooks: Vec::new(),
        blocked_metadata_hosts: Vec::new(),
        allow_metadata_hosts: Vec::new(),
        allow_all_metadata: false,
        guard: Default::default(),
        limits: config::LimitsResolved::default(),
        export: Default::default(),
        identity_providers: Default::default(),
        export_defs: Default::default(),
    }
}

fn make_provider(protocol: &str, base_url: &str, api_key_env: &str) -> config::ProviderCfg {
    let mut error_map = std::collections::HashMap::new();
    error_map.insert("400".to_string(), "client_error".to_string());

    config::ProviderCfg {
        protocol: protocol.into(),
        base_url: base_url.into(),

        api_key: config::SecretRef::env(api_key_env),
        health: None,
        error_map,
        path: None,
        path_base: None,
        token_url: None,
        scope: None,
        subject: None,
        auth: None,
        allow_metadata_hosts: Vec::new(),
        options: Default::default(),
    }
}

// Inert protocol names for pure validation functions with an explicit allowed-set input.
fn proto_a() -> &'static str {
    "host-input-a"
}
fn proto_b() -> &'static str {
    "host-input-b"
}

#[test]
fn a_token_url_is_judged_for_any_style_declaring_it() {
    let build = |word: &str| -> Vec<String> {
        let provider: crate::config::providers::ResolvedProvider = make_provider(
            "inert-dialect-metadata",
            "https://api.example.com",
            "API_KEY",
        )
        .into();
        let cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
        let flags = if word == "x-double-mint" {
            busbar_contract::abi::auth::STYLE_ENDPOINT_TOKEN_URL
        } else {
            0
        };
        let mut errors = Vec::new();
        validate_token_endpoint_fields("mint", &provider, word, flags, &cfg, &[], &mut errors);
        errors
    };
    let errs = build("x-double-mint");
    for want in [
        "provider 'mint' uses auth: x-double-mint but has no `token_url` (the OAuth token endpoint the client credentials are POSTed to)",
        "provider 'mint' uses auth: x-double-mint but has no `scope`",
    ] {
        assert!(
            errs.iter().any(|e| e == want),
            "a style declaring STYLE_ENDPOINT_TOKEN_URL is judged by the bit: want {want:?} in {errs:?}"
        );
    }
    let errs = build("bearer");
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("token_url") || e.contains("scope")),
        "a style stating no endpoint is not judged for one: {errs:?}"
    );
}

#[test]
fn vet_token_uri_takes_http_to_a_private_host_and_refuses_a_public_one() {
    for uri in [
        "http://10.0.0.5/token",
        "http://192.168.1.20/token",
        "http://127.0.0.1:9000/token",
        "http://[::1]/token",
        "https://oauth2.googleapis.com/token",
    ] {
        assert_eq!(
            vet_token_uri(uri, &MetadataPosture::default()),
            Ok(()),
            "token_uri {uri} must be accepted, as 1.5.5 did"
        );
    }
    let uri = "http://oauth2.example.com/token";
    assert_eq!(
        vet_token_uri(uri, &MetadataPosture::default()),
        Err(format!(
            "service-account token_uri must use https for a public host (got '{uri}'); it receives the signed JWT assertion, so plaintext http is permitted only for a private/loopback endpoint"
        )),
        "a public http token_uri must be refused in 1.5.5's words"
    );
    let imds = vet_token_uri("http://169.254.169.254/token", &MetadataPosture::default());
    assert!(
        imds.as_ref().is_err_and(|e| e.contains("cloud-metadata")),
        "a token_uri at the metadata host must be refused as cloud-metadata; got: {imds:?}"
    );
}

#[test]
fn test_the_boot_count_shows_eleven_and_the_printed_list_every_enforced_entry() {
    let counted = crate::config_validate::metadata_denylist_entries();
    assert_eq!(counted.len(), 11, "1.5.5's displayed count: {counted:?}");
    let printed = crate::config_validate::metadata_enforced_entries();
    assert_eq!(printed.len(), 13, "every enforced entry: {printed:?}");
    for entry in &counted {
        assert!(printed.contains(entry), "{entry} is printed: {printed:?}");
    }
    for entry in ["fd00:ec2::23", "fe80::/10"] {
        assert!(
            printed.iter().any(|e| e == entry),
            "{entry} is printed: {printed:?}"
        );
    }
    let task: std::net::IpAddr = "fd00:ec2::23".parse().expect("an address");
    assert!(
        busbar_contract::net::ip_is_cloud_metadata(&task),
        "the EC2 task-metadata endpoint is enforced"
    );
    let imds: std::net::IpAddr = "fd00:ec2::254".parse().expect("an address");
    assert!(busbar_contract::net::ip_is_cloud_metadata(&imds));
    assert!(
        busbar_contract::net::host_is_link_local_v6("fe80::1"),
        "IPv6 link-local is refused as metadata is"
    );
}

#[test]
fn test_validate_rejects_oversized_inbound_and_webhook_concurrency_limits() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.limits.max_inbound_concurrent = tokio::sync::Semaphore::MAX_PERMITS + 1;

    let errs = validate(&cfg).expect_err("the oversized limit must fail validation");
    assert!(
        errs.iter().any(|e| e.contains("max_inbound_concurrent")),
        "expected an oversized max_inbound_concurrent error; got: {errs:?}"
    );

    cfg.limits.max_inbound_concurrent = 0;
    assert!(
        validate(&cfg).is_ok(),
        "0 (disabled) and the exact boundary value must not error"
    );
}

#[test]
fn test_minimal_model_config_without_max_concurrent_deserializes() {
    let m: config::ModelCfg = serde_yaml::from_str("provider: myprovider\n")
        .expect("a model config with only `provider` must load (max_concurrent is optional)");
    assert_eq!(m.provider, "myprovider");
    assert_eq!(
        m.max_concurrent, None,
        "an omitted max_concurrent must be None (unbounded)"
    );
    assert_eq!(
        m.max_requests, -1,
        "an omitted max_requests must default to -1 (unlimited)"
    );
}

#[test]
fn test_legacy_auth_keys_are_rejected_at_parse() {
    let yaml = r#"
listen: "0.0.0.0:8080"
auth:
  mode: token
  token: "stale-legacy-secret"
  client_tokens: ["real-secret"]
providers:
  acme:
    api_key: { env: ACME_KEY }
models:
  model-1:
    provider: acme
    max_concurrent: 10
"#;
    let err = serde_yaml::from_str::<crate::config::DeployCfg>(yaml)
        .expect_err("a config setting the removed auth keys must fail to parse");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown field"),
        "expected serde's unknown-field error at parse; got: {msg}"
    );

    assert!(
        !msg.contains("stale-legacy-secret"),
        "the parse error must not leak the configured token value; got: {msg}"
    );

    let yaml2 = r#"
listen: "0.0.0.0:8080"
providers:
  acme:
    api_key_env: ACME_KEY
models:
  model-1:
    provider: acme
"#;
    let err2 = serde_yaml::from_str::<crate::config::DeployCfg>(yaml2)
        .expect_err("the removed api_key_env key must fail to parse");
    assert!(
        err2.to_string().contains("missing field `api_key`"),
        "expected the entry with no credential refused; got: {err2}"
    );
}

#[test]
fn test_ssrf_blocks_metadata_denylist_by_default() {
    for blocked in [
        "https://169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/",
        "http://169.254.169.254/",
        "https://169.254.170.2/v2/credentials",
        "https://169.254.0.23/",
        "https://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/",
        "https://168.63.129.16/",
        "https://[fd00:ec2::254]/",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://METADATA.INTERNAL/",
        "https://metadata.tencentyun.com/",
        "https://metadata.platformequinix.com/",
        "https://instance-data/latest/meta-data/",
        "https://instance-data.ec2.internal/",
        "https://metadata.google.internal./",
        "https://[::ffff:169.254.169.254]/",
        "https://[::169.254.169.254]/",
        "https://[::ffff:169.254.170.2]/",
        "https://[::ffff:100.100.100.200]/",
        "https://[::ffff:168.63.129.16]/",
        "https://2852039166/",
        "https://0xa9fea9fe/",
        "https://169.254.169.254./",
        "https://169%2E254%2E169%2E254/",
        "https://169.254.169.254:8443/",
        "https://user:pass@169.254.169.254/latest",
        "https://169.254.43518/",
        "https://169.16689662/",
    ] {
        let got = ssrf_blocked_host(blocked, &[], false, &[]);
        let host = got.as_deref().unwrap_or_else(|| {
            panic!("expected '{blocked}' to be flagged as a metadata SSRF target")
        });
        assert!(
            !host.is_empty(),
            "blocked '{blocked}' returned an EMPTY host string"
        );
    }
}

#[test]
fn test_ssrf_blocked_returns_exact_host_string() {
    assert_eq!(
        ssrf_blocked_host("https://169.254.169.254/latest", &[], false, &[]).as_deref(),
        Some("169.254.169.254")
    );
    assert_eq!(
        ssrf_blocked_host("https://user:pass@169.254.169.254:8443/x", &[], false, &[]).as_deref(),
        Some("169.254.169.254"),
        "userinfo and port must be stripped from the returned host"
    );
    assert_eq!(
        ssrf_blocked_host("https://metadata.google.internal/", &[], false, &[]).as_deref(),
        Some("metadata.google.internal")
    );
    assert_eq!(
        ssrf_blocked_host("https://100.100.100.200/", &[], false, &[]).as_deref(),
        Some("100.100.100.200")
    );
}

#[test]
fn test_expand_alternate_ipv4_imds_obfuscations() {
    let imds: std::net::Ipv4Addr = "169.254.169.254".parse().unwrap();
    assert_eq!(
        expand_alternate_ipv4("2852039166"),
        Some(imds),
        "1-part decimal"
    );
    assert_eq!(
        expand_alternate_ipv4("169.16689662"),
        Some(imds),
        "2-part inet_aton"
    );
    assert_eq!(
        expand_alternate_ipv4("169.254.43518"),
        Some(imds),
        "3-part inet_aton"
    );

    assert_eq!(
        expand_alternate_ipv4("169.254.169.254"),
        None,
        "an already-canonical dotted quad must return None from the expander"
    );
    assert_eq!(expand_alternate_ipv4("8.8.8.8"), None);

    for base in [
        "https://2852039166/",
        "https://169.16689662/",
        "https://169.254.43518/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "obfuscated IMDS form '{base}' must be blocked"
        );
    }
}

#[test]
fn test_expand_alternate_ipv4_imds_hex_octal_forms() {
    let imds: std::net::Ipv4Addr = "169.254.169.254".parse().unwrap();

    assert_eq!(
        expand_alternate_ipv4("0xA9FEA9FE"),
        Some(imds),
        "single-integer hex form of IMDS"
    );
    assert_eq!(
        expand_alternate_ipv4("0xA9.0xFE.0xA9.0xFE"),
        Some(imds),
        "dotted per-octet hex form of IMDS"
    );

    assert_eq!(
        expand_alternate_ipv4("025177524776"),
        Some(imds),
        "single-integer octal form of IMDS"
    );
    assert_eq!(
        expand_alternate_ipv4("0251.0376.0251.0376"),
        Some(imds),
        "dotted per-octet octal form of IMDS"
    );

    for base in [
        "https://0xA9FEA9FE/",
        "https://0xA9.0xFE.0xA9.0xFE/",
        "https://025177524776/",
        "https://0251.0376.0251.0376/",
    ] {
        assert!(
            ssrf_blocked_host(base, &[], false, &[]).is_some(),
            "hex/octal-obfuscated IMDS form '{base}' must be blocked"
        );
    }
}

#[test]
fn test_metadata_list_entries_are_mapped() {
    let full_width_ip = "\u{ff11}\u{ff10}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}.\u{ff19}\u{ff19}";
    let full_width_name = "\u{ff4d}\u{ff45}\u{ff54}\u{ff41}.example";
    for (entry, target) in [
        (full_width_ip, "https://10.99.99.99/v1"),
        (full_width_ip, "https://[::ffff:10.99.99.99]/v1"),
        (full_width_name, "https://meta.example/v1"),
        (full_width_name, "meta.example:443"),
    ] {
        assert!(
            ssrf_blocked_host(target, &[], false, &[entry.to_string()]).is_some(),
            "the entry `{entry}` must block `{target}`"
        );
        assert!(
            ssrf_blocked_host(target, &[entry.to_string()], false, &[entry.to_string()]).is_none(),
            "the allow entry `{entry}` must lift `{target}`"
        );
    }
}

const NO_HOST_ENTRIES: [&str; 10] = [
    "b\u{fc}cher\u{ff1c}.example",
    "%6c%6fcalhost",
    "169%2e254%2e169%2e254",
    "1.2.3.4.5",
    "999.1.1.1",
    "foo.127",
    "x.0",
    "db.1",
    "0x",
    "\u{ff11}.\u{ff12}.\u{ff13}.\u{ff14}.\u{ff15}",
];

#[test]
fn test_ssrf_allows_private_and_loopback_by_default() {
    for allowed in [
        "https://127.0.0.1/",
        "https://10.0.0.1/v1",
        "https://172.16.0.1/",
        "https://192.168.1.1:8443/",
        "https://[::1]/",
        "https://[::1]:443/",
        "https://[fe80::1]/",
        "https://[fc00::1]/",
        "https://0.0.0.0/",
        "https://user:pass@10.0.0.5/path",
        "https://100.64.0.1/",
        "https://100.127.255.255/",
        "https://[::ffff:10.0.0.1]/",
        "https://[::ffff:100.64.0.1]/",
        "https://[::127.0.0.1]/",
        "https://2130706433/",
        "https://127.1/",
        "https://localhost/",
        "https://api.localhost:11434/v1",
        "https://service.internal.localhost/",
        "https://API.LOCALHOST/",
    ] {
        assert!(
                ssrf_blocked_host(allowed, &[], false, &[]).is_none(),
                "expected '{allowed}' to be ALLOWED (private/loopback is a local-model target, not metadata)"
            );
    }
}

#[test]
fn test_ssrf_cgnat_allowed_but_alibaba_literal_blocked() {
    assert!(ssrf_blocked_host("https://100.64.0.0/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.127.255.255/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.63.255.255/", &[], false, &[]).is_none());
    assert!(ssrf_blocked_host("https://100.128.0.1/", &[], false, &[]).is_none());

    assert!(
            ssrf_blocked_host("https://100.100.100.200/", &[], false, &[]).is_some(),
            "the Alibaba metadata literal 100.100.100.200 must stay blocked even though CGNAT is allowed"
        );
}

#[test]
fn test_ssrf_blocked_host_allows_public_targets() {
    for ok in [
        "https://api.acme.example.com/v1/messages",
        "https://api.vendor-a.example.com",
        "https://example.com:8443/v1",
        "https://8.8.8.8/",
        "https://[2606:4700:4700::1111]/",
        "https://mylocalhost.com/",
        "https://notlocalhost.example.com/",
        "https://localhost.example.com/",
    ] {
        assert!(
            ssrf_blocked_host(ok, &[], false, &[]).is_none(),
            "expected '{ok}' to be allowed (not an SSRF target)"
        );
    }
}

#[test]
fn test_on_exhausted_is_structured_and_rejects_malformed_at_parse() {
    assert!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("bogus").is_err(),
        "an unknown on_exhausted keyword must fail to parse"
    );
    assert!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("\"fallback_pool:backup\"").is_err(),
        "the retired string form 'fallback_pool:name' must fail to parse (structured form only)"
    );
    assert!(matches!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("reject").unwrap(),
        config::OnExhaustedCfg::Reject
    ));
    assert!(matches!(
        serde_yaml::from_str::<config::OnExhaustedCfg>("least_bad").unwrap(),
        config::OnExhaustedCfg::LeastBad
    ));
    match serde_yaml::from_str::<config::OnExhaustedCfg>("{ fallback_pool: backup }").unwrap() {
        config::OnExhaustedCfg::FallbackPool(name) => assert_eq!(name, "backup"),
        other => panic!("expected FallbackPool, got {other:?}"),
    }
}

#[test]
fn test_queue_config_parses_and_both_keys_conflict() {
    match serde_yaml::from_str::<config::OnExhaustedCfg>("{ queue: { max_ms: 250 } }").unwrap() {
        config::OnExhaustedCfg::Queue { max_ms } => assert_eq!(max_ms, 250),
        other => panic!("expected Queue, got {other:?}"),
    }
    let both = serde_yaml::from_str::<config::OnExhaustedCfg>(
        "{ fallback_pool: cold, queue: { max_ms: 250 } }",
    );
    let err = format!("{}", both.expect_err("both keys must be a conflict error"));
    assert!(
        err.contains("exactly one of"),
        "both-keys error must say exactly one of fallback_pool | queue; got: {err}"
    );
}

#[test]
fn test_affinity_mode_is_a_closed_enum() {
    assert_eq!(
        serde_yaml::from_str::<config::AffinityMode>("session").unwrap(),
        config::AffinityMode::Session
    );
    assert!(
        serde_yaml::from_str::<config::AffinityMode>("sticky").is_err(),
        "'sticky' is not a supported affinity mode and must fail to deserialize"
    );
}

#[test]
fn test_allow_override_matches_obfuscated_spellings() {
    let allow = vec!["169.254.169.254".to_string()];
    for base in [
        "https://169.254.169.254/",
        "http://2852039166/",
        "http://[::ffff:169.254.169.254]/",
        "https://169.254.169.254./",
    ] {
        assert!(
            ssrf_blocked_host(base, &allow, false, &[]).is_none(),
            "an allow entry must unblock the obfuscated spelling '{base}'"
        );
    }

    assert!(
        ssrf_blocked_host("https://168.63.129.16/", &allow, false, &[]).is_some(),
        "a non-allowed metadata IP must stay blocked"
    );
}

#[test]
fn test_removed_member_keys_rejected_at_parse() {
    let legacy_cost =
        "members:\n  - model: m\n    cost_per_mtok: { input_utok: 1.0, output_utok: 2.0 }\n";
    let err = serde_yaml::from_str::<config::PoolCfg>(legacy_cost)
        .expect_err("the removed cost_per_mtok member key must fail to parse");
    assert!(
        err.to_string().contains("unknown field"),
        "expected an unknown-field error for cost_per_mtok; got: {err}"
    );

    let legacy_target = "members:\n  - target: m\n";
    let err = serde_yaml::from_str::<config::PoolCfg>(legacy_target)
        .expect_err("the retired target: member key must fail to parse");
    assert!(
        err.to_string().contains("unknown field"),
        "expected an unknown-field error for target; got: {err}"
    );

    let ok = serde_yaml::from_str::<config::PoolCfg>("members:\n  - model: m\n").unwrap();
    assert_eq!(ok.members[0].model, "m");
}

#[test]
fn test_validate_limits_boundary_fields_reject_zero_accept_one() {
    macro_rules! check_floor_one {
        ($field:ident, $needle:expr) => {{
            let mut bad = config::LimitsResolved::default();
            bad.$field = 0;
            let mut errs = Vec::new();
            validate_limits(&bad, &mut errs);
            assert!(
                errs.iter().any(|e| e.contains($needle)),
                "{}=0 must be rejected; got {errs:?}",
                stringify!($field)
            );

            let mut good = config::LimitsResolved::default();
            good.$field = 1;
            let mut errs = Vec::new();
            validate_limits(&good, &mut errs);
            assert!(
                !errs.iter().any(|e| e.contains($needle)),
                "{}=1 (the floor itself) must be ACCEPTED; got {errs:?}",
                stringify!($field)
            );
        }};
    }

    check_floor_one!(tls_handshake_timeout_secs, "tls_handshake_timeout_secs");
    check_floor_one!(
        request_body_read_timeout_secs,
        "request_body_read_timeout_secs"
    );

    check_floor_one!(max_honored_retry_after_secs, "max_honored_retry_after_secs");
    check_floor_one!(hard_down_cooldown_secs, "hard_down_cooldown_secs");
    check_floor_one!(
        upstream_error_body_max_bytes,
        "upstream_error_body_max_bytes"
    );
    check_floor_one!(default_max_tokens, "default_max_tokens");
    check_floor_one!(default_probe_interval_secs, "default_probe_interval_secs");
    check_floor_one!(default_probe_timeout_secs, "default_probe_timeout_secs");

    check_floor_one!(
        upstream_request_timeout_secs,
        "upstream_request_timeout_secs must be >= 1"
    );
    check_floor_one!(
        default_policy_timeout_ms,
        "default_policy_timeout_ms must be >= 1"
    );
}

#[test]
fn test_validate_limits_request_body_max_bytes_floor_and_ceiling_are_exact() {
    use crate::config::{REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR};

    let at_floor = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_FLOOR,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&at_floor, &mut errs);
    assert!(
        !errs.iter().any(|e| e.contains("below the")),
        "exactly the floor must be accepted; got {errs:?}"
    );

    let below_floor = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_FLOOR - 1,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&below_floor, &mut errs);
    assert!(
        errs.iter().any(|e| e.contains("below the")),
        "one byte below the floor must be rejected; got {errs:?}"
    );

    let at_ceil = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_CEIL,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&at_ceil, &mut errs);
    assert!(
        !errs.iter().any(|e| e.contains("exceeds the")),
        "exactly the ceiling must be accepted; got {errs:?}"
    );

    let over_ceil = config::LimitsResolved {
        request_body_max_bytes: REQUEST_BODY_MAX_BYTES_CEIL + 1,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&over_ceil, &mut errs);
    assert!(
        errs.iter().any(|e| e.contains("exceeds the")),
        "one byte over the ceiling must be rejected; got {errs:?}"
    );
}

#[test]
fn datagram_line_memory_limit_accepts_unset_or_any_positive_usize() {
    for value in [None, Some(1), Some(usize::MAX)] {
        let limits = config::LimitsResolved {
            datagram_line_memory_bytes: value,
            ..config::LimitsResolved::default()
        };
        let mut errors = Vec::new();
        validate_limits(&limits, &mut errors);
        assert!(errors.is_empty(), "{value:?}: {errors:?}");
    }
}

#[test]
fn datagram_line_memory_limit_zero_is_a_config_validation_error() {
    let deploy = crate::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nlimits:\n  datagram_line_memory_bytes: 0\n",
    )
    .expect("zero has the right type; validation must reject it");
    let cfg = crate::config::resolve(&deploy, &HashMap::new()).expect("resolve the config");
    assert_eq!(cfg.limits.datagram_line_memory_bytes, Some(0));
    let mut errors = Vec::new();
    validate_limits(&cfg.limits, &mut errors);
    assert_eq!(
        errors,
        ["limits.datagram_line_memory_bytes must be >= 1 when set (omit it or use null to disable the limit)"],
    );
}

#[test]
fn test_validate_limits_max_inbound_concurrent_ceiling_is_exact() {
    let at_cap = config::LimitsResolved {
        max_inbound_concurrent: MAX_SEMAPHORE_PERMITS,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&at_cap, &mut errs);
    assert!(
        !errs
            .iter()
            .any(|e| e.contains("max_inbound_concurrent must be <=")),
        "exactly MAX_SEMAPHORE_PERMITS must be accepted; got {errs:?}"
    );

    let over_cap = config::LimitsResolved {
        max_inbound_concurrent: MAX_SEMAPHORE_PERMITS + 1,
        ..config::LimitsResolved::default()
    };
    let mut errs = Vec::new();
    validate_limits(&over_cap, &mut errs);
    assert!(
        errs.iter()
            .any(|e| e.contains("max_inbound_concurrent must be <=")),
        "MAX_SEMAPHORE_PERMITS + 1 must be rejected; got {errs:?}"
    );
}

fn parse_auth(yaml: &str) -> config::AuthCfg {
    #[derive(serde::Deserialize)]
    struct Doc {
        #[serde(default)]
        auth: config::AuthDeployCfg,
        #[serde(default, rename = "identity-providers")]
        identity_providers: config::IdentityProviders,
    }
    let doc: Doc = serde_yaml::from_str(yaml).expect("auth yaml parses");
    let mut errors = Vec::new();
    let out = config::resolve_auth(&doc.auth, &doc.identity_providers, &mut errors);
    assert!(
        errors.is_empty(),
        "auth yaml must resolve cleanly: {errors:?}"
    );
    out
}

#[test]
fn test_public_url_requires_https() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.public_url = Some("http://api.busbar.example".to_string());
    let errs = validate(&cfg).expect_err("public http host must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("public_url") && e.contains("https")),
        "missing https error: {errs:?}"
    );

    cfg.public_url = Some("http://127.0.0.1:8080".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("public_url")),
        "loopback http must be accepted: {res:?}"
    );

    cfg.public_url = Some("https://api.busbar.example".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("public_url")),
        "public https must be accepted: {res:?}"
    );
}

#[test]
fn test_public_url_rejects_path_and_metadata() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.public_url = Some("https://api.busbar.example/x".to_string());
    let errs = validate(&cfg).expect_err("public_url with a path must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("public_url") && (e.contains("path") || e.contains("bare origin"))),
        "missing path error: {errs:?}"
    );

    cfg.public_url = Some("https://169.254.169.254".to_string());
    let errs = validate(&cfg).expect_err("public_url at a metadata host must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("public_url") && e.contains("metadata")),
        "missing metadata SSRF error: {errs:?}"
    );
}

#[test]
fn test_browser_login_requires_public_url() {
    let auth = parse_auth(
        "identity-providers:\n  oidc:\n    module: oidc-plugin\n    browser_login:\n      client_secret: { env: X }\n",
    );
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.auth = Some(auth);
    cfg.public_url = None;
    let errs = validate(&cfg).expect_err("browser_login without public_url must fail");
    assert!(
        errs.iter()
            .any(|e| e.contains("browser_login") && e.contains("public_url")),
        "error must name both browser_login and public_url: {errs:?}"
    );

    cfg.public_url = Some("https://busbar.example".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("browser_login")),
        "browser_login error must clear once public_url is set: {res:?}"
    );
}

#[test]
fn test_role_binding_under_browser_method_active() {
    let auth = parse_auth(
        "identity-providers:\n  oidc:\n    module: oidc-plugin\n    browser_login:\n      client_secret: { env: X }\nauth:\n  role_bindings:\n    oidc:\n      member: {}\n",
    );
    assert!(auth.methods["oidc"].browser_login.is_some());
    assert!(auth.role_bindings["oidc"].contains_key("member"));
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.auth = Some(auth);
    cfg.public_url = Some("https://busbar.example".to_string());
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("inactive module") && !e.contains("grants nothing")),
        "methods-only module must not be flagged inactive: {res:?}"
    );
    cfg.auth.as_mut().unwrap().methods.swap_remove("oidc");
    let errs = validate(&cfg).expect_err("without the browser method the binding is inactive");
    assert!(
        errs.iter()
            .any(|e| e.contains("role_bindings names module 'oidc'")
                && e.contains("inactive module")),
        "removing the only active method must be diagnosed: {errs:?}"
    );
}

#[test]
fn test_key_ttl_validates_duration() {
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    let mut auth = config::AuthCfg::default_none();
    auth.key_ttl = Some("90d".to_string());
    cfg.auth = Some(auth);
    let res = validate(&cfg);
    assert!(
        res.as_ref()
            .err()
            .into_iter()
            .flatten()
            .all(|e| !e.contains("key_ttl")),
        "valid key_ttl must pass: {res:?}"
    );

    let mut auth = config::AuthCfg::default_none();
    auth.key_ttl = Some("banana".to_string());
    cfg.auth = Some(auth);
    let errs = validate(&cfg).expect_err("garbage key_ttl must fail");
    assert!(
        errs.iter().any(|e| e.contains("key_ttl")),
        "missing key_ttl error: {errs:?}"
    );
}

#[test]
fn an_empty_protocol_set_refuses_every_provider_naming_the_build() {
    let mut errors = Vec::new();
    super::validate_provider_protocol_with(&[], "prov-a", proto_a(), &mut errors);
    super::validate_provider_protocol_with(&[], "prov-b", "no-such-protocol", &mut errors);

    assert_eq!(
        errors.len(),
        2,
        "an empty protocol set must refuse EVERY provider (one error each), got: {errors:?}"
    );
    for (err, prov) in errors.iter().zip(["prov-a", "prov-b"]) {
        assert!(err.contains(prov), "the refusal names the provider: {err}");
        assert!(
            err.contains("NO protocol") && err.contains("compiled in"),
            "the refusal must name the BUILD as the cause (no protocol compiled in), not call the \
             protocol unknown against an empty list: {err}"
        );
        assert!(
            !err.contains("must be one of"),
            "the empty set must NOT render the unknown-protocol arm with an empty tail: {err}"
        );
    }

    let mut errors = Vec::new();
    super::validate_provider_protocol_with(&[proto_a(), proto_b()], "prov-c", "nope", &mut errors);
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].contains(&format!("must be one of: {}, {}", proto_a(), proto_b())),
        "the populated set names the choices: {}",
        errors[0]
    );
}

#[test]
fn an_empty_protocol_set_refuses_every_provider_through_the_real_sweep() {
    let mut providers = HashMap::new();
    providers.insert(
        "prov-a".to_string(),
        make_provider(proto_a(), "https://a.example.com", "KEY_A"),
    );
    providers.insert(
        "prov-b".to_string(),
        make_provider("no-such-protocol", "https://b.example.com", "KEY_B"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());

    let mut errors = Vec::new();
    super::validate_providers_with(&[], &cfg, &[], &mut errors);

    for prov in ["prov-a", "prov-b"] {
        let hits: Vec<&String> = errors.iter().filter(|e| e.contains(prov)).collect();
        assert_eq!(
            hits.len(),
            1,
            "an empty protocol set must refuse '{prov}' exactly once, got: {hits:?}"
        );
        assert!(
            hits[0].contains("NO protocol") && hits[0].contains("compiled in"),
            "the refusal must name the BUILD as the cause: {}",
            hits[0]
        );
    }
    assert!(
        !errors.iter().any(|e| e.contains("must be one of")),
        "the empty set must never render the unknown-protocol arm with an empty tail: {errors:?}"
    );

    let mut errors = Vec::new();
    super::validate_providers_with(&[proto_a(), proto_b()], &cfg, &[], &mut errors);
    assert!(
        !errors.iter().any(|e| e.contains("prov-a")),
        "a provider naming a compiled-in protocol validates: {errors:?}"
    );
    let hits: Vec<&String> = errors.iter().filter(|e| e.contains("prov-b")).collect();
    assert_eq!(hits.len(), 1, "one refusal for the stranger: {hits:?}");
    assert!(
        hits[0].contains(&format!("must be one of: {}, {}", proto_a(), proto_b())),
        "the populated set names the choices: {}",
        hits[0]
    );
}

#[test]
fn the_empty_set_the_validator_refuses_is_the_one_an_empty_registry_produces() {
    let known = crate::plane_driver::dispatch::provider_dialects();
    assert!(
        known.is_empty(),
        "the premise of this test: a registry with no declarations knows no protocols"
    );

    let mut providers = HashMap::new();
    providers.insert(
        "prov-a".to_string(),
        make_provider(proto_a(), "https://a.example.com", "KEY_A"),
    );
    let cfg = make_root_cfg(providers, HashMap::new(), HashMap::new());

    let mut errors = Vec::new();
    super::validate_providers_with(&known, &cfg, &[], &mut errors);
    assert_eq!(
        errors.len(),
        1,
        "the registry-derived empty set refuses the provider, once: {errors:?}"
    );
    assert!(
        errors[0].contains("prov-a")
            && errors[0].contains("NO protocol")
            && errors[0].contains("compiled in"),
        "and names the build: {}",
        errors[0]
    );
}

fn root_with_auth_policy(policy: config::AuthPolicyCfg) -> RootCfg {
    let mut auth = config::AuthCfg::default_none();
    auth.policy = policy;
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.auth = Some(auth);
    cfg
}

fn policy_errors(cfg: &RootCfg) -> Vec<String> {
    validate(cfg)
        .err()
        .unwrap_or_default()
        .into_iter()
        .filter(|e| e.contains("auth.policy"))
        .collect()
}

#[test]
fn test_auth_policy_bad_duration_is_rejected() {
    let policy = config::AuthPolicyCfg {
        default_ttl: Some("not-a-duration".to_string()),
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter()
            .any(|e| e.contains("auth.policy.default_ttl") && e.contains("not a valid duration")),
        "a bad default_ttl must fail validation: {errs:?}"
    );

    let policy = config::AuthPolicyCfg {
        max_ttl: Some("90x".to_string()),
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter()
            .any(|e| e.contains("auth.policy.max_ttl") && e.contains("not a valid duration")),
        "a bad max_ttl must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_default_exceeding_max_is_rejected() {
    let policy = config::AuthPolicyCfg {
        default_ttl: Some("90d".to_string()),
        max_ttl: Some("24h".to_string()),
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter()
            .any(|e| e.contains("default_ttl") && e.contains("exceeds") && e.contains("max_ttl")),
        "default_ttl > max_ttl must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_ceiling_max_ttl_rules() {
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            max_ttl: Some("wat".to_string()),
            ..Default::default()
        },
    );
    let policy = config::AuthPolicyCfg {
        mint_ceilings: ceilings,
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter().any(
            |e| e.contains("auth.policy.mint_ceilings.app-admin.max_ttl")
                && e.contains("not a valid duration")
        ),
        "a bad ceiling max_ttl must fail validation: {errs:?}"
    );

    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            max_ttl: Some("30d".to_string()),
            ..Default::default()
        },
    );
    let policy = config::AuthPolicyCfg {
        max_ttl: Some("7d".to_string()),
        mint_ceilings: ceilings,
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter().any(
            |e| e.contains("auth.policy.mint_ceilings.app-admin.max_ttl") && e.contains("exceeds")
        ),
        "a ceiling exceeding the block max must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_role_modes_outside_the_block_modes_fail() {
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            binding_modes: Some(vec![config::BindingMode::TimeBound]),
            ..Default::default()
        },
    );
    let policy = config::AuthPolicyCfg {
        binding_modes: Some(vec![config::BindingMode::UserBound]),
        mint_ceilings: ceilings,
        ..Default::default()
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(
        errs.iter().any(
            |e| e.contains("auth.policy.mint_ceilings.app-admin.binding_modes")
                && e.contains("'time-bound'")
        ),
        "a role mode outside the block modes must fail validation: {errs:?}"
    );
}

#[test]
fn test_auth_policy_valid_block_passes() {
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(
        "app-admin".to_string(),
        config::MintCeilingCfg {
            max_ttl: Some("7d".to_string()),
            allowed_pools: Some(vec!["growth".to_string()]),
            binding_modes: Some(vec![config::BindingMode::TimeBound]),
        },
    );
    let policy = config::AuthPolicyCfg {
        self_mint: Some(true),
        binding_modes: Some(vec![
            config::BindingMode::TimeBound,
            config::BindingMode::Both,
        ]),
        default_ttl: Some("24h".to_string()),
        max_ttl: Some("90d".to_string()),
        mint_ceilings: ceilings,
    };
    let errs = policy_errors(&root_with_auth_policy(policy));
    assert!(errs.is_empty(), "a valid policy adds no error: {errs:?}");
}

#[test]
fn test_validate_refuses_every_duration_past_the_runtime_horizon() {
    let over_s = MAX_DURATION_SECS + 1;
    let over_ms = MAX_DURATION_MS + 1;
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.limits.pool_idle_timeout_secs = 1u64 << 63;
    cfg.limits.upstream_request_timeout_secs = over_s;
    cfg.limits.hard_down_cooldown_secs = over_s;
    cfg.limits.tls_handshake_timeout_secs = over_s;
    cfg.limits.request_body_read_timeout_secs = over_s;
    cfg.limits.max_honored_retry_after_secs = over_s;
    cfg.limits.default_probe_interval_secs = over_s;
    cfg.limits.default_probe_timeout_secs = u64::MAX;
    cfg.limits.usage_flush_interval_ms = over_ms;
    cfg.limits.default_policy_timeout_ms = u64::MAX;

    let errs = validate(&cfg).expect_err("every over-horizon duration must fail validation");
    for name in [
        "limits.pool_idle_timeout_secs (9223372036854775808) exceeds",
        "limits.upstream_request_timeout_secs",
        "limits.hard_down_cooldown_secs",
        "limits.tls_handshake_timeout_secs",
        "limits.request_body_read_timeout_secs",
        "limits.max_honored_retry_after_secs",
        "health.default_probe_interval_secs",
        "health.default_probe_timeout_secs",
        "advanced.usage_flush_interval_ms",
        "routing.default_policy_timeout_ms",
    ] {
        assert!(
            errs.iter()
                .any(|e| e.contains(name) && (e.contains("30-year") || e.contains("30 years"))),
            "expected a named over-horizon refusal for {name}; got: {errs:?}"
        );
    }

    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.limits.pool_idle_timeout_secs = MAX_DURATION_SECS;
    cfg.limits.upstream_request_timeout_secs = MAX_DURATION_SECS;
    cfg.limits.default_probe_timeout_secs = MAX_DURATION_SECS;
    cfg.limits.usage_flush_interval_ms = MAX_DURATION_MS;
    cfg.limits.default_policy_timeout_ms = MAX_DURATION_MS;
    assert!(
        validate(&cfg).is_ok(),
        "the boundary values must not error: {:?}",
        validate(&cfg)
    );

    assert!(std::time::Instant::now()
        .checked_add(std::time::Duration::from_millis(MAX_DURATION_MS))
        .is_some());
}

fn validate_cost_metadata(
    cfg: &RootCfg,
    declarations: &[&crate::plane_driver::registry::PlaneDeclaration],
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    for declaration in declarations {
        if let Some(card) = &cfg.rate_card {
            let flat = flat_card_present(card.keys().map(|k| split_plane_lane(k).0));
            validate_plane_card(declaration, card, flat, &mut errors);
        }
        if let Some(fees) = cfg.plane_fees.get(declaration.key) {
            validate_plane_fees(declaration, fees, &mut errors);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

static CLASS_PLANE: crate::plane_driver::registry::PlaneDeclaration =
    crate::plane_driver::registry::PlaneDeclaration {
        key: "class-plane",
        fallback: false,
        config_section: "tools",
        scope_kinds: &[],
        subject_noun: "class thing",
        admin_noun: "class-thing",
        audit_kind: "class-thing",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[bc("calls", "count"), bc("bytes", "byte")],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    };

const fn bc(
    class: &'static str,
    family: &'static str,
) -> crate::plane_driver::registry::BillableClass {
    crate::plane_driver::registry::BillableClass { class, family }
}

static FLAT_PLANE: crate::plane_driver::registry::PlaneDeclaration =
    crate::plane_driver::registry::PlaneDeclaration {
        key: "flat-plane",
        fallback: true,
        config_section: "pools",
        billable_classes: &[
            bc("input", "token"),
            bc("output", "token"),
            bc("cache_read", "token"),
            bc("cache_write", "token"),
            bc("search_units", "count"),
            bc("images", "count"),
        ],
        ..CLASS_PLANE
    };

fn card_yaml(y: &str) -> std::collections::BTreeMap<String, config::RateEntryCfg> {
    serde_yaml::from_str(y).expect("a card parses")
}

fn plane_card(
    plane: &str,
    lane: &str,
    entry: &str,
) -> std::collections::BTreeMap<String, config::RateEntryCfg> {
    let key = format!(
        "{plane}{}{lane}",
        busbar_kernel_ledger::cost::PLANE_LANE_SEP
    );
    [(key, serde_yaml::from_str(entry).expect("an entry parses"))].into()
}

#[test]
fn a_card_missing_a_declared_class_fails_validation_naming_every_missing_class() {
    let declarations = &[&FLAT_PLANE];
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.rate_card = Some(card_yaml("m: { input_utok: 3 }\n"));
    let errs = validate_cost_metadata(&cfg, declarations)
        .expect_err("a card silent about declared classes must refuse");
    let want = "pools.rate_card does not configure billable unit(s) search_units, images declared \
                by this plane; add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(card_yaml("m: { input_utok: 3, units: { images: 7 } }\n"));
    let errs =
        validate_cost_metadata(&cfg, declarations).expect_err("search_units is still unconfigured");
    assert!(
        errs.iter()
            .any(|e| e.contains("billable unit(s) search_units declared")),
        "{errs:?}"
    );
}

#[test]
fn a_card_configuring_every_declared_class_passes_with_explicit_zero() {
    let declarations = &[&FLAT_PLANE];
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.rate_card = Some(card_yaml(
        "m: { input_utok: 3, units: { search_units: 0 } }\nn: { units: { images: 0 } }\n",
    ));
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "{:?}",
        validate_cost_metadata(&cfg, declarations)
    );
}

#[test]
fn a_non_fallback_planes_card_is_held_to_the_same_rule() {
    let declarations = &[&CLASS_PLANE];
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.rate_card = Some(plane_card(
        "class-plane",
        "srv_read",
        "units: { calls: 10 }",
    ));
    let errs =
        validate_cost_metadata(&cfg, declarations).expect_err("bytes is declared and unconfigured");
    let want = "tools.rate_card does not configure billable unit(s) bytes declared by this plane; \
                add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(plane_card("class-plane", "", "{}"));
    let errs = validate_cost_metadata(&cfg, declarations)
        .expect_err("an empty present card configures nothing");
    assert!(
        errs.iter()
            .any(|e| e.contains("billable unit(s) calls, bytes declared")),
        "{errs:?}"
    );

    let full = "units: { calls: 10, bytes: 0 }";
    cfg.rate_card = Some(plane_card("class-plane", "srv_read", full));
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "{:?}",
        validate_cost_metadata(&cfg, declarations)
    );

    cfg.rate_card = None;
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "no card = billing off, no refusal"
    );
}

static DOOR_FEE_PLANE: crate::plane_driver::registry::PlaneDeclaration =
    crate::plane_driver::registry::PlaneDeclaration {
        key: "door-fee-plane",
        billable_classes: &[
            bc("calls", "count"),
            bc("bytes", "byte"),
            bc(busbar_contract::plane::PER_REQUEST, "count"),
        ],
        fee_units: &[busbar_contract::plane::PER_REQUEST],
        ..CLASS_PLANE
    };

#[test]
fn a_door_planes_fee_unit_is_no_class_its_card_must_price() {
    let declarations = &[&DOOR_FEE_PLANE];
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.rate_card = Some(plane_card(
        "door-fee-plane",
        "srv_read",
        "units: { calls: 2, bytes: 3 }",
    ));
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "{:?}",
        validate_cost_metadata(&cfg, declarations)
    );

    cfg.rate_card = Some(plane_card(
        "door-fee-plane",
        "srv_read",
        "units: { calls: 2 }",
    ));
    let errs =
        validate_cost_metadata(&cfg, declarations).expect_err("bytes is declared and unpriced");
    let want = "tools.rate_card does not configure billable unit(s) bytes declared by this plane; \
                add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(plane_card(
        "door-fee-plane",
        "srv_read",
        "units: { calls: 2, bytes: 3, per_request: 1 }",
    ));
    let errs = validate_cost_metadata(&cfg, declarations)
        .expect_err("a fee unit is no class a card prices");
    let want = "tools.rate_card configures unit(s) per_request not declared by this plane \
                (declared: calls, bytes); remove them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");
}

#[test]
fn a_dropped_in_planes_declared_classes_are_honoured() {
    let names = ["frames".to_string(), "widgets".to_string()];
    let classes: Vec<crate::plane_driver::registry::BillableClass> = names
        .into_iter()
        .map(|s| bc(Box::leak(s.into_boxed_str()), "count"))
        .collect();
    let dropped: &'static crate::plane_driver::registry::PlaneDeclaration =
        Box::leak(Box::new(crate::plane_driver::registry::PlaneDeclaration {
            key: "dropped-plane",
            config_section: "agents",
            billable_classes: Box::leak(classes.into_boxed_slice()),
            ..CLASS_PLANE
        }));
    let declarations = &[dropped];
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.rate_card = Some(plane_card("dropped-plane", "a", "units: { frames: 1 }"));
    let errs = validate_cost_metadata(&cfg, declarations)
        .expect_err("widgets is declared by the dropped-in plane");
    let want = "agents.rate_card does not configure billable unit(s) widgets declared by this \
                plane; add them (0 to make them free)";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    let full = "units: { frames: 1, widgets: 0 }";
    cfg.rate_card = Some(plane_card("dropped-plane", "a", full));
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "{:?}",
        validate_cost_metadata(&cfg, declarations)
    );
}

#[test]
fn a_card_configuring_an_undeclared_class_fails_naming_it_and_the_declared_list() {
    let declarations = &[&FLAT_PLANE, &CLASS_PLANE];
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.rate_card = Some(card_yaml(
        "m: { input_utok: 3, units: { search_units: 0, images: 0, typo_class: 1 } }\n",
    ));
    let errs =
        validate_cost_metadata(&cfg, declarations).expect_err("typo_class is declared by no plane");
    let want = "pools.rate_card configures unit(s) typo_class not declared by this plane \
                (declared: input, output, cache_read, cache_write, search_units, images); remove \
                them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(plane_card(
        "class-plane",
        "srv_read",
        "units: { calls: 1, bytes: 0, byts: 2 }",
    ));
    let errs =
        validate_cost_metadata(&cfg, declarations).expect_err("byts is not a declared tools class");
    let want = "tools.rate_card configures unit(s) byts not declared by this plane (declared: \
                calls, bytes); remove them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");

    cfg.rate_card = Some(card_yaml(
        "m: { input_utok: 3, units: { search_units: 0, images: 0 } }\n",
    ));
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "{:?}",
        validate_cost_metadata(&cfg, declarations)
    );
}

#[test]
fn a_fee_the_plane_does_not_count_fails_naming_it_and_the_counted_list() {
    use busbar_kernel_ledger::cost::{PlaneFees, PER_SESSION};
    let session: &'static crate::plane_driver::registry::PlaneDeclaration =
        Box::leak(Box::new(crate::plane_driver::registry::PlaneDeclaration {
            key: "session-plane",
            config_section: "streams",
            fee_units: &[PER_SESSION],
            ..CLASS_PLANE
        }));
    let declarations = &[session, &CLASS_PLANE];
    let fees = |plane: &str, per_request, per_session| {
        let f = PlaneFees {
            per_request,
            per_session,
        };
        config::PlaneFeesMap::from([(plane.to_string(), f)])
    };
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.plane_fees = fees("session-plane", 2, 40);
    let errs = validate_cost_metadata(&cfg, declarations)
        .expect_err("the session plane counts no request");
    let want = "streams.fees.per_request is not counted by this plane (counted: per_session); \
                remove it";
    assert_eq!(errs, vec![want.to_string()]);

    cfg.plane_fees = fees("class-plane", 0, 1);
    let errs =
        validate_cost_metadata(&cfg, declarations).expect_err("the class plane counts no fee unit");
    let want = "tools.fees.per_session is not counted by this plane (counted: none); remove it";
    assert_eq!(errs, vec![want.to_string()]);

    cfg.plane_fees = fees("session-plane", 0, 40);
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "{:?}",
        validate_cost_metadata(&cfg, declarations)
    );
}

#[test]
fn a_fee_unit_declared_as_a_class_is_neither_owed_nor_priced_by_the_card() {
    use busbar_kernel_ledger::cost::PER_SESSION;
    const CLASSES: &[crate::plane_driver::registry::BillableClass] =
        &[bc("calls", "count"), bc(PER_SESSION, "count")];
    let session: &'static crate::plane_driver::registry::PlaneDeclaration =
        Box::leak(Box::new(crate::plane_driver::registry::PlaneDeclaration {
            key: "session-plane",
            config_section: "live",
            billable_classes: CLASSES,
            fee_units: &[PER_SESSION],
            ..CLASS_PLANE
        }));
    let declarations = &[session];
    let mut cfg = make_root_cfg(HashMap::new(), HashMap::new(), HashMap::new());
    cfg.rate_card = Some(plane_card("session-plane", "a", "units: { calls: 1 }"));
    assert!(
        validate_cost_metadata(&cfg, declarations).is_ok(),
        "{:?}",
        validate_cost_metadata(&cfg, declarations)
    );

    cfg.rate_card = Some(plane_card(
        "session-plane",
        "a",
        "units: { calls: 1, per_session: 5 }",
    ));
    let errs =
        validate_cost_metadata(&cfg, declarations).expect_err("a card does not price the fee unit");
    let want = "live.rate_card configures unit(s) per_session not declared by this plane \
                (declared: calls); remove them or fix the name";
    assert!(errs.iter().any(|e| e == want), "{errs:?}");
}

#[test]
fn a_service_account_key_file_is_read_through_the_file_source_at_config_time() {
    let json = br#"{"client_email":"a@b","private_key":"k"}"#.to_vec();
    let mut asked = Vec::new();
    let read = super::service_account_json(b"/keys/sa.json\n".to_vec(), |file| {
        asked.push(file.file_path().map(str::to_string));
        Ok(json.clone())
    })
    .expect("the key file reads");
    assert_eq!(read, json);
    assert_eq!(asked, vec![Some("/keys/sa.json".to_string())]);

    let inline = super::service_account_json(json.clone(), |_| {
        panic!("an inline service account opens no file")
    })
    .expect("inline");
    assert_eq!(inline, json);
}

#[test]
fn an_unreadable_service_account_key_file_refuses_in_1_5_5s_words_without_the_path() {
    let refused = super::service_account_json(b"/keys/secret-name.json".to_vec(), |_| {
        Err("secret file:/keys/secret-name.json cannot resolve: No such file or directory (os error 2)".to_string())
    })
    .expect_err("an unreadable key file refuses");
    assert_eq!(
        refused,
        "could not read service-account key file named by this lane's credential: No such file or directory (os error 2)"
    );
    assert!(!refused.contains("secret-name"), "{refused}");
}
