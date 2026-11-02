// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-root-fetch-{tag}-{}-{}",
        std::process::id(),
        {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            format!(
                "{}-{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos()),
                line!(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        }
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn a_pin_cached_fetch_never_downloads() {
    let dir = scratch("cached");
    let body = b"cached-blob-bytes";
    std::fs::write(dir.join("cached-blob.dat"), body).unwrap();
    let target = FetchTarget {
        url: "https://plugin.invalid/cached-blob.dat".into(),
        sha256: Some(super::super::loader::sign::sha256_hex(body)),
        filename: "cached-blob.dat".into(),
    };
    let never = |url: &str| -> Result<Vec<u8>, String> { panic!("downloaded {url}") };
    let spec = super::super::loader::FetchSpec {
        url: target.url.clone(),
        sha256: target.sha256.clone(),
        filename: target.filename.clone(),
    };
    let got = super::super::loader::fetch_plugins(&dir, &[spec], true, &never)
        .expect("the cached pin fetches");
    assert_eq!(
        got,
        vec![super::super::loader::FetchOutcome::Cached {
            filename: "cached-blob.dat".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_roots_fetch_refuses_a_metadata_host_through_the_kernels_guard() {
    let dir = scratch("ssrf");
    let target = FetchTarget {
        url: "https://169.254.169.254/latest/plugin.tar.gz".into(),
        sha256: None,
        filename: "plugin.tar.gz".into(),
    };
    let guard = crate::root::plugin_fetch::downloader(&[]);
    let via_root = plugins_fetch(&dir, std::slice::from_ref(&target), true, &[]).unwrap_err();
    let spec = super::super::loader::FetchSpec {
        url: target.url.clone(),
        sha256: None,
        filename: target.filename.clone(),
    };
    let direct = super::super::loader::fetch_plugins(&dir, &[spec], true, &guard).unwrap_err();
    assert_eq!(via_root, direct);
    assert!(
        via_root[0].contains("blocked cloud-metadata host"),
        "{via_root:?}"
    );
    assert!(!dir.join("plugin.tar.gz").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn to_policy_floor_distinguishes_automatic_from_explicit_downgrade() {
    use crate::root::loader::sign::{evaluate, sign, Manifest, SigningKey, Verdict};

    let release = SigningKey::from_bytes(&[7u8; 32]);
    let artifact = b"\x7fELF old first-party build";
    let old = sign(
        &release,
        Manifest {
            name: "busbar-store-kv-plugin".into(),
            alias: "kv".into(),
            kind: "store".into(),
            version: "0.9.0".into(),
            publisher: crate::root::loader::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: crate::root::loader::supported_abi("store")[0],
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
            declares: Default::default(),
            statement: None,
            former_names: Vec::new(),
        },
        artifact,
    );

    let cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    let mut automatic = trust_policy(&cfg, env!("CARGO_PKG_VERSION")).expect("automatic policy");
    automatic.first_party_key = Some(release.verifying_key());

    assert!(
        matches!(
            evaluate(artifact, &old, &automatic).unwrap(),
            Verdict::Trusted {
                first_party: true,
                ..
            }
        ),
        "default policy must load a verified first-party artifact on its own version line"
    );

    let mut explicit = trust_policy(&cfg, env!("CARGO_PKG_VERSION")).expect("explicit policy");
    explicit
        .first_party_floors
        .insert("busbar-store-kv-plugin".to_string(), "0.9.0".to_string());
    explicit.first_party_key = Some(release.verifying_key());
    assert!(
        matches!(
            evaluate(artifact, &old, &explicit).unwrap(),
            Verdict::Trusted {
                first_party: true,
                ..
            }
        ),
        "an explicit rollback floor admits the prior first-party artifact"
    );

    let older = sign(
        &release,
        Manifest {
            name: "busbar-store-kv-plugin".into(),
            alias: "kv".into(),
            kind: "store".into(),
            version: "0.8.0".into(),
            publisher: crate::root::loader::sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: crate::root::loader::supported_abi("store")[0],
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
            declares: Default::default(),
            statement: None,
            former_names: Vec::new(),
        },
        artifact,
    );
    assert!(
        evaluate(artifact, &older, &explicit).is_err(),
        "an artifact below the pinned rollback target is still refused"
    );
}

#[test]
fn to_policy_honors_runtime_first_party_floor_override() {
    let mut cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };

    let auto = trust_policy(&cfg, env!("CARGO_PKG_VERSION")).expect("policy");
    assert_eq!(auto.binary_version, env!("CARGO_PKG_VERSION"));
    assert!(auto.first_party_floors.is_empty());

    cfg.first_party_floors
        .insert("acme-hook".to_string(), "0.9.0".to_string());
    let pinned = trust_policy(&cfg, env!("CARGO_PKG_VERSION")).expect("policy");
    assert_eq!(pinned.binary_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        pinned
            .first_party_floors
            .get("acme-hook")
            .map(String::as_str),
        Some("0.9.0")
    );
}

#[test]
fn to_policy_still_returns_ok_for_a_malformed_floor() {
    let mut cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    cfg.min_versions
        .insert("p".to_string(), "v1.6.0".to_string());
    assert!(
        trust_policy(&cfg, env!("CARGO_PKG_VERSION")).is_ok(),
        "a malformed floor must not fail the boot — it is refused at the comparator instead"
    );
}

use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::abi::mechanism::KindCode;

fn listening_plane(target_from: &str) -> Candidate {
    Candidate {
        kind: KindCode::Plane,
        name: "p1".into(),
        version: "1.0.0".into(),
        aliases: Vec::new(),
        sugar: Vec::new(),
        verbs: vec!["agents".into()],
        selecting: Vec::new(),
        schemes: Vec::new(),
        needs: vec![ReadNeed {
            direction: DIRECTION_INBOUND,
            egress_class: 0,
            transport: "scheme-a".into(),
            auth: String::new(),
            target_from: target_from.into(),
            trust_from: String::new(),
            details: ReadBlob {
                fmt: 0,
                flags: 0,
                bytes: Vec::new(),
            },
            timeout_ms: 0,
            keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
            keep_response_headers: Vec::new(),
            deny_response_headers: Vec::new(),
        }],
        stated: Vec::new(),
        origin: Origin::Dropped {
            file: "p1.tar.gz".into(),
            bytes: Arc::new(Vec::new()),
        },
        disk: false,
        orders: true,
    }
}

#[test]
fn a_selected_plane_inbound_need_keeps_its_consumer_and_physical_bind() {
    let doc: serde_json::Value =
        serde_json::from_str(r#"{"agents": {"ingress": {"listen": "127.0.0.1:8081"}}}"#).unwrap();
    let candidates = vec![listening_plane("ingress")];
    let selected = select(&Uses::of(&doc), &candidates);
    let plan = listener_needs(&doc, &candidates, &selected, Vec::new()).unwrap();
    assert_eq!(plan.binds[0].listen.to_string(), "127.0.0.1:8081");
    assert_eq!(plan.needs[0].instance, "p1");
    assert_eq!(plan.needs[0].at, "agents.ingress");
    let unused: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
    assert!(stages(&unused, vec![listening_plane("ingress")], Vec::new()).is_ok());
}

#[test]
fn a_root_listen_selector_preserves_effective_tls_and_does_not_shadow_relative_settings() {
    let doc =
        serde_json::json!({"tls": {"cert": {"env": "CERT"}, "key": {"env": "KEY"}}, "agents": {}});
    let roots = root_binds(
        &doc,
        &RootListens {
            listen: "127.0.0.1:8080",
            admin_listen: "127.0.0.1:8081",
        },
    );
    let candidates = vec![listening_plane("listen")];
    let selected = select(&Uses::of(&doc), &candidates);
    let plan = listener_needs(&doc, &candidates, &selected, roots.clone()).unwrap();
    assert_eq!(plan.binds, roots);
    assert_eq!(plan.needs[0].at, "listen");
    let relative =
        serde_json::json!({"agents": {"listen": {"listen": "127.0.0.1:8090", "max_conns": 7}}});
    let plan = listener_needs(&relative, &candidates, &selected, roots.clone()).unwrap();
    assert_eq!(plan.binds.last().unwrap().listen.port(), 8090);
    assert_eq!(plan.binds.last().unwrap().max_conns, 7);
    assert_eq!(plan.needs[0].at, "agents.listen");
    for malformed in [
        serde_json::Value::Null,
        serde_json::json!({}),
        serde_json::json!("127.0.0.1:8090"),
    ] {
        let doc = serde_json::json!({"agents": {"listen": malformed}});
        assert!(
            listener_needs(&doc, &candidates, &selected, roots.clone()).is_err(),
            "a present malformed relative bind must not attach to root"
        );
    }
    let missing = vec![listening_plane("")];
    assert!(listener_needs(&doc, &missing, &selected, roots).is_err());
}

#[test]
fn two_instances_of_one_module_can_share_root_and_own_a_distinct_bind() {
    let mut candidate = listening_plane("listen");
    candidate.kind = KindCode::Export;
    let doc = serde_json::json!({"export": {
        "shared": {"module": "p1", "settings": {}},
        "private": {"module": "p1", "settings": {"listen": {"listen": "127.0.0.1:8090"}}}
    }});
    let candidates = vec![candidate];
    let selected = select(&Uses::of(&doc), &candidates);
    let roots = root_binds(
        &doc,
        &RootListens {
            listen: "127.0.0.1:8080",
            admin_listen: "127.0.0.1:8081",
        },
    );
    let plan = listener_needs(&doc, &candidates, &selected, roots).unwrap();
    assert_eq!(
        plan.needs
            .iter()
            .find(|n| n.instance == "shared")
            .unwrap()
            .at,
        "listen"
    );
    assert_eq!(
        plan.needs
            .iter()
            .find(|n| n.instance == "private")
            .unwrap()
            .at,
        "export.private.settings.listen"
    );
    assert_eq!(plan.binds.last().unwrap().listen.port(), 8090);
}

#[test]
fn explicit_same_address_needs_share_compatible_physical_policy() {
    let mut candidate = listening_plane("ingress");
    candidate.kind = KindCode::Export;
    let candidates = vec![candidate];
    let mut doc = serde_json::json!({"tls": {"cert": "cert", "key": "key"}, "export": {
        "first": {"module": "p1", "settings": {"ingress": {"listen": "127.0.0.1:8080"}}},
        "second": {"module": "p1", "settings": {"ingress": {"listen": "127.0.0.1:8080"}}}
    }});
    let roots = root_binds(
        &doc,
        &RootListens {
            listen: "127.0.0.1:8080",
            admin_listen: "127.0.0.1:8081",
        },
    );
    let selected = select(&Uses::of(&doc), &candidates);
    let plan = listener_needs(&doc, &candidates, &selected, roots.clone()).unwrap();
    assert_eq!(plan.binds, roots);
    assert_eq!(plan.needs.len(), 2);
    assert!(plan.needs.iter().all(|need| need.at == "listen"));
    doc["export"]["second"]["settings"]["ingress"]["tls"] = serde_json::Value::Null;
    assert!(
        listener_needs(&doc, &candidates, &selected, roots.clone()).is_err(),
        "explicit clear TLS cannot downgrade an encrypted physical listener"
    );
    doc["export"]["second"]["settings"]["ingress"] = serde_json::json!({"listen": "0.0.0.0:8080"});
    assert!(
        listener_needs(&doc, &candidates, &selected, roots.clone()).is_err(),
        "overlapping wildcard binds are not identical physical listeners"
    );
    doc["export"]["second"]["settings"]["ingress"] =
        serde_json::json!({"listen": "127.0.0.1:8081"});
    assert!(
        listener_needs(&doc, &candidates, &selected, roots.clone()).is_err(),
        "a data SERVE need cannot attach to admin"
    );
    doc["export"]["first"]["settings"]["ingress"] =
        serde_json::json!({"listen": "127.0.0.1:8090", "max_conns": 7});
    doc["export"]["second"]["settings"]["ingress"] =
        serde_json::json!({"listen": "127.0.0.1:8090"});
    assert!(listener_needs(&doc, &candidates, &selected, roots.clone()).is_err());
    let mut reversed = selected.clone();
    reversed.reverse();
    assert!(
        listener_needs(&doc, &candidates, &reversed, roots).is_err(),
        "new private physical policy cannot depend on instance iteration order"
    );
}

#[test]
fn red_the_roots_listeners_head_the_one_list_of_listeners() {
    let doc: serde_json::Value = serde_json::from_str(
        r#"{"listen": "0.0.0.0:8080", "tls": {"cert": {"ref": "c"}, "key": {"ref": "k"}}}"#,
    )
    .unwrap();
    let root = root_binds(
        &doc,
        &RootListens {
            listen: "0.0.0.0:8080",
            admin_listen: "127.0.0.1:8081",
        },
    );
    let got = stages(&doc, Vec::new(), root)
        .map(|s| s.inbound)
        .ok()
        .unwrap();
    let seen: Vec<(String, String, bool, u64)> = got
        .iter()
        .map(|b| {
            assert_eq!(b.owner, BindOwner::Root);
            (
                b.listen_setting(),
                b.listen.to_string(),
                b.tls.is_some(),
                b.max_conns,
            )
        })
        .collect();
    assert_eq!(
        seen,
        [
            (
                "listen".to_string(),
                "0.0.0.0:8080".to_string(),
                true,
                u64::MAX
            ),
            (
                "admin_listen".to_string(),
                "127.0.0.1:8081".to_string(),
                false,
                u64::MAX
            ),
        ]
    );
    let report = stages(&doc, Vec::new(), got).ok().unwrap().lines();
    assert!(report.iter().all(|l| !l.contains("listens:")), "{report:?}");
}

use busbar_contract::plugin::Kind;

#[test]
fn red_3g_deals_each_seat_its_section_and_positions_a_refusal() {
    let doc = Document::parse(
        "agents:\n  a1:\n    url: b\n    tier: big\ntools:\n  t1:\n    url: a\nhooks:\n  h1:\n    module: m\n    settings:\n      k: 1\n"
            .to_owned(),
    )
    .expect("parses");
    let (agents, tools) = (vec!["agents".to_owned()], vec!["tools".to_owned()]);
    let seats = [
        ("p-agents", Seat::of(Kind::Plane, &agents, "p-agents")),
        ("p-tools", Seat::of(Kind::Plane, &tools, "p-tools")),
        ("h1", Seat::of(Kind::Hook, &[], "h1")),
    ];
    let mut seen = Vec::new();
    validate_dealt(&doc, seats, |instance, blob| {
        seen.push((instance, String::from_utf8(blob.to_vec()).unwrap()));
        Ok(())
    })
    .expect("nothing refuses");
    assert_eq!(
        seen,
        [
            ("p-agents", r#"{"agents":{"a1":{"url":"b"}}}"#.to_owned()),
            ("p-tools", r#"{"tools":{"t1":{"url":"a"}}}"#.to_owned()),
            ("h1", r#"{"k":1}"#.to_owned()),
        ]
    );

    let refused = validate_dealt(&doc, seats, |instance, _| {
        if instance == "p-tools" {
            Err("missing field `kind`".to_owned())
        } else {
            Ok(())
        }
    });
    assert_eq!(
        refused,
        Err("config.yaml: invalid YAML: tools: missing field `kind` at line 6 column 3".to_owned())
    );
}

#[test]
fn an_applied_plugins_logs_level_reaches_a_live_sink() {
    use crate::root::loader::dispatch::{Diagnostic, EnvelopeSink, NoSink, PluginLogConfig};
    use busbar_contract::abi::mechanism::call::{DIAG_LOG, SEVERITY_INFO, SEVERITY_WARN};
    let dir = scratch("logs-apply");
    let words = |level: &str| {
        let mut cfg = busbar_kernel::config::PluginsCfg::default();
        cfg.logs.dir = Some(dir.display().to_string());
        cfg.logs.level = Some(level.to_string());
        cfg
    };
    let boot = words("warn");
    let l = &boot.logs;
    let logs = PluginLogConfig::from_words(
        l.dir.as_deref(),
        l.level.as_deref(),
        &l.levels,
        l.rotate_mb,
        l.keep,
    )
    .expect("the boot words resolve");
    let sink = logs
        .clone()
        .sink(
            "applied",
            busbar_contract::abi::mechanism::KindCode::Hook,
            Arc::new(NoSink),
        )
        .expect("the sink opens");
    let info = |text: &str| {
        sink.diag(Diagnostic {
            id: DIAG_LOG,
            name: &[],
            severity: SEVERITY_INFO,
            text: text.as_bytes(),
        });
    };
    info("under warn");
    follow_plugin_logs(&logs, &words("info"));
    info("under info");
    follow_plugin_logs(&logs, &words("warn"));
    info("under warn again");

    sink.diag(Diagnostic {
        id: DIAG_LOG,
        name: &[],
        severity: SEVERITY_WARN,
        text: b"after the final level change",
    });
    let path = logs.path_for("applied", busbar_contract::abi::mechanism::KindCode::Hook);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let text = loop {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("after the final level change") || std::time::Instant::now() > deadline {
            break text;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        text.contains(" WARN  applied hook after the final level change"),
        "the writer reached the final level change:\n{text}"
    );
    assert!(
        text.contains(" INFO  applied hook under info"),
        "the applied level reached the live sink:\n{text}"
    );
    assert!(!text.contains("under warn"), "{text}");
}

const HARNESS_KEY_VAR: &str = "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY";

fn first_party_signed_by(
    key: &crate::root::loader::sign::SigningKey,
    artifact: &[u8],
) -> crate::root::loader::sign::Manifest {
    use crate::root::loader::sign::{sign, Manifest, FIRST_PARTY_PUBLISHER};
    sign(
        key,
        Manifest {
            name: "busbar-harness-seam-plugin".into(),
            alias: "harness-seam".into(),
            kind: "store".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            publisher: FIRST_PARTY_PUBLISHER.into(),
            abi_version: crate::root::loader::supported_abi("store")[0],
            ..Default::default()
        },
        artifact,
    )
}

#[cfg(not(feature = "test-harness"))]
#[test]
fn a_build_without_test_harness_ignores_the_harness_key_and_refuses_a_test_signed_first_party_plugin(
) {
    use crate::root::loader::sign::{embedded_release_pubkey, evaluate, SigningKey};
    let test_key = SigningKey::from_bytes(&[0x5a; 32]);
    let artifact = b"\x7fELF harness seam red arm";
    let signed = first_party_signed_by(&test_key, artifact);
    let mut unsigned = signed.clone();
    unsigned.signature.clear();

    std::env::set_var(
        HARNESS_KEY_VAR,
        hex::encode(test_key.verifying_key().as_bytes()),
    );
    let policy = trust_policy(&PluginsCfg::default(), env!("CARGO_PKG_VERSION"));
    std::env::remove_var(HARNESS_KEY_VAR);
    let policy = policy.expect("the default trust resolves");

    assert_eq!(
        policy.first_party_key,
        embedded_release_pubkey(),
        "a build without test-harness must keep the embedded release key as its only first-party key"
    );
    assert!(
        evaluate(artifact, &signed, &policy).is_err(),
        "a plugin signed first-party by a test key must be refused without test-harness"
    );
    assert!(
        evaluate(artifact, &unsigned, &policy).is_err(),
        "an unsigned first-party plugin must be refused under the default trust"
    );
}

#[cfg(feature = "test-harness")]
#[test]
fn a_test_harness_build_takes_its_first_party_key_from_the_harness_variable() {
    use crate::root::loader::sign::{evaluate, SigningKey, Verdict};
    let test_key = SigningKey::from_bytes(&[0x5a; 32]);
    let hex_key = hex::encode(test_key.verifying_key().as_bytes());
    assert_eq!(HARNESS_FIRST_PARTY_KEY_ENV, HARNESS_KEY_VAR);
    assert_eq!(
        harness_first_party_key(Some(&hex_key)).expect("a well-formed key"),
        Some(test_key.verifying_key())
    );
    assert_eq!(harness_first_party_key(None).unwrap(), None);
    assert_eq!(harness_first_party_key(Some("  ")).unwrap(), None);
    assert!(harness_first_party_key(Some("not-a-key")).is_err());

    let artifact = b"\x7fELF harness seam green arm";
    let policy = crate::root::loader::sign::TrustPolicy {
        first_party_key: harness_first_party_key(Some(&hex_key)).unwrap(),
        ..Default::default()
    };
    assert!(matches!(
        evaluate(
            artifact,
            &first_party_signed_by(&test_key, artifact),
            &policy
        ),
        Ok(Verdict::Trusted {
            first_party: true,
            ..
        })
    ));
}

async fn the_admin_catalog_row_for_a_harness_signed_plugin(
    tag: &str,
) -> (serde_json::Value, serde_json::Value) {
    use crate::root::loader::sign::SigningKey;
    use tower::ServiceExt as _;
    let test_key = SigningKey::from_bytes(&[0x6b; 32]);
    let artifact = b"\x7fELF admin catalog under the root's trust";
    let manifest = first_party_signed_by(&test_key, artifact);
    let dir = scratch(tag);
    std::fs::write(
        dir.join("harness-seam.tar.gz"),
        crate::root::loader::tarball::package(&manifest, "lib.so", artifact).expect("it packs"),
    )
    .expect("the tarball is written");
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .admin_chain(vec![])
        .plugins_dir(dir.clone())
        .plugin_admission(&crate::root::admission::ADMISSION)
        .build();
    let router = busbar_core_admin::build_router(app);
    let request = axum::http::Request::builder()
        .uri("/api/v1/admin/plugins?type=store")
        .body(axum::body::Body::empty())
        .expect("a request");
    std::env::set_var(
        HARNESS_KEY_VAR,
        hex::encode(test_key.verifying_key().as_bytes()),
    );
    let response = router.oneshot(request).await;
    std::env::remove_var(HARNESS_KEY_VAR);
    let response = response.expect("the admin surface answers");
    assert_eq!(response.status().as_u16(), 200);
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("the body");
    let _ = std::fs::remove_dir_all(&dir);
    let page: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON page");
    let row = page["items"]
        .as_array()
        .and_then(|rows| {
            rows.iter()
                .find(|r| r.to_string().contains("harness-seam.tar.gz"))
        })
        .unwrap_or_else(|| panic!("the dropped plugin is listed: {page}"))
        .clone();
    (row["valid"].clone(), row["trust"].clone())
}

#[cfg(feature = "test-harness")]
#[tokio::test]
async fn a_test_harness_admin_catalog_reads_a_harness_signed_plugin_as_valid() {
    let (valid, trust) =
        the_admin_catalog_row_for_a_harness_signed_plugin("admin-trust-green").await;
    assert_eq!(valid, serde_json::json!(true), "trust: {trust}");
    assert_eq!(trust, serde_json::json!("trusted"));
}

#[cfg(not(feature = "test-harness"))]
#[tokio::test]
async fn an_admin_catalog_without_test_harness_refuses_a_harness_signed_plugin() {
    let (valid, trust) = the_admin_catalog_row_for_a_harness_signed_plugin("admin-trust-red").await;
    assert_eq!(valid, serde_json::json!(false), "trust: {trust}");
    assert_eq!(trust, serde_json::json!("rejected"));
}

fn features_reached(manifest: &str, root: &str) -> std::collections::BTreeSet<String> {
    let mut table = std::collections::BTreeMap::<String, Vec<String>>::new();
    let mut in_features = false;
    let mut pending: Option<(String, String)> = None;
    for raw in manifest.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if let Some((name, mut body)) = pending.take() {
            body.push_str(line);
            match body.contains(']') {
                true => {
                    table.insert(name, entries(&body));
                }
                false => pending = Some((name, body)),
            }
            continue;
        }
        if line.starts_with('[') {
            in_features = line == "[features]";
            continue;
        }
        let Some((name, body)) = line.split_once('=').filter(|_| in_features) else {
            continue;
        };
        let (name, body) = (
            name.trim().trim_matches('"').to_string(),
            body.trim().to_string(),
        );
        match body.contains(']') {
            true => {
                table.insert(name, entries(&body));
            }
            false => pending = Some((name, body)),
        }
    }
    fn entries(body: &str) -> Vec<String> {
        body.trim_matches(|c| c == '[' || c == ']' || c == ' ')
            .split(',')
            .map(|e| e.trim().trim_matches('"').to_string())
            .filter(|e| !e.is_empty())
            .collect()
    }
    let mut reached = std::collections::BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(f) = stack.pop() {
        if f.contains(':') || f.contains('/') || !reached.insert(f.clone()) {
            continue;
        }
        stack.extend(table.get(&f).cloned().unwrap_or_default());
    }
    reached
}

#[test]
fn the_release_feature_set_excludes_test_harness() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(dir.join("Cargo.toml")).expect("read busbar's manifest");
    let default = features_reached(&manifest, "default");
    assert!(
        default.contains("root-admin"),
        "the walk reads the default set: {default:?}"
    );
    assert!(
        !default.contains("test-harness"),
        "the default feature set must not reach test-harness: {default:?}"
    );
    let planted = "[features]\ndefault = [\"a\"]\na = [\n  \"dep:x\",\n  \"test-harness\",\n]\ntest-harness = []\n";
    assert!(features_reached(planted, "default").contains("test-harness"));

    let root = dir.join("../..");
    for script in ["scripts/release-build.sh", "scripts/pgo-build.sh"] {
        let text = std::fs::read_to_string(root.join(script)).expect("read the release script");
        let builds: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.starts_with('#') && l.contains("cargo build --release"))
            .collect();
        assert!(!builds.is_empty(), "{script} names its release build");
        for b in builds {
            assert!(
                b.contains("--manifest-path dist/default/Cargo.toml --bin busbar"),
                "{script} builds the default distribution: {b}"
            );
            assert!(
                !b.contains("--features") && !b.contains("--all-features"),
                "{script}'s release build must take busbar's default features: {b}"
            );
        }
    }
}

#[test]
fn red_3g_deals_a_root_pool_named_after_a_knob_as_a_pool() {
    let doc = Document::parse(
        "pools:\n  hooks: [g]\n  tier:\n    members: [{model: m, tier: large}]\n    breaker: {trip: 1}\n  work:\n    members: [{model: m}]\n"
            .to_owned(),
    )
    .expect("parses");
    let pools = vec![busbar_contract::section::RESERVED_POOLS_KEY.to_owned()];
    let seats = [("p-pools", Seat::of(Kind::Plane, &pools, "p-pools"))];
    let mut seen = Vec::new();
    validate_dealt(&doc, seats, |instance, blob| {
        seen.push((instance, String::from_utf8(blob.to_vec()).unwrap()));
        Ok(())
    })
    .expect("nothing refuses");
    assert_eq!(
        seen,
        [(
            "p-pools",
            r#"{"pools":{"tier":{"members":[{"model":"m"}]},"work":{"members":[{"model":"m"}]}}}"#
                .to_owned()
        )]
    );
}

static SECRET_ROWS: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn dropped_secret(name: &str) -> Candidate {
    Candidate {
        kind: KindCode::Secret,
        name: name.into(),
        version: "1.0.0".into(),
        aliases: Vec::new(),
        sugar: Vec::new(),
        verbs: Vec::new(),
        selecting: Vec::new(),
        schemes: Vec::new(),
        needs: Vec::new(),
        stated: Vec::new(),
        origin: Origin::Dropped {
            file: format!("{name}.tar.gz"),
            bytes: Arc::new(Vec::new()),
        },
        disk: false,
        orders: true,
    }
}

#[test]
fn red_a_dry_runs_registry_build_leaves_the_live_dropped_secret_rows_alone() {
    use busbar_contract::secret::SecretAxis as _;
    let _held = SECRET_ROWS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rows = crate::root::linked::secret_rows();
    rows.set_dropped([dropped_secret("row159-live-vault")]);
    assert!(
        rows.answers("row159-live-vault"),
        "the running node's dropped-in secret answers"
    );

    let off = PluginsCfg::default();
    assert!(
        !off.enabled,
        "the dry run's configuration turns the plugins directory off"
    );
    crate::root::boot::registry(Vec::new(), Some(&off), None, &mut |_| {})
        .expect("a build with the plugins directory off is the linked rows alone");
    let answers = rows.answers("row159-live-vault");
    rows.set_dropped(std::iter::empty());
    assert!(
        answers,
        "a dry run's registry build replaced the running node's dropped-in secret rows"
    );
}

#[test]
fn a_committing_builds_admission_replaces_the_dropped_secret_rows() {
    use busbar_contract::secret::SecretAxis as _;
    let _held = SECRET_ROWS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let rows = crate::root::linked::secret_rows();
    rows.set_dropped([dropped_secret("row159-stale-vault")]);

    let off = PluginsCfg::default();
    let registry = crate::root::boot::registry(Vec::new(), Some(&off), None, &mut |_| {})
        .expect("a build with the plugins directory off is the linked rows alone");

    let plugin_rows: Arc<dyn busbar_contract::plugin_rows::PluginRows> = Arc::new(registry);
    admit_secrets(&plugin_rows, &off).expect("no dropped-in secret contests a word");
    let answers = rows.answers("row159-stale-vault");
    rows.set_dropped(std::iter::empty());
    assert!(
        !answers,
        "the committing build's admission kept a dropped-in secret its registry no longer has"
    );
}

pub(super) fn constructor_child(validate: bool) -> ! {
    let late = crate::root::serve::LateServices::new();
    crate::root::boot::install_native_load_guard().unwrap();
    crate::root::loader::dispatch::handle::arm().unwrap();
    let dispatcher = crate::root::dispatch::boot(1, &late);
    crate::root::doors::install_dispatcher(dispatcher);
    crate::register_protocols();
    crate::register_planes();
    crate::root::doors::install_plugin_logs(crate::root::boot::plugin_logs());
    let catalogue = crate::register_diagnostics();
    if validate {
        std::process::exit(crate::root::cli::validate_config_command());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(crate::run(1, late, catalogue, crate::ControlWork::new()));
    panic!("the constructor-only fixture must be refused for its missing plugin door");
}

#[cfg(unix)]
#[test]
fn bootstrap_archive_pins_refuse_before_native_constructors() {
    const CHILD: &str = "BUSBAR_BOOTSTRAP_ARCHIVE_CHILD";
    const MARKER: &str = "BUSBAR_BOOTSTRAP_CTOR_MARKER";
    if std::env::var_os(CHILD).is_some() {
        constructor_child(false);
    }
    let dir = scratch("bootstrap-constructor");
    let source = dir.join("constructor.c");
    let image = dir.join("constructor.so");
    std::fs::write(
        &source,
        r#"#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) static void mark_loaded(void) {
    const char *path = getenv("BUSBAR_BOOTSTRAP_CTOR_MARKER");
    if (path) { FILE *out = fopen(path, "wb"); if (out) { fputs("loaded", out); fclose(out); } }
}
"#,
    )
    .unwrap();
    let mut compiler = std::process::Command::new("cc");
    #[cfg(target_os = "macos")]
    compiler.arg("-dynamiclib");
    #[cfg(not(target_os = "macos"))]
    compiler.args(["-shared", "-fPIC"]);
    let compiled = compiler
        .arg(&source)
        .arg("-o")
        .arg(&image)
        .output()
        .unwrap();
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let library = std::fs::read(image).unwrap();
    let key = crate::root::loader::sign::SigningKey::from_bytes(&[0x35; 32]);
    let stated = crate::root::loader::dispatch::rendering_of(
        busbar_kernel_testkit::test_support::store_double::door,
    )
    .unwrap();
    let facts = busbar_contract::abi::mechanism::rendering::read(&stated).unwrap();
    let make = |version: &str| {
        let head = busbar_contract::abi::mechanism::rendering::RENDERING_MAGIC.len() + 16;
        let len = |at: usize| u32::from_le_bytes(stated[at..at + 4].try_into().unwrap()) as usize;
        let at = head + 4 + len(head);
        let mut rendering = stated[..at].to_vec();
        rendering.extend_from_slice(&(version.len() as u32).to_le_bytes());
        rendering.extend_from_slice(version.as_bytes());
        rendering.extend_from_slice(&stated[at + 4 + len(at)..]);
        let manifest = crate::root::loader::sign::sign(
            &key,
            crate::root::loader::sign::Manifest {
                name: facts.name.clone(),
                alias: "constructor-store".into(),
                kind: "store".into(),
                version: version.into(),
                publisher: "constructor-publisher".into(),
                abi_version: crate::root::loader::supported_abi("store")[0],
                statement: Some(hex::encode(rendering)),
                ..Default::default()
            },
            &library,
        );
        crate::root::loader::tarball::package(&manifest, "lib.so", &library).unwrap()
    };
    let older = make("1.0.0");
    let newer = make("1.1.0");
    let older_hash = crate::root::loader::sign::sha256_hex(&older);
    let newer_hash = crate::root::loader::sign::sha256_hex(&newer);
    let plugins = dir.join("plugins");
    std::fs::create_dir_all(&plugins).unwrap();
    std::fs::write(plugins.join("store.tar.gz"), &older).unwrap();
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&providers, "{}\n").unwrap();
    for (tag, pin, minimum, trusted, constructor) in [
        (
            "swapped-old",
            Some(newer_hash.as_str()),
            "1.0.0",
            true,
            false,
        ),
        ("unpinned", None, "1.0.0", true, false),
        ("matching", Some(older_hash.as_str()), "1.0.0", true, true),
        (
            "below-minimum",
            Some(older_hash.as_str()),
            "1.1.0",
            true,
            false,
        ),
        (
            "untrusted",
            Some(older_hash.as_str()),
            "1.0.0",
            false,
            false,
        ),
    ] {
        let marker = dir.join(format!("{tag}.marker"));
        let publisher_key = if trusted {
            key.verifying_key()
        } else {
            crate::root::loader::sign::SigningKey::from_bytes(&[0x36; 32]).verifying_key()
        };
        let floors = std::collections::BTreeMap::from([(facts.name.clone(), minimum)]);
        let fetch: Vec<_> = pin
            .into_iter()
            .map(|pin| serde_json::json!({"url":"http://127.0.0.1:9/store.tar.gz","sha256":pin}))
            .collect();
        let document = serde_json::json!({
            "providers": {}, "models": {}, "store": {"module":"constructor-store","settings":{}},
            "listen":"127.0.0.1:0", "admin_listen":"127.0.0.1:0",
            "advanced":{"worker_threads":1},
            "plugins":{"enabled":true,"dir":plugins,
                "trust":{"publishers":[{"name":"constructor-publisher","public_key":hex::encode(publisher_key.to_bytes())}]},
                "min_versions":floors,
                "fetch":fetch}
        });
        std::fs::write(&config, serde_yaml::to_string(&document).unwrap()).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "root::boot::tests::bootstrap_archive_pins_refuse_before_native_constructors",
                "--nocapture",
            ])
            .current_dir(&dir)
            .env(CHILD, "1")
            .env(MARKER, &marker)
            .env("BUSBAR_CONFIG", &config)
            .env("BUSBAR_PROVIDERS", &providers)
            .env("BUSBAR_DATA_DIR", dir.join("state"))
            .output()
            .unwrap();
        let logs = String::from_utf8_lossy(&output.stdout).into_owned()
            + &String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "the fixture exports no door: {logs}"
        );
        assert_eq!(marker.exists(), constructor, "{tag}: {logs}");
        if tag == "unpinned" {
            assert!(logs.contains("exact archive SHA-256"), "{logs}");
        }
        assert!(
            !dir.join("state/plugin-highwater.json").exists(),
            "application floors must remain Store-only"
        );
    }
    std::fs::remove_dir_all(dir).unwrap();
}
