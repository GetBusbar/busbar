// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's boot stages: its `plugins.fetch` runs the loader's fetch, and only ever downloads
//! through its SSRF-guarded download over the one connector (`root::plugin_fetch`).

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

/// A PIN-CACHED entry skips the network: the file already on disk hashes to the pin, so the
/// loader's fetch the root delegates to reports it cached and never calls the download (which
/// would fail the test). The root's `plugins_fetch` downloads only through the connector
/// (`root::plugin_fetch`, row 130 E6), so the panicking download is handed to the loader's fetch
/// directly; the root maps its outcome one to one.
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

/// THE ROOT'S FETCH CANNOT BYPASS THE GUARD: a cloud-metadata URL fetched through the root is
/// refused, before any dial, with the same message the loader's fetch gives the root's
/// SSRF-guarded download directly, and nothing is written.
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

/// PER-NAME anti-downgrade through the root's `trust_policy` (floors-only semantics): a validly-signed
/// first-party artifact on its own independent version line LOADS under the default policy (no
/// automatic binary-version floor — plugins ship 1.0.x/2.x under a 1.5.0 engine), while an
/// explicit per-name floor (the persisted rollback-pin seam) binds exactly at its pinned version:
/// at the pin loads, below the pin refuses.
#[test]
fn to_policy_floor_distinguishes_automatic_from_explicit_downgrade() {
    use crate::root::loader::sign::{evaluate, sign, Manifest, SigningKey, Verdict};

    // A first-party release key + an OLD (below the current binary) signed first-party artifact.
    let release = SigningKey::from_bytes(&[7u8; 32]);
    let artifact = b"\x7fELF old first-party build";
    let old = sign(
        &release,
        Manifest {
            name: "busbar-store-kv-plugin".into(),
            alias: "kv".into(),
            kind: "store".into(),
            version: "0.9.0".into(), // below any real CARGO_PKG_VERSION (1.x)
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

    // Build both policies off ONE PluginsCfg, but embed the SAME release key as the first-party key so
    // the signature verifies in-test (production reads the embedded release key; here we inject it).
    let cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    let mut automatic = trust_policy(&cfg, env!("CARGO_PKG_VERSION")).expect("automatic policy");
    automatic.first_party_keys = vec![crate::root::loader::sign::FirstPartyKey::unnamed(
        release.verifying_key(),
    )];
    // DEFAULT policy: no per-name floor pins this artifact, so its 0.9.0 version line is its own
    // business — a verified first-party plugin loads regardless of the binary's version.
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

    // EXPLICIT per-name floor (the rollback-pin seam): pinned exactly at the artifact's version,
    // it loads; the pin binds and nothing older passes (asserted below).
    let mut explicit = trust_policy(&cfg, env!("CARGO_PKG_VERSION")).expect("explicit policy");
    explicit
        .first_party_floors
        .insert("busbar-store-kv-plugin".to_string(), "0.9.0".to_string());
    explicit.first_party_keys = vec![crate::root::loader::sign::FirstPartyKey::unnamed(
        release.verifying_key(),
    )];
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

    // But an EVEN OLDER artifact is STILL refused under the explicit floor — a rollback lowers the
    // floor to EXACTLY the pinned target, not to zero.
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

/// A runtime-set PER-PLUGIN `first_party_floors` override on `PluginsCfg` is honored by the root's `trust_policy`
/// (the seam the persisted rollback pin drives) for that name ONLY, while the global `binary_version`
/// stays the binary's own version — so an UNPINNED first-party plugin still faces the full floor.
#[test]
fn to_policy_honors_runtime_first_party_floor_override() {
    let mut cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    // Default: the automatic floor equals the binary version and there are no per-name overrides.
    let auto = trust_policy(&cfg, env!("CARGO_PKG_VERSION")).expect("policy");
    assert_eq!(auto.binary_version, env!("CARGO_PKG_VERSION"));
    assert!(auto.first_party_floors.is_empty());
    // With an explicit per-name override (as a persisted rollback pin sets): only that name is lowered;
    // the global binary_version floor (what every OTHER first-party plugin uses) is untouched.
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

/// REGRESSION PROOF: a malformed `min_versions` floor does NOT fail the root's `trust_policy` — the
/// comparator (`version_at_least`), not config validation, is where a malformed floor is refused
/// (fail closed at the comparator, don't refuse the boot). Passes before AND after; it is
/// the anti-regression guard against the superseded design (the root's `trust_policy` returning
/// `Err` for this case), which the current design deliberately does NOT do. If this test goes red,
/// the superseded design has been reintroduced.
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

// ── INBOUND ──

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

/// RED (ARCHITECT ruling 2026-09-30): until an accepted connection has a consumer, a selected
/// plugin that declares an inbound need is refused at validate, naming the instance, the plugin and
/// the need, before its bind is even read, never bound and closed.
#[test]
fn red_a_selected_plugin_with_an_inbound_need_is_refused_until_it_can_be_served() {
    let doc: serde_json::Value =
        serde_json::from_str(r#"{"agents": {"ingress": {"listen": "127.0.0.1:8081"}}}"#).unwrap();
    let err = stages(&doc, vec![listening_plane("ingress")], Vec::new())
        .err()
        .expect("refused");
    assert!(
        err.starts_with(
            "agents (p1): inbound need 0 over `scheme-a` cannot be served by this build"
        ),
        "{err}"
    );
    // Not selected, not refused: the refusal is the configuration's use, not the plugin's presence.
    let unused: serde_json::Value = serde_json::from_str(r#"{}"#).unwrap();
    assert!(stages(&unused, vec![listening_plane("ingress")], Vec::new()).is_ok());
}

/// RED (ARCHITECT ruling 2026-09-30): the root's own listeners head THE ONE LIST: the data
/// door at `listen` with its raw `tls` block and the admin surface at `admin_listen` with its raw
/// `admin_tls`, uncapped as in 1.5.5; `--validate` reports only plugin listeners.
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

// ── STAGE 3g: THE DEAL ──

use busbar_contract::plugin::Kind;

/// RED: at 3g each seat is dealt only its own section, reserved sub-keys stripped,
/// and a plugin's validation refusal names the operator's file position in 1.5.5's form.
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

/// **RED ARM: `plugins.logs` FOLLOWS A CONFIG APPLY** (THE DESIGN §11.2). A sink opened under
/// `warn` drops an `info` line; once an apply's `plugins.logs` says `info`, the same sink writes it,
/// and a `warn` config applied again drops the next.
#[test]
fn an_applied_plugins_logs_level_reaches_a_live_sink() {
    use crate::root::loader::dispatch::{Diagnostic, EnvelopeSink, NoSink, PluginLogConfig};
    use busbar_contract::abi::mechanism::call::{DIAG_LOG, SEVERITY_INFO};
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
    let path = logs.path_for("applied", busbar_contract::abi::mechanism::KindCode::Hook);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let text = loop {
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        if text.contains("under info") || std::time::Instant::now() > deadline {
            break text;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    drop(sink);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        text.contains(" INFO  applied hook under info"),
        "the applied level reached the live sink:\n{text}"
    );
    assert!(!text.contains("under warn"), "{text}");
}

/// The variable the `test-harness` build's first-party key seam reads
/// (`boot::HARNESS_FIRST_PARTY_KEY_ENV`), spelled out here because a build without the feature has
/// no such constant.
const HARNESS_KEY_VAR: &str = "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY";

/// A first-party (`publisher: busbar`) manifest for `artifact`, signed by `key`.
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

/// **THE RED ARM OF THE HARNESS KEY SEAM (ARCHITECT ruling, busbar #700).** In a build WITHOUT
/// `test-harness`, which is every release build, setting the harness variable to a test key changes
/// nothing: the root's trust resolution keeps the embedded release key, so a plugin the test key
/// signed first-party is refused, and so is an unsigned one.
#[cfg(not(feature = "test-harness"))]
#[test]
fn a_build_without_test_harness_ignores_the_harness_key_and_refuses_a_test_signed_first_party_plugin(
) {
    use crate::root::loader::sign::{embedded_release_keys, evaluate, SigningKey};
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
        policy.first_party_keys,
        embedded_release_keys(),
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

/// The seam itself, in a `test-harness` build: a set variable names the first-party key, under which
/// a plugin that key signed first-party is trusted as first-party; unset or empty leaves the
/// embedded key standing; a malformed value is refused, never ignored.
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
        first_party_keys: harness_first_party_key(Some(&hex_key))
            .unwrap()
            .map(crate::root::loader::sign::FirstPartyKey::unnamed)
            .into_iter()
            .collect(),
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

/// THE ADMIN CATALOG'S ROW for a plugin a harness key signed first-party, read over
/// `GET /api/v1/admin/plugins?type=store` on a snapshot carrying the root's trust builder
/// ([`trust_policy`], what `root::linked::register_stores` installs for every snapshot), with the
/// harness variable set to that key: the row's (`valid`, `trust`). The key is not the kernel test
/// build's stand-in release key, so only the root's harness seam can admit it.
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
    let app = busbar_kernel::test_support::TestApp::new()
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
        // The row is found by its tarball's name, wherever the row states it.
        .and_then(|rows| {
            rows.iter()
                .find(|r| r.to_string().contains("harness-seam.tar.gz"))
        })
        .unwrap_or_else(|| panic!("the dropped plugin is listed: {page}"))
        .clone();
    (row["valid"].clone(), row["trust"].clone())
}

/// **THE ADMIN CATALOG JUDGES UNDER BOOT'S TRUST (the fleet e2e that read it red).** In a
/// `test-harness` build with the harness key set, the catalog row for a plugin that key signed
/// first-party reads valid and trusted — the verdict boot admits it under — because the admin
/// surface resolves through the root's one builder, harness key included, and builds none of its
/// own. RED before: the admin crate built its own policy without the harness key and reported the
/// row rejected (`first-party plugin only`) while boot admitted the plugin.
#[cfg(feature = "test-harness")]
#[tokio::test]
async fn a_test_harness_admin_catalog_reads_a_harness_signed_plugin_as_valid() {
    let (valid, trust) =
        the_admin_catalog_row_for_a_harness_signed_plugin("admin-trust-green").await;
    assert_eq!(valid, serde_json::json!(true), "trust: {trust}");
    assert_eq!(trust, serde_json::json!("trusted"));
}

/// The red arm: in a build WITHOUT `test-harness`, the same plugin under the same variable is
/// refused by the admin catalog, as boot refuses it — the harness key reaches neither.
#[cfg(not(feature = "test-harness"))]
#[tokio::test]
async fn an_admin_catalog_without_test_harness_refuses_a_harness_signed_plugin() {
    let (valid, trust) = the_admin_catalog_row_for_a_harness_signed_plugin("admin-trust-red").await;
    assert_eq!(valid, serde_json::json!(false), "trust: {trust}");
    assert_eq!(trust, serde_json::json!("rejected"));
}

/// The features a `[features]` table turns on from `root`, transitively: only the package's own
/// features (a `dep:` or `crate/feature` entry enables nothing of this package's own).
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

/// THE RELEASE ARTIFACT NEVER CARRIES THE HARNESS SEAM (ARCHITECT ruling, busbar #700, condition b):
/// the release builds (`scripts/release-build.sh`, both `scripts/pgo-build.sh` builds) compile
/// the default distribution (`dist/default`) with its default features and name no `--features` or `--all-features`, and the
/// default feature set does not reach `test-harness`. RED arm: a manifest whose default reaches it
/// through another feature is caught, so the walk is not vacuous.
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

/// RED (Q-STEP9-a, ARCHITECT 2026-10-07; base: a root pool named after a reserved sub-key was
/// stripped from the dealt blob as if it were that knob): the plane whose verb is the root `pools:`
/// section is dealt a pool named `tier` or `work` as the pool it is, its own knobs and its members'
/// taken off; only 1.5.5's two section words leave at the section level.
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

// ── THE DROPPED-IN SECRET ROWS ──

/// The process's one secret axis (`root::linked::secret_rows`) is shared by every test here that
/// writes its dropped-in rows: each holds this while its rows are in play.
static SECRET_ROWS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// A dropped-in secret plugin the running node admitted, answering `name`.
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

/// A DRY RUN LEAVES THE LIVE SECRET ROWS ALONE (row 159, audit root A-4): the registry build is
/// stage 1, Discover, which `--validate` and the admin config-validate run too (BUSBAR-1.6.0.md
/// l.456-457: "`--validate` runs stages 0–2 … nothing dials"; "A validation refusal keeps the
/// running generation"), and the secret plugins are opened in stage 3 (l.444, l.448). So a registry
/// build over a configuration with `plugins.enabled: false` leaves the dropped-in secret plugin
/// the running node admitted answering its word: a `{module: <it>}` reference keeps resolving.
///
/// RED before the fix: `root::boot::registry` put the build's dropped-in secret set on the
/// process's one secret axis (`admit_dropped` → `set_dropped`), so the dry run's empty set replaced
/// the running node's and the module stopped answering.
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

/// GREEN TWIN of the dry-run test above: the admission the committing builds make (boot's scan and
/// the app build, through the install record's `secret_admit`) still REPLACES the dropped-in secret
/// rows with its own registry's set (BUSBAR-1.6.0.md §3, stages 3a/3e open the secret plugins).
/// Added with the fix: before it, the registry build was the only admission, so there was no
/// separate committing path to name.
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
    // The app build's path: the kernel holds the registry as the contract's rows view and hands it
    // to the install record's admission, which reads it back as the registry this root built.
    let plugin_rows: Arc<dyn busbar_contract::plugin_rows::PluginRows> = Arc::new(registry);
    admit_secrets(&plugin_rows).expect("no dropped-in secret contests a word");
    let answers = rows.answers("row159-stale-vault");
    rows.set_dropped(std::iter::empty());
    assert!(
        !answers,
        "the committing build's admission kept a dropped-in secret its registry no longer has"
    );
}
