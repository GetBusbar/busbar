// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The root's boot stages: its `plugins.fetch` runs the loader's fetch, and only ever downloads
//! through the kernel's SSRF-guarded downloader.

use super::*;

fn scratch(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!(
        "busbar-root-fetch-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A PIN-CACHED entry skips the network: the file already on disk hashes to the pin, so the
/// root's fetch reports it cached and never calls the downloader (which would fail the test).
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
    let got = plugins_fetch(&dir, &[target], true, &never).expect("the cached pin fetches");
    assert_eq!(
        got,
        vec![Fetched::Cached {
            filename: "cached-blob.dat".into()
        }]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE ROOT'S FETCH CANNOT BYPASS THE GUARD: a cloud-metadata URL fetched through the root, with
/// the kernel's SSRF-guarded downloader, is refused with the same message the loader's fetch gives
/// that downloader directly, and nothing is written.
#[test]
fn the_roots_fetch_refuses_a_metadata_host_through_the_kernels_guard() {
    let dir = scratch("ssrf");
    let target = FetchTarget {
        url: "https://169.254.169.254/latest/plugin.tar.gz".into(),
        sha256: None,
        filename: "plugin.tar.gz".into(),
    };
    let guard = busbar_kernel::preflight::plugin_fetch_downloader(&[]);
    let via_root = plugins_fetch(&dir, std::slice::from_ref(&target), true, &guard).unwrap_err();
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
    automatic.first_party_key = Some(release.verifying_key());
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

/// RED (TODO step 9): at 3g each seat is dealt only its own section, reserved sub-keys stripped,
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
    let path = logs.path_for("applied");
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
