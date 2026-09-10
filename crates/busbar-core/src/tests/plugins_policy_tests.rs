// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `plugins:` RESOLUTION, proven where it lives: the trust policy's floors and warnings and the
//! fetch-list derivation. These moved out of the config grammar's own test battery with the
//! resolution they exercise — a grammar test asks "does this parse"; these ask "what does it mean
//! to the loader", which is the engine's question.

use crate::config::PluginsCfg;

/// `to_policy_with_floor`'s anti-downgrade-floor sanity warning must fire ONLY for a
/// non-empty, malformed floor — never for an OMITTED floor (empty string, "no floor set", not
/// "malformed floor") and never for a well-formed one. A minimal capturing `tracing::Subscriber`
/// (no test-only crate needed) records whether the WARN actually fired.
#[test]
fn to_policy_with_floor_warns_only_on_a_non_empty_malformed_floor() {
    use std::sync::{Arc, Mutex};

    struct CapturingSubscriber(Arc<Mutex<Vec<String>>>);
    impl tracing::Subscriber for CapturingSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            if *event.metadata().level() == tracing::Level::WARN {
                self.0
                    .lock()
                    .unwrap()
                    .push(event.metadata().name().to_string());
            }
        }
        fn enter(&self, _span: &tracing::span::Id) {}
        fn exit(&self, _span: &tracing::span::Id) {}
    }

    let run = |floor: &str| -> usize {
        let events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sub = CapturingSubscriber(events.clone());
        let mut cfg = PluginsCfg::default();
        cfg.min_versions.insert("p".to_string(), floor.to_string());
        tracing::subscriber::with_default(sub, || {
            let _ = super::trust_policy(&cfg, "1.5.0");
        });
        let n = events.lock().unwrap().len();
        n
    };

    assert_eq!(run(""), 0, "an omitted floor (empty string) must not warn");
    assert_eq!(run("1.2.3"), 0, "a well-formed floor must not warn");
    assert_eq!(
        run("v1.2.3"),
        1,
        "a malformed (leading-'v') floor must warn exactly once"
    );
}

/// PER-NAME anti-downgrade through `to_policy` (floors-only semantics): a validly-signed
/// first-party artifact on its own independent version line LOADS under the default policy (no
/// automatic binary-version floor — plugins ship 1.0.x/2.x under a 1.5.0 engine), while an
/// explicit per-name floor (the persisted rollback-pin seam) binds exactly at its pinned version:
/// at the pin loads, below the pin refuses.
#[test]
fn to_policy_floor_distinguishes_automatic_from_explicit_downgrade() {
    use busbar_plugin_sign::{evaluate, sign, Manifest, SigningKey, Verdict};

    // A first-party release key + an OLD (below the current binary) signed first-party artifact.
    let release = SigningKey::from_bytes(&[7u8; 32]);
    let artifact = b"\x7fELF old first-party build";
    let old = sign(
        &release,
        Manifest {
            name: "busbar-store-valkey-plugin".into(),
            alias: "valkey".into(),
            kind: "store".into(),
            version: "0.9.0".into(), // below any real CARGO_PKG_VERSION (1.x)
            publisher: busbar_plugin_sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: 2,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
        },
        artifact,
    );

    // Build both policies off ONE PluginsCfg, but embed the SAME release key as the first-party key so
    // the signature verifies in-test (production reads the embedded release key; here we inject it).
    let cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    let mut automatic = crate::preflight::engine_trust_policy(&cfg).expect("automatic policy");
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
    let mut explicit = crate::preflight::engine_trust_policy(&cfg).expect("explicit policy");
    explicit.first_party_floors.insert(
        "busbar-store-valkey-plugin".to_string(),
        "0.9.0".to_string(),
    );
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
            name: "busbar-store-valkey-plugin".into(),
            alias: "valkey".into(),
            kind: "store".into(),
            version: "0.8.0".into(),
            publisher: busbar_plugin_sign::FIRST_PARTY_PUBLISHER.into(),
            abi_version: 2,
            sha256: String::new(),
            signature: String::new(),
            description: String::new(),
            homepage: String::new(),
            license: String::new(),
            needs: Default::default(),
            settings_schema: None,
            schema_derived: false,
            host: None,
        },
        artifact,
    );
    assert!(
        evaluate(artifact, &older, &explicit).is_err(),
        "an artifact below the pinned rollback target is still refused"
    );
}

/// A runtime-set PER-PLUGIN `first_party_floors` override on `PluginsCfg` is honored by `to_policy`
/// (the seam the persisted rollback pin drives) for that name ONLY, while the global `binary_version`
/// stays the binary's own version — so an UNPINNED first-party plugin still faces the full floor.
#[test]
fn to_policy_honors_runtime_first_party_floor_override() {
    let mut cfg = PluginsCfg {
        enabled: true,
        ..Default::default()
    };
    // Default: the automatic floor equals the binary version and there are no per-name overrides.
    let auto = crate::preflight::engine_trust_policy(&cfg).expect("policy");
    assert_eq!(auto.binary_version, env!("CARGO_PKG_VERSION"));
    assert!(auto.first_party_floors.is_empty());
    // With an explicit per-name override (as a persisted rollback pin sets): only that name is lowered;
    // the global binary_version floor (what every OTHER first-party plugin uses) is untouched.
    cfg.first_party_floors
        .insert("acme-hook".to_string(), "0.9.0".to_string());
    let pinned = crate::preflight::engine_trust_policy(&cfg).expect("policy");
    assert_eq!(pinned.binary_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        pinned
            .first_party_floors
            .get("acme-hook")
            .map(String::as_str),
        Some("0.9.0")
    );
}

/// REGRESSION PROOF: a malformed `min_versions` floor does NOT fail `to_policy` — the
/// comparator (`version_at_least`), not config validation, is where a malformed floor is refused
/// (fail closed at the comparator, don't refuse the boot). Passes before AND after; it is
/// the anti-regression guard against the superseded design (`to_policy` returning
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
        crate::preflight::engine_trust_policy(&cfg).is_ok(),
        "a malformed floor must not fail the boot — it is refused at the comparator instead"
    );
}

#[test]
fn test_fetch_specs_maps_github_and_url() {
    use crate::config::PluginsCfg;
    let yaml = "\
enabled: true
fetch:
  - github: acme/widget@v2.0.1
    sha256: deadbeef
  - url: https://host/plugins/store-sqlite.tar.gz
";
    let cfg: PluginsCfg = serde_yaml::from_str(yaml).unwrap();
    let specs = super::fetch_specs(&cfg).expect("fetch_specs resolves");
    assert_eq!(specs.len(), 2);
    // github → release-asset url + {repo}.tar.gz filename, pin carried.
    assert_eq!(specs[0].filename, "widget.tar.gz");
    assert_eq!(
        specs[0].url,
        "https://github.com/acme/widget/releases/download/v2.0.1/widget.tar.gz"
    );
    assert_eq!(specs[0].sha256.as_deref(), Some("deadbeef"));
    // url → itself, filename from basename, no pin.
    assert_eq!(specs[1].url, "https://host/plugins/store-sqlite.tar.gz");
    assert_eq!(specs[1].filename, "store-sqlite.tar.gz");
    assert_eq!(specs[1].sha256, None);
}

#[test]
fn test_fetch_env_spec_reads_var() {
    use crate::config::PluginsCfg;
    std::env::set_var("BUSBAR_T_FETCH_URL", "https://host/p/thing.tar.gz@abc123");
    let cfg: PluginsCfg =
        serde_yaml::from_str("enabled: true\nfetch:\n  - env: BUSBAR_T_FETCH_URL\n").unwrap();
    let specs = super::fetch_specs(&cfg).expect("env spec resolves");
    assert_eq!(specs[0].url, "https://host/p/thing.tar.gz");
    assert_eq!(specs[0].sha256.as_deref(), Some("abc123"));
    assert_eq!(specs[0].filename, "thing.tar.gz");
    std::env::remove_var("BUSBAR_T_FETCH_URL");
}

#[test]
fn test_fetch_env_spec_unset_is_error() {
    use crate::config::PluginsCfg;
    std::env::remove_var("BUSBAR_T_FETCH_UNSET");
    let cfg: PluginsCfg =
        serde_yaml::from_str("enabled: true\nfetch:\n  - env: BUSBAR_T_FETCH_UNSET\n").unwrap();
    let err = super::fetch_specs(&cfg).expect_err("unset env var must error");
    assert!(
        err.contains("BUSBAR_T_FETCH_UNSET") && err.contains("not set"),
        "{err}"
    );
}
