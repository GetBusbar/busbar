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
    let via_root = plugins_fetch(&dir, &[target.clone()], true, &guard).unwrap_err();
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
            declares: Default::default(),
            statement: None,
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
            declares: Default::default(),
            statement: None,
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
