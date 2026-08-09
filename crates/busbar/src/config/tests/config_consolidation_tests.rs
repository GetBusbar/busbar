// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/config/overlay.rs`.

use super::*;
use crate::config::{ConfigMgmtCfg, OverlayBackend, OverlayCfg};

fn writable_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("busbar-cfgcons-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// (a) DURABLE-BY-DEFAULT: with NOTHING specified (default `ConfigMgmtCfg`) and NO
/// `BUSBAR_CONFIG_OVERLAY` env var, a mutable config resolves to a writable overlay next to
/// config.yaml, and an admin mutation persisted there SURVIVES a simulated restart (a fresh read).
///
/// Pre-1.5.3 an unset `BUSBAR_CONFIG_OVERLAY` meant RAM-only — there was no
/// default backend, so this durable round-trip had nowhere to land and `read` would find nothing.
#[test]
fn a_mutable_default_persists_across_a_simulated_restart_with_no_env_var() {
    let dir = writable_dir("durable-default");
    let config_path = dir.join("config.yaml");
    let res = resolve_backend(&ConfigMgmtCfg::default(), &config_path, None, true)
        .expect("a mutable default config must resolve a writable overlay");
    assert!(!res.locked, "default config is mutable");
    let path = res
        .path
        .expect("durable-by-default: a writable overlay next to config.yaml");
    assert_eq!(path, dir.join(DEFAULT_OVERLAY_FILENAME));

    let settings = RootSettings {
        per_request_fee: Some(7),
        ..Default::default()
    };
    persist_root(Some(&path), &settings).expect("persist must land durably");
    // Simulate a restart: read the overlay fresh from disk.
    let doc = read(&path).expect("overlay reads back after a 'restart'");
    assert_eq!(
        doc.root.and_then(|r| r.per_request_fee),
        Some(7),
        "the mutation must survive the simulated restart"
    );
}

/// (b) LOCKED ⇒ no overlay backend, so a persist against it is REFUSED (never a silent success).
///
/// Pre-1.5.3 there was no `locked` concept and `persist_root(None, ..)` returned
/// a silent `Ok`, so neither of these assertions could hold.
#[test]
fn b_locked_config_has_no_overlay_and_refuses_a_mutation() {
    let res = resolve_backend(
        &ConfigMgmtCfg {
            locked: true,
            overlay: None,
        },
        std::path::Path::new("/etc/busbar/config.yaml"),
        None,
        true,
    )
    .expect("a locked config resolves (overlay ignored)");
    assert!(res.locked);
    assert!(res.path.is_none(), "locked ⇒ no overlay backend");
    // A persist against the locked (None) backend must ERROR, not silently succeed.
    assert!(persist_root(res.path.as_deref(), &RootSettings::default()).is_err());
}

/// (c) BOOT INVARIANT: a MUTABLE config with the overlay explicitly DISABLED refuses. That state
/// is self-contradictory and can only be reached by typing it into config.yaml, so the fix is to
/// edit the file and the refusal is a boot `Err`.
///
/// The neighbouring case — a mutable config whose backend path is simply not WRITABLE (a
/// read-only config mount) — is NOT a boot refusal; it degrades to no-overlay. That is a property
/// of the environment rather than of the config, and it is covered in
/// `tests/overlay_read_only_tests.rs`.
///
/// Pre-1.5.3 nothing enforced "mutable XOR writable overlay" — a mutable config
/// with no backend booted fine and mutated in RAM only.
#[test]
fn c_mutable_with_the_overlay_explicitly_disabled_refuses() {
    let dir = writable_dir("disabled");
    let config_path = dir.join("config.yaml");
    let err = resolve_backend(
        &ConfigMgmtCfg {
            locked: false,
            overlay: Some(OverlayCfg::Disabled(false)),
        },
        &config_path,
        None,
        true,
    )
    .expect_err("mutable + overlay disabled must refuse");
    assert!(
        err.contains("config.locked") || err.contains("no writable overlay"),
        "the refusal must be actionable: {err}"
    );
}

/// (d) Overlay backend PRECEDENCE for the env→config migration: an explicit `config.overlay` WINS;
/// else the deprecated `BUSBAR_CONFIG_OVERLAY` env override is honored; else the default next to
/// config.yaml. Both the new config key AND the deprecated env fallback work.
///
/// Pre-1.5.3 the ONLY source was the env var; `config.overlay` did not exist, so
/// the "config wins" and "default next to config" cases had no code path.
#[test]
fn d_overlay_precedence_config_over_env_over_default() {
    let dir = writable_dir("precedence");
    let config_path = dir.join("config.yaml");
    let env = dir.join("env-overlay.json");

    // config.overlay.file wins over the env override.
    let cfg_file = ConfigMgmtCfg {
        locked: false,
        overlay: Some(OverlayCfg::Backend(OverlayBackend {
            file: Some("chosen.json".into()),
        })),
    };
    let r = resolve_backend(&cfg_file, &config_path, Some(&env), true).unwrap();
    assert_eq!(
        r.path.unwrap(),
        dir.join("chosen.json"),
        "config.overlay wins"
    );

    // No config.overlay → the deprecated env override is used (back-compat).
    let r2 = resolve_backend(&ConfigMgmtCfg::default(), &config_path, Some(&env), true).unwrap();
    assert_eq!(
        r2.path.unwrap(),
        env,
        "env fallback is honored when config is silent"
    );

    // Neither → default next to config.yaml.
    let r3 = resolve_backend(&ConfigMgmtCfg::default(), &config_path, None, true).unwrap();
    assert_eq!(
        r3.path.unwrap(),
        dir.join(DEFAULT_OVERLAY_FILENAME),
        "default next to config"
    );
}

/// (e) A BARE-FILENAME overlay (no directory component) in a writable cwd must be reported WRITABLE
/// — so a `BUSBAR_CONFIG=config.yaml` deployment run from inside its config dir (overlay resolves to
/// a bare `busbar-overlay.json`) BOOTS instead of being refused.
///
/// The pre-fix `is_backend_writable` no-parent branch probed the not-yet-existing
/// bare path via `OpenOptions::open` WITHOUT `.create(true)` → `NotFound` → `false` → boot refused,
/// even though the cwd is perfectly writable.
#[test]
fn e_bare_filename_overlay_in_writable_cwd_is_writable() {
    // A bare filename → `parent()` is `Some("")` (empty), NOT `None`: the exact branch under test.
    let bare = std::path::PathBuf::from(format!(
        "busbar-cfgcons-bare-does-not-exist-{}.json",
        std::process::id()
    ));
    assert!(
        !bare.exists(),
        "test precondition: the bare target must not already exist"
    );
    assert!(
        is_backend_writable(&bare),
        "a bare-filename overlay in a writable cwd must probe the cwd and report writable"
    );
    // The probe is cleaned up and the bare target itself is never created (only a probe file was).
    assert!(
        !bare.exists(),
        "the writability probe must not create the overlay target file"
    );
}

/// (f) The `None` (LOCKED) overlay path is REFUSED by EVERY persist/reset entry point — not just
/// `persist_root`. Guards against reverting any one of them to the pre-1.5.3 silent `Ok(())`.
///
/// `clear_section(None, ..)` and `try_persist_plugin_versions(None, ..)` returned
/// a silent `Ok(())` until this fix; reverting either to `return Ok(())` fails this test.
#[test]
fn f_every_persist_entry_point_refuses_a_none_locked_overlay() {
    let empty_names: std::collections::HashSet<String> = std::collections::HashSet::new();
    assert!(
        persist(
            None,
            &HashMap::<String, HookCfg>::new(),
            &[],
            None,
            None,
            &empty_names,
        )
        .is_err(),
        "persist(None) must refuse (hooks)"
    );
    assert!(
        persist_groups(
            None,
            &BTreeMap::<String, GroupCfg>::new(),
            None,
            None,
            &empty_names,
        )
        .is_err(),
        "persist_groups(None) must refuse (groups)"
    );
    assert!(
        persist_root(None, &RootSettings::default()).is_err(),
        "persist_root(None) must refuse (settings)"
    );
    assert!(
        clear_section(None, OverlaySection::Hooks).is_err(),
        "clear_section(None) must refuse (per-section reset)"
    );
    assert!(
        try_persist_plugin_versions(None, &BTreeMap::<String, String>::new()).is_err(),
        "try_persist_plugin_versions(None) must refuse (rollback pin)"
    );
}
