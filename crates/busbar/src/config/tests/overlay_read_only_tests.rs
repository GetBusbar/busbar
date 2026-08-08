// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A READ-ONLY CONFIG MOUNT MUST NOT STOP BUSBAR FROM SERVING.
//!
//! The documented Docker quickstart is the very first command a new user runs, and it mounts the
//! config read-only:
//!
//! ```text
//! docker run -d -p 8080:8080 -e ANTHROPIC_KEY \
//!   -v "$PWD/config.yaml:/etc/busbar/config.yaml:ro" getbusbar/busbar
//! ```
//!
//! On 1.5.3 that container exited 1 before binding a port, because the default overlay backend
//! (`busbar-overlay.json` next to config.yaml) lands in the read-only mount and `resolve_backend`
//! treated an unwritable backend as a boot refusal.
//!
//! The invariant the refusal was defending is real: an admin-API config change that cannot be
//! persisted would apply in RAM and silently revert on the next restart. But `path: None` already
//! defends it — every persist entry point refuses a `None` backend outright (see the `(f)` case in
//! `overlay.rs` and `NO_WRITABLE_OVERLAY_MSG` in the admin handlers). So the correct posture for an
//! unwritable backend is DEGRADE-AND-WARN, not refuse-to-boot: serve traffic, refuse mutations.
//!
//! These tests pin that, and pin the line between the two "no usable backend" states: an
//! environmental one (unwritable path) degrades, a self-contradictory config (`overlay: false` on a
//! mutable config) still refuses.

use crate::config::overlay::resolve_backend;
use crate::config::{ConfigMgmtCfg, OverlayBackend, OverlayCfg};

/// A scratch directory that this test owns outright.
fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("busbar-ro-cfg-{tag}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Drop a directory's write bit, run `f`, then restore it so cleanup can proceed even on a panic
/// path. Returns whatever `f` returned.
#[cfg(unix)]
fn with_read_only_dir<T>(dir: &std::path::Path, f: impl FnOnce() -> T) -> T {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    let out = f();
    let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755));
    out
}

/// THE QUICKSTART CASE. A config with no `config:` block at all (so mutable by default, exactly the
/// minimal config the getting-started guide tells you to write) living in a directory busbar cannot
/// write to RESOLVES rather than refusing, and resolves to NO overlay backend.
///
/// On 1.5.3 this returned `Err`, `main` called `die`, and the container exited 1 with
/// "the overlay backend '/etc/busbar/busbar-overlay.json' is not writable" before ever binding
/// :8080.
#[cfg(unix)]
#[test]
fn a_read_only_config_dir_boots_without_an_overlay_instead_of_refusing() {
    let dir = scratch("quickstart");
    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, "models: {}\n").unwrap();

    let res = with_read_only_dir(&dir, || {
        resolve_backend(&ConfigMgmtCfg::default(), &config_path, None, true)
    })
    .expect("a read-only config dir must NOT refuse to boot");

    assert!(
        res.path.is_none(),
        "an unwritable backend must resolve to NO backend, never to a path busbar cannot write: \
         {:?}",
        res.path
    );
    assert!(
        res.read_only_backend,
        "the degraded posture must be visible to the caller so boot can warn about it"
    );
    assert!(
        !res.locked,
        "the operator did not ask for `config.locked: true`; reporting the config as LOCKED would \
         misattribute an environmental constraint to a config choice they did not make"
    );
}

/// The degraded resolution is FAIL-CLOSED, not merely quiet: a mutation attempted against the
/// resolved backend errors rather than pretending to have persisted. This is the assertion that
/// makes degrading safe — it is the whole reason the boot refusal can be dropped.
#[cfg(unix)]
#[test]
fn b_a_degraded_backend_refuses_a_persist_rather_than_silently_dropping_it() {
    let dir = scratch("failclosed");
    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, "models: {}\n").unwrap();

    let res = with_read_only_dir(&dir, || {
        resolve_backend(&ConfigMgmtCfg::default(), &config_path, None, true)
    })
    .expect("a read-only config dir must resolve");

    assert!(
        crate::config::overlay::persist_root(
            res.path.as_deref(),
            &crate::config::overlay::RootSettings::default()
        )
        .is_err(),
        "a persist against the degraded (None) backend MUST error; a silent Ok is the RAM-only \
         mutation the boot invariant exists to prevent"
    );
}

/// The line holds in the other direction: a WRITABLE config dir is unaffected. Degrading must not
/// have turned the normal durable-by-default path into a no-overlay path by accident.
#[test]
fn c_a_writable_config_dir_still_resolves_a_durable_backend() {
    let dir = scratch("writable");
    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, "models: {}\n").unwrap();

    let res = resolve_backend(&ConfigMgmtCfg::default(), &config_path, None, true)
        .expect("a writable config dir resolves");

    assert_eq!(
        res.path.as_deref(),
        Some(dir.join("busbar-overlay.json").as_path()),
        "durable-by-default: the overlay lands next to config.yaml"
    );
    assert!(!res.read_only_backend);
    assert!(!res.locked);
}

/// An EXPLICIT `config.overlay.file` pointed at an unwritable directory degrades the same way. The
/// operator named a path, but the filesystem still says no, and refusing to serve traffic over it
/// is the same hostile outcome as the default-path case.
#[cfg(unix)]
#[test]
fn d_an_explicit_overlay_path_in_an_unwritable_dir_degrades_too() {
    let dir = scratch("explicit");
    let ro = dir.join("locked-down");
    std::fs::create_dir_all(&ro).unwrap();
    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, "models: {}\n").unwrap();

    let cfg = ConfigMgmtCfg {
        locked: false,
        overlay: Some(OverlayCfg::Backend(OverlayBackend {
            file: Some(ro.join("overlay.json").to_string_lossy().into_owned()),
        })),
    };

    let res = with_read_only_dir(&ro, || resolve_backend(&cfg, &config_path, None, true))
        .expect("an unwritable explicit overlay path must degrade, not refuse");
    assert!(res.path.is_none());
    assert!(res.read_only_backend);
}

/// The line the degrade does NOT cross. `config.overlay: false` on a mutable config is a config the
/// operator TYPED, and it contradicts itself: "mutations are allowed, and there is nowhere to store
/// them". There is no environment to be lenient about, and the fix is a one-line config edit, so it
/// stays a boot refusal.
#[test]
fn e_mutable_with_the_overlay_explicitly_disabled_is_still_a_boot_refusal() {
    let dir = scratch("disabled");
    let config_path = dir.join("config.yaml");
    std::fs::write(&config_path, "models: {}\n").unwrap();

    let err = resolve_backend(
        &ConfigMgmtCfg {
            locked: false,
            overlay: Some(OverlayCfg::Disabled(false)),
        },
        &config_path,
        None,
        true,
    )
    .expect_err("a self-contradictory config must still refuse");
    assert!(
        err.contains("config.locked"),
        "the refusal must name the fix: {err}"
    );
}

/// `--validate` (probe_fs = false) must stay side-effect-free AND must not report the degraded
/// posture, because it may be running nowhere near the target filesystem. It reports the config's
/// DECLARED intent: a mutable config with a backend path.
#[test]
fn f_validate_does_not_probe_and_never_reports_a_degraded_backend() {
    let res = resolve_backend(
        &ConfigMgmtCfg::default(),
        std::path::Path::new("/nonexistent-by-design/etc/busbar/config.yaml"),
        None,
        false,
    )
    .expect("--validate resolves without touching the filesystem");
    assert!(
        res.path.is_some(),
        "--validate reports the declared backend, it does not probe for it"
    );
    assert!(!res.read_only_backend);
}
