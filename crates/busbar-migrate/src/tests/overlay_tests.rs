// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r42 §9 C1 reds (f2), (g), (g2), (g3), (h), (n4)(2)-(3), (o3)-(o7) and (r)(3):
//! 1b's selection and recovery, 1c's root, named-map and group fold, and the 5c guard.

use std::ffi::OsString;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use busbar_contract::yaml::{self, Value, ValueExt};

use super::{BEFORE_MOVE, CRASH_AT, DEFAULT_OVERLAY_FILENAME, ENV, FOLDING_SUFFIX, MARKER};
use crate::scratch::Scratch;
use crate::{backup_path, patch, plan, read_version, write, Inputs, Plan, Refusal, Written};

fn accept(_: &str, _: Option<&str>) -> Result<(), String> {
    Ok(())
}

fn planned(path: &Path) -> Result<Plan, Refusal> {
    plan(&Inputs::new(path, &crate::scratch::facts(), &accept))
}

fn planned_with(
    path: &Path,
    env: &dyn Fn(&str) -> Option<OsString>,
    ignore_overlay: bool,
) -> Result<Plan, Refusal> {
    plan(&Inputs {
        env,
        ignore_overlay,
        ..Inputs::new(path, &crate::scratch::facts(), &accept)
    })
}

fn tree(text: &str) -> Value {
    patch::document(text).expect("a YAML mapping")
}

fn assert_tree(written: &str, expected: &str) {
    assert!(
        yaml::same_tree(&tree(written), &tree(expected)),
        "written:\n{written}\nexpected:\n{expected}"
    );
}

fn is_poison(path: &Path) -> bool {
    path.is_dir() && path.join(MARKER).is_file()
}

/// `<o>.busbar-p.*` left beside `o`.
fn building_left(o: &Path) -> bool {
    let name = o.file_name().unwrap().to_string_lossy().into_owned();
    std::fs::read_dir(o.parent().unwrap())
        .unwrap()
        .flatten()
        .any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with(&format!("{name}.busbar-p."))
        })
}

fn folding(o: &Path) -> std::path::PathBuf {
    crate::files::sibling(o, FOLDING_SUFFIX)
}

fn overlay_backup(o: &Path) -> std::path::PathBuf {
    crate::files::sibling(o, crate::BACKUP_SUFFIX)
}

const BASE: &str = "\
# 1.5.5 gateway
listen: 0.0.0.0:8080
store:
  module: sqlite
  settings:
    path: /var/lib/busbar/busbar.db
hooks:
  H:
    module: audit-tap
    kind: tap
pools:
  hooks: [H]
";

/// A group G and a tombstone of the base hook H.
const OVERLAY_G: &str = r#"{"version":1,"groups":{"G":{"enabled":true}},"deleted":["H"]}"#;

const FOLDED_G: &str = "\
config_version: 1
listen: 0.0.0.0:8080
auth:
  chain: []
store:
  module: sqlite
  settings:
    path: /var/lib/busbar/busbar.db
hooks: {}
pools: {}
groups:
  G:
    enabled: true
";

// ---- (g3) the selector, exactly as v1.5.5's `resolve_backend` ------------------------------------

/// (g3) a mutable config whose `config.overlay` is `false`, `true` or `{file: null}` is refused
/// with 1.5.5's own text (1.5.5 refused to boot it); nothing is written.
#[test]
fn a_mutable_config_without_an_overlay_backend_is_refused_with_1_5_5s_text() {
    for (selector, text) in [
        ("false", "has no writable overlay backend"),
        ("true", "`true` names no backend"),
        ("{file: null}", "has no writable overlay backend"),
        ("{}", "has no writable overlay backend"),
    ] {
        let scratch = Scratch::new();
        let path = scratch.deployment(&format!("listen: x\nconfig:\n  overlay: {selector}\n"));
        let refused = planned(&path).unwrap_err();
        assert_eq!(refused.word(), "CONFIG", "{selector}: {refused}");
        assert!(refused.to_string().contains(text), "{selector}: {refused}");
        assert_eq!(
            scratch.names(),
            ["config.yaml", "providers.yaml"],
            "{selector}"
        );
    }
}

/// (g3) a locked config reads no overlay (whatever sits at the default path), and 5c guards
/// nothing.
#[test]
fn a_locked_config_reads_no_overlay() {
    let scratch = Scratch::new();
    let path = scratch.deployment("listen: x\nconfig:\n  locked: true\n  overlay: false\n");
    let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let plan = planned(&path).unwrap();
    assert!(plan.overlay().is_none());
    assert!(
        plan.report()
            .iter()
            .any(|line| line.contains("config.locked: true")),
        "{:?}",
        plan.report()
    );
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    assert_eq!(std::fs::read_to_string(&o).unwrap(), OVERLAY_G);
    assert!(!overlay_backup(&o).exists());
}

/// (g3) `BUSBAR_CONFIG_OVERLAY` is honoured only while `config.overlay` is unset: with
/// `config.overlay.file` set, the file is used and the variable ignored.
#[test]
fn config_overlay_file_wins_over_the_environment() {
    let scratch = Scratch::new();
    let path = scratch.deployment("listen: x\nconfig:\n  overlay:\n    file: state/o.json\n");
    let elsewhere = scratch.dir().join("elsewhere.json");
    let env = |name: &str| (name == ENV).then(|| elsewhere.clone().into_os_string());
    let plan = planned_with(&path, &env, false).unwrap();
    let selected = plan.overlay().unwrap();
    assert_eq!(selected.path, scratch.dir().join("state/o.json"));
    assert_eq!(selected.by, crate::SelectedBy::File);
    // The same config without the selector: the variable selects.
    let path = scratch.deployment("listen: x\n");
    let plan = planned_with(&path, &env, false).unwrap();
    assert_eq!(plan.overlay().unwrap().path, elsewhere);
    assert_eq!(plan.overlay().unwrap().by, crate::SelectedBy::Env);
}

/// 1.5.5 interpolated config.yaml before it chose the path: a `${VAR}` in `config:` is resolved
/// through the boot's interpolation.
#[test]
fn the_selector_is_read_as_1_5_5_resolved_it() {
    // 1t reads the whole document through the boot's environment too, so STATE is set there.
    fn boot_env(name: &str) -> Option<String> {
        (name == "STATE").then(|| "/state".to_owned())
    }
    let scratch = Scratch::new();
    let path = scratch.deployment("listen: x\nconfig:\n  overlay:\n    file: ${STATE}/o.json\n");
    let state = scratch.dir().join("state");
    let interpolate = |text: &str| -> Result<String, String> {
        Ok(text.replace("${STATE}", &state.display().to_string()))
    };
    let facts = crate::Facts {
        env: boot_env,
        ..crate::scratch::facts()
    };
    let plan = plan(&Inputs {
        interpolate: &interpolate,
        ..Inputs::new(&path, &facts, &accept)
    })
    .unwrap();
    assert_eq!(plan.overlay().unwrap().path, state.join("o.json"));
    let refuse = |_: &str| -> Result<String, String> { Err("STATE is not set".to_owned()) };
    let refused = plan_with_interpolation(&path, &refuse);
    assert_eq!(refused.word(), "CONFIG");
    assert!(
        refused.to_string().contains("STATE is not set"),
        "{refused}"
    );
}

fn plan_with_interpolation(
    path: &Path,
    interpolate: &dyn Fn(&str) -> Result<String, String>,
) -> Refusal {
    plan(&Inputs {
        interpolate,
        ..Inputs::new(path, &crate::scratch::facts(), &accept)
    })
    .unwrap_err()
}

// ---- (f2) an env-selected overlay, folded in place ------------------------------------------------

/// (f2) `BUSBAR_CONFIG_OVERLAY=<dir>/data/overlay.json` holding group G and a tombstone of base
/// hook H: the report names the path and how it was selected, G is folded, H is gone, the overlay
/// path is P and `<o>.1.5.5` is byte-identical. Without the variable the default path is reported
/// absent, at WARN.
#[test]
fn an_env_selected_overlay_is_folded_in_place() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.file("data/overlay.json", OVERLAY_G);
    let env = |name: &str| (name == ENV).then(|| o.clone().into_os_string());
    let plan = planned_with(&path, &env, false).unwrap();
    let line = format!(
        "overlay: `{}` (selected by BUSBAR_CONFIG_OVERLAY): folded",
        o.display()
    );
    assert!(plan.report().contains(&line), "{:?}", plan.report());
    assert!(
        !plan.warnings().contains(&line),
        "a folded overlay is not a warning"
    );
    assert_tree(plan.planned(), FOLDED_G);
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), plan.planned());
    assert!(is_poison(&o), "the overlay path is P");
    assert_eq!(
        std::fs::read_to_string(overlay_backup(&o)).unwrap(),
        OVERLAY_G
    );
    assert!(!folding(&o).exists());
    assert!(!building_left(&o));
    assert_eq!(std::fs::read_to_string(backup_path(&path)).unwrap(), BASE);

    // The same deployment booted without the variable.
    let other = Scratch::new();
    let path = other.deployment(BASE);
    other.file("data/overlay.json", OVERLAY_G);
    let plan = planned(&path).unwrap();
    let line = format!(
        "overlay: `{}` (selected by default): absent",
        other.dir().join(DEFAULT_OVERLAY_FILENAME).display()
    );
    assert!(plan.report().contains(&line), "{:?}", plan.report());
    assert!(plan.warnings().contains(&line), "{:?}", plan.warnings());
    assert_eq!(
        read_version(plan.planned()),
        Ok(1),
        "nothing is folded; the base is stamped"
    );
    assert!(yaml::same_tree(
        &tree(plan.planned()).get("hooks").cloned().unwrap(),
        &tree(BASE).get("hooks").cloned().unwrap()
    ));
}

/// (o5) a store-less 1.5.5 on another node keeps its own overlay: this node's report names only
/// this node's path, once.
#[test]
fn the_report_names_only_this_nodes_overlay() {
    let scratch = Scratch::new();
    let path = scratch.deployment("listen: x\n");
    scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let plan = planned(&path).unwrap();
    let lines: Vec<&String> = plan
        .report()
        .iter()
        .filter(|line| line.starts_with("overlay: "))
        .collect();
    assert_eq!(lines.len(), 1, "{:?}", plan.report());
    assert!(lines[0].contains(&scratch.dir().display().to_string()));
}

// ---- (g), (g2) root.store and writability -----------------------------------------------------

const OVERLAY_POSTGRES: &str = r#"{"version":1,
 "root":{"store":{"module":"postgres","settings":{"url":"postgres://db/busbar"}}},
 "hooks":{"api_gate":{"kind":"gate","module":"ratelimit"}},
 "groups":{"G":{}}}"#;

/// (g) the overlay's `root.store` is what 1.5.5 opened: it replaces the base sqlite store, and a
/// config with no `store:` block gets it too.
#[test]
fn the_overlays_root_store_replaces_the_base_store() {
    for base in [BASE, "listen: 0.0.0.0:8080\n"] {
        let scratch = Scratch::new();
        let path = scratch.deployment(base);
        scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_POSTGRES);
        let plan = planned(&path).unwrap();
        let store = tree(plan.planned()).get("store").cloned().unwrap();
        assert!(
            yaml::same_tree(
                &store,
                &tree("module: postgres\nsettings:\n  url: postgres://db/busbar\n")
            ),
            "{}",
            plan.planned()
        );
    }
}

/// (g2) an overlay 1.5.5 could not write was never read by 1.5.5: the base store is kept, the
/// hook and group are absent, one report line (also a WARN) names the file, and the file is
/// untouched with no `<o>.1.5.5`. Shapes: a directory at the path (as root too), a file under a
/// parent that is a file, and mode 0444 when this process is not root. `--ignore-overlay` then
/// has nothing pending. The same pair writable folds postgres, as (g).
#[test]
fn an_unwritable_overlay_is_not_folded_and_left_untouched() {
    let check = |scratch: &Scratch, path: &Path, o: &Path| {
        let plan = planned(path).unwrap();
        let line = format!(
            "overlay: `{}` (selected by {}): not writable, not folded",
            o.display(),
            plan.overlay().map(|s| s.by).map_or("?", |by| match by {
                crate::SelectedBy::File => "`config.overlay.file`",
                crate::SelectedBy::Env => ENV,
                crate::SelectedBy::Default => "default",
            })
        );
        assert!(plan.report().contains(&line), "{:?}", plan.report());
        assert!(plan.warnings().contains(&line));
        let planned = tree(plan.planned());
        assert_eq!(
            planned
                .get("store")
                .and_then(|s| s.get("module"))
                .and_then(ValueExt::as_str),
            Some("sqlite")
        );
        assert!(planned.get("groups").is_none());
        assert!(planned
            .get("hooks")
            .and_then(|h| h.get("api_gate"))
            .is_none());
        let ignoring = planned_with(path, &|_| None, true);
        assert!(ignoring.is_ok(), "nothing is pending: {ignoring:?}");
        assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
        assert!(!overlay_backup(o).exists());
        let _ = scratch;
    };

    // A directory at the default path, not ours.
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.dir().join(DEFAULT_OVERLAY_FILENAME);
    std::fs::create_dir(&o).unwrap();
    scratch.file("busbar-overlay.json/inside", OVERLAY_POSTGRES);
    check(&scratch, &path, &o);
    assert!(o.is_dir() && !o.join(MARKER).exists(), "left as it was");

    // A missing file whose parent is a file: 1.5.5's probe fails.
    let scratch = Scratch::new();
    scratch.file("blocker", "");
    let path = scratch.deployment(&format!(
        "{BASE}config:\n  overlay:\n    file: blocker/overlay.json\n"
    ));
    let o = scratch.dir().join("blocker/overlay.json");
    check(&scratch, &path, &o);

    // Mode 0444 (only a non-root process is stopped by mode bits).
    let scratch = Scratch::new();
    if scratch.as_root() {
        eprintln!("(g2) mode-0444 leg skipped: the test runs as root");
    } else {
        let path = scratch.deployment(BASE);
        let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_POSTGRES);
        std::fs::set_permissions(&o, std::fs::Permissions::from_mode(0o444)).unwrap();
        let mtime = std::fs::metadata(&o).unwrap().modified().unwrap();
        check(&scratch, &path, &o);
        assert_eq!(std::fs::read_to_string(&o).unwrap(), OVERLAY_POSTGRES);
        assert_eq!(std::fs::metadata(&o).unwrap().modified().unwrap(), mtime);
        std::fs::set_permissions(&o, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    // The same pair, writable: postgres is folded.
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_POSTGRES);
    let plan = planned(&path).unwrap();
    let planned = tree(plan.planned());
    assert_eq!(
        planned
            .get("store")
            .and_then(|s| s.get("module"))
            .and_then(ValueExt::as_str),
        Some("postgres")
    );
}

/// (h) `--ignore-overlay` with a pending overlay refuses CONFIG: the fold is never skipped.
#[test]
fn ignore_overlay_with_a_pending_overlay_is_refused() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let refused = planned_with(&path, &|_| None, true).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(
        refused.to_string().contains("--ignore-overlay"),
        "{refused}"
    );
    assert_eq!(
        scratch.names(),
        ["busbar-overlay.json", "config.yaml", "providers.yaml"]
    );
}

// ---- (n4)(2)-(3) what the fold refuses or drops -------------------------------------------------

/// (n4)(3) an overlay that is not JSON refuses CONFIG naming the file and the byte offset;
/// `version` above 1 refuses NEWER; a `${` in a folded string refuses CONFIG naming the entry.
/// Nothing is written.
#[test]
fn an_overlay_1_5_5_could_not_read_is_refused() {
    for (overlay, word, text) in [
        (r#"{"groups": {"G": }"#, "CONFIG", "at byte"),
        (r#"{"version": 2}"#, "NEWER", "version: 2"),
        (
            r#"{"groups": {"G": {"note": "${HOME}"}}}"#,
            "CONFIG",
            "groups.G.note",
        ),
        (
            r#"{"root": {"limits": {"max_inbound_concurent": 5}}}"#,
            "CONFIG",
            "max_inbound_concurent",
        ),
        (r#"{"root": {"metrics": {}}}"#, "CONFIG", "root.metrics"),
        (r#"[]"#, "CONFIG", "not a JSON object"),
    ] {
        let scratch = Scratch::new();
        let path = scratch.deployment(BASE);
        let o = scratch.file(DEFAULT_OVERLAY_FILENAME, overlay);
        let refused = planned(&path).unwrap_err();
        assert_eq!(refused.word(), word, "{overlay}: {refused}");
        let shown = refused.to_string();
        assert!(shown.contains(text), "{overlay}: {shown}");
        if word == "CONFIG" && text == "at byte" {
            assert!(shown.contains(&o.display().to_string()), "{shown}");
        }
        assert_eq!(
            scratch.names(),
            ["busbar-overlay.json", "config.yaml", "providers.yaml"]
        );
    }
}

/// (n4)(2) a top-level key 1.5.5's `OverlayDoc` did not have is never emitted: 1.5.5 ignored it
/// (no `deny_unknown_fields`), so it is dropped with one report line naming it (§A3 1c).
#[test]
fn an_unknown_top_level_key_is_dropped_and_reported() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    scratch.file(
        DEFAULT_OVERLAY_FILENAME,
        r#"{"document_patch":{"listen":"elsewhere"},"groups":{"G":{"enabled":true}},"deleted":["H"]}"#,
    );
    let plan = planned(&path).unwrap();
    assert!(
        plan.report()
            .iter()
            .any(|line| line.contains("`document_patch` is dropped")),
        "{:?}",
        plan.report()
    );
    assert_tree(plan.planned(), FOLDED_G);
}

// ---- (r)(3), 5L: the preconditions and the sweep --------------------------------------------------

/// (r)(3) `<o>.1.5.5` present with other bytes refuses CONFIG naming it at 5R, nothing written.
#[test]
fn an_overlay_backup_with_other_bytes_refuses_the_write() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let plan = planned(&path).unwrap();
    std::fs::write(overlay_backup(&o), "{}").unwrap();
    let refused = write(&plan, &accept).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(
        refused.to_string().contains("busbar-overlay.json.1.5.5"),
        "{refused}"
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), BASE);
    assert_eq!(std::fs::read_to_string(&o).unwrap(), OVERLAY_G);
}

#[test]
fn a_conflicting_overlay_backup_refuses_before_store_migration() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    std::fs::write(overlay_backup(&o), "{}").unwrap();
    let refused = planned(&path).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("busbar-overlay.json.1.5.5"));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), BASE);
    assert_eq!(std::fs::read_to_string(&o).unwrap(), OVERLAY_G);
    assert_eq!(std::fs::read_to_string(overlay_backup(&o)).unwrap(), "{}");
}

/// 5L: a dead holder's T is removed under the lock, and the upgrade completes.
#[test]
fn a_dead_holders_building_directory_is_swept() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let dead = scratch.dir().join("busbar-overlay.json.busbar-p.4194304.0");
    std::fs::create_dir(&dead).unwrap();
    std::fs::write(dead.join(MARKER), "x").unwrap();
    let plan = planned(&path).unwrap();
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    assert!(!dead.exists());
    assert!(is_poison(&o));
}

// ---- (o3), (o4) a running 1.5.5 against the guard -------------------------------------------------

/// v1.5.5's overlay write: temp file, then `rename` over the path (a new inode every write).
fn write_as_1_5_5(o: &Path, text: &str) -> std::io::Result<()> {
    let temp = o.with_file_name(format!(
        ".{}.{}-0.tmp",
        o.file_name().unwrap().to_string_lossy(),
        std::process::id()
    ));
    std::fs::write(&temp, text)?;
    let renamed = std::fs::rename(&temp, o);
    if renamed.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    renamed
}

/// (o3) a 1.5.5 writes `<o>` between 5R and 5c's move: LIVE_WRITER (the moved file is not the one
/// read), `<o>` keeps the writer's bytes, config.yaml is not stamped; the next boot plans another
/// digest and folds what the writer wrote.
#[test]
fn an_overlay_write_during_the_guard_is_a_live_writer_and_nothing_is_lost() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let first = planned(&path).unwrap();
    const LATER: &str = r#"{"version":1,"groups":{"G":{"enabled":true},"K":{}},"deleted":["H"]}"#;
    let writer = o.clone();
    BEFORE_MOVE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || write_as_1_5_5(&writer, LATER).unwrap()));
    });
    let refused = write(&first, &accept);
    BEFORE_MOVE.with(|hook| *hook.borrow_mut() = None);
    let refused = refused.unwrap_err();
    assert_eq!(refused.word(), "LIVE_WRITER", "{refused}");
    assert_eq!(std::fs::read_to_string(&o).unwrap(), LATER);
    assert!(!folding(&o).exists());
    assert_eq!(
        read_version(&std::fs::read_to_string(&path).unwrap()),
        Ok(0)
    );
    let next = planned(&path).unwrap();
    assert_ne!(next.digest(), first.digest());
    assert!(tree(next.planned())
        .get("groups")
        .and_then(|groups| groups.get("K"))
        .is_some());
    assert_eq!(write(&next, &accept), Ok(Written::Stamped));
    assert_eq!(std::fs::read_to_string(overlay_backup(&o)).unwrap(), LATER);
}

/// (o4) after the upgrade, P refuses every 1.5.5 overlay write: its rename over a directory fails,
/// and its read-modify-write read is not "absent" (so 1.5.5 refuses the mutation).
#[test]
fn the_poison_refuses_later_1_5_5_overlay_writes() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let plan = planned(&path).unwrap();
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    assert!(write_as_1_5_5(&o, "{}").is_err());
    let read = std::fs::read(&o).unwrap_err();
    assert_ne!(read.kind(), std::io::ErrorKind::NotFound);
    assert!(is_poison(&o));
}

// ---- (o6), (o7) every crash point reads back; the rollback restores 1.5.5's file ---------------

/// The uninterrupted upgrade of `BASE` with `OVERLAY_G`: the stamped config.yaml.
fn uninterrupted() -> String {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
    let plan = planned(&path).unwrap();
    assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
    std::fs::read_to_string(&path).unwrap()
}

/// Run the upgrade killed at 5c point `at` (the guard stops there, nothing cleaned up).
fn killed_at(path: &Path, at: u8) {
    let plan = planned(path).unwrap();
    CRASH_AT.with(|point| point.set(at));
    let outcome = write(&plan, &accept);
    CRASH_AT.with(|point| point.set(0));
    let refused = outcome.unwrap_err();
    assert!(refused.to_string().contains("test kill"), "{refused}");
}

/// The overlay rollback of docs/migration-1.6.md, step by step: remove P; move
/// `<o>.busbar-folding` back if it exists (and drop `<o>.1.5.5`), else move `<o>.1.5.5` back;
/// any `<o>.busbar-p.*` may go.
fn roll_back(o: &Path) {
    if is_poison(o) {
        std::fs::remove_dir_all(o).unwrap();
    }
    if folding(o).exists() {
        std::fs::rename(folding(o), o).unwrap();
        let _ = std::fs::remove_file(overlay_backup(o));
    } else if overlay_backup(o).exists() {
        std::fs::rename(overlay_backup(o), o).unwrap();
    }
    let name = o.file_name().unwrap().to_string_lossy().into_owned();
    for entry in std::fs::read_dir(o.parent().unwrap()).unwrap().flatten() {
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(&format!("{name}.busbar-p."))
        {
            std::fs::remove_dir_all(entry.path()).unwrap();
        }
    }
}

/// (o6) a kill at each 5c point (T built, `<o>` moved to F, P renamed in, F linked as B, F
/// removed): the next boot's 1b reads either the overlay (at `<o>`, F or B) or P, folds it once,
/// and the result equals the uninterrupted run, with P in place, B byte-identical and no F or T.
#[test]
fn every_guard_crash_point_reads_back_to_the_same_upgrade() {
    let expected = uninterrupted();
    for at in 1..=5 {
        let scratch = Scratch::new();
        let path = scratch.deployment(BASE);
        let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
        killed_at(&path, at);
        assert_eq!(
            read_version(&std::fs::read_to_string(&path).unwrap()),
            Ok(0)
        );
        let plan = planned(&path).unwrap();
        assert!(
            plan.report().iter().any(|line| line.ends_with(": folded")),
            "point {at}: {:?}",
            plan.report()
        );
        assert_eq!(write(&plan, &accept), Ok(Written::Stamped), "point {at}");
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            expected,
            "point {at}"
        );
        assert!(is_poison(&o), "point {at}");
        assert_eq!(
            std::fs::read_to_string(overlay_backup(&o)).unwrap(),
            OVERLAY_G,
            "point {at}"
        );
        assert!(!folding(&o).exists(), "point {at}");
        assert!(!building_left(&o), "point {at}");
    }
}

/// (o6) the absent selection (the default install: no overlay file, a writable default path):
/// a kill after P is in place leaves P with no F or B, "nothing to fold", and the upgrade
/// completes; no B is ever made.
#[test]
fn an_absent_overlay_guarded_then_killed_is_nothing_to_fold() {
    for at in [1, 3] {
        let scratch = Scratch::new();
        let path = scratch.deployment(BASE);
        let o = scratch.dir().join(DEFAULT_OVERLAY_FILENAME);
        killed_at(&path, at);
        let plan = planned(&path).unwrap();
        let expected = if at == 3 {
            "absent (an earlier upgrade boot folded it: nothing to fold)"
        } else {
            "absent"
        };
        assert!(
            plan.report().iter().any(|line| line.ends_with(expected)),
            "point {at}: {:?}",
            plan.report()
        );
        assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
        assert!(is_poison(&o));
        assert!(!overlay_backup(&o).exists());
        assert!(!building_left(&o));
    }
}

/// (o6) a regular file at `<o>` beside `<o>.busbar-folding`: a 1.5.5 wrote it during an upgrade;
/// LIVE_WRITER, both kept.
#[test]
fn a_file_beside_the_folding_copy_is_a_live_writer() {
    let scratch = Scratch::new();
    let path = scratch.deployment(BASE);
    let o = scratch.file(DEFAULT_OVERLAY_FILENAME, "{}");
    std::fs::write(folding(&o), OVERLAY_G).unwrap();
    let refused = planned(&path).unwrap_err();
    assert_eq!(refused.word(), "LIVE_WRITER");
    assert!(refused.to_string().contains(".busbar-folding"), "{refused}");
    assert_eq!(std::fs::read_to_string(&o).unwrap(), "{}");
    assert_eq!(std::fs::read_to_string(folding(&o)).unwrap(), OVERLAY_G);
}

/// (o7) the guide's overlay rollback, after a full upgrade and after each kill point, puts the
/// pre-upgrade overlay back at `<o>` byte for byte (the file a pinned 1.5.5 then reads, with G);
/// config.yaml.1.5.5 restores config.yaml. Red first: r26's text moved only `<o>.1.5.5` back,
/// which after a kill between the move to F and the link leaves `<o>` without the overlay.
#[test]
fn the_overlay_rollback_restores_1_5_5s_file_from_every_state() {
    for at in 0..=5 {
        let scratch = Scratch::new();
        let path = scratch.deployment(BASE);
        let o = scratch.file(DEFAULT_OVERLAY_FILENAME, OVERLAY_G);
        if at == 0 {
            let plan = planned(&path).unwrap();
            assert_eq!(write(&plan, &accept), Ok(Written::Stamped));
        } else {
            killed_at(&path, at);
        }
        roll_back(&o);
        assert_eq!(
            std::fs::read_to_string(&o).unwrap(),
            OVERLAY_G,
            "state {at}"
        );
        if backup_path(&path).exists() {
            std::fs::rename(backup_path(&path), &path).unwrap();
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), BASE, "state {at}");
    }
}
