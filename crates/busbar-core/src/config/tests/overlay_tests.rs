// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/config/overlay.rs`.

use super::*;

fn gate() -> HookCfg {
    serde_json::from_value(serde_json::json!({
        "kind": "gate", "module": "test-hook", "prompt": "rw", "global": true
    }))
    .unwrap()
}

/// write → read round-trips the overlay through the filesystem (atomic write, fail-soft read).
#[test]
fn write_read_round_trip() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-overlay-test-{}.json", std::process::id()));
    let doc = from_state(
        &HashMap::from([("compress".to_string(), gate())]),
        &["compress".to_string()],
    );
    write(&path, &doc).expect("atomic write");
    let read_back = read(&path).expect("read back");
    assert!(read_back.hooks.contains_key("compress"));
    assert_eq!(read_back.global_hooks, vec!["compress".to_string()]);
    // No durable temp for THIS target (`.<file-name>.<pid>-<seq>.tmp`, the primitive's unique
    // naming) must linger after a successful write — the rename consumed it, and the RAII guard
    // leaves nothing to accumulate. (Scan by our unique file-name prefix; the temp_dir is shared.)
    let file_name = path.file_name().unwrap().to_string_lossy().into_owned();
    let no_durable_temp = || {
        let prefix = format!(".{file_name}.");
        !std::fs::read_dir(&dir).unwrap().any(|e| {
            let n = e.unwrap().file_name();
            let n = n.to_string_lossy();
            n.starts_with(&prefix) && n.ends_with(".tmp")
        })
    };
    assert!(no_durable_temp(), "no durable temp should remain");
    // A pre-existing stale temp from a prior crashed run (a foreign name under the primitive's
    // per-call-unique naming) must NOT wedge the next write — it is simply ignored.
    std::fs::write(path.with_extension("overlay.tmp"), b"stale").unwrap();
    write(&path, &doc).expect("write despite a pre-existing stale temp");
    assert!(no_durable_temp(), "no durable temp should remain");
    let _ = std::fs::remove_file(path.with_extension("overlay.tmp"));
    let _ = std::fs::remove_file(&path);
}

/// The overlay can carry operator-supplied credential material verbatim (e.g. a postgres
/// `store.settings.url` of `postgres://user:pass@host:5432/busbar`), so `write` must publish it
/// 0600 (owner read/write only) rather than at OS/umask-default permissions (typically 0644,
/// world-readable) — the same posture the signing key gets, and for the same reason.
#[test]
#[cfg(unix)]
fn write_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "busbar-overlay-perm-test-{}.json",
        std::process::id()
    ));
    let doc = from_state(
        &HashMap::from([("compress".to_string(), gate())]),
        &["compress".to_string()],
    );
    write(&path, &doc).expect("atomic write");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o600,
        "overlay file must be 0600 (credential-bearing), got {mode:#o}"
    );
    let _ = std::fs::remove_file(&path);
}

/// A missing or corrupt overlay is fail-soft (None), never a panic.
#[test]
fn read_absent_or_corrupt_is_none() {
    assert!(read(Path::new("/nonexistent/busbar-overlay-xyz.json")).is_none());
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "busbar-overlay-corrupt-{}.json",
        std::process::id()
    ));
    std::fs::write(&path, b"{ this is not json").unwrap();
    assert!(
        read(&path).is_none(),
        "a corrupt overlay must not brick boot"
    );
    let _ = std::fs::remove_file(&path);
}

/// A minimal RESOLVED config to merge overlays into (providers/models empty; registry empty).
fn minimal_cfg() -> RootCfg {
    let deploy: super::super::DeployCfg =
        serde_json::from_value(serde_json::json!({"providers": {}, "models": {}})).unwrap();
    super::super::resolve(&deploy, &HashMap::new()).expect("minimal config resolves")
}

/// merge_into adds overlay hooks to the resolved registry + unions global names; an overlay
/// hook with a base hook's name wins.
#[test]
fn merge_into_deploy() {
    let mut cfg = minimal_cfg();
    cfg.hooks.insert("base_hook".to_string(), gate());
    let doc = from_state(
        &HashMap::from([
            ("base_hook".to_string(), gate()), // same name as a base hook → overlay wins
            ("api_hook".to_string(), gate()),
        ]),
        &["api_hook".to_string(), "base_hook".to_string()],
    );
    cfg.global_hooks.push("base_hook".to_string());
    merge_into(&mut cfg, doc);
    assert!(cfg.hooks.contains_key("api_hook"));
    assert!(cfg.hooks.contains_key("base_hook"));
    // global_hooks unioned, no duplicate of base_hook.
    assert_eq!(
        cfg.global_hooks
            .iter()
            .filter(|g| *g == "base_hook")
            .count(),
        1,
        "global union does not duplicate"
    );
    assert!(cfg.global_hooks.iter().any(|g| g == "api_hook"));
}

/// TOMBSTONE: a hook the API deleted (recorded in `deleted`) is removed from the effective config at
/// boot even if it was defined in base config.yaml — so an API deletion survives a restart.
#[test]
fn merge_into_applies_tombstones() {
    let mut cfg = minimal_cfg();
    cfg.hooks.insert("base_hook".to_string(), gate());
    cfg.global_hooks.push("base_hook".to_string());
    let doc = OverlayDoc {
        hooks: HashMap::new(),
        global_hooks: Vec::new(),
        deleted: vec!["base_hook".to_string()],
        ..Default::default()
    };
    merge_into(&mut cfg, doc);
    assert!(
        !cfg.hooks.contains_key("base_hook"),
        "a tombstoned base hook is removed from the effective config"
    );
    assert!(!cfg.global_hooks.iter().any(|g| g == "base_hook"));
}

/// REGRESSION: `persist` must NOT overwrite a present-but-unreadable/corrupt overlay — that would
/// drop accumulated deletion tombstones and silently resurrect a deleted hook on restart.
#[test]
fn persist_refuses_to_overwrite_unreadable_overlay() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "busbar-overlay-corrupt-persist-{}.json",
        std::process::id()
    ));
    let corrupt = b"{ this is not valid json and may hide tombstones";
    std::fs::write(&path, corrupt).unwrap();
    let err = persist(
        Some(&path),
        &HashMap::from([("newhook".to_string(), gate())]),
        &["newhook".to_string()],
        Some("deleteme"),
        None,
        &std::collections::HashSet::new(),
    );
    assert!(
        err.is_err(),
        "persisting onto a corrupt overlay must FAIL CLOSED (refuse), not silently proceed"
    );
    let raw = std::fs::read(&path).expect("file still present");
    assert_eq!(
        raw, corrupt,
        "persist must preserve an unreadable overlay verbatim"
    );
    let _ = std::fs::remove_file(&path);
}

/// A WHOLESALE registry write (config rollback passes both tombstone
/// args `None`) must reconcile away any tombstone for a name that the restored registry
/// contains — otherwise the boot-merge inserts the hook then subtracts it, and the rollback
/// silently vanishes on the next restart. `persist` retains only tombstones whose name is
/// ABSENT from the persisted registry.
#[test]
fn persist_reconciles_tombstone_against_present_hook() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-overlay-recon-{}.json", std::process::id()));
    // Seed a prior overlay that tombstoned "x" (an earlier API delete).
    write(
        &path,
        &OverlayDoc {
            hooks: HashMap::new(),
            global_hooks: Vec::new(),
            deleted: vec!["x".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    // Rollback restores a registry that CONTAINS "x", persisting with both tombstone args None.
    persist(
        Some(&path),
        &HashMap::from([("x".to_string(), gate())]),
        &["x".to_string()],
        None,
        None,
        &std::collections::HashSet::new(),
    )
    .expect("persist");
    let doc = read(&path).expect("read back");
    assert!(
        !doc.deleted.iter().any(|n| n == "x"),
        "a restored hook must not remain tombstoned, or it vanishes on restart"
    );
    // And it survives the boot merge (inserted, not subtracted).
    let mut cfg = minimal_cfg();
    merge_into(&mut cfg, doc);
    assert!(
        cfg.hooks.contains_key("x"),
        "rollback is durable across restart"
    );
    let _ = std::fs::remove_file(&path);
}

/// REGRESSION: a tombstone for a name that is ABSENT from base `config.yaml` (never defined there,
/// or since removed from it) can never be reconciled by the "name comes back" rule — nothing will
/// ever re-add it as a HOOK, since the boot-merge only inserts base-config names. Such a tombstone
/// is permanently inert dead weight and must be pruned at persist time. A tombstone whose name IS
/// still in base config is kept (it is still actively shadowing that base entry).
#[test]
fn persist_prunes_tombstone_for_a_name_absent_from_base_config() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-ovl-prune-hook-{}.json", std::process::id()));
    write(
        &path,
        &OverlayDoc {
            hooks: HashMap::new(),
            global_hooks: Vec::new(),
            deleted: vec!["ghost".to_string(), "shadowed_base".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    let base_hook_names: std::collections::HashSet<String> =
        ["shadowed_base".to_string()].into_iter().collect();
    persist(
        Some(&path),
        &HashMap::from([("newhook".to_string(), gate())]),
        &["newhook".to_string()],
        None,
        None,
        &base_hook_names,
    )
    .expect("persist");
    let doc = read(&path).expect("read back");
    assert!(
        !doc.deleted.iter().any(|n| n == "ghost"),
        "a tombstone for a name absent from base config.yaml is permanently inert and must be \
             pruned: {:?}",
        doc.deleted
    );
    assert!(
        doc.deleted.iter().any(|n| n == "shadowed_base"),
        "a tombstone for a name STILL in base config must be kept (it still shadows it): {:?}",
        doc.deleted
    );
    let _ = std::fs::remove_file(&path);
}

fn group_with_budget() -> GroupCfg {
    serde_json::from_value(serde_json::json!({
        "limits": [ { "budget": 1000, "per": "month" } ]
    }))
    .unwrap()
}

/// merge_into inserts overlay groups (an overlay group with a base group's name wins) and applies
/// group tombstones LAST — an API-deleted group stays gone even if base config.yaml defined it.
#[test]
fn merge_into_groups_and_group_tombstones() {
    let mut cfg = minimal_cfg();
    cfg.groups.insert("team".to_string(), group_with_budget());
    cfg.groups.insert("doomed".to_string(), group_with_budget());
    let doc = OverlayDoc {
        groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
        deleted_groups: vec!["doomed".to_string()],
        ..Default::default()
    };
    merge_into(&mut cfg, doc);
    assert!(cfg.groups.contains_key("user:alice"), "overlay group added");
    assert!(cfg.groups.contains_key("team"), "base group untouched");
    assert!(
        !cfg.groups.contains_key("doomed"),
        "tombstoned group removed even though base defined it"
    );
}

/// REGRESSION: a HOOK write must PRESERVE the groups section + its tombstones — the read-modify-write
/// loads the whole doc and mutates only the hook section. Guards against "persist rebuilds the doc
/// inline and silently drops groups".
#[test]
fn persist_hook_preserves_groups_section() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-ovl-preserve-{}.json", std::process::id()));
    write(
        &path,
        &OverlayDoc {
            groups: BTreeMap::from([("user:bob".to_string(), group_with_budget())]),
            deleted_groups: vec!["oldteam".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    persist(
        Some(&path),
        &HashMap::from([("h".to_string(), gate())]),
        &["h".to_string()],
        None,
        None,
        &std::collections::HashSet::new(),
    )
    .expect("persist");
    let doc = read(&path).expect("read back");
    assert!(doc.hooks.contains_key("h"), "hook written");
    assert!(
        doc.groups.contains_key("user:bob"),
        "groups section preserved across a hook write"
    );
    assert!(
        doc.deleted_groups.iter().any(|n| n == "oldteam"),
        "group tombstones preserved across a hook write"
    );
    assert_eq!(
        doc.version, OVERLAY_VERSION,
        "schema version stamped on write"
    );
    let _ = std::fs::remove_file(&path);
}

/// Symmetric: a GROUP write preserves the hooks section, and reconciles away a group tombstone for a
/// name the written registry contains (wholesale-rollback safety, mirroring the hook path's c1r5 fix).
#[test]
fn persist_groups_preserves_hooks_and_reconciles_tombstone() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-ovl-gpreserve-{}.json", std::process::id()));
    write(
        &path,
        &OverlayDoc {
            hooks: HashMap::from([("keepme".to_string(), gate())]),
            deleted_groups: vec!["x".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    // Persist a group registry that CONTAINS "x" (a rollback), both tombstone args None.
    persist_groups(
        Some(&path),
        &BTreeMap::from([("x".to_string(), group_with_budget())]),
        None,
        None,
        &std::collections::HashSet::new(),
    )
    .expect("persist groups");
    let doc = read(&path).expect("read back");
    assert!(
        doc.hooks.contains_key("keepme"),
        "hooks section preserved across a group write"
    );
    assert!(doc.groups.contains_key("x"), "group written");
    assert!(
        !doc.deleted_groups.iter().any(|n| n == "x"),
        "tombstone reconciled away for a restored group, else it vanishes on restart"
    );
    let _ = std::fs::remove_file(&path);
}

/// REGRESSION (groups half of the hook test above): a group tombstone for a name absent from base
/// `config.yaml` can never come back via the "name comes back" reconciliation (nothing re-adds a
/// non-base name at boot), so it is permanently inert and must be pruned at persist time. A
/// tombstone for a name still in base config is kept.
#[test]
fn persist_groups_prunes_tombstone_for_a_name_absent_from_base_config() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "busbar-ovl-prune-group-{}.json",
        std::process::id()
    ));
    write(
        &path,
        &OverlayDoc {
            deleted_groups: vec!["ghost_group".to_string(), "shadowed_base_group".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    let base_group_names: std::collections::HashSet<String> =
        ["shadowed_base_group".to_string()].into_iter().collect();
    persist_groups(
        Some(&path),
        &BTreeMap::from([("newgroup".to_string(), group_with_budget())]),
        None,
        None,
        &base_group_names,
    )
    .expect("persist groups");
    let doc = read(&path).expect("read back");
    assert!(
        !doc.deleted_groups.iter().any(|n| n == "ghost_group"),
        "a group tombstone for a name absent from base config.yaml is permanently inert and \
             must be pruned: {:?}",
        doc.deleted_groups
    );
    assert!(
        doc.deleted_groups
            .iter()
            .any(|n| n == "shadowed_base_group"),
        "a group tombstone for a name STILL in base config must be kept: {:?}",
        doc.deleted_groups
    );
    let _ = std::fs::remove_file(&path);
}

/// `OverlaySection::parse` is the ONE valid-name gate: `groups`/`hooks` round-trip, everything
/// else is `None` (the reset endpoint 400s on it).
#[test]
fn overlay_section_parse_round_trips_and_rejects() {
    assert_eq!(
        OverlaySection::parse("groups"),
        Some(OverlaySection::Groups)
    );
    assert_eq!(OverlaySection::parse("hooks"), Some(OverlaySection::Hooks));
    assert_eq!(OverlaySection::parse("root"), Some(OverlaySection::Root));
    assert_eq!(OverlaySection::Groups.as_str(), "groups");
    assert_eq!(OverlaySection::Hooks.as_str(), "hooks");
    assert_eq!(OverlaySection::Root.as_str(), "root");
    for bad in ["", "Groups", "hook", "auth", "plugins", "groups/", "Root"] {
        assert!(
            OverlaySection::parse(bad).is_none(),
            "`{bad}` is not a section"
        );
    }
}

/// `clear_section(Groups)` wipes the groups entries + tombstones and leaves the hooks section
/// (and its tombstones) untouched — the per-section reset invariant.
#[test]
fn clear_section_wipes_one_section_only() {
    let mut doc = OverlayDoc {
        hooks: HashMap::from([("h".to_string(), gate())]),
        global_hooks: vec!["h".to_string()],
        deleted: vec!["gonehook".to_string()],
        groups: BTreeMap::from([("user:alice".to_string(), group_with_budget())]),
        deleted_groups: vec!["gonegroup".to_string()],
        ..Default::default()
    };
    doc.clear_section(OverlaySection::Groups);
    assert!(doc.groups.is_empty(), "groups entries cleared");
    assert!(doc.deleted_groups.is_empty(), "group tombstones cleared");
    assert!(doc.hooks.contains_key("h"), "hooks section preserved");
    assert_eq!(
        doc.global_hooks,
        vec!["h".to_string()],
        "global wiring preserved"
    );
    assert_eq!(
        doc.deleted,
        vec!["gonehook".to_string()],
        "hook tombstones preserved"
    );
    // And the symmetric case.
    doc.clear_section(OverlaySection::Hooks);
    assert!(doc.hooks.is_empty() && doc.global_hooks.is_empty() && doc.deleted.is_empty());
}

/// `section_is_empty` is true only when a section carries neither entries nor tombstones — the
/// idempotent-no-op predicate the reset handler short-circuits on.
#[test]
fn section_is_empty_tracks_entries_and_tombstones() {
    let empty = OverlayDoc::default();
    assert!(empty.section_is_empty(OverlaySection::Groups));
    assert!(empty.section_is_empty(OverlaySection::Hooks));
    // A lone tombstone (no live entry) still counts as non-empty (a base deletion to revert).
    let tombstoned = OverlayDoc {
        deleted_groups: vec!["x".to_string()],
        deleted: vec!["y".to_string()],
        ..Default::default()
    };
    assert!(!tombstoned.section_is_empty(OverlaySection::Groups));
    assert!(!tombstoned.section_is_empty(OverlaySection::Hooks));
}

/// The DURABLE half of a reset: `clear_section` on disk wipes one section + preserves the other,
/// exactly like the read-modify-write persist paths. Guards "reset drops the sibling section".
#[test]
fn clear_section_persist_preserves_sibling() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-ovl-clearsect-{}.json", std::process::id()));
    write(
        &path,
        &OverlayDoc {
            hooks: HashMap::from([("keepme".to_string(), gate())]),
            deleted: vec!["keephook_tomb".to_string()],
            groups: BTreeMap::from([("user:zap".to_string(), group_with_budget())]),
            deleted_groups: vec!["zap_tomb".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    clear_section(Some(&path), OverlaySection::Groups).expect("clear groups section");
    let doc = read(&path).expect("read back");
    assert!(
        doc.groups.is_empty() && doc.deleted_groups.is_empty(),
        "groups reset on disk"
    );
    assert!(
        doc.hooks.contains_key("keepme"),
        "hooks entries survive the groups reset"
    );
    assert_eq!(
        doc.deleted,
        vec!["keephook_tomb".to_string()],
        "hook tombstones survive"
    );
    assert_eq!(doc.version, OVERLAY_VERSION, "schema version stamped");
    let _ = std::fs::remove_file(&path);
}

/// A section reset must REFUSE to overwrite a present-but-corrupt overlay (clearing it would drop
/// the sibling section's tombstones), mirroring the persist paths' fail-closed posture.
#[test]
fn clear_section_refuses_to_overwrite_corrupt_overlay() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "busbar-ovl-clearcorrupt-{}.json",
        std::process::id()
    ));
    let corrupt = b"{ not valid json hiding tombstones";
    std::fs::write(&path, corrupt).unwrap();
    assert!(
        clear_section(Some(&path), OverlaySection::Groups).is_err(),
        "clearing a section on a corrupt overlay must FAIL CLOSED (refuse), not clobber it"
    );
    let raw = std::fs::read(&path).expect("still present");
    assert_eq!(
        raw, corrupt,
        "a corrupt overlay is preserved verbatim, never clobbered"
    );
    let _ = std::fs::remove_file(&path);
}

// ── ROOT section (1.5.0 full-config coverage) ─────────────────────────────────────────────

/// A minimal base `DeployCfg` (all uncovered sections at their defaults) to apply root overrides
/// onto. Uses the real YAML parse path so the defaults match production exactly.
fn minimal_deploy() -> DeployCfg {
    serde_yaml::from_str("providers: {}\nmodels: {}\n").expect("minimal deploy parses")
}

/// A `RootSettings` naming a couple of overrides, parsed from JSON exactly as the API body would.
fn sample_root() -> RootSettings {
    serde_json::from_value(serde_json::json!({
        "listen": "0.0.0.0:9000",
        "per_request_fee": 7,
        "rate_card": { "m0": { "input_utok": 1.5, "output_utok": 2.0 } },
        "limits": { "max_inbound_concurrent": 512 }
    }))
    .expect("root settings parse")
}

/// `apply_to_deploy` overwrites ONLY the named fields; unset fields keep base values.
#[test]
fn root_apply_overwrites_only_named_fields() {
    let mut deploy = minimal_deploy();
    let base_admin_listen = deploy.admin_listen.clone();
    // NON-DEFAULT base values, or this test cannot see the defect it guards: with an
    // all-defaults base a whole-section clobber is indistinguishable from a per-field merge,
    // which is why it passed for as long as the bug existed.
    deploy.limits.upstream_request_timeout_secs = 30;
    deploy.limits.request_body_max_bytes = 1_048_576;
    sample_root().apply_to_deploy(&mut deploy);
    assert_eq!(
        deploy.limits.upstream_request_timeout_secs, 30,
        "a limits field the overlay never names keeps the operator's value"
    );
    assert_eq!(
        deploy.limits.request_body_max_bytes, 1_048_576,
        "including a deliberately tightened body cap"
    );
    assert_eq!(deploy.listen, "0.0.0.0:9000", "listen overridden");
    assert_eq!(deploy.per_request_fee, 7, "fee overridden");
    assert_eq!(
        deploy.limits.max_inbound_concurrent, 512,
        "a limits field overridden"
    );
    assert!(
        deploy
            .rate_card
            .as_ref()
            .is_some_and(|rc| rc.contains_key("m0")),
        "rate_card overridden"
    );
    assert_eq!(
        deploy.admin_listen, base_admin_listen,
        "an unset field keeps its base value"
    );
}

/// `is_empty` / `section_is_empty(Root)` track whether any override is set.
#[test]
fn root_is_empty_tracks_overrides() {
    assert!(RootSettings::default().is_empty());
    assert!(OverlayDoc::default().section_is_empty(OverlaySection::Root));
    let doc = OverlayDoc {
        root: Some(sample_root()),
        ..Default::default()
    };
    assert!(!doc.section_is_empty(OverlaySection::Root));
    // A root override does not make hooks/groups non-empty (independent sections).
    assert!(doc.section_is_empty(OverlaySection::Hooks));
    assert!(doc.section_is_empty(OverlaySection::Groups));
}

/// `persist_root` round-trips the root section AND preserves the hooks + groups sections; storing
/// an empty `RootSettings` clears the section back to `None`.
#[test]
fn persist_root_round_trips_and_preserves_siblings() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-ovl-root-{}.json", std::process::id()));
    write(
        &path,
        &OverlayDoc {
            hooks: HashMap::from([("keepme".to_string(), gate())]),
            groups: BTreeMap::from([("user:z".to_string(), group_with_budget())]),
            deleted_groups: vec!["oldteam".to_string()],
            ..Default::default()
        },
    )
    .unwrap();
    persist_root(Some(&path), &sample_root()).expect("persist root");
    let doc = read(&path).expect("read back");
    assert!(
        doc.root
            .as_ref()
            .is_some_and(|r| r.per_request_fee == Some(7)),
        "root section written"
    );
    assert!(doc.hooks.contains_key("keepme"), "hooks preserved");
    assert!(doc.groups.contains_key("user:z"), "groups preserved");
    assert_eq!(
        doc.deleted_groups,
        vec!["oldteam".to_string()],
        "group tombstones preserved"
    );
    // Storing an empty root clears the section.
    persist_root(Some(&path), &RootSettings::default()).expect("persist empty root");
    let doc = read(&path).expect("read back after clear");
    assert!(doc.root.is_none(), "empty root clears the section");
    assert!(doc.hooks.contains_key("keepme"), "hooks still preserved");
    let _ = std::fs::remove_file(&path);
}

/// `clear_section(Root)` wipes only the root override; the hooks/groups sections survive. And the
/// on-disk `clear_section` refuses a corrupt overlay (fail-closed, like the sibling sections).
#[test]
fn clear_root_section_only() {
    let mut doc = OverlayDoc {
        hooks: HashMap::from([("h".to_string(), gate())]),
        root: Some(sample_root()),
        ..Default::default()
    };
    doc.clear_section(OverlaySection::Root);
    assert!(doc.root.is_none(), "root cleared");
    assert!(doc.hooks.contains_key("h"), "hooks preserved");
}

/// `apply_root_to_deploy` is a no-op when the overlay has no root override, and applies it when
/// present — the pre-resolve boot-merge half.
#[test]
fn apply_root_to_deploy_noop_and_active() {
    let mut deploy = minimal_deploy();
    apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
    assert_eq!(
        deploy.per_request_fee, 0,
        "no root override → base unchanged"
    );
    let doc = OverlayDoc {
        root: Some(sample_root()),
        ..Default::default()
    };
    apply_root_to_deploy(&mut deploy, &doc);
    assert_eq!(deploy.per_request_fee, 7, "root override applied");
}

/// An unknown key in a root-settings body is a loud reject (`deny_unknown_fields`), never a silent
/// no-op — the same fail-closed posture as the DeployCfg surface.
#[test]
fn root_settings_rejects_unknown_field() {
    let r: Result<RootSettings, _> =
        serde_json::from_value(serde_json::json!({ "lissten": "0.0.0.0:9000" }));
    assert!(r.is_err(), "a typo'd root field is rejected");
}

/// PLUGIN VERSION PINS (1.5.0 rollback-friendly versioning): a `plugin_versions` pin lowers BOTH
/// the per-name `min_versions` floor (third-party path) AND a PER-NAME `first_party_floors` entry
/// (first-party path) when applied to a base `DeployCfg`. Each pin scopes its first-party
/// override to its own name — there is no single global floor lowered for every first-party plugin.
#[test]
fn plugin_versions_pins_lower_the_floors() {
    let mut deploy = minimal_deploy();
    // Base has a higher floor and no first-party floor override (the automatic default).
    deploy
        .plugins
        .min_versions
        .insert("acme-store-x".to_string(), "2.0.0".to_string());
    assert!(deploy.plugins.first_party_floors.is_empty());

    let doc = OverlayDoc {
        plugin_versions: BTreeMap::from([
            ("acme-store-x".to_string(), "1.4.0".to_string()),
            (
                "busbar-store-valkey-plugin".to_string(),
                "1.5.0".to_string(),
            ),
        ]),
        ..Default::default()
    };
    apply_plugin_versions_to_deploy(&mut deploy, &doc);

    assert_eq!(
        deploy
            .plugins
            .min_versions
            .get("acme-store-x")
            .map(String::as_str),
        Some("1.4.0"),
        "the third-party floor is LOWERED to the pinned version"
    );
    // PER-NAME first-party floor overrides: each pinned name gets exactly its pinned version;
    // there is no global floor, so an unpinned first-party plugin is unaffected.
    assert_eq!(
        deploy
            .plugins
            .first_party_floors
            .get("acme-store-x")
            .map(String::as_str),
        Some("1.4.0"),
    );
    assert_eq!(
        deploy
            .plugins
            .first_party_floors
            .get("busbar-store-valkey-plugin")
            .map(String::as_str),
        Some("1.5.0"),
    );
}

/// No pins ⇒ no per-name floor overrides (the automatic posture is untouched): `apply_root_to_deploy`
/// (which also applies pins) leaves `first_party_floors` EMPTY when the overlay carries no pins, so
/// every first-party plugin keeps the binary's own version as its floor.
#[test]
fn no_pins_leaves_first_party_floor_none() {
    let mut deploy = minimal_deploy();
    apply_root_to_deploy(&mut deploy, &OverlayDoc::default());
    assert!(
        deploy.plugins.first_party_floors.is_empty(),
        "with no pins the automatic first-party floor stands"
    );
}

/// `try_persist_plugin_versions` round-trips the pin map AND preserves the hooks/groups/root
/// sections; storing an empty map clears the section (every pin lifted → the base floors return).
#[test]
fn persist_plugin_versions_round_trips_and_preserves_siblings() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-ovl-pins-{}.json", std::process::id()));
    write(
        &path,
        &OverlayDoc {
            hooks: HashMap::from([("keepme".to_string(), gate())]),
            root: Some(sample_root()),
            ..Default::default()
        },
    )
    .unwrap();
    let pins = BTreeMap::from([("acme-store-x".to_string(), "1.4.0".to_string())]);
    try_persist_plugin_versions(Some(&path), &pins).unwrap();
    let doc = read(&path).expect("read back");
    assert_eq!(
        doc.plugin_versions.get("acme-store-x").map(String::as_str),
        Some("1.4.0"),
        "pin persisted"
    );
    assert!(doc.hooks.contains_key("keepme"), "hooks preserved");
    assert!(doc.root.is_some(), "root preserved");
    assert!(
        !doc.section_is_empty(OverlaySection::PluginVersions),
        "the pin section is non-empty"
    );

    // Clearing the pins restores the base floors and preserves siblings.
    try_persist_plugin_versions(Some(&path), &BTreeMap::new()).unwrap();
    let doc = read(&path).expect("read back after clear");
    assert!(doc.plugin_versions.is_empty(), "pins cleared");
    assert!(doc.hooks.contains_key("keepme"), "hooks still preserved");
    assert!(
        doc.section_is_empty(OverlaySection::PluginVersions),
        "the pin section is empty after clear"
    );
    let _ = std::fs::remove_file(&path);
}

/// `clear_section(PluginVersions)` wipes only the pins; the other sections survive — the durable
/// half of `DELETE /api/v1/admin/overlay/plugin_versions` (lift every rollback pin).
#[test]
fn clear_plugin_versions_section_only() {
    let mut doc = OverlayDoc {
        hooks: HashMap::from([("h".to_string(), gate())]),
        plugin_versions: BTreeMap::from([("p".to_string(), "1.0.0".to_string())]),
        ..Default::default()
    };
    doc.clear_section(OverlaySection::PluginVersions);
    assert!(doc.plugin_versions.is_empty(), "pins cleared");
    assert!(doc.hooks.contains_key("h"), "hooks preserved");
}

/// The `plugin_versions` path segment parses to the section and round-trips its label.
#[test]
fn plugin_versions_section_parses() {
    assert_eq!(
        OverlaySection::parse("plugin_versions"),
        Some(OverlaySection::PluginVersions)
    );
    assert_eq!(OverlaySection::PluginVersions.as_str(), "plugin_versions");
}

/// 1.6.0 CLEAN SLATE, SAFETY: a persisted overlay written by a PRE-1.6.0 build whose hook entries
/// still spell the plugin reference `plugin:` (the removed alias) and pin the stage with the removed
/// single-stage `at:` key must NOT brick boot. `read` auto-migrates the raw document BEFORE the
/// `deny_unknown_fields` `HookCfg` deserialize would reject those keys: `plugin:` → `module:` and
/// `at: <stage>` → `phase: [<stage>]` (behavior-preserving). Without the boot migration this file is
/// classified `Unreadable` and every API-registered hook — security gates included — silently
/// vanishes.
#[test]
fn read_auto_migrates_a_legacy_plugin_and_at_overlay() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-overlay-legacy-{}.json", std::process::id()));
    // A pre-1.6.0 overlay: `plugin:` (not `module:`) and the single-stage `at:` key.
    std::fs::write(
        &path,
        serde_json::json!({
            "version": OVERLAY_VERSION,
            "hooks": {
                "audit": { "kind": "tap", "plugin": "audit-hook", "at": "response" }
            },
            "global_hooks": ["audit"]
        })
        .to_string(),
    )
    .unwrap();

    let doc = read(&path).expect("a legacy plugin:/at: overlay must still load, not brick boot");
    let hook = doc.hooks.get("audit").expect("the migrated hook loads");
    assert_eq!(
        hook.plugin, "audit-hook",
        "`plugin:` migrated onto the module field"
    );
    assert_eq!(
        hook.phase,
        vec![crate::config::HookStage::Response],
        "the single-stage `at: response` migrated into a `phase:` list, behavior-preserving"
    );
    std::fs::remove_file(&path).ok();
}

/// The at→phase overlay migration honors the SAME hard stage-value rename `--migrate-config` uses
/// (`completion` → `response`), so a very old overlay pinned with a retired stage vocabulary loads
/// at the renamed stage rather than bricking.
#[test]
fn read_migrates_a_retired_stage_value_in_a_legacy_at_overlay() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!(
        "busbar-overlay-oldstage-{}.json",
        std::process::id()
    ));
    std::fs::write(
        &path,
        serde_json::json!({
            "version": OVERLAY_VERSION,
            "hooks": { "audit": { "kind": "tap", "module": "audit-hook", "at": "completion" } }
        })
        .to_string(),
    )
    .unwrap();
    let doc = read(&path).expect("loads");
    assert_eq!(
        doc.hooks["audit"].phase,
        vec![crate::config::HookStage::Response],
        "`at: completion` migrates to `phase: [response]` (the 1.5.3 stage rename)"
    );
    std::fs::remove_file(&path).ok();
}

/// A non-empty `phase:` on a legacy overlay entry is AUTHORITATIVE: a stray `at:` alongside it is
/// dropped, not merged (matching the old `fires_at_stage` precedence where the list won).
#[test]
fn read_drops_at_when_phase_is_already_present() {
    let dir = std::env::temp_dir();
    let path = dir.join(format!("busbar-overlay-both-{}.json", std::process::id()));
    std::fs::write(
        &path,
        serde_json::json!({
            "version": OVERLAY_VERSION,
            "hooks": {
                "audit": { "kind": "tap", "module": "audit-hook", "at": "request",
                           "phase": ["response"] }
            }
        })
        .to_string(),
    )
    .unwrap();
    let doc = read(&path).expect("loads");
    assert_eq!(
        doc.hooks["audit"].phase,
        vec![crate::config::HookStage::Response],
        "the explicit `phase:` list wins; the stray `at:` is dropped"
    );
    std::fs::remove_file(&path).ok();
}
