// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **DECISIONS #11 FOR `kind: store`, ON THE SCOPE-KIND VOCABULARY** (1.6.0 SDK-SCOPEKINDS).
//!
//! The engine registers each installed plane's scope kinds (`mcp_server`, `mcp_tool`, …) at boot,
//! into the process-global `busbar_contract::records::scope_kinds` registry. A COMPILED-IN store
//! shares that registry. A DROPPED-IN store is a `cdylib` that statically links its OWN copy of the
//! contract crate, so its registry is a different static the boot registration never reaches.
//!
//! While the `VirtualKey` wire refused to serialize a kind its process had not registered, that
//! difference was observable: the dropped-in store accepted `put_key` (deserialization never
//! checked) and then FAILED `get_key` / `list_keys`, because answering meant serializing the key back
//! across the boundary inside the plugin. The compiled-in build of the same source answered. Two
//! builds, two behaviours — the store-sqlite port had to re-register every kind it read back to
//! paper over it.
//!
//! The fix makes the wire an opaque, lossless carrier (every kind to its own `allowed_{kind}s`
//! field), so kind validation stays the engine's and a plugin never needs the vocabulary. This
//! module drives the SAME store (the in-tree store example), LINKED and `dlopen`ed, through the same
//! script, and requires both to hand back the key byte-identically.
//!
//! RED at the pre-fix HEAD: the dropped-in arm's `get_key` returns the plugin's serialize error
//! (`scope kind 'mcp_server' has no registered wire field`), so the `expect` below panics.

use super::both_ways::store_fixture;
use busbar_api::{ScopeRef, Store, VirtualKey};

/// Two scope kinds a plane registers at boot, read from `tests/fixtures/plane_scope_kinds.txt` (data,
/// not code: the loader names no plane).
const PLANE_SCOPE_KINDS: &str = include_str!("../../tests/fixtures/plane_scope_kinds.txt");

/// One plane scope kind from [`PLANE_SCOPE_KINDS`], by key. Panics on a missing key: a fixture that
/// lost a row must fail the test, never hand it an empty kind.
fn plane_kind(key: &str) -> &'static str {
    PLANE_SCOPE_KINDS
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .find_map(|l| {
            let (k, v) = l.split_once('=')?;
            (k.trim() == key).then(|| v.trim())
        })
        .unwrap_or_else(|| panic!("tests/fixtures/plane_scope_kinds.txt has no `{key}` row"))
}

/// The key both arms store: a pool grant beside two PLANE grants, so the wire carries every shape
/// at once — the pool field the pre-generalization wire had, plus two registered-by-the-engine kinds
/// the plugin process never registered.
fn key_with_plane_grants() -> VirtualKey {
    VirtualKey {
        id: "vk_scopekinds".into(),
        generation_hash: "binding:vk_scopekinds:1".into(),
        name: "scope-kinds".into(),
        allowed_scopes: Some(vec![
            ScopeRef::pool("fast"),
            ScopeRef {
                kind: plane_kind("server").into(),
                value: "filesystem".into(),
            },
            ScopeRef {
                kind: plane_kind("tool").into(),
                value: "filesystem_read_file".into(),
            },
        ]),
        enabled: true,
        created_at: 1_700_000_000,
        ..Default::default()
    }
}

/// The host side of boot: the composition root registers each installed plane's scope kinds. The
/// test registers them in ITS process — which is the linked arm's process, and is NOT the dropped-in
/// plugin's registry. That asymmetry is the defect under test.
fn register_like_boot() {
    busbar_api::register_scope_kind(plane_kind("server"));
    busbar_api::register_scope_kind(plane_kind("tool"));
}

/// Run the script against one store and return what the HOST was handed, as wire bytes:
/// `(get_key, list_keys)`, each serialized in the host exactly as the engine would persist/serve it.
fn round_trip(store: &dyn Store, arm: &str) -> (Vec<u8>, Vec<u8>) {
    let key = key_with_plane_grants();
    store
        .put_key(&key)
        .unwrap_or_else(|e| panic!("{arm}: put_key: {e}"));
    let got = store
        .get_key(&key.id)
        .unwrap_or_else(|e| panic!("{arm}: get_key must hand the key back: {e}"))
        .unwrap_or_else(|| panic!("{arm}: get_key found nothing"));
    let listed = store
        .list_keys()
        .unwrap_or_else(|e| panic!("{arm}: list_keys must hand the key back: {e}"));
    (
        serde_json::to_vec(&got).expect("host serialize get_key"),
        serde_json::to_vec(&listed).expect("host serialize list_keys"),
    )
}

/// The in-tree store example `cdylib`, if built: the newest of the uplifted `<profile_dir>/<name>`
/// copy and the raw `<profile_dir>/deps/<name>` output (a scoped `cargo test -p` only produces the
/// latter). Under CI a missing artifact is a HARD failure, never a silent skip.
fn store_example_cdylib() -> Option<std::path::PathBuf> {
    let candidate = (|| {
        let exe = std::env::current_exe().ok()?;
        let profile_dir = exe.parent()?.parent()?;
        let name = crate::plugin_library_filename(super::both_ways::fixture("store").0);
        [
            profile_dir.join(&name),
            profile_dir.join("deps").join(&name),
        ]
        .into_iter()
        .filter_map(|p| {
            std::fs::metadata(&p)
                .and_then(|m| m.modified())
                .ok()
                .map(|mtime| (p, mtime))
        })
        .max_by_key(|(_, mtime)| *mtime)
        .map(|(p, _)| p)
    })();
    if candidate.is_none() && std::env::var_os("CI").is_some() {
        panic!(
            "the store example plugin cdylib is not built under CI: `cargo test --workspace` must \
             build {}. Refusing to silently skip DECISIONS #11's compiled-in vs dropped-in \
             scope-kind equivalence.",
            super::both_ways::fixture("store").0
        );
    }
    candidate
}

/// **THE EQUIVALENCE.** The same store, LINKED and `dlopen`ed, hands back a key carrying `mcp_server`
/// and `mcp_tool` grants byte-identically — and identical to what the host put in.
#[test]
fn linked_and_dropped_in_store_round_trip_a_plane_scope_grant_identically() {
    register_like_boot();

    let linked = store_fixture::open("{}").expect("compiled-in ctor");
    let (linked_get, linked_list) = round_trip(linked.as_ref(), "linked");

    let Some(path) = store_example_cdylib() else {
        // Not built under this scoped run; `store_example_cdylib` hard-fails under CI.
        return;
    };
    let dropped = crate::load_store(&path, "{}").expect("dlopen the store example plugin");
    let (dropped_get, dropped_list) = round_trip(dropped.as_ref(), "dropped-in");

    // The linked store hands back what it was given, save the `revision` every store stamps.
    let linked_back: VirtualKey = serde_json::from_slice(&linked_get).unwrap();
    let expected = VirtualKey {
        revision: linked_back.revision,
        ..key_with_plane_grants()
    };
    assert_eq!(
        String::from_utf8_lossy(&linked_get),
        String::from_utf8_lossy(&serde_json::to_vec(&expected).unwrap()),
        "the linked store must hand back exactly what it was given"
    );
    assert_eq!(
        String::from_utf8_lossy(&dropped_get),
        String::from_utf8_lossy(&linked_get),
        "DECISIONS #11: the dropped-in store must hand back the key byte-identically to the linked one"
    );
    assert_eq!(
        String::from_utf8_lossy(&dropped_list),
        String::from_utf8_lossy(&linked_list),
        "DECISIONS #11: list_keys must agree across the two builds"
    );
    // The grant is really in the bytes both arms agreed on — the equivalence is not over a key that
    // lost its plane grants on both sides.
    let back: VirtualKey = serde_json::from_slice(&dropped_get).unwrap();
    assert!(back.scope_allowed(plane_kind("tool"), "filesystem_read_file"));
    assert!(back.scope_allowed(plane_kind("server"), "filesystem"));
    assert!(!back.scope_allowed("pool", "filesystem_read_file"));
}
