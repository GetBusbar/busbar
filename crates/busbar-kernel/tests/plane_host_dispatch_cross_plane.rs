// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `entitlement_check` SCOPE-KIND BIJECTION TEST, relocated here from
//! `src/plane_host/tests/dispatch_tests.rs`: which kind sits at which ABI scope-kind index is a claim
//! about the REAL roster's declared vocabulary, so it runs over the planes this binary links (the
//! test-linked table, `tests/linked/mod.rs`) and reads every kind back from the plane's own
//! declaration — spelling none. `busbar_kernel::plane_host::dispatch::entitlement_check` stays
//! `pub(crate)` (widening it trips clippy's `not_unsafe_ptr_arg_deref` — see its doc), so this drives
//! the REAL wired fn through the PUBLIC `PlaneHostVtable::entitlement_check` field
//! `with_dispatch_scope` hands back — the same seam a real plane calls through. Every OTHER test in
//! `dispatch_tests.rs` names no real plane's scope-kind vocabulary and stays there.

mod linked;

use busbar_kernel::governance::{GovState, MemoryStore};
use busbar_kernel::plane_host::with_dispatch_scope;
use busbar_kernel::test_support::TestApp;
use busbar_plugin::hot::{CallerRef, TargetRef, POD_VERSION};
use std::sync::Arc;

fn register_planes() {
    linked::install();
}

fn caller_ref(id: &[u8], scope: u32) -> CallerRef {
    CallerRef {
        size: core::mem::size_of::<CallerRef>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        scope,
        _reserved2: 0,
        ref_ptr: id.as_ptr(),
        ref_len: id.len(),
    }
}

fn target_ref(value: &[u8], scope_kind: u32) -> TargetRef {
    TargetRef {
        size: core::mem::size_of::<TargetRef>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        scope_kind,
        _reserved2: 0,
        ref_ptr: value.as_ptr(),
        ref_len: value.len(),
    }
}

fn scoped_key(
    id: &str,
    scopes: Option<Vec<busbar_contract::records::ScopeRef>>,
) -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: id.to_string(),
        generation_hash: String::new(),
        name: "test".to_string(),
        allowed_scopes: scopes,
        enabled: true,
        created_at: 1_700_000_000,
        group: None,
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
        ..Default::default()
    }
}

/// An app whose governance holds `key`, built so `lookup_by_sub` resolves it from the loaded cache.
fn app_with_key(key: &busbar_contract::records::VirtualKey) -> Arc<busbar_kernel::state::App> {
    use busbar_contract::records::RecordStore;
    let store = Arc::new(MemoryStore::new());
    store.put_key(key).expect("memory store accepts the key");
    let gov = Arc::new(GovState::new(store, None).expect("gov constructs"));
    TestApp::new().governance(gov).build()
}

/// The vice-versa of the cross-kind fail-closed proof (`entitlement_check_denies_a_target_outside_the_grant`,
/// which stayed local — it only asserts a DENIAL, true regardless of what a scope-kind index resolves
/// to), driven for EVERY scope kind a linked plane declares beyond the neutral base `pool`: a key
/// scoped to that kind's grant DOES cover the matching target at the kind's ABI index — proving the
/// index genuinely resolves to that kind over the real roster, not merely failing to resolve to
/// anything — and does NOT satisfy a `pool` (index 0) target of the same value. This pins the
/// scope-kind index bijection (`scope_kind_index` and `scope_kind_at` are inverses, and no plane
/// kind aliases the base kind) without spelling any plane's vocabulary: each kind is read back from
/// the plane's own declaration.
#[test]
fn entitlement_check_a_plane_kind_grant_does_not_cover_a_pool() {
    use busbar_kernel::plane::registry::{scope_kind_at, scope_kind_index};
    register_planes();
    let pool_idx = scope_kind_index("pool").expect("the neutral base kind always has an index");
    assert_eq!(pool_idx, 0, "the neutral base kind is index 0");
    let kinds: Vec<&'static str> = linked::planes()
        .iter()
        .flat_map(|d| d.scope_kinds.iter().copied())
        .filter(|k| *k != "pool")
        .collect();
    assert!(
        !kinds.is_empty(),
        "the test-linked roster declares at least one plane scope kind beyond `pool`"
    );
    for kind in kinds {
        let idx = scope_kind_index(kind).expect("a declared kind has an ABI index");
        assert_ne!(idx, pool_idx, "`{kind}` must not alias the base kind");
        assert_eq!(
            scope_kind_at(idx),
            Some(kind),
            "index {idx} resolves back to `{kind}`"
        );
        let key = scoped_key(
            "k-1",
            Some(vec![busbar_contract::records::ScopeRef {
                kind: kind.to_string(),
                value: "fast".to_string(),
            }]),
        );
        let app = app_with_key(&key);
        with_dispatch_scope(&app, |host, vt| {
            let entitlement_check = vt
                .entitlement_check
                .expect("the host vtable always wires entitlement_check");
            let caller = caller_ref(b"k-1", 0);
            // The grant DOES cover the matching target of its own kind (sanity: the grant is live).
            let target = target_ref(b"fast", idx);
            assert!(
                entitlement_check(host, &caller, &target),
                "the key's `{kind}` grant covers `fast` at index {idx} → entitled"
            );
            // …but it must NOT cover a `pool` target of the same value.
            let pool = target_ref(b"fast", pool_idx);
            assert!(
                !entitlement_check(host, &caller, &pool),
                "a `{kind}` grant must NOT cover a `pool` target"
            );
        });
    }
}
