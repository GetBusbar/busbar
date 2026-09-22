// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CROSS-PLANE `entitlement_check` SCOPE-KIND BIJECTION TEST, relocated here from
//! `src/plane_host/tests/dispatch_tests.rs` (the "fix the 38" pass after the A6/HostCtx
//! dev-dependency-cycle cleanup): `scope_kind_at(1)` is the FIRST installed plane's own declared
//! scope kind (`crate::plane::registry::scope_kind_at`'s doc) — asserting it equals `"mcp_server"`
//! is a claim about the REAL `busbar_mcp` plane's declared vocabulary, which `cargo xtask gate
//! construction`'s `neutral-no-dialect` rule (ceiling 0) forbids `busbar-kernel` itself from faking
//! under a synthetic `#[cfg(test)]` decl. `busbar_kernel::plane_host::dispatch::entitlement_check`
//! stays `pub(crate)` (widening it to plain `pub` trips clippy's `not_unsafe_ptr_arg_deref` — see its
//! doc), so this drives the REAL wired fn through the PUBLIC `PlaneHostVtable::entitlement_check`
//! field `with_dispatch_scope` hands back — the same seam a real plane calls through. Every OTHER
//! test in `dispatch_tests.rs` (nested_dispatch, workhandle open/resume, the pool-grant entitlement
//! checks, gate_scan) names no real plane's scope-kind vocabulary and stays there.

use busbar_kernel::governance::{GovState, MemoryStore};
use busbar_kernel::plane_host::with_dispatch_scope;
use busbar_kernel::test_support::TestApp;
use busbar_plugin::hot::{CallerRef, TargetRef, POD_VERSION};
use std::sync::Arc;

fn register_planes() {
    busbar_llm::testkit::install_test_seams();
    busbar_mcp::testkit::install_test_seams();
    busbar_a2a::testkit::install_test_seams();
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

fn scoped_key(id: &str, scopes: Option<Vec<busbar_api::ScopeRef>>) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
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
fn app_with_key(key: &busbar_api::VirtualKey) -> Arc<busbar_kernel::state::App> {
    use busbar_api::Store;
    let store = Arc::new(MemoryStore::new());
    store.put_key(key).expect("memory store accepts the key");
    let gov = Arc::new(GovState::new(store, None).expect("gov constructs"));
    TestApp::new().governance(gov).build()
}

/// The vice-versa of the cross-kind fail-closed proof (`entitlement_check_denies_a_target_outside_the_grant`,
/// which stayed local — it only asserts a DENIAL, true regardless of what scope_kind 1 resolves to): a
/// key scoped to an `mcp_server` grant does NOT satisfy a `pool` (scope_kind 0) target, AND the grant
/// DOES cover the matching mcp_server target first — proving scope_kind 1 genuinely resolves to
/// `"mcp_server"` over the real roster, not merely failing to resolve to anything. This pins the
/// scope-kind index bijection — `mcp_server` is index 1, `pool` is index 0 — so the two kinds never
/// alias each other.
#[test]
fn entitlement_check_mcp_server_grant_does_not_cover_a_pool() {
    register_planes();
    let key = scoped_key(
        "k-1",
        Some(vec![busbar_api::ScopeRef {
            kind: "mcp_server".to_string(),
            value: "fast".to_string(),
        }]),
    );
    let app = app_with_key(&key);
    with_dispatch_scope(&app, |host, vt| {
        let entitlement_check = vt
            .entitlement_check
            .expect("the host vtable always wires entitlement_check");
        let caller = caller_ref(b"k-1", 0);
        // The grant DOES cover the matching mcp_server target (sanity: the grant is live).
        let server = target_ref(b"fast", 1); // scope_kind 1 = "mcp_server"
        assert!(
            entitlement_check(host, &caller, &server),
            "the key's mcp_server grant covers `fast` → entitled"
        );
        // …but it must NOT cover a `pool` target of the same value.
        let pool = target_ref(b"fast", 0); // scope_kind 0 = "pool"
        assert!(
            !entitlement_check(host, &caller, &pool),
            "an `mcp_server` grant must NOT cover a `pool` target"
        );
    });
}
