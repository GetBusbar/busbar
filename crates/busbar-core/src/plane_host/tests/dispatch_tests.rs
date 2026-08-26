// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/dispatch.rs`.

use super::*;
use crate::plane_host::{with_dispatch_scope, DurableScope};
use busbar_plugin::hot::POD_VERSION;
use std::sync::Arc;

// The durable-scope type is named by this family but exercised only through the process-lifetime
// registry the wired slots use; assert it constructs so a rider extending it stays append-only.
#[test]
fn durable_scope_stub_constructs() {
    let _ = DurableScope::new();
}

fn op_desc(depth: u32, correlation_id: u64) -> OpDesc {
    OpDesc {
        size: core::mem::size_of::<OpDesc>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        depth,
        _reserved2: 0,
        correlation_id,
        work_ptr: core::ptr::null(),
        work_len: 0,
    }
}

fn workhandle_desc(scope: u32, ttl_secs: u32, correlation_id: u64) -> WorkHandleDesc {
    WorkHandleDesc {
        size: core::mem::size_of::<WorkHandleDesc>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        scope,
        ttl_secs,
        correlation_id,
    }
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

fn content_chunk(data: &[u8]) -> ContentChunk {
    ContentChunk {
        size: core::mem::size_of::<ContentChunk>() as u32,
        version: POD_VERSION,
        is_final: 1,
        _reserved: 0,
        session_id: 0,
        offset: 0,
        data_ptr: data.as_ptr(),
        data_len: data.len(),
    }
}

/// Drive a slot over a REAL recovered `HostState` from an app with no governance.
fn with_bare_app<R>(f: impl FnOnce(HostCtx) -> R) -> R {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, _vt| f(host))
}

// ── nested_dispatch: the DEPTH-BOUND governance decision ────────────────────────────────────

#[test]
fn nested_dispatch_refuses_at_depth_zero() {
    with_bare_app(|host| {
        let desc = op_desc(0, 42);
        let mut out = MaybeUninit::<OpResult>::uninit();
        assert_eq!(
            nested_dispatch(host, &desc, std::ptr::from_mut(&mut out)),
            StatusClass::Refused,
            "an exhausted depth budget refuses re-entry"
        );
    });
}

#[test]
fn nested_dispatch_refuses_beyond_the_host_ceiling() {
    with_bare_app(|host| {
        let desc = op_desc(MAX_NESTED_DEPTH + 1, 42);
        let mut out = MaybeUninit::<OpResult>::uninit();
        assert_eq!(
            nested_dispatch(host, &desc, std::ptr::from_mut(&mut out)),
            StatusClass::Refused,
            "a remaining-depth claim beyond the host ceiling refuses re-entry"
        );
    });
}

#[test]
fn nested_dispatch_within_budget_is_unsupported_not_refused() {
    with_bare_app(|host| {
        let desc = op_desc(1, 42);
        let mut out = MaybeUninit::<OpResult>::uninit();
        // Within the depth bound the re-entrancy guard PASSES; the router re-entry itself is Phase 2.
        assert_eq!(
            nested_dispatch(host, &desc, std::ptr::from_mut(&mut out)),
            StatusClass::Unsupported
        );
    });
}

#[test]
fn nested_dispatch_null_desc_is_refused() {
    with_bare_app(|host| {
        let mut out = MaybeUninit::<OpResult>::uninit();
        assert_eq!(
            nested_dispatch(host, core::ptr::null(), std::ptr::from_mut(&mut out)),
            StatusClass::Refused
        );
    });
}

// ── workhandle_open / resume: the DURABLE unit-of-work ──────────────────────────────────────

#[test]
fn workhandle_open_then_resume_is_ok_and_survives_the_dispatch() {
    // Open the durable handle inside ONE dispatch scope...
    let id = with_bare_app(|host| {
        let desc = workhandle_desc(7, 0, 99);
        let id = workhandle_open(host, &desc);
        assert!(!id.is_none(), "an opened durable handle is a non-zero id");
        id
    });
    // ...and resume it inside a DIFFERENT, later dispatch scope: it was NOT reclaimed at the first
    // future's drop (the DurableScope property; a DispatchScope-arena handle would be gone here).
    with_bare_app(|host| {
        assert_eq!(
            workhandle_resume(host, id),
            StatusClass::Ok,
            "the durable handle survives the dispatch future and resumes by lookup"
        );
    });
}

#[test]
fn workhandle_resume_unknown_is_gone() {
    with_bare_app(|host| {
        assert_eq!(
            workhandle_resume(host, WorkHandleId(u64::MAX)),
            StatusClass::Gone
        );
        assert_eq!(
            workhandle_resume(host, WorkHandleId::NONE),
            StatusClass::Gone
        );
    });
}

#[test]
fn workhandle_open_null_desc_yields_none() {
    with_bare_app(|host| {
        assert!(workhandle_open(host, core::ptr::null()).is_none());
    });
}

// ── entitlement_check: the caller key's scope grant ─────────────────────────────────────────

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
fn app_with_key(key: &busbar_api::VirtualKey) -> Arc<crate::state::App> {
    use busbar_api::Store;
    let store = Arc::new(busbar_store_memory::MemoryStore::new());
    store.put_key(key).expect("memory store accepts the key");
    let gov = Arc::new(crate::governance::GovState::new(store, None).expect("gov constructs"));
    crate::test_support::TestApp::new().governance(gov).build()
}

#[test]
fn entitlement_check_allows_a_target_the_grant_covers() {
    let key = scoped_key("k-1", Some(vec![busbar_api::ScopeRef::pool("fast")]));
    let app = app_with_key(&key);
    with_dispatch_scope(&app, |host, _vt| {
        let caller = caller_ref(b"k-1", 0);
        let target = target_ref(b"fast", 0); // scope_kind 0 = "pool"
        assert!(
            entitlement_check(host, &caller, &target),
            "the key's pool grant covers `fast` → entitled"
        );
    });
}

#[test]
fn entitlement_check_denies_a_target_outside_the_grant() {
    let key = scoped_key("k-1", Some(vec![busbar_api::ScopeRef::pool("fast")]));
    let app = app_with_key(&key);
    with_dispatch_scope(&app, |host, _vt| {
        let caller = caller_ref(b"k-1", 0);
        let cold = target_ref(b"cold", 0); // pool the grant does NOT list
        assert!(
            !entitlement_check(host, &caller, &cold),
            "a pool the grant omits is denied"
        );
        // Cross-kind is fail-closed: a pool-only grant does not cover an mcp_server target.
        let server = target_ref(b"fast", 1); // scope_kind 1 = "mcp_server"
        assert!(!entitlement_check(host, &caller, &server));
        // An unknown caller id is denied.
        let stranger = caller_ref(b"nobody", 0);
        let fast = target_ref(b"fast", 0);
        assert!(!entitlement_check(host, &stranger, &fast));
    });
}

#[test]
fn entitlement_check_fails_closed_on_null_and_no_governance() {
    // No governance → deny, and null PODs → deny, and a panic-free bare app.
    with_bare_app(|host| {
        let caller = caller_ref(b"k-1", 0);
        let target = target_ref(b"fast", 0);
        assert!(
            !entitlement_check(host, &caller, &target),
            "no governance → deny"
        );
        assert!(!entitlement_check(host, core::ptr::null(), &target));
        assert!(!entitlement_check(host, &caller, core::ptr::null()));
    });
}

// ── gate_scan: the real content-governance gate ─────────────────────────────────────────────

#[test]
fn gate_scan_continues_a_clean_chunk_with_no_gates() {
    with_bare_app(|host| {
        let chunk = content_chunk(b"hello world");
        assert_eq!(
            gate_scan(host, &chunk),
            GateDecision::Continue,
            "no gate is attached → the real decide proceeds → Continue"
        );
    });
}

#[test]
fn gate_scan_blocks_a_null_chunk() {
    with_bare_app(|host| {
        assert_eq!(
            gate_scan(host, core::ptr::null()),
            GateDecision::Block,
            "a null chunk fails closed to Block"
        );
    });
}

/// A content gate that always REJECTS — the shape a real screening hook takes on a policy hit.
struct RejectGate;

#[async_trait::async_trait]
impl crate::hooks::RoutingPolicy for RejectGate {
    async fn decide(
        &self,
        _req: &crate::hooks::RoutingRequest<'_>,
        _candidates: &[crate::hooks::Candidate<'_>],
        _ctx: &crate::hooks::RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> crate::hooks::PolicyResult {
        Ok(crate::hooks::RoutingDecision::Reject {
            status: 451,
            message: "screened".to_string(),
        })
    }
    fn name(&self) -> &'static str {
        "reject-gate"
    }
}

#[test]
fn gate_scan_blocks_when_a_real_gate_rejects() {
    let gates: Vec<(u16, crate::hooks::ResolvedPolicy)> = vec![(
        0,
        crate::hooks::ResolvedPolicy::Policy {
            policy: Arc::new(RejectGate),
            on_error: crate::config::PolicyOnError::Reject,
            on_error_chain: Vec::new(),
            timeout: std::time::Duration::from_secs(5),
            send_prompt: true,
            send_user: false,
            on_empty: crate::config::PolicyOnError::Reject,
        },
    )];
    with_bare_app(|host| {
        let chunk = content_chunk(b"screen me");
        // Drive the seam body with a REAL rejecting gate through the REAL `hooks::gate::decide`.
        assert_eq!(
            gate_scan_inner(host, &chunk, &gates),
            GateDecision::Block,
            "a real gate Reject maps to Block through this seam"
        );
    });
}
