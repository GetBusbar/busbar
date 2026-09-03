// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/mod.rs`.

use super::*;
use busbar_plugin::hot::{
    AdmissionId, AuthQuery, AuthResolved, Decision, Facts, MeterOutcome, MetricSample, StatusClass,
    Usage, UsageComponent, POD_VERSION,
};
use core::mem::MaybeUninit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Drive the wired slots through the REAL recovery path over a live `App` from the test-support
/// builder. The three wired fns recover the `HostState` but none of them read `app`, so a minimal
/// `TestApp` suffices; what matters is that `HostCtx` recovers a live `HostState` for the call.
fn with_test_state<R>(f: impl FnOnce(HostCtx, &PlaneHostVtable, &DispatchScope) -> R) -> R {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: `host` is the live HostState minted by `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) };
        let scope = state.scope;
        f(host, vt, scope)
    })
}

#[test]
fn builds_a_full_vtable_with_frozen_preamble() {
    let vt = build_plane_host_vtable();
    assert_eq!(busbar_plugin::check_preamble(&vt.abi), Ok(()));
    assert_eq!(vt.size as usize, core::mem::size_of::<PlaneHostVtable>());
    // Every slot is populated and wired after the Phase-1 fan-out: no slot is a `None`.
    assert!(vt.govern_admit.is_some());
    assert!(vt.breaker_admit.is_some());
    assert!(vt.breaker_admit_reason.is_some());
    assert!(vt.clock_now.is_some());
    assert!(vt.metrics_emit.is_some());
    assert!(vt.egress_open.is_some());
    assert!(vt.auth_resolve.is_some());
    assert!(vt.gate_scan.is_some());
    // The minor-19 metering-lease slots are now WIRED (no longer the reserved `None`).
    assert!(vt.cost_reserve.is_some());
    assert!(vt.cost_settle.is_some());
}

#[test]
fn wired_clock_now_returns_a_nonzero_nanos_clock() {
    with_test_state(|host, vt, _scope| {
        let now = (vt.clock_now.unwrap())(host);
        assert!(
            now > 0,
            "host clock must be a live nonzero nanosecond reading"
        );
    });
}

#[test]
fn wired_govern_admit_decides_over_the_facts_pod() {
    with_test_state(|host, vt, _scope| {
        let admit = Facts::new(10, 100, 1, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*admit as *const Facts),
            Decision::Admit,
            "budget covers the request → admit"
        );
        let deny = Facts::new(100, 10, 1, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*deny as *const Facts),
            Decision::Deny,
            "request exceeds budget → deny"
        );
        // Fail-closed on a null POD.
        assert_eq!(
            (vt.govern_admit.unwrap())(host, core::ptr::null()),
            Decision::Deny
        );
    });
}

/// The GOVERNANCE `govern_admit` slot REGISTERS the real RAII grant in the dispatch arena on an
/// admit and reclaims it on scope-drop; a deny registers nothing. Drives the slot via the vtable.
#[test]
fn wired_govern_admit_registers_grant_in_arena_and_reclaims() {
    with_test_state(|host, vt, scope| {
        assert_eq!(scope.registered(), 0, "arena starts empty");
        // Admit → the grant rides the arena.
        let admit = Facts::new(10, 100, 7, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*admit as *const Facts),
            Decision::Admit
        );
        assert_eq!(scope.registered(), 1, "an admitted grant is registered");
        // Deny → nothing registered (still just the one from the admit above).
        let deny = Facts::new(100, 10, 7, 0, 0, b"pool");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*deny as *const Facts),
            Decision::Deny
        );
        assert_eq!(scope.registered(), 1, "a denied request registers no grant");
        // Explicit reclaim (the abort-path assertion): the arena empties.
        scope.reclaim_all();
        assert_eq!(
            scope.registered(),
            0,
            "reclaim releases the registered grant"
        );
    });
}

/// With governance ENABLED, `govern_admit` drives the real `GovState::try_admit` limit engine and
/// still registers the RAII grant it returns. Exercises the delegation over a live `GovState`.
#[test]
fn wired_govern_admit_drives_the_real_limit_engine() {
    let gov = Arc::new(
        crate::governance::GovState::new(Arc::new(crate::governance::MemoryStore::new()), None)
            .expect("memory store constructs"),
    );
    let app = crate::test_support::TestApp::new().governance(gov).build();
    with_dispatch_scope(&app, |host, vt| {
        // SAFETY: live HostState from `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) };
        let admit = Facts::new(5, 50, 3, 0, 0, b"pool-a");
        assert_eq!(
            (vt.govern_admit.unwrap())(host, &*admit as *const Facts),
            Decision::Admit,
            "the real limit engine admits an ungrouped (unlimited) chain"
        );
        assert_eq!(
            state.scope.registered(),
            1,
            "the engine's grant is registered in the arena"
        );
    });
}

/// The GOVERNANCE `meter_charge` slot charges a usage through the real metering path (money-scalar
/// breakdown + write-behind accrual), returning `Charged`; a null POD is fail-closed to `Rejected`.
#[test]
fn wired_meter_charge_charges_a_usage_pod() {
    with_test_state(|host, vt, _scope| {
        let usage = Usage {
            size: core::mem::size_of::<Usage>() as u32,
            version: POD_VERSION,
            component: UsageComponent::Tokens,
            _reserved: 0,
            amount: 1_000,
            unit_cost_micros: 3,
            admission: AdmissionId(42),
            key_id_ptr: core::ptr::null(),
            key_id_len: 0,
            model_ptr: core::ptr::null(),
            model_len: 0,
            provider_ptr: core::ptr::null(),
            provider_len: 0,
            units_ptr: core::ptr::null(),
            units_len: 0,
        };
        assert_eq!(
            (vt.meter_charge.unwrap())(host, &usage as *const Usage),
            MeterOutcome::Charged,
            "a well-formed usage charges"
        );
        // A zero-cost usage still charges (a sparse, empty breakdown is valid).
        let zero = Usage {
            amount: 0,
            unit_cost_micros: 0,
            ..usage
        };
        assert_eq!(
            (vt.meter_charge.unwrap())(host, &zero as *const Usage),
            MeterOutcome::Charged
        );
        // Fail-closed on a null POD.
        assert_eq!(
            (vt.meter_charge.unwrap())(host, core::ptr::null()),
            MeterOutcome::Rejected
        );
    });
}

/// The GOVERNANCE `auth_resolve` slot resolves a credential REF to a host-side reference, writing
/// the out-param ONLY on `Ok`. A query naming no credential (or a null query) is `Refused` and
/// leaves the out-slot untouched.
#[test]
fn wired_auth_resolve_writes_pod_only_on_ok() {
    with_test_state(|host, vt, _scope| {
        let audience = b"aud:example";
        let query = AuthQuery {
            size: core::mem::size_of::<AuthQuery>() as u32,
            version: POD_VERSION,
            _reserved: 0,
            credential_ref: 0x9abc,
            audience_ptr: audience.as_ptr(),
            audience_len: audience.len(),
        };
        let mut out = MaybeUninit::<AuthResolved>::uninit();
        assert_eq!(
            (vt.auth_resolve.unwrap())(
                host,
                &query as *const AuthQuery,
                &mut out as *mut MaybeUninit<AuthResolved>
            ),
            StatusClass::Ok
        );
        // SAFETY: the Ok status published the slot (init-only-on-Ok).
        let resolved = unsafe { out.assume_init() };
        // The host MINTS a fresh, opaque, host-owned ref — distinct from the input `credential_ref`
        // (the CLUSTER-3 (d) decision), never the echoed input.
        assert_ne!(resolved.resolved_ref, 0, "a live host-side ref is minted");
        assert_ne!(
            resolved.resolved_ref, 0x9abc,
            "the mint is a NEW ref, not the input echoed"
        );
        assert!(resolved.expires_unix > 0, "a bounded expiry is stamped");
        // The PLAINTEXT lives host-side behind the ref; the plane received only the opaque ref. The
        // mint is bound to the query's audience (FFI-F5), so it resolves for THAT destination.
        let secret = super::creds::resolve(
            resolved.resolved_ref,
            resolved.expires_unix - 1,
            "aud:example",
        )
        .expect("the minted ref resolves host-side for its bound destination");
        assert!(
            secret.starts_with(b"hostcred:"),
            "the host owns the resolved credential; it never crossed to the plane"
        );

        // A query naming no credential is refused; the out-slot is NOT written.
        let none = AuthQuery {
            credential_ref: 0,
            ..query
        };
        let mut out2 = MaybeUninit::<AuthResolved>::uninit();
        assert_eq!(
            (vt.auth_resolve.unwrap())(
                host,
                &none as *const AuthQuery,
                &mut out2 as *mut MaybeUninit<AuthResolved>
            ),
            StatusClass::Refused
        );
        // Fail-closed on a null query.
        assert_eq!(
            (vt.auth_resolve.unwrap())(
                host,
                core::ptr::null(),
                &mut out2 as *mut MaybeUninit<AuthResolved>
            ),
            StatusClass::Refused
        );
    });
}

#[test]
fn wired_metrics_emit_reaches_the_recorder() {
    with_test_state(|host, vt, _scope| {
        let name = b"busbar_plane_host_test";
        let sample = MetricSample {
            size: core::mem::size_of::<MetricSample>() as u32,
            version: busbar_plugin::hot::POD_VERSION,
            _reserved: 0,
            _reserved2: 0,
            value_bits: 1.5f64.to_bits(),
            name_ptr: name.as_ptr(),
            name_len: name.len(),
            labels_ptr: core::ptr::null(),
            labels_len: 0,
        };
        assert_eq!(
            (vt.metrics_emit.unwrap())(host, &sample as *const MetricSample),
            StatusClass::Ok
        );
        // Null POD is refused, not faulted.
        assert_eq!(
            (vt.metrics_emit.unwrap())(host, core::ptr::null()),
            StatusClass::Refused
        );
    });
}

/// The async guard is `Send` (so a future holding it across `.await` stays `Send`) and the Send
/// route is `Send + 'static` (so it can be moved into `spawn_blocking`). Compile-time proof.
#[test]
fn guards_have_the_right_thread_bounds() {
    fn assert_send<T: Send>() {}
    fn assert_send_static<T: Send + 'static>() {}
    assert_send::<HostDispatch<'static>>();
    assert_send_static::<SendHostDispatch>();
    // The durable route rides a DETACHED runner, so it too must be Send + 'static.
    assert_send_static::<DurableHostDispatch>();
}

/// The OWNED async guard held across an `.await` reclaims its arena when the future completes —
/// the fix for the sync-only closure form (which would drop the scope before the future ran).
#[tokio::test]
async fn host_dispatch_guard_reclaims_across_an_await() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    let app = crate::test_support::TestApp::new().build();
    {
        let host = HostDispatch::new(&app);
        let f = reclaimed.clone();
        host.scope().register_egress(Box::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        }));
        // Materialize the HostCtx synchronously and recover a live HostState through it.
        host.with_host(|ctx, vt| {
            assert!(ctx as usize != 0, "a live HostCtx is minted");
            assert!(vt.clock_now.is_some());
        });
        // The guard is held ACROSS this await — the scope must not reclaim yet.
        tokio::task::yield_now().await;
        assert_eq!(
            reclaimed.load(Ordering::SeqCst),
            0,
            "held across await, not reclaimed"
        );
    }
    // Guard dropped at the end of the future → the arena reclaimed exactly once.
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}

/// The Send route survives a move into `spawn_blocking`, materializes a live `HostCtx` on the
/// blocking thread, and reclaims its arena when the closure (and the guard) end.
#[tokio::test]
async fn send_host_dispatch_works_inside_spawn_blocking() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(crate::test_support::TestApp::new().build());
    let host = SendHostDispatch::new(Arc::clone(&app));
    let f = reclaimed.clone();
    let now = tokio::task::spawn_blocking(move || {
        host.scope().register_egress(Box::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        }));
        // The raw HostCtx is minted and used INSIDE the blocking closure, never across the boundary.
        let now = host.with_host(|ctx, vt| (vt.clock_now.unwrap())(ctx));
        assert_eq!(host.scope().registered(), 1);
        now
        // `host` drops here → the hop arena reclaims on the blocking thread.
    })
    .await
    .expect("blocking hop joins");
    assert!(now > 0, "the host clock read on the blocking thread");
    assert_eq!(
        reclaimed.load(Ordering::SeqCst),
        1,
        "the hop arena reclaimed at closure end"
    );
}

#[test]
fn dispatch_scope_reclaims_a_registered_handle_on_scope_end() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    let flag = reclaimed.clone();
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, _vt| {
        // SAFETY: live HostState from `with_dispatch_scope`.
        let state: &HostState = unsafe { recover(host) };
        let f = flag.clone();
        state.scope.register_egress(Box::new(move || {
            f.fetch_add(1, Ordering::SeqCst);
        }));
        assert_eq!(state.scope.registered(), 1);
        assert_eq!(flag.load(Ordering::SeqCst), 0);
    });
    // The dispatch scope ended → the registered handle was reclaimed exactly once.
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}
