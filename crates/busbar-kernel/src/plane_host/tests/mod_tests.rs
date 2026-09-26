// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/plane_host/mod.rs`.

use super::*;
use busbar_plugin::hot::{
    AdmissionId, AuthQuery, AuthResolved, Decision, Facts, MeterOutcome, MetricSample,
    RawUsageComponent, StatusClass, Usage, UsageComponent, POD_VERSION,
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
        let state: &HostState = unsafe { recover(host) }
            .expect("host generation still live inside with_dispatch_scope");
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
        let state: &HostState = unsafe { recover(host) }
            .expect("host generation still live inside with_dispatch_scope");
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
            component: RawUsageComponent::of(UsageComponent::Tokens),
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

/// The test emitter's registry key. Distinct per test where a test needs its own cardinality
/// budget; `forget_emitter` clears one so tests do not inherit each other's ceilings.
const TEST_PLANE: &str = "test-plane";

/// Like [`with_test_state`], but the `HostCtx` is ATTRIBUTED to `plane` — the mint a real plane
/// dispatch uses. `metrics_emit` refuses an unattributed handle, so every test of that slot has to
/// come through here, which is the point: the host's provenance is not optional.
fn with_test_state_as<R>(
    plane: &'static str,
    f: impl FnOnce(HostCtx, &PlaneHostVtable, &DispatchScope) -> R,
) -> R {
    let app = crate::test_support::TestApp::new().build();
    let scope = DispatchScope::new();
    crate::plane_host::with_borrowed_host_as(plane, &app, &scope, |host, vt| f(host, vt, &scope))
}

/// Build a `MetricSample` over a borrowed name and a value — the POD a plane hands `metrics_emit`.
fn sample_of(name: &[u8], value: f64) -> MetricSample {
    labelled_sample(name, value, &[])
}

/// The same, carrying an OPAQUE packed label blob (the ABI says the host does not interpret it).
fn labelled_sample(name: &[u8], value: f64, labels: &[u8]) -> MetricSample {
    MetricSample {
        size: core::mem::size_of::<MetricSample>() as u32,
        version: busbar_plugin::hot::POD_VERSION,
        _reserved: 0,
        _reserved2: 0,
        value_bits: value.to_bits(),
        name_ptr: name.as_ptr(),
        name_len: name.len(),
        labels_ptr: if labels.is_empty() {
            core::ptr::null()
        } else {
            labels.as_ptr()
        },
        labels_len: labels.len(),
    }
}

#[test]
fn wired_metrics_emit_reaches_the_recorder() {
    with_test_state_as(TEST_PLANE, |host, vt, _scope| {
        // An ADMISSIBLE name: within the charset and outside the reserved `busbar_` namespace.
        // (It was `busbar_plane_host_test` before the host started bounding this slot — which is
        // the point: the old wiring let a plane write into the first-party namespace, and the test
        // that "proved the sample reaches the recorder" was itself doing it.)
        let sample = sample_of(b"plane_host_test", 1.5);
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

/// THE HOST BOUNDS THE HOT LANE TOO (DECISIONS #85). A plane REPORTS a sample; what it is allowed to
/// have said is the host's decision, and it is the SAME decision the cold lane's envelope fold makes
/// — `crate::metrics::observe::admits_metric_name`, asked once and answered once.
///
/// Every rejection here was reachable before: the slot took the name verbatim, invented
/// `busbar_plane_metric` when given none, and never looked at the value. So a plane could shadow a
/// first-party series, emit a name Prometheus cannot parse (which costs the WHOLE exposition, not
/// the sample), or push a `NaN` straight into the recorder.
#[test]
fn metrics_emit_refuses_what_the_host_does_not_admit() {
    with_test_state_as(TEST_PLANE, |host, vt, _scope| {
        let emit = vt.metrics_emit.unwrap();
        // The RESERVED namespace: a plane cannot impersonate a first-party series.
        let reserved = sample_of(b"busbar_http_requests_total", 1.0);
        assert_eq!(
            emit(host, &reserved as *const MetricSample),
            StatusClass::Refused
        );
        // Outside the Prometheus identifier charset.
        for bad in [
            &b"Bad-Name"[..],
            &b"1leading"[..],
            &b"has space"[..],
            &b"UPPER"[..],
        ] {
            let s = sample_of(bad, 1.0);
            assert_eq!(
                emit(host, &s as *const MetricSample),
                StatusClass::Refused,
                "{:?} must not reach the recorder",
                String::from_utf8_lossy(bad)
            );
        }
        // NON-FINITE values. `f64::from_bits` hands these back for bit patterns a plane can produce.
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let s = sample_of(b"plane_host_test", v);
            assert_eq!(emit(host, &s as *const MetricSample), StatusClass::Refused);
        }
        // NO NAME is not a metric. The old wiring invented `busbar_plane_metric` here — a reserved
        // name no plane chose and no operator could attribute.
        let unnamed = MetricSample {
            size: core::mem::size_of::<MetricSample>() as u32,
            version: busbar_plugin::hot::POD_VERSION,
            _reserved: 0,
            _reserved2: 0,
            value_bits: 1.0f64.to_bits(),
            name_ptr: core::ptr::null(),
            name_len: 0,
            labels_ptr: core::ptr::null(),
            labels_len: 0,
        };
        assert_eq!(
            emit(host, &unnamed as *const MetricSample),
            StatusClass::Refused
        );
    });
}

/// ONE RULE, BOTH LANES. The predicate the hot slot asks is the predicate the cold envelope fold
/// asks — asserted directly, so the two can never be "fixed" apart.
#[test]
fn both_abi_lanes_ask_the_same_metric_name_question() {
    assert!(crate::metrics::observe::admits_metric_name(
        "plane_host_test"
    ));
    assert!(!crate::metrics::observe::admits_metric_name(
        "busbar_anything"
    ));
    assert!(!crate::metrics::observe::admits_metric_name("Bad-Name"));
    assert!(!crate::metrics::observe::admits_metric_name(""));
}

/// **PROVENANCE IS NOT OPTIONAL.** A handle minted for the HOST's own use — `calllog`, `auditlog`,
/// trust, the breaker — carries no emitter, and `metrics_emit` refuses it.
///
/// This is the same finding as the name-invention it sits beside: an identity the emitter supplies
/// is a claim, not an attribution. The host either knows who is emitting, from the mint it performed
/// itself, or the sample does not become a series. Anonymous series are series an operator cannot
/// act on, and two planes reporting one name would be indistinguishable in the exposition.
#[test]
fn metrics_emit_refuses_a_handle_with_no_host_attributed_emitter() {
    // `with_test_state` goes through `with_dispatch_scope`, which is a HOST-internal mint.
    with_test_state(|host, vt, _scope| {
        let sample = sample_of(b"plane_host_test", 1.0);
        assert_eq!(
            (vt.metrics_emit.unwrap())(host, &sample as *const MetricSample),
            StatusClass::Refused,
            "an unattributed handle must not be able to register a series"
        );
    });
}

/// **THE CARDINALITY BUDGET, RED-PROVABLE: a bounded emitter is admitted, an unbounded one is
/// refused.**
///
/// A name check bounds what a series may be CALLED; nothing bounded how MANY. A plane emitting
/// `req_0_total`, `req_1_total`, … passes every charset rule ever written and grows the recorder's
/// registry without limit — and a Prometheus registry never shrinks, so by the time an operator
/// notices, a restart is the only remedy. That is resource exhaustion reachable from an untrusted
/// plugin.
///
/// The refusal is RETURNED to the plane, not swallowed: it is entitled to know its telemetry stopped
/// landing.
#[test]
fn metrics_emit_admits_a_bounded_emitter_and_refuses_an_unbounded_one() {
    const PLANE: &str = "cardinality-series-plane";
    crate::metrics::observe::forget_cardinality(PLANE);
    with_test_state_as(PLANE, |host, vt, _scope| {
        let emit = vt.metrics_emit.unwrap();
        // BOUNDED: the same series, over and over, is admitted every time — a well-behaved emitter
        // never runs out of budget.
        let steady = sample_of(b"steady_total", 1.0);
        for _ in 0..(crate::metrics::observe::MAX_SERIES_PER_PLUGIN * 4) {
            assert_eq!(
                emit(host, &steady as *const MetricSample),
                StatusClass::Ok,
                "an established series must keep reporting forever"
            );
        }
        // UNBOUNDED: a fresh series name every call. The budget admits up to the ceiling (one slot
        // is already spent on `steady_total`) and refuses past it.
        let mut admitted = 1usize;
        for i in 0..(crate::metrics::observe::MAX_SERIES_PER_PLUGIN * 2) {
            let name = format!("churn_{i}_total");
            let s = sample_of(name.as_bytes(), 1.0);
            if emit(host, &s as *const MetricSample) == StatusClass::Ok {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted,
            crate::metrics::observe::MAX_SERIES_PER_PLUGIN,
            "the budget must be a hard ceiling, not a suggestion"
        );
        // And the ESTABLISHED series is untouched by the flood — a misbehaving shape must not evict
        // a well-behaved one, or a real series flaps in and out of the exposition.
        assert_eq!(
            emit(host, &steady as *const MetricSample),
            StatusClass::Ok,
            "an established series must survive another series exhausting the budget"
        );
    });
}

/// The LABEL half of the same budget, on the hot lane's OPAQUE blob. The host does not interpret
/// these bytes — the ABI says so — and does not need to: telling two label sets apart is all a
/// cardinality bound requires, which is what lets the bound exist before the label encoding does.
#[test]
fn metrics_emit_bounds_distinct_label_sets_under_one_series() {
    const PLANE: &str = "cardinality-label-plane";
    crate::metrics::observe::forget_cardinality(PLANE);
    with_test_state_as(PLANE, |host, vt, _scope| {
        let emit = vt.metrics_emit.unwrap();
        let mut admitted = 0usize;
        for i in 0..(crate::metrics::observe::MAX_LABEL_SETS_PER_SERIES * 3) {
            let labels = format!("request_id\u{1}{i}");
            let s = labelled_sample(b"one_series_total", 1.0, labels.as_bytes());
            if emit(host, &s as *const MetricSample) == StatusClass::Ok {
                admitted += 1;
            }
        }
        assert_eq!(
            admitted,
            crate::metrics::observe::MAX_LABEL_SETS_PER_SERIES,
            "labelling by request id must hit a ceiling, not explode the registry"
        );
        // A label set ALREADY inside the budget keeps being admitted.
        // The same bytes `format!("request_id\u{1}0")` produces — a byte-string literal cannot
        // carry a `\u{}` escape, so the code unit is spelled directly.
        let known = labelled_sample(b"one_series_total", 1.0, b"request_id\x010");
        assert_eq!(emit(host, &known as *const MetricSample), StatusClass::Ok);
    });
}

/// ONE BUDGET, BOTH LANES — the same assertion shape as the name question above. The cold lane's
/// fold and the hot lane's slot ask `admits_cardinality`, so a plugin cannot pick a lane to get a
/// more generous ceiling.
#[test]
fn both_abi_lanes_ask_the_same_cardinality_question() {
    const PLANE: &str = "shared-budget-plane";
    crate::metrics::observe::forget_cardinality(PLANE);
    // Spend the whole series budget through the shared predicate...
    for i in 0..crate::metrics::observe::MAX_SERIES_PER_PLUGIN {
        assert!(crate::metrics::observe::admits_cardinality(
            PLANE,
            &format!("s_{i}_total"),
            0
        ));
    }
    // ...and the HOT lane's entry point sees the same exhausted budget, because it is the same one.
    assert!(!crate::metrics::observe::admits_cardinality_opaque(
        PLANE,
        "one_more_total",
        &[]
    ));
    // An established series still passes on either entry point.
    assert!(crate::metrics::observe::admits_cardinality_opaque(
        PLANE,
        "s_0_total",
        &[]
    ));
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
            assert!(!ctx.is_null(), "a live HostCtx is minted");
            assert!(
                HostGeneration::is_live(ctx.generation()),
                "the minting dispatch's generation is live for the duration of `with_host`"
            );
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
        let state: &HostState = unsafe { recover(host) }
            .expect("host generation still live inside with_dispatch_scope");
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

// ── A6 use-after-free hardening: a STALE `HostCtx` (its minting dispatch has ended, so its
// `HostGeneration` is no longer live) must be REFUSED at the recovery site, never dereferenced. ──

/// `recover` refuses a `HostCtx` copied out of a dispatch that has already ended — the exact A6
/// shape: a plane that stashed the handle and replayed it after the `HostState` it addressed went
/// out of scope. Before the generation guard, `recover` had no way to detect this and would hand back
/// a dangling `&HostState`; now the generation check catches it BEFORE the pointer is ever read.
#[test]
fn stale_host_ctx_is_refused_not_dereferenced() {
    let app = crate::test_support::TestApp::new().build();
    // `HostCtx` is `Copy`; copy it out of the dispatch that minted it. When `with_dispatch_scope`
    // returns, its `HostGeneration` token has already dropped and popped off this thread's live set.
    let stale_host = with_dispatch_scope(&app, |host, _vt| host);
    assert!(
        !HostGeneration::is_live(stale_host.generation()),
        "the minting dispatch has ended; its generation must no longer be live"
    );
    // SAFETY: `recover` checks the generation BEFORE dereferencing; a stale handle is refused, never
    // read — so calling it here with an ended dispatch's handle is not itself unsound.
    let recovered = unsafe { recover(stale_host) };
    assert!(
        recovered.is_none(),
        "a stale HostCtx (generation no longer live) must be refused, never dereferenced"
    );
}

/// The end-to-end ABI shape of the same guard: a real vtable slot (`clock_now`) handed a stale
/// `HostCtx` fails closed to its documented sentinel (`0`) rather than reading freed stack memory —
/// proving the guard is live on the actual dispatch path a plane calls, not just at the `recover` unit.
#[test]
fn stale_host_ctx_through_a_real_vtable_slot_fails_closed() {
    let app = crate::test_support::TestApp::new().build();
    let stale_host = with_dispatch_scope(&app, |host, _vt| host);
    assert!(!HostGeneration::is_live(stale_host.generation()));
    // A freshly built vtable (not the one the ended dispatch minted) so this call exercises only
    // the stale `HostCtx`, never a stale vtable reference.
    let vt = build_plane_host_vtable();
    let now = (vt.clock_now.unwrap())(stale_host);
    assert_eq!(
        now, 0,
        "a stale handle reads the fail-closed clock, never a dereference"
    );
}

/// THE REACHABILITY PIN for the invoke-family rewrite commit rule, stated at core's own function.
///
/// `apply_rewrite_to_invoke_args` is where a `prompt: rw` hook's reply becomes the `arguments` a
/// plane is handed back, and `transform_over_over` re-serialises that value with `serde_json::to_vec`.
/// Two facts about it decide whether a plane's apply site has a live hole or a dormant one, and both
/// are asserted here rather than read off the source by a plane's own test:
///
/// 1. It admits ANY JSON object as the replacement. It does not know, and cannot check, the TYPE the
///    receiving plane will decode into. For MCP and A2A the target is `serde_json::Value`, so bytes
///    core commits always parse and their "output I cannot read back" arms are unreachable through
///    this host. For `busbar-voice` the target is `SessionConfig`, which rejects `{"voice": 7}` as a
///    type mismatch — so THAT plane's arm is genuinely reachable through core's real host, and its
///    refusal (`busbar_voice::mount::committed_session_config`) is a live fix, not a dormant one.
/// 2. The commit is a WHOLESALE REPLACEMENT, not a merge. A hook that names one field produces
///    `arguments` carrying ONLY that field — every other key the caller (or the plane's own lock)
///    had is gone from the committed bytes. A plane whose target type defaults its absent fields
///    therefore silently blanks its own locked values unless it merges, which is the second half of
///    the voice rule.
#[test]
fn a_committed_invoke_rewrite_installs_any_json_object_verbatim() {
    // The arguments as the plane handed them to the seam: a locked field the hook never names, plus
    // the one it does. `persona` stands in for any string-typed field of a plane's typed config
    // (the doc above names the concrete one); core never learns which plane's type it is.
    let mut args = serde_json::json!({ "instructions": "locked by the plane", "persona": "alloy" });
    let rw = busbar_contract::hooks::RewriteReply {
        messages: vec![serde_json::json!({ "role": "user", "content": { "persona": 7 } })],
        tools: Vec::new(),
    };
    assert!(
        apply_rewrite_to_invoke_args(&mut args, &rw),
        "core COMMITS this rewrite (`applied: true`): the reply carries a JSON object, which is the \
         only thing this fn checks. It never consults the receiving plane's type."
    );
    assert_eq!(
        String::from_utf8(serde_json::to_vec(&args).expect("a Value always serializes"))
            .expect("json is utf-8"),
        r#"{"persona":7}"#,
        "these are the bytes `transform_over_over` hands back. (1) They are not a valid typed \
         config whose `persona` is a string — so a plane decoding into a typed \
         config CAN be handed a committed rewrite it cannot read. (2) `instructions` is GONE: the \
         commit replaced the arguments wholesale rather than patching the one named field."
    );
}

/// THE HOST RE-ASK READS THE BINDINGS IN FORCE NOW. `role_bindings` is per-snapshot (rebuilt from
/// the applied config on every apply), so a host that re-checked against the snapshot it was minted
/// on would keep a role-bound subscription alive after its binding was removed. Stands before the
/// swap (the binding is there), lapses after it (the binding is gone).
///
/// RED at HEAD: the re-ask re-resolved the synthesized key by id against the registry, so the FIRST
/// ask already lapsed — the "stands" half fails.
#[test]
fn a_role_bound_standing_is_rechecked_against_the_live_snapshot_bindings() {
    use crate::trust::validate::{Lapsed, Refusal, Snapshot, Standing};
    let mut roles = std::collections::BTreeMap::new();
    roles.insert("eng".to_string(), crate::config::RoleBindingCfg::default());
    let mut rb = crate::config::RoleBindings::new();
    rb.insert("idp".to_string(), roles);
    let principal = crate::auth::Principal {
        id: "alice@example.com".to_string(),
        name: None,
        roles: vec!["eng".to_string()],
        ttl_secs: None,
    };
    let key = crate::governance::synthesize_bound_key("idp", &principal, &rb).expect("bound");
    let handle = Arc::new(crate::state::AppHandle::new(
        crate::test_support::TestApp::new()
            .role_bindings(rb)
            .build(),
    ));
    let host = EngineHostImpl::from_handle(Arc::clone(&handle));
    let standing = Standing::opened(
        Some(&key),
        Snapshot::Watching,
        std::time::Duration::from_secs(300),
    );

    let now = host
        .principal_standing(&standing, 1, 1_700_000_000)
        .expect("the binding stands")
        .expect("governed");
    assert_eq!(now.id, "alice@example.com");

    // A config apply that removes the binding swaps in a snapshot without it.
    handle.swap(crate::test_support::TestApp::new().build());
    assert_eq!(
        host.principal_standing(&standing, 1, 1_700_000_000),
        Err(Lapsed::Identity(Refusal::IdentityNotLive {
            principal: "alice@example.com".to_string()
        }))
    );
}

/// The hook accesses the node journal holds under one ingress label, oldest first. The journal is
/// process-wide, so each test below uses a label no other test uses.
fn hook_accesses_under(op: &str) -> Vec<crate::audit::amend::Access> {
    crate::audit::amend::node_recent()
        .into_iter()
        .filter_map(|a| match a.body {
            crate::audit::amend::AmendBody::Access(x) if x.op_class.as_str() == op => Some(x),
            _ => None,
        })
        .collect()
}

/// A rewrite hook that abstains: only what it was handed matters.
struct AbstainingRewrite;

#[async_trait::async_trait]
impl crate::hooks::RoutingPolicy for AbstainingRewrite {
    async fn decide(
        &self,
        _req: &busbar_contract::hooks::RoutingRequest<'_>,
        _candidates: &[busbar_contract::hooks::Candidate<'_>],
        _ctx: &busbar_contract::hooks::RoutingContext<'_>,
        _budget: std::time::Duration,
    ) -> busbar_contract::hooks::PolicyResult {
        Ok(busbar_contract::hooks::RoutingDecision::Abstain)
    }
    fn name(&self) -> &'static str {
        "abstaining-rewrite"
    }
}

/// THE REWRITE LEG EVERY NON-LLM PLANE FIRES (`host.transform_over`, reached by the tool, agent and
/// session planes alike) hands the hook the call's arguments, and leaves exactly one access
/// amendment naming the hook — the same record the gate seam leaves.
#[test]
fn the_plane_rewrite_leg_leaves_one_access_amendment_per_hook_handed_the_arguments() {
    const PLANE: &str = "access-rewrite-leg";
    let mut app = crate::test_support::TestApp::new().build();
    let mut containers = crate::state::ContainerRewriteMap::new();
    containers.insert(
        "c".to_string(),
        vec![(
            std::time::Duration::from_millis(500),
            Arc::new(AbstainingRewrite) as Arc<dyn crate::hooks::RoutingPolicy>,
        )],
    );
    Arc::get_mut(&mut app)
        .expect("sole owner")
        .plane_rewrites
        .insert(PLANE, containers);
    let verdict = transform_over_over(&app, PLANE, "c", 1, "tool", br#"{"path":"/x"}"#);
    assert!(matches!(verdict, TransformVerdict::Proceed { .. }));
    let seen = hook_accesses_under(PLANE);
    assert_eq!(seen.len(), 1, "one access per hand-over: {seen:?}");
    assert_eq!(seen[0].name, "abstaining-rewrite");
}

/// THE PORT A PLANE'S OWN HOOK CALL SITES RECORD THROUGH: the host's provided `hook_read` seals the
/// access on the node journal, naming the hook, the caller and the fields that crossed.
#[test]
fn the_host_hook_read_port_seals_one_access_amendment_on_the_node_journal() {
    const OP: &str = "access-host-port";
    let app = crate::test_support::TestApp::new().build();
    let host = crate::test_support::engine_host(&app);
    host.hook_read("port-hook", Some("key-1"), OP, true);
    let seen = hook_accesses_under(OP);
    assert_eq!(seen.len(), 1, "{seen:?}");
    assert_eq!(seen[0].name, "port-hook");
    assert_eq!(
        seen[0].subject,
        crate::audit::amend::Subject::PrincipalId("key-1".to_string())
    );
    assert_eq!(
        seen[0].fields,
        vec!["content".to_string(), "identity".to_string()]
    );
}

// ── `counter_add` (minor 25): a plane adds only to a family it DECLARED ────────────────────────

/// The families [`COUNTING_PLANE`] declares.
const COUNTING_FAMILIES: &[busbar_contract::plane::MetricFamily] = &[
    busbar_contract::plane::MetricFamily {
        name: "counting_plane_units_total",
        kind: busbar_contract::plane::COUNTER,
        label_keys: &["unit", "outcome"],
    },
    busbar_contract::plane::MetricFamily {
        name: "counting_plane_bare_total",
        kind: busbar_contract::plane::COUNTER,
        label_keys: &[],
    },
];

/// A neutral plane declaring [`COUNTING_FAMILIES`].
static COUNTING_PLANE: crate::plane::registry::PlaneDecl = crate::plane::registry::PlaneDecl {
    declaration: crate::plane::registry::PlaneDeclaration {
        key: "counting-plane",
        fallback: false,
        config_section: "counting",
        metric_families: COUNTING_FAMILIES,
        ..crate::test_support::NEUTRAL_FALLBACK.declaration
    },
    ..crate::test_support::NEUTRAL_FALLBACK
};

/// Borrowed label values, as a plane hands them.
fn values(v: &[&'static str]) -> Vec<busbar_plugin::hot::DeclStr> {
    v.iter()
        .map(|s| busbar_plugin::hot::DeclStr::new(s))
        .collect()
}

/// Add through the slot under `plane`'s attribution, with `COUNTING_PLANE` registered.
fn add(
    plane: &'static str,
    family: &str,
    v: &[busbar_plugin::hot::DeclStr],
    delta: u64,
) -> StatusClass {
    let _registry = crate::plane::registry::TestRegistryIsolation::seeded(&[&COUNTING_PLANE]);
    with_test_state_as(plane, |host, vt, _| {
        (vt.counter_add.unwrap())(
            host,
            family.as_ptr(),
            family.len(),
            v.as_ptr(),
            v.len(),
            delta,
        )
    })
}

/// A declared family renders exactly its declared name and keys — no provenance label — and adds.
#[test]
fn counter_add_renders_a_declared_family_as_declared() {
    crate::metrics::init();
    let v = values(&["widget", "ok"]);
    assert_eq!(
        add("counting-plane", "counting_plane_units_total", &v, 3),
        StatusClass::Ok
    );
    assert_eq!(
        add("counting-plane", "counting_plane_units_total", &v, 2),
        StatusClass::Ok
    );
    assert_eq!(
        add("counting-plane", "counting_plane_bare_total", &[], 1),
        StatusClass::Ok
    );
    let scrape = crate::metrics::render();
    for line in [
        "counting_plane_units_total{unit=\"widget\",outcome=\"ok\"} 5",
        "counting_plane_bare_total 1",
    ] {
        assert!(
            scrape.lines().any(|l| l == line),
            "{line} not in:\n{scrape}"
        );
    }
}

/// RED ARMS: what the plane did not declare, and what it declared but supplied wrongly, is refused;
/// so is a handle the host attributes to no plane, or to a plane that declared nothing.
#[test]
fn counter_add_refuses_what_the_plane_did_not_declare() {
    let two = values(&["widget", "ok"]);
    let long: &'static str = Box::leak("x".repeat(65).into_boxed_str());
    let bad_utf8: &'static [u8] = &[0xff, 0xfe];
    let not_utf8 = [
        busbar_plugin::hot::DeclStr {
            ptr: bad_utf8.as_ptr(),
            len: 2,
        },
        two[1],
    ];
    for (plane, family, v) in [
        ("counting-plane", "counting_plane_other_total", &two[..]),
        ("counting-plane", "busbar_minted_total", &two[..]),
        ("counting-plane", "counting_plane_units_total", &two[..1]),
        (
            "counting-plane",
            "counting_plane_units_total",
            &values(&[long, "ok"])[..],
        ),
        (
            "counting-plane",
            "counting_plane_units_total",
            &not_utf8[..],
        ),
        (
            "counting-plane",
            "counting_plane_units_total",
            &[busbar_plugin::hot::DeclStr::NONE, two[1]][..],
        ),
        ("undeclaring-plane", "counting_plane_units_total", &two[..]),
    ] {
        assert_eq!(
            add(plane, family, v, 1),
            StatusClass::Refused,
            "{plane} {family}"
        );
    }
    let _registry = crate::plane::registry::TestRegistryIsolation::seeded(&[&COUNTING_PLANE]);
    with_test_state(|host, vt, _| {
        let f = "counting_plane_bare_total";
        let unattributed =
            (vt.counter_add.unwrap())(host, f.as_ptr(), f.len(), core::ptr::null(), 0, 1);
        assert_eq!(unattributed, StatusClass::Refused);
    });
}
