// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_host` — the HOST side of the plane ABI: the construction point + lifecycle arena the
//! capability fan-out fills in.
//!
//! The HOT-lane ABI ([`busbar_plugin::hot`]) defines the `#[repr(C)] PlaneHostVtable` — the inbound
//! seam a plane calls BACK into core (`govern_admit`, `meter_charge`, `egress_open`, `clock_now`, …).
//! This module is core's HOST-SIDE implementation of that seam: it builds the vtable, recovers core's
//! own state from the opaque [`HostCtx`] the ABI threads through every call, and owns the per-dispatch
//! [`DispatchScope`] arena that reclaims every host handle a plane acquired when the dispatch ends.
//!
//! ADDITIVE and UNUSED: nothing in the engine calls the plane seam yet. Phase 2 wires the in-place
//! plane calls against [`with_dispatch_scope`]. After the Phase-1 capability fan-out (breaker,
//! govern, trust, journal, egress, dispatch) EVERY vtable slot is wired over a real primitive — no
//! `unimplemented!()` stub remains (see [`vtable`]). The shipped in-process `plane::host` seam is
//! untouched.
//!
//! ## The three pieces
//!
//! * [`HostState`] + [`recover`] — the `HostCtx` recovery invariant. The ABI hands every host call an
//!   opaque `HostCtx` (a `*mut c_void`); core recovers its [`HostState`] (the live `App` + the active
//!   [`DispatchScope`]) from it.
//! * [`scope`] — the [`DispatchScope`] arena (the §4 leak keystone) plus the [`SessionScope`] /
//!   [`DurableScope`] stubs.
//! * [`vtable`] — [`build_plane_host_vtable`]; every slot wired (three proof-of-life fns here, the
//!   rest forwarding into the capability modules), zero stubs remaining.

pub mod breaker;
pub mod dispatch;
pub mod egress;
mod govern;
pub mod journal;
pub mod scope;
pub mod trust;
pub mod vtable;

pub use scope::{DispatchScope, DurableScope, SessionScope};
pub use vtable::build_plane_host_vtable;

use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use crate::state::App;
use std::sync::Arc;

/// Core's own state behind the opaque [`HostCtx`] the plane ABI threads through every host call. A
/// plane never dereferences the `HostCtx`; it passes it back, and core recovers THIS via [`recover`].
///
/// Holds the live [`App`] (the config generation the dispatch was admitted on) and the per-invocation
/// [`DispatchScope`] arena. Borrowed, not owned: a `HostState` lives on the stack of the core frame
/// that opened the dispatch (see [`with_dispatch_scope`]) and outlives every host call made during it.
pub struct HostState<'a> {
    /// The live engine snapshot backing the host calls (governance, metrics, egress, … primitives).
    pub app: &'a App,
    /// The per-dispatch-invocation arena; every acquired host handle registers here and is reclaimed
    /// when this `HostState`'s owning scope drops.
    pub scope: &'a DispatchScope,
}

/// Recover core's [`HostState`] from the opaque [`HostCtx`] the plane handed back.
///
/// # Invariant
///
/// The host ALWAYS passes, as the `HostCtx` of every vtable call, exactly a `*const HostState` that is
/// LIVE for the entire dispatch duration — it is [`with_dispatch_scope`] that mints the `HostCtx` from
/// a stack `HostState` and keeps that `HostState` alive across the whole `f(host, &vtable)` call. The
/// plane never fabricates, mutates, or outlives the pointer (it only stores and returns it). Under that
/// invariant this is sound: the pointer is non-null, aligned, and points at a live `HostState` for a
/// lifetime the caller's frame bounds.
///
/// # Safety
///
/// `host` MUST be a `HostCtx` produced by [`with_dispatch_scope`] for a dispatch that is still on the
/// stack, per the invariant above. Calling with any other pointer is undefined behavior.
#[must_use]
pub unsafe fn recover<'a>(host: HostCtx) -> &'a HostState<'a> {
    debug_assert!(!host.is_null(), "HostCtx must never be null in a live call");
    // SAFETY: by the documented invariant `host` is a live `*const HostState` for the call's duration.
    unsafe { &*(host as *const HostState<'a>) }
}

/// Open a [`DispatchScope`], build the host vtable, and hand a plane a [`HostCtx`] + `&PlaneHostVtable`
/// for the duration of `f` — reclaiming every registered host handle when the scope ends. This is the
/// seam the in-place plane will dogfood in Phase 2 (it is ADDITIVE — nothing calls it yet).
///
/// The `HostState` is built on this frame's stack and its address becomes the `HostCtx`; it stays live
/// for the whole `f` call, satisfying [`recover`]'s invariant. When `f` returns (or unwinds), the
/// `DispatchScope` drops and [`DispatchScope::reclaim_all`] runs — so a dropped/cancelled dispatch
/// future never leaks a bare host handle (the HalfOpen-wedge bug).
pub fn with_dispatch_scope<R>(
    app: &App,
    f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R,
) -> R {
    // Delegated to the owned [`HostDispatch`] guard so the SYNC seam and the ASYNC seam mint the exact
    // same `HostCtx` from the exact same stack-pinned `HostState` — one recovery invariant, two entry
    // shapes. `HostDispatch::new` allocates nothing (an empty `DispatchScope`), and the arena reclaim
    // still fires when the guard drops at the end of this call.
    HostDispatch::new(app).with_host(f)
}

/// The ASYNC-CAPABLE dispatch guard: an OWNED RAII handle a core `async` dispatch fn creates at the top
/// of its body and holds as a LOCAL across every `.await`, so the [`DispatchScope`] arena lives for the
/// whole future and reclaims on ANY exit — normal return, client-disconnect cancel, or panic. This is
/// the fix for the sync-only [`with_dispatch_scope`]: an `async move {}` passed to the closure form
/// would make `R` the future and drop the scope BEFORE it was awaited; an owned guard held on the async
/// stack frame closes that hole (the §4 HalfOpen-wedge fix on the real `async` dispatch paths).
///
/// Zero-alloc on the fast lane: it BORROWS the live [`App`] and STACK-PINS its own [`DispatchScope`]
/// (no heap until a handle is actually registered), so holding one across awaits costs no per-dispatch
/// allocation — only the LLM-alloc-sensitive budget's price of a couple of pointers on the frame.
///
/// The raw [`HostCtx`] pointer is `!Send` (it aliases this stack `HostState`), so it is materialized
/// ONLY inside the synchronous [`with_host`](Self::with_host) / [`host_ctx`](Self::host_ctx) runs and
/// MUST NOT be held across an `.await` — the guard itself is `Send` (it holds only `&App` + the arena),
/// so the enclosing future stays `Send`. For a `Send + 'static` route into `spawn_blocking`, take a
/// [`SendHostDispatch`] on that branch instead.
pub struct HostDispatch<'a> {
    app: &'a App,
    scope: DispatchScope,
}

impl<'a> HostDispatch<'a> {
    /// Open an async dispatch guard over the live `app`. Allocates nothing (an empty arena).
    #[must_use]
    pub fn new(app: &'a App) -> Self {
        HostDispatch {
            app,
            scope: DispatchScope::new(),
        }
    }

    /// The per-dispatch arena. Every host handle a plane acquires during this dispatch registers here
    /// and is reclaimed when this guard drops.
    #[must_use]
    pub fn scope(&self) -> &DispatchScope {
        &self.scope
    }

    /// The live engine snapshot this dispatch was admitted on.
    #[must_use]
    pub fn app(&self) -> &App {
        self.app
    }

    /// Borrow a [`HostState`] over this guard's `app` + arena. The raw `HostCtx` materialized from it
    /// (see [`with_host`](Self::with_host)) is `!Send` and valid only while the returned borrow lives.
    #[must_use]
    pub fn host_state(&self) -> HostState<'_> {
        HostState {
            app: self.app,
            scope: &self.scope,
        }
    }

    /// Run `f` SYNCHRONOUSLY with a materialized [`HostCtx`] + the host `&PlaneHostVtable` — the
    /// between-awaits seam a plane call rides. The `HostState` backing the `HostCtx` is stack-pinned
    /// for exactly the duration of `f` (the [`recover`] invariant); the pointer must not escape it.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let state = self.host_state();
        let vtable = build_plane_host_vtable();
        // The stack `HostState`'s address IS the opaque HostCtx; it outlives every call `f` makes.
        let host: HostCtx = (&state as *const HostState).cast_mut().cast::<std::os::raw::c_void>();
        let out = f(host, &vtable);
        let _keep_alive = &state;
        out
    }
}

/// A `Send + 'static` route to a host for the `spawn_blocking` breaker paths (a2a relay admit/settle
/// run on a blocking thread; see `a2a::receive::{unary_hop,stream_hop}`). Unlike [`HostDispatch`] it
/// OWNS its inputs — an `Arc<App>` (Send + Sync) and its own [`DispatchScope`] — so the whole guard can
/// be MOVED into the `spawn_blocking` closure, which materializes the raw `HostCtx` INSIDE the closure
/// (where the blocking body actually calls the vtable) and never carries the `!Send` pointer across the
/// task boundary. The arena reclaims when the closure ends and the guard drops (reclaim at HOP end).
///
/// Hot-path note: this is taken ONLY on the `spawn_blocking` branch, never on the sync LLM fast lane —
/// it is one `Arc<App>` refcount bump (~ns) and a stack-moved guard, no heap arena until a handle is
/// registered. Do NOT reach for it on the fast path; use the borrowing [`HostDispatch`] there.
pub struct SendHostDispatch {
    app: Arc<App>,
    scope: DispatchScope,
}

impl SendHostDispatch {
    /// Open a Send host guard owning `app`. Allocates nothing beyond the caller's existing `Arc` bump.
    #[must_use]
    pub fn new(app: Arc<App>) -> Self {
        SendHostDispatch {
            app,
            scope: DispatchScope::new(),
        }
    }

    /// The per-hop arena (reclaimed when this guard drops at the end of the blocking closure).
    #[must_use]
    pub fn scope(&self) -> &DispatchScope {
        &self.scope
    }

    /// The live engine snapshot the hop was admitted on.
    #[must_use]
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Borrow a [`HostState`] over the owned `app` + arena — the materialization seam, called INSIDE
    /// the blocking closure so the raw `HostCtx` never crosses the `spawn_blocking` boundary.
    #[must_use]
    pub fn host_state(&self) -> HostState<'_> {
        HostState {
            app: &self.app,
            scope: &self.scope,
        }
    }

    /// Run `f` synchronously with a materialized [`HostCtx`] + host vtable, INSIDE the blocking body.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let state = self.host_state();
        let vtable = build_plane_host_vtable();
        let host: HostCtx = (&state as *const HostState).cast_mut().cast::<std::os::raw::c_void>();
        let out = f(host, &vtable);
        let _keep_alive = &state;
        out
    }
}

/// A `Send + 'static` route to a host whose lifecycle arena is a [`DurableScope`] the DETACHED runner
/// owns — the create_task settle path (`mcp::tasks::Runner`). Unlike [`SendHostDispatch`] its arena is
/// NOT reclaimed at request-future drop: the breaker probe-hold `into_task_dispatch` handed off rides
/// here and releases only when THIS guard drops WITH the runner (normal end OR a `tasks/cancel` abort),
/// the v4-arena-bug guard. A `HostState` materialized over `durable.arena()` drives the exact same host
/// `breaker_settle` seam the per-request path does, so the runner's detached leg can settle the durable
/// admission through the vtable with no change to the breaker path.
///
/// ADDITIVE and UNUSED by the breaker inversion: the guard is REACHABLE at the durable site (the runner
/// carries one), but `tasks::run` does not yet call settle — the durable scope's drop still reclaims the
/// probe, exactly as before. Phase-2 CLUSTER-1 flips the detached leg to `settle` through this route.
pub struct DurableHostDispatch {
    app: Arc<App>,
    /// The durable arena holding the handed-off breaker probe-hold; drops (and reclaims) with the guard.
    durable: DurableScope,
    /// The durable admission's id — what the detached leg settles by. [`AdmissionId::NONE`] when no
    /// settling admission was handed off (a degenerate route that won nothing to re-home).
    admission: busbar_plugin::hot::AdmissionId,
}

impl DurableHostDispatch {
    /// Open a durable host route owning `app` and the runner's `durable` scope, keyed by the durable
    /// `admission` id the detached leg settles.
    #[must_use]
    pub fn new(
        app: Arc<App>,
        durable: DurableScope,
        admission: busbar_plugin::hot::AdmissionId,
    ) -> Self {
        DurableHostDispatch {
            app,
            durable,
            admission,
        }
    }

    /// The durable admission id the detached leg settles (or [`AdmissionId::NONE`]).
    #[must_use]
    pub fn admission(&self) -> busbar_plugin::hot::AdmissionId {
        self.admission
    }

    /// The durable arena (reclaimed with this guard at task end).
    #[must_use]
    pub fn durable(&self) -> &DurableScope {
        &self.durable
    }

    /// The live engine snapshot the task was admitted on.
    #[must_use]
    pub fn app(&self) -> &App {
        &self.app
    }

    /// Borrow a [`HostState`] over the owned `app` + the DURABLE arena — the materialization seam the
    /// detached leg calls to reach `breaker_settle` for the durable admission.
    #[must_use]
    pub fn host_state(&self) -> HostState<'_> {
        HostState {
            app: &self.app,
            scope: self.durable.arena(),
        }
    }

    /// Run `f` synchronously with a materialized [`HostCtx`] + host vtable over the durable arena.
    pub fn with_host<R>(&self, f: impl FnOnce(HostCtx, &PlaneHostVtable) -> R) -> R {
        let state = self.host_state();
        let vtable = build_plane_host_vtable();
        let host: HostCtx = (&state as *const HostState).cast_mut().cast::<std::os::raw::c_void>();
        let out = f(host, &vtable);
        let _keep_alive = &state;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin::hot::{
        AdmissionId, AuthQuery, AuthResolved, Decision, Facts, MeterOutcome, MetricSample,
        StatusClass, Usage, UsageComponent, POD_VERSION,
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
    }

    #[test]
    fn wired_clock_now_returns_a_nonzero_nanos_clock() {
        with_test_state(|host, vt, _scope| {
            let now = (vt.clock_now.unwrap())(host);
            assert!(now > 0, "host clock must be a live nonzero nanosecond reading");
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
            assert_eq!(scope.registered(), 0, "reclaim releases the registered grant");
        });
    }

    /// With governance ENABLED, `govern_admit` drives the real `GovState::try_admit` limit engine and
    /// still registers the RAII grant it returns. Exercises the delegation over a live `GovState`.
    #[test]
    fn wired_govern_admit_drives_the_real_limit_engine() {
        let gov = Arc::new(
            crate::governance::GovState::new(
                Arc::new(crate::governance::MemoryStore::new()),
                None,
            )
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
                (vt.auth_resolve.unwrap())(host, &query as *const AuthQuery, &mut out as *mut MaybeUninit<AuthResolved>),
                StatusClass::Ok
            );
            // SAFETY: the Ok status published the slot (init-only-on-Ok).
            let resolved = unsafe { out.assume_init() };
            assert_eq!(resolved.resolved_ref, 0x9abc, "host-side ref resolved");
            assert!(resolved.expires_unix > 0, "a bounded expiry is stamped");

            // A query naming no credential is refused; the out-slot is NOT written.
            let none = AuthQuery {
                credential_ref: 0,
                ..query
            };
            let mut out2 = MaybeUninit::<AuthResolved>::uninit();
            assert_eq!(
                (vt.auth_resolve.unwrap())(host, &none as *const AuthQuery, &mut out2 as *mut MaybeUninit<AuthResolved>),
                StatusClass::Refused
            );
            // Fail-closed on a null query.
            assert_eq!(
                (vt.auth_resolve.unwrap())(host, core::ptr::null(), &mut out2 as *mut MaybeUninit<AuthResolved>),
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
            assert_eq!(reclaimed.load(Ordering::SeqCst), 0, "held across await, not reclaimed");
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
        assert_eq!(reclaimed.load(Ordering::SeqCst), 1, "the hop arena reclaimed at closure end");
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
}
