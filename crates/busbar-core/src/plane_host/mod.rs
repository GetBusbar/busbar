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
//! plane calls against [`with_dispatch_scope`]; the fan-out fills the stubbed vtable slots (see
//! [`vtable`]). The DISPATCH family — `nested_dispatch`, `workhandle_open`/`_resume`,
//! `entitlement_check`, `gate_scan` — is already wired over real primitives in [`dispatch`]. The
//! shipped in-process `plane::host` seam is untouched.
//!
//! ## The three pieces
//!
//! * [`HostState`] + [`recover`] — the `HostCtx` recovery invariant. The ABI hands every host call an
//!   opaque `HostCtx` (a `*mut c_void`); core recovers its [`HostState`] (the live `App` + the active
//!   [`DispatchScope`]) from it.
//! * [`scope`] — the [`DispatchScope`] arena (the §4 leak keystone) plus the [`SessionScope`] /
//!   [`DurableScope`] stubs.
//! * [`vtable`] — [`build_plane_host_vtable`], three wired proof-of-life slots, nineteen typed stubs.

pub mod dispatch;
pub mod scope;
pub mod vtable;

pub use scope::{DispatchScope, DurableScope, SessionScope};
pub use vtable::build_plane_host_vtable;

use busbar_plugin::hot::host::{HostCtx, PlaneHostVtable};
use crate::state::App;

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
    let scope = DispatchScope::new();
    let state = HostState { app, scope: &scope };
    let vtable = build_plane_host_vtable();
    // The stack `HostState`'s address IS the opaque HostCtx; it outlives every call `f` makes.
    let host: HostCtx = (&state as *const HostState).cast_mut().cast::<std::os::raw::c_void>();
    // `state` lives on this frame's stack until the function returns, so the `HostCtx` above stays
    // valid for every host call `f` makes (the `recover` invariant). `HostState` has no `Drop`, so
    // there is nothing to reclaim for it; the arena reclaim happens when `scope` drops below.
    let out = f(host, &vtable);
    let _keep_alive = &state;
    out
    // `scope` drops here → reclaim_all().
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin::hot::{Decision, Facts, MetricSample, StatusClass};
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
        // Every slot is populated (3 wired + 19 stubbed): the fan-out has one hole each, not a `None`.
        assert!(vt.govern_admit.is_some());
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
