// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/plane/dispatch_scope.rs`.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// A test RAII guard whose `Drop` bumps a shared counter — stands in for the real admission guard.
struct DropCounter(Arc<AtomicUsize>);
impl Drop for DropCounter {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn arena_reclaims_a_registered_guard_on_drop() {
    let reclaimed = Arc::new(AtomicUsize::new(0));
    {
        let scope = DispatchScope::new();
        let id = scope.register_admission(Box::new(DropCounter(reclaimed.clone())));
        assert_eq!(id, AdmissionId(1));
        assert_eq!(scope.registered(), 1);
        // Not yet reclaimed while the scope is live.
        assert_eq!(reclaimed.load(Ordering::SeqCst), 0);
    }
    // Scope dropped: the real guard `Drop` ran.
    assert_eq!(reclaimed.load(Ordering::SeqCst), 1);
}

#[test]
fn arena_reclaims_every_kind_and_runs_closers() {
    let count = Arc::new(AtomicUsize::new(0));
    let scope = DispatchScope::new();
    let c = count.clone();
    scope.register_admission(Box::new(DropCounter(count.clone())));
    let cc = c.clone();
    scope.register_egress(Box::new(move || {
        cc.fetch_add(1, Ordering::SeqCst);
    }));
    let ccc = c.clone();
    scope.register_pipe(Box::new(move || {
        ccc.fetch_add(1, Ordering::SeqCst);
    }));
    let cccc = c.clone();
    scope.register_lease(Box::new(move || {
        cccc.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(scope.registered(), 4);
    // Explicit reclaim (the abort-path hardening assertion): synchronous, reclaims all four.
    scope.reclaim_all();
    assert_eq!(count.load(Ordering::SeqCst), 4);
    assert_eq!(scope.registered(), 0);
    // Idempotent: a second reclaim (e.g. the Drop after an explicit reclaim) is a no-op.
    scope.reclaim_all();
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

/// One closer that panics must not take the rest of the arena with it: the entries around it still
/// reclaim, and the panic does not escape a call that `Drop` also makes (escaping there, mid-unwind,
/// aborts the process rather than leaking).
#[test]
fn a_panicking_closer_does_not_strand_the_other_handles() {
    let count = Arc::new(AtomicUsize::new(0));
    let reclaimed = Arc::new(AtomicUsize::new(0));
    let scope = DispatchScope::new();

    // Registered first, reclaimed LAST (LIFO) — it is the one a panic ahead of it would strand.
    scope.register_admission(Box::new(DropCounter(reclaimed.clone())));
    let c = count.clone();
    scope.register_egress(Box::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    }));
    scope.register_pipe(Box::new(|| {
        panic!("a closer that kills a subprocess went wrong")
    }));
    let c = count.clone();
    scope.register_lease(Box::new(move || {
        c.fetch_add(1, Ordering::SeqCst);
    }));
    assert_eq!(scope.registered(), 4);

    // The panic is contained: `reclaim_all` returns rather than unwinding into its caller.
    let quiet = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    scope.reclaim_all();
    std::panic::set_hook(quiet);

    assert_eq!(
        count.load(Ordering::SeqCst),
        2,
        "the closers on both sides of the panicking one still ran"
    );
    assert_eq!(
        reclaimed.load(Ordering::SeqCst),
        1,
        "the guard behind the panicking closer was not stranded"
    );
    assert_eq!(scope.registered(), 0, "the arena is empty either way");
}

#[test]
fn handle_ids_are_nonzero_and_monotonic() {
    let scope = DispatchScope::new();
    let a = scope.register_egress(Box::new(|| {}));
    let b = scope.register_egress(Box::new(|| {}));
    assert!(!a.is_none());
    assert_eq!(a, EgressId(1));
    assert_eq!(b, EgressId(2));
}
