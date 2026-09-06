// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Operator-triggered restart: the seam that applies every restart-scoped setting without an SSH
//! session.
//!
//! `listen`, `admin_listen`, `tls`, `admin_tls`, `admin_require_mtls` and `store` are bound or
//! derived once at process start. They are not hot-appliable, and the reasons are load-bearing
//! rather than incidental: rebinding a socket can fail and leave a plane with no listener; rotating
//! `client_ca` live would not revoke, because TLS session resumption restores a client's identity
//! without re-consulting the verifier; and moving the store would leave every in-memory derivation
//! of the old one — flush baselines, key caches, the audit watermark — silently describing the new
//! one.
//!
//! A restart resolves all of that by construction, so busbar performs it rather than asking the
//! operator to. This is deliberately NOT an in-process rebuild: the durable audit's sequence
//! counters advance only via `fetch_max`, precisely so history cannot be rewound, and only a process
//! boundary resets them.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use tokio::sync::broadcast;

/// The process shutdown broadcaster, published by `main` once the channel exists.
static SHUTDOWN: OnceLock<broadcast::Sender<()>> = OnceLock::new();

/// Whether the drain is RELEASED BY THE EXIT PATH instead of by the handler that asked for it.
///
/// A composition that answers this operation directly writes the response the moment the handler
/// returns, so publishing inside the handler and publishing "once the answer exists" are the same
/// instant. A composition that walks the operation through the loop has steps still to run after
/// the handler answers, and a drain published inside the handler is therefore a side effect that
/// begins while the response is still travelling — which is visible on the wire, because a draining
/// server marks the connection closing on the way out. Such a composition arms this, and the drain
/// waits for the exit path that owns effects outliving the response.
static DRAIN_AT_EXIT: AtomicBool = AtomicBool::new(false);

/// The unit whose drain has been asked for and not yet released.
///
/// The ACT is process-wide — there is one process to drain — but the ASK belongs to one request, and
/// conflating the two is a live fault rather than a tidiness point. A single bit is released by the
/// tail of whichever administrative unit finishes next, so an unrelated request arriving between the
/// restart's handler and the restart's own exit path takes the ask away with it: the drain then
/// begins under a response that is not the restart's, and the shutdown races the 202 the restarting
/// caller is still waiting for. Keying the ask by the unit that made it means only that unit's exit
/// path can release it, whatever else is in flight beside it.
static DRAIN_ASKED: AtomicU64 = AtomicU64::new(NO_UNIT);

/// The key of no unit at all — the value the cell holds when nothing is asked.
///
/// Zero is safe as that marker because the loop's own keys begin at one, so no unit can ever be
/// mistaken for the absence of one.
const NO_UNIT: u64 = 0;

/// The unit an ask belongs to when the composition that made it names no unit.
///
/// A composition that answers the operation directly has no unit key to attribute with, and it also
/// has no second request that could steal the ask — so one reserved value is enough, and it is one
/// no loop-issued key can collide with.
pub const UNKEYED_UNIT: u64 = u64::MAX;

tokio::task_local! {
    /// The unit whose work is executing on this task.
    ///
    /// A task-local rather than a thread-local because the operation's body runs on a task the seam
    /// spawned, not on the blocking worker the loop walks on: a thread-local set by the walker would
    /// be invisible exactly where the handler that asks for the drain runs.
    static ASKING_UNIT: u64;
}

/// Run one unit's work with its key ambient, so a drain that work asks for is attributed to it.
///
/// The composition that walks operations through a loop wraps the body's execution in this. Nothing
/// else has to change: the handler still calls [`begin_drain`] knowing nothing about which
/// composition it is answering under, and the attribution is read from where it is running.
pub async fn as_unit<F>(unit: u64, f: F) -> F::Output
where
    F: std::future::Future,
{
    ASKING_UNIT.scope(unit, f).await
}

/// The unit whose work is running here, or the unkeyed marker outside any such scope.
fn asking_unit() -> u64 {
    ASKING_UNIT.try_with(|unit| *unit).unwrap_or(UNKEYED_UNIT)
}

pub fn publish_shutdown(tx: broadcast::Sender<()>) {
    let _ = SHUTDOWN.set(tx);
}

/// Declare that this composition releases the drain on its exit path.
///
/// Called once by the composition that owns such a path. Undeclared — every composition that
/// answers the operation directly — the drain publishes exactly where and when it always did.
pub fn drain_released_at_exit() {
    DRAIN_AT_EXIT.store(true, Ordering::Release);
}

/// Release a drain THIS unit asked for, if it asked for one.
///
/// Answers whether one fired. Called from the exit path, once the response is in hand and nothing
/// left to run can change it, so the drain begins where it would have begun without the steps in
/// between. A request that asked for no drain releases none, which is every request but one — and a
/// request that asked for none can no longer release one somebody else asked for, because the cell
/// is taken only by the unit named in it.
pub fn release_asked_drain(unit: u64) -> bool {
    if DRAIN_ASKED
        .compare_exchange(unit, NO_UNIT, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return false;
    }
    send_shutdown();
    true
}

/// Send on the channel a signal fires on, if `main` has published it.
fn send_shutdown() {
    if let Some(tx) = SHUTDOWN.get() {
        let _ = tx.send(());
    }
}

/// Whether this process can restart itself. Checked BEFORE the audit record so a refusal is never
/// written as an applied restart that then failed.
pub(crate) fn can_restart() -> bool {
    SHUTDOWN.get().is_some()
}

/// Begin the graceful drain, on the same channel a signal fires.
///
/// Where the composition releases drains at its exit path this records the ask and returns; the
/// drain is the same drain, published from the one place that runs after the answer is written.
/// Visible outside this crate because the ask and the release are two halves of ONE seam and a seam
/// with one half reachable is a seam nobody outside can prove. The release — the half that actually
/// stops a process — has always been public; the ask, which only records an intention this crate
/// still owns the meaning of, was not, so the composition that owns the exit path could describe its
/// obligation but never exercise it.
pub fn begin_drain() {
    if DRAIN_AT_EXIT.load(Ordering::Acquire) {
        DRAIN_ASKED.store(asking_unit(), Ordering::Release);
        return;
    }
    send_shutdown();
}

/// The environment markers a process supervisor is known to stamp. Single source of truth for both
/// `supervisor_detected` and its test — a marker added here is immediately covered by the test's own
/// literal-list assertion instead of needing a matching hand-edit in a re-implementation.
const SUPERVISOR_MARKERS: [&str; 2] = ["INVOCATION_ID", "KUBERNETES_SERVICE_HOST"];

// TEST-ONLY escape hatch for the real HTTP-level `POST /restart` driver
// (`drive_admin_error_surface`'s `restart_no_supervisor` case), which needs a deterministic
// unsupervised environment to reach the `NoSupervisor` 409 through the real handler -- process env
// vars are not a safe way to force that (a real, reproduced cross-test hazard: `INVOCATION_ID`/
// `KUBERNETES_SERVICE_HOST` are read by other tests sharing this binary, and CI runners were found
// to genuinely set `INVOCATION_ID` themselves, making the driver's original "confirmed true on this
// repo's CI runners" assumption false). A `thread_local` is safe here specifically because the
// tests that exercise this run on the DEFAULT (single-OS-thread) `#[tokio::test]` flavor, where the
// test body and the request it drives through the spawned server both execute on the same thread --
// unlike `set_var`, this is invisible to every other test's own OS thread.
// Only used by admin::tests, which itself requires `auth-admin-tokens` (see that module's own
// `mod tests;` gate) -- under --no-default-features, plain `cfg(test)` compiled these in with no
// caller, tripping -D dead-code.
#[cfg(all(test, feature = "auth-admin-tokens"))]
thread_local! {
    static FORCE_UNSUPERVISED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Scope-guard: forces `supervisor_detected()` to `false` for the duration of `f` on THIS thread
/// only, restoring the prior value afterward even if `f` panics.
#[cfg(all(test, feature = "auth-admin-tokens"))]
pub(crate) async fn with_forced_unsupervised<F, Fut, T>(f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let prior = FORCE_UNSUPERVISED.with(|c| c.replace(true));
    let result = f().await;
    FORCE_UNSUPERVISED.with(|c| c.set(prior));
    result
}

/// Whether a process supervisor will bring busbar back up.
///
/// Exiting is only a RESTART if something restarts it. systemd stamps `INVOCATION_ID` and Kubernetes
/// stamps `KUBERNETES_SERVICE_HOST`, but `docker run --restart` sets nothing, so absence is not proof
/// of absence — which is why an undetected supervisor asks for confirmation rather than refusing
/// outright.
pub(crate) fn supervisor_detected() -> bool {
    #[cfg(all(test, feature = "auth-admin-tokens"))]
    if FORCE_UNSUPERVISED.with(std::cell::Cell::get) {
        return false;
    }
    supervisor_detected_in(|k| std::env::var_os(k).is_some())
}

/// The decision, separated from the environment read. Testable by injecting a closure over a
/// fixture set — no environment mutation (which would race every other test reading the SAME two
/// vars in this shared-process test binary), no `unsafe`.
fn supervisor_detected_in(present: impl Fn(&str) -> bool) -> bool {
    SUPERVISOR_MARKERS.iter().any(|k| present(k))
}

#[cfg(test)]
#[path = "tests/restart.rs"]
mod tests;
