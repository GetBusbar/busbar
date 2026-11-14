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

use std::sync::OnceLock;
use tokio::sync::broadcast;

/// The process shutdown broadcaster, published by `main` once the channel exists.
static SHUTDOWN: OnceLock<broadcast::Sender<()>> = OnceLock::new();

pub(crate) fn publish_shutdown(tx: broadcast::Sender<()>) {
    let _ = SHUTDOWN.set(tx);
}

/// Whether this process can restart itself. Checked BEFORE the audit record so a refusal is never
/// written as an applied restart that then failed.
pub(crate) fn can_restart() -> bool {
    SHUTDOWN.get().is_some()
}

/// Begin the graceful drain, on the same channel a signal fires.
pub(crate) fn begin_drain() {
    if let Some(tx) = SHUTDOWN.get() {
        let _ = tx.send(());
    }
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
