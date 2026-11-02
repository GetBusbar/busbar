// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

/// TEST ONLY: the PRODUCTION `audit` stream ([`KIND_ID_AUDIT`]), registered ONCE against a shared
/// no-sink app so the live-server `GET /audit` tests mint sequences without racing to re-register (a
/// re-register resets every position — see [`stream_registry::register`]). Audit is the ONLY seam stream with a
/// mounted read verb (`get_audit`) exercised by live-server assertions, so it is the only one that
/// needs the process-wide registration the test HTTP harness never boots through `register_and_migrate`.
///
/// A NO-SINK registration is sufficient: the seam append mints and returns `(seq, prev_hash, hash)`
/// even with no durable sink attached, so [`emit_admin_hostless`] still pushes to [`AUDIT_LOG`]; these
/// tests assert the in-session read-model ring, never durable persistence.
fn global_audit_host_app() -> &'static Arc<busbar_kernel::state::App> {
    static APP: std::sync::OnceLock<Arc<busbar_kernel::state::App>> = std::sync::OnceLock::new();
    APP.get_or_init(|| {
        let app = super::TestApp::new().build();
        busbar_kernel::audit::auditlog::register_test_audit_stream(&app);
        app
    })
}

/// TEST ONLY: ensure the process-wide `audit` stream is registered ONCE (no-sink) — the single funnel
/// every HTTP test's [`super::TestApp::build_with_store`] passes through, so no live-server
/// audit test can forget it. Idempotent (never re-registers, which would reset the chain position).
///
/// RE-ENTRANCY GUARD: building the shared global app itself goes through `build_with_store`, which calls
/// this — a `thread_local` flag makes that nested call a no-op so the `OnceLock` is not re-entered
/// (which panics). A DIFFERENT thread racing the first init still goes through `global_audit_host_app`
/// and blocks on the `OnceLock` until init completes, so it is correctly serialized.
pub fn ensure_global_audit_stream_registered() {
    thread_local! {
        static BUILDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if BUILDING.with(std::cell::Cell::get) {
        return;
    }
    BUILDING.with(|b| b.set(true));
    let _ = global_audit_host_app();
    BUILDING.with(|b| b.set(false));
}
