// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

fn global_audit_host_app() -> &'static Arc<busbar_kernel::state::App> {
    static APP: std::sync::OnceLock<Arc<busbar_kernel::state::App>> = std::sync::OnceLock::new();
    APP.get_or_init(|| {
        let app = super::TestApp::new().build();
        busbar_kernel::audit::auditlog::register_test_audit_stream(&app);
        app
    })
}

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
