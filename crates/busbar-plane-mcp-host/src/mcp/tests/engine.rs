// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ENGINE BINDING for this plane's test binary — the ONE place in the MCP test tree that names
//! the engine crate. Every other test file reaches the engine (the test-App builder, governance
//! registries, the call log, the audit ring, the store-plugin fixture, the built App's router /
//! host / handle / breaker cells) through the neutral `busbar_substrate::testkit::engine_kit` seam,
//! by way of [`engine`] and the small helpers here.
//!
//! The helpers keep the tests' old call shapes (`engine_host(&app)`, `build_router(app)`,
//! `app_handle(app)`) so the port from the engine's concrete fixture reads as a rename, not a rewrite.
//! Test files glob-import this module.

use busbar_substrate::plane_host::EngineHost;
pub(crate) use busbar_substrate::testkit::engine_kit::{
    EngineApp, EngineHandle, EngineTestKit, GovKit, HookEnvHandle, HookNeed, TestAppKit,
    TestAppKitExt,
};
use std::sync::Arc;

/// The engine's test kit. Binding it here — and nowhere else — is what lets the rest of this tree
/// stay neutral: swap the engine and this one function changes.
pub(crate) fn engine() -> &'static dyn EngineTestKit {
    &busbar_core::test_support::engine_kit::CORE_ENGINE_KIT
}

/// A fresh test-App builder — the fluent chain a test drives `.mcp(&cfg).mcp_server(..).build()` on.
pub(crate) fn test_app() -> Box<dyn TestAppKit> {
    engine().new_app()
}

/// Install the engine's metrics recorder for this process (idempotent).
pub(crate) fn metrics_init() {
    engine().metrics_init();
}

/// The neutral host over a built App — what the production ingress path threads into the engine.
pub(crate) fn engine_host(app: &Arc<dyn EngineApp>) -> Arc<dyn EngineHost> {
    Arc::clone(app).engine_host()
}

/// The neutral host over a LIVE handle, retaining the handle so a later swap is seen.
pub(crate) fn engine_host_from_handle(handle: &Arc<dyn EngineHandle>) -> Arc<dyn EngineHost> {
    Arc::clone(handle).engine_host()
}

/// Wrap a built App in a fresh swappable handle.
pub(crate) fn app_handle(app: Arc<dyn EngineApp>) -> Arc<dyn EngineHandle> {
    app.handle()
}

/// The full HTTP router over a built App, exactly as the composition root mounts it.
pub(crate) fn build_router(app: Arc<dyn EngineApp>) -> axum::Router {
    app.router()
}
