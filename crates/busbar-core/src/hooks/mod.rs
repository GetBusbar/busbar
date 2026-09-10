// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `hooks` — THE SPELLING. The hook policy ENGINE is [`busbar_core_policy`]; this module is the name
//! roughly thirty in-core call sites already write, kept so none of them moved.
//!
//! # What left, and why
//!
//! Owner ruling, 2026-09-08: the engine that resolves a pool's configured hooks into policy
//! transports, fires them and reads what they answered — `resolve_policy`, the three pool resolvers,
//! the gate decision, `push_configure`, the transport-publish wait, the status/schema reads, the
//! settings-drift keys, the single-flight resolution cache and the `/metrics/hooks` scrape — is a
//! CORE crate of its own. The kernel SEATS a hook plugin after Admit; deciding which hook runs, with
//! which grants, on which terminal is POLICY, and the two jobs shared a crate only because
//! busbar-core was the only place there was.
//!
//! Nothing about the engine changed in the move. It is checkable from its manifest that it names no
//! plane, no dialect and no transport, which was never checkable while it lived here.
//!
//! # What stayed
//!
//! Two things. The SEAT ADAPTER (`seat`): the engine reaches a `kind: hook` plugin only through its
//! own port, and binding the hybrid-ABI registry, the manifest's declared needs and the built-in
//! ranking plugin behind that port is the composition's job — so [`HookEnv`] here is the engine's
//! environment bound over this crate's registry, and the dlopen battery that packages a REAL hook
//! plugin and asserts on what it answered lives beside the adapter (`engine_tests`), because that
//! claim is about adapter + loader + engine together. And the axum HANDLER for `GET /metrics/hooks`,
//! below: an axum route that extracts `CurrentApp` is the composition root's business, and `App` is
//! precisely the name the engine may not have. It is four lines around the engine's renderer.

/// Everything the engine exposes, at the paths this crate's callers already write:
/// `crate::hooks::{HookEnv, resolve_policy, resolve_pool_gates, push_configure, fetch_status, …}`
/// and the `gate` / `wire` / `plugin` submodules.
pub use busbar_core_policy::*;

pub mod seat;
/// The engine's environment bound over this crate's plugin registry — the one the thirty call
/// sites construct with `HookEnv::new(registry, secret_resolver)`.
pub use seat::HookEnv;

#[cfg(test)]
#[path = "tests/engine_tests.rs"]
mod engine_tests;

/// The hook-metrics scrape. The engine owns the cache, the stale-while-revalidate refresh and the
/// Prometheus rendering; this shadows the engine's `scrape` with the same name plus the one thing
/// that could not go — the route handler.
pub mod scrape {
    pub use busbar_core_policy::scrape::*;

    /// `GET /metrics/hooks` — the Prometheus scrape of hook-reported metrics. Standard text
    /// exposition, governed by the auth chain exactly like busbar's own `/metrics` (both carry
    /// operational topology, so busbar does NOT exempt them — a scraper authenticates with a bearer
    /// token, which Prometheus and Grafana both support in scrape/datasource config).
    /// Stale-while-revalidate: renders the cache now, refreshes stale hooks in the background; never
    /// blocks on a hook socket.
    pub(crate) async fn handler(
        crate::state::CurrentApp(app): crate::state::CurrentApp,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        (
            axum::http::StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            busbar_core_policy::scrape::render(
                &app.hook_registry,
                app.config_version,
                &app.hook_env,
            ),
        )
            .into_response()
    }
}
