// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::Router;

use busbar_contract::route::{RouteAuth, RouteMethod};
use busbar_kernel::core_routes::CoreRouter;
use busbar_kernel::state::AppHandle;

pub(crate) trait AdminTransport {
    fn name(&self) -> &'static str;

    fn version(&self) -> &'static str;

    fn area(&self) -> &'static str;

    fn router(&self) -> Router<Arc<AppHandle>>;
}

/// Every method an admin surface's routes take: the surface is declared at its prefix for each,
/// under the operator chain (`RouteAuth::Admin`).
const SURFACE_METHODS: [RouteMethod; 5] = [
    RouteMethod::Get,
    RouteMethod::Post,
    RouteMethod::Put,
    RouteMethod::Patch,
    RouteMethod::Delete,
];

pub(crate) fn mount<T: AdminTransport>(router: CoreRouter, transport: &T) -> CoreRouter {
    let prefix = format!(
        "{}/{}/{}",
        crate::v1::contract::API_ROOT,
        transport.version(),
        transport.area()
    );
    tracing::info!(
        transport = transport.name(),
        prefix = %prefix,
        "native API surface mounted"
    );
    router.nest(
        &prefix,
        transport.router(),
        &SURFACE_METHODS,
        RouteAuth::Admin,
    )
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
