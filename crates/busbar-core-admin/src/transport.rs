// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use axum::Router;

use busbar_kernel::state::AppHandle;

pub(crate) trait AdminTransport {
    fn name(&self) -> &'static str;

    fn version(&self) -> &'static str;

    fn area(&self) -> &'static str;

    fn router(&self) -> Router<Arc<AppHandle>>;
}

pub(crate) fn mount<T: AdminTransport>(
    router: Router<Arc<AppHandle>>,
    transport: &T,
) -> Router<Arc<AppHandle>> {
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
    router.nest(&prefix, transport.router())
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
