// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::port`'s off-path code: a plane instance's driver, bound once per serving
//! generation to its opened port. Its route table, the route index a request looks its mounted
//! route up in, and its declared usage classes are built here; a request only reads them.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::services::Caller;
use busbar_ports::plane::PlanePort;

use crate::host_services::KernelServices;
use crate::plane_driver::port::PortDriver;
use crate::plane_driver::port_auth::NoTickets;
use crate::plane_driver::port_routes::{plan, Mounted, PortRoutes, RouteRefused};
use crate::plane_driver::CoreAudit;
use crate::refusal::RefusalMap;

impl PortDriver {
    /// Binds an already-opened plane to its complete kernel services and caller.
    /// Image admission and instance opening belong to the composition root.
    pub fn new(
        port: Arc<dyn PlanePort>,
        services: Arc<KernelServices>,
        caller: Caller,
        refusals: Arc<dyn RefusalMap>,
        classes: &(dyn Fn(u32) -> Option<u32> + Sync),
    ) -> Result<Self, RouteRefused> {
        let routes = plan(port.routes(), port.admin_openapi(), classes)?;
        let usage: Arc<[String]> = port
            .usage_classes()
            .iter()
            .map(|u| u.class.to_string())
            .collect();
        let mounted = route_index(&routes);
        let declared = Arc::from(port.usage_classes());
        Ok(Self {
            port,
            services,
            caller,
            refusals,
            audit: Arc::new(CoreAudit),
            routes,
            mounted,
            tickets: Arc::new(NoTickets),
            usage,
            classes: declared,
            hooks: None,
        })
    }
}

/// The data, upgrade and admin routes by id, in that order of precedence (the first that states an
/// id keeps it), each shared so a request takes its route without copying it.
fn route_index(routes: &PortRoutes) -> BTreeMap<u32, Arc<Mounted>> {
    let mut index = BTreeMap::new();
    for mounted in routes
        .data
        .iter()
        .chain(&routes.upgrade)
        .chain(&routes.admin)
    {
        index
            .entry(mounted.route)
            .or_insert_with(|| Arc::new(mounted.clone()));
    }
    index
}
