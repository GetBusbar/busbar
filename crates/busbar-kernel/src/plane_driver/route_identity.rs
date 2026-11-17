// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Original ingress metadata captured from the actual seat and its checked invocation.

use std::sync::Arc;

use crate::host_services::InvocationContext;

use super::image_identity::PlaneImageIdentity;
use super::port::PortSeat;
use super::port_routes::{Mounted, PortRoutes};

/// Route evidence only. Credential and selected-member authority remain with their actual
/// request/admission owners. There is no constructor from a route number or descriptor copy.
#[derive(Clone)]
pub struct OriginalPlaneRoute {
    context: InvocationContext,
    image: Arc<PlaneImageIdentity>,
    mounted: Mounted,
    audience: Option<Box<str>>,
}

impl OriginalPlaneRoute {
    pub fn route(&self) -> u32 {
        self.mounted.route
    }

    pub fn accepts(&self, context: &InvocationContext, route: u32) -> bool {
        self.context.is_live() && self.context.same_unit(context) && self.mounted.route == route
    }

    /// Called only with a seat from the actual current App under its publication gate.
    /// A fresh port instance is compatible when its admitted image and complete effective
    /// descriptor are unchanged; caller-name equality alone never establishes compatibility.
    pub(crate) fn matches_current(&self, current: &PortSeat) -> bool {
        self.context.is_live()
            && self.context.instance() == current.instance
            && self.image.compatible_with(&current.image)
            && self.audience.as_deref() == current.audience.as_deref()
            && mounted(current.driver.routes(), self.mounted.route) == Some(&self.mounted)
    }
}

impl std::fmt::Debug for OriginalPlaneRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginalPlaneRoute").finish_non_exhaustive()
    }
}

impl PortSeat {
    /// Root invokes this for the actual routed request before passing it to this driver.
    /// The same context must subsequently bind the Task, admission and selected preparation.
    pub fn retain_route(
        &self,
        context: &InvocationContext,
        route: u32,
    ) -> Option<OriginalPlaneRoute> {
        if self.instance != context.instance()
            || !Arc::ptr_eq(self.driver.core(), context.generation().core())
            || !context.accepts(self.driver.caller())
        {
            return None;
        }
        Some(OriginalPlaneRoute {
            context: context.clone(),
            image: Arc::clone(&self.image),
            mounted: mounted(self.driver.routes(), route)?.clone(),
            audience: self.audience.as_deref().map(Box::from),
        })
    }
}

fn mounted(routes: &PortRoutes, route: u32) -> Option<&Mounted> {
    routes
        .data
        .iter()
        .chain(&routes.admin)
        .chain(&routes.upgrade)
        .chain(routes.line.iter())
        .chain(&routes.recovery)
        .find(|mounted| mounted.route == route)
}
