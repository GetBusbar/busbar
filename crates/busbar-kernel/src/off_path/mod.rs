// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL REQUEST-PATH MODULES' OFF-PATH CODE: what a request-path module needs built once per
//! configuration, per published generation or per process lifecycle (its tables, its admin and
//! schema projections, its configuration refusals), never per request. It sits outside the
//! request-path marker because it does not run per request; the request path only reads what it
//! built. Each submodule is named for the request-path module it builds for.

pub(crate) mod auth;
pub(crate) mod export;
/// `governance`: boot recovery, persistence replay, operator-issued control-plane operations and
/// configuration builds of the governance module; none runs per request.
pub(crate) mod governance;
pub(crate) mod host_outbound;
pub(crate) mod host_records;
pub(crate) mod host_services;
pub(crate) mod inbound;
pub(crate) mod plane_dispatch;
pub(crate) mod plane_door;
pub(crate) mod plane_driver;
pub(crate) mod plane_hooks;
pub(crate) mod plane_needs;
pub(crate) mod plane_registry;
pub(crate) mod plane_route_tables;
pub(crate) mod plane_serve;
pub(crate) mod router;
pub(crate) mod telemetry;
pub(crate) mod timing;
