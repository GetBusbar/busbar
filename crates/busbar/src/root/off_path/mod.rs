// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE REQUEST-PATH MODULES' OFF-PATH CODE: what a request-path module needs built once per
//! configuration, per published generation or per process lifecycle (its tables, its boot-time
//! workers, its configuration refusals), never per request. It sits outside the request-path
//! marker because it does not run per request; the request path only reads what it built. Each
//! submodule is named for the request-path module it builds for.

pub(crate) mod auth_bindings;
pub(crate) mod door_steps;
pub(crate) mod egress_ports;
pub(crate) mod exports;
pub(crate) mod hooks;
pub(crate) mod listener;
pub(crate) mod model_egress;
pub(crate) mod native_nests;
pub(crate) mod plane_node;
pub(crate) mod serve;
pub(crate) mod serve_datagram;
pub(crate) mod serve_lines;
pub(crate) mod serve_observations;
