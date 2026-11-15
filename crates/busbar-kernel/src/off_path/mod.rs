// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL REQUEST-PATH MODULES' OFF-PATH CODE: what a request-path module needs built once per
//! configuration, per published generation or per process lifecycle (its tables, its admin and
//! schema projections, its configuration refusals), never per request. It sits outside the
//! request-path marker because it does not run per request; the request path only reads what it
//! built. Each submodule is named for the request-path module it builds for.

/// `governance`: boot recovery, persistence replay, operator-issued control-plane operations and
/// configuration builds of the governance module; none runs per request.
pub(crate) mod governance;
