// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR REQUEST-PATH TREE'S OFF-PATH CODE: what a request-path module needs built once per
//! configuration, binding or process lifecycle (its tables, its sealed registrations, its
//! configuration refusals), never per request. It sits outside the request-path marker because it
//! does not run per request; the request path only reads what it built. Each submodule is named for
//! the request-path module it builds for.

pub(crate) mod conns;
pub(crate) mod egress;
pub(crate) mod framing;
pub(crate) mod guard;
pub(crate) mod lines;
pub(crate) mod process;
pub(crate) mod proxy;
pub(crate) mod seal;
pub(crate) mod tls;
