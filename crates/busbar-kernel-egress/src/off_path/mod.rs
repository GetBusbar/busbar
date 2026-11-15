// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EGRESS REQUEST-PATH MODULES' OFF-PATH CODE: what they need built once per configuration (a
//! pool and its members, as the pool configuration is loaded), never per request. It sits outside
//! the request-path marker because it does not run per request; the request path only reads what
//! it built.

mod pool;
