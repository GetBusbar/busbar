// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE IDENTITY REQUEST-PATH MODULES' OFF-PATH CODE: what they need once per build start or per
//! configuration (the linked rows installed, the admin chain's operator credential built, its
//! configuration text spelled), never per request. It sits outside the request-path marker because
//! it does not run per request; the request path only reads what it built.

pub(crate) mod operator;
