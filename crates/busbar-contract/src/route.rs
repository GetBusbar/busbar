// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's route vocabulary: a route's auth and method, the auth points, method and path-form numbers and the matchers.
//!
//! These names are core's own. Until the old plugin interface is deleted they are still defined inside `abi/`;
//! this module is their one path for every caller, and their definitions move here when `abi/` goes
//! (`K0-HOMES.md`). Nothing here is part of the plugin interface.

pub use crate::abi::auth::{AuthPoint, AuthPoints, POINT_HEAD, POINT_HEAD_BODY};
pub use crate::abi::mechanism::route::{Route, RouteAuth, RouteMethod};
pub use crate::abi::transport::route::{
    method_bit, path_matches, Interner, RouteView, FIELD_VALUE_PREFIX, METHOD_ANY, METHOD_DELETE,
    METHOD_GET, METHOD_HEAD, METHOD_PATCH, METHOD_POST, METHOD_PUT, PATH_CONTAINS, PATH_EXACT,
    PATH_PATTERN, PATH_PREFIX, PATH_SUFFIX,
};

#[cfg(test)]
#[path = "tests/home_pins_tests.rs"]
mod tests;
