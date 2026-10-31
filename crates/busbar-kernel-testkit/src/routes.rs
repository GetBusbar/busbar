// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BASE DATA ROUTER'S MOUNTED SURFACE for an App, as plain data, read off the kernel's own
//! `base_data_core_lines` (the routes the data router mounts before any door plane's), so a test
//! asserts which paths appear, at which bar, without naming the router's types.

use busbar_contract::abi::mechanism::route::RouteAuth;
use busbar_kernel::state::App;

/// `(path, declared admission bar)` for every base data route of `app`.
#[must_use]
pub fn base_data_route_table_view(app: &App) -> Vec<(String, RouteAuth)> {
    busbar_kernel::base_data_core_lines(app)
        .into_iter()
        .map(|(path, _, auth)| (path, auth))
        .collect()
}

/// `(path, method, declared admission bar)` for every base data route of `app`.
#[must_use]
pub fn base_data_route_method_view(app: &App) -> Vec<(String, String, RouteAuth)> {
    busbar_kernel::base_data_core_lines(app)
        .into_iter()
        .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
        .collect()
}
