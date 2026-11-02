// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::mechanism::route::RouteAuth;
use busbar_kernel::state::App;

#[must_use]
pub fn base_data_route_table_view(app: &App) -> Vec<(String, RouteAuth)> {
    busbar_kernel::base_data_core_lines(app)
        .into_iter()
        .map(|(path, _, auth)| (path, auth))
        .collect()
}

#[must_use]
pub fn base_data_route_method_view(app: &App) -> Vec<(String, String, RouteAuth)> {
    busbar_kernel::base_data_core_lines(app)
        .into_iter()
        .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
        .collect()
}
