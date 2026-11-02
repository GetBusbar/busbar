// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::authz::Scope;
use busbar_contract::surface::ADMIN_PREFIX;

const READ_ONLY_POST_PATHS: &[&str] = &["/config/validate", "/plugins/inspect"];

pub fn admin_required_scope(method: &str, path: &str) -> Scope {
    if method == "GET" || method == "HEAD" {
        return Scope::ReadOnly;
    }

    let path = path.split_once('?').map_or(path, |(before, _)| before);
    let rel = path.strip_prefix(ADMIN_PREFIX).unwrap_or(path);
    if READ_ONLY_POST_PATHS.contains(&rel) {
        return Scope::ReadOnly;
    }
    Scope::Full
}

#[cfg(test)]
mod tests;
