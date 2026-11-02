// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub use busbar_contract::duration::parse_duration_secs;

use busbar_contract::authz::Scope;

pub fn parse_ceiling(subject: &str, token: &str) -> Result<Scope, String> {
    Scope::parse(token).ok_or_else(|| {
        format!(
            "{subject} has unknown max_admin_scope '{token}': expected read-only or full. \
             There is no `none`: omit the key for the most restrictive default \
             (`{}`), and to grant NO admin authority through this identity source grant no \
             `admin_scope` under its `role_bindings:` — the ceiling caps what a grant can \
             reach, it cannot express the absence of one.",
            busbar_contract::DEFAULT_MAX_ADMIN_SCOPE
        )
    })
}
