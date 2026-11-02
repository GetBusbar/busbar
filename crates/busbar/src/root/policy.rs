// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::transport::TransportSettings;
use busbar_kernel::config::limits::LimitsResolved;

#[must_use]
pub fn client_settings(limits: &LimitsResolved) -> TransportSettings {
    client_settings_under(limits, |name| std::env::var_os(name))
}

#[must_use]
pub(crate) fn client_settings_under(
    limits: &LimitsResolved,
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> TransportSettings {
    use busbar_kernel::appbuild::{
        upstream_bool_env_override, ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE, ENV_UPSTREAM_HTTP1_ONLY,
    };
    TransportSettings {
        pool_max_idle_per_host: limits.pool_max_idle_per_host,
        pool_idle_timeout_secs: limits.pool_idle_timeout_secs,
        upstream_http1_only: upstream_bool_env_override(
            env(ENV_UPSTREAM_HTTP1_ONLY),
            limits.upstream_http1_only,
        ),
        upstream_h2_prior_knowledge: upstream_bool_env_override(
            env(ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE),
            limits.upstream_h2_prior_knowledge,
        ),
        request_body_max_bytes: limits.request_body_max_bytes,

        response_body_max_bytes: limits.request_body_max_bytes,
        request_timeout_secs: limits.upstream_request_timeout_secs,
    }
}

#[cfg(test)]
#[path = "tests/policy.rs"]
mod tests;
