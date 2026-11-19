// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

/// Build a section patch: an all-`Option` twin, its per-field `apply`, and its accumulate-across-
/// PUTs `merge`. A `removed` key (one that stopped being a setting) is accepted from an old body or
/// overlay, carried onto the base so `config::resolve` says its one line, and never persisted.
macro_rules! section_patch {
    ($(#[$m:meta])* $patch:ident => $src:path {
        $($(#[$fm:meta])* $field:ident : $ty:ty),+ $(,)?
    } $(removed { $($removed:ident),+ $(,)? })?) => {
        $(#[$m])*
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $patch {
            $(
                #[serde(default, skip_serializing_if = "Option::is_none")]
                $(#[$fm])*
                pub $field: Option<$ty>,
            )+
            $($(
                #[serde(default, skip_serializing)]
                pub $removed: Option<serde::de::IgnoredAny>,
            )+)?
        }

        impl $patch {
            /// Splice the named fields onto a resolved base; unnamed fields keep the base's value.
            pub fn apply(&self, base: &mut $src) {
                $( if let Some(v) = &self.$field { base.$field = v.clone(); } )+
                $($( if self.$removed.is_some() { base.$removed = self.$removed; } )+)?
            }

            /// Accumulate a newer patch over an older one, per field, for the persisted overlay.
            pub fn merge(self, older: Self) -> Self {
                Self {
                    $( $field: self.$field.or(older.$field), )+
                    $($( $removed: None, )+)?
                }
            }
        }
    };
}

section_patch!(
    /// Per-field patch for [`crate::config::LimitsCfg`].
    LimitsPatch => crate::config::LimitsCfg {
        upstream_request_timeout_secs: u64,
        request_body_max_bytes: usize,
        pool_max_idle_per_host: usize,
        pool_idle_timeout_secs: u64,
        max_inbound_concurrent: usize,
        max_keys_per_principal: usize,
        max_auto_provisioned_groups: usize,
        hard_down_cooldown_secs: u64,
        upstream_error_body_max_bytes: usize,
        tls_handshake_timeout_secs: u64,
        request_body_read_timeout_secs: u64,
        max_honored_retry_after_secs: u64,
        default_max_tokens: u32,
        reasoning_effort_budgets: crate::config::ReasoningEffortBudgets,
    }
);

section_patch!(
    /// Per-field patch for [`crate::config::SecurityCfg`].
    SecurityPatch => crate::config::SecurityCfg {
        blocked_metadata_hosts: Vec<String>,
        allow_metadata_hosts: Vec<String>,
        allow_all_metadata: bool,
    }
);

section_patch!(
    /// Per-field patch for [`crate::config::AdvancedCfg`].
    AdvancedPatch => crate::config::AdvancedCfg {
        usage_flush_interval_ms: u64,
        // BOOT-TIME (restart-to-apply), same class as `emit_server_timing` was: `server_timing` is
        // baked into router middleware state, so a live PUT is stored but does not take effect until a restart (see `reload_to_apply_fields`).
        response_headers: crate::config::ResponseHeadersCfg,
    } removed {
        rate_sweep_interval,
        worker_threads,
    }
);

section_patch!(
    /// Per-field patch for [`crate::config::HealthDefaultsCfg`].
    HealthPatch => crate::config::HealthDefaultsCfg {
        default_probe_interval_secs: u64,
        default_probe_timeout_secs: u64,
    }
);

section_patch!(
    /// Per-field patch for [`crate::config::RoutingCfg`].
    RoutingPatch => crate::config::RoutingCfg {
        default_policy_timeout_ms: u64,
    }
);

#[cfg(test)]
#[path = "tests/patch_tests.rs"]
mod tests;
