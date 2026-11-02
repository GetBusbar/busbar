// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use serde::{Deserialize, Serialize};

/// Build a section patch: an all-`Option` twin, its per-field `apply`, and its accumulate-across-
/// PUTs `merge`.
macro_rules! section_patch {
    ($(#[$m:meta])* $patch:ident => $src:path { $($(#[$fm:meta])* $field:ident : $ty:ty),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub struct $patch {
            $(
                #[serde(default, skip_serializing_if = "Option::is_none")]
                $(#[$fm])*
                pub $field: Option<$ty>,
            )+
        }

        impl $patch {
            /// Splice the named fields onto a resolved base; unnamed fields keep the base's value.
            pub fn apply(&self, base: &mut $src) {
                $( if let Some(v) = &self.$field { base.$field = v.clone(); } )+
            }

            /// Accumulate a newer patch over an older one, per field, for the persisted overlay.
            pub fn merge(self, older: Self) -> Self {
                Self { $( $field: self.$field.or(older.$field), )+ }
            }
        }
    };
}

section_patch!(
    /// Per-field patch for [`crate::config::LimitsCfg`].
    LimitsPatch => crate::config::LimitsCfg {
        upstream_request_timeout_secs: u64,
        request_body_max_bytes: usize,
        // Outer None = omitted; Some(None) = explicitly disable; Some(Some(bytes)) = set.
        #[serde(deserialize_with = "deserialize_optional_patch")]
        datagram_line_memory_bytes: Option<usize>,
        pool_max_idle_per_host: usize,
        pool_idle_timeout_secs: u64,
        max_inbound_concurrent: usize,
        max_keys_per_principal: usize,
        max_auto_provisioned_groups: usize,
        hook_content_max_bytes: usize,
        hard_down_cooldown_secs: u64,
        upstream_error_body_max_bytes: usize,
        tls_handshake_timeout_secs: u64,
        request_body_read_timeout_secs: u64,
        max_honored_retry_after_secs: u64,
        default_max_tokens: u32,
        reasoning_effort_budgets: crate::config::ReasoningEffortBudgets,
    }
);

fn deserialize_optional_patch<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}

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
        rate_sweep_interval: u32,
        usage_flush_interval_ms: u64,
        // BOOT-TIME (restart-to-apply), same class as `emit_server_timing` was: `server_timing` is
        // baked into router middleware state and `route_policy` seeds a process-wide `OnceLock`, so a
        // live PUT is stored but does not take effect until a restart (see `reload_to_apply_fields`).
        response_headers: crate::config::ResponseHeadersCfg,
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
