// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PER-FIELD patches for the root config sections a `PUT /config/settings` may set.
//!
//! The overlay stores what the operator NAMED, never a whole section. Storing the section meant a
//! partial body deserialized into a full struct of compiled defaults, so every field the operator
//! did not mention silently reverted — including `config.yaml` values the API can neither read back
//! (`GET` returns no effective values for unset fields) nor restore.
//!
//! Each patch is an all-`Option` twin, `deny_unknown_fields` so a typo is still a 400 at body-parse
//! time, and `apply` splices only the named fields onto the RESOLVED base. Keeping the patch typed
//! (rather than sparse JSON) is what lets `apply_to_deploy` stay infallible: it is called from boot,
//! `--validate`, reload, apply and reset, none of which can take a merge error.
//!
//! `tls`, `admin_tls` and `store` are deliberately NOT field-merged — a cert bundle and a store
//! definition are atomic units, and `store.settings` is opaque plugin config busbar must not
//! reinterpret.

use serde::{Deserialize, Serialize};

/// Build a section patch: an all-`Option` twin, its per-field `apply`, and its accumulate-across-
/// PUTs `merge`.
macro_rules! section_patch {
    ($(#[$m:meta])* $patch:ident => $src:path { $($field:ident : $ty:ty),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(crate) struct $patch {
            $(
                #[serde(default, skip_serializing_if = "Option::is_none")]
                pub(crate) $field: Option<$ty>,
            )+
        }

        impl $patch {
            /// Splice the named fields onto a resolved base; unnamed fields keep the base's value.
            pub(crate) fn apply(&self, base: &mut $src) {
                $( if let Some(v) = &self.$field { base.$field = v.clone(); } )+
            }

            /// Accumulate a newer patch over an older one, per field, for the persisted overlay.
            pub(crate) fn merge(self, older: Self) -> Self {
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

// 1.5.3: there is NO `ObservabilityPatch` any more. The `observability:` BLOCK IS DELETED
// — its last field (`otlp_url`) is now an `export:` instance with `module: otlp`, and the
// `export:` block is edited in config.yaml + applied via plugin reload like every other exporter,
// never through the single-value settings overlay.

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
