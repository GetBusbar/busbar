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

section_patch!(
    /// Per-field patch for [`crate::config::ObservabilityCfg`].
    ObservabilityPatch => crate::config::ObservabilityCfg {
        otlp_url: Option<String>,
        request_log_webhook_url: Option<String>,
        max_inflight_webhook_deliveries: usize,
        webhook_delivery_timeout_secs: u64,
        emit_server_timing: bool,
    }
);

section_patch!(
    /// Per-field patch for [`crate::config::AdvancedCfg`].
    AdvancedPatch => crate::config::AdvancedCfg {
        rate_sweep_interval: u32,
        usage_flush_interval_ms: u64,
    }
);

section_patch!(
    /// Per-field patch for [`crate::config::MetricsCfg`].
    MetricsPatch => crate::config::MetricsCfg {
        buffer_seconds: u64,
        key_gauge_limit: usize,
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
mod tests {
    use super::*;

    /// DRIFT GUARD: destructuring the source struct exhaustively means adding a field there fails
    /// to compile until the patch carries it. Without this the mirror silently loses a field and
    /// reintroduces the exact silent-revert bug it exists to fix.
    #[test]
    fn every_patch_mirrors_every_field_of_its_section() {
        let crate::config::LimitsCfg {
            upstream_request_timeout_secs,
            request_body_max_bytes,
            pool_max_idle_per_host,
            pool_idle_timeout_secs,
            max_inbound_concurrent,
            max_keys_per_principal,
            max_auto_provisioned_groups,
            hard_down_cooldown_secs,
            upstream_error_body_max_bytes,
            tls_handshake_timeout_secs,
            request_body_read_timeout_secs,
            max_honored_retry_after_secs,
            default_max_tokens,
            reasoning_effort_budgets,
        } = crate::config::LimitsCfg::default();
        let _ = LimitsPatch {
            upstream_request_timeout_secs: Some(upstream_request_timeout_secs),
            request_body_max_bytes: Some(request_body_max_bytes),
            pool_max_idle_per_host: Some(pool_max_idle_per_host),
            pool_idle_timeout_secs: Some(pool_idle_timeout_secs),
            max_inbound_concurrent: Some(max_inbound_concurrent),
            max_keys_per_principal: Some(max_keys_per_principal),
            max_auto_provisioned_groups: Some(max_auto_provisioned_groups),
            hard_down_cooldown_secs: Some(hard_down_cooldown_secs),
            upstream_error_body_max_bytes: Some(upstream_error_body_max_bytes),
            tls_handshake_timeout_secs: Some(tls_handshake_timeout_secs),
            request_body_read_timeout_secs: Some(request_body_read_timeout_secs),
            max_honored_retry_after_secs: Some(max_honored_retry_after_secs),
            default_max_tokens: Some(default_max_tokens),
            reasoning_effort_budgets: Some(reasoning_effort_budgets),
        };

        let crate::config::SecurityCfg {
            blocked_metadata_hosts,
            allow_metadata_hosts,
            allow_all_metadata,
        } = crate::config::SecurityCfg::default();
        let _ = SecurityPatch {
            blocked_metadata_hosts: Some(blocked_metadata_hosts),
            allow_metadata_hosts: Some(allow_metadata_hosts),
            allow_all_metadata: Some(allow_all_metadata),
        };

        let crate::config::ObservabilityCfg {
            otlp_url,
            request_log_webhook_url,
            max_inflight_webhook_deliveries,
            webhook_delivery_timeout_secs,
            emit_server_timing,
        } = crate::config::ObservabilityCfg::default();
        let _ = ObservabilityPatch {
            otlp_url: Some(otlp_url),
            request_log_webhook_url: Some(request_log_webhook_url),
            max_inflight_webhook_deliveries: Some(max_inflight_webhook_deliveries),
            webhook_delivery_timeout_secs: Some(webhook_delivery_timeout_secs),
            emit_server_timing: Some(emit_server_timing),
        };

        let crate::config::AdvancedCfg {
            rate_sweep_interval,
            usage_flush_interval_ms,
        } = crate::config::AdvancedCfg::default();
        let _ = AdvancedPatch {
            rate_sweep_interval: Some(rate_sweep_interval),
            usage_flush_interval_ms: Some(usage_flush_interval_ms),
        };

        // `MetricsCfg` has no `Default` impl — `buffer_seconds` is deliberately REQUIRED (no serde
        // default), so a literal instance stands in for `::default()`.
        let crate::config::MetricsCfg {
            buffer_seconds,
            key_gauge_limit,
        } = crate::config::MetricsCfg {
            buffer_seconds: 60,
            key_gauge_limit: 1_000,
        };
        let _ = MetricsPatch {
            buffer_seconds: Some(buffer_seconds),
            key_gauge_limit: Some(key_gauge_limit),
        };

        let crate::config::HealthDefaultsCfg {
            default_probe_interval_secs,
            default_probe_timeout_secs,
        } = crate::config::HealthDefaultsCfg::default();
        let _ = HealthPatch {
            default_probe_interval_secs: Some(default_probe_interval_secs),
            default_probe_timeout_secs: Some(default_probe_timeout_secs),
        };

        let crate::config::RoutingCfg {
            default_policy_timeout_ms,
        } = crate::config::RoutingCfg::default();
        let _ = RoutingPatch {
            default_policy_timeout_ms: Some(default_policy_timeout_ms),
        };
    }

    /// THE DEFECT. A partial patch must leave every unnamed field alone. Before this, a partial
    /// body deserialized into a whole section, so omitted fields carried compiled defaults and
    /// silently overwrote `config.yaml` — with no way to read the old values back.
    #[test]
    fn a_partial_patch_leaves_unnamed_fields_untouched() {
        let mut base = crate::config::LimitsCfg {
            upstream_request_timeout_secs: 30,
            request_body_max_bytes: 1_048_576,
            ..Default::default()
        };
        LimitsPatch {
            max_inbound_concurrent: Some(512),
            ..Default::default()
        }
        .apply(&mut base);
        assert_eq!(base.max_inbound_concurrent, 512, "the named field is set");
        assert_eq!(
            base.upstream_request_timeout_secs, 30,
            "an unnamed field keeps the operator's value, not the compiled default"
        );
        assert_eq!(
            base.request_body_max_bytes, 1_048_576,
            "including a deliberately tightened body cap"
        );
    }

    /// Successive PUTs to DIFFERENT fields of one section accumulate in the overlay.
    #[test]
    fn merge_accumulates_across_puts() {
        let merged = LimitsPatch {
            max_inbound_concurrent: Some(512),
            ..Default::default()
        }
        .merge(LimitsPatch {
            upstream_request_timeout_secs: Some(30),
            ..Default::default()
        });
        assert_eq!(merged.upstream_request_timeout_secs, Some(30));
        assert_eq!(merged.max_inbound_concurrent, Some(512));
    }

    /// A typo is still a 400 at body-parse time — the failure does not move to boot.
    #[test]
    fn an_unknown_field_is_refused() {
        assert!(serde_json::from_str::<LimitsPatch>(r#"{"max_inbound_concurent": 5}"#).is_err());
    }
}
