// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PER-FIELD patches for the root config sections a `PUT /config/settings` may set.
//!
//! The overlay stores what the operator NAMED, never a whole section. Storing the section meant a
//! partial body deserialized into a full struct of compiled defaults, so every field the operator
//! did not mention silently reverted — including values set in `config.yaml`, which the API can
//! neither read back nor restore.
//!
//! Each patch is an all-`Option` twin of its section, `deny_unknown_fields` so a typo is still a
//! 400 at body-parse time, and `apply` splices only the named fields onto the RESOLVED base. A
//! `#[test]` per section destructures the source struct exhaustively, so adding a field there fails
//! to compile until the patch carries it — the mirror cannot drift.

use serde::{Deserialize, Serialize};

/// Build a section patch: an all-`Option` twin, its per-field `apply`, and its accumulate-across-
/// PUTs `merge`. `$src` is the section it mirrors.
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
            /// Splice the named fields onto a resolved base. Unnamed fields keep the base's value —
            /// which is the whole point.
            pub(crate) fn apply(&self, base: &mut $src) {
                $( if let Some(v) = &self.$field { base.$field = v.clone(); } )+
            }

            /// Accumulate a newer patch over an older one, per field, for the persisted overlay.
            pub(crate) fn merge(self, older: Self) -> Self {
                Self { $( $field: self.$field.or(older.$field), )+ }
            }

            /// True when nothing is set — an empty section is not persisted.
            pub(crate) fn is_empty(&self) -> bool {
                true $( && self.$field.is_none() )+
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

#[cfg(test)]
mod tests {
    use super::*;

    /// DRIFT GUARD: destructure the source struct exhaustively. Adding a field to `LimitsCfg`
    /// fails to compile here until `LimitsPatch` carries it, so the mirror cannot silently lose a
    /// field — which would reintroduce exactly the silent-revert bug the patch exists to fix.
    #[test]
    fn limits_patch_mirrors_every_field() {
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
        // Every field is also a patch field; the struct literal is the assertion.
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
    }

    /// The same guard for `SecurityCfg`.
    #[test]
    fn security_patch_mirrors_every_field() {
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
    }

    /// THE DEFECT: a partial patch must leave every unnamed field alone. Before this, a partial
    /// body deserialized into a whole `LimitsCfg`, so the omitted fields carried compiled defaults
    /// and silently overwrote `config.yaml`.
    #[test]
    fn a_partial_patch_leaves_unnamed_fields_untouched() {
        let mut base = crate::config::LimitsCfg {
            upstream_request_timeout_secs: 30,
            request_body_max_bytes: 1_048_576,
            ..Default::default()
        };
        let patch = LimitsPatch {
            max_inbound_concurrent: Some(512),
            ..Default::default()
        };
        patch.apply(&mut base);
        assert_eq!(base.max_inbound_concurrent, 512, "the named field is set");
        assert_eq!(
            base.upstream_request_timeout_secs, 30,
            "an unnamed field keeps the base value, NOT the compiled default"
        );
        assert_eq!(
            base.request_body_max_bytes, 1_048_576,
            "including a deliberately tightened body cap"
        );
    }

    /// Successive PUTs accumulate per field rather than replacing each other.
    #[test]
    fn merge_accumulates_across_puts() {
        let older = LimitsPatch {
            upstream_request_timeout_secs: Some(30),
            ..Default::default()
        };
        let newer = LimitsPatch {
            max_inbound_concurrent: Some(512),
            ..Default::default()
        };
        let merged = newer.merge(older);
        assert_eq!(merged.upstream_request_timeout_secs, Some(30));
        assert_eq!(merged.max_inbound_concurrent, Some(512));
    }

    /// A typo is still rejected at body-parse time — the 400 does not move to boot.
    #[test]
    fn an_unknown_field_is_refused() {
        let err = serde_json::from_str::<LimitsPatch>(r#"{"max_inbound_concurent": 5}"#);
        assert!(err.is_err(), "deny_unknown_fields still fires on the patch");
    }
}
