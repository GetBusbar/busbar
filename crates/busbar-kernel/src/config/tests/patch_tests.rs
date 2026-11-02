// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn every_patch_mirrors_every_field_of_its_section() {
    let crate::config::LimitsCfg {
        upstream_request_timeout_secs,
        request_body_max_bytes,
        datagram_line_memory_bytes,
        pool_max_idle_per_host,
        pool_idle_timeout_secs,
        max_inbound_concurrent,
        max_keys_per_principal,
        max_auto_provisioned_groups,
        hook_content_max_bytes,
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
        datagram_line_memory_bytes: Some(datagram_line_memory_bytes),
        pool_max_idle_per_host: Some(pool_max_idle_per_host),
        pool_idle_timeout_secs: Some(pool_idle_timeout_secs),
        max_inbound_concurrent: Some(max_inbound_concurrent),
        max_keys_per_principal: Some(max_keys_per_principal),
        max_auto_provisioned_groups: Some(max_auto_provisioned_groups),
        hook_content_max_bytes: Some(hook_content_max_bytes),
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

    let crate::config::AdvancedCfg {
        rate_sweep_interval,
        usage_flush_interval_ms,
        response_headers,

        worker_threads: _,
        upstream_http1_only: _,
        upstream_h2_prior_knowledge: _,

        block_private_addresses: _,
        allow_destinations: _,
    } = crate::config::AdvancedCfg::default();
    let _ = AdvancedPatch {
        rate_sweep_interval: Some(rate_sweep_interval),
        usage_flush_interval_ms: Some(usage_flush_interval_ms),
        response_headers: Some(response_headers),
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

#[test]
fn an_unknown_field_is_refused() {
    assert!(serde_json::from_str::<LimitsPatch>(r#"{"max_inbound_concurent": 5}"#).is_err());
}

#[test]
fn datagram_line_memory_patch_distinguishes_omission_set_and_disable() {
    let mut base = crate::config::LimitsCfg {
        datagram_line_memory_bytes: Some(12345),
        ..Default::default()
    };
    let omitted: LimitsPatch = serde_json::from_str(r#"{"max_inbound_concurrent":7}"#).unwrap();
    assert_eq!(omitted.datagram_line_memory_bytes, None);
    omitted.apply(&mut base);
    assert_eq!(base.datagram_line_memory_bytes, Some(12345));

    let set: LimitsPatch = serde_json::from_str(r#"{"datagram_line_memory_bytes":54321}"#).unwrap();
    assert_eq!(set.datagram_line_memory_bytes, Some(Some(54321)));
    set.apply(&mut base);
    assert_eq!(base.datagram_line_memory_bytes, Some(54321));

    let disable: LimitsPatch =
        serde_json::from_str(r#"{"datagram_line_memory_bytes":null}"#).unwrap();
    assert_eq!(disable.datagram_line_memory_bytes, Some(None));
    let merged = disable.merge(set);
    assert_eq!(merged.datagram_line_memory_bytes, Some(None));
    let persisted = serde_json::to_string(&merged).unwrap();
    let restored: LimitsPatch = serde_json::from_str(&persisted).unwrap();
    assert_eq!(restored.datagram_line_memory_bytes, Some(None));
    restored.apply(&mut base);
    assert_eq!(base.datagram_line_memory_bytes, None);
    assert_eq!(base.max_inbound_concurrent, 7);
}
