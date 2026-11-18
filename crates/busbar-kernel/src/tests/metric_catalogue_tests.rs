// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-337: the host metric catalogue's golden (C1), the plane-carried derivation (C3b, C5) and
//! the describe loop.

use super::*;
use busbar_contract::plane::{check_metric_families, MetricFamily, PlaneDeclaration, COUNTER};

/// One golden line per family: `name kind [sorted,labels] unit plane_carried`, sorted by name.
fn golden_lines() -> String {
    let mut rows: Vec<&MetricDecl> = HOST_METRICS.iter().collect();
    rows.sort_by_key(|d| d.name);
    let mut out = String::new();
    for d in rows {
        let mut labels = d.labels.to_vec();
        labels.sort();
        out.push_str(&format!(
            "{} {} [{}] {} {}\n",
            d.name,
            d.kind.as_str(),
            labels.join(","),
            d.unit.map_or("-", |u| u.as_str()),
            if d.plane_carried {
                "plane_carried"
            } else {
                "-"
            },
        ));
    }
    out
}

/// C1: the Console-facing shape of every host family (name, type, label keys, unit, plane
/// carriage), byte for byte. `help` is excluded on purpose: the docs table (C4) covers it, and the
/// Console signs names, types, labels and units only. A change here needs a `Test-Change` trailer
/// and the DES-3 Console sign-off.
#[test]
fn the_host_metric_catalogue_matches_its_golden() {
    assert_eq!(golden_lines(), GOLDEN);
}

const GOLDEN: &str = "\
busbar_admission_denied_total counter [gate] - -\n\
busbar_audit_stage_failures_total counter [] - -\n\
busbar_billing_tap_decode_fail_total counter [protocol,reason] - plane_carried\n\
busbar_billing_truncated_total counter [] - plane_carried\n\
busbar_breaker_trips_total counter [lane,pool] - plane_carried\n\
busbar_bucket_budget_remaining_cents gauge [bucket,group,window] count -\n\
busbar_bucket_spend_cents gauge [bucket,group,window] count -\n\
busbar_bucket_tokens gauge [bucket,model,tier] - -\n\
busbar_build_info gauge [version] - -\n\
busbar_card_history_alarms_total counter [] - -\n\
busbar_export_audit_integrity_failures_total counter [instance] - -\n\
busbar_export_capture_refusals_total counter [instance,reason] - -\n\
busbar_export_custody_total counter [instance,level,stream] - -\n\
busbar_export_dropped_total counter [instance,reason] - -\n\
busbar_export_held_lines gauge [instance,reason] - -\n\
busbar_failovers_total counter [pool,reason] - plane_carried\n\
busbar_file_logs_dropped_total counter [] - plane_carried\n\
busbar_governed_admissions_live gauge [] count -\n\
busbar_hook_project_over_cap_total counter [part] - -\n\
busbar_insecure_transport_admitted_total counter [accept,instance,kind] - -\n\
busbar_journal_quarantined_total counter [] - -\n\
busbar_key_spend_cents gauge [key] count -\n\
busbar_key_tokens_total gauge [key] count -\n\
busbar_lane_available gauge [lane,pool] count -\n\
busbar_lane_available_permits gauge [lane,pool] count -\n\
busbar_lane_inflight gauge [lane,pool] count -\n\
busbar_lane_recovery_hint_ms gauge [lane,pool] milliseconds -\n\
busbar_lane_request_duration_seconds histogram [instance,model,pool,target] seconds -\n\
busbar_lane_state gauge [lane,pool] count -\n\
busbar_login_attempts_total counter [method,outcome] - -\n\
busbar_login_throttled_total counter [limiter,method] - -\n\
busbar_metering_pending_coalesced_total counter [] - -\n\
busbar_plane_channel_slot_full_total counter [] - -\n\
busbar_plane_channel_unattributed_total counter [] - -\n\
busbar_plane_request_duration_seconds histogram [ingress_protocol,plane,pool] seconds -\n\
busbar_plane_requests_total counter [ingress_protocol,outcome,plane,pool] - -\n\
busbar_plugin_inspect_cap_refusals_total counter [] - -\n\
busbar_plugin_inspect_slot_held_seconds gauge [] seconds -\n\
busbar_plugin_label_refused_total counter [] - -\n\
busbar_plugin_observations_dropped_total counter [] - -\n\
busbar_plugin_request_headers_truncated_total counter [] - -\n\
busbar_plugin_response_headers_rejected_total counter [] - -\n\
busbar_plugin_text_cut_total counter [field,plugin] - -\n\
busbar_pool_queued gauge [pool] count -\n\
busbar_request_duration_seconds histogram [ingress_protocol,pool] seconds -\n\
busbar_request_phase_client_errors_total counter [ingress_protocol,phase,plane,pool,process_boot_nonce] - -\n\
busbar_request_phase_duration_bin_total counter [ingress_protocol,phase,plane,pool,process_boot_nonce,upper_bound_ms] - -\n\
busbar_request_phase_duration_count_total counter [ingress_protocol,phase,plane,pool,process_boot_nonce] - -\n\
busbar_request_phase_duration_seconds histogram [ingress_protocol,outcome,phase,plane,pool] seconds -\n\
busbar_request_phase_duration_sum_us_total counter [ingress_protocol,phase,plane,pool,process_boot_nonce] microseconds -\n\
busbar_request_phase_errors_total counter [ingress_protocol,phase,plane,pool,process_boot_nonce] - -\n\
busbar_request_phase_observations_dropped_total counter [reason] - -\n\
busbar_requests_total counter [ingress_protocol,outcome,pool] - plane_carried\n\
busbar_route_policy_rejections_total counter [policy,pool,status] - plane_carried\n\
busbar_route_policy_selections_total counter [policy,pool] - plane_carried\n\
busbar_store_slots gauge [state] - -\n\
busbar_tap_notifications_dropped_total counter [] - plane_carried\n\
busbar_telemetry_overflow_replays_total counter [] - -\n\
busbar_telemetry_request_capture_refusals_total counter [reason] - -\n\
busbar_telemetry_request_cells gauge [state] - -\n\
busbar_telemetry_request_reserved_bytes gauge [] bytes -\n\
busbar_translations_total counter [from,to] - plane_carried\n\
busbar_unit_checkpoints_terminal gauge [] count -\n\
busbar_unit_refusals_total counter [instance,reason] - -\n\
busbar_upstream_attempts_total counter [lane,pool] - plane_carried\n\
busbar_upstream_failures_total counter [disposition,lane,pool] - plane_carried\n\
busbar_webhook_logs_dropped_total counter [] - plane_carried\n\
";

#[test]
fn every_catalogue_row_is_a_unique_reserved_name_with_unique_label_keys_and_help() {
    let mut seen = std::collections::BTreeSet::new();
    for d in HOST_METRICS {
        assert!(d.name.starts_with("busbar_"), "{}", d.name);
        assert!(seen.insert(d.name), "{} is declared twice", d.name);
        let keys = d.labels;
        assert!(
            !keys.iter().enumerate().any(|(i, k)| keys[..i].contains(k)),
            "{} repeats a label key: {keys:?}",
            d.name
        );
        assert!(!d.help.is_empty() && !d.help.contains('|'), "{}", d.name);
        assert!(
            !d.plane_carried || d.kind == Kind::Counter,
            "{}: a plane carries counters only",
            d.name
        );
    }
}

/// A declaration keyed `key` stating exactly `families`.
fn plane(key: &'static str, families: &'static [MetricFamily]) -> PlaneDeclaration {
    PlaneDeclaration {
        key,
        fallback: false,
        config_section: key,
        scope_kinds: &[],
        subject_noun: key,
        admin_noun: key,
        audit_kind: key,
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        class_parents: &[],
        fee_units: &[],
        metric_families: families,
        record_kinds: &[],
        required_config_sections: &[],
        trust_keys: &[],
        caller_credential_refusal: None,
        served_op_classes: &[],
    }
}

fn carries(name: &'static str, label_keys: &'static [&'static str]) -> Result<(), String> {
    let families: &'static [MetricFamily] = Box::leak(Box::new([MetricFamily {
        name,
        kind: COUNTER,
        label_keys,
    }]));
    check_metric_families(&[&plane("p", families)], plane_carried_series())
}

/// C5: the plane-carried list is derived from the catalogue. Every `plane_carried` row is
/// admitted with exactly its catalogue labels, and the carried names are the set the hand list
/// (`root::linked::PLANE_CARRIED_SERIES`) held before the derivation.
#[test]
fn the_plane_carried_series_are_the_catalogue_rows_with_their_labels() {
    let carried = plane_carried_series();
    for d in HOST_METRICS.iter().filter(|d| d.plane_carried) {
        assert!(carried.contains(&(d.name, d.labels)), "{}", d.name);
        assert_eq!(carries(d.name, d.labels), Ok(()), "{}", d.name);
    }
    let mut names: Vec<&str> = carried.iter().map(|(n, _)| *n).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "busbar_billing_tap_decode_fail_total",
            "busbar_billing_truncated_total",
            "busbar_breaker_trips_total",
            "busbar_failovers_total",
            "busbar_file_logs_dropped_total",
            "busbar_requests_total",
            "busbar_route_policy_rejections_total",
            "busbar_route_policy_selections_total",
            "busbar_tap_notifications_dropped_total",
            "busbar_translations_total",
            "busbar_upstream_attempts_total",
            "busbar_upstream_failures_total",
            "busbar_webhook_logs_dropped_total",
        ]
    );
}

/// C3b (guard, TST-1): a plane declaring a plane-carried family with a wrong label set is refused,
/// as it was under the hand list; so is a host family that is not plane-carried.
#[test]
fn a_plane_carried_family_with_a_wrong_label_set_is_refused() {
    let err = carries(REQUESTS_TOTAL, &["ingress_protocol", "pool"]).unwrap_err();
    assert!(
        err.contains(REQUESTS_TOTAL) && err.contains("exactly its label keys"),
        "{err}"
    );
    let err = carries(REQUESTS_TOTAL, &["pool", "ingress_protocol", "outcome"]).unwrap_err();
    assert!(err.contains("exactly its label keys"), "{err}");
    let err = carries(
        PLANE_REQUESTS_TOTAL,
        &["plane", "ingress_protocol", "pool", "outcome"],
    )
    .unwrap_err();
    assert!(err.contains(PLANE_REQUESTS_TOTAL), "{err}");
}
