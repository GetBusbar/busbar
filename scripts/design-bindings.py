#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""design-bindings.py -- the DESIGN BINDINGS LEDGER derivation.

Answers, mechanically, the owner's question "is what we built compliant with what we designed?"
for the one part of docs/design/ARCHITECTURE.md that is written as testable rules: Appendix B, the
parity bindings (PB-0 master rule + one table row per binding). Each binding becomes one entry in
qa/design-bindings.json carrying the checks that PROVE it today:

  kind            what the check is
  ------------    ---------------------------------------------------------------------------
  test            a Rust test fn (bare name, or `path/to/file.rs::name` when the name is not
                  unique across the tree); existence = the fn is declared under a test attribute
  oracle-cell     one shadow-oracle cell id (testing/shadow-oracle/cells.json) that diffs the
                  published 1.5.5 binary on that surface
  oracle-family   a whole cell family (every cell in it cites the binding)
  lint            a scripts/*-lint.sh style static check
  conformance     a row of a conformance rig (testing/*-conformance)
  gate            a scripts/*.sh or testing/*.sh gate

Where mappings come from -- and why the list is short:
  1. EXPLICIT CITATIONS. A shadow-oracle cell whose `why` names `PB-N` was written to exercise that
     binding; that is the one derivation that is honest without a human reading the test. These
     are recomputed on every --write.
  2. CURATED MAPPINGS (SEED below). Tests and gates were found by grepping the binding's literal
     strings and reading the test body to confirm it asserts the binding's rule. A test that merely
     touches the surface is NOT mapped. This table is data, edited by hand when a new proof lands.
  3. HAND-CURATED ENTRIES already in qa/design-bindings.json are preserved across --write, so a
     mapping added directly in the JSON survives a re-derivation.

A binding with no check is `unmapped` and carries a one-line suggestion of the check that would
prove it. Many are unmapped; that is the finding, not a defect of this script.

Usage:
  design-bindings.py --write          regenerate qa/design-bindings.json + qa/DESIGN-BINDINGS.md
  design-bindings.py --verify         print one TSV row per binding: id, PASS|FAIL|SKIP, title, detail
                                      (existence only; nothing is executed) -- consumed by
                                      scripts/design-bindings.sh, which records each row in the
                                      fleet-fixtures ledger and lets verdict.sh decide
  design-bindings.py --summary        counts only
  --bindings <json> --arch <md> --cells <json> override the inputs (the shell selftest uses these).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / "docs" / "design" / "ARCHITECTURE.md"
CELLS = ROOT / "testing" / "shadow-oracle" / "cells.json"
OUT_JSON = ROOT / "qa" / "design-bindings.json"
OUT_MD = ROOT / "qa" / "DESIGN-BINDINGS.md"
CRATES = ROOT / "crates"

KINDS = ("test", "oracle-cell", "oracle-family", "lint", "conformance", "gate")

# A family is collapsed to one `oracle-family` check when at least this many of its cells cite the
# binding; below that the cells are listed one by one.
FAMILY_COLLAPSE_MIN = 6

# ── Curated mappings ─────────────────────────────────────────────────────────────────────────────
# id -> list of (kind, ref, proves). Every entry here was confirmed by reading the test/gate: it
# asserts the binding's rule, not just its vocabulary. `proves` names the clause of the binding the
# check pins, because most bindings are omnibus rows and a single test rarely covers all of one.
# Add here (or directly in the JSON) when a proof lands.
SEED: dict[str, list[tuple[str, str, str]]] = {
    "PB-1": [
        ("test", "enforce_restricts_reapplies_compliance_tags_across_pools", "a Reject restrict with no eligible lane fails closed; the Weighted arm passes candidates unchanged"),
        ("test", "multi_restrict_disjoint_intersection_fails_closed", "two restricts intersecting to empty produce a 503 (status only, not the literal body)"),
    ],
    "PB-2": [
        ("test", "excluded_reasons_records_at_capacity", "a saturated lane's try_admit yields no pick and records AtCapacity"),
        ("test", "at_capacity_reject_sheds_503_not_queued", "a saturated reject pool sheds 503 at once, never parks"),
        ("test", "queue_dispatches_when_permit_frees_before_deadline", "waiting only under on_exhausted queue, on the lane semaphore"),
        ("test", "queue_times_out_to_503_when_capacity_never_frees", "queue max_ms elapses to a 503"),
        ("gate", "scripts/release-check.sh", "phase-0c-soak-reject: real binary at max_concurrent 1 sheds excess with a fast 503"),
    ],
    "PB-3": [
        ("test", "ordered_walk_skips_tripped_preferred_to_next", "a tripped lane is excluded from the walk, not ordered last"),
        ("test", "ordered_walk_skips_excluded_preferred", "an excluded lane never receives an attempt"),
        ("test", "at_capacity_plus_tripped_member_rejects_503", "all excluded lands on the pool terminal"),
        ("test", "least_bad_never_reaches_an_excluded_member", "least_bad ranks admissible lanes only"),
        ("test", "strengthened_lane_availability_invariant", "property test: the availability invariant holds under every policy"),
    ],
    "PB-4": [
        ("test", "at_capacity_default_no_on_exhausted_sheds_503", "key absent: 503 + Retry-After"),
        ("test", "retry_after_reflects_cooldown_when_a_member_is_tripped", "Retry-After is the soonest genuine cooldown"),
        ("test", "retry_after_has_saturation_floor_when_purely_at_capacity", "the AT_CAPACITY_RETRY_AFTER_SECS floor of 2"),
        ("test", "retry_after_empty_candidate_set_uses_floor_not_one", "an empty candidate set uses the floor"),
        ("test", "least_bad_still_serves_the_only_member_after_it_was_tried", "least_bad: one breaker-bypassing attempt"),
        ("test", "a_fallback_pool_applies_its_own_exclusions", "fallback_pool re-applies restricts"),
        ("test", "at_capacity_fallback_chain_spills_through_to_third_pool", "fallback_pool is multi-level"),
        ("test", "at_capacity_self_referential_fallback_stays_503", "the visited guard"),
        ("test", "queue_skips_wait_and_rejects_when_no_candidate_at_capacity", "queue parks only when some exclusion was AtCapacity"),
        ("test", "queue_won_permit_but_breaker_now_open_never_dispatches", "the queue winner re-checks the breaker"),
        ("test", "queue_two_waiters_one_freed_permit_wakes_exactly_one", "FIFO permit park wakes one"),
        ("test", "test_scrape_gauges_pool_queued_reads_live_depth", "the busbar_pool_queued gauge"),
        ("gate", "scripts/release-check.sh", "reject SLO on the real binary: 503 + Retry-After >= 2; soak-queue phase sees busbar_pool_queued > 0"),
    ],
    "PB-5": [
        ("test", "sticky_affinity_never_selects_zero_weight_drained_member", "sticky fast path skipped on weight 0"),
        ("test", "sticky_fall_through_records_reason", "sticky fast path skipped on an excluded lane"),
        ("test", "test_sticky_yields_when_tripped", "sticky yields to the walk when the lane is tripped"),
        ("test", "order_last_in_chain_wins", "the last ordering gate wins"),
        ("test", "stale_order_filtered_against_post_restrict_set", "the order is re-validated against the post-restrict set"),
        ("test", "last_order_gate_filtered_to_empty_abstains_to_base_not_to_a_lower_gate", "empty order abstains to the base policy"),
        ("test", "ordered_walk_falls_through_to_swrr_when_no_preferred_ready", "the ready_in peek then SWRR fall-through"),
        ("test", "ordered_walk_empty_order_is_swrr", "no ordering gate means the SWRR floor"),
    ],
    "PB-6": [
        ("test", "global_gate_reject_short_circuits_the_request", "a decision-gate reject ends the request"),
        ("test", "global_request_stage_tap_fires_on_a_real_dispatched_request", "request-stage taps fire through fire_global_taps"),
    ],
    "PB-8": [
        ("test", "test_saturated_lane_respects_deadline_no_infinite_spin", "the pick_among guard is bounded by failover.timeout_secs and resolves 503"),
        ("test", "test_context_length_failover_no_penalty", "context-length exclusion carries no breaker penalty"),
        ("test", "test_prefers_larger_context_max", "candidates whose context_max is not larger are excluded"),
        ("test", "a_changed_upstream_timeout_rebuilds_the_client_an_unrelated_apply_reuses_it", "upstream_request_timeout_secs is carried onto the client"),
        ("test", "test_member_override_wins_over_model_default", "the per-attempt time-to-headers cap with pool-member override"),
        ("test", "test_attempt_cap_budget_floor", "the attempt cap floor"),
    ],
    "PB-9": [
        ("test", "rotate_invalidates_the_outstanding_signed_token", "rotate has no grace on the serving node"),
        ("test", "local_revoke_rejects_the_very_next_auth_attempt", "the serving node refuses the old token at once"),
        ("test", "peer_revoke_written_to_the_store_is_honoured_within_the_window", "the denylist re-sync window on other nodes"),
    ],
    "PB-10": [
        ("test", "test_disposition_hard_down_billing_code", "HardDown billing disposition row"),
        ("test", "test_disposition_transient_rate_limit_code", "TransientUpstream rate-limit row with a code"),
        ("test", "test_disposition_transient_server_error", "TransientUpstream 5xx row"),
        ("test", "test_disposition_hard_down_auth", "HardDown auth row"),
        ("test", "test_disposition_code_drives_classification", "the provider code drives the disposition"),
        ("test", "test_disposition_client_fault_no_known_code", "ClientFault row without a known code"),
        ("test", "test_classify_context_length_both_protocols", "ContextLength row"),
        ("test", "test_extract_error_bad_api_key_classifies_as_auth_harddown", "gemini bad key classifies HardDown auth"),
    ],
    "PB-11": [
        ("test", "supported_abi_auth_floor_admits_v1", "the auth window [1,2]"),
        ("test", "a_v2_store_artifact_is_accepted_at_load", "a v2 store artifact loads through the adapter"),
        ("test", "untrusted_is_skipped_not_fatal_but_reference_fails_loud", "an untrusted plugin is logged and skipped, never dlopened"),
        ("gate", "scripts/signing-gate.sh", "signed loads; unsigned, wrong-key and tampered manifests refused with the literal messages"),
    ],
    "PB-12": [
        ("test", "each_webhook_instance_gets_its_own_admission_gate", "the webhook admission gate is per instance (the corrected CFG-249 row)"),
        ("test", "file_sink_sheds_appends_beyond_its_inflight_cap", "the fixed MAX_INFLIGHT_FILE_APPENDS cap"),
        ("test", "producerless_stream_is_a_loud_config_error", "validate-time refusal of a producerless stream"),
        ("test", "audit_is_refused_as_a_stream_with_the_reason", "the audit stream refusal literal"),
        ("test", "unknown_stream_names_the_vocabulary", "an unknown stream names the vocabulary"),
        ("test", "durable_true_is_a_loud_not_yet_implemented_error", "durable: true is a config refusal"),
        ("test", "fields_on_metrics_is_a_loud_error", "fields: is refused where not exhaustive"),
        ("test", "empty_streams_list_is_a_loud_error", "an empty streams list is refused"),
    ],
    "PB-14": [
        ("test", "test_metering_accumulator_is_bounded_and_lossless_under_sustained_store_outage", "deltas are retained and retried across a store outage"),
    ],
    "PB-16": [
        ("test", "test_finish_refunds_flat_fee_on_non_2xx_keeps_on_2xx", "the fee is refunded on a non-2xx and kept on a 2xx"),
        ("test", "test_pre_routing_failure_does_not_refund_prior_charge", "a pre-routing failure refunds nothing extra"),
        ("test", "finish_admitted_does_not_refund_an_uncharged_admit", "finish_admitted never refunds an uncharged admit"),
    ],
    "PB-18": [
        ("test", "test_inbound_concurrency_layer_added_only_when_positive", "max_inbound_concurrent 0 adds no layer at all"),
        ("oracle-cell", "boot.refusal|BOOT-089e|validate", "the BOOT-089e literal incl. 0 disables the inbound layer"),
    ],
    "PB-19": [
        ("test", "test_missing_group_fails_closed_at_ingress", "429 with the literal group is not configured body"),
        ("test", "test_missing_group_fails_closed", "try_admit returns MissingGroup, never admitted"),
        ("test", "govern_admit_reason_reason_bytes_match_direct_try_admit", "the rendered MissingGroup reason is byte-identical through the plane host"),
    ],
    "PB-20": [
        ("test", "the_admin_audit_digest_is_unchanged_by_the_unification", "hash = SHA-256 hex over the canonical prev|seq|ts|action|resource|outcome|principal"),
        ("test", "hash_chain_links_and_verifies", "genesis prev_hash is empty; tamper breaks verify"),
        ("test", "export_load_roundtrip_resumes_chain", "restore resumes the sequence"),
        ("test", "admin_audit_chain_boot_verifies_from_frozen_bytes", "restore_from_store over frozen legacy bytes with zero chain breaks"),
        ("oracle-cell", "admin.ops|GetAudit|ok", "GET /audit diffed against the 1.5.5 binary"),
    ],
    "PB-21": [
        ("test", "test_admin_v1_rotate_idempotency_in_flight_is_not_replayed_as_complete", "a concurrent duplicate is 409, not a replay of the Null sentinel"),
        ("test", "test_admin_v1_key_idempotent_mint_and_if_match", "a replay returns the first response"),
        ("test", "test_admin_v1_idempotency_key_is_principal_scoped", "the (actor, header) key"),
        ("test", "test_admin_v1_rotate_idempotent_replay_survives_the_ttl_sweep", "the rotate:{id} key form and the TTL sweep"),
        ("test", "test_admin_v1_idempotency_reservation_frees_on_failure", "Reserved is cleared on Drop"),
        ("test", "an_idempotency_key_survives_a_client_disconnect_mid_mint", "InFlight is deliberately not cleared"),
    ],
    "PB-22": [
        ("test", "test_governance_over_budget_native_envelope_all_ingress", "budget is insufficient_quota, 429 everywhere and 400 on bedrock"),
        ("test", "test_governance_rate_limit_429_native_envelope_all_ingress", "requests is always 429 rate_limit_error, bedrock included"),
        ("test", "chain_and_parent_blocks_child_and_charges_nothing", "a blocked attempt charges nothing on any chain bucket"),
        ("test", "test_group_blocked_429_names_the_budget_group", "the first blocking bucket names the 429 and charges 0"),
        ("test", "budget_cap_derives_from_ledger_and_rate_card", "the derived + fee lookahead"),
        ("test", "test_group_token_spend_blocks_chain_admission", "tokens is enforced post-hoc via derived spend"),
        ("test", "concurrent_gauge_holds_and_releases", "the concurrent gauge"),
        ("test", "disabled_group_freezes_the_chain", "the FREEZE arm"),
    ],
    "PB-24": [
        ("test", "split_admin_listener_no_double_exposure", "admin claims only on the admin listener"),
        ("test", "admin_plane_boot_guard", "an exposed admin bind refuses to boot without admin_require_mtls false"),
        ("test", "admin_require_mtls_defaults_on_and_the_retired_key_loud_fails", "the guard is on by default"),
        ("oracle-cell", "ops.scrape|metrics|admin-listener", "/metrics is absent on the admin listener, diffed against 1.5.5"),
    ],
    "PB-26": [
        ("test", "test_unpriced_passthrough_model_rejected_when_rate_card_present", "the no configured rate for model 400 literal"),
        ("oracle-cell", "http.crosscut|unknown-path|openai-suffix", "the same 400 body recorded from the 1.5.5 binary"),
        ("test", "test_governance_pool_acl_403_openai_native_envelope", "the pool-ACL 403 arm"),
        ("test", "test_governance_pool_acl_403_bedrock_native_envelope", "the pool-ACL 403 arm on bedrock"),
        ("test", "test_fallback_pool_acl_denies_key_not_allowed_on_fallback_target", "fallback_pools_authorized 403"),
        ("test", "test_finish_refunds_flat_fee_on_non_2xx_keeps_on_2xx", "post-guard exits refund billable on a non-2xx"),
        ("test", "test_pre_routing_failure_does_not_refund_prior_charge", "a pre-routing failure refunds nothing extra"),
        ("test", "test_bedrock_non_object_body_is_400", "the non-object body 400"),
    ],
    "PB-27": [
        ("test", "test_mid_stream_transport_error_does_not_bill_partial_usage", "the SSE-cut arm bills zero"),
        ("test", "test_streaming_translate_abort_trips_breaker_and_skips_billing", "a translate abort bills no tokens"),
        ("test", "test_untranslatable_2xx_does_not_charge_tokens", "a buffered untranslatable 2xx bills zero"),
        ("test", "test_cross_protocol_nonstream_over_cap_body_returns_500_uncharged", "over the translate cap is 500 and uncharged"),
        ("test", "test_streaming_pre_first_byte_transport_error_refunds_budget", "the pre-first-byte cut refunds the lane unit"),
        ("test", "test_truncated_body_does_not_refund_budget", "the post-first-byte cut does not refund the lane unit"),
        ("test", "test_cancel_drop_bills_partial_tokens", "a client disconnect bills the partial tokens"),
        ("test", "test_cancel_drop_mid_stream_refunds_budget", "a client disconnect refunds the lane unit"),
        ("test", "test_finish_refunds_flat_fee_on_non_2xx_keeps_on_2xx", "the flat fee is kept after 2xx headers"),
    ],
    "PB-28": [
        ("test", "enforce_restricts_reapplies_compliance_tags_across_pools", "for a gate, Weighted leaves the candidate set unchanged"),
    ],
    "PB-30": [
        ("test", "resolver_table", "the detect ladder rungs: headers, SigV4 prefix, path suffixes, catch-all"),
        ("test", "test_api_root_unmatched_paths_speak_the_admin_envelope", "/api paths get the frozen admin envelope"),
        ("test", "test_fallback_bedrock_404_is_native_envelope_with_amzn_headers", "fallback_error_response per inferred protocol (bedrock)"),
        ("test", "test_fallback_openai_404_is_json_no_amzn_headers", "fallback_error_response per inferred protocol (openai)"),
    ],
    "PB-31": [
        ("test", "confinement_rejects_hook_out_of_namespace", "/hooks/{owner} confinement"),
        ("test", "confinement_export_metrics_exception_and_reserved_routes", "/exports/{owner} and the /metrics exception"),
        ("test", "route_dispatches_to_handle_http_and_resolves_live_after_swap", "kernel-mounted dispatch from the declared table"),
        ("test", "head_dispatches_to_the_declared_get_route", "HEAD resolves to the declared GET route"),
        ("test", "over_cap_response_headers_are_rejected_not_silently_truncated", "the 64-header cap 502 arm"),
        ("test", "under_cap_response_headers_relay_unchanged", "under the cap headers relay unchanged"),
        ("test", "paths_awaiting_restart_flags_only_newly_declared_unmounted_paths", "a newly declared route path is restart-scoped"),
        ("test", "collision_is_a_loud_failure_naming_the_owner", "a route collision is loud"),
    ],
    "PB-32": [
        ("test", "windows_are_per_principal_per_class_and_refill", "Config 10/min in a 60 s window"),
        ("test", "plugin_inspect_is_classified_into_its_own_dedicated_bucket", "Crud 60/min with PluginInspect in its own bucket"),
        ("test", "only_the_first_denial_in_a_window_is_audited", "the first denial per window is audited"),
        ("test", "test_admin_v1_mutation_rate_limit_config_class", "429 rate_limited enforced before the handler"),
    ],
    "PB-33": [
        ("test", "chooser_renders_0_1_n_buttons", "the 200 text/html chooser"),
        ("test", "redirect_begin_still_redirects", "the 302 to the IdP"),
        ("test", "logout_renders_signed_out_and_clears_cookie", "?logout"),
        ("test", "callback_state_mismatch_400", "?code dispatch with a state check"),
        ("test", "refresh_rotates_key_and_revokes_the_old_one", "?refresh"),
        ("test", "test_mcp_token_is_confined_to_the_mcp_plane", "/auth/token is in the unauthenticated exact-path bypass set"),
        ("gate", "scripts/release-check-1.5.2.sh", "live-hermetic GET /auth/token?method= through the IdP callback to a key"),
    ],
    "PB-34": [
        ("test", "admin_token_secret_ref_re_resolves_on_apply", "the admin token re-resolves on apply through the deferred rotation"),
        ("test", "signing_key_secret_ref_re_resolves_on_apply_and_fails_closed", "auth.signing_key re-resolves on apply"),
        ("test", "blank_admin_token_refuses_to_start", "fail-closed empties"),
        ("test", "env_module_resolves_and_fails_closed", "env built-in: trailing newline trim and the error texts"),
        ("test", "file_module_resolves_and_fails_closed", "file built-in: trim and fail-closed"),
        ("test", "malformed_builtin_refs_error_precisely", "the strict two-way env/file match"),
        ("test", "literal_wrapper_opts_a_setting_out_of_secret_coercion", "classify_setting's one-level literal passthrough"),
        ("test", "unresolvable_secret_ref_setting_fails_closed_naming_field", "an unresolvable setting ref fails closed"),
        ("test", "secret_ref_builtin_modules_pass_with_empty_registry", "built-ins resolve with no plugin registry"),
        ("test", "secret_ref_wrong_kind_plugin_fails_at_preflight", "a wrong-kind plugin ref fails at preflight"),
    ],
    "PB-35": [
        ("test", "test_empty_chain_is_open_front_door", "an empty chain is Open with or without a credential"),
        ("test", "test_nonempty_chain_fails_closed_on_all_pass", "all-Pass without a keys arm is Denied"),
        ("test", "test_keys_in_chain_sets_flag_not_module", "the keys arm sets keys_in_chain and boxes no module"),
        ("test", "test_chain_identifies_with_module_and_principal", "the first Identify wins"),
        ("test", "test_extract_client_token_precedence_is_authorization_first", "carrier precedence: Authorization first"),
        ("test", "test_extract_client_token_non_bearer_authorization_falls_through_to_x_api_key", "a non-Bearer Authorization falls through to x-api-key"),
        ("test", "test_extract_client_token_non_bearer_authorization_falls_through_to_x_goog_api_key", "a non-Bearer Authorization falls through to x-goog-api-key"),
        ("test", "verdict_rules_and_expiry", "Identify TTL clamp, Pass TTL, Reject never cached"),
        ("test", "bounded_eviction", "the MAX_ENTRIES cap"),
        ("test", "module_partitions_and_flush", "the cache is keyed per module and flush counts"),
        ("test", "an_unauthenticated_chain_admits_nothing_to_the_cache", "run_chain_cached caches nothing for a denied chain"),
        ("test", "test_admin_v1_credential_cache_and_flush_endpoint", "POST /auth/cache/flush returns a real flushed count"),
    ],
    "PB-36": [
        ("test", "admin_scope_resolution", "admin_auth [] grants Scope::Full when no principal"),
    ],
    "PB-38": [
        ("test", "add_usage_sweeps_stale_windows", "the add_usage sweep by window_start"),
        ("test", "add_usage_sweep_boundary_is_exact", "strict > on the usage sweep boundary"),
        ("test", "add_metering_sweeps_stale_buckets", "the add_metering sweep by bucket age"),
        ("test", "add_metering_sweep_boundary_is_exact", "strict > on the metering sweep boundary"),
        ("test", "put_key_sweeps_stale_tombstones", "the put_key tombstone sweep"),
        ("test", "put_credential_sweeps_stale_revoked_creds", "the put_credential revoked-only sweep"),
        ("test", "test_budget_sweep_staleness_boundary_is_exact", "the idle cell sweep boundary is strict"),
        ("test", "test_budget_sweep_evicts_idle_attribution_cells_but_never_group_caps", "a cell survives while it still enforces a cap or is dirty"),
        ("test", "test_budget_sweep_only_exempts_group_cells_that_still_enforce_a_cap", "the still_enforces_a_cap predicate"),
    ],
    "PB-39": [
        ("test", "test_admin_v1_config_settings_process_level_flagged_reload_to_apply", "listen, admin_listen, tls, admin_tls, admin_require_mtls, store are stored but flagged"),
        ("test", "test_admin_v1_config_settings_boot_scoped_limits_flagged_reload_to_apply", "the boot-scoped limits keys are flagged; request_body_max_bytes is not"),
        ("test", "test_admin_v1_config_settings_max_inbound_concurrent_flagged_reload_to_apply", "max_inbound_concurrent is restart-scoped"),
        ("test", "test_admin_v1_config_settings_boot_scoped_observability_flagged_reload_to_apply", "the observability keys are restart-scoped"),
        ("test", "test_admin_v1_export_put_that_adds_a_route_reports_restart_required", "a newly declared plugin route path is restart-scoped, with the note on the named-map mutation"),
        ("test", "test_admin_v1_config_reload_swaps_disk_truth_and_carries_health", "config/reload re-reads disk and keeps config_version on a rejected reload"),
    ],
    "PB-40": [
        ("gate", "scripts/config-stability-gate.sh", "the config grammar is frozen against a committed snapshot; deny_unknown_fields flips and breaking deltas are red"),
        ("test", "test_plugins_trust_allow_unsigned_injection_already_fails_via_deny_unknown_fields", "an unknown key is refused by deny_unknown_fields"),
    ],
    "PB-43": [
        ("test", "test_is_ready_any_cell_false_when_every_cell_open", "healthz readiness is false when every cell is open"),
        ("test", "test_is_ready_any_cell_true_when_a_pool_cell_is_ready", "any per-pool cell ready makes the node ready"),
        ("test", "test_is_ready_is_side_effect_free", "the readiness peek never steals the recovery probe"),
        ("test", "healthz_returns_a_real_response_not_the_default", "the 503 body is literally no usable lanes"),
        ("test", "thread_per_core_boots_and_serves_healthz", "/healthz is served unauthenticated on a real listener"),
        ("test", "counter_renders_with_hook_label_and_verbatim_name", "/metrics/hooks: one hook label, no prefixing"),
        ("test", "histogram_renders_as_summary", "a bucketless histogram renders as a summary"),
        ("test", "busbar_prefix_is_reserved", "busbar_-prefixed hook metrics are dropped"),
        ("test", "type_conflict_for_shared_name_is_dropped", "first-occurrence type wins"),
        ("test", "test_stats_reports_at_capacity_when_lane_saturated", "/stats per-lane fields and the Unavailable classification"),
        ("test", "test_stats_limit_is_numeric_alias_of_max_concurrent", "/stats limit and the unbounded string"),
        ("test", "test_recovery_hint_ms", "the recovery_hint_ms floor of 2000"),
    ],
    "PB-45": [
        ("test", "a_failed_read_does_not_close_the_staleness_window", "one denylist re-sync attempt per REVOCATION_SYNC_TTL_SECS window"),
        ("test", "a_successful_read_unions_and_closes_the_window", "the re-sync unions and closes the window"),
        ("test", "a_hung_store_does_not_park_the_reactor", "the re-sync runs on the blocking pool"),
        ("test", "test_key_state_distinguishes_disable_revoke_and_tombstone", "enabled=false is a reversible pause with no denylist row"),
        ("test", "local_revoke_rejects_the_very_next_auth_attempt", "revoke is synchronous on the serving node"),
    ],
    "PB-47": [
        ("test", "pool_scoped_accrual_and_refund_mirror_the_charge", "accrual and refund land on the pool the admission charged"),
        ("test", "budget_block_carries_downgrade_target", "the block names the downgrade pool"),
        ("test", "test_budget_exhaustion_downgrades_pool", "admission lands on the effective post-downgrade pool"),
        ("test", "test_downgrade_cycle_terminates_via_the_revisit_guard", "the visited-set guard prevents a double charge"),
    ],
    "PB-49": [
        ("test", "a_read_only_config_dir_boots_without_an_overlay_instead_of_refusing", "the boot writability posture of the overlay"),
        ("test", "f_every_persist_entry_point_refuses_a_none_locked_overlay", "NO_WRITABLE_OVERLAY_MSG at every persist site"),
        ("test", "d_overlay_precedence_config_over_env_over_default", "config.overlay over BUSBAR_CONFIG_OVERLAY over the default"),
        ("test", "write_is_0600", "the overlay file mode 0o600"),
        ("test", "merge_into_applies_tombstones", "overlay tombstones"),
        ("test", "safe_mode_requested_matches_the_exact_flag_only", "the --safe-mode flag match"),
    ],
    "PB-50": [
        ("test", "every_shipped_config_migrates_to_a_valid_current_config", "every shipped config.yaml migrates and validates through the real binary"),
        ("test", "a_migration_with_nothing_to_decide_emits_no_comment_banner", "no banner when nothing to decide"),
        ("test", "legacy_markers_detected_and_named", "the 1.x markers are detected and named"),
        ("test", "detect_real_14x_top_level_and_on_exhausted_markers", "1.4.x markers detected"),
    ],
    "PB-51": [
        ("test", "otlp_level_floors_at_debug_and_never_trails_stderr", "the OTLP level floors at DEBUG independently"),
    ],
    "PB-52": [
        ("test", "worker_threads_from_env_parses_valid_rejects_invalid", "BUSBAR_WORKER_THREADS: 0 warns and is ignored"),
        ("test", "validate_worker_threads_config_diagnoses_zero", "advanced.worker_threads 0 is diagnosed"),
        ("test", "worker_threads_from_config_reads_a_real_file", "advanced.worker_threads is read from the config file"),
        ("test", "busbar_providers_env_is_deprecated_but_honored", "BUSBAR_PROVIDERS still wins and prints the deprecation warning"),
        ("test", "d_overlay_precedence_config_over_env_over_default", "config wins for BUSBAR_CONFIG_OVERLAY"),
        ("test", "validate_honors_deprecated_busbar_config_overlay_env_var", "the env fallback on the CLI path"),
    ],
    "PB-53": [
        ("test", "metrics_route_declared_only_when_configured", "/metrics is declared only with export.prometheus"),
    ],
    "PB-54": [
        ("lint", "scripts/tracing-lint.sh", "every instrument span declares an explicit level"),
        ("oracle-family", "cli", "CLI flags and env cells diffed against the 1.5.5 binary"),
    ],
    "PB-55": [
        ("test", "test_health_probe_recovers_tripped_lane", "mode dead: a 2xx probe recovers a tripped lane"),
        ("test", "test_health_probe_failure_records_transient", "mode active: a failing probe records transient"),
        ("test", "test_probe_auth_failure_is_hard_down_not_transient", "a probe auth failure is hard-down"),
        ("test", "test_probe_client_fault_does_not_penalize_lane", "a probe client fault does not penalize"),
        ("test", "a_swap_does_not_push_the_probe_deadline_out", "the probe schedule is inherited across a swap"),
    ],
    "PB-56": [
        ("test", "redirects_surface_verbatim_and_are_followed_by_neither_stack", "redirect Policy::none"),
    ],
    "PB-57": [
        ("test", "test_zero_weight_member_is_never_selected", "weight-0 lanes are filtered before selection"),
        ("test", "test_swrr_no_open_selection", "an open lane is filtered before the credit walk"),
        ("test", "test_swrr_all_down_returns_none", "all down selects none"),
        ("test", "a_saturated_primary_is_passed_over_inside_the_one_loop_and_the_twin_serves", "only an at-capacity lane reaches try_admit after selection"),
    ],
    "PB-59": [
        ("test", "test_two_node_flush_is_additive_no_lost_update", "add_usage is an atomic accumulate across two nodes"),
        ("test", "accrual_and_hydrate_cover_every_chain_bucket", "a fresh node hydrates each bucket from the store"),
    ],
    "PB-60": [
        ("test", "oversized_request_413_is_reshaped_on_the_live_stack", "an oversized POST answers a 413 JSON envelope on the live stack"),
        ("test", "test_oversized_body_413_bedrock_native_envelope_with_amzn_headers", "the bedrock 413 carries the x-amzn headers"),
        ("test", "test_axum_marker_413_is_reshaped_even_as_plain_text", "the reshape fires only on the AXUM_BODY_LIMIT_413_MARKER"),
        ("test", "test_relayed_upstream_413_not_reshaped", "a relayed upstream 413 passes through untouched"),
        ("test", "test_reshape_oversized_413_passthrough", "non-413 and already-JSON pass through"),
    ],
    "PB-62": [
        ("test", "required_scope_matrix", "reads are read-only, mutations full, config/validate and plugins/inspect read-only"),
        ("test", "required_scope_mutations_are_full", "every mutation requires full"),
        ("test", "openapi_paths_annotate_required_scope", "x-busbar-required-scope equals the enforced scope on every path"),
    ],
    "PB-63": [
        ("test", "admin_token_secret_ref_re_resolves_on_apply", "an apply reuses the same GovState"),
        ("test", "plugin_reload_reports_an_unrebuildable_disk_config", "plugins/reload fails closed on a broken disk config"),
        ("test", "kind_restart_default_matches_binding_lifecycle", "kind_restart_default per plugin kind"),
    ],
    "PB-64": [
        ("test", "next_refresh_never_sleeps_past_a_live_token_expiry", "REFRESH_SKEW_SECS and MIN_SLEEP_SECS"),
        ("test", "headers_for_emits_nothing_before_first_mint", "no header before the first mint"),
        ("test", "is_ready_false_before_first_mint_true_after", "is_ready is false pre-mint so the prober skips the lane"),
        ("test", "cached_token_new_omits_header_for_bytes_invalid_in_a_header_value", "an unencodable credential omits the header"),
        ("test", "headers_for_reflects_prebuilt_header_after_a_refresh", "the header is built once at mint"),
        ("test", "token_response_tolerates_expires_in_as_number_string_or_absent", "expires_in defaults to 3600"),
    ],
    "PB-65": [
        ("test", "test_auth_headers_valid_key_emits_x_goog_api_key", "the x-goog-api-key header name"),
        ("test", "auth_headers_api_key_emits_only_x_api_key", "api-key emits x-api-key with anthropic-version"),
        ("test", "auth_headers_unrecognized_credential_emits_both_headers", "the mode-blind arm emits both headers"),
        ("test", "classify_credential_covers_each_family", "the anthropic key-prefix disambiguation"),
        ("test", "auth_headers_oauth_token_emits_only_authorization_bearer", "an oauth token emits only Authorization"),
        ("test", "test_bedrock_sigv4_sign_request_structure", "the SigV4 SignedHeaders line"),
        ("test", "test_bedrock_sigv4_session_token", "the access:secret:session split"),
        ("test", "test_bedrock_sigv4_misconfigured_key_no_signature", "a misconfigured key signs nothing"),
    ],
    "PB-66": [
        ("test", "non_allowlisted_client_header_is_not_forwarded", "a non-allowlisted client header never reaches the upstream"),
        ("test", "test_egress_accept_matches_native_sdk", "the pinned accept group incl. the bedrock eventstream override"),
        ("test", "test_egress_ua_versions_are_pinned_and_present", "the pinned native-SDK user-agent"),
        ("test", "test_ingress_stream_content_type_by_protocol", "streaming_content_type per ingress writer"),
        ("test", "test_bedrock_ingress_success_carries_amzn_request_id", "bedrock relays x-amzn-requestid"),
        ("test", "test_forward_once_bedrock_error_relays_amzn_headers", "bedrock relays x-amzn-errortype"),
        ("test", "test_anthropic_ingress_success_carries_request_id_header", "anthropic relays request-id"),
        ("test", "test_anthropic_same_proto_error_relays_upstream_request_id_verbatim_once", "request-id relayed verbatim exactly once"),
        ("test", "test_synth_anthropic_request_id_is_well_formed", "the synthesized req_01 + 24 base62 id"),
    ],
    "PB-67": [
        ("test", "test_cross_protocol_error_kind_mapping", "the status to kind table as wire literals"),
        ("test", "test_shape_cross_protocol_error_auth_kinds", "the ingress-native envelope with the canonical kind"),
        ("test", "test_ingress_error_bedrock_amzn_headers", "the bedrock error envelope headers"),
        ("test", "test_vendor_auth_failure_message_is_plausible_per_proto", "per-dialect auth-failure envelopes incl. bedrock 403 and gemini 400"),
        ("test", "test_bedrock_ingress_wrong_token_is_403_native_envelope", "the bedrock 403 end to end"),
        ("test", "error_kind_to_bedrock_type_covers_ingress_emitted_kinds", "the kind to native table"),
        ("test", "test_openai_classify", "the OpenAI-family kind literals"),
        ("test", "write_error_kind_vocabulary_mapping", "the anthropic kind vocabulary"),
    ],
    "PB-68": [
        ("test", "test_ssrf_blocks_metadata_denylist_by_default", "the hardcoded denylist, the six hostnames and the alternate-IPv4 expansion"),
        ("test", "test_ssrf_blocked_returns_exact_host_string", "the canonicalizer's returned host"),
        ("test", "test_reject_cidr_metadata_entries", "CIDR entries are rejected at boot"),
        ("test", "test_global_allow_overrides_blocked_metadata_hosts", "allow_overrides wins over the denylist"),
        ("test", "test_allow_all_metadata_beats_nonempty_blocked_list", "allow_all is the first conjunct"),
        ("test", "test_ssrf_allows_private_and_loopback_by_default", "no over-blocking, no runtime DNS check"),
        ("test", "test_validate_rejects_non_https_base_url", "the public-https / private-http scheme rule literals"),
        ("test", "test_validate_token_url_ssrf_and_scheme", "the same rules on token_url"),
        ("test", "the_shared_internal_predicate_covers_every_range_any_plane_ever_checked", "one shared predicate across planes"),
    ],
    "PB-73": [
        ("test", "server_timing_header_absent_by_default_present_when_enabled", "Server-Timing absent by default, on every response when enabled"),
        ("test", "route_policy_headers_absent_by_default_on_the_live_stack", "the route headers are absent by default"),
        ("test", "route_policy_headers_absent_for_a_default_policy_even_when_outer_gate_enabled", "no route headers for the SWRR floor even when enabled"),
        ("test", "route_policy_headers_present_only_when_both_gates_open", "route headers only when route_policy and a non-default ordering"),
        ("test", "test_emit_server_timing_moved_to_advanced_response_headers", "both flags default false"),
        ("lint", "scripts/response-header-lint.sh", "every injected response header is an opt-in advanced.response_headers toggle from one site"),
    ],
    "PB-74": [
        ("test", "reserved_hook_names_are_frozen", "RESERVED_HOOK_NAMES equals its frozen membership and a frozen word fails boot"),
        ("test", "test_validate_allows_api_prefixed_but_boundary_safe_names", "reserved_admin_name membership"),
        ("gate", "scripts/config-stability-gate.sh", "no legal earlier config.yaml becomes a boot failure (additive-only grammar)"),
    ],
    "PB-75": [
        ("test", "openapi_json_matches_committed_file", "the committed openapi.json byte-equals a fresh render"),
        ("test", "served_openapi_equals_committed_file", "the served document byte-equals the committed file"),
    ],
    "PB-76": [
        ("test", "split_admin_listener_no_double_exposure", "admin routes are absent (hard 404) on the data listener"),
        ("test", "auth_token_absent_from_admin_router", "/auth/token is a data-listener verb only"),
        ("test", "admin_auth_route_is_absent_from_the_data_listener", "plugin admin routes are absent from the data listener"),
        ("test", "test_api_root_unmatched_paths_speak_the_admin_envelope", "unmatched path 404 not_found and wrong method method_not_allowed envelopes"),
    ],
    "PB-77": [
        ("test", "test_signing_key_rotate_reports_kid_and_revoke_all", "rotate is report-only with the signing_key.report audit action"),
    ],
    "PB-79": [
        ("test", "missing_group_fails_closed", "MissingGroup fails closed at admission"),
        ("test", "disabled_group_freezes_the_chain", "a frozen group blocks the chain"),
        ("test", "chain_and_parent_blocks_child_and_charges_nothing", "a parent block charges nothing"),
        ("test", "total_window_blocks_without_retry_after", "a block without Retry-After"),
        ("test", "test_try_admit_rejects_at_group_cap", "the concurrent refusal carries retry_after None"),
        ("test", "test_chain_enforcement_rejects_naming_the_blocking_group", "the first blocking bucket names the refusal"),
        ("test", "test_governance_rate_limit_429_native_envelope_all_ingress", "requests refusal is 429 rate_limit_error on every ingress"),
        ("test", "test_budget_over_quota_bedrock_envelope", "budget refusal is the Bedrock 400"),
    ],
    "PB-80": [
        ("test", "backoff_saturates_not_wraps_at_high_streak", "the shift saturates rather than wrapping"),
        ("test", "test_cooldown_jitter_is_symmetric", "the plus/minus jitter"),
        ("test", "test_retry_after_exceeds_max_cooldown", "the max_cooldown_secs clamp"),
        ("test", "test_probe_failure_honors_retry_after_floor", "honor_retry_after as a floor"),
        ("test", "test_retry_after_not_honored_ignores_server_value", "the flag off ignores the server value"),
        ("test", "test_hard_down_long_cooldown_and_recovery", "hard_down_cooldown_secs"),
        ("test", "test_single_flight_probe", "the single-flight half-open probe"),
        ("test", "test_floor_prevents_trip", "min_requests"),
        ("test", "test_trip_on_error_rate", "threshold"),
        ("test", "test_consecutive_trip_mode", "consecutive_n"),
        ("test", "hard_down_all_cells_records_a_logical_trip", "logical-trip counting"),
        ("test", "test_escalating_cooldown_on_repeated_trips", "cooldown escalates with the streak"),
    ],
    "PB-81": [
        ("test", "hook_calls_are_capped_and_saturation_fails_on_the_caller_deadline", "the MAX_INFLIGHT_HOOK_CALLS cap"),
        ("test", "dlopen_slow_gate_hits_the_deadline", "call_bounded cuts a slow gate at its budget"),
        ("test", "dlopen_plugin_panic_is_fail_closed_err", "a panicking plugin is a fail-closed error"),
        ("lint", "scripts/blocking-ffi-lint.sh", "every plugin transport call is made from a blocking context"),
    ],
    "PB-82": [
        ("test", "read_response_subtracts_cached_prefix_from_prompt_tokens", "openai: the cached count is subtracted from the prompt total"),
        ("test", "read_response_subtracts_cached_prefix_from_input_tokens", "responses: the cached count is subtracted"),
        ("test", "test_cached_content_token_count_reads_into_cache_read", "gemini: the cached count reads into cache_read"),
        ("test", "test_gemini_usage_counts_thinking_tokens_as_output", "gemini tokens_out includes thoughtsTokenCount"),
        ("test", "adds_include_usage_when_absent", "stream_options.include_usage is forced upstream"),
        ("test", "test_streaming_openai_egress_without_client_opt_in_still_gets_include_usage_injected", "injection happens without client opt-in"),
        ("test", "strip_same_proto_usage_fires_without_object_field", "the same-protocol hide-back seam"),
    ],
    "PB-83": [
        ("test", "test_pool_breaker_isolation", "independent breaker state per (pool, lane)"),
        ("test", "test_record_hard_down_all_cells_trips_default_and_every_pool", "the hard-down park fans out across the default and every pool cell"),
        ("test", "test_budget_is_lane_global_across_pools", "the lifetime max_requests is lane-global"),
        ("test", "test_unbounded_lane_skips_the_semaphore_bounded_still_enforces", "max_concurrent is lane-global"),
    ],
    "PB-84": [
        ("test", "completion_tap_reports_ok_outcome", "the response stage reports ok"),
        ("test", "completion_tap_fires_synthetic_rejected_by_gate", "the synthetic outcome rejected_by_gate"),
    ],
    "PB-85": [
        ("test", "per_model_then_global_then_4096", "default_max_tokens is injected only when the IR carries none; a caller value survives"),
        ("test", "test_requires_max_tokens_per_protocol", "the per-dialect requires_max_tokens table"),
        ("test", "test_openai_explicit_max_tokens_preserved_over_lane_default", "an explicit client value is never rewritten on a real forward"),
        ("test", "test_openai_omits_max_tokens_injects_fallback_for_anthropic", "injection on a cross-protocol forward"),
    ],
    "PB-87": [
        ("test", "rerank_resp_billing_is_flat", "rerank projects Billing::Flat"),
        ("test", "rerank_resp_billing_flat_regardless_of_search_units", "Flat survives reported search units"),
    ],
    "PB-88": [
        ("test", "bad_request_reject_keeps_the_unchanged_generic_400", "the literal 400 We could not process the content of your request"),
        ("test", "req_bedrock_to_cohere", "a cross-pair request translates to a golden with no refusal"),
        ("test", "resp_responses_to_gemini", "a cross-pair response translates to a golden with no refusal"),
    ],
    "PB-90": [
        ("test", "every_shipped_config_migrates_to_a_valid_current_config", "the shipped corpus, which carries these keys, still migrates and validates"),
        ("test", "every_patch_mirrors_every_field_of_its_section", "the limits keys still exist and are mirrored by the patch"),
        ("test", "resolved_billing_and_limits_config_is_byte_stable", "resolved billing and limits are byte-stable across the corpus"),
        ("gate", "scripts/config-stability-gate.sh", "a key cannot silently stop landing (additive-only grammar)"),
    ],
    "PB-91": [
        ("test", "refund_returns_the_fee_but_never_the_requests_limit_slot", "a refund returns the fee but never the requests slot"),
        ("test", "test_finish_refunds_flat_fee_on_non_2xx_keeps_on_2xx", "the fee follows the client-facing status"),
    ],
    "PB-94": [
        ("test", "test_passthrough_forwards_caller_token", "passthrough sends the caller token"),
        ("test", "sign_request_resolves_ambiguous_credential_to_single_header_by_mode", "passthrough vs own picks one header"),
        ("test", "override_present_runs_full_lookup", "a pool scalar replaces the section default"),
        ("test", "golden_migrate_auth_upstream_credentials_moves_to_pools", "the 1.5.5 key lands under pools"),
    ],
    "PB-95": [
        ("test", "attempt_tap_carries_attempt_story", "the routing-stage payload carries a 1-based attempt_number"),
        ("test", "route_tap_reports_surviving_candidates", "remaining_candidates on the candidate stage"),
    ],
    "PB-96": [
        ("test", "test_translate_anthropic_egress_to_openai_ingress", "[DONE] for an openai ingress"),
        ("test", "test_translate_openai_egress_to_anthropic_ingress", "no [DONE] for an anthropic ingress"),
        ("test", "bedrock_stream_framing_emits_one_metadata_delta_then_guards_duplicate", "the bedrock exactly-one-metadata invariant"),
        ("test", "test_translate_openai_include_usage_egress_to_bedrock_ingress_single_metadata", "the bedrock two-frame split decodes through a real eventstream decoder"),
        ("test", "test_duplicate_terminal_message_delta_after_stop_is_dropped", "the post-stop ordering guard"),
        ("test", "test_tool_id_remap_is_a_stable_reversible_bijection", "the bb1 tool-id remap bijection"),
        ("test", "cohere_tool_ids_pass_through_verbatim_no_decode", "the even-length reverse decode guard"),
        ("test", "strip_same_proto_usage_fires_without_object_field", "the same-proto usage hide-back"),
    ],
    "PB-97": [
        ("test", "head_pristine_matches_translate_output", "head_provably_pristine re-emits the retained bytes"),
        ("test", "non_object_body_is_head_pristine", "a non-object body is pristine"),
        ("test", "pristine_same_proto_is_byte_identical_body_model", "an unmodified same-dialect request reaches upstream byte-identical"),
        ("test", "pristine_same_proto_is_byte_identical_url_model", "same, with the model on the path"),
        ("test", "claude_on_vertex_drops_model_and_injects_anthropic_version", "the Claude-on-Vertex shim literal"),
        ("test", "invalidator_3_model_rewrite_forces_non_pristine", "a rewrite takes the encode_egress path"),
        ("test", "invalidator_4_same_proto_model_shim_strip_forces_non_pristine", "strip_same_protocol_model_shim forces re-encode"),
    ],
    "PB-98": [
        ("test", "test_normalize_raw_error_with_provider_override", "the provider code is first in the error_map ladder"),
        ("test", "restored_halfopen_state_normalizes_to_open", "HalfOpen restores as Open"),
        ("test", "restore_does_not_clobber_new_limit_with_unlimited_sentinel", "the budget carry-over rule on restore"),
        ("test", "test_hard_down_follows_identity_across_rebuild", "(model, provider) identity across a config apply"),
        ("test", "least_busy_prefers_most_headroom", "least_busy native"),
        ("test", "least_busy_all_saturated_ranks_by_idx", "least_busy never abstains"),
        ("test", "cheapest_all_unknown_abstains", "cheapest abstains when every signal is missing"),
        ("test", "usage_all_unknown_abstains", "usage abstains when every signal is missing"),
        ("test", "fastest_orders_by_latency", "fastest native"),
        ("test", "from_ranked_never_produces_reject", "reply precedence: an order never becomes a reject"),
        ("test", "from_ranked_empty_is_abstain", "an empty order is abstain"),
        ("test", "dlopen_notify_is_fire_and_forget", "the notify op is fire-and-forget"),
    ],
    "PB-99": [
        ("test", "test_metering_accumulates_split_per_key_model_and_bucket", "the flushed row literals key_group_at_use, pricing_version, billable_requests"),
        ("test", "test_record_metering_from_ir_usage_and_flat", "a flat-fee op still counts the request"),
        ("test", "test_additive_flush_carries_refund_deltas", "billable_requests deltas verbatim"),
        ("test", "delete_key_tombstones_and_cascades_usage_and_creds", "delete_key destroys usage rows and credentials"),
        ("test", "scrub_key_requires_tombstone_first", "scrub_key nulls PII only on a tombstone"),
    ],
    "PB-100": [
        ("test", "test_admin_v1_key_idempotent_mint_and_if_match", "stale If-Match is 409 and the ETag is header-only"),
        ("test", "test_admin_v1_overlay_reset_hooks_reverts_to_base", "a stale reset is version_conflict"),
        ("test", "keys_error_surface_is_byte_stable", "the keys error surface incl. malformed If-Match is byte-stable"),
        ("test", "admin_error_surface_witnesses_every_declared_response", "every declared admin error response is witnessed"),
        ("test", "declared_error_set_is_exactly_what_the_handlers_emit", "the MalformedIfMatch row is emitted by the handler"),
        ("test", "record_list_get_and_bound", "VersionLog MAX_VERSIONS bound"),
        ("test", "exchange_ok_body_includes_base_url_equal_to_public_url", "POST /auth/token base_url is public_url verbatim"),
        ("test", "begin_sets_httponly_secure_cookie_and_redirects", "the GET /auth/token begin flow"),
        ("test", "callback_state_mismatch_400", "constant-time state check"),
        ("test", "callback_nonce_mismatch_rejected", "the id_token nonce"),
        ("test", "execute_hop_refuses_non_allowlisted_host", "the hop host allowlist"),
        ("test", "vet_hop_url_enforces_https_allowlist_and_blocks_metadata", "ssrf_blocked_host on hops"),
        ("test", "execute_hop_does_not_follow_redirect", "hops never follow redirects"),
        ("test", "refresh_rotates_key_and_revokes_the_old_one", "?refresh rotates and revokes"),
    ],
    "PB-101": [
        ("test", "test_verify_sigv4_ingress_credential_unsigned_payload_rejected", "UNSIGNED-PAYLOAD is refused"),
        ("test", "test_verify_sigv4_ingress_credential_body_matches_signed_hash_admits", "the pre-buffer structural gate admits a matching body"),
        ("test", "test_verify_sigv4_ingress_credential_tampered_body_rejected", "a tampered body is refused"),
        ("test", "test_verify_inbound_sigv4_unknown_key_dummy_secret_is_signature_mismatch", "DUMMY_SECRET constant-time reject"),
        ("test", "throughput_floor_trips_on_a_dribble_the_inter_frame_timer_cannot_catch", "MIN_BODY_THROUGHPUT_BYTES_PER_SEC and the grace"),
        ("test", "a_fast_large_upload_is_not_killed_by_the_throughput_floor", "the floor does not kill a fast upload"),
        ("test", "total_deadline_trips_on_a_body_that_stays_above_the_floor_forever", "the total body deadline"),
        ("test", "body_read_timeout_trips_on_stalled_body", "the inter-frame read timeout"),
        ("test", "mtls_valid_client_cert_gets_200", "mTLS required-or-none admits a valid cert"),
        ("test", "mtls_rejects_bad_client_then_serves_valid", "mTLS rejects a bad client with no HTTP status"),
    ],
}

# ── Findings the survey turned up that the owner must see next to the binding ────────────────────
# A green test that asserts the OPPOSITE of a binding is not a proof; it is a design/code conflict.
# These are carried on the entry as `note` and never counted as checks.
NOTES: dict[str, str] = {
    "PB-7": "CONTRADICTED by a green test: crates/busbar-core/src/tests/tests.rs test_inbound_over_capacity_queues_fifo_and_serves_when_freed asserts an over-cap arrival queues FIFO and is served 200, not the 503 + Retry-After: 1 the binding requires. Owner decision needed: binding or code.",
    "PB-11": "CONTRADICTED in part by green tests: crates/plugin-loader/src/tests/registry_tests.rs store_abi_below_or_above_the_range_is_refused_naming_v2_to_v4 and supported_abi_store_floor_admits_v2 pin a store window of v2..=v4, where the binding requires v2..=v2 and refuses ABI 3/4. The plugins.load cells prove the trust/skip half only.",
    "PB-84": "In tension with green tests: hook_seam_tests.rs completion_tap_fires_synthetic_rejected_by_auth asserts a completion tap fires on an auth denial, where the binding says pre-forward refusals never tap.",
    "PB-75": "The mapped goldens pin served == committed today; openapi_doc_is_31_and_v1_prefixed asserts info.version tracks the crate version, which is the opposite of a 1.5.5-verbatim pin. Treat as partial.",
    "PB-13": "data_dir, DataDirNotWritable, KeysetMissing and wal_capacity do not exist in crates/ yet; the binding is vacuously true and nothing tests it.",
    "PB-15": "No WAL or high-water concept exists in crates/ yet; vacuously true, untested.",
    "PB-48": "max_unit_duration does not exist in crates/; the stall sweep is not built, so the binding is vacuously true.",
    "PB-8": "The mapped tests cover the deadline, context_max exclusion and attempt caps; DETAIL_REQUEST_TIMEOUT is asserted by no test and max_unit_duration does not exist yet.",
    "PB-66": "CONTRADICTED in part by green tests: crates/busbar-llm/src/engine/tests/client_header_forwarding_tests.rs client_anthropic_beta_reaches_matching_anthropic_upstream and client_openai_beta_reaches_matching_openai_upstream assert an allowlisted anthropic-beta / OpenAI-Beta client header DOES ride upstream, where the binding says NO client request header is forwarded. Owner decision needed.",
    "PB-60": "oversized_request_413_is_reshaped_on_the_live_stack documents that the body cap fires before auth buffers the body on the admin leg; the binding says the cap is enforced inside the handler after auth. Worth an owner read; the http.crosscut 413 cells diff the real order against 1.5.5.",
    "PB-58": "OverBudget, OverdraftCeiling and StaleSlice do not exist in crates/; vacuously true, untested.",
    "PB-61": "MAX_NEEDMORE_FRAMES does not exist in crates/; no test drives a multi-chunk body to the cap.",
}

# ── Suggestions for unmapped bindings: what check would prove it ─────────────────────────────────
# One line per binding: the cheapest check that would move it to `mapped`. Used only while unmapped.
SUGGEST: dict[str, str] = {
    "PB-0": "oracle-family coverage gate: every row id of docs/design/inventory/*.md appears in at least one cells.json cell (a derived cell-count test, red on any inventory row with no cell)",
    "PB-1": "engine unit test: gate restrict-empty with on_empty absent and with `first` both render the 503 KIND_OVERLOADED literal; plus a hooks-family oracle cell",
    "PB-2": "engine unit test: a lane at max_concurrent is skipped (try_admit AtCapacity) with no wait; `on_exhausted: queue` waits at most max_ms",
    "PB-3": "select/walk unit test: tripped, budget-exhausted and at-capacity lanes are absent from the walk order and the pool falls to on_exhausted after the requests charge",
    "PB-4": "walk unit tests per terminal: default 503 Retry-After from soonest cooldown else 2; least_bad one attempt; fallback_pool visited guard; queue parks only on AtCapacity (route.failover cells cover fo/lb only)",
    "PB-5": "select unit test: sticky-affinity fast path, stable priority sort, last ordering gate wins, ready_in peek, SWRR fallthrough (route.failover|fo|all-up covers only the happy order)",
    "PB-6": "engine unit test: rewrite-gate Reject and decision-gate reject consume the requests slot and refund billable; request-stage tap errors are swallowed",
    "PB-7": "axum test: with max_inbound_concurrent=1 every listed data route sheds 503 with Retry-After: 1 while the admin listener answers; plus an http.crosscut cell",
    "PB-8": "engine unit test with a mock upstream: 120 s walk deadline pre-attempt 503 DETAIL_REQUEST_TIMEOUT, reqwest timeout only when not streaming, context_max exclusion set",
    "PB-9": "auth unit test: revoke/rotate does not abort an in-flight unit; generation gate refuses the old token on the next request on the serving node",
    "PB-10": "table-driven unit test over the 31 disposition rows asserting status, kind literal, breaker record and metric labels; one llm.wire upstream_down cell per row",
    "PB-11": "plugins.load cells cover trust/skip; add a plugin-loader unit test for the exact `manifest abi_version {n} is not supported` literal and the per-kind windows",
    "PB-12": "export unit tests: the 16 validate-time refusal literals, MAX_INFLIGHT_FILE_APPENDS=64, `durable: true` refused; boot.refusal cells for each refused stream",
    "PB-13": "boot test: a config with no data_dir writes no data-dir files and emits no KeysetMissing/DataDirNotWritable; boot.warning cell with data_dir unset",
    "PB-14": "store-outage integration test: admission proceeds and /usage returns 500 AdminError::Internal while the store is down; boot refuses on a hydrate error",
    "PB-15": "unit test: WAL is absent when data_dir is unset and admission never returns a WAL refusal on a migrated config",
    "PB-16": "billing cell family: byte-identical /usage after each exit class; unit test that an undelivered unit writes no metering row and refunds the fee",
    "PB-17": "boot.warning oracle family gate: warning count on every 1.5.5 corpus config equals the golden's (config.migrate cells could carry the warning count)",
    "PB-18": "unit test: budgets derived from max_inbound_concurrent, and 0 leaves every derived budget unbounded; a body 1.5.5 accepted is accepted",
    "PB-19": "governance unit test: a key bound to an absent group is refused insufficient_quota 429 (400 on bedrock) with the literal message; over_budget cell variant",
    "PB-20": "audit unit test: 8 wire fields, genesis prev_hash empty, SHA-256 over the canonical string, 1000-entry ring; admin.ops|GetAudit cell",
    "PB-21": "admin.ops idempotent-replay cells cover replay; add a unit test for the in-flight 409 conflict envelope and the TTL 600 s",
    "PB-22": "governance unit test: check-then-charge order, first blocking bucket names the 429, requests/billable +1 on every bucket of the chain, budget formula",
    "PB-23": "cli|--safe-mode|first-arg cell exists and is cited; an ordering owner decision remains OPEN",
    "PB-24": "axum test: admin routes 404 on the data listener; admin_require_mtls refuses a plain connection; http.crosscut cells",
    "PB-25": "busbar-llm unit test: a stream with no usage frame bills zero tokens on every dialect",
    "PB-26": "governance unit test per exit: each finish_rejected exit charges nothing and each post-guard exit keeps the requests slot with billable refunded",
    "PB-27": "engine unit test per arm: terminal error, SSE cut, buffered cross-proto failure, client disconnect -- tokens zero and max_requests refund rules; route.failover|fo|primary-cut-stream covers one arm",
    "PB-28": "engine unit test: on_empty weighted skips a gate's restriction; for the base policy escapes to full-pool SWRR",
    "PB-29": "engine unit test asserting the four distinct 503 bodies keyed on base policy vs decision gate",
    "PB-30": "detect unit test over the 14 rungs and proto_for_path; http.crosscut cells cover the /api envelope and two unknown-path cases",
    "PB-31": "plugin_routes unit test: the route shapes, 405/404 empty bodies, three 502 arms, 64-header cap",
    "PB-32": "admin rate unit test: 10/60/30 per minute, 429 rate_limited with Retry-After: 60, first denial audited",
    "PB-33": "http.crosscut|auth-token|GET-none covers the unauthenticated GET; add cells for ?logout/?code/?method/?refresh",
    "PB-34": "secret-ref resolution tests per site: boot vs reload posture, memoization, literal rejected at SecretRef positions, trailing CRLF trim",
    "PB-35": "auth chain unit tests: Open only when chain and keys arm both empty, Pass TTL, MAX_ENTRIES, carrier precedence (one http.crosscut cell covers bearer+x-api-key)",
    "PB-36": "admin auth unit test: admin_auth [] grants Scope::Full to an anonymous principal",
    "PB-37": "store adapter unit test: only Unsupported opens a default on the four audit/denylist methods",
    "PB-38": "memory store unit test: the four 31-day sweeps use strict > and run every 256 writes; live rows never swept",
    "PB-39": "config reload unit test: each RESTART key is stored-not-applied and ConfigReloadView is unchanged; each LIVE key applies on swap",
    "PB-40": "serde unit test: the `expected one of` list for every deny_unknown_fields struct is byte-equal to the 1.5.5 snapshot; boot.refusal cells per unknown key",
    "PB-41": "boot test: no record-rate or keyset_ref warning without data_dir/peers; boot.warning cell",
    "PB-42": "boot test against a read-only store fixture: boots with hydrate only, no write probe",
    "PB-43": "ops.scrape cells cover /metrics, /metrics/hooks, /stats; add /healthz 200/503 cells and a unit test for the hook exposition rules",
    "PB-44": "unit test: in_flight_reserve is 0 without a SESSION transport and shedding happens exactly at max_inbound_concurrent",
    "PB-45": "auth unit test: revoke is synchronous on the serving node; denylist re-sync TTL 5 s; by_id refresh only on local mutation",
    "PB-46": "hook seating unit test: a migrated Request-stage hook seats After(Admit) ahead of Candidate hooks in config order",
    "PB-47": "route.failover|fb|member-down cites it; add a governance unit test that the scoped charge and refund walk the attempted pool",
    "PB-48": "engine unit test: max_unit_duration only alarms; a stream is cut only by the total reqwest deadline",
    "PB-49": "overlay unit tests: locked/overlay/env precedence, NO_WRITABLE_OVERLAY_MSG at all five sites as 400 invalid_request, 0o600",
    "PB-50": "config.migrate family covers the corpus; add a unit test for the 23 markers and the 0/1/2 exit codes",
    "PB-51": "cli|env|RUST_LOG-crate-filter cell cites it; add a unit test that `busbar=debug` falls back to INFO",
    "PB-52": "unit test for the worker-thread precedence chain, .min(128), 0 warns and ignores; cli cells for the five deprecation warnings",
    "PB-53": "metrics unit test: five counters have no describe, busbar_billing_truncated_total pre-registered at 0, retired names absent from a scrape",
    "PB-54": "cli family covers a few flags; add cells for every 1.5.5 flag/exit code, env var and the 25-step boot log order",
    "PB-55": "health prober unit test with a mock: 30 s interval, 5 s timeout, first probe one interval in, log lines, body cap",
    "PB-56": "egress client unit test asserting the reqwest builder settings (no redirects, 10 s connect, keepalive 60 s, nodelay)",
    "PB-57": "select unit test: weight-0, inadmissible and open-breaker lanes are filtered before the SWRR walk; only at-capacity reaches try_admit",
    "PB-58": "governance unit test: an admitted unit is never aborted for OverBudget or OverdraftCeiling on a migration-sealed bucket",
    "PB-59": "two-node integration test with a shared store: each node admits up to its own cap, no re-read until restart",
    "PB-60": "http.crosscut 413 cells cover three paths; add a unit test that an unauthenticated oversize request gets 401 and a relayed upstream 413 passes through",
    "PB-61": "ingress test: a chunked body up to request_body_max_bytes is accepted regardless of chunk count",
    "PB-62": "admin unit test: required_scope over every openapi path equals the x-busbar-required-scope table (34 read-only / 32 full)",
    "PB-63": "plugin reload integration test: governance instance reused across reload, in-flight finish on old snapshot, rollback error strings",
    "PB-64": "egress auth unit test: mint loop constants, no header before first mint, prober skips a pre-mint lane",
    "PB-65": "per-scheme wire unit tests: header names, anthropic five-way prefix arms, SigV4 canonical URI and SignedHeaders, fail-closed NoCredential",
    "PB-66": "header unit tests: no client header forwarded, four-group egress headers, per-writer relayed response header set; llm.wire cells diff the headers",
    "PB-67": "table-driven unit test over the 27-row matrix and the 11 KIND literals; one llm.wire upstream_down cell per row",
    "PB-68": "network guard unit tests: denylist precedence, allow_overrides, CIDR rejection, alternate-IPv4 expansion, scheme rule literals",
    "PB-69": "server posture unit test: ALPN http/1.1 only, header_read_timeout 30 s, body read timeout 30 s, handshake timeout 10 s",
    "PB-70": "ops.scrape|metrics cell on a 1.5.5 config diffs the series set; add a unit test that no ledger series is registered without data_dir",
    "PB-71": "documented-vs-actual cell family (27 README + 29 CHANGELOG claims) with the two contradicted rows pinned as code-wins",
    "PB-72": "lint: every PB row's inventory column resolves to an existing inventory file and anchor (a docs consistency lint, red on a dangling ref)",
    "PB-73": "middleware unit test: Server-Timing on every response when enabled; route headers only with route_policy and a non-default ordering hook",
    "PB-74": "unit test that the reserved-name sets equal their pinned 1.5.5 membership and that no top-level mcp:/a2a:/voice: key is parsed",
    "PB-75": "admin test: GET /admin/openapi.json body equals fixtures/openapi-1.5.5.json byte for byte (info.version included)",
    "PB-76": "http.crosscut admin cells cover outside-prefix and unknown; add a wrong-method cell asserting the method_not_allowed envelope",
    "PB-77": "admin unit test: POST /signing-key/rotate rotates nothing, audit action signing_key.report, body verbatim; admin.ops cell",
    "PB-78": "admin unit test: revoke on a tombstoned key returns 200 {revoked} and writes key.revoke/applied",
    "PB-79": "governance unit test per (phase, metric, depth): refusal order and the 429/400 message and Retry-After scale",
    "PB-80": "route.failover|fo|primary-429 cites it; add breaker unit tests for the shift/clamp/jitter arithmetic and the trip condition",
    "PB-81": "unit tests: store calls have no timeout; hooks default 1 ms under 64 in flight take on_error; auth offload 64 / 5 s yields Denied",
    "PB-82": "busbar-llm unit tests: cached count subtracted on openai/responses/gemini, gemini thoughts added, include_usage forced and hidden back",
    "PB-83": "breaker unit test: per (pool, lane) state; hard-down park fans out across the default and every per-pool cell",
    "PB-84": "tap unit test: response stage fires once per forwarded request at head time, never on a pre-forward refusal, outcome field only",
    "PB-85": "busbar-llm unit test: default_max_tokens injected only when the IR carries none; a client value is never clamped",
    "PB-86": "busbar-llm unit test: the four token classes read through the plane normalization, no raw wire pointer in the kernel (a lint on the kernel crate)",
    "PB-87": "billing unit test: Flat and per-op meters sealed at Migration; no 1.5.5-billed class is Refused(Admit, Unpriced)",
    "PB-88": "busbar-llm test over all 36 pairs: no pair-level refusal; the drop/clamp sites warn; untranslatable content renders the literal 400",
    "PB-89": "config unit test: default_on_error is nothing and a failing migrated gate does not participate",
    "PB-90": "config test: each listed key round-trips onto its 1.5.5 handler unchanged (config.migrate corpus cells with those keys)",
    "PB-91": "engine unit test: fee follows the client-facing status; translate-cap arm keeps the lane max_requests unit; route.failover|fo|primary-cut-body cites it",
    "PB-92": "auth unit test: a key with expires_at in the past still verifies (only token exp is enforced)",
    "PB-93": "store adapter unit test: every 1.6.0-only op on an ABI-2 store answers from the node-local shim with no error and no log line",
    "PB-94": "egress auth unit test: passthrough sends the caller token (empty when unauthenticated), own sends the operator key; BOOT-W04 warning",
    "PB-95": "tap unit test: routing-stage payload per failover attempt with 1-based attempt_number; candidate stage once; byte-equal to hooks/wire.rs fixture",
    "PB-96": "busbar-llm byte-exact fixtures per dialect for framing, usage fold, bedrock two-frame split, [DONE], tool-id remap; llm.wire ok_stream cells",
    "PB-97": "engine unit test: a pristine same-dialect request reaches the mock upstream byte-identical; shim strips verbatim",
    "PB-98": "unit tests: error_map ladder, restore_health_impl carry-over, the five ranking natives, reply precedence, additive pools.hooks",
    "PB-99": "store/metering unit tests: flush_metering literals, hydrate trusts billable_requests, delete_key keeps metering rows, gauge derivations",
    "PB-100": "admin.ops If-Match cells cover 43 mutations; add unit tests for VersionLog MAX_VERSIONS, /auth/token envelopes, the method set, no CORS",
    "PB-101": "SigV4 inbound unit tests: six-row matrix, UNSIGNED-PAYLOAD refused, constant-time compare; mTLS never maps to a principal; body throughput floor",
    "PB-102": "ops unit test: an alarm emits no log event, metric or stderr line on a 1.5.5 config; ops.scrape cell diffs the closed 25-metric set",
}

# A default suggestion when a binding has no hand-written one: pick by the inventory column.
def default_suggestion(b: dict) -> str:
    inv = b.get("inventory", "")
    if "config" in inv and ("BOOT" in inv or "CFG" in inv):
        return "oracle cell in family boot.refusal / boot.warning (config mutation fixture), plus a unit test on the parse"
    if "routes-admin" in inv:
        return "oracle cell in family admin.ops or http.crosscut, plus an axum handler test asserting the literal body"
    if "governance" in inv:
        return "unit test on the admission state machine asserting the literal status/message, plus a billing family cell"
    if "dialects" in inv:
        return "byte-exact unit test in busbar-llm over a fixture pair, plus a llm.wire cell"
    if "proxy-hooks" in inv:
        return "engine unit test with a hook fixture asserting the pick/charge order, plus a route.failover cell"
    if "plugins-stores" in inv:
        return "plugin-loader unit test against an ABI-2 fixture, plus a plugins cell"
    if "auth-secrets" in inv:
        return "auth chain unit test asserting the verdict, plus an http.crosscut cell"
    if "ops" in inv:
        return "cli / ops.scrape cell diffing the 1.5.5 binary output"
    return "a unit test asserting the literal rule, plus an oracle cell on the surface"


# ── Appendix B parsing ───────────────────────────────────────────────────────────────────────────
def _split_row(line: str) -> list[str]:
    # cells may contain escaped pipes (`\|`); split only on the unescaped ones
    parts = re.split(r"(?<!\\)\|", line.strip())
    parts = parts[1:-1] if len(parts) >= 2 else parts
    return [p.strip().replace("\\|", "|") for p in parts]


def parse_appendix_b(text: str) -> tuple[dict | None, list[dict]]:
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("## Appendix B")), None)
    if start is None:
        return None, []
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    master = None
    rows: list[dict] = []
    for l in lines[start:end]:
        m = re.match(r"\*\*PB-0 \(master rule\)\.\*\*\s*(.*)", l)
        if m:
            master = {"id": "PB-0", "surface": "master rule", "binding": m.group(1).strip(),
                      "inventory": "every row of every inventory file under docs/design/inventory/"}
            continue
        if re.match(r"\|\s*PB-\d+\s*\|", l):
            cells = _split_row(l)
            if len(cells) < 4:
                continue
            rows.append({"id": cells[0], "surface": cells[1], "binding": cells[2], "inventory": cells[3]})
    return master, rows


def parse_appendix_a(text: str) -> list[str]:
    """Appendix A is prose separated by ` · `; the decisions carry no ids, so they are recorded as
    text only (no ledger row can be owed for something that has no stable identifier)."""
    lines = text.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("## Appendix A")), None)
    if start is None:
        return []
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    body = " ".join(l.strip() for l in lines[start + 1:end] if l.strip())
    return [d.strip() for d in body.split(" · ") if d.strip()]


# ── Existing-JSON merge + oracle citations ───────────────────────────────────────────────────────
def cited_cells(cells: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = defaultdict(list)
    for c in cells:
        for pb in set(re.findall(r"PB-\d+", json.dumps(c, ensure_ascii=False))):
            out[pb].append(c)
    return out


def derive_oracle_checks(pb: str, cited: dict[str, list[dict]], all_cells: list[dict]) -> list[dict]:
    checks: list[dict] = []
    by_family: dict[str, list[dict]] = defaultdict(list)
    for c in cited.get(pb, []):
        by_family[c.get("family") or c.get("plane") or "?"].append(c)
    fam_sizes = Counter((c.get("family") or c.get("plane") or "?") for c in all_cells)
    for fam, cs in sorted(by_family.items()):
        if len(cs) >= FAMILY_COLLAPSE_MIN:
            checks.append({"kind": "oracle-family", "ref": fam, "status": "mapped",
                           "cites": len(cs), "family_size": fam_sizes[fam], "source": "cells.json why"})
        else:
            for c in sorted(cs, key=lambda x: x["id"]):
                checks.append({"kind": "oracle-cell", "ref": c["id"], "status": "mapped",
                               "why": c.get("why", ""), "source": "cells.json why"})
    return checks


def merge_checks(*lists: list[dict]) -> list[dict]:
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []
    for lst in lists:
        for ch in lst:
            key = (ch["kind"], ch["ref"])
            if not ch.get("ref") or key in seen:
                continue
            seen.add(key)
            ch = dict(ch)
            ch["status"] = "mapped"
            out.append(ch)
    return out


def build(arch_text: str, cells_doc: dict, existing: dict | None) -> dict:
    master, rows = parse_appendix_b(arch_text)
    bindings = ([master] if master else []) + rows
    all_cells = cells_doc.get("cells", [])
    cited = cited_cells(all_cells)
    prior = {b["id"]: b for b in (existing or {}).get("bindings", [])}
    out_b: list[dict] = []
    for b in bindings:
        pb = b["id"]
        seed = [{"kind": k, "ref": r, "proves": p, "source": "curated"} for k, r, p in SEED.get(pb, [])]
        # hand-curated = anything in the prior JSON that this script did not derive itself
        hand = [c for c in prior.get(pb, {}).get("checks", [])
                if c.get("status") == "mapped" and c.get("source") not in ("cells.json why", "curated")]
        for c in hand:
            c.setdefault("source", "hand")
        checks = merge_checks(derive_oracle_checks(pb, cited, all_cells), seed, hand)
        entry = dict(b)
        if pb in NOTES:
            entry["note"] = NOTES[pb]
        if checks:
            entry["status"] = "mapped"
            entry["checks"] = checks
        else:
            entry["status"] = "unmapped"
            sug = SUGGEST.get(pb) or default_suggestion(b)
            entry["suggestion"] = sug
            entry["checks"] = [{"kind": suggest_kind(sug), "ref": "", "status": "unmapped", "suggestion": sug}]
        out_b.append(entry)
    dropped = sorted(set(prior) - {b["id"] for b in bindings})
    return {
        "_comment": [
            "GENERATED by scripts/design-bindings.py --write. Hand-added `checks` entries are preserved across regeneration;",
            "derived entries (source = 'cells.json why' or 'curated') are recomputed each time.",
            "status: mapped = at least one existing check proves the binding; unmapped = no check today (see `suggestion`).",
            "Checked by scripts/design-bindings.sh --check (existence only; nothing is executed).",
        ],
        "derived_from": {"architecture": str(ARCH.relative_to(ROOT)), "cells": str(CELLS.relative_to(ROOT))},
        "counts": counts(out_b),
        "owner_decisions": {
            "note": "Appendix A carries no per-decision ids, so its decisions are recorded as text only and owe no ledger row.",
            "decisions": parse_appendix_a(arch_text),
        },
        "dropped_since_last_write": dropped,
        "bindings": out_b,
    }


def suggest_kind(s: str) -> str:
    s = s.lower()
    if "lint" in s:
        return "lint"
    if "gate" in s and "cell" not in s:
        return "gate"
    if "conformance" in s:
        return "conformance"
    if "cell" in s and "test" not in s:
        return "oracle-cell"
    return "test"


def counts(bindings: list[dict]) -> dict:
    mapped = [b for b in bindings if b["status"] == "mapped"]
    by_kind: Counter = Counter()
    for b in mapped:
        for c in b["checks"]:
            by_kind[c["kind"]] += 1
    return {"bindings": len(bindings), "mapped": len(mapped), "unmapped": len(bindings) - len(mapped),
            "checks_by_kind": dict(sorted(by_kind.items()))}


# ── Existence verification (nothing runs) ────────────────────────────────────────────────────────
_TEST_ATTR = re.compile(r"^\s*#\[\s*(tokio::test|test|async_std::test|rstest|test_case)")
_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)")


def test_index(crates: Path) -> dict[str, set[str]]:
    """fn name -> set of files (relative) where it is declared under a test attribute."""
    idx: dict[str, set[str]] = defaultdict(set)
    for f in crates.rglob("*.rs"):
        if "/target/" in str(f):
            continue
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        armed = 0
        for l in lines:
            if _TEST_ATTR.match(l):
                armed = 8  # the fn may sit a few attribute lines below
                continue
            if armed:
                m = _FN.match(l)
                if m:
                    idx[m.group(1)].add(str(f.relative_to(ROOT)))
                    armed = 0
                elif l.strip().startswith("#[") or not l.strip():
                    armed -= 1
                else:
                    armed = 0
    return idx


def verify(doc: dict, cells_doc: dict, crates: Path, root: Path) -> list[tuple[str, str, str, str]]:
    idx = test_index(crates) if crates.exists() else {}
    cell_ids = {c["id"] for c in cells_doc.get("cells", [])}
    families = Counter((c.get("family") or c.get("plane") or "?") for c in cells_doc.get("cells", []))
    rows: list[tuple[str, str, str, str]] = []
    for b in doc.get("bindings", []):
        pb, title = b["id"], f"{b['id']} {b['surface']}"[:70]
        mapped = [c for c in b.get("checks", []) if c.get("status") == "mapped" and c.get("ref")]
        if not mapped:
            rows.append((pb, "SKIP", title, "unmapped: " + (b.get("suggestion") or "no check proves this binding yet")))
            continue
        missing: list[str] = []
        for c in mapped:
            k, r = c["kind"], c["ref"]
            ok = False
            if k == "test":
                if "::" in r:
                    path, name = r.rsplit("::", 1)
                    ok = path in idx.get(name, set())
                else:
                    ok = r in idx
            elif k == "oracle-cell":
                ok = r in cell_ids
            elif k == "oracle-family":
                ok = families.get(r, 0) > 0
            elif k in ("lint", "gate", "conformance"):
                ok = (root / r).exists()
            if not ok:
                missing.append(f"{k}:{r}")
        if missing:
            rows.append((pb, "FAIL", title, "referenced check vanished: " + ", ".join(missing)))
        else:
            rows.append((pb, "PASS", title, ", ".join(f"{c['kind']}:{c['ref']}" for c in mapped)))
    return rows


# ── Markdown ─────────────────────────────────────────────────────────────────────────────────────
def _md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_md(doc: dict) -> str:
    c = doc["counts"]
    out = ["# Design bindings ledger", "",
           "GENERATED by `scripts/design-bindings.py --write` from `docs/design/ARCHITECTURE.md` Appendix B. Do not edit by hand.",
           "", "One row per parity binding; `checks` lists what proves it TODAY (existence-checked by",
           "`scripts/design-bindings.sh --check`; nothing is executed). A binding with no check is `unmapped`",
           "and carries the check that would prove it -- that list is the owner's post-check plan.", "",
           "## Summary", "",
           f"- bindings: **{c['bindings']}**  (PB-0 master rule + {c['bindings'] - 1} table rows)",
           f"- mapped: **{c['mapped']}**", f"- unmapped: **{c['unmapped']}**",
           "- checks by kind: " + ", ".join(f"{k} {v}" for k, v in c["checks_by_kind"].items()), "",
           "## Bindings", "", "| # | Surface | Status | Checks |", "|---|---|---|---|"]
    for b in doc["bindings"]:
        if b["status"] == "mapped":
            parts = []
            for ch in b["checks"]:
                extra = f" ({ch['cites']}/{ch['family_size']} cells cite it)" if ch["kind"] == "oracle-family" and "cites" in ch else ""
                parts.append(f"{ch['kind']}: `{ch['ref']}`{extra}")
            checks = "<br>".join(_md(p) for p in parts)
        else:
            checks = "_none_"
        out.append(f"| {b['id']} | {_md(b['surface'])} | {b['status']} | {checks} |")
    noted = [b for b in doc["bindings"] if b.get("note")]
    if noted:
        out += ["", "## Findings: bindings in conflict with the tree", "",
                "A green test that asserts the opposite of a binding is not a proof. These need an owner decision.", ""]
        for b in noted:
            out.append(f"- **{b['id']}** ({_md(b['surface'])}): {_md(b['note'])}")
    out += ["", "## Post-check plan: the unmapped bindings", "",
            "Each line is the check that would move the binding to `mapped`.", ""]
    for b in doc["bindings"]:
        if b["status"] == "unmapped":
            out.append(f"- **{b['id']}** ({_md(b['surface'])}): {_md(b.get('suggestion', ''))}")
    out += ["", "## Running the checks (a slower tier)", "",
            "`scripts/design-bindings.sh --check` proves existence only. The mapped kinds can be executed later by a slower tier:", "",
            "- `test`: `cargo test -p <crate> <fn>` per ref (the crate is the first path segment under crates/ where the fn is declared).",
            "- `oracle-cell` / `oracle-family`: `testing/shadow-oracle/record.sh` + `replay.sh` over the named cell ids, against the pinned 1.5.5 golden.",
            "- `gate` / `lint`: run the script with its own `--selftest` first, then its check mode.",
            "- `conformance`: the rig under testing/*-conformance for the named row.", ""]
    od = doc.get("owner_decisions", {})
    out += ["", "## Appendix A owner decisions", "",
            od.get("note", ""), "", f"{len(od.get('decisions', []))} decisions recorded as text in the JSON."]
    return "\n".join(out) + "\n"


# ── main ─────────────────────────────────────────────────────────────────────────────────────────
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--write", action="store_true")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--summary", action="store_true")
    ap.add_argument("--arch", default=str(ARCH))
    ap.add_argument("--cells", default=str(CELLS))
    ap.add_argument("--bindings", default=str(OUT_JSON), help="the ledger JSON to verify / to preserve hand entries from")
    ap.add_argument("--out-json", default=str(OUT_JSON))
    ap.add_argument("--out-md", default=str(OUT_MD))
    ap.add_argument("--crates", default=str(CRATES))
    a = ap.parse_args(argv)

    cells_doc = json.loads(Path(a.cells).read_text()) if Path(a.cells).exists() else {"cells": []}
    bp = Path(a.bindings)
    existing = json.loads(bp.read_text()) if bp.is_file() and bp.stat().st_size > 0 else None

    if a.verify:
        if existing is None:
            print(f"design-bindings: {a.bindings} missing -- run --write first", file=sys.stderr)
            return 2
        for r in verify(existing, cells_doc, Path(a.crates), ROOT):
            print("\t".join(x.replace("\t", " ") for x in r))
        return 0

    doc = build(Path(a.arch).read_text(), cells_doc, existing)
    if a.write:
        Path(a.out_json).write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
        Path(a.out_md).write_text(render_md(doc))
        print(f"wrote {a.out_json} and {a.out_md}")
    c = doc["counts"]
    print(f"bindings {c['bindings']}  mapped {c['mapped']}  unmapped {c['unmapped']}  by kind {c['checks_by_kind']}")
    if doc["dropped_since_last_write"]:
        print("dropped (no longer in Appendix B): " + ", ".join(doc["dropped_since_last_write"]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
