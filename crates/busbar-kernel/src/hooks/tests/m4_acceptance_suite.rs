//! # M4 acceptance suite (TODO M4 HOOK-PARITY, 1.6.0-TODO PHASE 4)
//!
//! The kernel's single named home for the v1.5.5 `kind: hook` test corpus, ported as BLACK-BOX
//! assertions against the CURRENT resolution path (the `test_env`/`resolve_one` harness above,
//! which resolves a `plugin:` ref through the registry and the kernel's hook axis port — the same
//! `resolve_gate_transport` seam a live request uses — not a hand-rolled `HookPolicy::policy`).
//!
//! ## Moved out with the test-hook plugin (OWNER 2026-10-03, no test plugins)
//!
//! This file held ONE test: the inflight cap, ported from the loader's
//! `hook_calls_are_capped_and_saturation_fails_on_the_caller_deadline`. The cap is the
//! dispatcher's (a hook's Statement `max_inflight`), and the plugin that wedged it here is deleted;
//! a double behind the kernel's port would only prove its own cap. It now lives where the cap does,
//! every assertion kept: `busbar-plugin-loader`'s
//! `hook_door_tests::the_inflight_cap_saturates_and_fails_on_the_caller_deadline_through_the_axis`,
//! over the loader's own hook fixture. The kernel's half of the same call path (the budget, the
//! error `on_error` decides) stays in `tests.rs` above.
//!
//! ## THE COUNT, ENUMERATED (ARCHITECT ruling M9, 2026-10-14)
//!
//! The suite's size is [`HOOK_PARITY_TESTS`], the length of [`V155_HOOK_CORPUS`]: every
//! `#[test]`/`#[tokio::test]` function of the seven v1.5.5 `kind: hook` files, by name, read off
//! the `v1.5.5` tag (`git show v1.5.5:<file>`, an attribute at the start of a line). It is **181**:
//! 69 of llm origin (`proxy/tests/hook_seam_tests.rs` 42, `hook_opt_in_projection_tests.rs` 27)
//! and 112 of kernel, loader and ranking origin (`hooks/tests/tests.rs` 50, `scrape_tests.rs` 11,
//! `hooks/wire.rs` 19, the loader's `hook.rs` 16, `hooks-ranking` 16).
//!
//! The 184 below was `grep -c '#\[(tokio::)?test'` over the same files, which also counts three
//! COMMENTS that spell an attribute (`hook_seam_tests.rs:2133`, `scrape_tests.rs:236,246`): 43 and
//! 13 where the files hold 42 and 11 tests. Every other written size is held to this one by
//! `cargo xtask gate hook-parity-count`.
//!
//! ## Reconciliation: 189 counted vs the signed brief's "178+4"
//!
//! A direct `#[test]`/`#[tokio::test]` count of the 8 v1.5.5 files named in
//! `inventory-hook.md` §5 gives **189** (50+43+27+13+5+16+16+19). The brief's own tally
//! ("178 hook tests plus 4 auth-cache tests") does not reconcile against any grouping of those 8
//! files' counts — no subset or combination sums to 178, and the brief's own worked arithmetic
//! ("19+43+27+16+5+5" = 115) is a third, still-different number. That mismatch is the brief's, not
//! resolved here.
//!
//! What DOES resolve, checked file-by-file against predev on this branch:
//!
//! - `crates/busbar/src/export/tests/webhook_tests.rs` (v1.5.5, 5 tests: `push_target_validates_
//!   and_carries_auth_header`, `deliver_logs_is_noop_when_unconfigured`, `delivery_failure_masks_
//!   userinfo`, `each_webhook_instance_gets_its_own_admission_gate`, `build_request_log_shape`) is
//!   **`kind: export`** (outbound webhook delivery), not `kind: hook` — it lived under `export/`
//!   in v1.5.5 too. The code it tests still exists, unchanged in kind, at
//!   `crates/busbar-kernel/src/export/{mod.rs,plugin.rs}`. The predev file at the inventory's
//!   "renamed" path (`crates/busbar-llm/src/tests/webhook_tests.rs`) is NOT a port of those 5 tests
//!   at all — it holds 11 unrelated tests (`a_tampered_body_is_refused_with_signature_mismatch`,
//!   `an_unsigned_request_is_refused_for_missing_headers`, …) verifying an INBOUND signed-webhook
//!   admission gate. Same file name, disjoint feature, disjoint kind. This is a misclassification
//!   in the inventory table, not a hook-kind gap: **excluded from this suite's scope.**
//! - True `kind: hook` v1.5.5 corpus by that attribute count: **189 − 5 = 184**; by name, **181**
//!   (the enumeration above: the attribute count read three comments as tests).
//! - Of the 184: 89 already live natively in this crate (`tests.rs` 50→57, `scrape_tests.rs` 13→13,
//!   `wire_tests.rs` 19→19 on predev — additions are predev-only, nothing v1.5.5 removed); 70 live
//!   in `busbar-llm/src/engine/tests/{hook_seam_tests.rs,hook_opt_in_projection_tests.rs}` (plane
//!   projection/rewrite-gate coverage, verified all v1.5.5 names present there or renamed
//!   1:1 — e.g. `block_text_responses_reasoning_rejects_malformed_encrypted_content` →
//!   `responses_reasoning_reader_rejects_malformed_encrypted_content`); 16 live in
//!   the plugin loader's own hook, transform-failure and panic-status tests (split, +5
//!   predev-only); 16 live in the ranking hook's own unit and determinism suites (split, +5
//!   predev-only). 89+70+16+16=191
//!   ≠ 184 only because the "+N predev-only" additions above are counted in the file totals but not
//!   in the 184 (they are net-new, tracked in inventory-hook.md §5's own predev-only list).
//!
//! ## What is physically consolidated HERE vs left at its existing (passing) location
//!
//! The ONE test from the loader-origin group whose PINNED 1.5.5 behaviour (`MAX_INFLIGHT_HOOK_CALLS =
//! 64` per loaded hook) had no equivalent in `tests.rs` — the concurrency-cap/backpressure guarantee
//! — lives in the loader (see above). Everything else in the
//! loader-origin 16 already has a same-behaviour sibling in `tests.rs` above, reached through
//! the identical harness, and is not duplicated:
//!
//! | v1.5.5 (the loader's hook module) | this crate's already-passing equivalent |
//! |---|---|
//! | `dlopen_policy_drives_every_op` | `dlopen_decide_order_and_abstain` + `dlopen_transform_rewrite_and_reject` + `dlopen_status_and_schema_reads` |
//! | `dlopen_policy_abstains_and_drops_unknown_idx` | `dlopen_decide_order_and_abstain` |
//! | `dlopen_configure_acks_exact_version` | same name, `tests.rs:1751` |
//! | `dlopen_notify_never_errors` | `dlopen_notify_is_fire_and_forget` |
//! | `dlopen_configure_nack_is_err` | `dlopen_configure_nack_does_not_commit` |
//! | `dlopen_empty_management_reads_are_none` | `dlopen_empty_management_reads_are_fail_open_none` |
//! | `dlopen_slow_gate_hits_the_deadline` (ARCHITECT-named) | `dlopen_decide_deadline_cuts_off_a_slow_gate`, `tests.rs:2134` — **unignored, passing**: confirms the owner ruling (off-worker `spawn_blocking` + hard `timeout_ms`) holds on today's dispatch path |
//! | `dlopen_decide_reject_over_the_seam` | `dlopen_decide_reject_status_is_clamped` + `dlopen_decide_reject_from_opt_in_prompt` |
//! | `dlopen_transform_rewrites_over_the_seam` | `dlopen_transform_rewrite_and_reject` |
//! | `dlopen_a_hook_that_cannot_answer_is_an_err_not_an_abstain` | `dlopen_decide_raw_reply_is_fail_closed` |
//!
//! Genuinely not consolidated (no equivalent in `tests.rs`, but currently passing, unignored, at
//! their v1.5.5-inherited predev location in the plugin loader's own tests, which this crate does
//! not duplicate because they assert on the loader's OWN internal load/log plumbing rather than an
//! observable reply/timeout/metric the request path exposes): `load_refuses_kind_mismatch`,
//! `load_refuses_malformed_config`, `dlopen_plugin_panic_is_fail_closed_err`,
//! `a_plugin_log_reaches_the_host`, `the_log_ctx_is_interned_not_allocated_per_load`.
//!
//! The `busbar-llm`-origin 70 and ranking-hook-origin 16 are similarly left at their existing,
//! passing predev locations: both exercise crate-private test scaffolding (`busbar_llm`'s
//! `WeightedLane`/prompt-projection fixtures; the ranking hook's native-policy signal tables) that
//! is not exported for cross-crate reuse, so relocating them here would mean rewriting rather than
//! porting them — out of scope for a byte-for-byte behaviour port.
//!
//! The two ARCHITECT-named timeout tests pass, unignored, in `tests.rs` above (the kernel's half)
//! and in the loader's `a_slow_hook_is_cut_off_at_its_budget_through_the_axis` (the lane's half).

/// Where a v1.5.5 hook test came from: the plane's request path (llm) or the kernel, the loader and
/// the ranking hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Origin {
    /// `crates/busbar/src/proxy/tests/` in v1.5.5: run through the plane's `project`.
    Llm,
    /// `crates/busbar/src/hooks/` in v1.5.5.
    Kernel,
    /// `crates/plugin-loader/src/hook.rs` in v1.5.5.
    Loader,
    /// `crates/hooks-ranking/src/lib.rs` in v1.5.5.
    Ranking,
}

/// THE SUITE'S SIZE: the one number every writing of it is held to.
pub(crate) const HOOK_PARITY_TESTS: usize = 181;
/// Of them, of llm origin.
pub(crate) const LLM_ORIGIN: usize = 69;
/// Of them, of kernel, loader and ranking origin.
pub(crate) const KERNEL_LOADER_RANKING_ORIGIN: usize = 112;

/// THE v1.5.5 `kind: hook` CORPUS, by name: `(origin, v1.5.5 file, test fn)`.
#[rustfmt::skip]
pub(crate) const V155_HOOK_CORPUS: &[(Origin, &str, &str)] = &[
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "default_flags_project_nothing"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "global_gate_reject_short_circuits_the_request"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "global_gate_abstain_does_not_reject"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "enforce_restricts_reapplies_compliance_tags_across_pools"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "base_policy_restrict_persists_across_fallback_pool_hop"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "completion_tap_fires_synthetic_rejected_by_auth"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "completion_tap_status_is_protocol_native_gemini_400"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "completion_tap_fires_synthetic_rejected_by_gate"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "completion_tap_reports_ok_outcome"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "attempt_tap_carries_attempt_story"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "route_tap_reports_surviving_candidates"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "same_protocol_passthrough_carries_global_rewrite"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "pool_scoped_rw_gate_rewrites_the_body"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "on_error_fallback_hook_fires_and_decides"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "on_error_chain_exhausted_applies_terminal"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "on_error_reject_terminal_short_circuits_before_a_live_lane_ever_dispatches"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "global_request_stage_tap_fires_on_a_real_dispatched_request"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "pool_gate_reject_fires_from_pool_runtime_gates"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_priority_tie_break_surfaces_lowest_priority"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "multi_restrict_disjoint_intersection_fails_closed"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "multi_restrict_intersection_dispatches_only_the_survivor"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "stale_order_filtered_against_post_restrict_set"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "order_last_in_chain_wins"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "last_order_gate_filtered_to_empty_abstains_to_base_not_to_a_lower_gate"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "global_gate_order_arm_is_honored"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "send_prompt_projects_content_only"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "send_user_projects_identity_only"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_decision_maps_to_reject_request_outcome"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "max_tokens_saturates_not_wraps"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "send_user_projects_governance_key_identity"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "send_user_falls_back_to_synthesized_group_key_identity"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "send_user_prefers_resolved_key_over_disabled_legacy_lookup"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "forward_with_pool_keyed_threads_group_key_to_pool_policy"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_status_and_message_resanitized_at_the_seam"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_408_maps_to_anthropic_timeout_envelope"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_rides_the_full_forward_path"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_kind_mapping_matches_status_semantics"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_message_reaches_anthropic_error_body"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "reject_produces_bedrock_native_envelope"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "request_id_counter_is_unique_and_monotonic_across_sequential_requests"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "same_request_id_joins_gate_decision_and_completion_tap"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_seam_tests.rs", "request_id_is_recorded_as_native_u64_tracing_field"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_flattens_string_and_block_content"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_system_blocks_and_absent"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_keeps_empty_entries_aligned"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "system_text_chars_counts_block_arrays"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_reads_gemini_contents"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_reads_responses_input"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "max_tokens_signal_is_dialect_aware_for_responses"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_reads_bedrock_messages"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "body_end_user_reads_both_dialects"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_sees_anthropic_thinking_text"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_sees_bedrock_reasoning_text"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_sees_responses_reasoning_summary_only"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_marks_anthropic_redacted_thinking"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_marks_bedrock_redacted_content"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_marks_responses_encrypted_content_only_reasoning"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_and_total_chars_mark_responses_reasoning_with_empty_content_array"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "block_text_responses_reasoning_rejects_malformed_encrypted_content"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_responses_reasoning_prefers_text_over_encrypted_content"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "responses_single_part_reasoning_text_borrows"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "responses_multi_part_reasoning_text_concatenates"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_attributes_responses_reasoning_to_assistant"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_mixed_text_and_thinking_turn_joins_both"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "prompt_projection_gemini_thought_part_still_projects"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "total_text_chars_counts_reasoning_text"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "size_signal_and_projection_agree_on_reasoning"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "every_known_protocol_has_a_declared_reasoning_wire_shape"),
    (Origin::Llm, "crates/busbar/src/proxy/tests/hook_opt_in_projection_tests.rs", "apply_rewrite_to_body_echoes_redacted_marker_as_visible_text"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "from_ranked_drops_unknown_and_dedups"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "preresolve_hook_secrets_fails_closed_on_unresolvable_secret"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "preopen_gate_hooks_aborts_on_a_broken_gate_but_never_a_broken_tap"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "native_policy_resolves_constructed_policy"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "default_hook_resolves_as_base_for_unnamed_pools"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "default_rw_hook_is_not_the_base_ordering"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "weighted_policy_resolves_none_zero_cost"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "unknown_hook_ref_falls_back_to_none"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "plugin_gate_resolves_constructed_policy"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "weighted_default_resolves_none"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "on_error_chain_resolves_gates_and_terminals"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "on_error_chain_strategy_terminates"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "pool_rw_gate_resolves_as_rewrite_not_decision"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "missing_plugin_gate_is_absent_not_stranded"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "resolve_rewrite_hooks_admits_only_prompt_rw_gates"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "rewrite_admission_requires_the_signed_manifest_rewrite_need"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "hook_inert_gate_banner_fires_only_for_a_gate_with_the_chain_killing_mismatch"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "effective_access_warns_on_inert_read_grants_only"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "effective_access_inert_gate_rewrite_banner_fires_once_per_hook_name"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "resolve_gate_hooks_admits_only_decision_gates"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "resolve_tap_hooks_admits_only_request_stage_taps"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "resolve_tap_hooks_honors_phase_list"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "resolve_tap_hooks_carries_prompt_grant"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "policy_timeout_treats_zero_as_default"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "from_ranked_empty_is_abstain"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "native_resolve_forces_opt_in_flags_off"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "gate_grants_pass_through_as_projection_flags"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "manifest_intent_and_grant_projection_matrix"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "from_ranked_never_produces_reject"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "opt_in_projections_redact_debug"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_decide_order_and_abstain"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_decide_reject_from_opt_in_prompt"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_transform_rewrite_and_reject"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_notify_is_fire_and_forget"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_status_and_schema_reads"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_configure_acks_exact_version"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_on_error_chain_link_is_live_plugin"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_prompt_no_grant_withholds_content"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_decide_reject_status_is_clamped"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_decide_restrict_and_fail_closed"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_decide_raw_reply_is_fail_closed"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_user_identity_projection_rides_the_wire"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_decide_deadline_cuts_off_a_slow_gate"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_empty_management_reads_are_fail_open_none"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "dlopen_configure_nack_does_not_commit"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "offload_bounded_returns_none_when_the_work_outlives_the_deadline"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "offload_bounded_logs_when_the_blocking_task_panics"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "settings_drift_reports_only_key_names_and_never_resolves_a_secret"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "settings_drift_never_compares_a_secret_ref_field"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/tests.rs", "concurrent_push_configure_does_not_starve_the_runtime"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "counter_renders_with_hook_label_and_verbatim_name"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "histogram_renders_as_summary"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "histogram_with_buckets_renders_as_native_histogram"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "busbar_prefix_is_reserved"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "two_hooks_same_name_share_header_split_by_label"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "type_conflict_for_shared_name_is_dropped"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "label_values_are_escaped"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "unique_hook_never_repeats"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "manufactured_collision_proves_the_shared_literal_hazard_and_the_fix"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "only_one_refresh_per_hook_can_be_in_flight"),
    (Origin::Kernel, "crates/busbar/src/hooks/tests/scrape_tests.rs", "hook_labels_cannot_shadow_renderer_labels"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "status_metric_hints_cap_char_safe"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "status_metrics_labels_quantiles_and_estimates"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "status_metrics_caps_the_quantile_count"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "status_metrics_validates_native_buckets"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "default_payload_omits_opt_in_keys"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "opt_in_payload_carries_prompt_identity_tags"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "opt_in_prompt_without_system_still_sends_messages"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "reject_bare_uses_defaults"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "reject_status_clamps_to_4xx"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "reject_message_is_sanitized"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "reject_takes_precedence"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "reject_is_fail_closed_on_malformed_values"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "reject_message_strips_unicode_line_separators"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "anonymous_identity_emits_empty_user_object"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "opt_in_content_with_newlines_stays_one_line"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "non_reject_replies_unchanged"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "normalize_restrict_precedence_and_fail_closed"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "parse_restrict_is_fail_closed"),
    (Origin::Kernel, "crates/busbar/src/hooks/wire.rs", "parse_rewrite_is_fail_closed"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_policy_drives_every_op"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_policy_abstains_and_drops_unknown_idx"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "load_refuses_kind_mismatch"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_configure_acks_exact_version"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_notify_never_errors"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_configure_nack_is_err"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_empty_management_reads_are_none"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_slow_gate_hits_the_deadline"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "load_refuses_malformed_config"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_decide_reject_over_the_seam"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_transform_rewrites_over_the_seam"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_plugin_panic_is_fail_closed_err"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "a_plugin_log_reaches_the_host"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "the_log_ctx_is_interned_not_allocated_per_load"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "dlopen_a_hook_that_cannot_answer_is_an_err_not_an_abstain"),
    (Origin::Loader, "crates/plugin-loader/src/hook.rs", "hook_calls_are_capped_and_saturation_fails_on_the_caller_deadline"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "weighted_native_abstains"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "cheapest_orders_by_cost_demoting_unknown"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "cheapest_all_unknown_abstains"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "fastest_orders_by_latency"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "least_busy_prefers_most_headroom"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "usage_orders_by_rate_headroom_demoting_unknown"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "usage_all_unknown_abstains"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "native_registry_known_and_unknown"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "native_registry_names_round_trip"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "all_natives_abstain_on_empty_pool"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "single_candidate_prefers_it"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "least_busy_all_saturated_ranks_by_idx"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "usage_all_at_cap_ranks_by_idx"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "cheapest_all_weight_zero_no_cost_abstains"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "fastest_all_unknown_latency_abstains"),
    (Origin::Ranking, "crates/hooks-ranking/src/lib.rs", "fastest_orders_by_latency_demoting_unknown"),
];

/// THE COUNT IS THE ENUMERATION: the constant is the corpus's length, the split sums to it, and no
/// test is listed twice. RED on any written figure that is not what the corpus holds.
#[test]
fn the_hook_parity_count_is_the_enumerated_corpus() {
    assert_eq!(V155_HOOK_CORPUS.len(), HOOK_PARITY_TESTS);
    let llm = V155_HOOK_CORPUS
        .iter()
        .filter(|(o, _, _)| *o == Origin::Llm)
        .count();
    assert_eq!(llm, LLM_ORIGIN);
    assert_eq!(V155_HOOK_CORPUS.len() - llm, KERNEL_LOADER_RANKING_ORIGIN);
    assert_eq!(LLM_ORIGIN + KERNEL_LOADER_RANKING_ORIGIN, HOOK_PARITY_TESTS);
    let distinct: std::collections::BTreeSet<(&str, &str)> = V155_HOOK_CORPUS
        .iter()
        .map(|(_, file, name)| (*file, *name))
        .collect();
    assert_eq!(
        distinct.len(),
        V155_HOOK_CORPUS.len(),
        "a test is listed twice"
    );
    let files: std::collections::BTreeSet<&str> =
        V155_HOOK_CORPUS.iter().map(|(_, file, _)| *file).collect();
    assert_eq!(
        files.len(),
        7,
        "the corpus is seven v1.5.5 files: {files:?}"
    );
    assert!(
        !files.iter().any(|f| f.contains("webhook")),
        "the v1.5.5 webhook tests are kind: export, not hook"
    );
}
