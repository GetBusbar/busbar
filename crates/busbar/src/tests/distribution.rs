#[path = "../../../../dist/default/tests/product/auth_plugin_chain.rs"]
mod auth_plugin_chain;

#[path = "../../../../dist/default/tests/product/auth_plugin_chain_trust.rs"]
mod auth_plugin_chain_trust;

#[path = "../../../../dist/default/tests/product/plugin_preflight_scan.rs"]
mod plugin_preflight_scan;

#[cfg(feature = "auth-admin-tokens")]
#[path = "../../../../dist/default/tests/product/admin_cross_plane/main.rs"]
mod admin_cross_plane;

#[path = "oauth2_application/mod.rs"]
mod oauth2_application;

#[path = "kernel_application/state.rs"]
mod kernel_state;

#[path = "kernel_application/router.rs"]
mod kernel_router;

#[path = "../../../../dist/default/tests/product/decisions_hooks.rs"]
mod decisions_hooks;

#[path = "kernel_application/hooks_pool_admission.rs"]
mod hooks_pool_admission;

#[path = "admin_application/usage_reads_the_process_rate_history.rs"]
mod admin_usage_history;

#[path = "kernel_application/central_root_rules.rs"]
mod central_root_rules;

#[path = "kernel_application/central_admin_verbs.rs"]
mod central_admin_verbs;

#[path = "kernel_application/central_router_headers.rs"]
mod central_router_headers;

#[path = "kernel_application/central_rebuild.rs"]
mod central_rebuild;

#[path = "kernel_application/auth_carrier_tests.rs"]
mod auth_carrier_tests;

#[path = "kernel_application/config_validation_models.rs"]
mod config_validation_models;

#[path = "kernel_application/config_validation_application.rs"]
mod config_validation_application;

#[path = "kernel_application/config_validation_store.rs"]
mod config_validation_store;

#[path = "kernel_application/config_validation_secrets.rs"]
mod config_validation_secrets;

#[path = "kernel_application/auth_admit_tests.rs"]
mod auth_admit_tests;

#[path = "kernel_application/auth_chain_tests.rs"]
mod auth_chain_tests;

#[path = "kernel_application/auth_keys_tests.rs"]
mod auth_keys_tests;

#[path = "kernel_application/auth_scope_tests.rs"]
mod auth_scope_tests;

#[path = "kernel_application/central_config_recovery_boot.rs"]
mod central_config_recovery_boot;

#[path = "../../../../dist/default/tests/product/store_adapter_verb_seam.rs"]
mod store_adapter_verb_seam;

#[path = "../../../../dist/default/tests/product/auth_cross_plane.rs"]
mod auth_cross_plane;

#[path = "../../../../dist/default/tests/product/admin_planeverbs_cross_plane.rs"]
mod admin_planeverbs_cross_plane;

#[path = "../../../../dist/default/tests/product/ledger_admin_views_legacy_leg.rs"]
mod ledger_admin_views_legacy_leg;

#[path = "../../../../dist/default/tests/product/money_one_function_equivalence.rs"]
mod money_one_function_equivalence;

#[path = "../../../../dist/default/tests/product/rate_apply_commit.rs"]
mod rate_apply_commit;

#[path = "../../../../dist/default/tests/product/registry_cross_plane.rs"]
mod registry_cross_plane;

#[path = "../../../../dist/default/tests/product/plugins_logs_preflight.rs"]
mod plugins_logs_preflight;

#[path = "../../../../dist/default/tests/product/metrics_cross_plane.rs"]
mod metrics_cross_plane;

#[path = "../../../../dist/default/tests/product/plane_integration.rs"]
mod plane_integration;

#[path = "../../../../dist/default/tests/product/law7_plane_gating.rs"]
mod law7_plane_gating;

#[path = "../../../../dist/default/tests/product/endpoints_cross_plane.rs"]
mod endpoints_cross_plane;

#[path = "../../../../dist/default/tests/product/residual_envelope_cross_plane.rs"]
mod residual_envelope_cross_plane;

#[path = "kernel_application/auth_diagnostic_tests.rs"]
mod auth_diagnostic_tests;

#[path = "kernel_application/auth_self_keys_tests.rs"]
mod auth_self_keys_tests;

#[path = "kernel_application/config_parser_deploy.rs"]
mod config_parser_deploy;

#[path = "kernel_application/config_parser_groups_collision.rs"]
mod config_parser_groups_collision;

#[path = "kernel_application/config_parser_legacy.rs"]
mod config_parser_legacy;

#[path = "kernel_application/config_parser_migration.rs"]
mod config_parser_migration;

#[path = "kernel_application/config_parser_named_map_replace.rs"]
mod config_parser_named_map_replace;

#[path = "kernel_application/config_parser_plane_sections.rs"]
mod config_parser_plane_sections;

#[path = "kernel_application/plane_driver_health.rs"]
mod plane_driver_health;

#[path = "kernel_application/plane_driver_hooks.rs"]
mod plane_driver_hooks;

#[path = "kernel_application/plane_driver_host.rs"]
mod plane_driver_host;

#[path = "kernel_application/plane_driver_serve.rs"]
mod plane_driver_serve;

#[path = "admin_application/admin_configuration_contracts.rs"]
mod admin_configuration_contracts;

#[path = "admin_application/admin_governance_api.rs"]
mod admin_governance_api;

#[path = "admin_application/admin_group_admission.rs"]
mod admin_group_admission;

#[path = "admin_application/admin_info_and_validation.rs"]
mod admin_info_and_validation;

#[path = "admin_application/admin_key_custody_surface.rs"]
mod admin_key_custody_surface;

#[path = "admin_application/admin_key_delete_contracts.rs"]
mod admin_key_delete_contracts;

#[path = "admin_application/admin_key_request_contracts.rs"]
mod admin_key_request_contracts;

#[path = "admin_application/admin_key_states_and_secrets.rs"]
mod admin_key_states_and_secrets;

#[path = "admin_application/admin_routing_contracts.rs"]
mod admin_routing_contracts;

#[path = "admin_application/admin_signed_key_lifecycle.rs"]
mod admin_signed_key_lifecycle;

#[path = "admin_application/admin_token_carriers.rs"]
mod admin_token_carriers;

#[path = "admin_application/admin_topology_live_status.rs"]
mod admin_topology_live_status;

#[path = "admin_application/config_boundaries.rs"]
mod config_boundaries;

#[path = "admin_application/config_store_overlay.rs"]
mod config_store_overlay;

#[path = "admin_application/config_transactions.rs"]
mod config_transactions;

#[path = "admin_application/custody_idempotency.rs"]
mod custody_idempotency;

#[path = "admin_application/custody_provision.rs"]
mod custody_provision;

#[path = "admin_application/custody_usage_range.rs"]
mod custody_usage_range;

#[path = "admin_application/key_revoke_tombstone_tests.rs"]
mod key_revoke_tombstone_tests;

#[path = "admin_application/plugin_inspect_envelope.rs"]
mod plugin_inspect_envelope;

#[path = "admin_application/split_admin_listener.rs"]
mod split_admin_listener;

#[path = "kernel_application/auth_dpop_tests.rs"]
mod auth_dpop_tests;

#[path = "kernel_application/auth_preflight_tests.rs"]
mod auth_preflight_tests;

#[path = "admin_application/admin_all_reads_guard.rs"]
mod admin_all_reads_guard;

#[path = "admin_application/admin_auth_row_projection.rs"]
mod admin_auth_row_projection;

#[path = "admin_application/admin_budget_group_contracts.rs"]
mod admin_budget_group_contracts;

#[path = "admin_application/admin_configuration_health.rs"]
mod admin_configuration_health;

#[path = "admin_application/admin_delegated_authority.rs"]
mod admin_delegated_authority;

#[path = "admin_application/admin_key_queries_and_audit.rs"]
mod admin_key_queries_and_audit;

#[path = "admin_application/admin_locked_configuration.rs"]
mod admin_locked_configuration;

#[path = "admin_application/admin_mint_policy_ceilings.rs"]
mod admin_mint_policy_ceilings;

#[path = "admin_application/admin_restart_refusal.rs"]
mod admin_restart_refusal;

#[path = "admin_application/admin_settings_boundaries.rs"]
mod admin_settings_boundaries;

#[path = "admin_application/admin_settings_persistence.rs"]
mod admin_settings_persistence;

#[path = "admin_application/admin_token_ttl_ceiling.rs"]
mod admin_token_ttl_ceiling;

#[path = "admin_application/config_at_rest_recovery.rs"]
mod config_at_rest_recovery;

#[path = "admin_application/config_key_transactions.rs"]
mod config_key_transactions;

#[path = "admin_application/config_price_activation.rs"]
mod config_price_activation;

#[path = "admin_application/config_secret_transaction.rs"]
mod config_secret_transaction;

#[path = "admin_application/service_group_deletion.rs"]
mod service_group_deletion;

#[path = "admin_application/service_groups.rs"]
mod service_groups;

#[path = "admin_application/service_hooks.rs"]
mod service_hooks;

#[path = "admin_application/service_named_defs.rs"]
mod service_named_defs;

#[path = "admin_application/service_plugin_policy.rs"]
mod service_plugin_policy;

#[path = "admin_application/service_hook_probe.rs"]
mod service_hook_probe;

#[path = "admin_application/service_plugin_integration.rs"]
mod service_plugin_integration;

#[path = "admin_application/service_plane_usage.rs"]
mod service_plane_usage;

#[path = "admin_application/service_group_usage.rs"]
mod service_group_usage;

#[path = "kernel_application/misc_boot.rs"]
mod misc_boot;

#[path = "kernel_application/misc_ingress_terminal.rs"]
mod misc_ingress_terminal;

#[path = "kernel_application/misc_operation.rs"]
mod misc_operation;

#[path = "kernel_application/misc_router_door.rs"]
mod misc_router_door;

#[path = "kernel_application/misc_router_session.rs"]
mod misc_router_session;

#[path = "kernel_application/auth_admin_tests.rs"]
mod kernel_application_auth_admin_tests;

#[path = "kernel_application/exports_projection.rs"]
mod kernel_application_exports_projection;

#[path = "kernel_application/hooks_runtime_replies.rs"]
mod kernel_application_hooks_runtime_replies;

#[path = "admin_application/admin_config_history_and_overlay.rs"]
mod admin_application_admin_config_history_and_overlay;

#[path = "admin_application/admin_corrupt_overlay_refusals.rs"]
mod admin_application_admin_corrupt_overlay_refusals;

#[path = "admin_application/admin_hook_crud_contracts.rs"]
mod admin_application_admin_hook_crud_contracts;

#[path = "admin_application/admin_hook_overlay_reset.rs"]
mod admin_application_admin_hook_overlay_reset;

#[path = "admin_application/admin_hook_read_metadata.rs"]
mod admin_application_admin_hook_read_metadata;

#[path = "admin_application/admin_key_mutation_gates.rs"]
mod admin_application_admin_key_mutation_gates;

#[path = "admin_application/admin_key_store_selection.rs"]
mod admin_application_admin_key_store_selection;

#[path = "admin_application/admin_named_map_scope.rs"]
mod admin_application_admin_named_map_scope;

#[path = "admin_application/admin_operation_namespaces.rs"]
mod admin_application_admin_operation_namespaces;

#[path = "admin_application/admin_overlay_boundaries.rs"]
mod admin_application_admin_overlay_boundaries;

#[path = "admin_application/admin_overlay_persist_failures.rs"]
mod admin_application_admin_overlay_persist_failures;

#[path = "admin_application/admin_restart_idempotency.rs"]
mod admin_application_admin_restart_idempotency;

#[path = "admin_application/admin_rotate_pool_ceilings.rs"]
mod admin_application_admin_rotate_pool_ceilings;

#[path = "admin_application/admin_scope_ladder.rs"]
mod admin_application_admin_scope_ladder;

#[path = "admin_application/admin_usage_model_key.rs"]
mod admin_application_admin_usage_model_key;

#[path = "../root/tests/serve_a2a_parity.rs"]
mod a2a_actual_parity;
