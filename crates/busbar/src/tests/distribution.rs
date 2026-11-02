#[path = "../../../../dist/default/tests/product/auth_plugin_chain.rs"]
mod auth_plugin_chain;

#[path = "../../../../dist/default/tests/product/auth_plugin_chain_trust.rs"]
mod auth_plugin_chain_trust;

#[path = "../../../../dist/default/tests/product/plugin_preflight_scan.rs"]
mod plugin_preflight_scan;

#[cfg(feature = "auth-admin-tokens")]
#[path = "../../../../dist/default/tests/admin_cross_plane/main.rs"]
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
