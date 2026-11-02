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
