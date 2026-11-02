#[path = "../../../../dist/default/tests/product/auth_plugin_chain.rs"]
mod auth_plugin_chain;

#[path = "../../../../dist/default/tests/product/auth_plugin_chain_trust.rs"]
mod auth_plugin_chain_trust;

#[path = "../../../../dist/default/tests/product/plugin_preflight_scan.rs"]
mod plugin_preflight_scan;

#[cfg(feature = "auth-admin-tokens")]
#[path = "../../../../dist/default/tests/admin_cross_plane/main.rs"]
mod admin_cross_plane;
