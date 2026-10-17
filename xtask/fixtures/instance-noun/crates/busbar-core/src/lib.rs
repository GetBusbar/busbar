// FIXTURE for instance-noun-neutrality selftest. Every plugin-instance noun below is named
// in code by a NON-family crate (busbar-core), so each noun's census row must go RED.
pub fn mcp_leak() {}
pub fn a2a_leak() {}
pub fn llm_leak() {}
pub fn busbar_plane_streaming_leak() {}
pub fn voice_leak() {}
pub fn jev_leak() {}
pub fn busbar_transport_http_leak() {}
pub fn busbar_transport_ws_leak() {}
pub fn busbar_transport_stdio_leak() {}
pub fn busbar_transport_tcp_leak() {}
pub fn busbar_transport_tls_leak() {}
pub fn busbar_transport_sse_leak() {}
pub fn busbar_transport_grpc_leak() {}
pub fn postgres_leak() {}
pub fn mysql_leak() {}
pub fn valkey_leak() {}
pub fn sqlite_leak() {}
pub fn sigv4_leak() {}
pub fn gcp_leak() {}
pub fn hashicorp_vault_leak() {}
pub fn hook_test_plugin_leak() {}
pub fn busbar_store_memory_leak() {}
pub const GOVERNANCE_STORE_MEMORY_LEAK: &str = "memory";
pub fn busbar_hook_ranking_leak() {}
// The linked plugin instances (audit XG HIGH 3): each named by its crate identifier.
pub fn busbar_plane_decisions_leak() {}
pub fn busbar_transport_webrtc_leak() {}
pub fn busbar_secret_env_leak() {}
pub fn busbar_secret_file_leak() {}
pub fn busbar_auth_header_leak() {}
pub fn busbar_auth_sigv4_leak() {}
pub fn busbar_auth_oauth_leak() {}
pub fn busbar_auth_oidc_leak() {}
pub fn busbar_auth_webhook_signature_leak() {}
pub fn busbar_auth_admin_tokens_plugin_leak() {}
pub fn busbar_export_file_leak() {}
pub fn busbar_export_webhook_leak() {}
pub fn busbar_export_prometheus_leak() {}
pub fn busbar_export_otlp_leak() {}
