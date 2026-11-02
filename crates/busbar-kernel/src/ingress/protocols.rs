// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    let _ = path;
    None
}

pub fn residual_default_dialect() -> Option<&'static str> {
    None
}

pub fn vendor_auth_failure_message(proto: &str) -> &'static str {
    let _ = proto;
    "authentication failed"
}

pub fn quota_exceeded_status(proto: &str) -> u16 {
    let _ = proto;
    429
}

pub fn auth_failure_status_and_kind(proto: &str) -> (u16, &'static str) {
    let _ = proto;
    (401, busbar_contract::protocol::KIND_AUTHENTICATION)
}

pub fn error_parts(
    proto: &str,
    status: u16,
    kind: &str,
    message: &str,
) -> (serde_json::Value, Vec<(String, Vec<u8>)>) {
    let _ = (proto, status);
    (
        serde_json::json!({ "error": { "message": message, "type": kind } }),
        Vec::new(),
    )
}

pub fn uses_signed_ingress_auth(proto: &str) -> bool {
    let _ = proto;
    false
}
