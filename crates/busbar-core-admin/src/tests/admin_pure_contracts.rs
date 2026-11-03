// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

const LOCKED_CONFIG_MUTATION_MESSAGE: &str = "config mutation refused: this busbar has no writable Store-backed config overlay; edit config.yaml and reload a locked deployment";

#[test]
fn test_existence_gate_is_claimable_without_runtime() {
    let first = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(first);
    let again = super::EXISTENCE_GATE.claim("vk_gate_probe".to_string());
    drop(again);
}

#[test]
fn test_persist_root_without_an_overlay_errs() {
    let result = busbar_kernel::config::overlay::persist_root(
        None,
        &busbar_kernel::config::overlay::RootSettings::default(),
    );
    assert!(
        result.is_err(),
        "persist_root(None, ..) must NOT silently succeed — a None backend means a locked config, so \
         the mutation is refused, never falsely reported as persisted"
    );
    let msg = result.unwrap_err();
    assert_eq!(
        msg, LOCKED_CONFIG_MUTATION_MESSAGE,
        "the error must explain the locked/no-overlay posture: {msg}"
    );
}

#[test]
fn test_config_settings_scope_matrix() {
    use axum::http::Method;
    assert_eq!(
        crate::v1::contract::required_scope(&Method::PUT, "/api/v1/admin/config/settings").as_str(),
        "full",
        "PUT /config/settings is a full-scope mutation"
    );
    assert_eq!(
        crate::v1::contract::required_scope(&Method::GET, "/api/v1/admin/config/settings").as_str(),
        "read-only",
        "GET /config/settings is read-only"
    );

    assert_eq!(
        crate::v1::contract::required_scope(&Method::DELETE, "/api/v1/admin/overlay/root").as_str(),
        "full",
        "a root reset is a full-scope mutation"
    );
}

#[test]
fn key_replay_names_match_the_actual_http_controls() {
    assert_eq!(
        crate::idempotency::create_replay_key("stuck-mint"),
        "create:10:stuck-mint"
    );
    let id = "actual-key-id";
    assert_eq!(
        crate::idempotency::rotate_replay_key(id, "stuck-rotate"),
        format!("rotate:{}:{id}:12:stuck-rotate", id.len())
    );
}

#[test]
fn audience_key_mint_validates_explicit_scope_without_changing_default_requests() {
    for body in [
        serde_json::json!({"name": "plain"}),
        serde_json::json!({"name": "scoped", "audience": "https://gateway.example/v1/realtime"}),
    ] {
        let req: super::CreateKeyReq = serde_json::from_value(body).unwrap();
        assert!(req.validate_audience().is_ok());
    }
    for body in [
        serde_json::json!({"name": "empty", "audience": ""}),
        serde_json::json!({"name": "blank", "audience": "  "}),
        serde_json::json!({"name": "unsupported", "audience": "https://gateway.example/v1/realtime", "issue_aws_credential": true}),
    ] {
        let req: super::CreateKeyReq = serde_json::from_value(body).unwrap();
        assert!(req.validate_audience().is_err());
    }
    assert!(serde_json::from_value::<super::CreateKeyReq>(
        serde_json::json!({"name": "wrong-type", "audience": 7})
    )
    .is_err());
}
