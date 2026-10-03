// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// The gate's refusals are frozen wire facts: tooling branches on the code, and the status and
/// message are what 1.5.5 answered.
#[test]
fn refusal_codes_statuses_and_messages_are_frozen() {
    let cases = [
        (
            Refusal::NotFound {
                what: "resource".into(),
            },
            "not_found",
            404u16,
            "resource not found",
        ),
        (
            Refusal::Unauthorized,
            "unauthorized",
            401,
            "missing or invalid admin credential (Bearer or x-admin-token)",
        ),
        (
            Refusal::MethodNotAllowed,
            "method_not_allowed",
            405,
            "method not allowed for this resource",
        ),
        (
            Refusal::RateLimited,
            "rate_limited",
            429,
            "admin mutation rate limit exceeded; retry next minute",
        ),
        (Refusal::Internal, "internal", 500, "internal error"),
    ];
    for (r, code, status, message) in cases {
        assert_eq!(r.code(), code);
        assert_eq!(r.status(), status);
        assert_eq!(r.message(), message);
    }
}

/// The envelope bytes are the frozen `{"error":{"code","message"}}` shape, keys in that order.
#[test]
fn the_envelope_is_the_frozen_shape() {
    assert_eq!(
        envelope("not_found", "resource not found"),
        r#"{"error":{"code":"not_found","message":"resource not found"}}"#
    );
}

/// The authorization matrix, test-locked (1.5.2 scope collapse): reads (+ the two dry-run POSTs)
/// are read-only, every mutation is full. Unknown methods fail closed to full.
#[test]
fn required_scope_matrix() {
    for path in [
        "/api/v1/admin/info",
        "/api/v1/admin/hooks",
        "/api/v1/admin/keys",
        "/api/v1/admin/config",
        "/api/v1/admin/audit",
    ] {
        assert_eq!(required_scope("GET", path), Scope::ReadOnly, "{path}");
    }
    // The two stateless dry-run POSTs stay read-only.
    assert_eq!(
        required_scope("POST", "/api/v1/admin/config/validate"),
        Scope::ReadOnly
    );
    assert_eq!(
        required_scope("POST", "/api/v1/admin/plugins/inspect"),
        Scope::ReadOnly
    );
    // Every mutation is now full — hooks, keys, config, groups alike.
    for (method, path) in [
        ("POST", "/api/v1/admin/hooks"),
        ("DELETE", "/api/v1/admin/hooks/my-hook"),
        ("PATCH", "/api/v1/admin/hooks/my-hook/settings"),
        ("POST", "/api/v1/admin/keys"),
        ("DELETE", "/api/v1/admin/keys/vk_123"),
        ("POST", "/api/v1/admin/keys/vk_123/rotate"),
        ("POST", "/api/v1/admin/config/apply"),
        ("POST", "/api/v1/admin/groups"),
    ] {
        assert_eq!(required_scope(method, path), Scope::Full, "{method} {path}");
    }
    assert_eq!(
        required_scope("OPTIONS", "/api/v1/admin/hooks"),
        Scope::Full,
        "unknown methods fail closed"
    );
}

/// Every mutating verb resolves to `Full`, and the read verbs (+ the two dry-run POSTs) to
/// `ReadOnly`. The narrower `hooks-register`/`mint` requirements are GONE.
#[test]
fn required_scope_mutations_are_full() {
    assert_eq!(required_scope("POST", "/api/v1/admin/keys"), Scope::Full);
    assert_eq!(required_scope("POST", "/api/v1/admin/hooks"), Scope::Full);
    assert_eq!(required_scope("GET", "/api/v1/admin/keys"), Scope::ReadOnly);
    assert_eq!(
        required_scope("POST", "/api/v1/admin/config/validate"),
        Scope::ReadOnly
    );
}
