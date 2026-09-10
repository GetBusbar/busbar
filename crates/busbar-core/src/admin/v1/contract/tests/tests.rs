use super::*;

/// GOLDEN WIRE LITERALS: the mount constants pinned byte-for-byte. Everything else in the app
/// DERIVES paths from these constants (no hand-written absolute path anywhere) — so this pin is
/// the ONE place a path change must be made deliberately, and the tripwire that catches an
/// accidental edit sailing through the derived code.
#[test]
fn mount_constants_are_the_frozen_wire_literals() {
    assert_eq!(API_ROOT, "/api");
    assert_eq!(ADMIN_PREFIX, "/api/v1/admin");
    assert!(
        ADMIN_PREFIX.starts_with(API_ROOT),
        "the admin prefix hangs off the native-API root"
    );
}

/// The stable error taxonomy is locked: each variant's `code` + HTTP status is the frozen wire
/// contract tooling branches on. A change here is a breaking change to v1 and must fail this test.
#[test]
fn admin_error_codes_and_statuses_are_frozen() {
    let cases = [
        (AdminError::not_found("key"), "not_found", 404u16),
        (AdminError::Unauthorized, "unauthorized", 401),
        (AdminError::MethodNotAllowed, "method_not_allowed", 405),
        (
            AdminError::Forbidden {
                needed: Scope::Full,
            },
            "forbidden",
            403,
        ),
        (AdminError::Validation("bad".into()), "invalid_request", 400),
        (
            AdminError::VersionConflict("stale".into()),
            "version_conflict",
            409,
        ),
        (AdminError::Conflict("state".into()), "conflict", 409),
        (AdminError::RateLimited, "rate_limited", 429),
        (AdminError::Internal, "internal", 500),
        (AdminError::Unavailable("busy".into()), "unavailable", 503),
    ];
    for (e, code, status) in cases {
        assert_eq!(e.code(), code, "frozen error code changed");
        assert_eq!(e.http_status(), status, "frozen error status changed");
    }
}

/// CONTRACT: the admin usage response ALWAYS serializes `currency: "USD"`, sourced from the
/// single `USAGE_CURRENCY` const (so a future removal is one line). Emitted ONLY on `UsageView`
/// (the `GET /api/v1/admin/usage` surface); the per-key/per-model ledger views stay
/// currency-agnostic. Regression guard: dropping this field breaks the contract and the
/// committed openapi.json.
#[test]
fn usage_view_serializes_currency_from_const() {
    let view = UsageView {
        window: UsageWindow { start: 0, end: 1 },
        as_of: 0,
        currency: (),
        total: UsageBreakdown::default(),
        by_model: Vec::new(),
        by_key: Vec::new(),
        by_key_truncated: false,
        others: None,
    };
    let v: serde_json::Value = serde_json::to_value(&view).expect("serialize UsageView");
    assert_eq!(
        v.get("currency").and_then(|c| c.as_str()),
        Some(USAGE_CURRENCY),
        "usage response must carry the currency field from the USAGE_CURRENCY const"
    );
    assert_eq!(USAGE_CURRENCY, "USD");
    // The per-model / per-key ledger rows stay currency-agnostic (no currency key).
    let row = UsageBreakdown::default();
    let rv: serde_json::Value = serde_json::to_value(row).expect("serialize breakdown");
    assert!(
        rv.get("currency").is_none(),
        "the raw-split ledger breakdown must NOT carry a currency"
    );
}
