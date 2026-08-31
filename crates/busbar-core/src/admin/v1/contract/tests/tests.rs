use super::*;
use axum::http::Method;

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
        assert_eq!(
            required_scope(&Method::GET, path),
            Scope::ReadOnly,
            "{path}"
        );
    }
    // The two stateless dry-run POSTs stay read-only.
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/config/validate"),
        Scope::ReadOnly
    );
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/plugins/inspect"),
        Scope::ReadOnly
    );
    // Every mutation is now full — hooks, keys, config, groups alike.
    for (method, path) in [
        (Method::POST, "/api/v1/admin/hooks"),
        (Method::DELETE, "/api/v1/admin/hooks/my-hook"),
        (Method::PATCH, "/api/v1/admin/hooks/my-hook/settings"),
        (Method::POST, "/api/v1/admin/keys"),
        (Method::DELETE, "/api/v1/admin/keys/vk_123"),
        (Method::POST, "/api/v1/admin/keys/vk_123/rotate"),
        (Method::POST, "/api/v1/admin/config/apply"),
        (Method::POST, "/api/v1/admin/groups"),
    ] {
        assert_eq!(
            required_scope(&method, path),
            Scope::Full,
            "{method} {path}"
        );
    }
    assert_eq!(
        required_scope(&Method::OPTIONS, "/api/v1/admin/hooks"),
        Scope::Full,
        "unknown methods fail closed"
    );
}

/// Every mutating verb resolves to `Full`, and the read verbs (+ the two dry-run POSTs) to
/// `ReadOnly`. The narrower `hooks-register`/`mint` requirements are GONE.
#[test]
fn required_scope_mutations_are_full() {
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/keys"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/hooks"),
        Scope::Full
    );
    assert_eq!(
        required_scope(&Method::GET, "/api/v1/admin/keys"),
        Scope::ReadOnly
    );
    assert_eq!(
        required_scope(&Method::POST, "/api/v1/admin/config/validate"),
        Scope::ReadOnly
    );
}

/// `parse` drops the retired delegated tokens (they now resolve to `None`, i.e. no grant), while
/// `read-only`/`full` still round-trip.
#[test]
fn scope_parse_drops_mint_and_hooks_register() {
    assert!(Scope::parse("mint").is_none());
    assert!(Scope::parse("hooks-register").is_none());
    assert!(Scope::parse("bogus").is_none());
    assert_eq!(Scope::parse("read-only"), Some(Scope::ReadOnly));
    assert_eq!(Scope::parse("full"), Some(Scope::Full));
    assert_eq!(Scope::ReadOnly.as_str(), "read-only");
    assert_eq!(Scope::Full.as_str(), "full");
}

/// The two-rung chain: `ReadOnly` does not satisfy a `Full` requirement, `Full` satisfies both, and
/// a `Full` grant capped by a `ReadOnly` ceiling collapses to read-only.
#[test]
fn readonly_not_allow_full_full_allows_readonly() {
    assert!(!Scope::ReadOnly.allows(Scope::Full));
    assert!(Scope::ReadOnly.allows(Scope::ReadOnly));
    assert!(Scope::Full.allows(Scope::ReadOnly));
    assert!(Scope::Full.allows(Scope::Full));

    // Grants: a Full grant capped by a ReadOnly ceiling authorizes reads but not mutations.
    let capped = Grants::of(Scope::Full).capped_by(Scope::ReadOnly);
    assert!(capped.allows(Scope::ReadOnly));
    assert!(!capped.allows(Scope::Full));

    // `with` is a union over `allows`, and `dominates`/`meet` derive from the same seam.
    for a in Scope::ALL {
        for b in Scope::ALL {
            let union = Grants::of(a).with(b);
            for n in Scope::ALL {
                assert_eq!(
                    union.allows(n),
                    a.allows(n) || b.allows(n),
                    "Grants::of({a:?}).with({b:?}).allows({n:?})"
                );
            }
        }
    }
    assert_eq!(Scope::Full.meet(Scope::ReadOnly), Scope::ReadOnly);
    assert!(Scope::Full.dominates(Scope::ReadOnly));
    assert!(!Scope::ReadOnly.dominates(Scope::Full));
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
