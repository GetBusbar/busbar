// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// The authorization matrix, ported from 1.5.5's `required_scope_matrix` test: reads (+ the two
/// dry-run POSTs) are read-only, every mutation is full, unknown methods fail closed to full.
#[test]
fn required_scope_matrix() {
    for path in [
        "/api/v1/admin/info",
        "/api/v1/admin/hooks",
        "/api/v1/admin/keys",
        "/api/v1/admin/config",
        "/api/v1/admin/audit",
    ] {
        assert_eq!(admin_required_scope("GET", path), Scope::ReadOnly, "{path}");
    }
    assert_eq!(
        admin_required_scope("POST", "/api/v1/admin/config/validate"),
        Scope::ReadOnly
    );
    assert_eq!(
        admin_required_scope("POST", "/api/v1/admin/plugins/inspect"),
        Scope::ReadOnly
    );
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
        assert_eq!(
            admin_required_scope(method, path),
            Scope::Full,
            "{method} {path}"
        );
    }
    assert_eq!(
        admin_required_scope("OPTIONS", "/api/v1/admin/hooks"),
        Scope::Full,
        "unknown methods fail closed"
    );
}

/// `parse` drops the retired delegated tokens; `read-only`/`full` round-trip.
#[test]
fn scope_parse_drops_retired_tokens() {
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

    let capped = Grants::of(Scope::Full).capped_by(Scope::ReadOnly);
    assert!(capped.allows(Scope::ReadOnly));
    assert!(!capped.allows(Scope::Full));

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

/// The APPROVE step itself: a principal whose grants allow the needed scope is approved; one that
/// doesn't is refused naming the scope that would have sufficed.
#[test]
fn approve_checks_held_grants_against_needed_scope() {
    assert!(approve(Grants::of(Scope::Full), Scope::ReadOnly).is_ok());
    assert!(approve(Grants::of(Scope::Full), Scope::Full).is_ok());
    assert!(approve(Grants::of(Scope::ReadOnly), Scope::ReadOnly).is_ok());
    assert_eq!(
        approve(Grants::of(Scope::ReadOnly), Scope::Full),
        Err(Refused::InsufficientScope {
            needed: Scope::Full
        })
    );
    // No grants at all refuses everything, including a read.
    assert_eq!(
        approve(Grants::default(), Scope::ReadOnly),
        Err(Refused::InsufficientScope {
            needed: Scope::ReadOnly
        })
    );
}

/// `transport:handshake` is a plain constant every principal is granted without a `Policy` entry —
/// pinned so a future edit to the literal is deliberate, not a typo.
#[test]
fn transport_handshake_is_the_pinned_kernel_grant() {
    assert_eq!(TRANSPORT_HANDSHAKE, "transport:handshake");
}

/// The data-listener operational routes bypass the ordinary scope check on an exact-path match only
/// on an exact-path match only: a path that merely starts with one of them is not granted.
#[test]
fn kernel_granted_routes_are_exact_path_matches() {
    for p in ["/healthz", "/stats", "/metrics", "/metrics/hooks"] {
        assert!(is_kernel_granted(p), "{p}");
    }
    assert!(!is_kernel_granted("/healthzzz"));
    assert!(!is_kernel_granted("/api/v1/admin/healthz"));
    assert!(!is_kernel_granted("/metrics/hooks/extra"));
}

/// The table test: `required_scope` reproduces every one of the 66 pinned 1.5.5 admin operations,
/// and the table's own read-only/full split is exactly 34/32.
#[test]
fn required_scope_matches_every_pinned_admin_operation() {
    assert_eq!(
        ADMIN_SCOPE_TABLE.len(),
        66,
        "the 1.5.5 admin API had exactly 66 operations at the tag"
    );
    let read_only = ADMIN_SCOPE_TABLE
        .iter()
        .filter(|o| o.scope == Scope::ReadOnly)
        .count();
    let full = ADMIN_SCOPE_TABLE
        .iter()
        .filter(|o| o.scope == Scope::Full)
        .count();
    assert_eq!(read_only, 34, "34 read-only operations");
    assert_eq!(full, 32, "32 full operations");

    for entry in ADMIN_SCOPE_TABLE {
        assert_eq!(
            admin_required_scope(entry.method, entry.path),
            entry.scope,
            "{} {}",
            entry.method,
            entry.path
        );
    }
}

/// Every path in the table is `ADMIN_PREFIX`-rooted and every method is one of the five HTTP verbs
/// the admin API actually uses — a sanity check on the table's own shape, independent of
/// `required_scope`.
#[test]
fn admin_scope_table_rows_are_well_formed() {
    for entry in ADMIN_SCOPE_TABLE {
        assert!(
            entry.path.starts_with(ADMIN_PREFIX),
            "{} is not ADMIN_PREFIX-rooted",
            entry.path
        );
        assert!(
            matches!(entry.method, "GET" | "POST" | "PUT" | "PATCH" | "DELETE"),
            "unexpected method {} on {}",
            entry.method,
            entry.path
        );
    }
}

/// The design's own lookup key is the pair `(claim, operation class)`, and it can now be spelled.
///
/// Until the contract crate carried a claim's name, a 1.6.0-native plane had no way to be scoped at
/// all: its operations could be declared, but nothing could say which of its claims a policy entry
/// was about. What this pins is the two answers that are not "look it up": a pair the policy says
/// nothing about has no required scope, which is a refusal rather than a pass.
#[test]
fn a_claims_operation_class_is_scoped_through_the_policy() {
    use busbar_contract::{ClaimKey, OpClassId};

    struct OnePolicy;
    impl crate::PolicyView for OnePolicy {
        fn required_scope(&self, claim: ClaimKey, op: OpClassId) -> Option<Scope> {
            match (claim.as_str(), op.as_str()) {
                ("chat", "completion") => Some(Scope::ReadOnly),
                ("chat", "mint") => Some(Scope::Full),
                _ => None,
            }
        }
    }

    let policy = OnePolicy;
    assert_eq!(
        crate::required_scope(ClaimKey::new("chat"), OpClassId::new("completion"), &policy),
        Some(Scope::ReadOnly)
    );
    assert_eq!(
        crate::required_scope(ClaimKey::new("chat"), OpClassId::new("mint"), &policy),
        Some(Scope::Full)
    );
    // The same operation class under a claim the policy does not mention is not the same question.
    assert_eq!(
        crate::required_scope(
            ClaimKey::new("other"),
            OpClassId::new("completion"),
            &policy
        ),
        None,
        "an operation nobody wrote a policy entry for has not been authorized"
    );
}
