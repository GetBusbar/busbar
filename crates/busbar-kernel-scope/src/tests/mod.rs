// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

mod egress;

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

/// THE PORT IS VERBATIM OR IT IS A SECOND MATRIX WITH A SECOND OPINION.
///
/// Three ways a second copy of this matrix once differed from the enforced one (there is one copy
/// now; the kernel's admin gate calls this function), each still asserted against the behaviour of
/// 1.5.5's `axum::http::Method`-backed original:
///
/// 1. A NON-CANONICAL VERB IS NOT A READ. `Method`'s equality is case-sensitive (RFC 9110 §9.1):
///    `get` is an EXTENSION method that merely looks like `GET`, and the enforced matrix therefore
///    fails it closed to `full`. Case-folding it here DOWNGRADED it to `read-only` — the wrong
///    direction for an authorization matrix to differ in.
/// 2. THE DRY-RUN PATHS ARE MATCHED ON PATH ALONE, no method gate, exactly as the enforced matrix
///    matches them.
/// 3. THE QUERY STRING IS NOT PART OF THE OPERATION. The enforced matrix is handed `uri().path()`;
///    this one is handed the recorded request path, which carries `?query`.
#[test]
fn the_scope_matrix_matches_the_enforced_one_verbatim() {
    // 1. Non-canonical verbs fail CLOSED, never fold into a read.
    for verb in ["get", "Get", "gEt", "head", "Head", "post", "Post"] {
        assert_eq!(
            admin_required_scope(verb, "/api/v1/admin/keys"),
            Scope::Full,
            "`{verb}` is an extension method, not a read: it must fail closed to full"
        );
    }
    // Not even for the dry-run paths, where a folded `post` used to be the gate's own condition.
    for verb in ["post", "Post", "POSt"] {
        assert_eq!(
            admin_required_scope(verb, "/api/v1/admin/config/validate"),
            Scope::ReadOnly,
            "the dry-run rows are matched on PATH alone, as the enforced matrix matches them"
        );
    }

    // 2. The dry-run paths carry no method gate at all — the enforced matrix answers `read-only`
    //    for them whatever the verb, and so does this one.
    for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
        for path in [
            "/api/v1/admin/config/validate",
            "/api/v1/admin/plugins/inspect",
        ] {
            assert_eq!(
                admin_required_scope(method, path),
                Scope::ReadOnly,
                "{method} {path}: path membership alone decides, same as core"
            );
        }
    }

    // 3. A query string never changes which row a request is. `GET /audit?limit=4` and
    //    `GET /audit` are one operation, and so are the dry-run POSTs with and without one.
    assert_eq!(
        admin_required_scope("POST", "/api/v1/admin/config/validate?strict=1"),
        Scope::ReadOnly,
        "a read-only CI token must still be able to lint a config it passed a query on"
    );
    assert_eq!(
        admin_required_scope("POST", "/api/v1/admin/plugins/inspect?verbose"),
        Scope::ReadOnly
    );
    assert_eq!(
        admin_required_scope("GET", "/api/v1/admin/audit?limit=4"),
        Scope::ReadOnly
    );
    // And the query cannot be used to smuggle a mutation into a dry-run row either.
    assert_eq!(
        admin_required_scope("POST", "/api/v1/admin/config/apply?dry=/config/validate"),
        Scope::Full,
        "the row is decided by the path, and the path here is the apply row"
    );
    assert_eq!(
        admin_required_scope("POST", "/api/v1/admin/keys?x=/plugins/inspect"),
        Scope::Full
    );
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
