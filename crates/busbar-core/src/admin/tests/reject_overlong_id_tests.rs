// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/mod.rs`.

use super::{reject_overlong_id, KeyAudit, MAX_KEY_ID_LEN};

/// The bound is exact: an id of exactly `MAX_KEY_ID_LEN` chars is acceptable (`None`); one char
/// past it is rejected (`Some`). A mutated `>` → `>=` would reject the boundary length itself,
/// which a real minted id (`vk_` + 16 hex = 19 chars) never reaches but a caller passing exactly
/// the documented max legitimately could.
#[test]
fn id_length_boundary_is_exact() {
    let at_max = "a".repeat(MAX_KEY_ID_LEN);
    assert!(
        reject_overlong_id(KeyAudit::Read, &at_max).is_none(),
        "an id of exactly MAX_KEY_ID_LEN chars must be accepted"
    );

    let over_max = "a".repeat(MAX_KEY_ID_LEN + 1);
    assert!(
        reject_overlong_id(KeyAudit::Read, &over_max).is_some(),
        "an id one char past MAX_KEY_ID_LEN must be rejected"
    );
}

/// EVERY `/api/v1/admin/keys/{id}` handler must RUN the guard — the boundary test above proves the
/// helper works, which is worth nothing on a handler that never calls it.
///
/// `rotate_key` was the one that did not, and it is the worst one to miss: it is the only `{id}`
/// handler that STORES the id rather than merely looking it up. An unbounded id reaches
/// `resource = format!("key:{id}")`, which every audit row for the operation then carries (the admin
/// audit ring is bounded by ENTRY COUNT, not by bytes), and it reaches the idempotency cache key
/// `rotate:{id}:{header}`, whose stale entries are only swept on the NEXT use of that cache. So a
/// run of `POST /keys/<megabytes of 'a'>/rotate` pinned resident admin memory that nothing reclaims
/// — precisely the "DB/log-bloat guard" the helper's own doc comment says it exists to be.
///
/// This is a SOURCE-level sweep on purpose. The defect is a MISSING CALL, so no test of any single
/// handler catches it; only a check that enumerates the whole route family does, and that is also
/// what catches the next handler added without one.
#[test]
fn every_keys_id_handler_bounds_the_path_id() {
    let src = include_str!("../mod.rs");
    for func in [
        "async fn update_key(",
        "async fn rotate_key(",
        "async fn revoke_key(",
        "async fn get_key(",
        "async fn key_usage(",
        "async fn delete_key(",
    ] {
        let start = src.find(func).unwrap_or_else(|| {
            panic!("{func} no longer exists in admin/mod.rs — update this test to match the routes")
        });
        let rest = &src[start + func.len()..];
        // The body runs to the start of the next top-level function, or to EOF.
        let end = rest
            .find("\nasync fn ")
            .into_iter()
            .chain(rest.find("\npub(crate) async fn "))
            .chain(rest.find("\nfn "))
            .min()
            .unwrap_or(rest.len());
        assert!(
            rest[..end].contains("reject_overlong_id"),
            "{func} takes a caller-supplied path id and never bounds it. An unbounded id reaches \
             the audit `resource` string, the store lookup, and — for rotate — the idempotency \
             cache key, none of which are byte-bounded. Add \
             `if let Some(resp) = reject_overlong_id(who, &id) {{ return resp; }}`."
        );
    }
}
