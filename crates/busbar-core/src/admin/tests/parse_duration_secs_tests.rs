// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/mod.rs`.

use super::{apply_mint_ttl_ceiling, parse_duration_secs};

/// Unit multiplication is correct for each accepted suffix.
#[test]
fn each_unit_multiplies_correctly() {
    assert_eq!(parse_duration_secs("30s"), Ok(30));
    assert_eq!(parse_duration_secs("5m"), Ok(300));
    assert_eq!(parse_duration_secs("2h"), Ok(7200));
    assert_eq!(parse_duration_secs("3d"), Ok(259_200));
}

/// The max-duration bound is exactly 10 * 365 * 86_400 seconds (3650 days) — the boundary
/// itself must be accepted, and one day past it must be rejected. A mutated bound (e.g.
/// `10 + 365 * 86_400` instead of `10 * 365 * 86_400`) would reject values far below the real
/// 10-year limit, or accept values far above it, depending on the mutation.
#[test]
fn max_duration_boundary_is_exactly_ten_years() {
    assert_eq!(parse_duration_secs("3650d"), Ok(10 * 365 * 86_400));
    assert!(
        parse_duration_secs("3651d").is_err(),
        "one day past the 10-year bound must be rejected"
    );
}

/// No policy ceiling (`auth.policy.max_ttl` unset) is byte-identical pre-1.6.0 behavior: any
/// requested lifetime passes through unchanged, explicit or default.
#[test]
fn mint_ttl_ceiling_absent_is_a_passthrough() {
    assert_eq!(apply_mint_ttl_ceiling(86_400, true, None), Ok(86_400));
    assert_eq!(
        apply_mint_ttl_ceiling(90 * 86_400, false, None),
        Ok(90 * 86_400)
    );
}

/// A request AT or UNDER the ceiling is accepted verbatim, explicit or default.
#[test]
fn mint_ttl_ceiling_within_bound_is_unchanged() {
    let max = 7 * 86_400;
    assert_eq!(apply_mint_ttl_ceiling(max, true, Some(max)), Ok(max));
    assert_eq!(apply_mint_ttl_ceiling(3600, true, Some(max)), Ok(3600));
    assert_eq!(apply_mint_ttl_ceiling(3600, false, Some(max)), Ok(3600));
}

/// An EXPLICIT over-ask is REFUSED (the operator named a lifetime longer than policy allows), and
/// the error names the ceiling so the 4xx is actionable.
#[test]
fn mint_ttl_ceiling_refuses_explicit_over_ask() {
    let max = 7 * 86_400;
    let err = apply_mint_ttl_ceiling(30 * 86_400, true, Some(max))
        .expect_err("an explicit over-ask must be refused");
    assert!(err.contains("auth.policy.max_ttl"), "got: {err}");
    assert!(
        err.contains(&max.to_string()),
        "the ceiling is named: {err}"
    );
}

/// An over-long DEFAULT (no expires_in/expires_at) is CLAMPED down to the ceiling, never refused —
/// a default that predates a shorter policy must not silently outlive the cap, but it was never an
/// explicit ask to reject.
#[test]
fn mint_ttl_ceiling_clamps_over_long_default() {
    let max = 7 * 86_400;
    assert_eq!(
        apply_mint_ttl_ceiling(90 * 86_400, false, Some(max)),
        Ok(max),
        "the 90-day default is clamped to the 7-day policy ceiling"
    );
}
