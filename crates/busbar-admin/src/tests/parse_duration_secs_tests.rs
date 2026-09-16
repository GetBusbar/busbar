// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/mod.rs`.
//!
//! The `MintPolicy`/`RoleCeiling`/`MintRequest`/`apply_mint_ttl_ceiling` unit tests that used to
//! live here RELOCATED to `governance/tests/mint_policy_tests.rs` alongside the type itself (1.6.0
//! de-alias, stage 2a). Only the `parse_duration_secs` unit tests remain — they exercise
//! `busbar_core::config::parse::parse_duration_secs`, re-imported into `admin::mod` for the mint-time
//! `expires_in` parse, not admin-surface vocabulary.

use super::parse_duration_secs;

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
