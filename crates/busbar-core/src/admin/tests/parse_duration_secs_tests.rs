// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/mod.rs`.

use super::{apply_mint_ttl_ceiling, parse_duration_secs, MintPolicy, MintRequest, RoleCeiling};

const DAY: u64 = 86_400;

/// A `MintRequest` builder for the ceiling tests: caller `roles`, requested `pools` (3-state), a
/// `ttl` in seconds that is treated as EXPLICIT unless `default_ttl` is used, and no mode.
fn req<'a>(
    roles: &'a [String],
    pools: Option<&'a [String]>,
    ttl: u64,
    explicit: bool,
) -> MintRequest<'a> {
    MintRequest {
        roles,
        requested_pools: pools,
        requested_ttl_secs: ttl,
        explicit_ttl: explicit,
        requested_mode: None,
    }
}

fn role_policy(role: &str, ceiling: RoleCeiling, block_max_ttl: Option<u64>) -> MintPolicy {
    let mut ceilings = std::collections::BTreeMap::new();
    ceilings.insert(role.to_string(), ceiling);
    MintPolicy {
        self_mint: None,
        block_max_ttl_secs: block_max_ttl,
        block_binding_modes: None,
        ceilings,
    }
}

/// A role AT its TTL ceiling: a default (non-explicit) over-long request is CLAMPED down to the
/// role's `max_ttl`, even when the block cap is looser.
#[test]
fn mint_ceiling_role_ttl_clamps_the_default() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            max_ttl_secs: Some(7 * DAY),
            ..Default::default()
        },
        Some(30 * DAY), // looser block cap — the role narrows below it
    );
    let roles = vec!["app-admin".to_string()];
    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, false)),
        Ok(7 * DAY),
        "the default is clamped to the tighter role ceiling"
    );
}

/// An EXPLICIT TTL over-ask beyond the role ceiling is REFUSED.
#[test]
fn mint_ceiling_role_ttl_refuses_explicit_over_ask() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            max_ttl_secs: Some(7 * DAY),
            ..Default::default()
        },
        None,
    );
    let roles = vec!["app-admin".to_string()];
    assert!(
        policy
            .check_mint(&req(&roles, None, 30 * DAY, true))
            .is_err(),
        "an explicit request beyond the role TTL ceiling must be refused"
    );
}

/// A pool OUTSIDE the role's `allowed_pools` is refused (naming the offending pool); a subset is
/// allowed; requesting ALL pools under a finite ceiling is refused; the empty set is always allowed.
#[test]
fn mint_ceiling_role_pool_subset_is_enforced() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            allowed_pools: Some(vec!["growth".to_string(), "ops".to_string()]),
            ..Default::default()
        },
        None,
    );
    let roles = vec!["app-admin".to_string()];

    // subset OK
    let ok = vec!["growth".to_string()];
    assert!(policy
        .check_mint(&req(&roles, Some(&ok), DAY, true))
        .is_ok());

    // pool outside the ceiling → refused, naming it
    let bad = vec!["growth".to_string(), "secret".to_string()];
    let err = policy
        .check_mint(&req(&roles, Some(&bad), DAY, true))
        .expect_err("a pool outside the ceiling must be refused");
    assert!(err.contains("secret"), "the offending pool is named: {err}");

    // requesting ALL pools (None) under a finite ceiling → refused
    assert!(
        policy.check_mint(&req(&roles, None, DAY, true)).is_err(),
        "requesting ALL pools under a finite ceiling is an over-ask"
    );

    // the empty set is always within any ceiling
    let none: Vec<String> = Vec::new();
    assert!(policy
        .check_mint(&req(&roles, Some(&none), DAY, true))
        .is_ok());
}

/// A requested binding mode outside the role's allowed modes is refused; an allowed one passes.
#[test]
fn mint_ceiling_role_mode_membership_is_enforced() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            binding_modes: Some(vec!["time-bound".to_string()]),
            ..Default::default()
        },
        None,
    );
    let roles = vec!["app-admin".to_string()];

    let allowed = MintRequest {
        requested_mode: Some("time-bound"),
        ..req(&roles, None, DAY, true)
    };
    assert!(policy.check_mint(&allowed).is_ok());

    let refused = MintRequest {
        requested_mode: Some("user-bound"),
        ..req(&roles, None, DAY, true)
    };
    let err = policy
        .check_mint(&refused)
        .expect_err("a mode outside the role ceiling must be refused");
    assert!(
        err.contains("user-bound"),
        "the offending mode is named: {err}"
    );
}

/// A caller whose roles carry NO `mint_ceilings` entry falls back to the BLOCK caps alone: the block
/// TTL still clamps, and there is no pool restriction (the block level carries none).
#[test]
fn mint_ceiling_no_role_ceiling_falls_back_to_block() {
    let policy = MintPolicy {
        self_mint: None,
        block_max_ttl_secs: Some(14 * DAY),
        block_binding_modes: None,
        ceilings: std::collections::BTreeMap::new(),
    };
    let roles = vec!["some-unrelated-role".to_string()];

    // block TTL clamps the default
    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, false)),
        Ok(14 * DAY)
    );
    // no pool restriction from the block level: requesting ALL pools is fine
    assert!(policy.check_mint(&req(&roles, None, DAY, true)).is_ok());
    // an explicit under-block request is unchanged
    assert_eq!(policy.check_mint(&req(&roles, None, DAY, true)), Ok(DAY));
}

/// The per-role ceiling narrows BELOW the block cap but never above it: effective TTL = min(block,
/// role). A role permitting 30d under a 7d block is still capped at 7d.
#[test]
fn mint_ceiling_role_cannot_exceed_the_block_cap() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            max_ttl_secs: Some(30 * DAY), // role would allow more...
            ..Default::default()
        },
        Some(7 * DAY), // ...but the block hard-caps at 7d
    );
    let roles = vec!["app-admin".to_string()];
    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, false)),
        Ok(7 * DAY),
        "the block cap bounds even a looser role ceiling"
    );
}

/// The empty policy (no `auth.policy:`) is a full passthrough — byte-identical pre-1.6.0 behavior.
#[test]
fn mint_ceiling_empty_policy_is_passthrough() {
    let policy = MintPolicy::default();
    let roles: Vec<String> = vec!["anyone".to_string()];
    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, true)),
        Ok(90 * DAY)
    );
}

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
