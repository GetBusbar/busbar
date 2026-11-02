// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{apply_mint_ttl_ceiling, MintPolicy, MintRequest, RoleCeiling};

const DAY: u64 = 86_400;

fn req<'a>(
    roles: &'a [String],
    pools: Option<&'a [String]>,
    ttl: u64,
    explicit: bool,
) -> MintRequest<'a> {
    MintRequest {
        roles,
        requested_pools: pools,
        grants_other_kinds: false,
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

#[test]
fn mint_ceiling_of_named_pools_refuses_a_grant_of_another_kind() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            allowed_pools: Some(vec!["fast".to_string()]),
            ..Default::default()
        },
        None,
    );
    let roles = vec!["app-admin".to_string()];
    let pools = vec!["fast".to_string()];
    let other = MintRequest {
        grants_other_kinds: true,
        ..req(&roles, Some(&pools), DAY, true)
    };
    let err = policy
        .check_mint(&other)
        .expect_err("another kind under a pool ceiling must be refused");
    assert!(err.contains("auth.policy.mint_ceilings"), "got: {err}");
    assert!(policy
        .check_mint(&req(&roles, Some(&pools), DAY, true))
        .is_ok());
    let unceilinged = vec!["someone-else".to_string()];
    assert!(policy
        .check_mint(&MintRequest {
            grants_other_kinds: true,
            ..req(&unceilinged, Some(&pools), DAY, true)
        })
        .is_ok());
}

#[test]
fn mint_ceiling_role_ttl_clamps_the_default() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            max_ttl_secs: Some(7 * DAY),
            ..Default::default()
        },
        Some(30 * DAY),
    );
    let roles = vec!["app-admin".to_string()];
    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, false)),
        Ok(7 * DAY),
        "the default is clamped to the tighter role ceiling"
    );
}

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

    let ok = vec!["growth".to_string()];
    assert!(policy
        .check_mint(&req(&roles, Some(&ok), DAY, true))
        .is_ok());

    let bad = vec!["growth".to_string(), "secret".to_string()];
    let err = policy
        .check_mint(&req(&roles, Some(&bad), DAY, true))
        .expect_err("a pool outside the ceiling must be refused");
    assert!(err.contains("secret"), "the offending pool is named: {err}");

    assert!(
        policy.check_mint(&req(&roles, None, DAY, true)).is_err(),
        "requesting ALL pools under a finite ceiling is an over-ask"
    );

    let none: Vec<String> = Vec::new();
    assert!(policy
        .check_mint(&req(&roles, Some(&none), DAY, true))
        .is_ok());
}

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

#[test]
fn mint_ceiling_role_modes_cannot_widen_the_block_modes() {
    let mut policy = role_policy(
        "app-admin",
        RoleCeiling {
            binding_modes: Some(vec!["time-bound".to_string(), "user-bound".to_string()]),
            ..Default::default()
        },
        None,
    );
    policy.block_binding_modes = Some(vec!["user-bound".to_string()]);
    let roles = vec!["app-admin".to_string()];

    let widened = MintRequest {
        requested_mode: Some("time-bound"),
        ..req(&roles, None, DAY, true)
    };
    let err = policy
        .check_mint(&widened)
        .expect_err("a mode the block forbids is refused whatever the role allows");
    assert!(
        err.contains("time-bound"),
        "the offending mode is named: {err}"
    );

    let within = MintRequest {
        requested_mode: Some("user-bound"),
        ..req(&roles, None, DAY, true)
    };
    assert!(
        policy.check_mint(&within).is_ok(),
        "a mode both lists allow passes"
    );
}

#[test]
fn mint_ceiling_no_role_ceiling_falls_back_to_block() {
    let policy = MintPolicy {
        self_mint: None,
        block_max_ttl_secs: Some(14 * DAY),
        block_binding_modes: None,
        ceilings: std::collections::BTreeMap::new(),
    };
    let roles = vec!["some-unrelated-role".to_string()];

    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, false)),
        Ok(14 * DAY)
    );

    assert!(policy.check_mint(&req(&roles, None, DAY, true)).is_ok());

    assert_eq!(policy.check_mint(&req(&roles, None, DAY, true)), Ok(DAY));
}

#[test]
fn mint_ceiling_role_cannot_exceed_the_block_cap() {
    let policy = role_policy(
        "app-admin",
        RoleCeiling {
            max_ttl_secs: Some(30 * DAY),
            ..Default::default()
        },
        Some(7 * DAY),
    );
    let roles = vec!["app-admin".to_string()];
    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, false)),
        Ok(7 * DAY),
        "the block cap bounds even a looser role ceiling"
    );
}

#[test]
fn mint_ceiling_empty_policy_is_passthrough() {
    let policy = MintPolicy::default();
    let roles: Vec<String> = vec!["anyone".to_string()];
    assert_eq!(
        policy.check_mint(&req(&roles, None, 90 * DAY, true)),
        Ok(90 * DAY)
    );
}

#[test]
fn mint_ttl_ceiling_absent_is_a_passthrough() {
    assert_eq!(apply_mint_ttl_ceiling(86_400, true, None), Ok(86_400));
    assert_eq!(
        apply_mint_ttl_ceiling(90 * 86_400, false, None),
        Ok(90 * 86_400)
    );
}

#[test]
fn mint_ttl_ceiling_within_bound_is_unchanged() {
    let max = 7 * 86_400;
    assert_eq!(apply_mint_ttl_ceiling(max, true, Some(max)), Ok(max));
    assert_eq!(apply_mint_ttl_ceiling(3600, true, Some(max)), Ok(3600));
    assert_eq!(apply_mint_ttl_ceiling(3600, false, Some(max)), Ok(3600));
}

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

#[test]
fn mint_ttl_ceiling_clamps_over_long_default() {
    let max = 7 * 86_400;
    assert_eq!(
        apply_mint_ttl_ceiling(90 * 86_400, false, Some(max)),
        Ok(max),
        "the 90-day default is clamped to the 7-day policy ceiling"
    );
}
