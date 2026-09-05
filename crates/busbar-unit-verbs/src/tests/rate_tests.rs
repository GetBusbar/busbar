// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ported assertions from `busbar-core::admin::rate::tests` for the mutation rate limiter: budgets
//! per class, per-principal isolation, the fixed one-minute window reset, and that a denial still
//! counts (so probing costs the same budget as mutating).

use crate::rate::{MutationClass, MutationLimiter, RateCheck, CONFIG_CLASS_RULES};
use crate::verb::KernelVerb;

#[test]
fn crud_budget_is_60_per_minute_then_denies() {
    let limiter = MutationLimiter::new();
    for i in 0..60 {
        assert!(
            limiter.check("alice", MutationClass::Crud, 0).admitted(),
            "attempt {i} should be admitted"
        );
    }
    assert_eq!(
        limiter.check("alice", MutationClass::Crud, 0),
        RateCheck::Denied {
            first_in_window: true
        }
    );
    assert_eq!(
        limiter.check("alice", MutationClass::Crud, 0),
        RateCheck::Denied {
            first_in_window: false
        }
    );
}

#[test]
fn config_budget_is_10_per_minute() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Config, 0).admitted());
}

#[test]
fn plugin_inspect_budget_is_30_per_minute() {
    let limiter = MutationLimiter::new();
    for _ in 0..30 {
        assert!(limiter
            .check("alice", MutationClass::PluginInspect, 0)
            .admitted());
    }
    assert!(!limiter
        .check("alice", MutationClass::PluginInspect, 0)
        .admitted());
}

#[test]
fn budgets_are_isolated_per_principal() {
    let limiter = MutationLimiter::new();
    for _ in 0..60 {
        assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Crud, 0).admitted());
    // A different principal has its own, untouched budget in the same window.
    assert!(limiter.check("bob", MutationClass::Crud, 0).admitted());
}

#[test]
fn budgets_are_isolated_per_class_for_the_same_principal() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Config, 0).admitted());
    // The CRUD budget is untouched by exhausting CONFIG.
    assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
}

#[test]
fn a_new_window_resets_the_budget() {
    let limiter = MutationLimiter::new();
    for _ in 0..60 {
        assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Crud, 0).admitted());
    // 60 seconds later is a new fixed window.
    assert!(limiter.check("alice", MutationClass::Crud, 60).admitted());
}

#[test]
fn forbidden_class_has_zero_budget() {
    let limiter = MutationLimiter::new();
    assert!(!limiter.check("alice", MutationClass::Forbidden, 0).admitted());
}

/// CG-38: `MutationClass::for_verb` classifies every 1.5.5 mutating admin operation exactly the
/// way `busbar-core::admin::rate::classify_mutation` (1.5.5, `crates/busbar/src/admin/rate.rs`)
/// does, over the same relative paths — the blast-radius CONFIG rows at 10/min must never be
/// confused with the roomier 60/min CRUD rows, and `plugins/inspect` must land in its own
/// dedicated 30/min bucket rather than either.
#[test]
fn for_verb_matches_1_5_5s_classify_mutation_row_for_row() {
    use KernelVerb::*;

    // The blast-radius CONFIG class (10/min): whole-config mutations (including `config/settings`
    // — only `config/validate` is carved out, and it is `ReadOnly`-scoped so it never reaches this
    // classifier at all), the admin-auth chain, an overlay section reset, both plugin swaps,
    // restart, and every mutation under the two named-map sections (`export`,
    // `identity-providers`) regardless of method — 1.5.5's `classify_mutation` is pure path, so a
    // `PUT`, `PATCH` or `DELETE` on the same relative path all classify identically.
    let config_rows = [
        PostConfigApply,
        PostConfigReload,
        PostConfigRollback,
        PutConfigSettings,
        PutAdminAuth,
        DeleteOverlaySection,
        PostPluginsReload,
        PostPluginsRollback,
        PostRestart,
        PutExportName,
        DeleteExportName,
        PatchExportNameSettings,
        PutIdentityProvidersName,
        DeleteIdentityProvidersName,
        PatchIdentityProvidersNameSettings,
    ];
    for verb in config_rows {
        assert_eq!(
            MutationClass::for_verb(verb, CONFIG_CLASS_RULES),
            MutationClass::Config,
            "{verb:?} must classify Config (10/min), matching 1.5.5"
        );
    }

    // `plugins/inspect` gets its own dedicated 30/min bucket — neither CONFIG nor CRUD — despite
    // being `ReadOnly`-scoped.
    assert_eq!(
        MutationClass::for_verb(PostPluginsInspect, CONFIG_CLASS_RULES),
        MutationClass::PluginInspect
    );

    // Everything else that mutates is the roomier 60/min CRUD class.
    let crud_rows = [
        PostAuthCacheFlush,
        PostGroups,
        DeleteGroupsName,
        PatchGroupsName,
        PutGroupsName,
        PostHooks,
        DeleteHooksName,
        PutHooksName,
        PatchHooksNameSettings,
        PostKeys,
        DeleteKeysId,
        PatchKeysId,
        PostKeysIdRevoke,
        PostKeysIdRotate,
        PostPlugins,
        DeletePluginsFile,
        PostSigningKeyRotate,
    ];
    for verb in crud_rows {
        assert_eq!(
            MutationClass::for_verb(verb, CONFIG_CLASS_RULES),
            MutationClass::Crud,
            "{verb:?} must classify Crud (60/min), matching 1.5.5"
        );
    }

    // Every read (including the two stateless dry-run POSTs other than `plugins/inspect`) is
    // never rate-limited as a mutation.
    for verb in [
        GetConfig,
        PostConfigValidate,
        GetAdminAuth,
        GetExport,
        GetIdentityProviders,
        GetKeys,
    ] {
        assert_eq!(
            MutationClass::for_verb(verb, CONFIG_CLASS_RULES),
            MutationClass::Forbidden,
            "{verb:?} is a read and must never be rate-limited as a mutation"
        );
    }

    // A 1.6.0 new verb has no admin path at all and falls through to CRUD, exactly as 1.5.5's
    // path-only classifier implicitly does for anything it never saw.
    assert_eq!(
        MutationClass::for_verb(Verify, CONFIG_CLASS_RULES),
        MutationClass::Crud
    );
}

/// The two budgets that matter most for parity: a CONFIG-class verb is denied at the 11th
/// attempt in a window, never the 61st (i.e. it must not be silently sharing CRUD's budget).
#[test]
fn config_class_verb_is_limited_at_10_not_60() {
    let limiter = MutationLimiter::new();
    let class = MutationClass::for_verb(KernelVerb::PostConfigApply, CONFIG_CLASS_RULES);
    assert_eq!(class, MutationClass::Config);
    for _ in 0..10 {
        assert!(limiter.check("alice", class, 0).admitted());
    }
    assert!(
        !limiter.check("alice", class, 0).admitted(),
        "a blast-radius CONFIG verb must be capped at 10/min, not 60/min"
    );
}
