// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

    assert!(limiter.check("bob", MutationClass::Crud, 0).admitted());
}

#[test]
fn budgets_are_isolated_per_class_for_the_same_principal() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Config, 0).admitted());

    assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
}

#[test]
fn a_new_window_resets_the_budget() {
    let limiter = MutationLimiter::new();
    for _ in 0..60 {
        assert!(limiter.check("alice", MutationClass::Crud, 0).admitted());
    }
    assert!(!limiter.check("alice", MutationClass::Crud, 0).admitted());

    assert!(limiter.check("alice", MutationClass::Crud, 60).admitted());
}

#[test]
fn forbidden_class_has_zero_budget() {
    let limiter = MutationLimiter::new();
    assert!(!limiter
        .check("alice", MutationClass::Forbidden, 0)
        .admitted());
}

#[test]
fn for_verb_matches_1_5_5s_classify_mutation_row_for_row() {
    use KernelVerb::*;

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

    assert_eq!(
        MutationClass::for_verb(PostPluginsInspect, CONFIG_CLASS_RULES),
        MutationClass::PluginInspect
    );

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

    assert_eq!(
        MutationClass::for_verb(Adjust, CONFIG_CLASS_RULES),
        MutationClass::Crud
    );
}

#[test]
fn the_two_read_only_new_verbs_never_spend_a_mutation_slot() {
    for verb in [KernelVerb::Verify, KernelVerb::PlaneFacts] {
        assert_eq!(
            MutationClass::for_verb(verb, CONFIG_CLASS_RULES),
            MutationClass::Forbidden,
            "{verb:?} is a read and must never draw the mutation budget"
        );
    }

    assert_eq!(
        MutationClass::for_verb(KernelVerb::Adjust, CONFIG_CLASS_RULES),
        MutationClass::Crud
    );
}

#[test]
fn every_named_surface_is_never_rate_limited_as_a_mutation() {
    for verb in crate::verb::NAMED_SURFACES {
        assert_eq!(
            MutationClass::for_verb(*verb, CONFIG_CLASS_RULES),
            MutationClass::Forbidden,
            "{verb:?} is a named surface and must never be rate-limited as a mutation"
        );
    }
}

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

#[test]
fn an_out_of_order_now_cannot_refill_a_spent_budget() {
    let limiter = MutationLimiter::new();
    for i in 0..10 {
        assert!(
            limiter
                .check("alice", MutationClass::Config, 120)
                .admitted(),
            "attempt {i} inside the budget"
        );
    }
    assert!(!limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());

    let _ = limiter.check("mallory", MutationClass::Crud, 60);
    assert!(
        !limiter
            .check("alice", MutationClass::Config, 120)
            .admitted(),
        "a request from an earlier window wiped alice's live counter and handed her a fresh budget"
    );

    let _ = limiter.check("mallory", MutationClass::Crud, 0);
    assert!(
        !limiter
            .check("alice", MutationClass::Config, 120)
            .admitted(),
        "an unreadable wall clock read as 0 wiped alice's live counter"
    );
}

#[test]
fn a_regressing_clock_is_clamped_into_the_live_window_rather_than_opening_an_older_one() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter
            .check("alice", MutationClass::Config, 600)
            .admitted());
    }

    assert!(
        !limiter.check("alice", MutationClass::Config, 0).admitted(),
        "a regressed clock must be clamped into the live window, not open a fresh older one"
    );

    assert!(limiter
        .check("alice", MutationClass::Config, 660)
        .admitted());
}

#[test]
fn the_sweep_drops_only_windows_older_than_the_current_one() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 60).admitted());
    }

    assert!(!limiter
        .check("alice", MutationClass::Config, 119)
        .admitted());

    assert!(limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());

    for _ in 0..9 {
        assert!(limiter
            .check("alice", MutationClass::Config, 120)
            .admitted());
    }
    assert!(!limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());
}

#[test]
fn for_verb_agrees_with_the_kernel_path_classifier_for_every_legacy_mutating_verb() {
    for row in crate::verb::LEGACY_VERBS {
        if row.scope == crate::verb::VerbScope::ReadOnly
            && row.verb != KernelVerb::PostPluginsInspect
        {
            continue;
        }
        let rel = row.path.strip_prefix("/api/v1/admin").unwrap_or(row.path);
        let admin_class = MutationClass::for_verb(row.verb, CONFIG_CLASS_RULES);
        let kernel_class = busbar_kernel::ratelimit::classify_mutation(rel);
        assert_eq!(
            admin_class.label(),
            kernel_class.label(),
            "{:?} ({rel}): admin-verb classifier says {} but the kernel path classifier says {} \
             — the two CONFIG_CLASS_RULES tables have drifted",
            row.verb,
            admin_class.label(),
            kernel_class.label(),
        );
    }
}

#[path = "rate_window_tests.rs"]
mod rate_window_tests;
