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
    assert!(!limiter
        .check("alice", MutationClass::Forbidden, 0)
        .admitted());
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

    // A 1.6.0 new MUTATING verb has no admin path at all and falls through to CRUD, exactly as
    // 1.5.5's path-only classifier implicitly does for anything it never saw.
    assert_eq!(
        MutationClass::for_verb(CommitUpgrade, CONFIG_CLASS_RULES),
        MutationClass::Crud
    );
}

/// The two 1.6.0 verbs bound as GETs never spend a mutation slot.
///
/// `verify` and `plane_facts` are the two of the twelve the architecture document binds as `GET`,
/// and they have no legacy row, so the path lookup below cannot see them: without being named they
/// fall through to CRUD and cost one of the sixty mutations a minute an operator gets. A node being
/// watched — `verify` is the check the operator-key ceremony's own battery cell runs — would then
/// refuse the config change the operator came to make, and name the config change in the refusal.
#[test]
fn the_two_read_only_new_verbs_never_spend_a_mutation_slot() {
    for verb in [KernelVerb::Verify, KernelVerb::PlaneFacts] {
        assert_eq!(
            MutationClass::for_verb(verb, CONFIG_CLASS_RULES),
            MutationClass::Forbidden,
            "{verb:?} is a read and must never draw the mutation budget"
        );
    }
    // The control: a mutating new verb on the same table still draws it.
    assert_eq!(
        MutationClass::for_verb(KernelVerb::CommitUpgrade, CONFIG_CLASS_RULES),
        MutationClass::Crud
    );
}

/// The eight named surfaces have no legacy row (see the module doc on `NAMED_SURFACES`), so the
/// legacy-scope lookup in `for_verb` cannot see them and they would otherwise fall through to
/// `Crud` — a read like `GET /healthz` or a model listing spending a mutation slot per hit, exactly
/// the bug the ledger views are already guarded against a few lines above. `required_scope` already
/// calls every one of these `ReadOnly`; the rate limiter must agree.
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

/// A REQUEST CARRYING AN OLDER CLOCK MUST NOT REFILL A SPENT BUDGET.
///
/// `now` reaches this limiter from the arrival timestamp the composition root pins with
/// `SystemTime::now()` — a WALL clock, which steps backwards on an NTP correction and which the
/// root's own error arm reads as `0` when the clock is before the epoch. So an older `now` is not a
/// hypothetical: it is the ordinary consequence of a time source that is not monotonic, and this
/// limiter is what stands between that and an unbounded config blast radius.
///
/// The failure the sweep had: any request at all, from any principal, in any class, carrying an
/// older `now` recomputed an older window and cleared the WHOLE map — so Alice, having spent her ten
/// CONFIG mutations, got a fresh ten. That is the limiter being bypassable by anything that can
/// nudge the clock.
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
    // Some other principal, some other class, an EARLIER window. This is the whole exploit.
    let _ = limiter.check("mallory", MutationClass::Crud, 60);
    assert!(
        !limiter
            .check("alice", MutationClass::Config, 120)
            .admitted(),
        "a request from an earlier window wiped alice's live counter and handed her a fresh budget"
    );
    // And again from a clock all the way back at the epoch, which is exactly what the root's
    // `map_or(0, ..)` arm supplies when the wall clock is unreadable.
    let _ = limiter.check("mallory", MutationClass::Crud, 0);
    assert!(
        !limiter
            .check("alice", MutationClass::Config, 120)
            .admitted(),
        "an unreadable wall clock read as 0 wiped alice's live counter"
    );
}

/// The CLOCK-REGRESSION POSTURE, stated: a regressed `now` is CLAMPED into the newest window this
/// limiter has judged, so the attempt spends from the live budget. Never refused outright (a wall
/// clock that slipped is the operator's problem, and refusing every mutation until it catches up is
/// a self-inflicted outage on the one surface an operator would use to fix it), and never allowed to
/// open a second, older window — which is the refill above by another name.
#[test]
fn a_regressing_clock_is_clamped_into_the_live_window_rather_than_opening_an_older_one() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter
            .check("alice", MutationClass::Config, 600)
            .admitted());
    }
    // Alice's own retry, with a clock that slipped back ten minutes.
    assert!(
        !limiter.check("alice", MutationClass::Config, 0).admitted(),
        "a regressed clock must be clamped into the live window, not open a fresh older one"
    );
    // The clamp is not a permanent refusal either: once the clock advances past the window, the
    // budget releases exactly as it always did.
    assert!(limiter
        .check("alice", MutationClass::Config, 660)
        .admitted());
}

/// THE SWEEP DROPS ONLY WINDOWS OLDER THAN THE CURRENT ONE — and does drop those, so the map does
/// not grow one entry per principal per class forever.
#[test]
fn the_sweep_drops_only_windows_older_than_the_current_one() {
    let limiter = MutationLimiter::new();
    for _ in 0..10 {
        assert!(limiter.check("alice", MutationClass::Config, 60).admitted());
    }
    // Still the same fixed window at 119 (60..120), so the budget is still spent — which is what
    // makes the reset below a WINDOW crossing rather than a per-second reset.
    assert!(!limiter
        .check("alice", MutationClass::Config, 119)
        .admitted());
    // Crossing into 120 drops the stale entry and opens a fresh budget.
    assert!(limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());
    // And the drop was real: alice's window-60 counter is gone, so the WHOLE budget is back, not
    // just the one attempt that crossed.
    for _ in 0..9 {
        assert!(limiter
            .check("alice", MutationClass::Config, 120)
            .admitted());
    }
    assert!(!limiter
        .check("alice", MutationClass::Config, 120)
        .admitted());
}

/// The window arithmetic and the audit labels, in their own file.
#[path = "rate_window_tests.rs"]
mod rate_window_tests;
