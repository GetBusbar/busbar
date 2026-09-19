// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/rate.rs`.

use super::*;

/// The budget is per (principal, class) within a fixed window; a new window refills; one
/// principal exhausting a class neither affects another principal nor its own other class.
#[test]
fn windows_are_per_principal_per_class_and_refill() {
    let l = MutationLimiter::new();
    let t = 1_000_000; // window-aligned enough (fixed windows key on now - now%60)
    for _ in 0..10 {
        assert!(l.check("a", MutationClass::Config, t).admitted());
    }
    assert_eq!(
        l.check("a", MutationClass::Config, t),
        RateCheck::Denied {
            first_in_window: true
        },
        "11th config mutation in the window is limited"
    );
    assert!(
        l.check("a", MutationClass::Crud, t).admitted(),
        "the other class has its own budget"
    );
    assert!(
        l.check("b", MutationClass::Config, t).admitted(),
        "another principal has its own budget"
    );
    assert!(
        l.check("a", MutationClass::Config, t + 60).admitted(),
        "a new window refills"
    );
}

/// The denial path writes a durable audit record, which is a blocking store round-trip. Only the
/// FIRST denial per (principal, class, window) may do so, or a client that ignores its 429s
/// drives unbounded blocking work through the very limiter meant to stop work — and can park the
/// one shared store connection that governance and the admin plane both need.
#[test]
fn only_the_first_denial_in_a_window_is_audited() {
    let l = MutationLimiter::new();
    let t = 1_000_000;
    for _ in 0..10 {
        assert!(l.check("a", MutationClass::Config, t).admitted());
    }
    assert_eq!(
        l.check("a", MutationClass::Config, t),
        RateCheck::Denied {
            first_in_window: true
        }
    );
    for _ in 0..500 {
        assert_eq!(
            l.check("a", MutationClass::Config, t),
            RateCheck::Denied {
                first_in_window: false
            },
            "a sustained probe must not keep auditing"
        );
    }
    // A fresh window starts a fresh record: the log still shows each window's limiting.
    for _ in 0..10 {
        assert!(l.check("a", MutationClass::Config, t + 60).admitted());
    }
    assert_eq!(
        l.check("a", MutationClass::Config, t + 60),
        RateCheck::Denied {
            first_in_window: true
        }
    );
}

/// `POST /plugins/inspect` gets its OWN dedicated budget — neither the CONFIG class nor the
/// shared CRUD class: burning the shared 60/min CRUD budget on N candidate-artifact inspections
/// during a fleet-wide plugin upgrade would starve real mutating work in the same window.
#[test]
fn plugin_inspect_is_classified_into_its_own_dedicated_bucket() {
    use crate::admin::v1::contract::PATH_PLUGINS_INSPECT;
    let class = classify_mutation(PATH_PLUGINS_INSPECT);
    assert!(matches!(class, MutationClass::PluginInspect));
    assert_ne!(class.label(), MutationClass::Crud.label());
    assert_ne!(class.label(), MutationClass::Config.label());

    // Exhausting the CRUD budget must not touch the plugin-inspect budget, and vice versa —
    // proof the two are genuinely independent counters, not aliases of the same class.
    let l = MutationLimiter::new();
    let t = 2_000_000;
    for _ in 0..60 {
        assert!(l.check("op", MutationClass::Crud, t).admitted());
    }
    assert!(
        matches!(
            l.check("op", MutationClass::Crud, t),
            RateCheck::Denied { .. }
        ),
        "CRUD budget (60/min) is now exhausted"
    );
    assert!(
        l.check("op", MutationClass::PluginInspect, t).admitted(),
        "plugin-inspect has its own untouched budget"
    );
}

/// A regressed/backward clock (NTP step, VM live-migration, container clock skew) must not wipe
/// every principal's budget. The window-sweep in `check` used to drop any entry whose window
/// wasn't an exact match (`==`) for the freshly computed window; if the clock stepped backward,
/// the newly computed window would be smaller than the real, already-recorded window, so an
/// `==` sweep would treat every principal's live entry as "past" and evict it — refilling
/// everyone's budget for free. The fix (`>=`) must keep any entry whose window is still current
/// or ahead of the (bogus, regressed) computed window, sweeping only strictly-older entries.
#[test]
fn backward_clock_does_not_wipe_other_principals_budgets() {
    let l = MutationLimiter::new();
    let real_now = 1_000_000; // aligned to a window boundary (1_000_000 % 60 == 0)

    // "a" and "b" each spend their whole CONFIG budget in the real, current window.
    for _ in 0..10 {
        assert!(l.check("a", MutationClass::Config, real_now).admitted());
    }
    assert!(matches!(
        l.check("a", MutationClass::Config, real_now),
        RateCheck::Denied { .. }
    ));
    for _ in 0..5 {
        assert!(l.check("b", MutationClass::Config, real_now).admitted());
    }

    // The clock now regresses by several windows (e.g. an NTP step). A third principal's
    // request lands with a `now` that computes an OLDER window than "a" and "b" already hold.
    let regressed_now = real_now - 5 * MUTATION_RATE_WINDOW_SECS;
    assert!(l.check("c", MutationClass::Config, regressed_now).admitted());

    // Back at the real (later) time, "a" must still be denied (budget not refilled) and "b"
    // must still show exactly 5 spent, not a fresh 0 — the regressed-clock sweep must not have
    // evicted either entry.
    assert!(
        matches!(
            l.check("a", MutationClass::Config, real_now),
            RateCheck::Denied { .. }
        ),
        "a backward-clock request from another principal must not refill 'a' budget"
    );
    for _ in 0..5 {
        assert!(
            l.check("b", MutationClass::Config, real_now).admitted(),
            "'b' should have exactly 5 remaining of its original 10, not a wiped/refilled budget"
        );
    }
    assert!(matches!(
        l.check("b", MutationClass::Config, real_now),
        RateCheck::Denied { .. }
    ));
}

/// `/config/validate` and `/plugins/inspect` are BOTH `read-only`-scoped, stateless dry-run/
/// preview POSTs, but they must NOT share a rate bucket with each other or with CRUD — each has
/// its own dedicated class.
#[test]
fn config_validate_and_plugin_inspect_do_not_share_a_bucket() {
    use crate::admin::v1::contract::{PATH_CONFIG_VALIDATE, PATH_PLUGINS_INSPECT};
    assert!(matches!(
        classify_mutation(PATH_CONFIG_VALIDATE),
        MutationClass::Crud
    ));
    assert!(matches!(
        classify_mutation(PATH_PLUGINS_INSPECT),
        MutationClass::PluginInspect
    ));
}
