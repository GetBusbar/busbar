// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/admin/rate.rs`.

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
