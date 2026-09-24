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

/// A REQUEST CARRYING AN OLDER CLOCK MUST NOT REFILL A SPENT BUDGET.
///
/// `now` reaches this limiter as a wall-clock read pinned per request; wall clocks are not
/// monotonic (an NTP correction steps them backwards), so an older `now` arriving after a newer one
/// is not hypothetical. The sweep used `*w == window`, which reads as "drop every entry from a PAST
/// window" but also drops entries from a FUTURE one relative to an older arrival: any request at
/// all, from any principal, in any class, carrying an older `now` recomputed an older window and
/// cleared the WHOLE map — so a principal who had just spent their ten CONFIG-class mutations got a
/// fresh ten. That is the limiter being bypassable by anything that can nudge the clock back.
#[test]
fn an_out_of_order_now_cannot_refill_a_spent_budget() {
    let l = MutationLimiter::new();
    for i in 0..10 {
        assert!(
            l.check("alice", MutationClass::Config, 120).admitted(),
            "attempt {i} inside the budget"
        );
    }
    assert!(!l.check("alice", MutationClass::Config, 120).admitted());
    // Some other principal, some other class, an EARLIER window. This is the whole exploit.
    let _ = l.check("mallory", MutationClass::Crud, 60);
    assert!(
        !l.check("alice", MutationClass::Config, 120).admitted(),
        "a request from an earlier window wiped alice's live counter and handed her a fresh budget"
    );
    // And again from a clock all the way back at the epoch (what an unreadable wall clock reads as).
    let _ = l.check("mallory", MutationClass::Crud, 0);
    assert!(
        !l.check("alice", MutationClass::Config, 120).admitted(),
        "an unreadable wall clock read as 0 wiped alice's live counter"
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

/// ITEM 558: `CONFIG_CLASS_RULES` is not the only thing that decides class membership, and its doc
/// no longer says it is.
///
/// Three deciders run ahead of the table inside `classify_mutation`. Each is pinned here by a path
/// on which the table ALONE gives a different answer than the classifier does — so a reader who
/// took the table for the whole decision (as its doc told them to) would be wrong on every one — and
/// the table's own doc is held to naming all three.
#[test]
fn the_config_table_is_not_the_whole_decision_and_its_doc_names_what_else_decides() {
    use crate::admin::v1::contract::{PATH_CONFIG_VALIDATE, PATH_PLUGINS_INSPECT};
    let table_alone = |rel: &str| {
        CONFIG_CLASS_RULES.iter().any(|rule| match rule {
            PathRule::Exact(p) => rel == *p,
            PathRule::Prefix(p) => rel.starts_with(p),
        })
    };
    // The validate carve-out: the table's `/config/` prefix says CONFIG, the classifier says CRUD.
    assert!(table_alone(PATH_CONFIG_VALIDATE));
    assert!(matches!(
        classify_mutation(PATH_CONFIG_VALIDATE),
        MutationClass::Crud
    ));
    // The inspect carve-out: absent from the table, its own class.
    assert!(!table_alone(PATH_PLUGINS_INSPECT));
    assert!(matches!(
        classify_mutation(PATH_PLUGINS_INSPECT),
        MutationClass::PluginInspect
    ));
    // The registry-derived named-map roots: absent from the table, CONFIG.
    for section in crate::config::named_map::NamedMapSection::sections() {
        let rel = format!("{}/some-name", section.path_root());
        assert!(!table_alone(&rel), "{rel} is not a table row");
        assert!(
            matches!(classify_mutation(&rel), MutationClass::Config),
            "{rel} is CONFIG by the named-map scan"
        );
    }

    let source = include_str!("../ratelimit.rs");
    let doc_start = source
        .find("const CONFIG_CLASS_RULES")
        .and_then(|at| source[..at].rfind("\n\n"))
        .expect("the table has a doc block");
    let doc = &source[doc_start..source.find("const CONFIG_CLASS_RULES").unwrap()];
    assert!(
        !doc.contains("nothing\n/// else decides class membership")
            && !doc.contains("nothing else decides class membership"),
        "the table's doc claims to be the whole decision again"
    );
    for decider in ["/config/validate", "/plugins/inspect", "named-map root"] {
        assert!(
            doc.contains(decider),
            "the table's doc does not name the decider that runs ahead of it: {decider}"
        );
    }
}
