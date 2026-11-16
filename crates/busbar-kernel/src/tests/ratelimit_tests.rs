// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn windows_are_per_principal_per_class_and_refill() {
    let l = MutationLimiter::new();
    let t = 1_000_000;
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

    let _ = l.check("mallory", MutationClass::Crud, 60);
    assert!(
        !l.check("alice", MutationClass::Config, 120).admitted(),
        "a request from an earlier window wiped alice's live counter and handed her a fresh budget"
    );

    let _ = l.check("mallory", MutationClass::Crud, 0);
    assert!(
        !l.check("alice", MutationClass::Config, 120).admitted(),
        "an unreadable wall clock read as 0 wiped alice's live counter"
    );
}

#[test]
fn a_corrected_forward_clock_step_does_not_pin_the_budget_in_the_future() {
    let l = MutationLimiter::new();
    let t = 1_000_020;
    let stepped = t + 86_400;
    for _ in 0..10 {
        assert!(l.check("op", MutationClass::Config, stepped).admitted());
    }
    assert!(!l.check("op", MutationClass::Config, stepped).admitted());

    assert!(
        !l.check("op", MutationClass::Config, t).admitted(),
        "a clock that has only just read behind is still judged against the live window"
    );
    assert!(!l.check("op", MutationClass::Config, t + 59).admitted());

    for i in 0..10 {
        assert!(
            l.check("op", MutationClass::Config, t + 60).admitted(),
            "attempt {i}: a corrected forward step still pins the limiter in the future"
        );
    }
    assert!(!l.check("op", MutationClass::Config, t + 60).admitted());
    assert!(l.check("op", MutationClass::Config, t + 120).admitted());
}

#[test]
fn a_clock_that_returns_to_the_high_water_mark_restarts_the_watch() {
    let l = MutationLimiter::new();
    for _ in 0..10 {
        assert!(l.check("alice", MutationClass::Config, 600).admitted());
    }
    let _ = l.check("mallory", MutationClass::Crud, 0);
    let _ = l.check("mallory", MutationClass::Crud, 600);
    assert!(
        !l.check("alice", MutationClass::Config, 60).admitted(),
        "a window measured across a return to the high-water mark refilled a spent budget"
    );
    assert!(!l.check("alice", MutationClass::Config, 600).admitted());
}

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

#[test]
fn plugin_inspect_is_classified_into_its_own_dedicated_bucket() {
    use crate::admin::gate::PATH_PLUGINS_INSPECT;
    let class = classify_mutation(PATH_PLUGINS_INSPECT);
    assert!(matches!(class, MutationClass::PluginInspect));
    assert_ne!(class.label(), MutationClass::Crud.label());
    assert_ne!(class.label(), MutationClass::Config.label());

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

#[test]
fn config_validate_and_plugin_inspect_do_not_share_a_bucket() {
    use crate::admin::gate::{PATH_CONFIG_VALIDATE, PATH_PLUGINS_INSPECT};
    assert!(matches!(
        classify_mutation(PATH_CONFIG_VALIDATE),
        MutationClass::Crud
    ));
    assert!(matches!(
        classify_mutation(PATH_PLUGINS_INSPECT),
        MutationClass::PluginInspect
    ));
}

#[test]
fn the_config_table_is_not_the_whole_decision() {
    use crate::admin::gate::{PATH_CONFIG_VALIDATE, PATH_PLUGINS_INSPECT};
    let table_alone = |rel: &str| {
        CONFIG_CLASS_RULES.iter().any(|rule| match rule {
            PathRule::Exact(p) => rel == *p,
            PathRule::Prefix(p) => rel.starts_with(p),
            PathRule::Within(head, mid) => rel.starts_with(head) && rel.contains(mid),
        })
    };

    assert!(table_alone(PATH_CONFIG_VALIDATE));
    assert!(matches!(
        classify_mutation(PATH_CONFIG_VALIDATE),
        MutationClass::Crud
    ));

    let attachment = "/hooks/audit/attachments/pools.fast";
    assert!(table_alone(attachment));
    assert!(matches!(
        classify_mutation(attachment),
        MutationClass::Config
    ));
    assert!(!table_alone("/hooks/audit"));

    assert!(!table_alone(PATH_PLUGINS_INSPECT));
    assert!(matches!(
        classify_mutation(PATH_PLUGINS_INSPECT),
        MutationClass::PluginInspect
    ));

    for section in crate::config::named_map::NamedMapSection::sections() {
        let rel = format!("{}/some-name", section.path_root());
        assert!(!table_alone(&rel), "{rel} is not a table row");
        assert!(
            matches!(classify_mutation(&rel), MutationClass::Config),
            "{rel} is CONFIG by the named-map scan"
        );
    }
}

#[test]
fn a_named_map_root_matches_on_a_segment_boundary_only() {
    for section in crate::config::named_map::NamedMapSection::sections() {
        let root = section.path_root();
        for inside in [
            root.to_string(),
            format!("{root}/n"),
            format!("{root}/n/settings"),
        ] {
            assert!(
                matches!(classify_mutation(&inside), MutationClass::Config),
                "{inside} is the section's own path"
            );
        }
        let neighbour = format!("{root}-keyset");
        assert!(
            matches!(classify_mutation(&neighbour), MutationClass::Crud),
            "{neighbour} only shares the root's leading characters"
        );
    }
}

/// The reference limiter's per-(principal, class) entry: (window, admitted, denied).
type Window = (u64, u32, u32);

/// Today's limiter, kept as the reference: two retains per check.
struct Reference {
    latest_window: u64,
    behind_since: Option<u64>,
    windows: std::collections::HashMap<(String, MutationClass), Window>,
}

impl Reference {
    fn check(&mut self, principal: &str, class: MutationClass, now: u64) -> RateCheck {
        let arrived_in = now - (now % MUTATION_RATE_WINDOW_SECS);
        if arrived_in.saturating_add(MUTATION_RATE_WINDOW_SECS) < self.latest_window {
            let since = self.behind_since.map_or(now, |since| since.min(now));
            if now - since >= MUTATION_RATE_WINDOW_SECS {
                self.latest_window = arrived_in;
                self.behind_since = None;
                self.windows.retain(|_, (w, _, _)| *w <= arrived_in);
            } else {
                self.behind_since = Some(since);
            }
        } else {
            self.behind_since = None;
        }
        let window = arrived_in.max(self.latest_window);
        self.latest_window = window;
        self.windows.retain(|_, (w, _, _)| *w >= window);
        let entry = self
            .windows
            .entry((principal.to_string(), class))
            .or_insert((window, 0, 0));
        if entry.1 >= class.limit() {
            entry.2 += 1;
            return RateCheck::Denied {
                first_in_window: entry.2 == 1,
            };
        }
        entry.1 += 1;
        RateCheck::Admitted
    }
}

#[test]
fn ratelimit_verdicts_unchanged() {
    let limiter = MutationLimiter::new();
    let mut reference = Reference {
        latest_window: 0,
        behind_since: None,
        windows: std::collections::HashMap::new(),
    };
    let classes = [
        MutationClass::Config,
        MutationClass::Crud,
        MutationClass::PluginInspect,
        MutationClass::Forbidden,
    ];
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut now = 1_000_000u64;
    for _ in 0..100_000 {
        let r = next();
        now = match r % 100 {
            0 => now.saturating_sub(next() % 400),
            1..=3 => now + next() % 120,
            _ => now + next() % 2,
        };
        let principal = format!("p{}", next() % 40);
        let class = classes[(next() % 4) as usize];
        assert_eq!(
            limiter.check(&principal, class, now),
            reference.check(&principal, class, now),
            "{principal} at {now}"
        );
    }
}

#[test]
fn every_mutation_class_names_itself_to_the_audit_row() {
    assert_eq!(MutationClass::Config.label(), "config");
    assert_eq!(MutationClass::Crud.label(), "crud");
    assert_eq!(MutationClass::PluginInspect.label(), "plugin-inspect");
    assert_eq!(MutationClass::Forbidden.label(), "forbidden");

    let labels = [
        MutationClass::Config,
        MutationClass::Crud,
        MutationClass::PluginInspect,
        MutationClass::Forbidden,
    ]
    .map(MutationClass::label);
    let mut sorted = labels.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        labels.len(),
        "two classes share one audit label"
    );
    assert!(
        !labels.iter().any(|l| l.is_empty()),
        "a class has no audit label at all"
    );
}

#[test]
fn the_four_budgets_are_the_spec_defaults_and_forbidden_admits_nothing() {
    assert_eq!(MutationClass::Config.limit(), 10);
    assert_eq!(MutationClass::Crud.limit(), 60);
    assert_eq!(MutationClass::PluginInspect.limit(), 30);
    assert_eq!(MutationClass::Forbidden.limit(), 0);

    let limiter = MutationLimiter::new();
    assert!(
        !limiter
            .check(
                "alice",
                MutationClass::Forbidden,
                7 * MUTATION_RATE_WINDOW_SECS
            )
            .admitted(),
        "a Forbidden attempt drew on a budget"
    );

    assert!(MutationClass::Config.limit() < MutationClass::PluginInspect.limit());
    assert!(MutationClass::PluginInspect.limit() < MutationClass::Crud.limit());
}
