// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Per-principal ADMIN MUTATION rate limits — separate from the data
//! plane's per-key RPM. Config-plane mutations (apply/rollback) are capped at 10/min and the other
//! mutation classes (hook CRUD, key CRUD) at 60/min, per principal, in fixed one-minute windows.
//! FAILED attempts count too (anti-enumeration: probing 404s spends the same budget as mutating),
//! which is why enforcement lives in the auth middleware — before any handler runs. Limit events
//! are audited.

use std::collections::HashMap;

/// Fixed mutation-rate window length (seconds). Also the `Retry-After` value `auth.rs`'s
/// `rate_limited_response` advertises on a 429 — derived from this const so the advertised
/// back-off always equals the real window.
pub(crate) const MUTATION_RATE_WINDOW_SECS: u64 = 60;

/// The mutation classes with distinct budgets. `Config` = apply/rollback (the blast-radius class);
/// `Crud` = everything else that mutates (hooks, keys).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum MutationClass {
    Config,
    Crud,
    /// `POST /plugins/inspect`'s OWN dedicated budget — NOT the shared 60/min CRUD bucket
    /// (already shared across key/group/hook/cache-flush mutations; inspecting N candidate
    /// artifacts during a fleet-wide plugin upgrade would burn N of the same 60/min an operator
    /// needs for real mutating work in that window) and NOT the unmetered-read bucket either,
    /// since decompressing + parsing an attacker-controlled archive is a mutation-like cost profile
    /// even though the endpoint changes no state.
    PluginInspect,
    /// NOT a budget: the FORBIDDEN path uses this class purely for its per-(principal, window)
    /// "already audited once" counter. The 403 is the answer; the verdict is never used to shed.
    Forbidden,
}

impl MutationClass {
    /// The per-minute budget for this class (spec defaults; a config knob is an additive follow-up).
    fn limit(self) -> u32 {
        match self {
            MutationClass::Config => 10,
            MutationClass::Crud => 60,
            // Roomier than CONFIG (a fleet-wide upgrade preview legitimately inspects many
            // candidates in one operator session) but deliberately tighter than the general-purpose
            // CRUD budget (60/min) it must not share, since its cost profile — decompress + parse an
            // attacker-controlled archive — is heavier per call than an ordinary CRUD mutation.
            MutationClass::PluginInspect => 30,
            MutationClass::Forbidden => 0,
        }
    }

    /// Audit-facing label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            MutationClass::Config => "config",
            MutationClass::Crud => "crud",
            MutationClass::PluginInspect => "plugin-inspect",
            MutationClass::Forbidden => "forbidden",
        }
    }
}

/// One rule in the CONFIG-class blast-radius set. `Exact` matches the whole relative path;
/// `Prefix` matches every path starting with the string (used for `/config/` and `/overlay/`,
/// whose membership is a subtree, not a single endpoint).
enum PathRule {
    Exact(&'static str),
    Prefix(&'static str),
}

/// THE single source of truth for which admin mutation endpoints are in the tight CONFIG class
/// (10/min) versus the roomy CRUD class (60/min). `classify_mutation` reads this table; nothing
/// else decides class membership. `docs/admin-api.md`'s rate-limit table is a hand-written
/// restatement of exactly this list — kept honest by
/// `admin::tests::tests::rate_limit_doc_table_matches_classifier`, which enumerates every
/// mutation operation in the committed `openapi.json`, classifies each via this table, and fails
/// if the resulting CONFIG set differs from the doc's `config` row by even one endpoint in either
/// direction.
///
/// This used to be an inline `if`/`else` boolean expression with the same six clauses — sound,
/// but a predicate can only answer "is this one in?", never "which ones are in?", so nothing
/// could enumerate its membership to check it against the doc. A table can be iterated as well as
/// matched, which is what makes the cross-check test possible at all (the `reload_to_apply`
/// structural fix, applied here).
const CONFIG_CLASS_RULES: &[PathRule] = &[
    // Whole-config mutations (apply/reload/rollback) — `/config/validate` is a stateless dry-run
    // carved out below, before this prefix ever matches it.
    PathRule::Prefix("/config/"),
    // The admin auth chain itself — `PUT /admin-auth` (the remount moved it off `/auth`).
    PathRule::Exact(crate::admin::v1::contract::PATH_ADMIN_AUTH),
    // A per-section overlay reset discards a whole section back to base config — a blast-radius
    // revert (rebuilds the App).
    PathRule::Prefix("/overlay/"),
    // Both PLUGIN SWAP endpoints do a full `rebuild_app_from_disk` + `handle.swap` (identical
    // blast radius to `config/reload`) — not the 6x-looser CRUD budget. `/plugins` (install/list)
    // and `/plugins/{file}` (delete) do NOT swap the App, so they are deliberately absent here and
    // fall through to CRUD.
    PathRule::Exact("/plugins/reload"),
    PathRule::Exact("/plugins/rollback"),
    // Restarting ends the process; the 6x looser CRUD budget would be a flood knob.
    PathRule::Exact("/restart"),
];

/// Classify a mutation request's ADMIN_PREFIX-relative path. Pure function of
/// [`CONFIG_CLASS_RULES`] plus the carve-outs: `/config/validate` is a read-only dry-run that must
/// not contend with the CONFIG budget despite living under `/config/`, and `/plugins/inspect` is a
/// read-only archive preview that must not contend with EITHER the CONFIG or the shared CRUD budget
/// — it gets its own dedicated [`MutationClass::PluginInspect`] bucket.
pub(crate) fn classify_mutation(rel: &str) -> MutationClass {
    if rel == crate::admin::v1::contract::PATH_CONFIG_VALIDATE {
        return MutationClass::Crud;
    }
    if rel == crate::admin::v1::contract::PATH_PLUGINS_INSPECT {
        return MutationClass::PluginInspect;
    }
    // The GENERIC named-DEFINITION map writes (`/identity-providers`, `/export`; `tools`/`agents`
    // later) each re-run the boot pipeline and swap a whole new `App` — the SAME blast radius as
    // `/config/reload` and `/plugins/reload`, so they take the CONFIG budget, not the 6x-looser CRUD
    // one. Derived from the section table rather than listed as literals, so a new section is
    // classified correctly the moment its variant exists (the `docs/admin-api.md` config row and
    // `rate_limit_doc_table_matches_classifier` are the paired ledger).
    if crate::config::named_map::NamedMapSection::ALL
        .iter()
        .any(|s| rel.starts_with(s.path_root()))
    {
        return MutationClass::Config;
    }
    let is_config = CONFIG_CLASS_RULES.iter().any(|rule| match rule {
        PathRule::Exact(p) => rel == *p,
        PathRule::Prefix(p) => rel.starts_with(p),
    });
    if is_config {
        MutationClass::Config
    } else {
        MutationClass::Crud
    }
}

/// Fixed-window counters keyed by (principal, class). Held on `App` behind an `Arc` (shared across
/// config-apply snapshots — rate state survives every swap); bounded by construction: entries are
/// per-principal-per-class and a sweep on every check drops past-window entries, so a churn of
/// principals cannot grow the map unboundedly.
/// One window entry: (window start, attempts spent in it, denials already audited in it).
type Window = (u64, u32, u32);

/// The outcome of one rate check. `Denied` distinguishes the FIRST denial in a window from the
/// rest, because the caller writes a durable audit record on denial: a client that keeps hammering
/// past its budget would otherwise drive one blocking store round-trip per REJECTED request, so the
/// shed path — whose whole job is to stop doing work — would do unbounded work. One record per
/// principal per class per window says everything the log needs to.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RateCheck {
    Admitted,
    Denied { first_in_window: bool },
}

impl RateCheck {
    #[cfg(test)]
    fn admitted(&self) -> bool {
        matches!(self, RateCheck::Admitted)
    }
}

pub(crate) struct MutationLimiter {
    windows: std::sync::Mutex<Option<HashMap<(String, MutationClass), Window>>>,
}

impl MutationLimiter {
    pub(crate) fn new() -> Self {
        Self {
            windows: std::sync::Mutex::new(None),
        }
    }

    /// Spend one attempt from `principal`'s budget for `class` at time `now` (unix seconds).
    /// Returns `false` when the budget for the current window is exhausted (the caller responds
    /// 429 and audits). Never panics (poisoned lock recovered).
    pub(crate) fn check(&self, principal: &str, class: MutationClass, now: u64) -> RateCheck {
        let window = now - (now % MUTATION_RATE_WINDOW_SECS);
        let mut guard = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        let map = guard.get_or_insert_with(HashMap::new);
        // Opportunistic sweep: drop every entry from a PAST window (each principal-class re-inserts
        // on its next attempt), keeping the map proportional to currently-active principals.
        map.retain(|_, (w, _, _)| *w == window);
        let entry = map
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

#[cfg(test)]
mod tests {
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
}
