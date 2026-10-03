// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-principal admin-mutation rate limiter, moved verbatim from
//! `busbar-core::admin::rate` (fixed one-minute windows, `Config` class at 10/min, `Crud` class at
//! 60/min, `PluginInspect` at 30/min, failed attempts count too, opportunistic per-window sweep).
//! [`MutationClass::for_verb`] takes the migrated `CONFIG_CLASS_RULES` table as DATA — a
//! `&'static [ConfigClassRule]` the composition root supplies from the sealed policy — because this
//! crate has no `NamedMapSection`/config-section registry of its own (that lives in `busbar-core`'s
//! config module, which this crate does not depend on) and must not hard-code the blast-radius
//! membership as a literal `match` arm. [`CONFIG_CLASS_RULES`] below is the exact table
//! `busbar-core::admin::rate::CONFIG_CLASS_RULES` (1.5.5, `crates/busbar/src/admin/rate.rs`)
//! encoded, transcribed against the same ADMIN_PREFIX-relative path strings, plus the two
//! generic named-map write roots (`/export`, `/identity-providers`) 1.5.5 derives from
//! `NamedMapSection::ALL` rather than listing as literals — reproduced here as data because this
//! crate cannot name that registry. Everything downstream of "which class is this verb" — the
//! limit values, the fixed window, the sweep, the audit-once signal — is unchanged.
//!
//! [`CONFIG_CLASS_RULES`] is a second, independent table from [`PATH_CLASS_RULES`], the one the
//! kernel's auth middleware classifies an operator-surface PATH with through [`classify_path`]
//! (item 558) — see that constant's doc for why the two are not collapsed into one, and for the
//! cross-check test that keeps them from silently drifting apart. The path classifier moved here
//! from `busbar_kernel::ratelimit` (1.6.0-TODO.md D4): which class a route spends from is this
//! crate's knowledge of its own routes; the kernel keeps the budget and reaches the classifier
//! through its admin seam.

use crate::verb::KernelVerb;
use busbar_contract::surface::ADMIN_PREFIX;
use std::collections::HashMap;
use std::sync::Mutex;

/// One rule in the CONFIG-class blast-radius set — mirrors 1.5.5's private `PathRule` exactly.
/// `Exact` matches the whole ADMIN_PREFIX-relative path; `Prefix` matches every path starting with
/// the string (used for the whole-config and overlay subtrees, and the two named-map sections,
/// whose membership is a subtree, not a single endpoint).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigClassRule {
    /// The relative path must equal this string exactly.
    Exact(&'static str),
    /// The relative path must start with this string.
    Prefix(&'static str),
}

impl ConfigClassRule {
    /// Whether `rel` (an ADMIN_PREFIX-relative path, e.g. `"/config/apply"`) is matched by this
    /// rule.
    pub fn matches(&self, rel: &str) -> bool {
        match self {
            ConfigClassRule::Exact(p) => rel == *p,
            ConfigClassRule::Prefix(p) => rel.starts_with(p),
        }
    }
}

/// THE single source of truth for which admin mutation endpoints are in the tight CONFIG class
/// (10/min) versus the roomy CRUD class (60/min) on the admin-VERB path — 1.5.5's
/// `CONFIG_CLASS_RULES` (`crates/busbar/src/admin/rate.rs`), transcribed verbatim against
/// ADMIN_PREFIX-relative paths, with the two `NamedMapSection::ALL` roots (`export`,
/// `identity-providers`) appended as the same kind of `Prefix` rule 1.5.5 derives from that
/// registry (this crate cannot name it, so the root's sealed policy is expected to supply the
/// current, possibly larger, set of named-map roots at composition time — this constant is the
/// 1.5.5-parity default the root may pass as-is or extend).
///
/// A SECOND, independent table answers the same question on the admin-HTTP path:
/// [`classify_path`] (item 558) — driven from the live plane registry
/// rather than a literal list, so it sees named-map roots this table does not (`tools`, `agents`).
/// This crate cannot collapse into that one: it has no `KernelVerb`-shaped input to the kernel's
/// path classifier, and swapping this table for a call into it would change which class two
/// `Full`-scope verbs land in today (a customer-visible rate-limit tier change out of this item's
/// scope — see item 372, owned elsewhere). What ties the two tables together instead is
/// `for_verb_agrees_with_the_kernel_path_classifier_for_every_legacy_mutating_verb`
/// (`tests/rate_tests.rs`), which walks every legacy mutating verb through both classifiers over
/// the same relative path and goes RED the moment they disagree — currently green, because no live
/// `KernelVerb` reaches a path either table classifies differently today.
pub const CONFIG_CLASS_RULES: &[ConfigClassRule] = &[
    // Whole-config mutations (apply/reload/rollback/settings). `/config/validate` is a stateless
    // dry-run and `ReadOnly`-scoped, so it never reaches `for_verb`'s table lookup at all (filtered
    // out by the read-only check first) — exactly how 1.5.5 carves it out before this prefix ever
    // matches it.
    ConfigClassRule::Prefix("/config/"),
    // The admin auth chain itself.
    ConfigClassRule::Exact("/admin-auth"),
    // A per-section overlay reset discards a whole section back to base config.
    ConfigClassRule::Prefix("/overlay/"),
    // Both plugin swap endpoints do a full rebuild — identical blast radius to `config/reload`.
    ConfigClassRule::Exact("/plugins/reload"),
    ConfigClassRule::Exact("/plugins/rollback"),
    // Restarting ends the process.
    ConfigClassRule::Exact("/restart"),
    // The generic named-DEFINITION map sections (1.5.5's `NamedMapSection::ALL`): every mutation
    // under a section's root re-runs the boot pipeline and swaps a whole new `App` — the same blast
    // radius as `/config/reload`, so every method (`PUT`/`PATCH`/`DELETE`) under the root takes the
    // CONFIG budget, matching 1.5.5's pure-path (method-blind) classifier exactly.
    ConfigClassRule::Prefix("/identity-providers"),
    ConfigClassRule::Prefix("/export"),
];

/// The FIXED endpoints of the tight CONFIG class (10/min), as against the roomy CRUD class (60/min).
///
/// This table is NOT the whole decision, and it used to say it was ("nothing else decides class
/// membership", item 558). The one decider is [`classify_path`], and it reads four things in
/// this order, first answer wins: the `/config/validate` carve-out (CRUD, although this table's
/// `/config/` prefix covers it), the `/plugins/inspect` carve-out (its own class), every
/// registry-derived named-map root (CONFIG — one per `NamedMapSection::sections()`, so a plane's
/// section joins without an edit here), and only then this table. `docs/admin-api.md`'s rate-limit
/// table is a hand-written restatement of the CONFIG set that FUNCTION produces — kept honest by
/// `rate_limit_doc_table_matches_classifier` (busbar-core-admin's tests), which classifies every
/// mutation operation in the committed `openapi.json` through [`classify_path`] and fails if the
/// CONFIG set differs from the doc's `config` row by one endpoint in either direction; so all four
/// deciders are inside that check, not only this table.
///
/// This is the classifier the kernel's auth middleware runs through the admin seam
/// (`busbar_kernel::admin::seam`). The admin-VERB path classifies with a SECOND table,
/// [`CONFIG_CLASS_RULES`]
/// (`MutationClass::for_verb`), which hardcodes the two core named-map roots and which nothing
/// compares with this one.
///
/// This used to be an inline `if`/`else` boolean expression with the same six clauses — sound,
/// but a predicate can only answer "is this one in?", never "which ones are in?", so nothing
/// could enumerate its membership to check it against the doc. A table can be iterated as well as
/// matched, which is what makes the cross-check test possible at all (the `reload_to_apply`
/// structural fix, applied here).
pub const PATH_CLASS_RULES: &[ConfigClassRule] = &[
    // Whole-config mutations (apply/reload/rollback) — `/config/validate` is a stateless dry-run
    // carved out below, before this prefix ever matches it.
    ConfigClassRule::Prefix("/config/"),
    // The admin auth chain itself — `PUT /admin-auth` (the remount moved it off `/auth`).
    ConfigClassRule::Exact(crate::v1::contract::PATH_ADMIN_AUTH),
    // A per-section overlay reset discards a whole section back to base config — a blast-radius
    // revert (rebuilds the App).
    ConfigClassRule::Prefix("/overlay/"),
    // Both PLUGIN SWAP endpoints do a full `rebuild_app_from_disk` + `handle.swap` (identical
    // blast radius to `config/reload`) — not the 6x-looser CRUD budget. `/plugins` (install/list)
    // and `/plugins/{file}` (delete) do NOT swap the App, so they are deliberately absent here and
    // fall through to CRUD.
    ConfigClassRule::Exact("/plugins/reload"),
    ConfigClassRule::Exact("/plugins/rollback"),
    // Restarting ends the process; the 6x looser CRUD budget would be a flood knob.
    ConfigClassRule::Exact("/restart"),
];

/// Classify a mutation request's ADMIN_PREFIX-relative path: the two carve-outs, then the
/// registry-derived named-map roots, then [`PATH_CLASS_RULES`] — in that order. `/config/validate`
/// is a read-only dry-run that must not contend with the CONFIG budget despite living under
/// `/config/`, and `/plugins/inspect` is a read-only archive preview that must not contend with
/// EITHER the CONFIG or the shared CRUD budget — it gets its own `PluginInspect` class.
pub fn classify_path(rel: &str) -> busbar_kernel::ratelimit::MutationClass {
    use busbar_kernel::ratelimit::MutationClass;
    if rel == busbar_kernel::admin::refusal::PATH_CONFIG_VALIDATE {
        return MutationClass::Crud;
    }
    if rel == busbar_kernel::admin::refusal::PATH_PLUGINS_INSPECT {
        return MutationClass::PluginInspect;
    }
    // The GENERIC named-DEFINITION map writes (`/identity-providers`, `/export`, and any registered
    // plane's own named-map section) each re-run the boot pipeline and swap a whole new `App` — the SAME blast radius as
    // `/config/reload` and `/plugins/reload`, so they take the CONFIG budget, not the 6x-looser CRUD
    // one. Derived from the section table rather than listed as literals, so a new section is
    // classified correctly the moment its variant exists (the `docs/admin-api.md` config row and
    // `rate_limit_doc_table_matches_classifier` are the paired ledger).
    // On a path-SEGMENT boundary: `/export` and `/export/{name}` are the section, `/export-keyset`
    // is not.
    if busbar_kernel::config::named_map::NamedMapSection::sections()
        .iter()
        .any(|s| {
            rel.strip_prefix(s.path_root().as_ref())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
    {
        return MutationClass::Config;
    }
    if PATH_CLASS_RULES.iter().any(|rule| rule.matches(rel)) {
        MutationClass::Config
    } else {
        MutationClass::Crud
    }
}

/// The ADMIN_PREFIX-relative path for a legacy verb, or `None` for a verb with no fixed path (every
/// 1.6.0 new verb, and the named non-admin surfaces) — those never match a [`ConfigClassRule`] and
/// fall through to [`MutationClass::Crud`], exactly as 1.5.5's classifier (which only ever saw
/// legacy admin paths) implicitly did.
fn relative_admin_path(verb: KernelVerb) -> Option<&'static str> {
    crate::verb::LEGACY_VERBS
        .iter()
        .find(|r| r.verb == verb)
        .map(|r| r.path.strip_prefix(ADMIN_PREFIX).unwrap_or(r.path))
}

/// Fixed mutation-rate window length (seconds) — matches `busbar-core::admin::rate` exactly.
pub const MUTATION_RATE_WINDOW_SECS: u64 = 60;

/// The mutation classes with distinct budgets — the same four `busbar-core::admin::rate` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationClass {
    /// Whole-config-blast-radius mutations (apply/reload/rollback, admin-auth, overlay, plugin
    /// swap, restart) — 10/min.
    Config,
    /// Everything else that mutates (hooks, keys, groups, export, identity providers) — 60/min.
    Crud,
    /// `POST /plugins/inspect`'s own dedicated budget — 30/min.
    PluginInspect,
    /// Not a budget: a read, or a verb this limiter never shapes (counted zero, always denied if
    /// ever checked, matching 1.5.5's `Forbidden` bookkeeping-only class).
    Forbidden,
}

impl MutationClass {
    /// The per-minute budget for this class (spec defaults; matches
    /// `busbar-core::admin::rate::MutationClass::limit` exactly).
    pub fn limit(self) -> u32 {
        match self {
            MutationClass::Config => 10,
            MutationClass::Crud => 60,
            MutationClass::PluginInspect => 30,
            MutationClass::Forbidden => 0,
        }
    }

    /// Audit-facing label — matches `busbar-core::admin::rate::MutationClass::label`.
    pub fn label(self) -> &'static str {
        match self {
            MutationClass::Config => "config",
            MutationClass::Crud => "crud",
            MutationClass::PluginInspect => "plugin-inspect",
            MutationClass::Forbidden => "forbidden",
        }
    }

    /// Classify a verb into its rate-limit class, against `config_class_rules` — the composition
    /// root's sealed [`CONFIG_CLASS_RULES`] (or an equivalent it supplies). `PostPluginsInspect` is
    /// decided before the read-only check because 1.5.5 gives it its own dedicated budget despite
    /// being `ReadOnly`-scoped (a stateless dry-run with a mutation-like cost profile); every other
    /// read (and the other stateless dry-run, `config/validate`) is `Forbidden` (never
    /// rate-limited as a mutation); everything else is classified by matching its
    /// ADMIN_PREFIX-relative path (a new 1.6.0 verb or named surface has none, and falls through to
    /// `Crud`, exactly as 1.5.5's path-only classifier implicitly did for surfaces it never saw).
    ///
    /// The five 1.6.0 ledger views, the three audit-chain reads
    /// ([`crate::verb::AUDIT_VERBS`]), the eight named surfaces AND the two 1.6.0 verbs the design
    /// binds as `GET` ([`crate::verb::READ_ONLY_NEW_VERBS`]) are named in the read-only check
    /// EXPLICITLY, and this is the one place that matters: none of them has a legacy row, so the row
    /// lookup below cannot see them, and without the name they would fall through to `Crud` and
    /// spend a mutation slot per read. A read that consumes a mutation budget refuses an operator's
    /// config change because they looked at a balance first, ran `verify`, hit `/healthz` or listed
    /// models, which is the opposite of what a read is for.
    /// [`crate::verbs::required_scope`] already calls every named surface `ReadOnly` for exactly
    /// this reason; this check is repeated as data here (rather than calling that function) because
    /// `for_verb` must stay free of any dependency on the executor module it is classifying inputs
    /// for.
    pub fn for_verb(verb: KernelVerb, config_class_rules: &[ConfigClassRule]) -> MutationClass {
        if verb == KernelVerb::PostPluginsInspect {
            return MutationClass::PluginInspect;
        }
        let is_read_only = crate::verb::LEDGER_VERBS.contains(&verb)
            || crate::verb::AUDIT_VERBS.contains(&verb)
            || crate::verb::NAMED_SURFACES.contains(&verb)
            || crate::verb::READ_ONLY_NEW_VERBS.contains(&verb)
            || crate::verb::LEGACY_VERBS
                .iter()
                .any(|r| r.verb == verb && r.scope == crate::verb::VerbScope::ReadOnly);
        if is_read_only {
            return MutationClass::Forbidden;
        }
        match relative_admin_path(verb) {
            Some(rel) if config_class_rules.iter().any(|r| r.matches(rel)) => MutationClass::Config,
            _ => MutationClass::Crud,
        }
    }
}

/// One window entry: (window start, attempts spent in it, denials already audited in it).
type Window = (u64, u32, u32);

/// The outcome of one rate check — matches `busbar-core::admin::rate::RateCheck` exactly.
#[derive(Debug, PartialEq, Eq)]
pub enum RateCheck {
    /// The attempt is inside budget.
    Admitted,
    /// The attempt exceeds the window's budget. `first_in_window` is true only for the FIRST denial
    /// in this window (the caller writes exactly one audit row per principal per class per window).
    Denied {
        /// Whether this is the first denial recorded in the current window.
        first_in_window: bool,
    },
}

impl RateCheck {
    /// Whether the attempt was admitted.
    pub fn admitted(&self) -> bool {
        matches!(self, RateCheck::Admitted)
    }
}

/// Fixed-window counters keyed by (principal, class) — moved verbatim from
/// `busbar-core::admin::rate::MutationLimiter`.
pub struct MutationLimiter {
    state: Mutex<LimiterState>,
}

/// The counters and the newest window they belong to, under ONE lock.
///
/// The high-water mark has to be read and written in the same critical section as the sweep, or two
/// concurrent checks could each decide they are the newest and one could still rewind the map.
struct LimiterState {
    /// The newest window start this limiter has ever judged against — never decreases. See
    /// [`MutationLimiter::check`] for why a limiter fed a wall clock needs one.
    latest_window: u64,
    /// Fixed-window counters keyed by (principal, class).
    windows: HashMap<(String, MutationClass), Window>,
}

impl MutationLimiter {
    /// A fresh limiter with no recorded windows.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(LimiterState {
                latest_window: 0,
                windows: HashMap::new(),
            }),
        }
    }

    /// Spend one attempt from `principal`'s budget for `class` at time `now` (unix seconds).
    /// Returns `Denied` when the budget for the current window is exhausted. Never panics (a
    /// poisoned lock is recovered, matching the source).
    ///
    /// # A clock that goes backwards
    ///
    /// `now` is a WALL clock — the composition root pins it per request with `SystemTime::now()`,
    /// and reads an unreadable clock as `0`. Wall clocks are not monotonic: an NTP correction steps
    /// them backwards, and so does a container starting before its host's time syncs. The limiter
    /// therefore has to say what it does when `now` regresses, and the only unacceptable answer is
    /// the one it used to give.
    ///
    /// It used to sweep with `*w == window`, which reads as "drop every entry from a PAST window"
    /// but also drops entries from a FUTURE one. So a single request — any principal, any class —
    /// carrying an older `now` recomputed an older window and cleared EVERY live counter in the map.
    /// A principal who had just spent their ten CONFIG-class mutations got a fresh ten, and the
    /// config blast-radius limit became bypassable by anything that could nudge the clock back.
    ///
    /// The posture now is CLAMP, not refuse and not wipe:
    ///
    /// * **Clamp.** A regressed `now` is judged against `latest_window` — the newest window this
    ///   limiter has seen — so the attempt spends from the LIVE budget instead of opening a second,
    ///   older one. A caller cannot buy budget by arriving with an older timestamp; the worst a
    ///   backwards step can do is make the current window last longer, which errs toward refusing.
    /// * **Not refuse.** Turning a slipped clock into a hard refusal would take the admin surface
    ///   down until the clock caught up — including the surface an operator would use to fix it.
    ///   A rate limiter is not the right place to fail an operator closed over an infrastructure
    ///   fault it merely observed.
    /// * **Never wipe.** The sweep drops entries STRICTLY OLDER than the window being judged and
    ///   nothing else, so no arrival can clear a counter that is still live.
    pub fn check(&self, principal: &str, class: MutationClass, now: u64) -> RateCheck {
        let arrived_in = now - (now % MUTATION_RATE_WINDOW_SECS);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // The clamp. `max` (rather than an assignment) is what makes `latest_window` monotone: time
        // moving forward advances it, time moving backwards leaves it exactly where it was.
        let window = arrived_in.max(state.latest_window);
        state.latest_window = window;
        let map = &mut state.windows;
        // Opportunistic sweep: drop every entry from a window STRICTLY OLDER than this one, and
        // only those. Written as `>=` rather than `==` so the sweep is safe on its own terms — it
        // could not wipe a live counter even if a future edit reached it with a window the clamp
        // above had not raised.
        map.retain(|_, (w, _, _)| *w >= window);
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

impl Default for MutationLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/rate_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/path_class_tests.rs"]
mod path_class_tests;
