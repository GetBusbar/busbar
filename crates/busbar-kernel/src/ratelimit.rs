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
pub const MUTATION_RATE_WINDOW_SECS: u64 = 60;

/// The mutation classes with distinct budgets. `Config` = apply/rollback (the blast-radius class);
/// `Crud` = everything else that mutates (hooks, keys).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum MutationClass {
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
    pub fn label(self) -> &'static str {
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

/// The FIXED endpoints of the tight CONFIG class (10/min), as against the roomy CRUD class (60/min).
///
/// This table is NOT the whole decision, and it used to say it was ("nothing else decides class
/// membership", item 558). The one decider is [`classify_mutation`], and it reads four things in
/// this order, first answer wins: the `/config/validate` carve-out (CRUD, although this table's
/// `/config/` prefix covers it), the `/plugins/inspect` carve-out (its own class), every
/// registry-derived named-map root (CONFIG — one per `NamedMapSection::sections()`, so a plane's
/// section joins without an edit here), and only then this table. `docs/admin-api.md`'s rate-limit
/// table is a hand-written restatement of the CONFIG set that FUNCTION produces — kept honest by
/// `rate_limit_doc_table_matches_classifier` (busbar-core-admin's tests), which classifies every
/// mutation operation in the committed `openapi.json` through [`classify_mutation`] and fails if the
/// CONFIG set differs from the doc's `config` row by one endpoint in either direction; so all four
/// deciders are inside that check, not only this table.
///
/// This is the classifier the admin HTTP middleware runs (`auth` → `classify_mutation`). The
/// admin-VERB path classifies with a SECOND table, `busbar_core_admin::rate::CONFIG_CLASS_RULES`
/// (`MutationClass::for_verb`), which hardcodes the two core named-map roots and which nothing
/// compares with this one.
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

/// Classify a mutation request's ADMIN_PREFIX-relative path: the two carve-outs, then the
/// registry-derived named-map roots, then [`CONFIG_CLASS_RULES`] — in that order. `/config/validate`
/// is a read-only dry-run that must not contend with the CONFIG budget despite living under
/// `/config/`, and `/plugins/inspect` is a read-only archive preview that must not contend with
/// EITHER the CONFIG or the shared CRUD budget — it gets its own [`MutationClass::PluginInspect`].
pub fn classify_mutation(rel: &str) -> MutationClass {
    if rel == crate::admin::v1::contract::PATH_CONFIG_VALIDATE {
        return MutationClass::Crud;
    }
    if rel == crate::admin::v1::contract::PATH_PLUGINS_INSPECT {
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
    if crate::config::named_map::NamedMapSection::sections()
        .iter()
        .any(|s| {
            rel.strip_prefix(s.path_root().as_ref())
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
        })
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
pub enum RateCheck {
    Admitted,
    Denied { first_in_window: bool },
}

impl RateCheck {
    #[cfg(test)]
    fn admitted(&self) -> bool {
        matches!(self, RateCheck::Admitted)
    }
}

/// The counters and the newest window they belong to, under ONE lock — the high-water mark has to
/// be read and written in the same critical section as the sweep, or two concurrent checks could
/// each decide they are the newest and one could still rewind the map.
struct LimiterState {
    /// The newest window start this limiter has ever judged against — never decreases. See
    /// [`MutationLimiter::check`] for why a limiter fed a wall clock needs one.
    latest_window: u64,
    /// Fixed-window counters keyed by (principal, class).
    windows: HashMap<(String, MutationClass), Window>,
}

pub(crate) struct MutationLimiter {
    state: std::sync::Mutex<LimiterState>,
}

impl MutationLimiter {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(LimiterState {
                latest_window: 0,
                windows: HashMap::new(),
            }),
        }
    }

    /// Spend one attempt from `principal`'s budget for `class` at time `now` (unix seconds).
    /// Returns `false` when the budget for the current window is exhausted (the caller responds
    /// 429 and audits). Never panics (poisoned lock recovered).
    ///
    /// # A clock that goes backwards
    ///
    /// `now` is a WALL clock the caller pins per request; wall clocks are not monotonic (an NTP
    /// correction steps them backwards, and so does a container starting before its host's time
    /// syncs), so an older `now` arriving after a newer one is not hypothetical.
    ///
    /// This used to sweep with `*w == window`, which reads as "drop every entry from a PAST
    /// window" but also drops entries from a FUTURE one relative to an older arrival. So a single
    /// request — any principal, any class — carrying an older `now` recomputed an older window and
    /// cleared EVERY live counter in the map: a principal who had just spent their budget got a
    /// fresh one, and the limit became bypassable by anything that could nudge the clock back.
    ///
    /// The posture now is CLAMP, not refuse and not wipe:
    ///
    /// * **Clamp.** A regressed `now` is judged against `latest_window` — the newest window this
    ///   limiter has seen — so the attempt spends from the LIVE budget instead of opening a second,
    ///   older one. A caller cannot buy budget by arriving with an older timestamp; the worst a
    ///   backwards step can do is make the current window last longer, which errs toward refusing.
    /// * **Not refuse.** Turning a slipped clock into a hard refusal would take this surface down
    ///   until the clock caught up. A rate limiter is not the right place to fail closed over an
    ///   infrastructure fault it merely observed.
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

#[cfg(test)]
#[path = "tests/ratelimit_tests.rs"]
mod tests;
