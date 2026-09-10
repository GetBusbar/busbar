// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-principal admin-mutation rate limiter, moved verbatim from
//! `busbar-core::admin::rate` (fixed one-minute windows, `Config` class at 10/min, `Crud` class at
//! 60/min, `PluginInspect` at 30/min, failed attempts count too, opportunistic per-window sweep).
//! [`MutationClass::for_verb`] (verb-keyed) and [`MutationClass::for_path`] (path-keyed) both take
//! the migrated `CONFIG_CLASS_RULES` table as DATA — a `&[ConfigClassRule]` the composition root
//! supplies from the sealed policy — because this crate has no `NamedMapSection`/config-section
//! registry of its own (that lives in `busbar-core`'s config module, which this crate does not
//! depend on) and must not hard-code the blast-radius membership as a literal `match` arm.
//! [`CONFIG_CLASS_RULES`] below is the exact table `busbar-core::admin::rate::CONFIG_CLASS_RULES`
//! (1.5.5, `crates/busbar/src/admin/rate.rs`) encoded, transcribed against the same
//! ADMIN_PREFIX-relative path strings, and NOTHING ELSE.
//!
//! THE NAMED-MAP ROOTS ARE NOT IN IT, and that is the drift this module used to carry. 1.5.5
//! DERIVES the generic named-DEFINITION map write roots at runtime from the section registry
//! (`NamedMapSection::sections()`), while this crate listed `/identity-providers` and `/export` as
//! literals — so a section that joined the registry (a plane declaring a `named_def_list`)
//! silently extended one table and not the other, and the same mutation was CONFIG class on one
//! path and CRUD class on the other. [`config_class_rules`] closes it: the composition root reads
//! the DECLARED section keys — whatever they are, however many there are, spelling no plane noun —
//! and this crate turns each into a [`ConfigClassRule::NamedMapRoot`] beside the six frozen rows.
//! Everything downstream of "which class is this" — the limit values, the fixed window, the sweep,
//! the audit-once signal — is unchanged.

use crate::verb::KernelVerb;
use std::collections::HashMap;
use std::sync::Mutex;

/// One rule in the CONFIG-class blast-radius set — mirrors 1.5.5's private `PathRule` exactly,
/// plus the one rule 1.5.5 never spelled because it derived it.
/// `Exact` matches the whole ADMIN_PREFIX-relative path; `Prefix` matches every path starting with
/// the string (used for the whole-config and overlay subtrees, whose membership is a subtree, not a
/// single endpoint); `NamedMapRoot` matches a named-DEFINITION map section by its declared KEY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigClassRule {
    /// The relative path must equal this string exactly.
    Exact(&'static str),
    /// The relative path must start with this string.
    Prefix(&'static str),
    /// A named-DEFINITION map SECTION, carried as the section's own declared KEY (`"export"`,
    /// `"identity-providers"`, and whatever a registered plane declares) rather than as a path.
    ///
    /// The key is what the DECLARATION holds — a config section key is also the admin path segment,
    /// which is why one string can be both — so the composition root can hand this crate the
    /// registry's answer verbatim without first synthesising `"/" + key` and without this crate
    /// spelling a section noun of its own. Matching is exactly `Prefix("/" + key)`: the path must
    /// begin with the one leading slash and then the key, which is the same subtree 1.5.5's
    /// `rel.starts_with(section.path_root())` selects, one allocation fewer.
    NamedMapRoot(&'static str),
}

impl ConfigClassRule {
    /// Whether `rel` (an ADMIN_PREFIX-relative path, e.g. `"/config/apply"`) is matched by this
    /// rule.
    pub fn matches(&self, rel: &str) -> bool {
        match self {
            ConfigClassRule::Exact(p) => rel == *p,
            ConfigClassRule::Prefix(p) => rel.starts_with(p),
            ConfigClassRule::NamedMapRoot(key) => rel
                .strip_prefix('/')
                .is_some_and(|after| after.starts_with(key)),
        }
    }
}

/// The SIX FROZEN ROWS of the CONFIG-class blast-radius set — 1.5.5's `CONFIG_CLASS_RULES`
/// (`crates/busbar/src/admin/rate.rs`) transcribed verbatim against ADMIN_PREFIX-relative paths,
/// and nothing else. These six are literals in 1.5.5 too.
///
/// This is NOT the whole class table: the named-DEFINITION map roots 1.5.5 derives from its section
/// registry are absent by design and are supplied by the composition root through
/// [`config_class_rules`]. A caller that passes this constant straight through is asking for the
/// six frozen rows and no named-map section — correct only for a deployment that declares none.
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
];

/// THE WHOLE class table for a deployment, built ONCE at composition from the DECLARED
/// named-definition map sections: the six frozen rows above, then one
/// [`ConfigClassRule::NamedMapRoot`] per section key the caller was handed.
///
/// Every mutation under a section's root re-runs the boot pipeline and swaps a whole new `App` —
/// the same blast radius as `/config/reload` — so every method (`PUT`/`PATCH`/`DELETE`) under the
/// root takes the CONFIG budget, matching 1.5.5's pure-path (method-blind) classifier exactly.
/// `section_keys` is whatever the section declaration answers: this crate does not know how many
/// there are, does not know their names, and cannot tell a 1.5.3-native section from a plane's.
/// That is the point — the derivation happens once, where the declaration is readable, and both
/// classifiers below read the SAME table afterwards.
pub fn config_class_rules(section_keys: &[&'static str]) -> Vec<ConfigClassRule> {
    let mut rules = CONFIG_CLASS_RULES.to_vec();
    rules.extend(
        section_keys
            .iter()
            .copied()
            .map(ConfigClassRule::NamedMapRoot),
    );
    rules
}

/// The ADMIN_PREFIX 1.5.5's `LEGACY_VERBS` paths carry, stripped by [`relative_admin_path`] so a
/// [`ConfigClassRule`] can be written against the same relative strings 1.5.5's table used.
pub const ADMIN_PREFIX: &str = "/api/v1/admin";

/// The stateless config DRY RUN. Carved out of the CONFIG class by 1.5.5 before `/config/` ever
/// matches it, and carved out here for the same reason: a validation that changes nothing must not
/// contend with the budget an operator needs to apply the change it validated.
const PATH_CONFIG_VALIDATE: &str = "/config/validate";

/// The archive PREVIEW. Its own dedicated budget in 1.5.5 — neither the CONFIG class nor the shared
/// CRUD one — because decompressing and parsing an attacker-controlled archive is a mutation-like
/// cost profile even though the endpoint changes no state.
const PATH_PLUGINS_INSPECT: &str = "/plugins/inspect";

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
    /// The five 1.6.0 ledger views, the eight named surfaces AND the two 1.6.0 verbs the design
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

    /// Classify an ADMIN_PREFIX-RELATIVE PATH into its rate-limit class, against the same
    /// `config_class_rules` table [`MutationClass::for_verb`] reads — 1.5.5's
    /// `busbar-core::admin::rate::classify_mutation`, expressed here so there is ONE classifier in
    /// the tree rather than a verb-keyed one and a path-keyed twin that can disagree.
    ///
    /// PATH-KEYED, not verb-keyed, and the difference is the whole reason this face exists. The
    /// enforcement chokepoint every admin request crosses runs BEFORE any verb is resolved: it has
    /// a method and a path and nothing else, and the 15 named-map operations that reach no kernel
    /// verb at all have no verb to be keyed on. A classifier that could only answer for a verb left
    /// those paths to a second copy of this table.
    ///
    /// The two carve-outs are 1.5.5's, in 1.5.5's order and with 1.5.5's answers: `/config/validate`
    /// is CRUD (not CONFIG — it lives under `/config/` and is checked first so the prefix never
    /// reaches it, and not `Forbidden` — a path-keyed classifier is not told the caller's method and
    /// this endpoint is reached by `POST`), and `/plugins/inspect` is its own `PluginInspect`
    /// bucket. Everything the table matches is `Config`; everything else is `Crud`.
    ///
    /// This function is pure and never rate-limits a READ, because it is never asked about one: the
    /// caller tests the method for a mutating verb first, exactly as 1.5.5 does.
    pub fn for_path(rel: &str, config_class_rules: &[ConfigClassRule]) -> MutationClass {
        if rel == PATH_CONFIG_VALIDATE {
            return MutationClass::Crud;
        }
        if rel == PATH_PLUGINS_INSPECT {
            return MutationClass::PluginInspect;
        }
        if config_class_rules.iter().any(|r| r.matches(rel)) {
            MutationClass::Config
        } else {
            MutationClass::Crud
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
