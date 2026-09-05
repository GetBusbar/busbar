// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-principal admin-mutation rate limiter, moved verbatim from
//! `busbar-core::admin::rate` (fixed one-minute windows, `Config` class at 10/min, `Crud` class at
//! 60/min, `PluginInspect` at 30/min, failed attempts count too, opportunistic per-window sweep —
//! PB-32). [`MutationClass::for_verb`] takes the migrated `CONFIG_CLASS_RULES` table as DATA — a
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

use crate::verb::KernelVerb;
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
/// (10/min) versus the roomy CRUD class (60/min) — 1.5.5's `CONFIG_CLASS_RULES`
/// (`crates/busbar/src/admin/rate.rs`), transcribed verbatim against ADMIN_PREFIX-relative paths,
/// with the two `NamedMapSection::ALL` roots (`export`, `identity-providers`) appended as the same
/// kind of `Prefix` rule 1.5.5 derives from that registry (this crate cannot name it, so the root's
/// sealed policy is expected to supply the current, possibly larger, set of named-map roots at
/// composition time — this constant is the 1.5.5-parity default the root may pass as-is or extend).
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

/// The ADMIN_PREFIX 1.5.5's `LEGACY_VERBS` paths carry, stripped by [`relative_admin_path`] so a
/// [`ConfigClassRule`] can be written against the same relative strings 1.5.5's table used.
const ADMIN_PREFIX: &str = "/api/v1/admin";

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
    pub fn for_verb(verb: KernelVerb, config_class_rules: &[ConfigClassRule]) -> MutationClass {
        if verb == KernelVerb::PostPluginsInspect {
            return MutationClass::PluginInspect;
        }
        let is_read_only = crate::verb::LEGACY_VERBS
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
    windows: Mutex<HashMap<(String, MutationClass), Window>>,
}

impl MutationLimiter {
    /// A fresh limiter with no recorded windows.
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Spend one attempt from `principal`'s budget for `class` at time `now` (unix seconds).
    /// Returns `Denied` when the budget for the current window is exhausted. Never panics (a
    /// poisoned lock is recovered, matching the source).
    pub fn check(&self, principal: &str, class: MutationClass, now: u64) -> RateCheck {
        let window = now - (now % MUTATION_RATE_WINDOW_SECS);
        let mut map = self.windows.lock().unwrap_or_else(|e| e.into_inner());
        // Opportunistic sweep: drop every entry from a PAST window.
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

impl Default for MutationLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/rate_tests.rs"]
mod tests;
