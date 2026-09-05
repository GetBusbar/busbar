// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-principal admin-mutation rate limiter, moved verbatim from
//! `busbar-core::admin::rate` (fixed one-minute windows, `Config` class at 10/min, `Crud` class at
//! 60/min, `PluginInspect` at 30/min, failed attempts count too, opportunistic per-window sweep —
//! PB-32). The only thing NOT moved verbatim is `classify_mutation`'s PATH-based rule table: this
//! crate has no `NamedMapSection`/config-section registry to classify a path against (that lives in
//! `busbar-core`'s config module, which this crate does not depend on), so classification is moved
//! to a `// contract:` seam — [`MutationClass::for_verb`] — the integrator fills in with the exact
//! same table `busbar-core::admin::rate::CONFIG_CLASS_RULES` encodes. Everything downstream of
//! "which class is this verb" — the limit values, the fixed window, the sweep, the audit-once
//! signal — is unchanged.

use crate::verb::KernelVerb;
use std::collections::HashMap;
use std::sync::Mutex;

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

    // contract: classification of every legacy mutating verb into {Config, Crud, PluginInspect} is
    // the integrator's `busbar-core::admin::rate::CONFIG_CLASS_RULES` table, reproduced against
    // `KernelVerb` instead of a raw path string. `PostPluginsInspect` and every read (`GetX`) are
    // decided here because they need no path table (they are single, named verbs); the blast-radius
    // CONFIG-class rows (`/config/*`, `/admin-auth`, `/overlay/*`, `plugins/reload`,
    // `plugins/rollback`, `/restart`, and the generic named-map write paths for
    // `identity-providers`/`export`) are left as a placeholder returning `Crud` — WRONG for those
    // rows until the integrator supplies the real table, and deliberately marked so rather than
    // silently guessed.
    /// Classify a verb into its rate-limit class. See the `// contract:` note above: the
    /// blast-radius CONFIG rows are not yet distinguished from CRUD here.
    pub fn for_verb(verb: KernelVerb) -> MutationClass {
        use KernelVerb::*;
        match verb {
            // Every read, and the other stateless dry-run, are never rate-limited as mutations.
            v if crate::verb::LEGACY_VERBS
                .iter()
                .any(|r| r.verb == v && r.scope == crate::verb::VerbScope::ReadOnly) =>
            {
                MutationClass::Forbidden
            }
            PostPluginsInspect => MutationClass::PluginInspect,
            // contract: the exact CONFIG_CLASS_RULES membership (see the doc comment above).
            PostConfigApply | PostConfigReload | PostConfigRollback | PutAdminAuth
            | DeleteOverlaySection | PostPluginsReload | PostPluginsRollback | PostRestart
            | PutExportName | PutIdentityProvidersName => MutationClass::Config,
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
