// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    pub fn matches(&self, rel: &str) -> bool {
        match self {
            ConfigClassRule::Exact(p) => rel == *p,
            ConfigClassRule::Prefix(p) => rel.starts_with(p),
        }
    }
}

pub const CONFIG_CLASS_RULES: &[ConfigClassRule] = &[
    ConfigClassRule::Prefix("/config/"),
    ConfigClassRule::Exact("/admin-auth"),
    ConfigClassRule::Prefix("/overlay/"),
    ConfigClassRule::Exact("/plugins/reload"),
    ConfigClassRule::Exact("/plugins/rollback"),
    ConfigClassRule::Exact("/restart"),
    ConfigClassRule::Prefix("/identity-providers"),
    ConfigClassRule::Prefix("/export"),
];

fn relative_admin_path(verb: KernelVerb) -> Option<&'static str> {
    crate::verb::LEGACY_VERBS
        .iter()
        .find(|r| r.verb == verb)
        .map(|r| r.path.strip_prefix(ADMIN_PREFIX).unwrap_or(r.path))
}

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
    pub fn limit(self) -> u32 {
        match self {
            MutationClass::Config => 10,
            MutationClass::Crud => 60,
            MutationClass::PluginInspect => 30,
            MutationClass::Forbidden => 0,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            MutationClass::Config => "config",
            MutationClass::Crud => "crud",
            MutationClass::PluginInspect => "plugin-inspect",
            MutationClass::Forbidden => "forbidden",
        }
    }

    pub fn for_verb(verb: KernelVerb, config_class_rules: &[ConfigClassRule]) -> MutationClass {
        if verb == KernelVerb::PostPluginsInspect {
            return MutationClass::PluginInspect;
        }
        let is_read_only = crate::verb::row_of(verb)
            .is_some_and(|row| row.scope == crate::verb::VerbScope::ReadOnly);
        if is_read_only {
            return MutationClass::Forbidden;
        }
        match relative_admin_path(verb) {
            Some(rel) if config_class_rules.iter().any(|r| r.matches(rel)) => MutationClass::Config,
            _ => MutationClass::Crud,
        }
    }
}

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
    pub fn admitted(&self) -> bool {
        matches!(self, RateCheck::Admitted)
    }
}

pub struct MutationLimiter {
    state: Mutex<LimiterState>,
}

struct LimiterState {
    latest_window: u64,

    windows: HashMap<(String, MutationClass), Window>,
}

impl MutationLimiter {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(LimiterState {
                latest_window: 0,
                windows: HashMap::new(),
            }),
        }
    }

    pub fn check(&self, principal: &str, class: MutationClass, now: u64) -> RateCheck {
        let arrived_in = now - (now % MUTATION_RATE_WINDOW_SECS);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let window = arrived_in.max(state.latest_window);
        state.latest_window = window;
        let map = &mut state.windows;

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
