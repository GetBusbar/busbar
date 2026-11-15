// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use foldhash::HashMap;

pub const MUTATION_RATE_WINDOW_SECS: u64 = 60;

/// The mutation classes with distinct budgets. `Config` = apply/rollback (the blast-radius class);
/// `Crud` = everything else that mutates (hooks, keys).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
}

enum PathRule {
    Exact(&'static str),
    Prefix(&'static str),
}

const CONFIG_CLASS_RULES: &[PathRule] = &[
    PathRule::Prefix("/config/"),
    PathRule::Exact(crate::admin::gate::PATH_ADMIN_AUTH),
    PathRule::Prefix("/overlay/"),
    PathRule::Exact("/plugins/reload"),
    PathRule::Exact("/plugins/rollback"),
    PathRule::Exact("/restart"),
];

pub fn classify_mutation(rel: &str) -> MutationClass {
    if rel == crate::admin::gate::PATH_CONFIG_VALIDATE {
        return MutationClass::Crud;
    }
    if rel == crate::admin::gate::PATH_PLUGINS_INSPECT {
        return MutationClass::PluginInspect;
    }

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

/// One (principal, class) budget in the current window: (admitted, denied).
type Budget = (u32, u32);

/// The number of [`MutationClass`] variants: one budget map per class.
const CLASS_COUNT: usize = 4;

impl MutationClass {
    fn slot(self) -> usize {
        match self {
            MutationClass::Config => 0,
            MutationClass::Crud => 1,
            MutationClass::PluginInspect => 2,
            MutationClass::Forbidden => 3,
        }
    }
}

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
    pub fn admitted(&self) -> bool {
        matches!(self, RateCheck::Admitted)
    }
}

struct LimiterState {
    latest_window: u64,

    behind_since: Option<u64>,

    /// Per class (indexed by [`MutationClass::slot`]), the budgets of the window `latest_window`
    /// names: every entry belongs to that window, so a window change empties the maps.
    windows: [HashMap<String, Budget>; CLASS_COUNT],
}

pub struct MutationLimiter {
    state: std::sync::Mutex<LimiterState>,
}

impl MutationLimiter {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(LimiterState {
                latest_window: 0,
                behind_since: None,
                windows: Default::default(),
            }),
        }
    }

    /// How many admitted mutations of `class` `principal` has spent in the window `now` falls in.
    /// A read: it charges nothing.
    pub fn used(&self, principal: &str, class: MutationClass, now: u64) -> u32 {
        let arrived_in = now - (now % MUTATION_RATE_WINDOW_SECS);
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if arrived_in != state.latest_window {
            return 0;
        }
        state.windows[class.slot()]
            .get(principal)
            .map_or(0, |entry| entry.0)
    }

    pub fn check(&self, principal: &str, class: MutationClass, now: u64) -> RateCheck {
        let arrived_in = now - (now % MUTATION_RATE_WINDOW_SECS);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        // Every entry belongs to the window `latest_window` named when this call began.
        let entries_window = state.latest_window;
        if arrived_in.saturating_add(MUTATION_RATE_WINDOW_SECS) < state.latest_window {
            let since = state.behind_since.map_or(now, |since| since.min(now));
            if now - since >= MUTATION_RATE_WINDOW_SECS {
                // A clock rewind re-bases the limiter to an earlier window; every entry is from the
                // later one, so the window change below drops them all.
                state.latest_window = arrived_in;
                state.behind_since = None;
            } else {
                state.behind_since = Some(since);
            }
        } else {
            state.behind_since = None;
        }

        let window = arrived_in.max(state.latest_window);
        state.latest_window = window;
        if window != entries_window {
            // Every entry is from another window: the budgets restart.
            state.windows.iter_mut().for_each(|budgets| budgets.clear());
        }
        let map = &mut state.windows[class.slot()];

        let limit = class.limit();
        match map.get_mut(principal) {
            Some(entry) => charge(entry, limit),
            // First sight of this principal in this window: key it once.
            None => charge(
                map.entry(crate::cold::host::ratelimit_principal_key(principal))
                    .or_insert((0, 0)),
                limit,
            ),
        }
    }
}

/// Charge one request against a window budget of `limit`.
fn charge(entry: &mut Budget, limit: u32) -> RateCheck {
    if entry.0 >= limit {
        entry.1 += 1;
        return RateCheck::Denied {
            first_in_window: entry.1 == 1,
        };
    }
    entry.0 += 1;
    RateCheck::Admitted
}

impl Default for MutationLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "tests/ratelimit_tests.rs"]
mod tests;
