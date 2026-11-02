// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;

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
    fn limit(self) -> u32 {
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

struct LimiterState {
    latest_window: u64,

    behind_since: Option<u64>,

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
                behind_since: None,
                windows: HashMap::new(),
            }),
        }
    }

    pub fn check(&self, principal: &str, class: MutationClass, now: u64) -> RateCheck {
        let arrived_in = now - (now % MUTATION_RATE_WINDOW_SECS);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if arrived_in.saturating_add(MUTATION_RATE_WINDOW_SECS) < state.latest_window {
            let since = state.behind_since.map_or(now, |since| since.min(now));
            if now - since >= MUTATION_RATE_WINDOW_SECS {
                state.latest_window = arrived_in;
                state.behind_since = None;
                state.windows.retain(|_, (w, _, _)| *w <= arrived_in);
            } else {
                state.behind_since = Some(since);
            }
        } else {
            state.behind_since = None;
        }

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

#[cfg(test)]
#[path = "tests/ratelimit_tests.rs"]
mod tests;
