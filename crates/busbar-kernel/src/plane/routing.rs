// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ROUTING TABLES OF ONE GENERATION, built from what each plane STATES on its snapshot
//! (`PlaneSnapshot.routing`, contract step 2b) and from nothing else (arch u26; #47, BUSBAR-1.6.0.md
//! l.2232: the routing keys belong to the plane; #49 l.2235: the kernel spells no plane section).
//!
//! A plane resolves its own sections into routing entries — each a `(section, entry)` with its
//! members, the lanes it excludes, the entry it falls back to and the facts the kernel consumes —
//! and the kernel builds its lane table, its entry table and its generic refusals from them. The
//! kernel never parses a plane's section for any of it; the entry's reserved sub-keys (its breaker
//! ladder, affinity, policy) stay the kernel's to read at the entry's `path`.
//!
//! A LANE is one member identity of one plane (`(plane, lane)`): the breaker cells, the counters and
//! the metric labels key on it, and one lane may be named by several entries. Every member naming a
//! lane states the lane's own facts identically (its provider, upstream name, concurrency cap,
//! request budget and context window); two that disagree are a plane's contradiction, refused here.
//! Lanes are ordered by name, as the previous release ordered its lanes, so a lane's index (and every
//! surface keyed by it) is stable across boots.

use std::collections::{BTreeMap, HashMap};

use busbar_contract::abi::plane::{
    FACT_ATTEMPT_TIMEOUT_MS, FACT_CONCURRENCY_CAP, FACT_CONTEXT_WINDOW, FACT_FAILOVER_MAX_HOPS,
    FACT_FAILOVER_TIMEOUT_SECS, FACT_MAX_REQUESTS,
};
use busbar_plugin_loader::dispatch::kinds::plane::{OwnedRouteEntry, OwnedRouteMember};

/// One plane's stated routing for the generation being built.
#[derive(Debug, Clone, Copy)]
pub struct StatedRouting<'a> {
    /// The plane's registry key.
    pub plane: &'static str,
    /// The entries its snapshot states, in its order.
    pub entries: &'a [OwnedRouteEntry],
}

/// ONE LANE: a member identity of one plane and the facts that are the lane's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedLane {
    /// The plane that states it.
    pub plane: &'static str,
    /// Its identity: the member's key in the plane's member map.
    pub name: String,
    /// The provider it is reached through (a key of the root `providers:` map).
    pub provider: String,
    /// The name the far end knows it by; `None` = its lane name.
    pub upstream: Option<String>,
    /// The most units it serves at once; `None` = unbounded.
    pub max_concurrent: Option<u64>,
    /// The most requests it serves in its life; `None` = no bound.
    pub max_requests: Option<u64>,
    /// The largest request it accepts, in the plane's units; `None` = unstated.
    pub context_window: Option<u64>,
}

/// ONE MEMBER of an entry: the lane it picks and how.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedMember {
    /// The lane's index in [`RoutingTables::lanes`].
    pub lane: usize,
    /// Its weight in the entry's pick (never `0`).
    pub weight: u32,
    /// Its tier, shown to the ranking hooks; `None` = none.
    pub tier: Option<String>,
    /// Its tags, shown to the ranking hooks.
    pub tags: Vec<String>,
    /// The milliseconds one attempt on it may take: its own, else its entry's; `None` = unbounded.
    pub attempt_timeout_ms: Option<u64>,
}

/// ONE ENTRY: a routable `(section, entry)` of one plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutedEntry {
    /// The plane that states it.
    pub plane: &'static str,
    /// The plane's declared section it lives in.
    pub section: String,
    /// Its name.
    pub name: String,
    /// Its config path, segment by segment: where the kernel reads its reserved sub-keys.
    pub path: Vec<String>,
    /// The entry (in the same section) its units fall back to when every member is exhausted.
    pub fallback: Option<String>,
    /// The lanes it never picks.
    pub exclude: Vec<String>,
    /// Its failover budget, seconds of wall clock across one unit's attempts; `None` = unstated.
    pub failover_timeout_secs: Option<u64>,
    /// The most failover hops one unit takes on it; `None` = unstated.
    pub failover_max_hops: Option<u64>,
    /// Its members, in its order.
    pub members: Vec<RoutedMember>,
}

/// THE GENERATION'S ROUTING TABLES: every stated lane (ordered by plane, then name) and every stated
/// entry (in statement order).
#[derive(Debug, Default, Clone)]
pub struct RoutingTables {
    lanes: Vec<RoutedLane>,
    by_lane: HashMap<(&'static str, String), usize>,
    entries: Vec<RoutedEntry>,
    by_entry: HashMap<(&'static str, String, String), usize>,
}

/// The value a fact list states for `fact`, if any (the contract check refused a fact stated twice).
fn fact(facts: &[(u16, u64)], fact: u16) -> Option<u64> {
    facts.iter().find(|(f, _)| *f == fact).map(|(_, v)| *v)
}

/// The lane-level facts one member states of its lane.
fn lane_of(plane: &'static str, m: &OwnedRouteMember) -> RoutedLane {
    RoutedLane {
        plane,
        name: m.lane.clone(),
        provider: m.provider.clone(),
        upstream: m.upstream.clone(),
        max_concurrent: fact(&m.facts, FACT_CONCURRENCY_CAP),
        max_requests: fact(&m.facts, FACT_MAX_REQUESTS),
        context_window: fact(&m.facts, FACT_CONTEXT_WINDOW),
    }
}

impl RoutingTables {
    /// BUILD the generation's tables from every plane's stated routing. An entry whose plane states
    /// no fallback takes the one its reserved sub-keys name at its `path` (`reserved_fallback`: the
    /// kernel's `on_exhausted`, never sent to the plane).
    ///
    /// # Errors
    ///
    /// Every contradiction found, each naming the plane, the section and the entry or lane: a lane
    /// stated with two different sets of lane facts, or one `(section, entry)` stated twice.
    pub fn build(
        stated: &[StatedRouting<'_>],
        reserved_fallback: &dyn Fn(&[String]) -> Option<String>,
    ) -> Result<Self, Vec<String>> {
        let mut errors = Vec::new();
        // The lanes first, so every lane's index is its place in the ordered table.
        let mut lanes: BTreeMap<(&'static str, String), RoutedLane> = BTreeMap::new();
        for s in stated {
            for e in s.entries {
                for m in &e.members {
                    let lane = lane_of(s.plane, m);
                    match lanes.get(&(s.plane, m.lane.clone())) {
                        None => {
                            lanes.insert((s.plane, m.lane.clone()), lane);
                        }
                        Some(first) if *first == lane => {}
                        Some(_) => errors.push(format!(
                            "routing: plane `{}` states lane `{}` twice with different lane facts \
                             (its provider, upstream name, concurrency cap, request budget and \
                             context window must be the same on every member naming it); `{}.{}` \
                             is the second",
                            s.plane, m.lane, e.section, e.entry
                        )),
                    }
                }
            }
        }
        let lanes: Vec<RoutedLane> = lanes.into_values().collect();
        let by_lane: HashMap<(&'static str, String), usize> = lanes
            .iter()
            .enumerate()
            .map(|(i, l)| ((l.plane, l.name.clone()), i))
            .collect();
        let mut entries = Vec::new();
        let mut by_entry = HashMap::new();
        for s in stated {
            for e in s.entries {
                let key = (s.plane, e.section.clone(), e.entry.clone());
                if by_entry.contains_key(&key) {
                    errors.push(format!(
                        "routing: plane `{}` states `{}.{}` twice",
                        s.plane, e.section, e.entry
                    ));
                    continue;
                }
                let entry_timeout = fact(&e.facts, FACT_ATTEMPT_TIMEOUT_MS);
                let members = e
                    .members
                    .iter()
                    .filter_map(|m| {
                        let lane = *by_lane.get(&(s.plane, m.lane.clone()))?;
                        Some(RoutedMember {
                            lane,
                            weight: m.weight,
                            tier: m.tier.clone(),
                            tags: m.tags.clone(),
                            attempt_timeout_ms: fact(&m.facts, FACT_ATTEMPT_TIMEOUT_MS)
                                .or(entry_timeout),
                        })
                    })
                    .collect();
                by_entry.insert(key, entries.len());
                entries.push(RoutedEntry {
                    plane: s.plane,
                    section: e.section.clone(),
                    name: e.entry.clone(),
                    path: e.path.clone(),
                    fallback: e.fallback.clone().or_else(|| reserved_fallback(&e.path)),
                    exclude: e.exclude.clone(),
                    failover_timeout_secs: fact(&e.facts, FACT_FAILOVER_TIMEOUT_SECS),
                    failover_max_hops: fact(&e.facts, FACT_FAILOVER_MAX_HOPS),
                    members,
                });
            }
        }
        if errors.is_empty() {
            Ok(RoutingTables {
                lanes,
                by_lane,
                entries,
                by_entry,
            })
        } else {
            Err(errors)
        }
    }

    /// Every lane, ordered by plane, then name: a lane's index is its place here.
    #[must_use]
    pub fn lanes(&self) -> &[RoutedLane] {
        &self.lanes
    }

    /// The index of plane `plane`'s lane `name`.
    #[must_use]
    pub fn lane(&self, plane: &'static str, name: &str) -> Option<usize> {
        self.by_lane.get(&(plane, name.to_string())).copied()
    }

    /// Every entry, in statement order.
    #[must_use]
    pub fn entries(&self) -> &[RoutedEntry] {
        &self.entries
    }

    /// Plane `plane`'s entry `name` in its section `section`.
    #[must_use]
    pub fn entry(&self, plane: &'static str, section: &str, name: &str) -> Option<&RoutedEntry> {
        let i = self
            .by_entry
            .get(&(plane, section.to_string(), name.to_string()))?;
        self.entries.get(*i)
    }

    /// The names of plane `plane`'s entries in section `section`, in statement order: the namespace
    /// a reference into that section (a group's allowed list, a fallback) is judged against.
    pub fn entry_names<'s>(
        &'s self,
        plane: &'static str,
        section: &'s str,
    ) -> impl Iterator<Item = &'s str> + 's {
        self.entries
            .iter()
            .filter(move |e| e.plane == plane && e.section == section)
            .map(|e| e.name.as_str())
    }

    /// THE LANE STORE'S ROWS for these lanes, in lane order: each lane's concurrency permits (an
    /// unbounded lane holds `Semaphore::MAX_PERMITS`, which never throttles yet keeps the permit
    /// path intact) and its request budget (`-1` = unlimited), every counter zero.
    #[must_use]
    pub fn lane_data(&self) -> Vec<crate::store::LaneData> {
        self.lanes
            .iter()
            .map(|l| {
                let max = l
                    .max_concurrent
                    .and_then(|n| usize::try_from(n).ok())
                    .unwrap_or(tokio::sync::Semaphore::MAX_PERMITS)
                    .min(tokio::sync::Semaphore::MAX_PERMITS);
                let budget = l
                    .max_requests
                    .map_or(-1, |n| i64::try_from(n).unwrap_or(i64::MAX));
                crate::store::LaneData {
                    member: l.name.clone(),
                    route: l.provider.clone(),
                    max,
                    sem: std::sync::Arc::new(tokio::sync::Semaphore::new(max)),
                    limited: l.max_requests.is_some(),
                    budget,
                    cooldown_until: 0,
                    streak: 0,
                    dead: false,
                    dead_reason: String::new(),
                    ok: 0,
                    err: 0,
                    client_fault: 0,
                }
            })
            .collect()
    }

    /// The entry `e` falls back to, in its own plane and section; `None` when it names none, or
    /// names no stated entry.
    #[must_use]
    pub fn fallback_of(&self, e: &RoutedEntry) -> Option<&RoutedEntry> {
        self.entry(e.plane, &e.section, e.fallback.as_deref()?)
    }

    /// THE GENERIC FALLBACK REFUSALS over every entry, in the previous release's words with the
    /// entry's noun taken from its plane's declaration (`noun(plane, section)`, the Statement
    /// section's `entry_noun`): a fallback naming no entry of its own section, a fallback naming its
    /// own entry, and a fallback ring (reported once, from its smallest-named member). The reserved
    /// `on_exhausted`/`fallback_pool` words are the kernel's own sub-key names.
    #[must_use]
    pub fn fallback_refusals(&self, noun: &dyn Fn(&str, &str) -> String) -> Vec<String> {
        let mut errors = Vec::new();
        for e in &self.entries {
            let Some(to) = e.fallback.as_deref() else {
                continue;
            };
            let n = noun(e.plane, &e.section);
            if self.fallback_of(e).is_none() {
                errors.push(format!(
                    "{n} '{}' on_exhausted references unknown fallback {n} '{to}'",
                    e.name
                ));
            } else if to == e.name {
                errors.push(format!(
                    "{n} '{}' on_exhausted references itself as its fallback {n} ('{to}'); a \
                     self-referential fallback never engages (the runtime loop guard terminates it \
                     on re-entry) so it 503s exactly as having no fallback would. Point it at a \
                     different {n} or remove on_exhausted",
                    e.name
                ));
            }
        }
        for e in &self.entries {
            let n = noun(e.plane, &e.section);
            let mut path: Vec<&str> = Vec::new();
            let mut cursor = e;
            loop {
                if path.contains(&cursor.name.as_str()) {
                    let start = path.iter().position(|p| *p == cursor.name).unwrap_or(0);
                    let ring = &path[start..];
                    let smallest = ring.iter().min().copied().unwrap_or_default();
                    if e.name == smallest && ring.len() > 1 {
                        let mut display = ring.to_vec();
                        display.push(cursor.name.as_str());
                        errors.push(format!(
                            "fallback_pool cycle detected: {}; on_exhausted fallback chains must \
                             not loop — the runtime loop guard terminates a cycle on re-entry, so \
                             every {n} in the ring 503s instead of degrading. Break the cycle \
                             (point one {n} at a non-looping {n} or remove its on_exhausted)",
                            display.join(" -> ")
                        ));
                    }
                    break;
                }
                let Some(next) = self.fallback_of(cursor) else {
                    break;
                };
                path.push(cursor.name.as_str());
                cursor = next;
            }
        }
        errors
    }
}

#[cfg(test)]
#[path = "tests/routing_tests.rs"]
mod tests;
