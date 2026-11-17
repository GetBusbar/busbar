// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The top-level `groups:` block - THE one limit tree. A group is a named
//! enforcement bucket: an ordered list of generic LIMITS plus an optional `parent` forming an
//! acyclic chain (validated). Enforcement walks the chain and ANDs every bucket;
//! `enabled: false` freezes a group (history kept). Keys are PURE AUTH and carry no limits - a key
//! binds to at most one group (`group:` at mint), and a key with no group is authed + unlimited.
//!
//! A limit is `{ <metric>: <amount>, per: <window> }` with exactly ONE metric key:
//!
//! ```yaml
//! limits:
//!   - { requests: 500, per: minute }
//!   - { budget: 1000000, per: month }
//!   - { concurrent: 5 }              # instantaneous - no `per`
//! ```
//!
//! metrics: `requests` | `tokens` | `budget` | `concurrent`. windows (nouns):
//! `minute` | `hour` | `day` | `month` | `total`. `concurrent` is an in-flight gauge and takes NO
//! `per`; the three windowed metrics REQUIRE one (a windowless cap is ambiguous - fail loudly).
//!
//! A windowed limit may additionally carry `pool: <name>` - the limit then accounts and enforces
//! per `(group, pool)` instead of group-wide, which is how a budget splits across named pools
//! (`{ budget: 5000, per: month, pool: tier-a }` + `{ budget: 5000, per: month, pool: tier-b }`).
//! The named pool must exist (validated at boot / `--validate` / the live config-apply path).
//! `concurrent` takes no `pool` (the in-flight gauge is per group).
//!
//! The SHAPES (the serde structs/enums, their `Default`s and their pure accessors) live in
//! `busbar_kernel::config::groups` and are re-exported below at this historical path, so no
//! caller of `busbar_kernel::config::groups::*` moves. This module keeps the tree VALIDATION and the
//! child-provisioning helpers, which touch the pool namespace and are core-only concerns.

use crate::diagnostics::coded;
use std::collections::BTreeMap;

pub use busbar_contract::records::ScopeRef;

pub fn validate_groups(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
    pool_exists: &dyn Fn(&str) -> bool,
    errors: &mut Vec<String>,
) {
    let mut identities: BTreeMap<String, (&str, &str, Option<&ScopeRef>)> = BTreeMap::new();
    for (name, group) in groups {
        for (field, limits) in std::iter::once(("limits", group.limits.as_slice())).chain(
            group
                .child_default
                .iter()
                .map(|template| ("child_default.limits", template.limits.as_slice())),
        ) {
            let mut selected_ids = std::collections::BTreeSet::new();
            for limit in limits {
                if let Some(selected) = &limit.selected {
                    if !valid_selected_identifier(name) {
                        errors.push(coded::config_group_invalid(format!("groups.{name}.{field}: selected-resource group identity must be 1..=128 UTF-8 bytes without controls")).into());
                    }
                    if !selected_ids.insert(selected.id()) {
                        errors.push(
                            coded::config_group_invalid(format!(
                                "groups.{name}.{field}: duplicate selected rule id `{}`",
                                selected.id()
                            ))
                            .into(),
                        );
                    }
                    if !limit.valid_selected_shape() {
                        errors.push(coded::config_group_invalid(format!("groups.{name}.{field}: invalid selected-resource limit combination")).into());
                    }
                }
            }
        }
        for limit in &group.limits {
            if limit.metric == LimitMetric::Concurrent || limit.selected.is_some() {
                continue;
            }
            let Some(window) = limit.per else { continue };
            let components = (name.as_str(), window.as_str(), limit.scope.as_ref());
            let id = crate::cost::group_bucket_id(components.0, components.1, components.2);
            if let Some(previous) = identities.get(&id) {
                if previous != &components {
                    errors.push(coded::config_group_invalid(format!(
                        "groups.{name}.limits has enforcement bucket identity `{id}` also used by \
                         distinct limits of group `{}`; rename the group or its pool to keep usage separate",
                        previous.0
                    )).into());
                }
            } else {
                identities.insert(id, components);
            }
        }

        let own = group.limits.iter().map(|l| (l, "limits"));
        let tmpl = group
            .child_default
            .iter()
            .flat_map(|cd| cd.limits.iter().map(|l| (l, "child_default.limits")));
        for (limit, field) in own.chain(tmpl) {
            if let Some(scope) = &limit.scope {
                let pool = &scope.value;
                if !pool_exists(pool) {
                    errors.push(
                        coded::config_group_invalid(format!(
                            "groups.{name}.{field} has `pool: {pool}`, but no such pool exists; \
                         name a pool from the top-level `pools:` section or drop the qualifier \
                         for a group-wide limit"
                        ))
                        .into(),
                    );
                }
            }
            if let Some(to) = &limit.downgrade_to {
                let to = &to.value;
                if !pool_exists(to) {
                    errors.push(
                        coded::config_group_invalid(format!(
                            "groups.{name}.{field} has `downgrade_to: {to}`, but no such pool \
                         exists; exhausted traffic needs a real pool to land on"
                        ))
                        .into(),
                    );
                }
            }
        }
        if let Some(parent) = &group.parent {
            if !groups.contains_key(parent) {
                errors.push(
                    coded::config_group_invalid(format!(
                        "groups.{name} names parent '{parent}', which does not exist.\n\
                     Paste this under groups and set its limits:\n\n    \
                     {parent}:\n      limits:\n        - {{ requests: 0, per: minute }}\n"
                    ))
                    .into(),
                );
                continue;
            }
        }

        let mut cursor = group.parent.as_deref();
        let mut path = vec![name.as_str()];
        while let Some(cur) = cursor {
            if path.contains(&cur) {
                errors.push(
                    coded::config_group_invalid(format!(
                    "groups chain starting at '{name}' is CYCLIC ({} -> {cur}); break the cycle \
                     by removing one `parent:`",
                    path.join(" -> ")
                ))
                    .into(),
                );
                break;
            }
            path.push(cur);
            cursor = groups.get(cur).and_then(|g| g.parent.as_deref());
        }
    }
}

pub fn resolve_child_default<'a>(
    groups: &'a BTreeMap<String, GroupCfg>,
    parent: &str,
) -> Option<&'a ChildDefault> {
    let mut cursor = Some(parent);
    for _ in 0..=groups.len() {
        let name = cursor?;
        let g = groups.get(name)?;
        if let Some(cd) = &g.child_default {
            return Some(cd);
        }
        cursor = g.parent.as_deref();
    }
    None
}

pub fn provision_child(groups: &BTreeMap<String, GroupCfg>, parent: &str) -> GroupCfg {
    let limits = resolve_child_default(groups, parent)
        .map(|cd| cd.limits.clone())
        .unwrap_or_default();
    GroupCfg {
        parent: Some(parent.to_string()),
        limits,
        ..Default::default()
    }
}

#[cfg(test)]
#[path = "tests/groups_tests.rs"]
mod tests;

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

/// One `groups:` entry.
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GroupCfg {
    /// Optional parent group, forming the enforcement chain (acyclic; validated at
    /// boot / `--validate`).
    #[serde(default)]
    pub parent: Option<String>,
    /// `false` FREEZES the group: every request charging through it is rejected while its history
    /// is kept. Default `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// The group's limits, enforced together (AND). Order preserved (ordered list).
    #[serde(default)]
    pub limits: Vec<LimitCfg>,
    /// Template limits stamped onto any CHILD group auto-provisioned under this one (e.g. a
    /// `user:<sub>` leaf created on first self-mint). Lookup is nearest-ancestor-wins: provisioning
    /// walks up from the immediate parent and uses the first `child_default` it finds; none anywhere
    /// -> the new child is inherit-only (no own limits, capped by the parent chain). Absent when a
    /// group sets no template. Does NOT affect enforcement of THIS group — provisioning-time only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub child_default: Option<ChildDefault>,
}

impl Default for GroupCfg {
    fn default() -> Self {
        GroupCfg {
            parent: None,
            enabled: true,
            limits: Vec::new(),
            child_default: None,
        }
    }
}

/// The limit template a group hands to its auto-provisioned children (see `GroupCfg::child_default`).
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct ChildDefault {
    /// Limits copied onto a newly auto-created child group. Same `{ <metric>: <amount>, per: <window> }`
    /// shape as any group's `limits`.
    #[serde(default)]
    pub limits: Vec<LimitCfg>,
}

pub(crate) fn default_true() -> bool {
    true
}

/// The metric a limit caps. The order is the order a bucket's caps are checked in, so a refusal
/// names the same metric whichever order the operator wrote the limits in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LimitMetric {
    /// Request count per window.
    Requests,
    /// Total tokens (all tiers) per window.
    Tokens,
    /// Spend (cents, abstract minor units, derived from the ledger x rate_card) per window.
    Budget,
    /// In-flight request gauge - instantaneous, no window.
    Concurrent,
}

impl LimitMetric {
    /// Every metric, in the order the refusals list them. The parser and every refusal read this
    /// one table.
    pub const ALL: [LimitMetric; 4] = [
        LimitMetric::Requests,
        LimitMetric::Tokens,
        LimitMetric::Budget,
        LimitMetric::Concurrent,
    ];

    /// The metric a limit key names, if it names one.
    pub fn from_key(key: &str) -> Option<LimitMetric> {
        Self::ALL.iter().copied().find(|m| m.as_str() == key)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            LimitMetric::Requests => "requests",
            LimitMetric::Tokens => "tokens",
            LimitMetric::Budget => "budget",
            LimitMetric::Concurrent => "concurrent",
        }
    }
}

/// A limit's accounting window (nouns only).
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum LimitWindow {
    Minute,
    Hour,
    Day,
    Month,
    Total,
}

impl LimitWindow {
    pub const ALL: [LimitWindow; 5] = [
        LimitWindow::Minute,
        LimitWindow::Hour,
        LimitWindow::Day,
        LimitWindow::Month,
        LimitWindow::Total,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            LimitWindow::Minute => "minute",
            LimitWindow::Hour => "hour",
            LimitWindow::Day => "day",
            LimitWindow::Month => "month",
            LimitWindow::Total => "total",
        }
    }
}

/// One parsed limit: exactly one metric key + its amount, plus the window for windowed metrics.
/// The `{ <metric>: amount, per: window }` shape is enforced at DESERIALIZE time (not a later
/// validation pass), so a malformed limit fails with a precise error at parse.
#[derive(Debug, Clone, PartialEq)]
pub struct LimitCfg {
    pub metric: LimitMetric,
    pub amount: u64,
    /// `Some` for `requests`/`tokens`/`budget` (required); ALWAYS `None` for `concurrent`.
    pub per: Option<LimitWindow>,
    /// `Some(scope)` scopes the limit to traffic dispatched through that scope - accounting
    /// becomes per `(group, scope)`. `None` = group-wide (every request charges it). ALWAYS
    /// `None` for `concurrent`. On the WIRE this is still the `pool: <name>` YAML key (under the
    /// generic-admission-topology generalization: a future scope kind gets its own YAML key,
    /// e.g. `mcp_server: <name>`, never a generic `scope: {kind, value}` object) and always
    /// decodes to `kind: "pool"`. The pool's existence is validated against the config's `pools:`
    /// at the door - generalized discipline: "validated against the config's registered universe
    /// for that scope's kind."
    pub scope: Option<ScopeRef>,
    /// What BUDGET exhaustion does: `block` (the default when absent -
    /// today's 429/quota rejection) or `downgrade` (the request re-admits and dispatches through
    /// `downgrade_to` instead of being refused - expensive calls get cheaper, not blocked).
    /// `downgrade` requires `downgrade_to` + a `pool:` scope + the `budget` metric (validated).
    pub on_exhaust: Option<OnExhaust>,
    /// The scope a `downgrade` sends exhausted traffic to. Present iff `on_exhaust: downgrade`.
    /// Same wire treatment as `scope`: the YAML key stays `downgrade_to: <pool-name>`.
    pub downgrade_to: Option<ScopeRef>,
    /// Process-local per-key selected-resource policy, separate from monetary buckets.
    pub selected: Option<SelectedLimitCfg>,
}

/// The configured identity of a selected-resource rule. Construction validates the wire grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedLimitCfg {
    id: Box<str>,
    instance: Box<str>,
    resource: Box<str>,
}

pub fn valid_selected_identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

impl SelectedLimitCfg {
    fn parse(id: String, selector: String) -> Result<Self, &'static str> {
        let Some((instance, resource)) = selector.split_once('/') else {
            return Err("upstream_resource must name instance/resource");
        };
        if !valid_selected_identifier(&id)
            || !valid_selected_identifier(instance)
            || !valid_selected_identifier(resource)
        {
            return Err("selected rule id, instance and resource must each be 1..=128 UTF-8 bytes without controls");
        }
        Ok(Self {
            id: id.into(),
            instance: instance.into(),
            resource: resource.into(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn instance(&self) -> &str {
        &self.instance
    }
    pub fn resource(&self) -> &str {
        &self.resource
    }
    pub fn selector(&self) -> String {
        format!("{}/{}", self.instance, self.resource)
    }
}

impl LimitCfg {
    pub(crate) fn valid_selected_shape(&self) -> bool {
        self.selected.is_some()
            && matches!(self.metric, LimitMetric::Requests | LimitMetric::Tokens)
            && self.per == Some(LimitWindow::Minute)
            && self.scope.is_none()
            && self.on_exhaust.is_none()
            && self.downgrade_to.is_none()
    }
}

/// The budget-exhaustion behavior a limit may declare (see [`LimitCfg::on_exhaust`]).
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OnExhaust {
    /// Refuse the request (429 / the vendor's quota status) - the default.
    Block,
    /// Re-route the request through `downgrade_to` instead of refusing it.
    Downgrade,
}

/// What a BUDGET limit does to a unit already in flight when it runs dry. Not configurable: every
/// limit finishes the unit in flight (`FinishUnit`); `CutStream` is the money layer's cut-at-
/// checkpoint behavior, which no config key selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ExhaustionMode {
    /// Finish the unit in flight. A unit that is not a stream overshoots by at most one request.
    #[default]
    FinishUnit,
    /// Cut the unit at the checkpoint that dries the budget: the client is told in-stream, and one
    /// Abort line bills what streamed.
    CutStream,
}

/// Every key a limit map accepts, as the unknown-key refusal lists them, in 1.5.5's order.
const LIMIT_KEYS: &[&str] = &[
    "requests",
    "tokens",
    "budget",
    "concurrent",
    "per",
    "pool",
    "on_exhaust",
    "downgrade_to",
    "id",
    "upstream_resource",
    "per_key",
    "enforcement",
];

/// Writes every metric name, 1.5.5's four first, joined by `sep`.
fn write_metrics(f: &mut impl fmt::Write, sep: &str) -> fmt::Result {
    for (i, m) in LimitMetric::ALL.iter().enumerate() {
        if i > 0 {
            f.write_str(sep)?;
        }
        f.write_str(m.as_str())?;
    }
    Ok(())
}

fn once<'de, A: MapAccess<'de>, T: Deserialize<'de>>(
    map: &mut A,
    slot: &mut Option<T>,
    key: &'static str,
) -> Result<(), A::Error> {
    if slot.is_some() {
        return Err(de::Error::duplicate_field(key));
    }
    *slot = Some(map.next_value()?);
    Ok(())
}

impl<'de> Deserialize<'de> for LimitCfg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LimitVisitor;

        impl<'de> Visitor<'de> for LimitVisitor {
            type Value = LimitCfg;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "a limit map `{ <metric>: <amount>, per: <window>, pool: <name> }` where \
                     <metric> is one of ",
                )?;
                write_metrics(f, "|")?;
                f.write_str(
                    " and <window> one of minute|hour|day|month|total (omit `per` for \
                     concurrent; `pool` is optional and scopes the limit to one pool's traffic)",
                )
            }

            fn visit_map<A>(self, mut map: A) -> Result<LimitCfg, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut metric: Option<(LimitMetric, u64)> = None;
                let mut per: Option<LimitWindow> = None;
                let mut pool: Option<String> = None;
                let mut on_exhaust: Option<OnExhaust> = None;
                let mut downgrade_to: Option<String> = None;
                let mut id: Option<String> = None;
                let mut resource: Option<String> = None;
                let mut per_key: Option<bool> = None;
                let mut enforcement: Option<String> = None;

                while let Some(key) = map.next_key::<String>()? {
                    if let Some(m) = LimitMetric::from_key(&key) {
                        if let Some((prev, _)) = metric {
                            return Err(de::Error::custom(format!(
                                "a limit takes exactly ONE metric key; found both '{}' and '{}'",
                                prev.as_str(),
                                m.as_str()
                            )));
                        }
                        metric = Some((m, map.next_value()?));
                        continue;
                    }
                    match key.as_str() {
                        "per" => once(&mut map, &mut per, "per")?,
                        "pool" => once(&mut map, &mut pool, "pool")?,
                        "on_exhaust" => once(&mut map, &mut on_exhaust, "on_exhaust")?,
                        "downgrade_to" => once(&mut map, &mut downgrade_to, "downgrade_to")?,
                        "id" => once(&mut map, &mut id, "id")?,
                        "upstream_resource" => once(&mut map, &mut resource, "upstream_resource")?,
                        "per_key" => once(&mut map, &mut per_key, "per_key")?,
                        "enforcement" => once(&mut map, &mut enforcement, "enforcement")?,
                        other => return Err(de::Error::unknown_field(other, LIMIT_KEYS)),
                    }
                }

                let Some((metric, amount)) = metric else {
                    let mut msg = String::from("a limit needs exactly one metric key (");
                    write_metrics(&mut msg, " | ").map_err(de::Error::custom)?;
                    msg.push(')');
                    return Err(de::Error::custom(msg));
                };

                if id.is_some() || resource.is_some() || per_key.is_some() || enforcement.is_some()
                {
                    let (Some(id), Some(resource), Some(true), Some("process")) =
                        (id, resource, per_key, enforcement.as_deref())
                    else {
                        return Err(de::Error::custom("selected-resource limits require id, upstream_resource, per_key: true and enforcement: process together"));
                    };
                    let selected =
                        SelectedLimitCfg::parse(id, resource).map_err(de::Error::custom)?;
                    let row = LimitCfg {
                        metric,
                        amount,
                        per,
                        scope: pool.map(ScopeRef::pool),
                        on_exhaust,
                        downgrade_to: downgrade_to.map(ScopeRef::pool),
                        selected: Some(selected),
                    };
                    if !row.valid_selected_shape() {
                        return Err(de::Error::custom("selected-resource limits require requests or tokens per minute and forbid pool, on_exhaust and downgrade_to"));
                    }
                    return Ok(row);
                }

                if metric == LimitMetric::Concurrent && pool.is_some() {
                    return Err(de::Error::custom(
                        "`concurrent` is a per-group in-flight gauge and takes NO `pool:` \
                         qualifier; remove `pool`",
                    ));
                }

                if on_exhaust == Some(OnExhaust::Downgrade) && downgrade_to.is_none() {
                    return Err(de::Error::custom(
                        "`on_exhaust: downgrade` requires `downgrade_to: <pool>` - where should \
                         the exhausted traffic go?",
                    ));
                }
                if downgrade_to.is_some() && on_exhaust != Some(OnExhaust::Downgrade) {
                    return Err(de::Error::custom(
                        "`downgrade_to` only makes sense with `on_exhaust: downgrade`",
                    ));
                }
                if on_exhaust.is_some() && metric != LimitMetric::Budget {
                    return Err(de::Error::custom(format!(
                        "`on_exhaust` is a BUDGET-exhaustion behavior; a `{}` limit does not \
                         take it",
                        metric.as_str()
                    )));
                }
                if on_exhaust == Some(OnExhaust::Downgrade) && pool.is_none() {
                    return Err(de::Error::custom(
                        "`on_exhaust: downgrade` requires a `pool:` scope on the limit - a \
                         GROUP-WIDE budget charges every pool, so there is nowhere cheaper to \
                         send the traffic",
                    ));
                }
                if on_exhaust == Some(OnExhaust::Downgrade) && downgrade_to == pool {
                    return Err(de::Error::custom(
                        "`downgrade_to` must name a DIFFERENT pool than the limit's own `pool:`",
                    ));
                }
                match (metric, per) {
                    (LimitMetric::Concurrent, Some(_)) => Err(de::Error::custom(
                        "`concurrent` is an instantaneous in-flight cap and takes NO `per:` \
                         window; remove `per`",
                    )),
                    (LimitMetric::Concurrent, None) => Ok(LimitCfg {
                        metric,
                        amount,
                        per: None,
                        scope: None,
                        on_exhaust: None,
                        downgrade_to: None,
                        selected: None,
                    }),
                    (_, None) => Err(de::Error::custom(format!(
                        "a `{}` limit requires a `per:` window \
                         (minute | hour | day | month | total)",
                        metric.as_str()
                    ))),
                    (_, Some(window)) => Ok(LimitCfg {
                        metric,
                        amount,
                        per: Some(window),
                        scope: pool.map(ScopeRef::pool),
                        on_exhaust,
                        downgrade_to: downgrade_to.map(ScopeRef::pool),
                        selected: None,
                    }),
                }
            }
        }

        // `deserialize_any`, not `deserialize_map`: a non-map value reaches the visitor, whose refusal
        // names the limit grammar (1.5.5's expecting line), not the YAML library's own wording.
        deserializer.deserialize_any(LimitVisitor)
    }
}

impl Serialize for LimitCfg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = 1
            + usize::from(self.per.is_some())
            + usize::from(self.scope.is_some())
            + usize::from(self.on_exhaust.is_some())
            + usize::from(self.downgrade_to.is_some())
            + 4 * usize::from(self.selected.is_some());
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry(self.metric.as_str(), &self.amount)?;
        if let Some(window) = self.per {
            map.serialize_entry("per", window.as_str())?;
        }

        if let Some(scope) = &self.scope {
            map.serialize_entry("pool", &scope.value)?;
        }
        if let Some(on_exhaust) = self.on_exhaust {
            map.serialize_entry("on_exhaust", &on_exhaust)?;
        }
        if let Some(to) = &self.downgrade_to {
            map.serialize_entry("downgrade_to", &to.value)?;
        }
        if let Some(selected) = &self.selected {
            map.serialize_entry("id", selected.id())?;
            map.serialize_entry("upstream_resource", &selected.selector())?;
            map.serialize_entry("per_key", &true)?;
            map.serialize_entry("enforcement", "process")?;
        }
        map.end()
    }
}

#[cfg(test)]
#[path = "tests/groups.rs"]
mod limit_grammar_tests;

#[cfg(test)]
#[path = "tests/group_limit_removed_keys.rs"]
mod group_limit_removed_keys;
