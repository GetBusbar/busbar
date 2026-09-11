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
//! metrics: `requests` | `tokens` | `tokens_input` | `tokens_output` | `tokens_cache_read` |
//! `tokens_cache_write` | `budget` | `concurrent`. The four `tokens_*` metrics mirror the cost
//! tiers (`tokens_input` = uncached input, `tokens_output` = output, `tokens_cache_read`,
//! `tokens_cache_write` = cache creation) and are windowed exactly like `tokens`. windows (nouns):
//! `minute` | `hour` | `day` | `month` | `total`. `concurrent` is an in-flight gauge and takes NO
//! `per`; the three windowed metrics REQUIRE one (a windowless cap is ambiguous - fail loudly).
//!
//! A windowed limit may additionally carry `pool: <name>` - the limit then accounts and enforces
//! per `(group, pool)` instead of group-wide, which is how a budget splits across model tiers
//! (`{ budget: 5000, per: month, pool: frontier }` + `{ budget: 5000, per: month, pool: value }`).
//! The named pool must exist (validated at boot / `--validate` / Admin API). `concurrent` takes no
//! `pool` (the in-flight gauge is per group).
//!
//! This file holds only the SHAPES (the serde structs/enums, their `Default`s and their pure
//! accessors). The tree VALIDATION and the child-provisioning helpers stay in busbar-core's
//! `config::groups`, which re-exports everything here at its historical path so no caller moves.

use std::fmt;

use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use busbar_api::ScopeRef;

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
    /// Matches the serde defaults of a bare `groups:` entry (enabled, no parent, no limits, no
    /// child_default), so construction sites can use `..Default::default()` and a future field
    /// addition touches ONE place instead of every literal.
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

/// The serde default for `GroupCfg::enabled` (a group is live unless it says otherwise).
pub fn default_true() -> bool {
    true
}

/// The metric a limit caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitMetric {
    /// Request count per window.
    Requests,
    /// Total tokens (all tiers) per window.
    Tokens,
    /// UNCACHED-INPUT tokens per window (`TierTokens.input`; cached prompt reads are excluded and
    /// counted under `tokens_cache_read` instead) — mirrors the cost `input` tier.
    TokensInput,
    /// OUTPUT tokens per window — mirrors the cost `output` tier.
    TokensOutput,
    /// CACHE-READ tokens per window — mirrors the cost `cache_read` tier.
    TokensCacheRead,
    /// CACHE-WRITE (cache creation) tokens per window — mirrors the cost `cache_write` tier.
    TokensCacheWrite,
    /// Spend (cents, abstract minor units, derived from the ledger x rate_card) per window.
    Budget,
    /// In-flight request gauge - instantaneous, no window.
    Concurrent,
}

impl LimitMetric {
    /// The config spelling (also the metrics/error vocabulary).
    pub fn as_str(&self) -> &'static str {
        match self {
            LimitMetric::Requests => "requests",
            LimitMetric::Tokens => "tokens",
            LimitMetric::TokensInput => "tokens_input",
            LimitMetric::TokensOutput => "tokens_output",
            LimitMetric::TokensCacheRead => "tokens_cache_read",
            LimitMetric::TokensCacheWrite => "tokens_cache_write",
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
    /// Every window, so a consumer that has to recognize a window WORD (e.g. `cost::
    /// is_bucket_of_group`, parsing a bucket id back) enumerates the same five spellings the
    /// projector writes rather than hard-coding its own list.
    pub const ALL: [LimitWindow; 5] = [
        LimitWindow::Minute,
        LimitWindow::Hour,
        LimitWindow::Day,
        LimitWindow::Month,
        LimitWindow::Total,
    ];

    /// The config spelling - ALSO the runtime window-period sentinel (`governance::budget_window`
    /// matches these exact strings) and the metrics/error vocabulary. One vocabulary everywhere.
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
                     <metric> is one of requests|tokens|tokens_input|tokens_output|\
                     tokens_cache_read|tokens_cache_write|budget|concurrent and <window> one of \
                     minute|hour|day|month|total (omit `per` for concurrent; `pool` is optional \
                     and scopes the limit to one pool's traffic)",
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

                while let Some(key) = map.next_key::<String>()? {
                    let named = match key.as_str() {
                        "requests" => Some(LimitMetric::Requests),
                        "tokens" => Some(LimitMetric::Tokens),
                        "tokens_input" => Some(LimitMetric::TokensInput),
                        "tokens_output" => Some(LimitMetric::TokensOutput),
                        "tokens_cache_read" => Some(LimitMetric::TokensCacheRead),
                        "tokens_cache_write" => Some(LimitMetric::TokensCacheWrite),
                        "budget" => Some(LimitMetric::Budget),
                        "concurrent" => Some(LimitMetric::Concurrent),
                        "per" => {
                            if per.is_some() {
                                return Err(de::Error::duplicate_field("per"));
                            }
                            per = Some(map.next_value()?);
                            None
                        }
                        "pool" => {
                            if pool.is_some() {
                                return Err(de::Error::duplicate_field("pool"));
                            }
                            pool = Some(map.next_value()?);
                            None
                        }
                        "on_exhaust" => {
                            if on_exhaust.is_some() {
                                return Err(de::Error::duplicate_field("on_exhaust"));
                            }
                            on_exhaust = Some(map.next_value()?);
                            None
                        }
                        "downgrade_to" => {
                            if downgrade_to.is_some() {
                                return Err(de::Error::duplicate_field("downgrade_to"));
                            }
                            downgrade_to = Some(map.next_value()?);
                            None
                        }
                        other => {
                            return Err(de::Error::unknown_field(
                                other,
                                &[
                                    "requests",
                                    "tokens",
                                    "tokens_input",
                                    "tokens_output",
                                    "tokens_cache_read",
                                    "tokens_cache_write",
                                    "budget",
                                    "concurrent",
                                    "per",
                                    "pool",
                                    "on_exhaust",
                                    "downgrade_to",
                                ],
                            ));
                        }
                    };
                    if let Some(m) = named {
                        if let Some((prev, _)) = metric {
                            return Err(de::Error::custom(format!(
                                "a limit takes exactly ONE metric key; found both '{}' and '{}'",
                                prev.as_str(),
                                m.as_str()
                            )));
                        }
                        metric = Some((m, map.next_value()?));
                    }
                }

                let Some((metric, amount)) = metric else {
                    return Err(de::Error::custom(
                        "a limit needs exactly one metric key \
                         (requests | tokens | tokens_input | tokens_output | tokens_cache_read | \
                         tokens_cache_write | budget | concurrent)",
                    ));
                };

                if metric == LimitMetric::Concurrent && pool.is_some() {
                    return Err(de::Error::custom(
                        "`concurrent` is a per-group in-flight gauge and takes NO `pool:` \
                         qualifier; remove `pool`",
                    ));
                }
                // The exhaustion pair is shape-checked HERE (metric + coupling are parse-time
                // facts); the pools' existence is validated with the tree.
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
                    }),
                }
            }
        }

        deserializer.deserialize_map(LimitVisitor)
    }
}

/// Serialize mirrors the custom deserializer: a limit is a map with its ONE metric key + amount, plus
/// `per: <window>` for the windowed metrics (never for `concurrent`). This is what lets a group survive
/// in the config OVERLAY (the Admin-API-mutable persistence layer): the round-trip `{ budget: 1000,
/// per: month }` -> LimitCfg -> `{ budget: 1000, per: month }` is exact, so an API-applied group budget
/// re-parses identically at boot. Deliberately hand-written (not derived) so it can never drift from the
/// `{ <metric>: <amount>, per: <window> }` shape the deserializer enforces.
impl Serialize for LimitCfg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let len = 1
            + usize::from(self.per.is_some())
            + usize::from(self.scope.is_some())
            + usize::from(self.on_exhaust.is_some())
            + usize::from(self.downgrade_to.is_some());
        let mut map = serializer.serialize_map(Some(len))?;
        map.serialize_entry(self.metric.as_str(), &self.amount)?;
        if let Some(window) = self.per {
            map.serialize_entry("per", window.as_str())?;
        }
        // Wire-compat: a `kind: "pool"` scope still serializes under the bare `pool:`
        // YAML key. There is no second kind yet, so every `scope` reaching here IS `kind: "pool"`
        // by construction (the deserializer above only ever produces `ScopeRef::pool`).
        if let Some(scope) = &self.scope {
            map.serialize_entry("pool", &scope.value)?;
        }
        if let Some(on_exhaust) = self.on_exhaust {
            map.serialize_entry("on_exhaust", &on_exhaust)?;
        }
        if let Some(to) = &self.downgrade_to {
            map.serialize_entry("downgrade_to", &to.value)?;
        }
        map.end()
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE RELAY — the parsed `groups:` tree read into the neutral limit vocabulary
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// **THE ONE RELAY** from this grammar into [`busbar_contract::limits`], the vocabulary the crate
/// that projects a limit tree into enforcement buckets reads.
///
/// A relay with no arithmetic in it: metric, amount, window, scope and downgrade target are copied
/// across in the order the grammar declares them, and what is DONE with them — which ledger cell a
/// limit lands in, how repeats fold, whose exhaustion behaviour governs — belongs entirely to the
/// projecting crate. A projection written here would be a SECOND projection, and two readings of
/// one `groups:` section that must agree exactly is how a deployment comes to be ADMITTED against
/// one set of ledger cells and BILLED against another, silently, because both readings are
/// internally consistent and neither knows the other exists.
///
/// It lives HERE, beside the grammar, because this is the crate that has the section parsed and the
/// contract vocabulary is one this crate already names. Every reader reaches it: a composition root,
/// an engine with no root behind it, and a test that builds a table by hand. That reachability is
/// the whole point — a reader that cannot reach the relay writes a copy of it, and the copy is the
/// failure above.
///
/// `lease_ids` is the interned name per group, where a composition root interned one. A group
/// absent from the map carries no lease id, which is not an error and not a degraded projection:
/// the resolved table is identical either way, and a caller reading interned names back simply does
/// not see that one. A caller with no interning to offer passes an empty map.
#[must_use]
pub fn group_specs(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
    lease_ids: &std::collections::BTreeMap<String, &'static str>,
) -> std::collections::BTreeMap<String, busbar_contract::limits::GroupSpec> {
    groups
        .iter()
        .map(|(name, cfg)| {
            let limits = cfg.limits.iter().map(limit_spec).collect();
            let spec = busbar_contract::limits::GroupSpec {
                lease_id: lease_ids.get(name).copied(),
                parent: cfg.parent.clone(),
                enabled: cfg.enabled,
                limits,
            };
            (name.clone(), spec)
        })
        .collect()
}

/// One parsed limit in the neutral vocabulary. The window is the grammar's own `&'static str`
/// spelling, which is also the runtime period sentinel — so the relay hands over the same word the
/// bucket id is built from rather than a re-spelling of it.
fn limit_spec(l: &LimitCfg) -> busbar_contract::limits::LimitSpec {
    busbar_contract::limits::LimitSpec {
        metric: metric_spec(l.metric),
        amount: l.amount,
        window: l.per.map(|w| w.as_str()),
        scope: l.scope.as_ref().map(scope_spec),
        downgrade_to: l.downgrade_to.as_ref().map(scope_spec),
    }
}

/// A scope reference in the neutral vocabulary, KIND AND ALL. The kind rides along because the
/// bucket id carries it, and a bucket id is a ledger row name.
fn scope_spec(s: &ScopeRef) -> busbar_contract::limits::ScopeSpec {
    busbar_contract::limits::ScopeSpec {
        kind: s.kind.to_string(),
        value: s.value.clone(),
    }
}

/// The grammar's metric in the neutral spelling. One arm per variant and no wildcard, so a metric
/// the grammar gains and this relay does not is a COMPILE ERROR, never a limit that projects to
/// nothing — an unprojected limit is a cap an operator wrote down and the node does not enforce.
fn metric_spec(metric: LimitMetric) -> busbar_contract::limits::LimitMetric {
    use busbar_contract::limits::LimitMetric as Spec;
    match metric {
        LimitMetric::Requests => Spec::Requests,
        LimitMetric::Tokens => Spec::Tokens,
        LimitMetric::TokensInput => Spec::TokensInput,
        LimitMetric::TokensOutput => Spec::TokensOutput,
        LimitMetric::TokensCacheRead => Spec::TokensCacheRead,
        LimitMetric::TokensCacheWrite => Spec::TokensCacheWrite,
        LimitMetric::Budget => Spec::Budget,
        LimitMetric::Concurrent => Spec::Concurrent,
    }
}
