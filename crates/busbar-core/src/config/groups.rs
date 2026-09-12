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
//! The SHAPES (the serde structs/enums, their `Default`s and their pure accessors) live in
//! `busbar_substrate::config::groups` and are re-exported below at this historical path, so no
//! caller of `busbar_core::config::groups::*` moves. This module keeps the tree VALIDATION and the
//! child-provisioning helpers, which touch the pool namespace and are core-only concerns.

use std::collections::BTreeMap;

// Re-exported so `use super::*;` in this module's tests (which construct a `ScopeRef` directly,
// matching what the pre-move `groups.rs` imported for the same purpose) keeps resolving.
pub use busbar_api::ScopeRef;

pub use busbar_substrate::config::groups::{
    ChildDefault, GroupCfg, LimitCfg, LimitMetric, LimitWindow, OnExhaust,
};

/// Validate the whole `groups:` tree: parents exist, acyclic, and every `pool:`
/// qualifier on a limit (own `limits` and `child_default.limits` alike) names a pool that exists.
/// `pool_exists` abstracts the pool namespace so boot (`cfg.pools`), `--validate`, and the Admin
/// API (`App.pools`) share this verbatim and cannot drift. Returns paste-ready errors in the
/// config_validate style.
pub(crate) fn validate_groups(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
    pool_exists: &dyn Fn(&str) -> bool,
    errors: &mut Vec<String>,
) {
    for (name, group) in groups {
        // A pool-qualified limit against a pool that doesn't exist would silently never match any
        // traffic (an unenforced budget) - reject it at the door instead.
        let own = group.limits.iter().map(|l| (l, "limits"));
        let tmpl = group
            .child_default
            .iter()
            .flat_map(|cd| cd.limits.iter().map(|l| (l, "child_default.limits")));
        for (limit, field) in own.chain(tmpl) {
            // Every `scope`/`downgrade_to` reaching here is `kind: "pool"` (the only registered
            // kind, and the deserializer only ever produces `ScopeRef::pool`); validate its
            // `.value` against the pool namespace, per the generalized discipline ("validated
            // against the config's registered universe for that scope's kind" — for `pool` that
            // universe is still `pools:`, unchanged).
            if let Some(scope) = &limit.scope {
                let pool = &scope.value;
                if !pool_exists(pool) {
                    errors.push(format!(
                        "groups.{name}.{field} has `pool: {pool}`, but no such pool exists; \
                         name a pool from the top-level `pools:` section or drop the qualifier \
                         for a group-wide limit"
                    ));
                }
            }
            if let Some(to) = &limit.downgrade_to {
                let to = &to.value;
                if !pool_exists(to) {
                    errors.push(format!(
                        "groups.{name}.{field} has `downgrade_to: {to}`, but no such pool \
                         exists; exhausted traffic needs a real pool to land on"
                    ));
                }
            }
        }
        if let Some(parent) = &group.parent {
            if !groups.contains_key(parent) {
                errors.push(format!(
                    "groups.{name} names parent '{parent}', which does not exist.\n\
                     Paste this under groups and set its limits:\n\n    \
                     {parent}:\n      limits:\n        - {{ requests: 0, per: minute }}\n"
                ));
                continue;
            }
        }
        // Walk the parent chain from this node: a repeat visit is a cycle. The visited-path check
        // is what makes the walk terminate; the path can never exceed the number of groups.
        let mut cursor = group.parent.as_deref();
        let mut path = vec![name.as_str()];
        while let Some(cur) = cursor {
            if path.contains(&cur) {
                errors.push(format!(
                    "groups chain starting at '{name}' is CYCLIC ({} -> {cur}); break the cycle \
                     by removing one `parent:`",
                    path.join(" -> ")
                ));
                break;
            }
            path.push(cur);
            cursor = groups.get(cur).and_then(|g| g.parent.as_deref());
        }
    }
}

/// Resolve the `child_default` template for a new child provisioned under `parent`, NEAREST-ANCESTOR
/// WINS: walk up the chain from `parent` and return the first group that sets a `child_default`.
/// `None` means no ancestor sets one -> the new child is inherit-only (no limits of its own, capped
/// solely by the parent chain). An unknown `parent` yields `None`.
///
/// Config reaching here is validated ACYCLIC, so the walk terminates on its own; the `groups.len()`
/// bound is a principled backstop (a distinct-node walk cannot exceed the number of groups without
/// revisiting one, i.e. a cycle) — deliberately NOT the arbitrary depth policy constant.
// Wired by the mint auto-provision path (`admin::v1::json::handlers::resolve_mint_group`).
pub(crate) fn resolve_child_default<'a>(
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

/// Build the leaf group to auto-provision as a child under `parent` (e.g. a `user:<sub>` leaf on first
/// self-mint): `parent` set, enabled, and limits copied from the nearest-ancestor `child_default`
/// (inherit-only -> empty limits when no ancestor sets one). The caller persists it via the overlay
/// (`overlay::persist_groups`) and binds the new key to it; the enforcement chain then caps the leaf by
/// `leaf ∩ parent ∩ ...`. Pure: does not mutate `groups`. `child_default` on the leaf itself is left
/// unset (a per-user leaf is not itself a template source).
// Wired by the mint auto-provision path (`admin::v1::json::handlers::resolve_mint_group`).
pub(crate) fn provision_child(groups: &BTreeMap<String, GroupCfg>, parent: &str) -> GroupCfg {
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
