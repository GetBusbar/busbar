// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Path claims per listener: at most one instance per (method set, path pattern) on each listener (IF §12.26).
//! Checked at config load, before any listener binds, so nothing is mounted twice, nothing is silently shadowed
//! and axum never panics on a config load.

use std::collections::HashMap;
use std::fmt::Write as _;

/// Core-written refusal text for config load (operator vocabulary only); the caller wraps it in its existing
/// config error. §12.26's; §12.25 (`hooks::strategy`) refuses with its own typed `StrategyRefused`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigRefused(pub String);
/// Which listener a claim is mounted on. `Export(i)` = the dedicated listener of export instance index i, when
/// the operator gave it one; otherwise its scopes are claims on `Data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ListenerId {
    Data,
    Admin,
    Export(u32),
}
/// K8. One claim; `owner` is operator vocabulary ("export prom-a"), or "core". `methods` = the bit encoding of plane
/// `RouteRec.methods` (§8.6); an export scope claims the GET bit.
pub struct PathClaim<'a> {
    pub listener: ListenerId,
    pub methods: u32,
    pub pattern: &'a str,
    pub owner: &'a str,
}
/// Refuses the first overlapping pair: the text names both owners and the pattern. The pair is the first claim
/// that overlaps an earlier one, with that earlier claim, so the text is stable across loads.
///
/// Two claims overlap when axum would refuse or shadow them: on the same listener, with intersecting method
/// sets, the patterns are equal after normalising parameter names (`{a}`, `:a` → one parameter; `{*a}`, `*a` →
/// one wildcard).
pub fn check_path_claims(claims: &[PathClaim<'_>]) -> Result<(), ConfigRefused> {
    let mut seen: HashMap<(ListenerId, String), Vec<usize>> = HashMap::with_capacity(claims.len());
    for (j, claim) in claims.iter().enumerate() {
        let earlier = seen
            .entry((claim.listener, shape(claim.pattern)))
            .or_default();
        if let Some(&i) = earlier
            .iter()
            .find(|&&i| claims[i].methods & claim.methods != 0)
        {
            return Err(refused(&claims[i], claim));
        }
        earlier.push(j);
    }
    Ok(())
}

/// The pattern with every parameter name dropped: the shape axum's router matches on.
fn shape(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len());
    for (n, segment) in pattern.split('/').enumerate() {
        if n > 0 {
            out.push('/');
        }
        let inner = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}'));
        match inner {
            Some(name) if name.starts_with('*') => out.push_str("{*}"),
            Some(_) => out.push_str("{}"),
            None if segment.starts_with('*') => out.push_str("{*}"),
            None if segment.starts_with(':') => out.push_str("{}"),
            None => out.push_str(segment),
        }
    }
    out
}

fn listener_words(listener: ListenerId) -> &'static str {
    match listener {
        ListenerId::Data => "the data listener",
        ListenerId::Admin => "the admin listener",
        ListenerId::Export(_) => "a dedicated export listener",
    }
}

fn refused(first: &PathClaim<'_>, second: &PathClaim<'_>) -> ConfigRefused {
    let on = listener_words(second.listener);
    let mut text = String::new();
    let _ = if first.owner == CORE || second.owner == CORE {
        let (core, other) = if first.owner == CORE {
            (first, second)
        } else {
            (second, first)
        };
        write!(
            text,
            "{} claims `{}` on {on}, which overlaps the core route `{}`",
            other.owner, other.pattern, core.pattern
        )
    } else if first.pattern == second.pattern {
        write!(
            text,
            "{} and {} both claim `{}` on {on} with a shared method",
            first.owner, second.owner, second.pattern
        )
    } else {
        write!(
            text,
            "{} and {} both claim `{}` on {on} with a shared method (`{}` has the same shape)",
            first.owner, second.owner, second.pattern, first.pattern
        )
    };
    text.push_str("; a path is served by at most one owner per listener");
    ConfigRefused(text)
}

/// The owner word of core's own routes.
const CORE: &str = "core";

#[cfg(test)]
#[path = "tests/path_claims_tests.rs"]
mod tests;
