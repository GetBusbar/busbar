// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The registry: everything the kernel can call, the generation it was called at, and whether two
//! claims could both match the same bytes.
//!
//! Registration is the only way in. A plugin never reaches into the kernel; the kernel registers
//! it, calls it and consumes what it returns. This file is that list, plus two things that follow
//! from it.
//!
//! **Generations.** Reloading configuration does not mutate the list a running unit is walking. A
//! new generation is a new number; entries say which generations they are live for; a unit pins the
//! generation it started at and keeps calling the same plugins all the way to its end, even while a
//! replacement is being installed underneath it.
//!
//! **Claims.** A claim says "these bytes are mine". Two claims that could both match the same bytes
//! make routing a coin toss, so the question is asked at boot, over every pair, and a node that
//! cannot answer "no" refuses to start. [`overlaps`] is deliberately CONSERVATIVE: where the shapes
//! are not comparable it answers "yes, they might", because the cost of a false yes is a
//! configuration error at boot and the cost of a false no is two planes fighting over live bytes.

use std::sync::Arc;

use crate::grammar::{Segment, Selector, SelectorFamily};

/// Which generation of the registry a lookup is against.
///
/// Monotonic, and never reused. A unit carries the one it started at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    /// The generation a freshly built registry is at.
    pub const FIRST: Generation = Generation(0);

    /// The generation as a number, for the journal.
    pub fn get(self) -> u64 {
        self.0
    }

    fn next(self) -> Generation {
        Generation(self.0 + 1)
    }
}

/// The kinds of plugin the kernel knows how to hold, and the one base trait every one of them
/// implements.
///
/// Both are the contract's: a plugin declares its own kind and its own key, so these are the very
/// values that arrive from outside the kernel. A registry that named its own copy would be
/// registering something other than what was handed to it.
pub use busbar_contract::{Kind as PluginKind, Plugin};

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Two plugins of one kind declared the same key.
    DuplicateKey {
        /// The kind they both are.
        kind: PluginKind,
        /// The key they both claimed.
        key: &'static str,
    },
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegistryError::DuplicateKey { kind, key } => {
                write!(f, "two {kind:?} plugins both declare the key {key:?}")
            }
        }
    }
}

impl std::error::Error for RegistryError {}

struct Registered {
    key: &'static str,
    kind: PluginKind,
    since: Generation,
    until: Option<Generation>,
    plugin: Arc<dyn Plugin>,
}

/// Everything the kernel can call, and when.
#[derive(Default)]
pub struct Registry {
    entries: Vec<Registered>,
    generation: Generation,
}

impl Default for Generation {
    fn default() -> Self {
        Generation::FIRST
    }
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("entries", &self.entries.len())
            .field("generation", &self.generation)
            .finish()
    }
}

impl Registry {
    /// An empty registry at the first generation.
    pub fn new() -> Self {
        Registry::default()
    }

    /// The generation a unit starting now should pin.
    pub fn generation(&self) -> Generation {
        self.generation
    }

    /// Add a plugin. Refused if its kind already has that key live.
    pub fn register(&mut self, plugin: Arc<dyn Plugin>) -> Result<Generation, RegistryError> {
        let (key, kind) = (plugin.key(), plugin.kind());
        if self.live(kind, key).is_some() {
            return Err(RegistryError::DuplicateKey { kind, key });
        }
        self.entries.push(Registered {
            key,
            kind,
            since: self.generation,
            until: None,
            plugin,
        });
        Ok(self.generation)
    }

    /// Swap a plugin for a new one, opening a new generation.
    ///
    /// The old entry is not deleted: it stays reachable at every generation it was live for, so a
    /// unit that started before the swap finishes against what it started with.
    pub fn replace(&mut self, plugin: Arc<dyn Plugin>) -> Generation {
        let (key, kind) = (plugin.key(), plugin.kind());
        let next = self.generation.next();
        for entry in &mut self.entries {
            if entry.kind == kind && entry.key == key && entry.until.is_none() {
                entry.until = Some(next);
            }
        }
        self.entries.push(Registered {
            key,
            kind,
            since: next,
            until: None,
            plugin,
        });
        self.generation = next;
        next
    }

    /// Retire a plugin as of the next generation.
    pub fn retire(&mut self, kind: PluginKind, key: &str) -> Generation {
        let next = self.generation.next();
        for entry in &mut self.entries {
            if entry.kind == kind && entry.key == key && entry.until.is_none() {
                entry.until = Some(next);
            }
        }
        self.generation = next;
        next
    }

    /// Look a plugin up as of the current generation.
    pub fn resolve(&self, kind: PluginKind, key: &str) -> Option<Arc<dyn Plugin>> {
        self.resolve_at(kind, key, self.generation)
    }

    /// Look a plugin up as of the generation a unit pinned.
    pub fn resolve_at(
        &self,
        kind: PluginKind,
        key: &str,
        at: Generation,
    ) -> Option<Arc<dyn Plugin>> {
        self.entries
            .iter()
            .find(|e| {
                e.kind == kind
                    && e.key == key
                    && e.since <= at
                    && e.until.map(|until| at < until).unwrap_or(true)
            })
            .map(|e| Arc::clone(&e.plugin))
    }

    /// How many plugins of a kind are live now.
    pub fn count(&self, kind: PluginKind) -> usize {
        self.entries
            .iter()
            .filter(|e| e.kind == kind && e.until.is_none())
            .count()
    }

    fn live(&self, kind: PluginKind, key: &str) -> Option<&Registered> {
        self.entries
            .iter()
            .find(|e| e.kind == kind && e.key == key && e.until.is_none())
    }
}

/// One claim, paired with the plane that made it.
///
/// The claim itself is the contract's — a plane writes it as an associated constant, so it is the
/// plane's own words. What the kernel adds is which plane said it, because the registry is what
/// knows that and because the across-planes overlap rule is the one thing a claim cannot answer
/// about itself.
pub use busbar_contract::Claim;

/// A claim as the registry holds it: the plane's words, and which plane said them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneClaim {
    /// The plane that made the claim.
    pub plane: &'static str,
    /// What the plane claimed.
    pub claim: Claim,
}

/// Two claims that could both match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimConflict {
    /// The first claim.
    pub left: PlaneClaim,
    /// The second.
    pub right: PlaneClaim,
}

impl std::fmt::Display for ClaimConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "claims of {} and {} on transport {} can both match",
            self.left.plane, self.right.plane, self.left.claim.transport
        )
    }
}

impl std::error::Error for ClaimConflict {}

/// Check every pair of claims across planes, and answer at boot.
///
/// Within ONE plane the claims are an ordered pattern set with most-specific-wins precedence, so
/// two of a plane's own claims are allowed to overlap; across planes they are not.
pub fn check_claims(claims: &[PlaneClaim]) -> Result<(), Box<ClaimConflict>> {
    for (i, left) in claims.iter().enumerate() {
        for right in &claims[i + 1..] {
            if left.plane == right.plane {
                continue;
            }
            if left.claim.transport == right.claim.transport
                && overlaps(&left.claim.selector, &right.claim.selector)
            {
                return Err(Box::new(ClaimConflict {
                    left: left.clone(),
                    right: right.clone(),
                }));
            }
        }
    }
    Ok(())
}

/// One plane's claims in the order they are tried: most specific first, and ties broken by the
/// order they were declared so the walk is stable across boots.
pub fn precedence_order(claims: &[PlaneClaim]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..claims.len()).collect();
    order.sort_by(|a, b| {
        crate::grammar::specificity(&claims[*b].claim.selector)
            .cmp(&crate::grammar::specificity(&claims[*a].claim.selector))
            .then(a.cmp(b))
    });
    order
}

/// Could these two selectors both match the same bytes?
///
/// Total over the cross-product: every pair of forms has an answer, and where the two forms read
/// different axes — a path pattern and a port, say — the answer is YES, because a request has both
/// a path and a port and nothing here proves they cannot coincide. Refusing to boot on that is the
/// conservative direction: an operator sees it once, at boot, with both claims named.
///
/// Reflexive and symmetric by construction, and both are asserted by the battery.
pub fn overlaps(left: &Selector, right: &Selector) -> bool {
    if crate::grammar::family(left) != crate::grammar::family(right) {
        // Different axes. Nothing here can prove they do not coincide, so they might.
        return true;
    }
    match crate::grammar::family(left) {
        SelectorFamily::Header => header_overlaps(left, right),
        SelectorFamily::Path => path_overlaps(left, right),
        SelectorFamily::Transport => transport_overlaps(left, right),
    }
}

/// Header forms: different headers never collide; the same header collides unless two exact values
/// differ, or a prefix rules the value out.
fn header_overlaps(left: &Selector, right: &Selector) -> bool {
    let (ln, rn) = (left.header_name(), right.header_name());
    if !matches!((ln, rn), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b)) {
        return false;
    }
    match (left, right) {
        (Selector::HeaderExact(_, a), Selector::HeaderExact(_, b)) => a == b,
        (Selector::HeaderExact(_, v), Selector::HeaderPrefix(_, p))
        | (Selector::HeaderPrefix(_, p), Selector::HeaderExact(_, v)) => v.starts_with(p),
        (Selector::HeaderPrefix(_, a), Selector::HeaderPrefix(_, b)) => {
            a.starts_with(b) || b.starts_with(a)
        }
        // Presence matches every value of that header, so it overlaps anything on it.
        _ => true,
    }
}

/// Path forms. Exact against exact is equality; a pattern is walked segment by segment, where a
/// variable overlaps any literal and a tail overlaps any remaining suffix; anything involving a
/// suffix or a "contains" fragment overlaps conservatively, because a path that satisfies both
/// always exists.
fn path_overlaps(left: &Selector, right: &Selector) -> bool {
    match (left, right) {
        (Selector::ExactPath(a), Selector::ExactPath(b)) => a == b,
        (Selector::ExactPath(p), Selector::PrefixOneLevel(prefix))
        | (Selector::PrefixOneLevel(prefix), Selector::ExactPath(p)) => one_level_under(prefix, p),
        (Selector::PrefixOneLevel(a), Selector::PrefixOneLevel(b)) => a == b,
        (Selector::ExactPath(p), Selector::PathPattern(pattern))
        | (Selector::PathPattern(pattern), Selector::ExactPath(p)) => pattern_matches(pattern, p),
        (Selector::PathPattern(a), Selector::PathPattern(b)) => patterns_overlap(a, b),
        (Selector::PrefixOneLevel(prefix), Selector::PathPattern(pattern))
        | (Selector::PathPattern(pattern), Selector::PrefixOneLevel(prefix)) => {
            patterns_overlap(pattern, &one_level_pattern(prefix))
        }
        (Selector::PathSuffix(a), Selector::PathSuffix(b)) => a.ends_with(b) || b.ends_with(a),
        (Selector::PathSuffix(s), Selector::ExactPath(p))
        | (Selector::ExactPath(p), Selector::PathSuffix(s)) => p.ends_with(s),
        (Selector::PathContains(c), Selector::ExactPath(p))
        | (Selector::ExactPath(p), Selector::PathContains(c)) => p.contains(c),
        // Fragment forms against pattern forms: a path satisfying both can always be written.
        _ => true,
    }
}

/// Transport forms: same form compares its value, different forms coincide.
fn transport_overlaps(left: &Selector, right: &Selector) -> bool {
    match (left, right) {
        (Selector::Sni(a), Selector::Sni(b))
        | (Selector::ClientCertSubject(a), Selector::ClientCertSubject(b))
        | (Selector::StreamName(a), Selector::StreamName(b))
        | (Selector::Alpn(a), Selector::Alpn(b)) => a == b,
        (Selector::Port(a), Selector::Port(b)) => a == b,
        _ => true,
    }
}

/// Is `path` exactly one segment below `prefix`?
fn one_level_under(prefix: &str, path: &str) -> bool {
    match path.strip_prefix(prefix) {
        Some(rest) => {
            let rest = rest.strip_prefix('/').unwrap_or(rest);
            !rest.is_empty() && !rest.contains('/')
        }
        None => false,
    }
}

/// A one-level prefix as the pattern it is: the prefix's literals, then one variable.
fn one_level_pattern(prefix: &'static str) -> Vec<Segment> {
    let mut segments: Vec<Segment> = split_path(prefix).map(Segment::Lit).collect();
    segments.push(Segment::Var);
    segments
}

/// Split a path into its non-empty segments.
fn split_path(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|s| !s.is_empty())
}

/// Does the pattern match this concrete path?
fn pattern_matches(pattern: &[Segment], path: &str) -> bool {
    let segments: Vec<&str> = split_path(path).collect();
    let mut i = 0usize;
    for (position, segment) in pattern.iter().enumerate() {
        match segment {
            Segment::Tail => return position == pattern.len() - 1,
            Segment::Var => {
                if i >= segments.len() {
                    return false;
                }
                i += 1;
            }
            Segment::Lit(lit) => {
                if segments.get(i) != Some(lit) {
                    return false;
                }
                i += 1;
            }
        }
    }
    i == segments.len()
}

/// Could one path satisfy both patterns? Per segment: a variable overlaps any literal, two
/// literals must be equal, and a tail overlaps whatever is left, including nothing.
fn patterns_overlap(left: &[Segment], right: &[Segment]) -> bool {
    let mut i = 0usize;
    loop {
        match (left.get(i), right.get(i)) {
            (None, None) => return true,
            (Some(Segment::Tail), _) | (_, Some(Segment::Tail)) => return true,
            (None, Some(_)) | (Some(_), None) => return false,
            (Some(Segment::Lit(a)), Some(Segment::Lit(b))) if a != b => return false,
            _ => i += 1,
        }
    }
}

/// Whether this deployment has already been bootstrapped.
///
/// One deployment, one bootstrap. The keyset is minted under the first `Bootstrap` unit of a
/// deployment whose store holds none; a second attempt is refused rather than minting a second
/// keyset, because two keysets in one deployment is the failure where nodes stop trusting each
/// other and no one finds out until a lease is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapVerdict {
    /// No prior bootstrap: mint, and seal the fingerprint.
    Mint,
    /// A prior bootstrap with this node's own fingerprint: nothing to do.
    AlreadyOurs,
    /// A prior bootstrap with a fingerprint this node does not have: refuse to serve, and tell the
    /// operator to import the keyset off-node.
    KeysetMissing,
}

/// Decide the bootstrap question from what the store holds and what this node has.
pub fn bootstrap(prior: Option<[u8; 32]>, ours: Option<[u8; 32]>) -> BootstrapVerdict {
    match (prior, ours) {
        (None, _) => BootstrapVerdict::Mint,
        (Some(sealed), Some(held)) if sealed == held => BootstrapVerdict::AlreadyOurs,
        (Some(_), _) => BootstrapVerdict::KeysetMissing,
    }
}
