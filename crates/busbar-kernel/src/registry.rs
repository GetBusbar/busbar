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

/// The kinds of plugin the kernel knows how to hold.
///
/// Closed, because it is structure: what each kind is FOR is open vocabulary the plugin declares.
// contract: the plugin kind table
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PluginKind {
    /// Says what bytes mean.
    Plane,
    /// Moves bytes. In-tree only.
    Transport,
    /// Turns a credential into a principal.
    Auth,
    /// Decorates an outbound request.
    EgressAuth,
    /// Keeps the journal and the windows.
    Store,
    /// Resolves and seals key material.
    Secret,
    /// Observes, and at a gate seat may restrict, veto or rewrite.
    Hook,
    /// Receives journal entries and content facts.
    Export,
}

/// The one base trait everything registered implements.
///
/// Deliberately tiny: a key and a kind. Everything a kind can actually DO lives on that kind's own
/// trait, which the caller looks up by key.
// contract: Plugin
pub trait Plugin: Send + Sync + 'static {
    /// The plugin's declared key. Its whole open vocabulary hangs off this.
    fn key(&self) -> &str;

    /// Which kind it is.
    fn kind(&self) -> PluginKind;
}

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// Two plugins of one kind declared the same key.
    DuplicateKey {
        /// The kind they both are.
        kind: PluginKind,
        /// The key they both claimed.
        key: String,
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
    key: String,
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
        let (key, kind) = (plugin.key().to_string(), plugin.kind());
        if self.live(kind, &key).is_some() {
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
        let (key, kind) = (plugin.key().to_string(), plugin.kind());
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

/// One claim: a plane saying which bytes on which transport belong to it.
// contract: Claim
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The plane that made the claim.
    pub plane: String,
    /// The transport it is claimed on, as a key. Two claims on different transports can never both
    /// match, because the bytes never reach both.
    pub transport: String,
    /// What it matches.
    pub selector: Selector,
}

/// Two claims that could both match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimConflict {
    /// The first claim.
    pub left: Claim,
    /// The second.
    pub right: Claim,
}

impl std::fmt::Display for ClaimConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "claims of {} and {} on transport {} can both match",
            self.left.plane, self.right.plane, self.left.transport
        )
    }
}

impl std::error::Error for ClaimConflict {}

/// Check every pair of claims across planes, and answer at boot.
///
/// Within ONE plane the claims are an ordered pattern set with most-specific-wins precedence, so
/// two of a plane's own claims are allowed to overlap; across planes they are not.
pub fn check_claims(claims: &[Claim]) -> Result<(), Box<ClaimConflict>> {
    for (i, left) in claims.iter().enumerate() {
        for right in &claims[i + 1..] {
            if left.plane == right.plane {
                continue;
            }
            if left.transport == right.transport && overlaps(&left.selector, &right.selector) {
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
pub fn precedence_order(claims: &[Claim]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..claims.len()).collect();
    order.sort_by(|a, b| {
        claims[*b]
            .selector
            .specificity()
            .cmp(&claims[*a].selector.specificity())
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
    if left.family() != right.family() {
        // Different axes. Nothing here can prove they do not coincide, so they might.
        return true;
    }
    match left.family() {
        SelectorFamily::Header => header_overlaps(left, right),
        SelectorFamily::Path => path_overlaps(left, right),
        SelectorFamily::Transport => transport_overlaps(left, right),
    }
}

/// Header forms: different headers never collide; the same header collides unless two exact values
/// differ, or a prefix rules the value out.
fn header_overlaps(left: &Selector, right: &Selector) -> bool {
    let (ln, rn) = (left.header(), right.header());
    if !matches!((ln, rn), (Some(a), Some(b)) if a.eq_ignore_ascii_case(b)) {
        return false;
    }
    match (left, right) {
        (Selector::HeaderExact(_, a), Selector::HeaderExact(_, b)) => a == b,
        (Selector::HeaderExact(_, v), Selector::HeaderPrefix(_, p))
        | (Selector::HeaderPrefix(_, p), Selector::HeaderExact(_, v)) => v.starts_with(p.as_str()),
        (Selector::HeaderPrefix(_, a), Selector::HeaderPrefix(_, b)) => {
            a.starts_with(b.as_str()) || b.starts_with(a.as_str())
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
        (Selector::PathSuffix(a), Selector::PathSuffix(b)) => {
            a.ends_with(b.as_str()) || b.ends_with(a.as_str())
        }
        (Selector::PathSuffix(s), Selector::ExactPath(p))
        | (Selector::ExactPath(p), Selector::PathSuffix(s)) => p.ends_with(s.as_str()),
        (Selector::PathContains(c), Selector::ExactPath(p))
        | (Selector::ExactPath(p), Selector::PathContains(c)) => p.contains(c.as_str()),
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
fn one_level_pattern(prefix: &str) -> Vec<Segment> {
    let mut segments: Vec<Segment> = split_path(prefix)
        .map(|s| Segment::Lit(s.to_string()))
        .collect();
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
                if segments.get(i) != Some(&lit.as_str()) {
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
