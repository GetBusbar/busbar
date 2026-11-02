// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use crate::grammar::{Selector, SelectorFamily};

/// Which generation of the registry a lookup is against.
///
/// Monotonic, and never reused. A unit carries the one it started at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Generation(u64);

impl Generation {
    pub const FIRST: Generation = Generation(0);

    pub fn get(self) -> u64 {
        self.0
    }
}

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
    pub fn new() -> Self {
        Registry::default()
    }

    pub fn generation(&self) -> Generation {
        self.generation
    }

    pub fn register(&mut self, plugin: Arc<dyn Plugin>) -> Result<Generation, RegistryError> {
        let (key, kind) = (plugin.key(), plugin.kind());
        if self.live(kind, key).is_some() {
            return Err(RegistryError::DuplicateKey { kind, key });
        }
        self.entries.push(Registered { key, kind, plugin });
        Ok(self.generation)
    }

    pub fn resolve(&self, kind: PluginKind, key: &str) -> Option<Arc<dyn Plugin>> {
        self.live(kind, key).map(|e| Arc::clone(&e.plugin))
    }

    pub fn count(&self, kind: PluginKind) -> usize {
        self.entries.iter().filter(|e| e.kind == kind).count()
    }

    fn live(&self, kind: PluginKind, key: &str) -> Option<&Registered> {
        self.entries.iter().find(|e| e.kind == kind && e.key == key)
    }
}

pub use busbar_contract::Claim;

/// A claim as the registry holds it: the plane's words, and which plane said them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaneClaim {
    /// The plane that made the claim.
    pub plane: &'static str,
    /// What the plane claimed.
    pub claim: Claim,
}

/// Two claims that could both match, at a precedence that cannot tell them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimConflict {
    /// The first claim.
    pub left: PlaneClaim,
    /// The second.
    pub right: PlaneClaim,
    /// Why the pair could not be settled by the order.
    pub reason: ConflictReason,
}

/// Why an overlapping pair is a refusal rather than a resolved precedence question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictReason {
    /// The two claims sit at the same precedence, so the sealed order has nothing to say about
    /// which of them owns the bytes and the route would be decided by declaration accident.
    EqualPrecedence,
}

impl std::fmt::Display for ClaimConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.reason {
            ConflictReason::EqualPrecedence => write!(
                f,
                "claims of {} and {} on transport {} can both match at equal precedence, so nothing \
                 decides which owns the bytes",
                self.left.plane, self.right.plane, self.left.claim.transport
            ),
        }
    }
}

impl std::error::Error for ClaimConflict {}

/// One overlapping pair the sealed order settled, and which side won it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedOverlap {
    /// The first claim, by index into the claim slice.
    pub left: usize,
    /// The second, by index.
    pub right: usize,
    /// Which of the two the order puts first, and therefore which one takes bytes both match.
    pub winner: usize,
}

/// One overlapping pair the sealed order could not settle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedOverlap {
    /// The first claim, by index into the claim slice.
    pub left: usize,
    /// The second, by index.
    pub right: usize,
    /// Why the pair is a refusal.
    pub reason: ConflictReason,
}

/// What sealing the claim set produced.
///
/// Three answers, not one. The ORDER is the walk every arriving connection is matched against.
/// The RESOLVED list is every cross-plane pair that could both match and was settled by that order:
/// they are recorded rather than refused, because most-specific-wins is a decision and not a
/// coincidence — recording them is what lets an operator read off which plane wins a shape two
/// planes both describe. The REFUSED list is the pairs the order cannot settle, and it is the only
/// one of the three that stops a boot.
#[derive(Debug, Clone, Default)]
pub struct SealedClaims {
    /// Indices into the claim slice, most specific first, ties broken by declaration order.
    pub order: Vec<usize>,
    /// Every cross-plane overlap the order settled, with the winner named.
    pub resolved: Vec<ResolvedOverlap>,
    /// Every cross-plane overlap the order could not settle.
    pub refused: Vec<RefusedOverlap>,
}

#[must_use]
pub fn seal_claims(claims: &[PlaneClaim]) -> SealedClaims {
    let mut sealed = SealedClaims {
        order: precedence_order(claims),
        ..SealedClaims::default()
    };
    for (i, left) in claims.iter().enumerate() {
        for (offset, right) in claims[i + 1..].iter().enumerate() {
            let j = i + 1 + offset;
            if left.plane == right.plane || !claims_overlap(&left.claim, &right.claim) {
                continue;
            }
            let (a, b) = (
                precedence(&left.claim.selector),
                precedence(&right.claim.selector),
            );
            match a.cmp(&b) {
                std::cmp::Ordering::Equal => sealed.refused.push(RefusedOverlap {
                    left: i,
                    right: j,
                    reason: ConflictReason::EqualPrecedence,
                }),
                std::cmp::Ordering::Greater => sealed.resolved.push(ResolvedOverlap {
                    left: i,
                    right: j,
                    winner: i,
                }),
                std::cmp::Ordering::Less => sealed.resolved.push(ResolvedOverlap {
                    left: i,
                    right: j,
                    winner: j,
                }),
            }
        }
    }
    sealed
}

#[must_use]
pub fn claims_overlap(left: &Claim, right: &Claim) -> bool {
    left.transport == right.transport
        && schemes_compatible(left, right)
        && overlaps(&left.selector, &right.selector)
}

#[must_use]
pub fn schemes_compatible(left: &Claim, right: &Claim) -> bool {
    let (Some(mine), Some(theirs)) = (left.scheme, right.scheme) else {
        return true;
    };
    let holds = |claim: &Claim, name: &str| {
        claim.scheme.is_some_and(|s| s == name) || claim.scheme_alternatives.contains(&name)
    };
    holds(right, mine)
        || holds(left, theirs)
        || left.scheme_alternatives.iter().any(|a| holds(right, a))
}

pub fn check_claims(claims: &[PlaneClaim]) -> Result<(), Box<ClaimConflict>> {
    match seal_claims(claims).refused.first() {
        None => Ok(()),
        Some(refused) => Err(Box::new(ClaimConflict {
            left: claims[refused.left].clone(),
            right: claims[refused.right].clone(),
            reason: refused.reason,
        })),
    }
}

#[must_use]
pub fn precedence(selector: &Selector) -> (u32, u32) {
    let anchored = u32::from(matches!(selector, Selector::PathSuffix(_)));
    (crate::grammar::specificity(selector), anchored)
}

pub fn precedence_order(claims: &[PlaneClaim]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..claims.len()).collect();
    order.sort_by(|a, b| {
        precedence(&claims[*b].claim.selector)
            .cmp(&precedence(&claims[*a].claim.selector))
            .then(a.cmp(b))
    });
    order
}

pub fn overlaps(left: &Selector, right: &Selector) -> bool {
    if crate::grammar::family(left) != crate::grammar::family(right) {
        return true;
    }
    match crate::grammar::family(left) {
        SelectorFamily::Header => header_overlaps(left, right),
        SelectorFamily::Path | SelectorFamily::Transport => left.overlaps(right),
    }
}

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

        _ => true,
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

pub fn bootstrap(prior: Option<[u8; 32]>, ours: Option<[u8; 32]>) -> BootstrapVerdict {
    match (prior, ours) {
        (None, _) => BootstrapVerdict::Mint,
        (Some(sealed), Some(held)) if sealed == held => BootstrapVerdict::AlreadyOurs,
        (Some(_), _) => BootstrapVerdict::KeysetMissing,
    }
}

#[cfg(test)]
#[path = "tests/registry_tests.rs"]
mod registry_tests;
