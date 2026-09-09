//! The dialects a boot registered, as DATA this plane reads.
//!
//! ## Why a plane has a registry at all
//!
//! A dialect declares its plane; a plane never names a dialect back. That is the kind boundary, and
//! it is what makes a plane dialect-neutral while its wire surface stays open. But the plane still
//! has to ANSWER two questions a dialect is the only thing that knows: which rungs of the detection
//! ladder are this dialect's, and where in this dialect's bytes each thing the loop asks about is
//! kept. So both arrive as data, at registration, and the plane holds what it was handed.
//!
//! ## Why it is a value and not a global
//!
//! The plane is a value with no interior mutability, and that is asserted rather than promised
//! (`tests/purity.rs` walks the type). A process-global registry would put the one mutable thing in
//! the tree inside the crate whose whole guarantee is that it holds nothing across calls. So the
//! registry is a `&'static` slice, built by the composition root at boot, sealed before the first
//! request, and CARRIED BY the plane exactly as its upstream table is. Registration is construction:
//! there is no `register` method here, because a method that could be called twice is a declaration
//! that could change after a boot proved the claims disjoint.
//!
//! ## What "registers by claim" means
//!
//! An entry is a ROW and a LADDER. The ladder is the dialect's rungs, at the numbers the dialect
//! declared, and [`LlmPlane::walk_ladder`](crate::LlmPlane::walk_ladder) merges every source into
//! ONE ascending walk — so a registered rung is not appended after the plane's own, it is
//! interleaved at its number and wins or loses exactly the contests that number says it should.

use crate::claims::{matches_selector, LadderClaim};
use crate::dialect::Dialect;
use crate::LlmPlane;

/// The most dialects one plane's registry walks.
///
/// A BOUND, not a limit anyone is expected to meet: the ladder walk keeps one cursor per source on
/// the stack, and a bound is what lets it do that without reaching the heap on a path a request can
/// take. The LLM protocol has six dialects; a plane that registered more than this would silently
/// stop walking the surplus, so the census test asserts the registry is inside it.
pub const MAX_REGISTERED_DIALECTS: usize = 8;

/// One dialect's whole contribution to its plane.
///
/// Both halves are constants on the dialect's own side — its `DialectMeta` and its location row —
/// so an entry is `const`-constructible and a composition root builds the whole registry without
/// allocating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialectEntry {
    /// Where this dialect keeps everything the loop asks about.
    pub locations: Dialect,
    /// This dialect's rungs of the detection ladder, in ascending rung order.
    ///
    /// Ascending is REQUIRED, not merely conventional: the merged walk takes the smallest unvisited
    /// rung from each source and stops scanning a source the moment it can no longer win, which is
    /// only sound for a source that is itself ordered. The dialect's own conformance battery
    /// asserts it.
    pub ladder: &'static [LadderClaim],
}

/// The dialects a boot registered into one plane, sealed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DialectRegistry {
    entries: &'static [DialectEntry],
}

impl DialectRegistry {
    /// A plane with no dialect registered.
    ///
    /// It is the honest state of a plane before its boot runs, and it is not an error: the plane
    /// still answers every question the loop asks, and its answer to "which dialect is this" is
    /// none — a refusal, rather than a guess at a vendor.
    pub const EMPTY: Self = Self::sealed(&[]);

    /// The registry a boot sealed.
    #[must_use]
    pub const fn sealed(entries: &'static [DialectEntry]) -> Self {
        Self { entries }
    }

    /// The registered entries, in registration order.
    #[must_use]
    pub const fn entries(&self) -> &'static [DialectEntry] {
        self.entries
    }
}

impl Default for DialectRegistry {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// The first claim of one ladder that matches, if it can beat what is already the best.
///
/// The ladder is ascending, so the moment a claim's rung is no longer better than the best found so
/// far, nothing further down this source can be either — which is what keeps the merged walk the
/// same cost as the single ordered walk it replaced.
fn best_of<'h>(
    ladder: &'static [LadderClaim],
    path: &str,
    header: &dyn Fn(&str) -> Option<&'h str>,
    best: &mut Option<&'static LadderClaim>,
) {
    for c in ladder {
        if let Some(b) = *best {
            if c.rung >= b.rung {
                return;
            }
        }
        if matches_selector(&c.claim.selector, path, header) {
            *best = Some(c);
            return;
        }
    }
}

impl LlmPlane {
    /// The dialects this plane was registered with.
    #[must_use]
    pub const fn dialects(&self) -> DialectRegistry {
        self.registry
    }

    /// One ladder source, by index: the plane's own first, then the registered entries in order.
    ///
    /// Source order is the tie-break for two claims on the same rung, and the plane's own claims
    /// come first for the reason declaration order always breaks a tie here — the plane is what the
    /// operator configured before any dialect was installed.
    fn ladder_source(&self, i: usize) -> &'static [LadderClaim] {
        if i == 0 {
            crate::claims::LADDER
        } else {
            self.registry.entries()[i - 1].ladder
        }
    }

    /// How many ladder sources this plane walks.
    fn ladder_sources(&self) -> usize {
        1 + self.registry.entries().len().min(MAX_REGISTERED_DIALECTS)
    }

    /// Where one dialect keeps what the loop asks about, by its key.
    ///
    /// The plane's own table first, then the registry. Both are searched because the split is
    /// staged: five of the six dialects have not been cut out yet, and a lookup that consulted only
    /// one of the two would answer for half the protocol.
    #[must_use]
    pub fn locations(&self, name: &str) -> Option<&'static Dialect> {
        if let Some(d) = crate::dialect::dialect(name) {
            return Some(d);
        }
        self.registry
            .entries()
            .iter()
            .find(|e| e.locations.name == name)
            .map(|e| &e.locations)
    }

    /// Every dialect this plane speaks, its own and its registered, in walk order.
    pub fn walk_dialects(&self, mut visit: impl FnMut(&'static Dialect)) {
        for d in crate::dialect::DIALECTS {
            visit(d);
        }
        for e in self.registry.entries().iter().take(MAX_REGISTERED_DIALECTS) {
            visit(&e.locations);
        }
    }

    /// The whole detection ladder — the plane's own rungs and every registered dialect's — as ONE
    /// ascending walk.
    ///
    /// A k-way merge over the sources, with one cursor per source on the stack. It is not a sort:
    /// a sort would need somewhere to put the result, and the one place a plane may not reach on a
    /// request's path is the heap.
    pub fn walk_ladder(&self, mut visit: impl FnMut(&'static LadderClaim)) {
        let sources = self.ladder_sources();
        let mut cursors = [0usize; 1 + MAX_REGISTERED_DIALECTS];
        loop {
            let mut best: Option<(usize, u16)> = None;
            for (i, cursor) in cursors.iter().enumerate().take(sources) {
                if let Some(c) = self.ladder_source(i).get(*cursor) {
                    if best.is_none_or(|(_, rung)| c.rung < rung) {
                        best = Some((i, c.rung));
                    }
                }
            }
            let Some((i, _)) = best else { return };
            visit(&self.ladder_source(i)[cursors[i]]);
            cursors[i] += 1;
        }
    }

    /// Which dialect a request's target and headers name, by the merged ladder in rung order.
    ///
    /// The answer is the LOWEST-numbered rung that matches, which is the same answer walking the
    /// merged ladder in order would give — reached without merging it, because this runs on the
    /// path a request takes and the merge would be a walk of every rung rather than of the ones
    /// that could still win.
    #[must_use]
    pub fn dialect_for<'h>(
        &self,
        path: &str,
        header: &dyn Fn(&str) -> Option<&'h str>,
    ) -> Option<&'static str> {
        let mut best: Option<&'static LadderClaim> = None;
        for i in 0..self.ladder_sources() {
            best_of(self.ladder_source(i), path, header, &mut best);
        }
        best.map(|c| c.dialect)
    }
}
