// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE — the "what may this caller SEE" walk and its judgement, defined inline HERE, in
//! core. It moved down into `busbar-substrate` in Phase-B B1 and was merged back by the W4.b P2
//! engine drain; this file is its only home, not a re-export of one elsewhere. It also hosts the
//! core-only catalogue tests, which name `crate::trust::validate::validate_visibility`.

// The catalogue serves whichever protocol planes are installed and nothing else; with none installed
// no in-core caller uses what it defines or imports, exactly as the pre-split module read dead
// there. Unconditional (the neutral seam names no plane feature — the items are public API whichever
// planes are compiled in).
#![allow(unused_imports)]
#![cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
#[cfg(test)]
#[path = "tests/catalogue_tests.rs"]
mod catalogue_tests;

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
use busbar_api::VirtualKey;

use crate::trust::validate::{Generations, Grant};

/// WHO IS ASKING, AND WHEN — the inputs the ordered gate's identity, expiry and generation steps
/// need, carried together.
///
/// One value rather than three arguments so a call site cannot pair this caller's key with another
/// request's clock or another apply's generation. Moved here from `a2a/catalogue.rs`, which had
/// written it for its own plane and stated exactly that reason; it is not a per-plane idea.
#[derive(Clone, Copy, Debug)]
pub struct Caller<'a> {
    /// `None` ONLY where governance is disabled and there is therefore no principal to carry a
    /// grant. It is not a way past the gate — [`crate::trust::validate`] states that posture once,
    /// for the whole tree, and this carries it rather than restating it.
    pub key: Option<&'a VirtualKey>,
    /// Seconds, for the key-expiry comparison. The caller's clock, so a test can move it.
    pub now: u64,
    /// The registry generation this ask is being judged under.
    // A2A-only field: the A2A catalogue walk consults it, the MCP one does not, so with `plane-a2a`
    // off (and MCP on) it is read nowhere.
    #[cfg_attr(not(feature = "relay"), allow(dead_code))]
    pub generation: Generations,
}

/// ONE KIND OF CATALOGUE ITEM. Implementing this is the ENTIRE cost of a new plane's catalogue: the
/// walk, the fail-closed floor, the entitlement-before-fitness ordering, the inventory order and the
/// render-after-filter rule are all inherited.
pub trait CatalogueItem {
    /// WHY an item is not in a caller's catalogue, in the plane's own words. Returned rather than
    /// merely filtered, because "why can this key not see the planner" is the question an operator
    /// actually asks, and a filter that only ever returns survivors cannot answer it.
    type Excluded;

    /// Everything the plane's structural fitness test needs beyond the item itself — a task shape, a
    /// delegating agent, `()` where there is nothing. NEVER caller-authored content: a catalogue
    /// that reads prose is a catalogue the upstream steers.
    type Query;

    /// What a SUCCESSFUL fitness test learned and the caller needs — the matched skill on A2A, `()`
    /// where fitness is a yes/no. Carried out of [`judge`] rather than recomputed, so the answer the
    /// caller acts on is the answer the filter reached.
    type Fit;

    /// THE WIRE FORM of one item. The plane owns the artifact: busbar publishes what the protocol
    /// defines, and core has no opinion about its shape.
    type Wire<'a>
    where
        Self: 'a;

    /// EVERY grant a principal must hold to SEE this item, pushed onto `out`. All of them,
    /// conjunctively — that is [`crate::trust::validate`]'s rule and not a second one here.
    ///
    /// Pushing NONE makes the item invisible rather than public — see the module header.
    fn required_grants<'g>(&'g self, query: &'g Self::Query, out: &mut Vec<Grant<'g>>);

    /// ASK THE ORDERED GATE, with the grants core has just collected.
    ///
    /// The plane chooses the ENTRY POINT and supplies the rest of the ask — its approval, its
    /// sighting, its fingerprint where it has one — because which question a catalogue is asking is
    /// a fact about the protocol. It does NOT choose an order, and it cannot evaluate a grant of its
    /// own: the grants arrive as a slice it can only pass on.
    fn admit(&self, caller: &Caller<'_>, grants: &[Grant<'_>]) -> Result<(), Self::Excluded>;

    /// STRUCTURAL FITNESS, applied only AFTER entitlement. An item the caller may not see is never
    /// fitness-tested, so a fitness test can never become a way to probe for what is hidden.
    fn fit(&self, query: &Self::Query) -> Result<Self::Fit, Self::Excluded>;

    /// The plane's refusal for "this item declares no grant at all", which is the fail-closed floor
    /// and never reaches the validator. One method rather than a shared arm, because a plane must be
    /// able to keep spelling its refusals the way its audit vocabulary already does.
    fn ungranted(&self) -> Self::Excluded;

    /// Render this item as its protocol carries it.
    fn render(&self) -> Self::Wire<'_>;
}

/// ONE ENTITLED ITEM: the item, and what its fitness test learned.
pub struct Entitled<'i, I: CatalogueItem> {
    pub item: &'i I,
    pub fit: I::Fit,
}

impl<I: CatalogueItem> Clone for Entitled<'_, I>
where
    I::Fit: Clone,
{
    fn clone(&self) -> Self {
        Entitled {
            item: self.item,
            fit: self.fit.clone(),
        }
    }
}

impl<I: CatalogueItem + std::fmt::Debug> std::fmt::Debug for Entitled<'_, I>
where
    I::Fit: std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entitled")
            .field("item", &self.item)
            .field("fit", &self.fit)
            .finish()
    }
}

impl<I: CatalogueItem + PartialEq> PartialEq for Entitled<'_, I>
where
    I::Fit: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.item == other.item && self.fit == other.fit
    }
}

/// JUDGE ONE ITEM for one caller. THE single place entitlement and fitness are sequenced, and the
/// order is load-bearing: GRANTS FIRST, then fitness.
///
/// The order is not a preference, and it is the same argument [`crate::trust::validate`] makes for
/// putting grant before artifact. Fitness reads the item's own content, and running it on an item
/// the caller may not see would make the REASON a caller is refused depend on what is inside
/// something it was never entitled to know exists — which is how a filter becomes an oracle.
pub fn judge<'i, I: CatalogueItem>(
    item: &'i I,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Result<Entitled<'i, I>, I::Excluded> {
    let mut grants: Vec<Grant<'_>> = Vec::new();
    item.required_grants(query, &mut grants);
    // THE FAIL-CLOSED FLOOR, and it is checked before the gate rather than by it: an EMPTY grant
    // list is honest at `validate_request`'s door (some asks legitimately need no grant) and is
    // never honest for an item in an inventory.
    if grants.is_empty() {
        return Err(item.ungranted());
    }
    item.admit(caller, &grants)?;
    let fit = item.fit(query)?;
    Ok(Entitled { item, fit })
}

/// THE CATALOGUE: walk an inventory, apply the caller's grants, keep the entitled subset.
///
/// ORDER IS THE INVENTORY'S, never re-sorted here. Both planes hand this an ordered inventory (a
/// `BTreeMap`'s values on MCP, config insertion order on A2A) precisely so an operator-facing
/// listing is deterministic rather than hash-ordered, and a re-sort here would take that away from
/// whichever plane got it right.
pub fn entitled<'i, I: CatalogueItem + 'i>(
    items: impl IntoIterator<Item = &'i I>,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Vec<Entitled<'i, I>> {
    items
        .into_iter()
        .filter_map(|i| judge(i, caller, query).ok())
        .collect()
}

/// The entitled subset as ITEMS — the same walk, for a caller that has no use for the fitness value.
// MCP-only helper: the MCP plane's catalogue calls this, the A2A plane renders differently, so with
// `plane-mcp` off (and A2A on) it has no caller.
#[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
pub fn visible<'i, I: CatalogueItem + 'i>(
    items: impl IntoIterator<Item = &'i I>,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Vec<&'i I> {
    entitled(items, caller, query)
        .into_iter()
        .map(|e| e.item)
        .collect()
}

/// The entitled subset AS THE WIRE CARRIES IT. Rendering happens after the filter and never before:
/// an item is rendered only once it has been decided the caller may see it, so no rendering path can
/// be the one that leaks.
pub fn rendered<'i, I: CatalogueItem + 'i>(
    items: impl IntoIterator<Item = &'i I>,
    caller: &Caller<'_>,
    query: &I::Query,
) -> Vec<I::Wire<'i>> {
    entitled(items, caller, query)
        .into_iter()
        .map(|e| e.item.render())
        .collect()
}
