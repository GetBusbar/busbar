// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CATALOGUE — one mechanism, in core, for "what may this caller SEE".
//!
//! ## Why this is core and not a plane's
//!
//! Owner's rule: *"core needs to be the core. if its used 2x or could be, its core."* A catalogue
//! answers the inventory question — which tools (MCP), which agents (A2A), which anything a
//! principal is entitled to be told exists. That is a DATA-EXPOSURE surface, not a convenience one,
//! and it was written once per plane: `mcp/catalogue.rs` walked a snapshot ANDing two grants of its
//! own, `a2a/catalogue.rs` walked a registration list and rendered its survivors at the call site.
//! Two implementations of "who may see what" agree right up until they do not, one plane gains a
//! filter the other never gets, and the divergence fails OPEN.
//!
//! So there is ONE walk ([`entitled`]) and ONE judgement ([`judge`]), and they live here. A plane
//! supplies the ITEM; it never supplies the mechanism. [`crate::trust`] is the precedent this copies
//! rather than a new idea — core owns the lifecycle, the plane owns the artifact — and
//! [`crate::audit`] is the same seam for evidence.
//!
//! ## THE ENTITLEMENT DECISION IS NOT THIS MODULE'S EITHER
//!
//! `identity -> grant` already has an owner: [`crate::trust::validate`]. This module does not
//! re-implement it, re-order it or wrap a second grant evaluator around it — it collects the grants
//! an item declares and hands them over. A catalogue that evaluated its own grants would be the
//! defect the ordered validator was written to end, re-opened from the inventory side.
//!
//! What each plane still says for itself is WHICH QUESTION ITS CATALOGUE IS ASKING, and it says it
//! by which entry point its [`CatalogueItem::admit`] calls:
//!
//! | plane | asks | because |
//! |---|---|---|
//! | MCP | [`crate::trust::validate::validate_visibility`] — identity, grant | the MCP catalogue LISTS what it will not dispatch, so an operator can see the approval queue; hiding a pending entry makes the queue invisible |
//! | A2A | [`crate::trust::validate::validate_request`] — identity, grant, artifact, generation | on this plane a listing IS an admission: an agent that is not `Approved` is not a candidate, and an A2A agent is not fungible |
//!
//! That difference is a fact about the two protocols, written down at two call sites, rather than a
//! step some shared function decided to skip.
//!
//! ## ONE MECHANISM IS NOT ONE INVENTORY
//!
//! Unifying the walk must not widen what anybody can see, and it does not: an item declares its own
//! grant requirement in the ONE grant vocabulary ([`crate::trust::validate::Grant`]), and nothing
//! here names a scope kind. An MCP tool still needs `mcp_server` AND `mcp_tool`; an A2A
//! registration still needs `agent`. Nothing here can grant what a plane did not ask for.
//!
//! ## THE FAIL-CLOSED FLOOR: silence is not universal visibility
//!
//! An item that declares NO grant is INVISIBLE, not public. That is the one rule the mechanism adds
//! rather than inherits, and it is a rule about INVENTORY ITEMS specifically — the validator's empty
//! grant list is honest for an ask addressed to something that needs no grant, and an item in an
//! inventory is never that. A third plane whose author forgets `required_grants` gets an empty
//! catalogue, which is a bug report, rather than a full one, which is a breach.
//! `an_item_that_declares_no_grant_is_invisible_not_public` pins it.
//!
//! ## CATALOGUE IS NOT DISPATCH, and hooks run on the other one
//!
//! Nothing here is a hook, a score, or a read of caller-authored prose. What a caller may SEE stays
//! a question answered by its key grants alone; whether a call may GO is dispatch's, and dispatch is
//! where hooks run. This module takes no hook registry, no scores and no content — it cannot consult
//! them, because it is not given them.
//!
//! ## WHAT A PLANE STILL OWNS
//!
//! Four things, and they are the entire cost of a new plane:
//!
//! | the plane supplies | why it cannot be core's |
//! |---|---|
//! | [`CatalogueItem::required_grants`] | the scope KINDS are the plane's vocabulary |
//! | [`CatalogueItem::admit`] | which question this plane's catalogue is asking (see the table above) |
//! | [`CatalogueItem::fit`] + [`CatalogueItem::Excluded`] | structural fitness and its refusal words differ per plane |
//! | [`CatalogueItem::render`] | the WIRE form is the protocol's, and busbar publishes it verbatim |
//!
//! ADDING A THIRD PLANE COSTS AN ITEM TYPE AND NOTHING ELSE. That is the acceptance test for this
//! seam, and `tests/catalogue_tests.rs` declares an item type for a plane busbar does not have and
//! enumerates, filters and renders it with no catalogue module, no walk, no filter and no error type
//! written for it.

// This module is shared plane infrastructure: every item below serves the MCP and/or A2A plane and
// nothing else. With BOTH planes compiled out (`--no-default-features`) the whole catalogue is
// vestigial, so its items read dead — scoped to exactly that config so `-D warnings` stays clean
// there while a real single-plane build still lints every item its plane leaves unused (those carry
// their own per-plane attrs below).
#![cfg_attr(
    not(any(feature = "plane-mcp", feature = "plane-a2a")),
    allow(dead_code)
)]

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
    #[cfg_attr(not(feature = "plane-a2a"), allow(dead_code))]
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
#[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
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
