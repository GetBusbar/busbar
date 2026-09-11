// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ONE RESOLVER, for every plane's leg bindings.
//!
//! ## The rule this file exists to keep
//!
//! Every plane is identical. A node resolves its units ONCE at boot — the auth chain, the arrival
//! door, the pricer, the metering policy, the book, the sealed origin — and each mounted plane adds
//! its own DECLARATION: the record legs its route plans reach, and the scope policy its operation
//! classes are judged under. A leg's bindings are those two halves put together, and putting them
//! together is one function, not one function per plane.
//!
//! The alternative is what the tree had: each plane's leg file carrying its own assembly, and the
//! only thing keeping five assemblies in step being that somebody remembered. The first thing to go
//! wrong with that is not a crash — it is one plane quietly built over a second door, or a second
//! book, and a node whose figures are two sets of figures that agreed on the day they were written.
//!
//! ## Keyed, never conditioned
//!
//! [`resolve_bindings`] takes a PLANE KEY and looks it up. There is no `match` on a plane's name
//! here and there cannot be one: what differs between two planes is DATA the node was handed when
//! the plane was mounted, and a plane this node did not mount resolves to nothing rather than to a
//! default. That is what makes adding a plane a mounting rather than an edit, and it is why the
//! same call serves a2a: a2a's twenty-three fields and mcp's eighteen share exactly the nine below
//! — `auth`, `auth_bindings`, `door`, `pricer`, `records`, `meter_policy`, `scope_policy`,
//! `durability`, `origin` — under the same names, resolved at the same moment, from the same node.
//!
//! ## What is NOT here, and why each absence is a decision
//!
//! The per-request half is not resolved here and must not be: the caller's bucket chain, the pool
//! the request named, the views a caller's key scopes produce, and the unit's two pinned clocks are
//! facts about ONE request. A binding assembled per unit would be a node whose answers depend on
//! which request asked; a per-request fact resolved at boot would be a node answering every caller
//! with the first caller's facts. Both are worse than the split.
//!
//! The money is not here either. What a class costs and what a request's flat fee is are the rate
//! card's, and the card has one reader.

use std::collections::BTreeMap;
use std::sync::Mutex;

use busbar_unit_admission::{Door, InMemoryCells, Pricer};
use busbar_unit_auth::Auth;

use crate::root::store::PlaneRecords;

/// ONE PLANE'S DECLARATION, as a node holds it after mounting that plane.
///
/// Both halves are the plane's own data rather than the root's reading of it: the record legs are
/// bound to the plane's declaration table (which schema carries which operation), and the scope
/// policy is the one the plane's operation classes were folded onto. A root that decided either
/// would be a root deciding what a plane declares.
pub struct MountedPlane {
    /// This plane's record legs, over the node's one store.
    pub records: PlaneRecords,
    /// What the scope unit reads at approve for this plane's classes.
    pub scope_policy: crate::root::policy::ScopePolicy,
}

/// THE NODE: the units every plane's leg is answered by, plus one entry per plane it mounted.
///
/// One of each unit and one book, which is the property the whole thing rests on — an entry added
/// here does not get a door of its own, and cannot. The planes are a map keyed by the plane's own
/// key, so what "this node serves mcp and a2a" means is that the map has two entries, and nothing
/// anywhere reads a plane's name to find out.
pub struct Node {
    /// The authentication chain, as configuration resolved it.
    pub auth: Auth,
    /// The node's one set of authentication seams — the credential cache and the revocation view.
    pub auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
    /// The admission unit's long-lived door.
    pub door: Door<InMemoryCells>,
    /// What the door prices a unit against.
    pub pricer: Pricer,
    /// What the usage unit folds against.
    pub meter_policy: crate::root::policy::MeterPolicyHandle,
    /// The journal, the ledger and the two audit chains. THE PROCESS'S ONE BOOK.
    pub durability: Mutex<crate::root::durability::Durability>,
    /// The sealed origin an audit record is written under.
    pub origin: busbar_caps::Origin,
    /// One entry per mounted plane, keyed the way the registry keys it.
    planes: BTreeMap<&'static str, MountedPlane>,
}

impl Node {
    /// Mount one plane on this node, under its own key.
    ///
    /// Takes and returns the node so a boot reads as the list of planes it mounted. A key mounted
    /// twice REPLACES, because two declarations under one key is two answers to what that plane
    /// declares and the later one is the one the operator meant.
    #[must_use]
    pub fn mounting(mut self, plane_key: &'static str, plane: MountedPlane) -> Self {
        self.planes.insert(plane_key, plane);
        self
    }

    /// Assemble a node over units somebody else resolved.
    ///
    /// Every argument is one decision configuration made, which is the shape that makes it
    /// impossible to build a node and forget one. Nothing here is expensive and nothing here is
    /// work: the chain is already resolved, the cells are already hydrated, the book is already
    /// open.
    #[must_use]
    pub fn over(
        auth: Auth,
        auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
        door: Door<InMemoryCells>,
        pricer: Pricer,
        meter_policy: crate::root::policy::MeterPolicyHandle,
        durability: Mutex<crate::root::durability::Durability>,
        origin: busbar_caps::Origin,
    ) -> Self {
        Node {
            auth,
            auth_bindings,
            door,
            pricer,
            meter_policy,
            durability,
            origin,
            planes: BTreeMap::new(),
        }
    }

    /// Which planes this node mounted, in key order.
    #[must_use]
    pub fn mounted(&self) -> Vec<&'static str> {
        self.planes.keys().copied().collect()
    }
}

/// THE BOOT-RESOLVED HALF of one plane's leg bindings — the nine every plane's leg has.
///
/// Borrowed, every one of them, and borrowed from the node: what a leg is driven over is the node's
/// instance and never a copy of it. A field here that was owned would be a plane holding its own
/// door or its own book, which is the defect the one-resolver rule exists to make unspellable.
pub struct LegBindings<'r> {
    /// The authentication chain, as configuration resolved it.
    pub auth: &'r Auth,
    /// The node's one set of authentication seams.
    pub auth_bindings: &'r crate::root::kernel::auth_bindings::AuthBindings,
    /// The admission unit's long-lived door.
    pub door: &'r Door<InMemoryCells>,
    /// What the door prices a unit against.
    pub pricer: &'r Pricer,
    /// THIS PLANE'S record legs, over the node's one store.
    pub records: &'r PlaneRecords,
    /// What the usage unit folds against.
    pub meter_policy: &'r crate::root::policy::MeterPolicyHandle,
    /// What the scope unit reads at approve, for THIS PLANE's classes.
    pub scope_policy: &'r crate::root::policy::ScopePolicy,
    /// The journal, the ledger and the two audit chains.
    pub durability: &'r Mutex<crate::root::durability::Durability>,
    /// The sealed origin the audit record is written under.
    pub origin: busbar_caps::Origin,
}

/// **THE ONE RESOLVER.** Everything one plane's leg is bound to that boot can resolve.
///
/// Seven of the nine come off the node and are the SAME value for every plane on it; two come off
/// the plane's own declaration and are that plane's. The lookup is the whole of the difference
/// between two planes, which is what "every plane is identical" means when it is written down
/// rather than asserted.
///
/// `None` is a plane this node did not mount. It is an absence and not an empty binding, because a
/// leg driven over a default door is a leg that admits and charges against something the operator
/// never configured — and it would look like it worked.
#[must_use]
pub fn resolve_bindings<'r>(plane_key: &str, node: &'r Node) -> Option<LegBindings<'r>> {
    let plane = node.planes.get(plane_key)?;
    Some(LegBindings {
        auth: &node.auth,
        auth_bindings: &node.auth_bindings,
        door: &node.door,
        pricer: &node.pricer,
        records: &plane.records,
        meter_policy: &node.meter_policy,
        scope_policy: &plane.scope_policy,
        durability: &node.durability,
        origin: node.origin,
    })
}

#[cfg(test)]
#[path = "tests/bindings.rs"]
mod tests;
