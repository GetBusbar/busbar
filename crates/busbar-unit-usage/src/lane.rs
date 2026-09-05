// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The three-way lane cross-check.
//!
//! Three independent things claim to know which lane served a unit: the lane the admission facts
//! located, the lane the verified destination actually was, and the lane the response said it was.
//! They are compared over the legs the plane DECLARES; a leg the plane never declares is simply not
//! compared, and a leg the plane declares but does not produce is a dispute.
//!
//! The request-side leg is a membership test, not an equality: a caller may name a POOL, and the
//! pool expands to its member lanes, so serving any member of the named pool agrees with the name.
//! The other two legs are equalities.

use std::collections::BTreeSet;

use crate::evidence::MeterPolicy;

/// The lane name each leg saw, where it saw one.
// contract: the admission facts, the verified destination's lane and the response's content facts
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LaneLegs {
    /// The name the admission facts located — which may be a pool name.
    pub admit_locator: Option<String>,
    /// The lane the verified destination actually was.
    pub verified: Option<String>,
    /// The lane the response's own facts named.
    pub response: Option<String>,
}

/// Which legs the plane declares it produces. A leg absent by declaration is skipped; a declared
/// leg absent at runtime is a dispute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LegDeclaration {
    /// The plane declares it locates a lane name at admission.
    pub admit_locator: bool,
    /// The plane declares its verified destination names a lane.
    pub verified: bool,
    /// The plane declares its response facts name a lane.
    pub response: bool,
}

impl Default for LegDeclaration {
    fn default() -> Self {
        LegDeclaration {
            admit_locator: true,
            verified: true,
            response: true,
        }
    }
}

/// What the cross-check concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaneCheck {
    /// The lane the posting is priced against.
    pub lane: Option<String>,
    /// Whether the legs disagreed, or a declared leg never arrived.
    pub disputed: bool,
}

/// Compare the legs the plane declares and decide which lane the posting prices against.
///
/// On agreement the verified lane is the answer — it is the one the unit actually reached. On
/// disagreement the answer is the CHEAPER of the candidate lanes and the posting is disputed:
/// posting the lower figure is the same rule the rest of the settlement follows, so a plane cannot
/// profit from a mismatch it caused.
pub fn cross_check_lane(
    legs: &LaneLegs,
    declared: &LegDeclaration,
    policy: &MeterPolicy,
) -> LaneCheck {
    let mut disputed = false;
    let mut candidates: BTreeSet<String> = BTreeSet::new();

    // A declared leg that produced nothing is itself a dispute: the plane said it would name a lane
    // and did not, so there is one fewer check standing between a wrong lane and an invoice.
    if declared.admit_locator && legs.admit_locator.is_none() {
        disputed = true;
    }
    if declared.verified && legs.verified.is_none() {
        disputed = true;
    }
    if declared.response && legs.response.is_none() {
        disputed = true;
    }

    if let Some(v) = legs.verified.as_deref() {
        candidates.insert(v.to_string());
    }
    if let Some(r) = legs.response.as_deref() {
        candidates.insert(r.to_string());
    }

    // The request-side leg is SET MEMBERSHIP: the lane actually served must be one of the lanes the
    // located name stands for, so naming a pool never mismatches its own member.
    if declared.admit_locator && declared.verified {
        if let (Some(named), Some(served)) =
            (legs.admit_locator.as_deref(), legs.verified.as_deref())
        {
            if !policy.expansion_of(named).contains(served) {
                disputed = true;
                for lane in policy.expansion_of(named) {
                    candidates.insert(lane.to_string());
                }
            }
        }
    }

    // The response-side leg is an equality against the lane that was actually reached.
    if declared.response && declared.verified {
        if let (Some(said), Some(served)) = (legs.response.as_deref(), legs.verified.as_deref()) {
            if said != served {
                disputed = true;
            }
        }
    }

    let lane = if disputed {
        // The cheaper entry, with the lane name itself as the tie-break so the answer is stable.
        candidates
            .into_iter()
            .min_by(|a, b| {
                policy
                    .price_of(a)
                    .cmp(&policy.price_of(b))
                    .then_with(|| a.cmp(b))
            })
            .or_else(|| legs.verified.clone())
    } else {
        legs.verified.clone().or_else(|| legs.response.clone())
    };

    LaneCheck { lane, disputed }
}
