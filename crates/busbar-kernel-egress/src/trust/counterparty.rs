// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! COUNTERPARTY-ADMIT — the ordered gate a catalogue's `admit` runs, as a unit.
//!
//! A catalogue answers "what may this caller SEE", and on a plane where a listing IS an admission —
//! A2A, where an agent that is not approved is not a candidate — the SEE question is decided by the
//! ordered gate this seat is. The catalogue mechanism (in the substrate) collects the grants an item
//! declares and calls the item's `admit`; that `admit`, on the A2A plane, is THIS: identity, then
//! grant, then artifact, then generation, in that one order, refusing at the first that fails and
//! naming which.
//!
//! ## Why the order is fixed and is not a preference
//!
//! Each check reads more than the last, and a later one must never become a way to probe past an
//! earlier one. Grant is asked before the counterparty's approval so that "does this agent exist for
//! me" cannot be answered by whether an approval lookup succeeded for a caller that holds no grant to
//! ask; generation is asked last so a sighting is only judged current once it is a sighting the
//! caller was entitled to have at all. That is the same argument the substrate catalogue makes for
//! grant-before-fitness, carried into the admit gate itself.
//!
//! ## Why the facts are carried together
//!
//! [`CounterpartyFacts`] bundles the caller's contribution (identity, grant) and the counterparty's
//! (approval, generation sighting) into one value rather than four arguments, for the reason the
//! catalogue's own `Caller` is bundled: a call site that assembled them separately could pair this
//! counterparty's approval with another caller's identity, or this apply's generation with an earlier
//! request's, and the gate would be judging a request that never existed.
//!
//! ## What this seat is NOT
//!
//! It is not dispatch. Whether a call may GO — hooks, scores, content — is the other step's, and
//! nothing here reads any of them. A suspended counterparty is refused here only because a suspension
//! withdraws its approval (it is no longer an [`admitted`](CounterpartyFacts::approved) artifact),
//! not because this seat scored its behaviour.

use busbar_contract::caps::ReasonCode;

/// Everything the counterparty-admit gate reads, carried together.
///
/// The four booleans are the four ordered checks. Two are the caller's contribution and two are the
/// counterparty's; they travel in one value so a call site cannot cross a caller with a counterparty
/// (see the module header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CounterpartyFacts {
    /// IDENTITY — the caller presents a principal that is authenticated, unexpired and unrevoked.
    /// `false` is [`CounterpartyRefusal::Unidentified`], the first and coarsest refusal: a request
    /// with no valid principal is refused before anything about the counterparty is read.
    pub identified: bool,
    /// GRANT — the caller holds every grant the counterparty's catalogue item declared it needs.
    /// Asked after identity and before the counterparty's own facts, so an ungranted caller learns
    /// nothing about whether the counterparty exists or is approved.
    pub granted: bool,
    /// ARTIFACT — the counterparty is an APPROVED registration. A pending, rejected or suspended
    /// counterparty is not an admissible artifact and is not a candidate; a suspension is exactly a
    /// withdrawal of this, which is why a suspended counterparty is refused here.
    pub approved: bool,
    /// GENERATION — the counterparty was sighted at the CURRENT registry generation, not an earlier
    /// apply's. Asked last: a sighting is only judged current once the caller was entitled to have it
    /// at all.
    pub current_generation: bool,
}

impl CounterpartyFacts {
    /// A counterparty that passes every check — the fixture callers narrow from.
    #[must_use]
    pub fn admissible() -> Self {
        CounterpartyFacts {
            identified: true,
            granted: true,
            approved: true,
            current_generation: true,
        }
    }
}

/// WHY the counterparty-admit gate refused — the first failing check, in the gate's own order.
///
/// Returned rather than a bare `false`, because "why can this caller not see this agent" is the
/// question an operator actually asks, and the ANSWER is which of the four ordered checks closed. The
/// variants are in the order the gate checks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterpartyRefusal {
    /// The caller presented no valid principal — refused before any counterparty fact was read.
    Unidentified,
    /// The caller holds no grant to reach this counterparty.
    Ungranted,
    /// The counterparty is not an approved artifact (pending, rejected or suspended).
    NotApproved,
    /// The counterparty's sighting is behind the current registry generation — a later apply
    /// superseded it.
    StaleGeneration,
}

impl CounterpartyRefusal {
    /// The closed-vocabulary reason this refusal is recorded under, so a counterparty refused here
    /// and a unit stopped for the same cause elsewhere in the loop name the same thing.
    ///
    /// - [`Unidentified`](Self::Unidentified) → [`ReasonCode::Unauthenticated`]: no principal
    ///   resolved.
    /// - [`Ungranted`](Self::Ungranted) → [`ReasonCode::ScopeDenied`]: the caller lacks the grant.
    /// - [`NotApproved`](Self::NotApproved) → [`ReasonCode::NoDestination`]: the counterparty is not
    ///   a candidate at all.
    /// - [`StaleGeneration`](Self::StaleGeneration) → [`ReasonCode::Superseded`]: a later apply
    ///   superseded the sighting.
    #[must_use]
    pub fn reason(self) -> ReasonCode {
        match self {
            CounterpartyRefusal::Unidentified => ReasonCode::Unauthenticated,
            CounterpartyRefusal::Ungranted => ReasonCode::ScopeDenied,
            CounterpartyRefusal::NotApproved => ReasonCode::NoDestination,
            CounterpartyRefusal::StaleGeneration => ReasonCode::Superseded,
        }
    }
}

/// ADMIT a counterparty for a caller — the ordered gate the catalogue's `admit` is served by.
///
/// The checks run in the ONE order [`CounterpartyFacts`]' fields document, and the FIRST that fails
/// is the refusal returned; no later check is consulted once an earlier one has closed, so the reason
/// a caller reads is stable and never depends on a check that a coarser one already made unreachable.
///
/// # Errors
///
/// The first failing check, as a [`CounterpartyRefusal`].
pub fn admit(facts: &CounterpartyFacts) -> Result<(), CounterpartyRefusal> {
    if !facts.identified {
        return Err(CounterpartyRefusal::Unidentified);
    }
    if !facts.granted {
        return Err(CounterpartyRefusal::Ungranted);
    }
    if !facts.approved {
        return Err(CounterpartyRefusal::NotApproved);
    }
    if !facts.current_generation {
        return Err(CounterpartyRefusal::StaleGeneration);
    }
    Ok(())
}
