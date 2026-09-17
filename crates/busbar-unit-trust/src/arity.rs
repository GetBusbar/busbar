// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ARITY POSTURE — how many destinations a step is allowed to resolve to, and what it does when the
//! count is wrong.
//!
//! The verify step narrows a proposed set of candidates down to what a caller may reach; a separate
//! question is how many the OPERATION permits. A message addressed to one named agent may resolve to
//! exactly one or it has not resolved at all — two agents matching is not "pick either", it is an
//! ambiguous request the caller has to disambiguate — while a submission to a pool of
//! interchangeable members is content with any non-empty set and lets the pick choose among them.
//! Those are the two postures ([`Arity`]), and stating them as data rather than as scattered
//! `if candidates.len() == 1` checks means a new caller decides its posture in one place and inherits
//! the refusal shapes.
//!
//! ## The ambiguous refusal carries the candidates
//!
//! An [`Arity::ExactlyOne`] resolve that finds several candidates refuses with the whole surviving
//! set in hand ([`ArityRefusal::Ambiguous`]), not a bare count. This is the "exactly-one-agent-or-
//! refuse-503" decision the A2A catalogue's select needs: a caller told only "ambiguous" cannot say
//! which agents it was ambiguous BETWEEN, and an operator diagnosing it cannot either. The candidate
//! set is the plane's own — this seat is generic over what a candidate IS ([`select`]'s `T`) — so a
//! plane keeps its own item type all the way through the refusal and renders it in its own words.
//!
//! ## Why the empty case and the ambiguous case are different refusals
//!
//! Both stop the step, but they are not the same fault: an empty set is "nothing you may reach can
//! serve this" ([`ArityRefusal::NoCandidate`]) and an over-full one under `ExactlyOne` is "you named
//! something that resolves to more than one" ([`ArityRefusal::Ambiguous`]). They carry different
//! diagnoses and, on a plane that renders them, can carry different statuses, so collapsing them into
//! one "could not select" would make two distinct caller mistakes indistinguishable.

use busbar_caps::ReasonCode;

/// HOW MANY destinations the operation permits the step to resolve to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arity {
    /// Exactly one, or refuse. Zero is [`ArityRefusal::NoCandidate`]; more than one is
    /// [`ArityRefusal::Ambiguous`], carrying the set it could not choose between. This is the
    /// posture a message addressed to a single named agent selects under.
    ExactlyOne,
    /// Any non-empty set, handed on for the pick to choose among. Zero is still
    /// [`ArityRefusal::NoCandidate`]; any count from one up is [`Selection::Choose`]. This is the
    /// posture a submission to a pool of interchangeable members selects under — the arity seat does
    /// not itself pick, it only confirms there is something to pick from.
    ChooseOne,
}

/// WHAT THE ARITY SEAT RESOLVED TO — one destination, or a set to choose among.
///
/// [`Arity::ExactlyOne`] always yields [`Selection::One`] (or refuses); [`Arity::ChooseOne`] always
/// yields [`Selection::Choose`] (or refuses), even for a single candidate — a pool of one is still
/// reached down the pick path, so the caller acts on one shape regardless of count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection<T> {
    /// A single destination the caller acts on directly.
    One(T),
    /// A non-empty set the pick chooses among. Never empty: the empty case is a refusal.
    Choose(Vec<T>),
}

/// WHY THE ARITY SEAT COULD NOT RESOLVE — kept as two distinct faults, never one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArityRefusal<T> {
    /// No candidate survived to select from. Nothing the caller may reach can serve this step.
    NoCandidate,
    /// Under [`Arity::ExactlyOne`], more than one candidate survived — the request has to be
    /// disambiguated. Carries the whole ambiguous set, in the plane's own candidate type, so the
    /// refusal can say which destinations it was ambiguous between.
    Ambiguous {
        /// Every candidate that survived to the tie — the set the caller must choose one of.
        candidates: Vec<T>,
    },
}

impl<T> ArityRefusal<T> {
    /// The closed-vocabulary reason this refusal is recorded under.
    ///
    /// Both map to [`ReasonCode::NoDestination`]: the kernel's vocabulary has one word for "no
    /// single destination resolved", and that is honest for an empty set AND for an ambiguous one
    /// (neither produced the single destination the step needed). The DISTINCTION an operator acts
    /// on — none versus several — lives in the variant and, for the ambiguous case, in the carried
    /// candidate set, not in a second reason word.
    #[must_use]
    pub fn reason(&self) -> ReasonCode {
        ReasonCode::NoDestination
    }
}

/// SELECT among candidates under a posture.
///
/// Generic over the candidate type so a plane carries its own item — an agent registration, a
/// destination, whatever it proposed — straight through both the [`Selection`] and, on the ambiguous
/// path, the [`ArityRefusal`]. The candidates arrive in the order the caller offered them; ties under
/// [`Arity::ExactlyOne`] are never broken here, because "pick the first of several" is exactly the
/// silent behaviour the ambiguous refusal exists to prevent.
///
/// # Errors
///
/// [`ArityRefusal::NoCandidate`] when `candidates` is empty, under either posture;
/// [`ArityRefusal::Ambiguous`] when more than one candidate is offered under [`Arity::ExactlyOne`].
pub fn select<T>(posture: Arity, candidates: Vec<T>) -> Result<Selection<T>, ArityRefusal<T>> {
    if candidates.is_empty() {
        return Err(ArityRefusal::NoCandidate);
    }
    match posture {
        Arity::ExactlyOne => {
            if candidates.len() == 1 {
                // The one that survived. `into_iter().next()` rather than indexing so the value is
                // moved out rather than requiring `T: Clone`.
                Ok(Selection::One(
                    candidates
                        .into_iter()
                        .next()
                        .expect("length checked to be exactly one"),
                ))
            } else {
                Err(ArityRefusal::Ambiguous { candidates })
            }
        }
        Arity::ChooseOne => Ok(Selection::Choose(candidates)),
    }
}
