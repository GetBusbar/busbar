// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MAY THIS COUNTERPARTY BE DEALT WITH? — the fold from asserted facts to one closed verdict.
//!
//! This is the same question [`crate::destination`] asks about a place, asked about the party at
//! the other end of it, and it is asked here for the same reason: it is the verify step's, it is
//! asked once, and it is asked before anything is charged.
//!
//! ## The order is the answer
//!
//! Identity, then grant, then registration, then artifact, then generation. The order is not
//! stylistic and it is not an optimisation — it is WHICH REFUSAL AN OPERATOR IS SHOWN when more
//! than one thing is wrong at once. A counterparty whose principal was deleted AND whose artifact
//! moved is an identity refusal, because re-establishing the artifact would fix nothing; reading
//! the two in the other order sends the operator to work the wrong remedy. So the fold
//! short-circuits at the first step that refuses, and the step it stopped at IS the verdict
//! ([`Verdict::IdentityNotLive`] rather than a bare [`Verdict::Denied`]).
//!
//! ## Standing is a CEILING, never a floor
//!
//! [`evaluate`] takes two things that are not symmetric. The STANDING is what the side keeping the
//! books already holds — the durable disposition an earlier observation settled. The FACTS are what
//! the side that just looked ASSERTS. Facts may only NARROW a standing that already allows; they
//! can never widen a standing that refuses.
//!
//! Without that asymmetry the assertion is a permission: a counterparty the books demoted on drift
//! would assert `registration: Approved` about itself, the fold would believe it, and the durable
//! quarantine would be undone by the very party it was recorded against. So a standing that is not
//! [`Verdict::Allow`] is returned unchanged and the facts are not read at all, and a standing that
//! IS `Allow` is handed to the fold, which can only take it down.
//!
//! ## No facts is not the same as facts that pass
//!
//! An asserting side that wrote nothing is answered with the standing alone. That is deliberate and
//! it is the only safe reading: absent facts are not passing facts (which would let a silent caller
//! skip every step), and they are not failing facts either (which would refuse every caller that
//! has nothing to add). What is known is the standing, so what is answered is the standing.

use busbar_contract::counterparty::{
    Artifact, CounterpartyFacts, Grant, Liveness, RegistrationState, Verdict,
};

/// FOLD asserted facts into a verdict, in the order stated in this module's header, stopping at the
/// first step that refuses so the verdict names that step.
///
/// [`Liveness::NoPrincipal`] passes this step: an honestly ungoverned deployment has no principal
/// to be live, and the steps below still run.
#[must_use]
pub fn fold(facts: &CounterpartyFacts) -> Verdict {
    // 1. IDENTITY.
    if facts.liveness == Liveness::NotLive {
        return Verdict::IdentityNotLive;
    }
    // 2. GRANT — the asker's own reach, then the target's list of who may reach it.
    match facts.grant {
        Grant::NotGranted => return Verdict::NotGranted,
        Grant::EgressDenied => return Verdict::EgressDenied,
        Grant::Held => {}
    }
    // 3a. REGISTRATION — only `Approved` serves; each other state names its own remedy, and an
    // unreadable register is refused rather than guessed at.
    match facts.registration {
        RegistrationState::Approved => {}
        RegistrationState::Quarantined | RegistrationState::Failed => return Verdict::Quarantined,
        RegistrationState::Pending => return Verdict::NeedsApproval,
        RegistrationState::Suspended | RegistrationState::Unknown => return Verdict::Denied,
    }
    // 3b. ARTIFACT — an artifact that moved and an artifact nobody could read are one refusal:
    // neither is evidence that what is offered is what was approved.
    match facts.artifact {
        Artifact::Drifted | Artifact::Unobservable => return Verdict::ArtifactDrifted,
        Artifact::NotAsked | Artifact::Serves => {}
    }
    // 4. GENERATION — the snapshot admitted under is the snapshot in force, or the ask is stale.
    if facts.generation_admitted != facts.generation_live {
        return Verdict::GenerationMoved;
    }
    Verdict::Allow
}

/// THE ONE COUNTERPARTY DECISION: the books' `standing` narrowed — never widened — by what the
/// asserting side wrote.
///
/// A `standing` other than [`Verdict::Allow`] is the whole answer and the facts are not read. A
/// standing of `Allow` with no facts is likewise the whole answer. Only an allowing standing WITH
/// facts reaches [`fold`], which can take it down to a specific refusal and can never take it up.
#[must_use]
pub fn evaluate(standing: Verdict, asserted: Option<&CounterpartyFacts>) -> Verdict {
    match (standing, asserted) {
        (Verdict::Allow, Some(facts)) => fold(facts),
        (standing, _) => standing,
    }
}
