// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The counterparty fold: the ORDER, and the rule that an assertion may only narrow.

use crate::counterparty::{evaluate, fold};
use busbar_contract::counterparty::{
    Artifact, CounterpartyFacts, Grant, Liveness, RegistrationState, Verdict,
};

/// Facts that pass every step, so a single field can be moved at a time and the verdict read.
fn passing() -> CounterpartyFacts {
    CounterpartyFacts {
        liveness: Liveness::Live,
        grant: Grant::Held,
        registration: RegistrationState::Approved,
        artifact: Artifact::Serves,
        generation_admitted: 5,
        generation_live: 5,
    }
}

/// Fold `passing()` with one field moved, so a step is read in isolation.
fn moving(mutate: impl FnOnce(&mut CounterpartyFacts)) -> Verdict {
    let mut facts = passing();
    mutate(&mut facts);
    fold(&facts)
}

/// Every refusal keeps the STEP that produced it, rather than collapsing to `Denied`.
#[test]
fn each_step_answers_with_its_own_verdict() {
    assert_eq!(fold(&passing()), Verdict::Allow);

    assert_eq!(
        moving(|f| f.liveness = Liveness::NotLive),
        Verdict::IdentityNotLive
    );
    assert_eq!(moving(|f| f.grant = Grant::NotGranted), Verdict::NotGranted);
    assert_eq!(
        moving(|f| f.grant = Grant::EgressDenied),
        Verdict::EgressDenied
    );
    assert_eq!(
        moving(|f| f.registration = RegistrationState::Quarantined),
        Verdict::Quarantined
    );
    assert_eq!(
        moving(|f| f.registration = RegistrationState::Failed),
        Verdict::Quarantined
    );
    assert_eq!(
        moving(|f| f.registration = RegistrationState::Pending),
        Verdict::NeedsApproval
    );
    assert_eq!(
        moving(|f| f.registration = RegistrationState::Suspended),
        Verdict::Denied
    );
    assert_eq!(
        moving(|f| f.registration = RegistrationState::Unknown),
        Verdict::Denied
    );
    assert_eq!(
        moving(|f| f.artifact = Artifact::Drifted),
        Verdict::ArtifactDrifted
    );
    assert_eq!(
        moving(|f| f.artifact = Artifact::Unobservable),
        Verdict::ArtifactDrifted
    );
    assert_eq!(moving(|f| f.generation_live = 6), Verdict::GenerationMoved);
}

/// An honestly ungoverned deployment has no principal to be live, and that is not a refusal — nor
/// is it a way past the gate: the steps below it still run.
#[test]
fn no_principal_passes_identity_without_skipping_the_rest() {
    let mut facts = passing();
    facts.liveness = Liveness::NoPrincipal;
    assert_eq!(fold(&facts), Verdict::Allow);

    facts.registration = RegistrationState::Pending;
    assert_eq!(fold(&facts), Verdict::NeedsApproval);
}

/// THE ORDER IS THE ANSWER: with every step failing at once, the verdict is the FIRST step's, so
/// an operator is sent to the remedy that actually unblocks the counterparty.
#[test]
fn the_first_failing_step_is_the_verdict() {
    let all_bad = CounterpartyFacts {
        liveness: Liveness::NotLive,
        grant: Grant::NotGranted,
        registration: RegistrationState::Quarantined,
        artifact: Artifact::Drifted,
        generation_admitted: 1,
        generation_live: 2,
    };
    assert_eq!(fold(&all_bad), Verdict::IdentityNotLive);

    let mut from_grant = all_bad;
    from_grant.liveness = Liveness::Live;
    assert_eq!(fold(&from_grant), Verdict::NotGranted);

    let mut from_registration = from_grant;
    from_registration.grant = Grant::Held;
    assert_eq!(fold(&from_registration), Verdict::Quarantined);

    let mut from_artifact = from_registration;
    from_artifact.registration = RegistrationState::Approved;
    assert_eq!(fold(&from_artifact), Verdict::ArtifactDrifted);

    let mut from_generation = from_artifact;
    from_generation.artifact = Artifact::Serves;
    assert_eq!(fold(&from_generation), Verdict::GenerationMoved);
}

/// STANDING IS A CEILING: an asserting side cannot buy its way back past a refusal the books
/// already hold, however clean the facts it writes about itself.
#[test]
fn asserted_facts_cannot_widen_a_refusing_standing() {
    let clean = passing();
    for standing in [
        Verdict::Quarantined,
        Verdict::Denied,
        Verdict::NeedsApproval,
        Verdict::IdentityNotLive,
        Verdict::GenerationMoved,
    ] {
        assert_eq!(evaluate(standing, Some(&clean)), standing);
    }
}

/// An allowing standing is the CEILING and not the answer: facts may take it down to a specific
/// refusal, and an asserting side that wrote nothing gets the standing back unchanged.
#[test]
fn an_allowing_standing_is_narrowed_by_facts_and_unchanged_without_them() {
    assert_eq!(evaluate(Verdict::Allow, None), Verdict::Allow);
    assert_eq!(evaluate(Verdict::Allow, Some(&passing())), Verdict::Allow);

    let mut drifted = passing();
    drifted.artifact = Artifact::Drifted;
    assert_eq!(
        evaluate(Verdict::Allow, Some(&drifted)),
        Verdict::ArtifactDrifted
    );
}

/// Every default is the refusing one, so a reader that filled nothing in cannot produce a pass.
#[test]
fn the_defaults_refuse() {
    assert_eq!(Verdict::default(), Verdict::Denied);
    assert_eq!(
        fold(&CounterpartyFacts::default()),
        Verdict::IdentityNotLive
    );
    assert_eq!(
        evaluate(Verdict::default(), Some(&passing())),
        Verdict::Denied
    );
}
