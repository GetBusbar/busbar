// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A sealed record survives the journal: `audit.v4` keeps the whole record, and reading it back
//! gives the record that was sealed — the same digest, the same signature, still verifying.

use busbar_contract::caps::{Audit as AuditStep, KernelSeal, MeterClassId, Pass};

use crate::journal::{from_journal_body, journal_body};
use crate::record::AuditChain;
use crate::sign::AuditSigningKey;

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

/// The classes the fixture's lines name, as a node's registered vocabulary would resolve them.
fn declared(name: &str) -> Option<MeterClassId> {
    ["tokens_in", "tokens_out"]
        .into_iter()
        .find(|c| *c == name)
        .map(MeterClassId::new)
}

fn sealed(n: u64) -> Vec<crate::record::AuditRecord> {
    let key = AuditSigningKey::from_hex_seed(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
    .expect("the test seed is 64 lowercase hex");
    let mut chain = AuditChain::new().signing_with(key);
    (1..=n)
        .map(|unit| {
            let mut inputs = super::sign_tests::rich_inputs(unit);
            inputs.what.incarnation = 3;
            crate::record::Audit::seal(&mut chain, inputs, &token())
        })
        .collect()
}

/// AN OUTCOME TAG THAT DOES NOT RE-RENDER IS REFUSED, never mapped to a different reason. The
/// decoder reads a sealed outcome back and accepts it only when it renders byte-equal to the tag
/// the record carries: a reason nobody spells that way, a padded number, a near-miss spelling — each
/// is refused, and so is the body that carries one.
#[test]
fn an_outcome_tag_that_does_not_re_render_is_refused_never_remapped() {
    use crate::journal::outcome_of;
    use busbar_contract::caps::{Outcome, ReasonCode, StepName};
    let real = Outcome::Refused(StepName::Admit, ReasonCode::OverBudget);
    assert_eq!(outcome_of("Refused(Admit, OverBudget)"), Some(real));
    for forged in [
        "Refused(Admit, OverBudgeT)",
        "Refused(Admit,  OverBudget)",
        "Refused(admit, OverBudget)",
        "Aborted(Superseded { by: UnitKey(007) })",
        "TimedOut(Admit) ",
        "Completed ",
    ] {
        assert_eq!(outcome_of(forged), None, "{forged:?} was accepted");
    }

    let body = journal_body(&sealed(1)[0]);
    let tag = b"Refused(Admit, OverBudget)";
    let at = body
        .windows(tag.len())
        .position(|w| w == tag)
        .expect("the outcome tag is in the body");
    let mut forged = body.clone();
    forged[at + tag.len() - 2] = b'T';
    assert!(
        from_journal_body(&forged, &declared).is_err(),
        "a body carrying a tag that does not re-render decoded"
    );
}
