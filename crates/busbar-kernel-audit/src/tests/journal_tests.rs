// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A sealed record survives the journal: `audit.v4` keeps the whole record, and reading it back

/// AN OUTCOME TAG THAT DOES NOT RE-RENDER IS REFUSED, never mapped to a different reason — the

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
}

/// A TEXT TOO LONG FOR THE LENGTH PREFIX REFUSES THE BODY, never cuts the field. The bound in a

#[test]
fn a_text_over_the_length_prefix_refuses_the_body_never_cuts_it() {
    use crate::journal::{FieldTooLong, Writer};
    let mut fits = Writer::within(4);
    fits.text("four");
    assert_eq!(
        fits.finish(),
        Ok([&4u32.to_be_bytes()[..], b"four"].concat())
    );
    let mut over = Writer::within(4);
    over.text("fiv\u{e9}");
    over.num(7);
    assert_eq!(over.finish(), Err(FieldTooLong));
}
