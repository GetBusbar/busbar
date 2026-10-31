// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A sealed record survives the journal: `audit.v4` keeps the whole record, and reading it back
//! gives the record that was sealed — the same digest, the same signature, still verifying.
//!
//! The batteries that seal a record (and so mint the audit step's token) live in the kernel's
//! member tests; what stays here reaches the crate-private decoder and seals nothing.

/// AN OUTCOME TAG THAT DOES NOT RE-RENDER IS REFUSED, never mapped to a different reason — the
/// DECODER half. The decoder reads a sealed outcome back and accepts it only when it renders
/// byte-equal to the tag the record carries: a reason nobody spells that way, a padded number, a
/// near-miss spelling — each is refused. That the body carrying one is refused too is pinned in the
/// kernel's member tests, which can seal the record it needs.
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
/// shipped build is `u32::MAX` bytes; the writer is driven here under a small one, which is the same
/// code path. A cut field would journal a record that no longer reads back as the one sealed.
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
