// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes.

use crate::record::Subject;

/// EVERY SUBJECT TAG THE AMENDMENT DIGEST SEALS IS SPELLED OUT, not derived.
///
/// The digested text for the subject used to be whatever the derived `Debug` printed, which made
/// every sealed amendment hostage to a rename: an amendment is a correction to money, and a
/// correction that reports itself tampered because somebody renamed a variant is worse than no
/// correction at all. The spellings live in the production file now; this pins each one, so a
/// rename shows up here — as a difference somebody has to look at — instead of in the hash.
#[test]
fn the_frozen_subject_tags_are_the_ones_the_amendment_digest_seals() {
    use crate::record::{subject_tag, subject_value};

    assert_eq!(
        subject_tag(&Subject::PrincipalId("pseudonym-1".into())),
        "principal"
    );
    assert_eq!(subject_tag(&Subject::Arrival), "arrival");
    assert_eq!(subject_tag(&Subject::Node(7)), "node");
    assert_eq!(subject_tag(&Subject::Aggregate), "aggregate");

    // The value is the second half of the pair, and it is what stops a principal whose pseudonym
    // reads as another subject's tag from digesting as that subject.
    assert_eq!(
        subject_value(&Subject::PrincipalId("pseudonym-1".into())),
        "pseudonym-1"
    );
    assert_eq!(subject_value(&Subject::Arrival), "");
    assert_eq!(subject_value(&Subject::Node(7)), "7");
    assert_eq!(subject_value(&Subject::Aggregate), "");
}
