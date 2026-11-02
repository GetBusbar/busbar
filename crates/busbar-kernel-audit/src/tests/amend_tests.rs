// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes.

use crate::record::Subject;

/// EVERY SUBJECT TAG THE AMENDMENT DIGEST SEALS IS SPELLED OUT, not derived.

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

    assert_eq!(
        subject_value(&Subject::PrincipalId("pseudonym-1".into())),
        "pseudonym-1"
    );
    assert_eq!(subject_value(&Subject::Arrival), "");
    assert_eq!(subject_value(&Subject::Node(7)), "7");
    assert_eq!(subject_value(&Subject::Aggregate), "");
}
