// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-NATIVE-FIRST-PARTY r3 §2.3, §2.6 and §5 L3, L4 (characterisation): one signer per image entry, read by
//! verified identity, fail closed for an unknown identity; a dropped image claiming a linked identity is refused and
//! inherits nothing.

use super::*;
use crate::admit::Signer;
use crate::sign::Verdict;

fn described() -> Described {
    Described {
        kind: KindCode::Export,
        methods: 0,
        facts: 0,
        items: Vec::new(),
        schema: None,
        metrics: Vec::new(),
    }
}

fn builder() -> ImagesBuilder {
    ImagesBuilder::new(
        &busbar_plugin_abi::host_side::host_vt::HOST,
        Arc::new(SlotTable::new()),
        Ceilings::DEFAULT,
    )
}

fn third_party() -> Signer {
    Signer::Dropped {
        verdict: Verdict::Trusted {
            publisher: "acme".into(),
            first_party: false,
        },
        proof: busbar_artifact_metadata::rows::Verification::default(),
    }
}

/// L3: no entry, no trust.
#[test]
fn images_first_party_of_an_unknown_identity_is_false() {
    let mut images = builder();
    images
        .admit_described("x-linked", &[0; 64], &[], Signer::Linked, described())
        .expect("a described image admits");
    let images = images.finish();
    for unknown in ["nobody", "", "x-linked-not"] {
        assert!(!images.first_party(unknown), "{unknown}");
        assert!(!images.trusted(unknown), "{unknown}");
        assert!(!images.linked(unknown), "{unknown}");
        assert!(images.signer(unknown).is_none(), "{unknown}");
    }
    assert!(
        images.linked("x-linked") && images.first_party("x-linked") && images.trusted("x-linked")
    );
}

/// L4: a dropped image claiming a linked identity is refused `NameConflict`; the one entry stays the linked one.
#[test]
fn a_dropped_image_claiming_a_linked_identity_is_refused_and_inherits_nothing() {
    let mut images = builder();
    images
        .admit_described("x", &[0; 64], &[], Signer::Linked, described())
        .expect("the linked image admits first");
    let refused = images
        .admit_described("x", &[0; 64], &[], third_party(), described())
        .expect_err("a second image answering to `x` is refused");
    assert_eq!(refused.code, RefusalCode::NameConflict);
    let images = images.finish();
    assert_eq!(images.identities().count(), 1);
    assert_eq!(images.signer("x"), Some(&Signer::Linked));
    assert!(images.first_party("x"));
}

/// A third party's entry is trusted but not first party; linked, first party and trusted come from one signer.
#[test]
fn linked_first_party_and_trusted_are_read_from_one_signer() {
    let mut images = builder();
    images
        .admit_described("tp", &[0; 64], &[], third_party(), described())
        .expect("the third party admits");
    let images = images.finish();
    assert!(!images.linked("tp") && !images.first_party("tp") && images.trusted("tp"));
}
