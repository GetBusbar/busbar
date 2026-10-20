// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND LAYOUT FINGERPRINTS ARE THEIR FOLDS (status row 188).
//!
//! Each kind states its fingerprint as a literal (`abi/<kind>/`'s `LAYOUT_FINGERPRINT`, which the
//! generated C header carries) and lists its shapes (`LAYOUT_SHAPES`, evaluated by the compiler).
//! This test holds the literal to the fold of the shapes, for every kind, and names the fold's
//! number when they part: a struct that moved needs its kind's literal moved with it (and the
//! header regenerated, `cargo xtask abi-header --write`), so every plugin of that kind built
//! before the move is refused at load instead of read at the wrong offsets.

use busbar_contract::abi::mechanism::layout::fingerprint;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::{auth, export, hook, plane, secret, store, transport};

/// Every kind's `(code, literal, shapes)`.
const KINDS: [(KindCode, u64, &[&[u64]]); 7] = [
    (
        KindCode::Store,
        store::LAYOUT_FINGERPRINT,
        store::LAYOUT_SHAPES,
    ),
    (
        KindCode::Secret,
        secret::LAYOUT_FINGERPRINT,
        secret::LAYOUT_SHAPES,
    ),
    (
        KindCode::Auth,
        auth::LAYOUT_FINGERPRINT,
        auth::LAYOUT_SHAPES,
    ),
    (
        KindCode::Hook,
        hook::LAYOUT_FINGERPRINT,
        hook::LAYOUT_SHAPES,
    ),
    (
        KindCode::Export,
        export::LAYOUT_FINGERPRINT,
        export::LAYOUT_SHAPES,
    ),
    (
        KindCode::Plane,
        plane::LAYOUT_FINGERPRINT,
        plane::LAYOUT_SHAPES,
    ),
    (
        KindCode::Transport,
        transport::LAYOUT_FINGERPRINT,
        transport::LAYOUT_SHAPES,
    ),
];

#[test]
fn every_kind_states_the_fold_of_its_shapes() {
    let parted: Vec<String> = KINDS
        .iter()
        .filter(|(_, stated, shapes)| *stated != fingerprint(shapes))
        .map(|(kind, stated, shapes)| {
            format!(
                "{kind:?}: states {stated:#018x}, its shapes fold to {:#018x}",
                fingerprint(shapes)
            )
        })
        .collect();
    assert!(
        parted.is_empty(),
        "a kind's LAYOUT_FINGERPRINT is not the fold of its LAYOUT_SHAPES (move the literal, then \
         `cargo xtask abi-header --write`): {}",
        parted.join("; ")
    );
}

#[test]
fn the_host_accepts_each_kind_at_its_own_fingerprint() {
    for (kind, stated, _) in KINDS {
        assert_eq!(kind.layout_fingerprint(), stated, "{kind:?}");
    }
    let mut all: Vec<u64> = KINDS.iter().map(|(_, f, _)| *f).collect();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), KINDS.len(), "no two kinds share a fingerprint");
    assert_eq!(KindCode::ALL.len(), KINDS.len(), "every kind is held here");
}

/// RED: any moved word moves the fold: a struct one field-width larger, a field at another
/// offset (the hook `RequestView` insertion that shifted `DecideIn` by 24 bytes), a struct
/// dropped from the list, and two structs swapped.
#[test]
fn a_moved_layout_moves_the_fingerprint() {
    for (kind, stated, shapes) in KINDS {
        let mut words: Vec<Vec<u64>> = shapes.iter().map(|s| s.to_vec()).collect();
        let refold = |w: &[Vec<u64>]| {
            let slices: Vec<&[u64]> = w.iter().map(Vec::as_slice).collect();
            fingerprint(&slices)
        };
        assert_eq!(
            refold(&words),
            stated,
            "{kind:?}: the unmoved shapes fold to the literal"
        );
        let last = words.len() - 1;

        words[0][0] += 24;
        assert_ne!(refold(&words), stated, "{kind:?}: a struct 24 bytes larger");
        words[0][0] -= 24;

        if let Some(i) = words.iter().position(|w| w.len() > 3) {
            words[i][3] += 24;
            assert_ne!(refold(&words), stated, "{kind:?}: a field 24 bytes later");
            words[i][3] -= 24;
        }

        let dropped = words.remove(last);
        assert_ne!(refold(&words), stated, "{kind:?}: a struct left out");
        words.push(dropped);

        if words.len() > 1 && words[0] != words[1] {
            words.swap(0, 1);
            assert_ne!(refold(&words), stated, "{kind:?}: two structs swapped");
        }
    }
}
