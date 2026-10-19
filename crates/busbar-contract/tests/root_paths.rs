// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plugin author can write a whole plugin against the crate root.
//!
//! The root re-export list is the crate's answer to "what is the plugin-visible ABI". A name that
//! is reachable only through its module is a name the list does not claim, and a plugin author
//! reading the list would conclude the type does not exist — so the names below were effectively
//! invisible even though every one of them is required to implement a shipped kind: a gate hook
//! cannot build a patch without `IrEdit`, and no kind can handle a full bounded collection without
//! `Overflow` or a full fact map without `FactsExhausted`.
//!
//! Nothing below names a module path. That is the whole assertion.

use busbar_contract::{
    AbiVersion, BoundedVec, FactValue, Facts, FactsExhausted, FrameStream, IrEdit, IrPatch, Kind,
    Overflow, Plugin, ScratchBytes, MAX_KEYS,
};

/// An auth plugin named entirely through the crate root.
struct RootScheme;

impl Plugin for RootScheme {
    fn key(&self) -> &'static str {
        "root-scheme"
    }
    fn kind(&self) -> Kind {
        Kind::Auth
    }
    fn abi(&self) -> AbiVersion {
        AbiVersion(1)
    }
}

/// A gate hook's patch, and both of the two "it did not fit" answers, built through the root.
#[test]
fn a_patch_and_both_full_answers_are_reachable_from_the_crate_root() {
    let mut patch = IrPatch::default();
    patch
        .edits
        .push(IrEdit {
            pointer: "/messages/0/content",
            replacement: ScratchBytes::new(b"redacted"),
        })
        .expect("one edit fits");
    assert_eq!(patch.edits.len(), 1);

    // The bounded list hands the item back rather than growing, and the shape it hands it back in
    // is a root name.
    let mut full: BoundedVec<u8, 1> = BoundedVec::new();
    full.push(1).expect("the first fits");
    let Err(Overflow { item, capacity }) = full.push(2) else {
        panic!("a full bounded list does not accept a second item");
    };
    assert_eq!((item, capacity), (2, 1));

    // So does the fact map, with its own.
    let mut facts = Facts::new();
    let keys: Vec<String> = (0..=MAX_KEYS).map(|i| format!("k{i}")).collect();
    let mut last = Ok(());
    for key in &keys {
        last = facts.set(key, FactValue::Bool(true));
    }
    let Err(FactsExhausted { capacity }) = last else {
        panic!("a full fact map does not accept a new key");
    };
    assert_eq!(capacity, MAX_KEYS);
}

/// The plugin above, and the transport's frame stream, at root paths.
#[test]
fn the_scheme_and_the_frame_stream_are_root_names() {
    let scheme: &dyn Plugin = &RootScheme;
    assert_eq!(scheme.key(), "root-scheme");
    assert_eq!(scheme.kind(), Kind::Auth);

    let _: Option<FrameStream> = None;
}
