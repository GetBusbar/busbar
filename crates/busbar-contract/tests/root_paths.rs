// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plugin author can write a whole plugin against the crate root.
//!
//! The root re-export list is the crate's answer to "what is the plugin-visible ABI". A name that
//! is reachable only through its module is a name the list does not claim, and a plugin author
//! reading the list would conclude the type does not exist — so the seven names below were
//! effectively invisible even though every one of them is required to implement a shipped kind:
//! the auth kind's outbound-sign operation cannot be written without `Signer`, `SignFailed` and
//! `EnvelopeFields`, a gate hook cannot build a patch without `IrEdit`, and neither can handle a
//! full bounded collection without `Overflow` or a full fact map without `FactsExhausted`.
//!
//! Nothing below names a module path. That is the whole assertion.

use busbar_contract::{
    AbiVersion, AuthDecoration, BoundedVec, ConfigView, EgressBody, EnvelopeFields, FactValue,
    Facts, FactsExhausted, FrameStream, IrEdit, IrPatch, Kind, Overflow, Plugin, ScratchBytes,
    SignFailed, Signer, MAX_KEYS,
};

/// An auth plugin whose outbound-sign operation is written entirely against the crate root.
///
/// ONE auth kind (DECISIONS #3): outbound-sign is an OPERATION here, not a second `Kind` variant
/// and not a second trait. What this file asserts is unchanged — every name the operation needs
/// resolves at the crate root — and it is asserted without a kind that does not exist.
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

impl RootScheme {
    /// The outbound-sign operation, written out so every name it needs is exercised at a root
    /// path rather than merely re-exported.
    fn decorate<'u>(
        &self,
        _cfg: &dyn ConfigView,
        body: &EgressBody<'u>,
        signer: &dyn Signer,
    ) -> AuthDecoration<'u> {
        // The signer is the whole reason the scheme never holds a key; a failure here is one of
        // the two closed reasons, and both are root names too.
        let signed = match signer.sign("upstream", body.body.as_slice()) {
            Ok(_) => true,
            Err(SignFailed::UnknownKey | SignFailed::Unavailable) => false,
        };
        AuthDecoration::Decorate {
            envelope_fields: EnvelopeFields::new(),
            body_signature: signed.then_some(body.body),
            slots: BoundedVec::new(),
        }
    }

    /// The second round of the same operation, for the same reason.
    fn continue_handshake<'u>(
        &self,
        _state: &busbar_contract::ChallengeState,
        _frame: &busbar_contract::Frame,
        _ctx: &busbar_contract::Ctx<'u>,
        _signer: &dyn Signer,
    ) -> AuthDecoration<'u> {
        AuthDecoration::Handshake {
            max_frames: 1,
            max_bytes: 0,
        }
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

/// The scheme above exists, and so does the transport's frame stream, at root paths.
///
/// Both operations are NAMED here, not merely defined: an operation nothing refers to is dead
/// code, and a root-path claim about a body the compiler never type-checks against a caller is no
/// claim at all. The two bindings spell each signature out in root names a second time, so the
/// coercion itself is the assertion.
#[test]
fn the_scheme_and_the_frame_stream_are_root_names() {
    let scheme: &dyn Plugin = &RootScheme;
    assert_eq!(scheme.key(), "root-scheme");
    assert_eq!(scheme.kind(), Kind::Auth);

    let _decorate: for<'u> fn(
        &RootScheme,
        &dyn ConfigView,
        &EgressBody<'u>,
        &dyn Signer,
    ) -> AuthDecoration<'u> = RootScheme::decorate;
    let _again: for<'u> fn(
        &RootScheme,
        &busbar_contract::ChallengeState,
        &busbar_contract::Frame,
        &busbar_contract::Ctx<'u>,
        &dyn Signer,
    ) -> AuthDecoration<'u> = RootScheme::continue_handshake;

    let _: Option<FrameStream> = None;
}
