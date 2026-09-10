// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIT VIEW: the projection the kernel lends a composition for the length of one call.
//!
//! `busbar_contract::unit::Unit` is the value the two upstream encoders take, and until this seam
//! existed nothing in this tree could build one: `Unit::new` takes the contract's sealing marker, a
//! workspace search for it finds only planes' own newtypes, and so `encode_egress` and `encode_end`
//! had a parameter no caller outside a plane's own tests could supply.
//!
//! What is held here is the DIVISION, because that is the whole of what the call decides. The half
//! about the WORK is the draft's and is carried across verbatim — a view that edited it would be the
//! kernel re-writing what the loop already judged. The half about WHOSE work it is is the kernel's,
//! and nothing on the draft reaches it — a draft that could name its own principal would be a plane
//! writing its own evidence.
//!
//! The third cell is a `compile_fail` and it lives on the seam's own doc comment
//! (`Kernel::unit_view`), because what it holds is that there is no OTHER route: the kernel's seal is
//! a private field, so this call is the only way out of that crate to a `Unit`.

use busbar_contract::bounded::{Facts, Ir};
use busbar_contract::plane::UnitDraft;
use busbar_contract::unit::Origin;
use busbar_contract::wire::Direction;
use busbar_contract::{OpClassId, PrincipalId, SessionId, StreamId, UnitKey};
use busbar_kernel::teller::{Kernel, UnitIdentity};

/// One draft, as a plane's decode would hand it over: a class, a body, and the facts it read.
fn drafted<'u>(body: &'u [u8], facts: Facts<'u>) -> UnitDraft<'u> {
    UnitDraft {
        op: OpClassId::new("turn"),
        body_ir: Ir::new(body, &[]),
        correlates: None,
        correlation_out: None,
        facts,
    }
}

fn identity() -> UnitIdentity {
    UnitIdentity {
        key: UnitKey::new(41),
        origin: Origin::Client,
        session: Some(SessionId(7)),
        stream: Some(StreamId(3)),
        direction: Direction::Outbound,
        principal: Some(PrincipalId::new("acct-9")),
    }
}

/// THE DRAFT'S HALF IS CARRIED VERBATIM: the class that priced the unit, the body the plane decoded
/// and the facts it read off the bytes.
///
/// The view is a projection and not a second judgement. The operation class in particular is the one
/// that PRICED the unit, which is why the loop treats a differing class at the audit step as a
/// dispute rather than a re-price; a view that could re-write it would put the money and the bytes
/// on two different answers to the same question.
#[test]
fn the_view_carries_the_drafts_own_judgement_unaltered() {
    let kernel = Kernel::new();
    let mut facts = Facts::new();
    facts
        .set(
            "modality",
            busbar_contract::bounded::FactValue::Str("audio"),
        )
        .expect("the map has room");
    let draft = drafted(br#"{"kind":"turn"}"#, facts);

    let view = kernel.unit_view(&identity(), &draft);

    assert_eq!(view.op(), draft.op, "the class that priced the unit");
    assert_eq!(
        view.body().body(),
        br#"{"kind":"turn"}"#,
        "the body the plane decoded, whole"
    );
    assert_eq!(
        view.draft_facts().get("modality"),
        Some(busbar_contract::bounded::FactValue::Str("audio")),
        "what decode determined is evidence every later reader is entitled to"
    );
    assert_eq!(view.correlates(), None, "the draft answered nothing");
}

/// THE IDENTITY'S HALF IS THE KERNEL'S, and the draft has no way to reach it.
///
/// Two views of the SAME draft under two identities differ in exactly the six fields the kernel
/// seals and in nothing else. That is the seam stated as a measurement: whose work a unit is cannot
/// be read off the bytes, so a caller that could name it would be naming somebody else's.
#[test]
fn the_identity_is_the_kernels_and_the_same_draft_takes_either() {
    let kernel = Kernel::new();
    let draft = drafted(br#"{"kind":"turn"}"#, Facts::new());

    let mine = kernel.unit_view(&identity(), &draft);
    let theirs = kernel.unit_view(
        &UnitIdentity {
            key: UnitKey::new(42),
            origin: Origin::Provider,
            session: Some(SessionId(8)),
            stream: None,
            direction: Direction::Inbound,
            principal: None,
        },
        &draft,
    );

    assert_eq!(mine.key(), UnitKey::new(41));
    assert_eq!(mine.origin(), Origin::Client);
    assert_eq!(mine.session(), Some(SessionId(7)));
    assert_eq!(mine.stream(), Some(StreamId(3)));
    assert_eq!(mine.direction(), Direction::Outbound);
    assert_eq!(mine.principal(), Some(&PrincipalId::new("acct-9")));

    assert_eq!(theirs.key(), UnitKey::new(42));
    assert_eq!(theirs.origin(), Origin::Provider);
    assert_eq!(theirs.session(), Some(SessionId(8)));
    assert_eq!(theirs.stream(), None, "a session's unstreamed side");
    assert_eq!(theirs.direction(), Direction::Inbound);
    assert_eq!(
        theirs.principal(),
        None,
        "before the authenticate step has answered there is nobody to name"
    );

    // And the work half is the same in both, because it is the same draft.
    assert_eq!(mine.op(), theirs.op());
    assert_eq!(mine.body().body(), theirs.body().body());
}
