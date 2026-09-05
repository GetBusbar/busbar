// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-frame arena, and the masking that hides a credential in the read cursor.
//!
//! Masking is decided by the location grammar rather than per plane, so every form is asked here
//! what it does — including the one that does nothing, because it was never in the bytes.

use busbar_kernel::arena::{Arena, CredentialSlab, ARENA_BYTES, FILL_BYTE};
use busbar_kernel::grammar::{ArrivalLocation, MaskKind, SignedOver, Span};

#[test]
fn masking_leaves_the_cursor_the_same_length_and_the_offsets_intact() {
    let mut cursor = b"GET /x\r\nauthorization: secret-token\r\n\r\n".to_vec();
    let before = cursor.len();
    let start = 23;
    let span = Span::new(start, start + "secret-token".len());
    let mut slab = CredentialSlab::with_capacity(1024);

    let masked = slab.mask(&mut cursor, span).expect("room in the slab");
    assert_eq!(cursor.len(), before, "every later offset still holds");
    assert_eq!(slab.read(masked), b"secret-token");
    assert!(
        !String::from_utf8_lossy(&cursor).contains("secret-token"),
        "the credential is no longer in the bytes a plane will see"
    );
    assert_eq!(cursor[start], FILL_BYTE);
}

#[test]
fn an_oversize_credential_is_refused_against_the_slab_and_not_the_cursor() {
    let mut cursor = vec![b'a'; 64];
    let mut slab = CredentialSlab::with_capacity(8);
    assert_eq!(
        slab.mask(&mut cursor, Span::new(0, 32)),
        Err(busbar_caps::ReasonCode::CredentialBudget)
    );
    assert_eq!(
        slab.mask(&mut cursor, Span::new(0, 128)),
        Err(busbar_caps::ReasonCode::CursorBudget)
    );
}

#[test]
fn every_location_form_says_how_it_is_masked() {
    assert_eq!(
        ArrivalLocation::Header("authorization").mask(),
        MaskKind::SameLengthFill
    );
    assert_eq!(ArrivalLocation::ClientCert.mask(), MaskKind::Nothing);
    assert_eq!(
        ArrivalLocation::Signed {
            over: SignedOver::Body
        }
        .mask(),
        MaskKind::SignatureSpan
    );
    assert_eq!(
        ArrivalLocation::HandshakeFrames {
            max_frames: 4,
            max_bytes: 256,
        }
        .mask(),
        MaskKind::BoundedPrefix
    );
    // A body signature has to see every byte it signs, so the unit does not open until the body has.
    assert!(ArrivalLocation::Signed {
        over: SignedOver::Both
    }
    .needs_whole_body());
    // A path segment is bytes in the read cursor exactly as a header is, so it hides the same way:
    // same-length fill, which leaves every offset already computed over the target where it was.
    assert_eq!(
        ArrivalLocation::PathSegment(0).mask(),
        MaskKind::SameLengthFill
    );
    assert!(!ArrivalLocation::PathSegment(0).needs_whole_body());
    assert!(!ArrivalLocation::Header("x").needs_whole_body());
}

#[test]
fn a_client_certificate_masks_nothing_because_it_was_never_in_the_bytes() {
    let mut cursor = b"hello".to_vec();
    let mut slab = CredentialSlab::with_capacity(64);
    // A client certificate is the one form that masks nothing, because it was never in the bytes.
    let masked = slab
        .mask_as(&mut cursor, Span::new(0, 5), &ArrivalLocation::ClientCert)
        .expect("nothing to do");
    assert!(masked.is_empty());
    assert_eq!(cursor, b"hello");
}

#[test]
fn the_arena_is_four_kibibytes_and_is_reset_per_frame() {
    let mut arena = Arena::new();
    assert_eq!(arena.remaining(), ARENA_BYTES);
    let span = arena.push(b"a frame's worth of bytes").expect("room");
    assert_eq!(arena.read(span), b"a frame's worth of bytes");
    assert_eq!(arena.used(), 24);

    // On the relay path the arena is reset per frame, so a session that relays all day uses the
    // same four kibibytes it used at its first frame.
    for _ in 0..1_000 {
        arena.reset();
        arena.push(b"another frame").expect("room, every time");
    }
    assert_eq!(arena.used(), 13);
    assert_eq!(arena.resets(), 1_000);
}

#[test]
fn asking_the_arena_for_more_than_it_has_is_an_answer_not_a_panic() {
    let mut arena = Arena::new();
    let full = arena.take(ARENA_BYTES).expect("all of it");
    assert_eq!(full.len(), ARENA_BYTES);
    let refused = arena.push(b"one more byte").expect_err("nothing left");
    assert_eq!(refused.remaining, 0);
    assert_eq!(refused.reason(), busbar_caps::ReasonCode::ArenaBudget);
}
