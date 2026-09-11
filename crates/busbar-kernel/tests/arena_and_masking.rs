// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-frame arena, and the masking that hides a credential in the read cursor.
//!
//! Masking is decided by the location grammar rather than per plane, so every form is asked here
//! what it does — including the one that does nothing, because it was never in the bytes.

use busbar_kernel::arena::{
    span_slab, Arena, ArenaBuf, CredentialSlab, ARENA_BYTES, CURSOR_CAP_BYTES, FILL_BYTE,
};
use busbar_kernel::grammar::{ArrivalLocation, MaskKind, SignedOver, Span};
use busbar_kernel::inflight::MAX_SESSION_UPSTREAMS;

/// The ceilings the kernel enforces are the ceilings the contract told the plugin about.
///
/// Three of these were declared twice, once here and once on the plugin surface, with nothing
/// checking that the two agreed. A plugin allocates, declares legs and names usage lines against
/// the contract's numbers; the kernel sizes buffers, admits pairings and settles reports against
/// these. Two independently-maintained constants that happen to agree today are a plugin refused
/// at a limit it was never told about the first time one of them moves.
#[test]
fn the_kernels_ceilings_are_the_contracts_own() {
    assert_eq!(ARENA_BYTES, busbar_contract::ARENA_BYTES);
    assert_eq!(CURSOR_CAP_BYTES, busbar_contract::MAX_CURSOR_BYTES);
    assert_eq!(
        MAX_SESSION_UPSTREAMS,
        busbar_contract::MAX_SESSION_UPSTREAMS
    );
    assert_eq!(
        busbar_caps::usage::MAX_USAGE_LINES,
        busbar_contract::MAX_USAGE_LINES
    );
}

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

/// The mask kinds are a closed set, and the set says so out loud.
///
/// Every other closed set in the contract carries the same anchor: the list IS the enum, so a kind
/// added without being named here changes the count and this fails. Without it the set was closed
/// only by whoever happened to be reading the enum that day.
#[test]
fn the_mask_kinds_are_a_closed_set() {
    assert_eq!(MaskKind::ALL.len(), 4, "the list is the whole enum");
    let mut seen = MaskKind::ALL.to_vec();
    seen.sort_by_key(|kind| format!("{kind:?}"));
    seen.dedup();
    assert_eq!(seen.len(), MaskKind::ALL.len(), "no kind is listed twice");
    // Exhaustive, with no catch-all: a new kind stops compiling here rather than being masked by
    // whatever arm happened to be last.
    for kind in MaskKind::ALL {
        match kind {
            MaskKind::SameLengthFill
            | MaskKind::Nothing
            | MaskKind::SignatureSpan
            | MaskKind::BoundedPrefix => {}
        }
    }
}

/// Every location form is masked by the kind it is masked by.
///
/// Asserting only that the answer is a member of the closed set is an assertion no answer could
/// fail — the previous test already pins that the set is the whole enum, so `ALL.contains(..)` was
/// true of every value `mask()` can return. The kind is what decides whether a credential is still
/// in the bytes a plane reads, so the expectation is a decision per form: `Query` masking `Nothing`
/// would leave an API key in the read cursor with nothing to say so.
#[test]
fn every_location_form_masks_by_a_kind_the_closed_set_names() {
    let forms = [
        ArrivalLocation::Header("authorization"),
        ArrivalLocation::Query("key"),
        ArrivalLocation::PathSegment(0),
        ArrivalLocation::FirstFrameJsonPointer("/token"),
        ArrivalLocation::ClientCert,
        ArrivalLocation::Signed {
            over: SignedOver::Url,
        },
        ArrivalLocation::HandshakeFrames {
            max_frames: 2,
            max_bytes: 64,
        },
    ];
    for form in forms {
        // Exhaustive, with no catch-all: a location form added to the grammar stops compiling here
        // until somebody decides how its span is hidden.
        let expected = match form {
            ArrivalLocation::Header(_)
            | ArrivalLocation::Query(_)
            | ArrivalLocation::PathSegment(_)
            | ArrivalLocation::FirstFrameJsonPointer(_) => MaskKind::SameLengthFill,
            ArrivalLocation::ClientCert => MaskKind::Nothing,
            ArrivalLocation::Signed { .. } => MaskKind::SignatureSpan,
            ArrivalLocation::HandshakeFrames { .. } => MaskKind::BoundedPrefix,
        };
        assert_eq!(
            form.mask(),
            expected,
            "{form:?} is hidden by a different kind than the one it declares"
        );
        assert!(
            MaskKind::ALL.contains(&form.mask()),
            "{form:?} masks by a kind the closed set does not name"
        );
    }
}

/// The bounded prefix masks the bound the location declared, and no more.
///
/// The bound is read off the location itself. It used to be read off a match with a catch-all
/// arm that answered zero, so a location form that ever masked by bounded prefix without being
/// named there would have masked NOTHING — a credential left in the cursor for every plane to
/// read, with nothing failing to say so.
#[test]
fn a_bounded_prefix_masks_the_bound_the_location_declared() {
    let mut cursor = b"hello world, and more".to_vec();
    let before = cursor.len();
    let whole = Span::new(0, before);
    let mut slab = CredentialSlab::with_capacity(64);
    let masked = slab
        .mask_as(
            &mut cursor,
            whole,
            &ArrivalLocation::HandshakeFrames {
                max_frames: 1,
                max_bytes: 5,
            },
        )
        .expect("room in the slab");
    assert_eq!(masked.len(), 5, "the declared bound, not the whole span");
    assert_eq!(slab.read(masked), b"hello");
    assert_eq!(cursor.len(), before);
    assert_eq!(&cursor[5..], b" world, and more", "the rest is left alone");
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
    let mut buf = ArenaBuf::new();
    let mut slab = span_slab();
    let arena = buf.lease(&mut slab[..]);
    assert_eq!(arena.remaining(), ARENA_BYTES);
    let bytes = arena
        .alloc_bytes(b"a frame's worth of bytes")
        .expect("room");
    assert_eq!(bytes.as_slice(), b"a frame's worth of bytes");
    assert_eq!(arena.used(), 24);
    drop(arena);

    // On the relay path the arena is reset per frame, so a session that relays all day uses the
    // same four kibibytes it used at its first frame. The reset IS the re-lease: it takes the
    // buffer back mutably, so every byte the frame before lent is over before the next one starts.
    for _ in 0..1_000 {
        let mut slab = span_slab();
        let arena = buf.lease(&mut slab[..]);
        arena
            .alloc_bytes(b"another frame")
            .expect("room, every time");
        assert_eq!(arena.used(), 13);
    }
    assert_eq!(buf.resets(), 1_001);
    assert_eq!(
        buf.high_water(),
        24,
        "the first frame was the widest, and nothing grew after it"
    );
}

#[test]
fn asking_the_arena_for_more_than_it_has_is_an_answer_not_a_panic() {
    let mut buf = ArenaBuf::new();
    let mut slab = span_slab();
    let arena = buf.lease(&mut slab[..]);
    let whole = vec![0u8; ARENA_BYTES];
    arena.alloc_bytes(&whole).expect("all of it");
    let refused = arena
        .alloc_bytes(b"one more byte")
        .expect_err("nothing left");
    assert_eq!(refused.remaining, 0);
    assert_eq!(refused.wanted, 13);
}
