// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The per-frame arena, and the masking that hides a credential in the read cursor.
//!
//! Masking is decided by the location grammar rather than per plane, so every form is asked here
//! what it does — including the one that does nothing, because it was never in the bytes.

use busbar_kernel::arena::{Arena, CredentialSlab, ARENA_BYTES, CURSOR_CAP_BYTES, FILL_BYTE};
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

/// A span the arena hands out holds nothing of the frame before it.
///
/// `take` promised zeroed space and `reset` moved the cursor without clearing a byte, so a unit
/// that took a span and then wrote LESS into it than it asked for could read the tail of the
/// previous frame straight back out — one connection's bytes surfacing inside another's buffer.
/// The promise is now kept where it is made.
#[test]
fn a_short_write_after_a_reset_shows_nothing_of_the_last_frame() {
    let mut arena = Arena::new();
    let secret = b"authorization: Bearer swordfish";
    let first = arena.push(secret).expect("the arena has room");
    assert_eq!(arena.read(first), secret);

    // The frame ends and the next one begins.
    arena.reset();
    let span = arena.take(secret.len()).expect("the arena has room");
    assert!(
        arena.read(span).iter().all(|byte| *byte == 0),
        "the span still held the last frame"
    );

    // And a unit that writes less than it asked for exposes no tail.
    arena.write(span, b"ok").expect("within the span");
    assert_eq!(&arena.read(span)[..2], b"ok");
    assert!(
        arena.read(span)[2..].iter().all(|byte| *byte == 0),
        "the tail of the span leaked the last frame"
    );
}

// ── The contract-facing per-unit arena ───────────────────────────────────────────────────────────
//
// The kernel's own `Arena` above is a span allocator: it takes `&mut self` and answers with an
// offset, which is the shape the loop wants and the shape a plugin cannot use. The contract's
// `Arena` is the other shape — `&self` in, a borrowed slice out — and until now NOTHING in the tree
// implemented it for real. Every implementor was a double that leaked its allocations with a
// comment saying so, which meant no serving path could build a `Ctx` and no plane could be served
// through the loop at all.
//
// These are the proofs that the shipping one is real: it copies, it refuses at its own ceiling
// rather than growing, and it hands back nothing that outlives the unit it was carved for.

use busbar_contract::bounded::Arena as ContractArena;
use busbar_kernel::arena::{ArenaSpace, UnitArena, ARENA_SPANS};

/// A unit arena copies bytes and hands back a borrow of its own space, not of the caller's input.
#[test]
fn the_unit_arena_copies_what_it_is_given() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);

    let src = b"the bytes a plane produced".to_vec();
    let held = arena.alloc_bytes(&src).expect("the arena has room");
    assert_eq!(held.as_slice(), src.as_slice());
    assert!(
        !std::ptr::eq(held.as_slice().as_ptr(), src.as_ptr()),
        "the arena handed back the caller's own bytes instead of a copy"
    );

    let text = arena.alloc_str("a declared pointer").expect("room");
    assert_eq!(text, "a declared pointer");
}

/// The arena is fixed size. An over-capacity request is the contract's refusal, never a growth.
#[test]
fn the_unit_arena_refuses_rather_than_grows() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);
    assert_eq!(arena.remaining(), ARENA_BYTES);

    let half = vec![b'x'; ARENA_BYTES / 2];
    arena.alloc_bytes(&half).expect("half fits");
    assert_eq!(arena.remaining(), ARENA_BYTES - half.len());

    let rest = vec![b'y'; ARENA_BYTES];
    let refused = arena
        .alloc_bytes(&rest)
        .expect_err("a request past the ceiling is refused");
    assert_eq!(refused.wanted, ARENA_BYTES);
    assert_eq!(refused.remaining, ARENA_BYTES - half.len());

    // A refusal costs the arena nothing: the next request that DOES fit still succeeds.
    assert_eq!(arena.remaining(), ARENA_BYTES - half.len());
    arena
        .alloc_bytes(&vec![b'z'; ARENA_BYTES - half.len()])
        .expect("exactly what is left still fits");
    assert_eq!(arena.remaining(), 0);
    arena
        .alloc_bytes(b"one more")
        .expect_err("an empty arena refuses");
}

/// A span table is allocated out of the same unit arena, and its pointers are copies too.
#[test]
fn the_unit_arena_allocates_a_span_table() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);

    let table = arena
        .alloc_spans(&[("/method", Span::new(0, 4)), ("/params", Span::new(6, 11))])
        .expect("two pointers fit");
    assert_eq!(table.len(), 2);
    assert_eq!(table[0], ("/method", Span::new(0, 4)));
    assert_eq!(table[1], ("/params", Span::new(6, 11)));

    // The pair region has a ceiling of its own, and it refuses rather than growing.
    let wide: Vec<(&str, Span)> = (0..=ARENA_SPANS).map(|_| ("/p", Span::new(0, 1))).collect();
    arena
        .alloc_spans(&wide)
        .expect_err("a table past the pair ceiling is refused");
}

/// The one property the leaking doubles never had: nothing survives the unit.
///
/// The space is the unit's, on the unit's own stack, and the arena borrows it. When the unit ends
/// the space is dropped and every borrow it handed out is already dead — proved here by the
/// compiler, since a `held` that outlived `space` would not build. The next unit's arena starts
/// full again over its own space, which is what "reset per unit" means when nothing leaks.
#[test]
fn nothing_the_unit_arena_hands_out_survives_the_unit() {
    for _ in 0..4 {
        let mut space = ArenaSpace::new();
        let arena = UnitArena::new(&mut space);
        assert_eq!(arena.remaining(), ARENA_BYTES);
        arena.alloc_bytes(&vec![b'q'; 1024]).expect("room");
        assert_eq!(arena.remaining(), ARENA_BYTES - 1024);
    }
}

/// The shipping arena is the one a `Ctx` can be built from — which is the whole point.
#[test]
fn the_unit_arena_is_what_a_context_is_built_from() {
    let mut space = ArenaSpace::new();
    let arena = UnitArena::new(&mut space);
    let handle: &dyn ContractArena = &arena;
    assert_eq!(handle.remaining(), ARENA_BYTES);
    assert_eq!(
        handle.alloc_str("v").expect("room"),
        "v",
        "the trait object allocates the same way the value does"
    );
}
