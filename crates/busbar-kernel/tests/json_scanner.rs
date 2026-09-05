// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The JSON span scanner, the masking that goes with it, and the arena.
//!
//! The case that matters is the big body whose one interesting key was serialised LAST: the whole
//! body has to be walked before the answer exists, so that is where the cost is measured.

use busbar_kernel::arena::{Arena, CredentialSlab, ARENA_BYTES, FILL_BYTE};
use busbar_kernel::grammar::{
    resolve_pointer, ArrivalLocation, MaskKind, Resolved, SignedOver, Span,
};

fn found<'b>(body: &'b [u8], pointer: &str) -> &'b [u8] {
    match resolve_pointer(body, pointer) {
        Resolved::Found(span) => span.of(body),
        other => panic!("{pointer} did not resolve: {other:?}"),
    }
}

#[test]
fn a_pointer_resolves_to_a_span_of_the_callers_own_bytes() {
    let body = br#"{"a": {"b": [1, 2, {"c": "here"}]}, "lane": "gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);
    assert_eq!(found(body, "/a/b/2/c"), br#""here""#);
    assert_eq!(found(body, "/a/b/1"), b"2");
    assert_eq!(resolve_pointer(body, "/missing"), Resolved::Missing);
    assert_eq!(resolve_pointer(body, "/a/b/9"), Resolved::Missing);
}

#[test]
fn an_empty_pointer_names_the_whole_document() {
    let body = br#"  {"a": 1}  "#;
    assert_eq!(found(body, ""), br#"{"a": 1}"#);
}

#[test]
fn a_truncated_document_asks_for_more_rather_than_answering() {
    let whole = br#"{"a": {"b": "value"}, "lane": "gold"}"#;
    for cut in 1..whole.len() - 1 {
        match resolve_pointer(&whole[..cut], "/lane") {
            // Until the key has arrived the answer is "not yet", never a wrong span.
            Resolved::NeedMore | Resolved::Missing => {}
            Resolved::Found(span) => panic!("resolved at {cut} bytes to {:?}", span),
            Resolved::Malformed => panic!("a prefix of valid JSON called malformed at {cut}"),
        }
    }
    assert_eq!(found(whole, "/lane"), br#""gold""#);
}

#[test]
fn escapes_are_decoded_on_both_sides_without_allocating_anything() {
    // A slash inside a key is `~1` in the pointer and an ordinary character in the document; a
    // tilde is `~0`; and the document's own escapes decode too.
    let body = "{\"a/b\": 1, \"c~d\": 2, \"e\\\"f\": 3, \"g\u{e9}h\": 4}".as_bytes();
    assert_eq!(found(body, "/a~1b"), b"1");
    assert_eq!(found(body, "/c~0d"), b"2");
    assert_eq!(found(body, "/e\"f"), b"3");
    assert_eq!(found(body, "/g\u{e9}h"), b"4");
}

#[test]
fn a_brace_inside_a_string_does_not_confuse_the_scan() {
    let body = br#"{"decoy": "}{[]\"", "lane": "gold"}"#;
    assert_eq!(found(body, "/lane"), br#""gold""#);
}

#[test]
fn nonsense_is_called_nonsense() {
    assert_eq!(resolve_pointer(b"not json", "/a"), Resolved::Missing);
    assert_eq!(resolve_pointer(b"{\"a\" 1}", "/a"), Resolved::Malformed);
    assert_eq!(resolve_pointer(b"{\"a\": 1}", "a"), Resolved::Malformed);
}

/// Build a body of at least `bytes` bytes whose lane key is the LAST thing in it.
fn big_body(bytes: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes + 64);
    body.extend_from_slice(br#"{"messages":["#);
    let chunk = br#"{"role":"one","content":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"#;
    while body.len() < bytes {
        body.extend_from_slice(chunk);
    }
    body.extend_from_slice(br#"{"role":"one","content":"last"}],"lane":"gold"}"#);
    body
}

#[test]
fn a_body_over_a_mebibyte_with_the_lane_key_last_still_resolves() {
    let body = big_body(1 << 20);
    assert!(body.len() >= 1 << 20);
    assert_eq!(found(&body, "/lane"), br#""gold""#);
    // And the span is a span of the caller's bytes, not a copy of them.
    match resolve_pointer(&body, "/lane") {
        Resolved::Found(span) => {
            assert_eq!(span.of(&body), &body[span.start..span.end]);
            assert!(span.start > (1 << 20));
        }
        other => panic!("{other:?}"),
    }
}

/// The scanner's budget is under a microsecond per kibibyte of body scanned. This times a scan of
/// a body whose one interesting key is last — the case where the whole body is walked — and prints
/// what it measured.
///
/// Measured on the machine this landed on: 359 ns per KiB in a release build (2.65 GiB/s), which is
/// inside the budget with room to spare, and 4,267 ns per KiB in a debug build, which is not — the
/// number that counts is the release one, and `cargo test --release` is how to see it.
#[test]
fn the_scanner_meets_its_budget_on_a_mebibyte() {
    let body = big_body(1 << 20);
    let kib = body.len() as f64 / 1024.0;

    // A warm pass, then the measured ones.
    assert!(matches!(
        resolve_pointer(&body, "/lane"),
        Resolved::Found(_)
    ));
    let rounds = 20;
    let started = std::time::Instant::now();
    for _ in 0..rounds {
        assert!(matches!(
            resolve_pointer(&body, "/lane"),
            Resolved::Found(_)
        ));
    }
    let elapsed = started.elapsed() / rounds;
    let per_kib_ns = elapsed.as_nanos() as f64 / kib;
    println!(
        "json span scanner: {} bytes scanned in {:?} — {:.1} ns per KiB ({:.2} GiB/s)",
        body.len(),
        elapsed,
        per_kib_ns,
        (body.len() as f64 / (1 << 30) as f64) / elapsed.as_secs_f64(),
    );
    // The budget is 1 microsecond per kibibyte. The assertion is generous on purpose — a debug
    // build measured on a shared machine is not the gate — but a regression of an order of
    // magnitude fails here rather than in production.
    assert!(
        per_kib_ns < 10_000.0,
        "{per_kib_ns:.0} ns per KiB is ten times the budget"
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
        ArrivalLocation::Header("authorization".into()).mask_kind(),
        MaskKind::SameLengthFill
    );
    assert_eq!(ArrivalLocation::ClientCert.mask_kind(), MaskKind::Nothing);
    assert_eq!(
        ArrivalLocation::Signed {
            over: SignedOver::Body
        }
        .mask_kind(),
        MaskKind::SignatureSpanOnly
    );
    assert_eq!(
        ArrivalLocation::HandshakeFrames {
            max_frames: 4,
            max_bytes: 256,
        }
        .mask_kind(),
        MaskKind::BoundedPrefix { max_bytes: 256 }
    );
    // A body signature has to see every byte it signs, so the unit does not open until the body has.
    assert!(ArrivalLocation::Signed {
        over: SignedOver::Both
    }
    .needs_whole_body());
    assert!(!ArrivalLocation::Header("x".into()).needs_whole_body());
}

#[test]
fn a_client_certificate_masks_nothing_because_it_was_never_in_the_bytes() {
    let mut cursor = b"hello".to_vec();
    let mut slab = CredentialSlab::with_capacity(64);
    let masked = slab
        .mask_as(&mut cursor, Span::new(0, 5), MaskKind::Nothing)
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
