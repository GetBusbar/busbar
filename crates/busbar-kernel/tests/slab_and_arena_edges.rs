// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The edges of the two buffers: the arena's span writes, and the slab's two budgets.
//!
//! Everything here is a boundary — the byte that just fits, the byte that does not, the count after
//! a clear, the message a refusal renders. The wider behaviour of both buffers is proven beside
//! this file; what is proven here is that each of those edges is where the code says it is, so a
//! comparison that slips by one, a counter that answers a constant or a clear that clears nothing
//! is a red cell rather than a silent change of a budget.

use busbar_kernel::arena::{Arena, ArenaFull, CredentialSlab, FILL_BYTE};
use busbar_kernel::grammar::Span;

/// A refusal says what was asked for and what was left, in its own words.
///
/// The arena's refusal is carried rather than panicked, so the message is the only thing an
/// operator reading a log has. A `Display` that renders nothing is a refusal that reports a budget
/// nobody can size.
#[test]
fn an_arena_refusal_renders_what_was_asked_for_and_what_was_left() {
    let full = ArenaFull {
        requested: 4_097,
        remaining: 12,
    };
    let rendered = full.to_string();
    assert!(
        rendered.contains("4097") && rendered.contains("12"),
        "both figures belong in the message, got {rendered:?}"
    );
    assert!(!rendered.is_empty());
}

/// A write that exactly fills the span it was handed is a write, not a refusal.
///
/// The bound is `bytes.len() > span.len()`. One byte either side of it is the whole rule: the
/// exact fit lands, and the byte past it is refused with the span's own size as the remainder.
#[test]
fn a_write_that_exactly_fills_its_span_lands_and_one_byte_more_is_refused() {
    let mut arena = Arena::new();
    let span = arena.take(4).expect("the arena has room");

    arena.write(span, b"abcd").expect("an exact fit is a write");
    assert_eq!(arena.read(span), b"abcd");

    let refused = arena
        .write(span, b"abcde")
        .expect_err("one byte past the span is not the arena's to give");
    assert_eq!(refused.requested, 5);
    assert_eq!(refused.remaining, 4, "the span's size, not the arena's");
}

/// A masked credential is not empty, and the slab counts the bytes it took.
///
/// `used` and `is_empty` are what every budget above them is computed from: a slab that always
/// answers zero used, or a handle that always answers empty, is a credential the auth unit reads
/// back as nothing at all.
#[test]
fn the_slab_counts_the_bytes_it_took_and_the_handle_says_it_is_not_empty() {
    let mut cursor = b"secret-token and more".to_vec();
    let mut slab = CredentialSlab::with_capacity(64);
    assert_eq!(slab.used(), 0, "a fresh slab holds nothing");
    assert_eq!(slab.remaining(), 64);

    let masked = slab
        .mask(&mut cursor, Span::new(0, 12))
        .expect("room in the slab");
    assert_eq!(masked.len(), 12);
    assert!(!masked.is_empty(), "twelve bytes is not nothing");
    assert_eq!(slab.used(), 12, "the slab holds what it took");
    assert_eq!(
        slab.remaining(),
        52,
        "what is left is the cap less what is held"
    );
    assert_eq!(slab.read(masked), b"secret-token");
    assert_eq!(cursor[0], FILL_BYTE);
}

/// The two budgets refuse the byte past their edge and admit the byte on it.
///
/// The cursor budget is `span.end > cursor.len()` and the slab budget is
/// `span.len() > remaining()`. A span that ends exactly at the last byte of the cursor is IN the
/// cursor, and a credential that exactly fills what the slab has left fits in it — so both edges
/// are masked here, and only the byte past each is refused.
#[test]
fn a_span_that_ends_on_the_last_byte_and_a_credential_that_exactly_fits_are_both_masked() {
    let mut cursor = b"0123456789".to_vec();
    let mut slab = CredentialSlab::with_capacity(10);

    // The span ends exactly at the end of the cursor: inside it, not past it.
    let masked = slab
        .mask(&mut cursor, Span::new(6, 10))
        .expect("a span that ends on the last byte is in the cursor");
    assert_eq!(slab.read(masked), b"6789");
    assert_eq!(slab.remaining(), 6);

    // And a credential that exactly fills what is left fits: the refusal is at one byte more.
    let mut second = b"abcdefg".to_vec();
    let exact = slab
        .mask(&mut second, Span::new(0, 6))
        .expect("exactly the remaining bytes still fit");
    assert_eq!(slab.read(exact), b"abcdef");
    assert_eq!(slab.remaining(), 0);
    assert_eq!(
        slab.mask(&mut second, Span::new(0, 1)),
        Err(busbar_caps::ReasonCode::CredentialBudget),
        "a full slab has nothing left to give"
    );
}

/// A cleared slab holds nothing, and says so.
///
/// The clear runs when a connection upgrades in band, where the facts and the principal are cleared
/// too. A clear that clears nothing leaves the last credential of the pre-upgrade connection
/// readable to the one after it, and leaves the slab's budget spent for the life of the connection.
#[test]
fn a_cleared_slab_holds_nothing_and_has_its_whole_budget_back() {
    let mut cursor = b"secret-token".to_vec();
    let mut slab = CredentialSlab::with_capacity(32);
    let masked = slab
        .mask(&mut cursor, Span::new(0, 12))
        .expect("room in the slab");
    assert_eq!(slab.read(masked), b"secret-token");
    assert_eq!(slab.used(), 12);

    slab.clear();
    assert_eq!(slab.used(), 0, "the credential is gone");
    assert_eq!(slab.remaining(), 32, "and the budget is whole again");

    // And the next credential starts at the beginning of the slab rather than after the old one.
    let mut next = b"second-token".to_vec();
    let after = slab
        .mask(&mut next, Span::new(0, 12))
        .expect("room in the slab");
    assert_eq!(slab.read(after), b"second-token");
    assert_eq!(slab.used(), 12);
}
