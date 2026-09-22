// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/mask.rs`'s `CredentialSlab`: the three credential-handling
//! hazards named as Part 2 #53's own top risk — a raw-plaintext `Debug`, a `clear()` that forgets
//! the byte count but not the bytes, and a slab that reaches the allocator without either.
//!
//! Every test plants a DISTINCTIVE secret value and asserts its ABSENCE (from the `Debug`
//! rendering, from the buffer after the wipe the drop path performs) — never a real secret, and
//! never an assertion that would require printing one to fail informatively.

use super::*;

/// CREDENTIAL PLAINTEXT IN `Debug` (Part 2 #53). A derived `Debug` on `CredentialSlab` would print
/// `buf` — raw client-credential plaintext — verbatim into any `{:?}` of a containing struct: a log
/// line, a panic message, a trace span. The hand-written impl must redact it.
///
/// Both assertions matter, not just the ASCII one: a DERIVED `Debug` on `Vec<u8>` renders as a
/// decimal byte array (`[97, 45, 100, ...]`), so the secret's ASCII text never appears verbatim
/// either way — that substring check alone would NOT have caught a regression back to
/// `#[derive(Debug)]` (confirmed red-before-green: it was the `REDACTED`-presence assertion that
/// actually failed). The decimal array is exactly as much a leak as the ASCII would be — every byte
/// is still fully recoverable from it — so the marker's presence is the assertion doing the real
/// work here.
#[test]
fn debug_never_prints_the_credential_bytes() {
    let mut slab = CredentialSlab::with_capacity(64);
    let mut cursor = b"a-distinctive-secret-marker-93f7a1".to_vec();
    let span = Span::new(0, cursor.len());
    let masked = slab.mask(&mut cursor, span).expect("room in the slab");
    // Precondition: the secret really is in the slab, or the absence assertion below proves
    // nothing.
    assert_eq!(slab.read(masked), b"a-distinctive-secret-marker-93f7a1");

    let rendered = format!("{slab:?}");
    assert!(
        !rendered.contains("a-distinctive-secret-marker-93f7a1"),
        "Debug output must never contain the credential plaintext (ASCII form), got: {rendered}"
    );
    // The non-secret shape survives — useful for diagnosing a `CredentialBudget` refusal without
    // ever printing the credential that triggered it.
    assert!(rendered.contains("CredentialSlab"));
    assert!(
        rendered.contains("REDACTED"),
        "buf must be redacted, not rendered as a raw byte array (a decimal array leaks the \
         credential just as much as ASCII would), got: {rendered}"
    );
    assert!(rendered.contains("64"), "the capacity is not a secret");
}

/// NO `Drop` (Part 2 #53, the third hazard). `clear()` is the IN-BAND UPGRADE path; nothing obliges
/// the ordinary end of a connection — or an unwind past it — to call anything at all. A slab that
/// goes out of scope without one hands its allocation back to the allocator still holding every
/// credential byte it ever copied out of a cursor.
///
/// HOW THIS IS MADE SOUND. Reading a value after its own `Drop` has run is a read of freed memory,
/// so this test does not do that. It proves the two halves separately, and both inside safe Rust:
///
/// 1. **That `Drop` wipes** — observably. `Drop` delegates to `CredentialSlab::wipe`, which
///    overwrites `0..len` IN PLACE and leaves the length alone; the test calls exactly what `drop`
///    calls and then reads every byte straight back out of a LIVE slab. No `unsafe`, no freed
///    region, no spare capacity (which safe Rust cannot slice, and which is the reason `clear`'s
///    truncating wipe could not be checked this way at all).
/// 2. **That `Drop` is wired to it** — by source review, the same technique
///    `clear_zeroizes_rather_than_merely_truncating` above and `plugins_boot_logging_wording_present`
///    (`crates/busbar-kernel/src/tests/tests.rs`) already use for the parts of a guarantee that
///    cannot be observed at runtime. This catches the regression that matters — someone deleting the
///    call, or swapping it for something that does not overwrite — the moment it is typed.
#[test]
fn the_drop_path_overwrites_every_credential_byte() {
    const NEEDLE: &[u8] = b"a-second-distinctive-secret-5c02de";

    // (2) The wiring. `Drop` must go through the wipe; a `drop` body that did anything else would
    // leave the bytes in the allocation no matter how well `wipe` works.
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mask.rs"));
    let drop_fn = src
        .split("impl Drop for CredentialSlab {")
        .nth(1)
        .expect(
            "CredentialSlab must have a Drop impl in src/mask.rs — without one a slab freed \
             without an explicit clear() goes back to the allocator holding a credential",
        )
        .split("\n}")
        .next()
        .expect("the Drop impl must close");
    assert!(
        drop_fn.contains("self.wipe()"),
        "Drop regressed to not wiping the buffer. Body was: {drop_fn}"
    );

    // (1) The wipe itself, observed on a live slab.
    let mut slab = CredentialSlab::with_capacity(64);
    let mut cursor = NEEDLE.to_vec();
    let span = Span::new(0, cursor.len());
    let masked = slab.mask(&mut cursor, span).expect("room in the slab");
    // Precondition: the secret really is in the buffer, or the absence assertion below proves
    // nothing at all.
    assert_eq!(slab.read(masked), NEEDLE);
    assert!(
        slab.buf.windows(NEEDLE.len()).any(|w| w == NEEDLE),
        "precondition: the credential is in the slab's own allocation before the wipe"
    );

    slab.wipe();

    assert!(
        !slab.buf.windows(NEEDLE.len()).any(|w| w == NEEDLE),
        "the credential bytes must not survive the wipe the drop path performs"
    );
    assert!(
        slab.buf.iter().all(|byte| *byte == 0),
        "every byte the slab was holding must be zero after the wipe, got: {:?}",
        slab.buf
    );
    assert_eq!(
        slab.buf.len(),
        NEEDLE.len(),
        "the wipe leaves the LENGTH alone — that is precisely what makes it readable back, and so \
         checkable, without reading a Vec's spare capacity or a freed allocation"
    );
}

/// NO ZEROIZE (Part 2 #53). A bare `Vec::clear()` only drops the length; the allocation still holds
/// every byte the credential ever occupied. `clear()` must overwrite them, not just forget the
/// count.
///
/// The overwrite cannot be PROVEN by reading the allocation from here: this crate carries
/// `#![deny(unsafe_code)]` everywhere outside the audited `plane_host` FFI seam (`crate::lib`'s own
/// words: "every other module still hard-fails on unsafe"), and `mask.rs` is not that seam. That is
/// not a gap in this test — it is the reflection of the exact guarantee the fix relies on: safe Rust
/// structurally refuses a caller a slice over a `Vec`'s SPARE capacity, so nothing outside `unsafe`
/// (a heap dump, a core file, a use-after-free elsewhere in the process) can read what a `Vec` is no
/// longer accounting for, either. Proving physical zeroing is therefore the `zeroize` crate's own
/// job — a RustCrypto crate whose OWN test suite exercises exactly the raw-memory read this one
/// cannot, and the reason it is a workspace dependency at all (see `plane_host::creds::Mint::secret`
/// for the sibling use). What THIS test proves is the two halves that stay inside this crate's
/// remit: (1) a SOURCE review — the same technique `plugins_boot_logging_wording_present`
/// (`crates/busbar-kernel/src/tests/tests.rs`) already uses for other runtime-unprovable text — that
/// `clear()` actually calls `Zeroize::zeroize`, so a regression back to a bare `Vec::clear()` is
/// caught the moment it is typed, not only in a memory forensics tool nobody ran; and (2) the full
/// observable CONTRACT `clear()` promises through the safe API: the slab reports itself empty
/// afterward, and its capacity — the "frame path never allocates" invariant this type documents — is
/// preserved, not shrunk.
#[test]
fn clear_zeroizes_rather_than_merely_truncating() {
    let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/mask.rs"));
    let clear_fn = src
        .split("pub fn clear(&mut self) {")
        .nth(1)
        .expect("CredentialSlab::clear must exist in src/mask.rs")
        .split("\n    }\n")
        .next()
        .expect("clear()'s body must close");
    assert!(
        clear_fn.contains("self.buf.zeroize()"),
        "clear() regressed to not calling Zeroize::zeroize — a bare Vec::clear() only drops the \
         length and leaves every credential byte sitting in the allocation. Body was: {clear_fn}"
    );

    let mut slab = CredentialSlab::with_capacity(64);
    let mut cursor = b"a-third-distinctive-secret-4b91aa".to_vec();
    let span = Span::new(0, cursor.len());
    let masked = slab.mask(&mut cursor, span).expect("room in the slab");
    // Precondition: the secret really is in the slab.
    assert_eq!(slab.read(masked), b"a-third-distinctive-secret-4b91aa");
    assert_eq!(slab.remaining(), 64 - cursor.len());

    slab.clear();

    assert_eq!(slab.used(), 0, "clear() must empty the slab's logical length");
    assert_eq!(
        slab.remaining(),
        64,
        "clear() must not shrink the allocation — the frame path relies on never allocating"
    );
}
