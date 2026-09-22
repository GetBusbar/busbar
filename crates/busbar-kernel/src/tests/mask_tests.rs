// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-kernel/src/mask.rs`'s `CredentialSlab`: the two credential-handling
//! hazards named as Part 2 #53's own top risk — a raw-plaintext `Debug` and a `clear()` that
//! forgets the byte count but not the bytes.
//!
//! Both tests plant a DISTINCTIVE secret value and assert its ABSENCE (from the `Debug` rendering,
//! from the post-`clear()` allocation) — never a real secret, and never an assertion that would
//! require printing one to fail informatively.

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
