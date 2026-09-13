// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-plugin/src/lib.rs`.

use super::*;
use crate::hot::Facts;

#[test]
fn preamble_layout_is_frozen() {
    // The three frozen offsets. A change here is a MAJOR event and also trips the layout golden.
    assert_eq!(core::mem::offset_of!(AbiPreamble, magic), 0);
    assert_eq!(core::mem::offset_of!(AbiPreamble, abi_major), 8);
    assert_eq!(core::mem::offset_of!(AbiPreamble, abi_minor), 12);
    assert_eq!(core::mem::size_of::<AbiPreamble>(), 16);
}

#[test]
fn check_preamble_accepts_current_and_newer_minor() {
    assert_eq!(check_preamble(&AbiPreamble::CURRENT), Ok(()));
    let newer_minor = AbiPreamble {
        abi_minor: ABI_MINOR + 7,
        ..AbiPreamble::CURRENT
    };
    assert_eq!(check_preamble(&newer_minor), Ok(()));
}

#[test]
fn check_preamble_fails_closed_on_magic_and_major() {
    let bad_magic = AbiPreamble {
        magic: 0xDEAD_BEEF,
        ..AbiPreamble::CURRENT
    };
    assert_eq!(
        check_preamble(&bad_magic),
        Err(PreambleError::BadMagic { found: 0xDEAD_BEEF })
    );
    let bad_major = AbiPreamble {
        abi_major: ABI_MAJOR + 1,
        ..AbiPreamble::CURRENT
    };
    assert_eq!(
        check_preamble(&bad_major),
        Err(PreambleError::MajorMismatch {
            ours: ABI_MAJOR,
            theirs: ABI_MAJOR + 1,
        })
    );
}

#[test]
fn sized_field_guard_hides_truncated_tail() {
    let g = Facts::new(10, 100, 1, 0, 0, b"pool");
    // A full-size struct reveals a tail field.
    assert_eq!(read_sized_field!(&*g, g.size, Facts, flags), Some(0));
    // A sender that advertised only the preamble reveals nothing past it.
    let mut truncated = *g;
    truncated.size = 6; // size(u32)=4 + version(u16)=2 — preamble only
    assert_eq!(
        read_sized_field!(&truncated, truncated.size, Facts, flags),
        None
    );
}

#[test]
fn write_out_publishes_on_ok_and_tolerates_null() {
    let mut slot = MaybeUninit::<u64>::uninit();
    // SAFETY: `slot` is a live, writable MaybeUninit.
    unsafe { write_out(&mut slot as *mut MaybeUninit<u64>, 0x1234_u64) };
    // SAFETY: we just wrote it on the Ok path.
    assert_eq!(unsafe { slot.assume_init() }, 0x1234);
    // A null out-slot must not fault.
    // SAFETY: null is explicitly tolerated by the contract.
    unsafe { write_out(core::ptr::null_mut::<MaybeUninit<u64>>(), 99_u64) };
}

// ── The minor-20 Usage keyed-unit tail (1.6.0 M1): pack/decode + sized-guard back-compat ────────

#[test]
fn usage_units_pack_decode_round_trips() {
    use crate::hot::pod::{decode_usage_units, pack_usage_units};
    use crate::hot::{AdmissionId, Usage, UsageComponent};

    let mut units = std::collections::BTreeMap::new();
    units.insert("classifications".to_string(), 3u64);
    units.insert("search".to_string(), 42u64);
    let packed = pack_usage_units(&units);

    let key = b"vk_1";
    let model = b"cmd-r";
    let provider = b"cohere";
    let guard = Usage::with_units(
        UsageComponent::Queries,
        1,
        0,
        AdmissionId(7),
        key,
        model,
        provider,
        &packed,
    );
    // A full minor-20 Usage decodes the exact map back.
    assert_eq!(unsafe { decode_usage_units(&*guard) }, units);
}

#[test]
fn usage_units_tail_hidden_from_a_pre_minor_20_sender() {
    use crate::hot::pod::{decode_usage_units, pack_usage_units};
    use crate::hot::{AdmissionId, Usage, UsageComponent};

    let mut units = std::collections::BTreeMap::new();
    units.insert("search".to_string(), 9u64);
    let packed = pack_usage_units(&units);
    let guard = Usage::with_units(
        UsageComponent::Queries,
        1,
        0,
        AdmissionId(1),
        b"k",
        b"m",
        b"p",
        &packed,
    );

    // Simulate an older peer that advertised only the minor-5 size (pre-units __size = 80): the
    // sized-struct guard must hide `units_ptr`/`units_len`, so the host bills via the legacy scalar.
    let mut old = *guard;
    old.size = 80;
    assert_eq!(read_sized_field!(&old, old.size, Usage, units_ptr), None);
    assert!(
        unsafe { decode_usage_units(&old) }.is_empty(),
        "a pre-minor-20 sender must expose NO keyed units (append-only back-compat)"
    );

    // The current sender (full size) still exposes them.
    assert_eq!(unsafe { decode_usage_units(&*guard) }, units);
}

/// The sized-field guard must be safe to point at a peer buffer that is SHORTER than the struct it
/// describes. Reading through a `&Usage` cannot be: the reference asserts the full 96 bytes are a
/// valid, dereferenceable `Usage` the instant it is formed, which over a 64-byte peer buffer is a
/// claim about memory that does not exist. The pointer form makes the advertised size the only thing
/// consulted, and touches nothing past it.
#[test]
fn sized_field_guard_reads_a_buffer_shorter_than_the_struct() {
    use crate::hot::pod::decode_usage_units;
    use crate::hot::Usage;

    // A peer that advertises only the pre-units prefix, in a buffer that is only that long — there
    // are no bytes at all where `units_ptr`/`units_len` would sit.
    const PREFIX: usize = 64;
    // Deliberately a HEAP buffer, not the array clippy would prefer: the point of the test is that
    // the allocation ENDS at `PREFIX`, so a read past it is a real out-of-bounds access that Miri or
    // ASan will flag. A stack array is surrounded by other live stack bytes and would swallow it.
    #[allow(clippy::useless_vec)]
    let mut buf = vec![0u8; PREFIX];
    buf[..4].copy_from_slice(&(PREFIX as u32).to_ne_bytes());
    let p = buf.as_ptr().cast::<Usage>();

    // `p` addresses `PREFIX` live bytes whose leading `size` says exactly that; the guard reads
    // nothing beyond it.
    assert_eq!(read_sized_field!(p, PREFIX as u32, Usage, units_ptr), None);
    assert_eq!(read_sized_field!(p, PREFIX as u32, Usage, units_len), None);
    // SAFETY: as above — the hidden tail means the decoder yields an empty map without a read.
    assert!(unsafe { decode_usage_units(p) }.is_empty());
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The borrowed-range read discipline and the capped out-buffer write.
//
// Every host-call slot that takes an ABI `(ptr, len)` or fills a caller `(buf, cap)` obeys the same
// four rules, and until now each slot kept its own copy of them. These cells assert the rules on the
// ONE definition, which is what makes the copies deletable.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A capped write NEVER writes past `cap`, and reports what it actually wrote — the length a POD's
/// `*_len` field is filled from. A short buffer TRUNCATES rather than refusing, because the reason is
/// advisory: the status class is the answer, the bytes are the explanation.
#[test]
fn write_capped_truncates_at_the_cap_and_reports_what_it_wrote() {
    let mut buf = [0u8; 4];
    // SAFETY: `buf` is a live writable range of exactly `cap` bytes.
    let n = unsafe { write_capped(buf.as_mut_ptr(), buf.len(), b"abcdefgh") };
    assert_eq!(n, 4);
    assert_eq!(&buf, b"abcd");

    let mut exact = [0u8; 8];
    // SAFETY: as above.
    let n = unsafe { write_capped(exact.as_mut_ptr(), exact.len(), b"abcdefgh") };
    assert_eq!(n, 8);
    assert_eq!(&exact, b"abcdefgh");
}

/// A null out-buffer, or a zero cap, writes NOTHING and reports zero — the ABI's "the caller does not
/// want the bytes" encoding. A slot that dereferenced either would fault on a caller who legitimately
/// asked only for the status.
#[test]
fn write_capped_tolerates_a_null_buffer_and_a_zero_cap() {
    // SAFETY: a null buffer is the tolerated absent-slot encoding; nothing is dereferenced.
    assert_eq!(
        unsafe { write_capped(core::ptr::null_mut(), 16, b"abc") },
        0
    );
    let mut buf = [0u8; 4];
    // SAFETY: `buf` is live; a zero cap means no byte of it may be touched.
    assert_eq!(unsafe { write_capped(buf.as_mut_ptr(), 0, b"abc") }, 0);
    assert_eq!(
        &buf, b"\0\0\0\0",
        "a zero cap wrote into the caller's buffer"
    );
}

/// An absent borrowed range — null pointer OR zero length — is an EMPTY view, never a dereference.
/// This is the rule that lets a POD spell an optional field as `(null, 0)`.
#[test]
fn an_absent_borrowed_range_is_empty_and_never_dereferenced() {
    // SAFETY: both forms are the absent encoding; neither pointer is read.
    unsafe {
        assert!(borrow_bytes(core::ptr::null(), 16).is_empty());
        assert!(borrow_bytes(b"abc".as_ptr(), 0).is_empty());
        assert_eq!(borrow_str(core::ptr::null(), 16), None);
        assert_eq!(borrow_str(b"abc".as_ptr(), 0), None);
        assert_eq!(borrow_string_lossy(core::ptr::null(), 16), "");
        assert_eq!(borrow_string_lossy(b"abc".as_ptr(), 0), "");
    }
}

/// The two string readings of a live range are DELIBERATELY different, and the difference is the
/// caller's fail-closed posture: `borrow_str` REFUSES non-UTF-8 (`None` drives the slot's refusal),
/// `borrow_string_lossy` SUBSTITUTES (a metering label or a pool name is recorded, never dropped).
/// A slot that picked the wrong one would either refuse a legal call or admit an illegal one.
#[test]
fn the_two_string_readings_split_on_invalid_utf8() {
    let good = b"pool-a";
    let bad = [0xffu8, 0xfe, 0xfd];
    // SAFETY: both are live, initialized ranges for the call.
    unsafe {
        assert_eq!(borrow_str(good.as_ptr(), good.len()), Some("pool-a"));
        assert_eq!(borrow_string_lossy(good.as_ptr(), good.len()), "pool-a");
        assert_eq!(borrow_str(bad.as_ptr(), bad.len()), None);
        assert_eq!(
            borrow_string_lossy(bad.as_ptr(), bad.len()),
            "\u{fffd}\u{fffd}\u{fffd}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The length-prefixed record framing.
//
// This shape was decoded in four places — `EgressDesc`'s argv, its child environment, `Usage`'s unit
// tail — and the only rule that matters is what each does with a MALFORMED block. Three of the four
// copies were on core's side of the ABI and were exercised only through it, so the rule is asserted
// here, on the definition they now share.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Build a framed block: each item as a little-endian `u32` length then its bytes.
fn framed(items: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for it in items {
        out.extend_from_slice(&(it.len() as u32).to_le_bytes());
        out.extend_from_slice(it);
    }
    out
}

/// A well-formed block reads back every record in order and lands the index exactly on the end —
/// which is how a caller's `while i < bytes.len()` loop terminates rather than spinning.
#[test]
fn a_framed_block_reads_back_every_record_and_lands_on_the_end() {
    let bytes = framed(&[b"/usr/bin/env", b"-i", b"", b"prog"]);
    let mut i = 0usize;
    let mut got: Vec<&[u8]> = Vec::new();
    while i < bytes.len() {
        got.push(read_len_prefixed(&bytes, &mut i).expect("well-formed record"));
    }
    assert_eq!(
        got,
        vec![&b"/usr/bin/env"[..], &b"-i"[..], &b""[..], &b"prog"[..]]
    );
    assert_eq!(i, bytes.len(), "the index must land exactly on the end");
    // An empty record is a legitimate zero-length value, NOT the end of the block: the third item
    // above is empty and the fourth still read back.
}

/// A PARTIAL LENGTH WORD stops the read. The index is left on the malformed boundary, never advanced
/// past the end — a caller that kept reading would otherwise walk off the block.
#[test]
fn a_partial_length_word_stops_the_read_without_advancing() {
    let mut bytes = framed(&[b"ok"]);
    bytes.extend_from_slice(&[0x01, 0x00]); // two bytes of a four-byte length word
    let mut i = 0usize;
    assert_eq!(read_len_prefixed(&bytes, &mut i), Some(&b"ok"[..]));
    let at_tail = i;
    assert_eq!(read_len_prefixed(&bytes, &mut i), None);
    assert_eq!(i, at_tail, "a refused read must not advance the index");
}

/// A LENGTH THAT CLAIMS MORE BYTES THAN REMAIN stops the read — the truncation that matters, because
/// it is what a sender at a newer minor looks like, and what a hostile sender would write to make a
/// host read past the block it was handed.
#[test]
fn a_length_claiming_more_than_the_block_holds_is_refused() {
    let mut bytes = (9u32).to_le_bytes().to_vec();
    bytes.extend_from_slice(b"only4"); // claims 9, holds 5
    let mut i = 0usize;
    assert_eq!(read_len_prefixed(&bytes, &mut i), None);
    assert_eq!(i, 0, "a refused read must not advance the index");

    // The same refusal at the arithmetic extreme: a length word near `usize::MAX` must not wrap.
    let mut huge = (u32::MAX).to_le_bytes().to_vec();
    huge.extend_from_slice(b"x");
    let mut j = 0usize;
    assert_eq!(read_len_prefixed(&huge, &mut j), None);
}

/// The bare length word reads independently and advances by exactly four — the arm `EgressDesc`'s
/// environment block uses, where a record is `name_len, name, value_len, value` and the lengths are
/// read before their bodies.
#[test]
fn the_bare_length_word_advances_by_exactly_four() {
    let bytes = [0x2a, 0x00, 0x00, 0x00, 0xff];
    let mut i = 0usize;
    assert_eq!(read_u32_le(&bytes, &mut i), Some(42));
    assert_eq!(i, 4);
    assert_eq!(read_u32_le(&bytes, &mut i), None, "one byte is not a word");
    assert_eq!(i, 4, "a refused read must not advance the index");
}
