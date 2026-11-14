// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CORE WIPING BUFFER (TRANSPORT-TLS §2.0): consume is wipe-and-advance, the read surface is
//! the live bytes only, compaction and growth move each byte at most a bounded number of times, and
//! nothing a buffer released stays readable in its allocation.

use super::*;

const SENTINEL: &[u8] = b"Authorization: Bearer SENTINEL-0123456789";

fn holds(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn moved_so_far() -> usize {
    MOVED.with(std::cell::Cell::get)
}

/// Every byte outside `[head, end)` is zero.
fn outside_live_is_zero(s: &SecureVec) -> bool {
    s.v[..s.head].iter().all(|b| *b == 0) && s.v[s.end..].iter().all(|b| *b == 0)
}

/// RED against a front-memmove `consume`: consuming moves nothing, it advances the view.
#[test]
fn secure_vec_consume_is_linear() {
    let mut s = SecureVec::new();
    s.extend(&[7_u8; 4096]).unwrap();
    let before = s.as_slice().as_ptr() as usize;
    let moved = moved_so_far();
    s.consume(1000);
    assert_eq!(s.len(), 3096);
    assert_eq!(
        s.as_slice().as_ptr() as usize,
        before + 1000,
        "consume advances the head; it never moves the live bytes to the front"
    );
    assert_eq!(moved_so_far(), moved, "consume moves no byte");
}

/// RED against `as_slice` over `[0, end)`: the consumed prefix is never part of a view.
#[test]
fn secure_vec_views_exclude_consumed_prefix() {
    let mut s = SecureVec::new();
    s.extend(b"abcdef").unwrap();
    s.consume(2);
    assert_eq!(s.as_slice(), b"cdef");
    s.extend(b"gh").unwrap();
    assert_eq!(s.as_slice(), b"cdefgh");
    assert_eq!(s.len(), 6);
    assert_eq!(
        format!("{s:?}"),
        "SecureVec { len: 6 }",
        "Debug never prints bytes"
    );
}

#[test]
fn secure_vec_wipes_consumed_prefix() {
    let mut s = SecureVec::new();
    s.extend(SENTINEL).unwrap();
    s.extend(&[1_u8; 100]).unwrap();
    s.consume(SENTINEL.len());
    assert!(
        !holds(s.allocation(), SENTINEL),
        "the consumed head is wiped"
    );
    assert!(outside_live_is_zero(&s));
    s.extend(SENTINEL).unwrap();
    s.clear();
    assert!(s.is_empty());
    assert!(
        s.allocation().iter().all(|b| *b == 0),
        "a cleared buffer is all zero"
    );
}

#[test]
fn secure_vec_compacts_only_when_half_consumed() {
    // Less than half consumed: the buffer grows rather than moving the live bytes.
    let mut s = SecureVec::new();
    s.extend(&[3_u8; 1024]).unwrap();
    assert_eq!(s.capacity(), 1024);
    s.consume(400);
    s.extend(&[4_u8; 100]).unwrap();
    assert_eq!(s.capacity(), 2048, "624 live > 400 consumed: grow");
    assert_eq!(s.len(), 724);

    // At least half consumed: the live bytes move to the front, in place, and the rest is zero.
    let mut s = SecureVec::new();
    s.extend(&[5_u8; 1024]).unwrap();
    let base = s.allocation().as_ptr() as usize;
    s.consume(600);
    s.extend(&[6_u8; 100]).unwrap();
    assert_eq!(s.capacity(), 1024, "424 live <= 600 consumed: compact");
    assert_eq!(
        s.as_slice().as_ptr() as usize,
        base,
        "compacted to the front"
    );
    assert_eq!(&s.as_slice()[..424], &[5_u8; 424][..]);
    assert_eq!(&s.as_slice()[424..], &[6_u8; 100][..]);
    assert!(
        outside_live_is_zero(&s),
        "compaction wipes the vacated span"
    );
}

#[test]
fn secure_vec_growth_wipes_old_block() {
    let mut s = SecureVec::new();
    s.extend(SENTINEL).unwrap();
    let old = s.allocation().as_ptr();
    let old_len = s.capacity();
    let (grown, old_wiped, _) =
        crate::support::observe_wipe(old, old_len, || s.extend(&[9_u8; 64 * 1024]));
    grown.unwrap();
    assert_ne!(
        s.allocation().as_ptr(),
        old,
        "the buffer grew into a new block"
    );
    assert_eq!(
        old_wiped,
        Some(true),
        "the old block is wiped before it is freed"
    );
    assert_eq!(&s.as_slice()[..SENTINEL.len()], SENTINEL, "live bytes kept");
}

#[test]
fn secure_vec_shrink_only_when_empty() {
    let mut s = SecureVec::new();
    s.extend(&[1_u8; 128 * 1024]).unwrap();
    let grown = s.capacity();
    assert!(grown >= 128 * 1024);
    s.consume(100);
    s.shrink_when_empty(64 * 1024);
    assert_eq!(s.capacity(), grown, "live bytes: never shrunk");
    s.clear();
    s.shrink_when_empty(64 * 1024);
    assert_eq!(s.capacity(), 64 * 1024, "empty: shrunk to the kept extent");
    assert!(s.allocation().iter().all(|b| *b == 0));
    s.extend(b"x").unwrap();
    assert_eq!(s.as_slice(), b"x");
}

/// A slow reader: 1 MiB queued in 4 KiB writes while the far end takes 1 KiB per write. Every
/// byte is moved (compaction or growth) at most twice on average.
#[test]
fn out_backpressure_moves_at_most_2x() {
    const TOTAL: usize = 1 << 20;
    let mut s = SecureVec::new();
    let start = moved_so_far();
    let mut queued = 0;
    let mut taken = 0;
    while queued < TOTAL {
        s.extend(&[8_u8; 4096]).unwrap();
        queued += 4096;
        for _ in 0..3 {
            let n = s.len().min(1024);
            s.consume(n);
            taken += n;
        }
    }
    while !s.is_empty() {
        let n = s.len().min(1024);
        s.consume(n);
        taken += n;
    }
    assert_eq!(taken, TOTAL);
    let moved = moved_so_far() - start;
    assert!(
        moved <= 2 * TOTAL,
        "moved {moved} bytes for {TOTAL} queued: at most 2x"
    );
}

// ---- T11-dev: the lent region and the scratch slot ----

fn misses() -> usize {
    SCRATCH_MISSES.with(Cell::get)
}

#[test]
fn secure_vec_read_into_wipes_untrusted_tail() {
    let mut s = SecureVec::new();
    let got = s
        .read_into(4096, Tail::Wipe, |dst| {
            assert!(dst.iter().all(|b| *b == 0), "the lent region is zero");
            dst.fill(0xAA);
            Ok(10)
        })
        .unwrap()
        .unwrap();
    assert_eq!(got, 10);
    assert_eq!(s.as_slice(), &[0xAA_u8; 10][..]);
    assert!(
        outside_live_is_zero(&s),
        "bytes the reader wrote past its count are wiped"
    );
}

#[test]
fn secure_vec_read_into_rejects_overlong_count() {
    let mut s = SecureVec::new();
    let r = s
        .read_into(64, Tail::Wipe, |dst| {
            dst.fill(0xBB);
            Ok(65)
        })
        .unwrap();
    assert_eq!(r.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert!(s.is_empty(), "nothing of a broken count is kept");
    assert!(
        s.allocation().iter().all(|b| *b == 0),
        "the lent region is wiped"
    );
}

/// A fake carrier writing past its count: the next lend of the same slot sees only zeros.
#[test]
fn carrier_untrusted_reader_tail_is_wiped() {
    {
        let mut scratch = Scratch::take(&READ_SCRATCH);
        let n = scratch
            .read_into(16 * 1024, Tail::Wipe, |dst| {
                dst.fill(0xCC);
                Ok(100)
            })
            .unwrap()
            .unwrap();
        assert_eq!(n, 100);
    }
    let mut scratch = Scratch::take(&READ_SCRATCH);
    assert!(scratch.is_empty());
    scratch
        .read_into(16 * 1024, Tail::Wipe, |dst| {
            assert!(
                dst.iter().all(|b| *b == 0),
                "the next lend sees zeros, never the last reader's bytes"
            );
            Ok(0)
        })
        .unwrap()
        .unwrap();
}

/// A `?` between take and put: the guard wipes what it held and puts it back.
#[test]
fn read_scratch_returned_wiped_on_error() {
    fn feed_fails() -> Result<(), ()> {
        Err(())
    }
    fn failing() -> Result<(), ()> {
        let mut scratch = Scratch::take(&READ_SCRATCH);
        scratch.extend(SENTINEL).map_err(|_| ())?;
        feed_fails()?;
        Ok(())
    }
    assert!(failing().is_err());
    READ_SCRATCH.with(|slot| {
        let held = slot.take().expect("the slot came back");
        assert!(held.is_empty());
        assert!(held.allocation().iter().all(|b| *b == 0), "returned wiped");
        slot.set(Some(held));
    });
}

/// A re-entrant take on one thread gets its own buffer, never an alias; the slot keeps the larger.
#[test]
fn read_scratch_reentrant_never_aliases() {
    let before = misses();
    let mut outer = Scratch::take(&READ_SCRATCH);
    outer.extend(&[1_u8; 2048]).unwrap();
    {
        let mut inner = Scratch::take(&READ_SCRATCH);
        assert_eq!(misses(), before + 1, "the inner taker found the slot held");
        inner.extend(&[2_u8; 64 * 1024]).unwrap();
        assert_ne!(inner.as_slice().as_ptr(), outer.as_slice().as_ptr());
        assert_eq!(
            outer.as_slice(),
            &[1_u8; 2048][..],
            "the outer bytes are untouched"
        );
    }
    drop(outer);
    READ_SCRATCH.with(|slot| {
        let kept = slot.take().expect("the slot holds a buffer");
        assert!(kept.capacity() >= 64 * 1024, "the larger buffer is kept");
        assert!(kept.allocation().iter().all(|b| *b == 0));
        slot.set(Some(kept));
    });
}
