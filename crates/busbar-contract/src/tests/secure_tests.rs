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
    moved_bytes()
}

/// Every byte outside `[head, end)` is zero.
fn outside_live_is_zero(s: &SecureVec) -> bool {
    s.allocation()[..s.live_range().start]
        .iter()
        .all(|b| *b == 0)
        && s.allocation()[s.live_range().end..].iter().all(|b| *b == 0)
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
    static GROWTH: [u8; 64 * 1024] = [9; 64 * 1024];
    let mut s = SecureVec::new();
    s.extend(SENTINEL).unwrap();
    let old = s.allocation().as_ptr();
    let old_len = s.capacity();
    let (grown, old_wiped, _) = crate::support::observe_wipe(old, old_len, || s.extend(&GROWTH));
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
    static LARGE: [u8; 128 * 1024] = [1; 128 * 1024];
    let mut s = SecureVec::new();
    s.extend(&LARGE).unwrap();
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

#[test]
fn secure_vec_read_into_unwind_wipes_loan() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        // Exercise an unchanged allocation, compaction, and growth before the loan.
        for (capacity, loan) in [(128, 4), (8, 4), (8, 8)] {
            let mut s = SecureVec::with_capacity(capacity).unwrap();
            s.extend(b"skipKEEP").unwrap();
            s.consume(4);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = s.read_into(loan, tail, |dst| {
                    dst[..2].copy_from_slice(b"PW");
                    panic!("reader panicked after a partial write");
                });
            }));
            assert!(result.is_err(), "the reader's panic must propagate");
            assert_eq!(s.as_slice(), b"KEEP", "prior live bytes survive");
            assert!(outside_live_is_zero(&s), "the abandoned loan is wiped");
            s.read_into(4, tail, |dst| {
                assert!(dst.iter().all(|byte| *byte == 0));
                dst[..2].copy_from_slice(b"OK");
                Ok(2)
            })
            .unwrap()
            .unwrap();
            assert_eq!(s.as_slice(), b"KEEPOK");
            assert!(outside_live_is_zero(&s));
        }
    }
}

#[test]
fn secure_vec_read_into_unwind_wipes_before_free() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let mut s = SecureVec::with_capacity(128).unwrap();
        s.extend(b"skipKEEP").unwrap();
        s.consume(4);
        let (pointer, len) = (s.allocation().as_ptr(), s.capacity());
        let (result, wiped, _) = crate::support::observe_wipe(pointer, len, || {
            std::panic::catch_unwind(move || {
                let _ = s.read_into(SENTINEL.len() + 8, tail, |dst| {
                    dst[..SENTINEL.len()].copy_from_slice(SENTINEL);
                    panic!("reader panicked while owning the buffer");
                });
            })
        });
        assert!(
            result.is_err(),
            "the buffer drops during the reader's unwind"
        );
        assert_eq!(
            wiped,
            Some(true),
            "all initialized bytes are wiped before free"
        );
    }
}

#[test]
fn secure_vec_read_into_error_wipes_loan() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let mut s = SecureVec::with_capacity(128).unwrap();
        s.extend(b"skipKEEP").unwrap();
        s.consume(4);
        let error = s
            .read_into(SENTINEL.len() + 8, tail, |dst| {
                dst[..SENTINEL.len()].copy_from_slice(SENTINEL);
                Err(io::ErrorKind::Interrupted.into())
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert_eq!(s.as_slice(), b"KEEP");
        assert!(outside_live_is_zero(&s), "Err abandons every loan byte");
    }
}

#[test]
fn secure_vec_read_into_overlong_wipes_both_tail_modes() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let mut s = SecureVec::with_capacity(128).unwrap();
        s.extend(b"skipKEEP").unwrap();
        s.consume(4);
        let error = s
            .read_into(16, tail, |dst| {
                dst.fill(0xBB);
                Ok(usize::MAX)
            })
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(s.as_slice(), b"KEEP");
        assert!(outside_live_is_zero(&s));
    }
}

#[test]
fn secure_vec_read_into_empty_and_full_success_preserve_live_bytes() {
    for tail in [Tail::Wipe, Tail::Trusted] {
        let mut s = SecureVec::with_capacity(128).unwrap();
        s.extend(b"KEEP").unwrap();
        assert_eq!(
            s.read_into(0, tail, |dst| {
                assert!(dst.is_empty());
                Ok(0)
            })
            .unwrap()
            .unwrap(),
            0
        );
        assert_eq!(
            s.read_into(4, tail, |dst| {
                dst.copy_from_slice(b"MORE");
                Ok(dst.len())
            })
            .unwrap()
            .unwrap(),
            4
        );
        assert_eq!(s.as_slice(), b"KEEPMORE");
        assert!(outside_live_is_zero(&s));
    }
}

#[test]
fn secure_vec_read_into_overflow_never_calls_reader() {
    let mut s = SecureVec::from(&b"KEEP"[..]);
    let result = s.read_into(usize::MAX, Tail::Wipe, |_| {
        panic!("allocation refusal must precede the callback");
    });
    assert!(matches!(result, Err(Overflow)));
    assert_eq!(s.as_slice(), b"KEEP");
    assert!(outside_live_is_zero(&s));
}

// SECURE-TYPES (core #164): the types that replace the banned zeroize wrapper. RED until they land.

/// RED against a wiping String wrapper that grows in place: growth moves the text into a fresh
/// block and wipes the old block before it is freed.
#[test]
fn secure_string_growth_wipes_old_block() {
    let mut s = SecureString::with_capacity(SENTINEL.len());
    s.push_str(std::str::from_utf8(SENTINEL).unwrap());
    let old = s.as_str().as_ptr();
    let old_len = s.as_str().len();
    let ((), old_wiped, _) =
        crate::support::observe_wipe(old, old_len, || s.push_str(&"x".repeat(4096)));
    assert_ne!(s.as_str().as_ptr(), old, "the text grew into a new block");
    assert_eq!(
        old_wiped,
        Some(true),
        "the old block is wiped before it is freed"
    );
    assert!(s.as_str().as_bytes().starts_with(SENTINEL), "text kept");
    assert_eq!(s.len(), SENTINEL.len() + 4096);
}

#[test]
fn secure_string_drop_wipes() {
    let s = SecureString::from(String::from_utf8(SENTINEL.to_vec()).unwrap());
    let (p, n) = (s.as_str().as_ptr(), s.len());
    let ((), wiped, _) = crate::support::observe_wipe(p, n, || drop(s));
    assert_eq!(
        wiped,
        Some(true),
        "a dropped SecureString is wiped before it is freed"
    );
}

#[test]
fn secure_vec_from_vec_drop_wipes() {
    let v = SecureVec::from(SENTINEL.to_vec());
    assert_eq!(&v[..], SENTINEL, "adopted bytes are the live bytes");
    let (p, n) = (v.as_slice().as_ptr(), v.len());
    let ((), wiped, _) = crate::support::observe_wipe(p, n, || drop(v));
    assert_eq!(
        wiped,
        Some(true),
        "a dropped SecureVec is wiped before it is freed"
    );
}

#[test]
fn secure_array_drop_wipes() {
    let a = Box::new(SecureArray::<32>::from([0x5a_u8; 32]));
    let p = a.as_ptr();
    let ((), wiped, _) = crate::support::observe_wipe(p, 32, || drop(a));
    assert_eq!(
        wiped,
        Some(true),
        "a dropped SecureArray is wiped before it is freed"
    );
}

/// RED against adopting a `Vec` as is: bytes a caller truncated away stay in the spare capacity.
#[test]
fn secure_vec_from_vec_scrubs_spare_capacity() {
    let mut raw = Vec::with_capacity(256);
    raw.extend_from_slice(b"ab");
    raw.extend_from_slice(SENTINEL);
    raw.truncate(2);
    let v = SecureVec::from(raw);
    assert_eq!(v.as_slice(), b"ab");
    assert!(
        !holds(v.allocation(), SENTINEL),
        "stale spare bytes are scrubbed"
    );
    assert!(outside_live_is_zero(&v));
}

#[test]
fn secure_vec_truncate_wipes_tail_and_zeroed_is_live_zero() {
    let mut v = SecureVec::zeroed(8);
    assert_eq!(v.as_slice(), &[0_u8; 8]);
    v.copy_from_slice(b"KEEPGONE");
    v.truncate(4);
    assert_eq!(&v[..], b"KEEP");
    assert!(!holds(v.allocation(), b"GONE"), "the cut tail is wiped");
    v.extend_from_slice(b"+1");
    assert_eq!(&v[..], b"KEEP+1");
    assert_eq!(v.into_vec(), b"KEEP+1".to_vec());
}

#[test]
fn secure_types_debug_prints_length_only() {
    let v = SecureVec::from(SENTINEL.to_vec());
    let s = SecureString::from("SENTINEL-abc");
    let a = SecureArray::<4>::from(*b"SENT");
    assert_eq!(
        format!("{v:?}"),
        format!("SecureVec {{ len: {} }}", SENTINEL.len())
    );
    assert_eq!(format!("{s:?}"), "SecureString { len: 12 }");
    assert_eq!(format!("{a:?}"), "SecureArray { len: 4 }");
}

#[test]
fn secure_string_serde_round_trip_and_constant_time_eq() {
    use serde::Deserialize as _;
    let s = SecureString::deserialize(
        serde::de::value::StrDeserializer::<serde::de::value::Error>::new("tok-1"),
    )
    .unwrap();
    assert_eq!(s.as_str(), "tok-1");
    assert_eq!(serde_saphyr::to_string(&s).unwrap().trim(), "tok-1");
    assert_eq!(s, SecureString::from("tok-1"));
    assert_ne!(s, SecureString::from("tok-2"));
    assert_eq!(s.clone(), s);
    let bytes = s.into_bytes();
    assert_eq!(bytes.as_slice(), b"tok-1");
    assert_eq!(
        SecureArray::<2>::from(*b"ab"),
        SecureArray::<2>::from(*b"ab")
    );
    assert_ne!(SecureArray::<2>::from(*b"ab"), SecureArray::<2>::zeroed());
}
