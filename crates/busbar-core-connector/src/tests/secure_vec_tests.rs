// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connector's per-thread scratch slots over the wiping buffer (T11-dev, T6). The buffer's own
//! tests moved with it to busbar-contract (src/tests/secure_tests.rs).

use super::*;

const SENTINEL: &[u8] = b"Authorization: Bearer SENTINEL-0123456789";

// ---- T11-dev: the lent region and the scratch slot ----

fn misses() -> usize {
    SCRATCH_MISSES.with(Cell::get)
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
        inner.extend(&vec![2_u8; 64 * 1024]).unwrap();
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

/// T6 has its own slot: holding the carrier read's scratch never empties the TLS plaintext's.
#[test]
fn scratch_slots_are_independent() {
    let before = misses();
    let mut read = Scratch::take(&READ_SCRATCH);
    read.extend(b"ciphertext").unwrap();
    let mut plain = Scratch::take(&TLS_PLAIN);
    plain.extend(b"plaintext").unwrap();
    assert_eq!(misses(), before, "neither taker found its slot held");
    assert_eq!(read.as_slice(), b"ciphertext");
    assert_eq!(plain.as_slice(), b"plaintext");
}
