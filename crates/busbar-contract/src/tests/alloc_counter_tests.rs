// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The counting allocator counts, per thread, and the freed-key witness sees an unzeroed key and
//! not a zeroised one. This crate's own test binary installs [`super::Counting`] as its
//! `#[global_allocator]` (`lib.rs`).

use super::{
    allocations, allocations_of, allocations_with, freed_unzeroed, last_seen, marked_key, reset,
    watch, WINDOW,
};

/// The counter counts: this crate's own test binary installs [`super::Counting`] as its
/// `#[global_allocator]` (`lib.rs`), so a heap allocation moves this thread's count and a call
/// that allocates nothing does not.
#[test]
fn the_counter_counts_this_threads_allocations() {
    let one = allocations_of(|| {
        let v: Vec<u8> = Vec::with_capacity(64);
        std::hint::black_box(v);
    });
    assert_eq!(one, 1, "one Vec::with_capacity is one allocation");

    let grown = allocations_of(|| {
        let mut v: Vec<u8> = Vec::with_capacity(1);
        v.extend_from_slice(&[0; 256]);
        std::hint::black_box(v);
    });
    assert_eq!(grown, 2, "an allocation and one realloc");

    let zeroed = allocations_of(|| {
        std::hint::black_box(vec![0u8; 128]);
    });
    assert_eq!(zeroed, 1, "vec![0; n] is one alloc_zeroed");

    let none = allocations_of(|| {
        std::hint::black_box(1 + 1);
    });
    assert_eq!(none, 0, "a call that allocates nothing counts nothing");

    reset();
    assert_eq!(allocations(), 0);
    std::hint::black_box(Box::new(7u64));
    assert_eq!(reset(), 1, "reset returns the count it cleared");
    assert_eq!(allocations(), 0);
}

/// Per thread: another thread's allocations do not reach this thread's count.
#[test]
fn another_threads_allocations_are_not_counted_here() {
    let here = allocations_of(|| {
        std::thread::scope(|s| {
            s.spawn(|| {
                for _ in 0..32 {
                    std::hint::black_box(Box::new([0u8; 64]));
                }
            });
        });
    });
    // Spawning the scoped thread allocates on THIS thread (its handle and packet), but none of
    // the spawned thread's 32 boxes is counted here.
    assert!(
        here < 32,
        "{here} allocations counted on the spawning thread"
    );
}

/// `allocations_with` hands back the closure's value beside its count.
#[test]
fn allocations_with_returns_the_value_and_the_count() {
    let (n, v) = allocations_with(|| std::hint::black_box(vec![1_u8; 64]));
    assert_eq!(v.len(), 64);
    assert_eq!(n, 1);
}

/// THE FREED-KEY WITNESS SEES: a marked key freed in a plain `Vec` is counted against its id,
/// and so is the block a growing `Vec` moved away from; a zeroising holder of the same bytes is
/// not counted.
#[test]
fn the_freed_key_witness_sees_an_unzeroed_key_and_not_a_zeroised_one() {
    let plain: Vec<u8> = marked_key::<56>(7).to_vec();
    drop(std::hint::black_box(plain));
    assert!(freed_unzeroed(7) >= 1, "a key freed unzeroed was not seen");

    let mut grown: Vec<u8> = marked_key::<56>(5).to_vec();
    grown.extend_from_slice(&[0; 512]);
    grown.fill(0);
    drop(std::hint::black_box(grown));
    assert!(
        freed_unzeroed(5) >= 1,
        "the block a growing Vec moved away from still held the key and was not seen"
    );

    let held = zeroize::Zeroizing::new(marked_key::<56>(6).to_vec());
    drop(std::hint::black_box(held));
    assert_eq!(freed_unzeroed(6), 0, "a zeroised key was counted");
}

/// THE WITNESS SEES A SPLIT COPY: any [`WINDOW`] consecutive bytes of a marked key, wherever they
/// sit in a freed block (a 16-byte master key split out of the keying material, at an offset
/// behind other bytes), are counted; fewer than a window's bytes are not.
#[test]
fn the_freed_key_witness_sees_any_window_of_a_key_and_not_less() {
    let key = marked_key::<56>(1);
    let mut split = vec![0xA5_u8; 40];
    split.extend_from_slice(&key[20..20 + WINDOW]);
    drop(std::hint::black_box(split));
    assert!(
        freed_unzeroed(1) >= 1,
        "a window of the key behind other bytes was not seen"
    );
    let seen = last_seen(1).expect("the sighting is recorded");
    assert_eq!((seen.at, seen.nth, seen.len), (40, 0, 56), "{seen:?}");
    assert!(seen.block >= 56, "{seen:?}");

    let key = marked_key::<56>(2);
    let short: Vec<u8> = key[30..30 + WINDOW - 1].to_vec();
    drop(std::hint::black_box(short));
    assert_eq!(freed_unzeroed(2), 0, "less than a window was counted");
}

/// THE WITNESS SEES A DERIVED COPY: a secret a test names with [`watch`] (a 12-byte salt, shorter
/// than a window, is matched whole; a derived 16-byte key at any offset) is counted under the
/// test's id once freed in a plain `Vec`, and not when its holder zeroises it.
#[test]
fn the_freed_key_witness_sees_a_watched_derived_secret() {
    let salt: [u8; 12] = *b"salt-of-id-3";
    watch(3, &salt);
    drop(std::hint::black_box(salt.to_vec()));
    assert!(freed_unzeroed(3) >= 1, "a watched salt was not seen");

    let derived: [u8; 16] = *b"derived-key-id-4";
    watch(4, &derived);
    let held = zeroize::Zeroizing::new(derived.to_vec());
    drop(std::hint::black_box(held));
    assert_eq!(freed_unzeroed(4), 0, "a zeroised derived key was counted");
    let mut plain = vec![7_u8; 3];
    plain.extend_from_slice(&derived);
    drop(std::hint::black_box(plain));
    assert!(
        freed_unzeroed(4) >= 1,
        "a derived key freed unzeroed was not seen"
    );
}
