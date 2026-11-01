// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The counting allocator counts per thread. This crate's own test binary installs [`super::Counting`] as its
//! `#[global_allocator]` (`lib.rs`).

use super::{allocations, allocations_of, allocations_with, reset};

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

#[test]
fn the_payload_probe_checks_only_registered_prefixes_and_records_complete_reads() {
    // SAFETY: both registered Vecs stay on this thread through destruction.
    let probe =
        unsafe { super::InitializedPayloadProbe::start().expect("open the memory observer") };
    let mut plain = Vec::with_capacity(16384);
    plain.resize(8193, 0);
    plain[8192] = 1;
    let mut wiped = zeroize::Zeroizing::new(Vec::with_capacity(16384));
    wiped.resize(8193, 1u8);
    // SAFETY: each slice starts at its allocation base and names only its initialized prefix.
    unsafe {
        super::watch_initialized_payload(&plain);
        super::watch_initialized_payload(&wiped);
    }
    drop(Vec::<u8>::with_capacity(32768));
    drop(plain);
    drop(wiped);
    let observations = probe.finish();
    assert!(
        !observations.reentered,
        "OS memory reader reentered the allocator"
    );
    assert_eq!(
        observations.payloads.len(),
        2,
        "unregistered memory is not observed"
    );
    for record in &observations.payloads {
        assert!(
            record.freed,
            "registered allocation was not freed: {record:?}"
        );
        assert_eq!(record.len, 8193, "spare capacity is excluded");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(record.read_error, None, "OS memory read failed: {record:?}");
            assert!(
                record.complete_read,
                "OS memory read was incomplete: {record:?}"
            );
            assert_eq!(record.bytes_read, record.len);
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(record.read_error, Some(std::io::ErrorKind::Unsupported));
            assert!(!record.complete_read);
            assert_eq!(record.bytes_read, 0);
        }
    }
    #[cfg(target_os = "linux")]
    {
        assert!(
            !observations.payloads[0].wiped,
            "the last initialized byte was not zero"
        );
        assert!(
            observations.payloads[1].wiped,
            "Zeroizing wipes its initialized payload"
        );
    }
    #[cfg(not(target_os = "linux"))]
    eprintln!("Registration and frees checked; memory proof requires Linux /proc/self/mem");
}

#[test]
fn growing_a_registered_vec_observes_its_actual_old_allocation() {
    // SAFETY: the Vec and its initialized prefix stay on this thread through growth and drop.
    let probe =
        unsafe { super::InitializedPayloadProbe::start().expect("open the memory observer") };
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(b"secret prefix in the old allocation");
    // SAFETY: this is the allocation's initialized base prefix.
    unsafe { super::watch_initialized_payload(&payload) };
    payload.reserve(payload.capacity() + 1);
    drop(payload);
    let observations = probe.finish();
    assert!(
        !observations.reentered,
        "OS memory reader reentered the allocator"
    );
    assert_eq!(
        observations.payloads.len(),
        1,
        "only the old allocation was registered"
    );
    let record = &observations.payloads[0];
    assert!(record.freed, "the actual old allocation was freed");
    assert!(
        record.reallocated,
        "growth released the registered allocation"
    );
    #[cfg(target_os = "linux")]
    {
        assert_eq!(record.read_error, None, "OS memory read failed: {record:?}");
        assert!(
            record.complete_read,
            "OS memory read was incomplete: {record:?}"
        );
        assert_eq!(record.bytes_read, record.len);
        assert!(
            !record.wiped,
            "the old allocation still contained the secret"
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        assert_eq!(record.read_error, Some(std::io::ErrorKind::Unsupported));
        assert!(!record.complete_read);
        eprintln!("Vec growth and old allocation free checked; memory proof requires Linux /proc/self/mem");
    }
}
