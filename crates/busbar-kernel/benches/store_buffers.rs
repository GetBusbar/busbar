// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PER-READ STORE COSTS a journal replay pays once per original frame:
//!
//! * `wipe_*` — dropping one read's 4 KiB output buffer: `Zeroizing<Vec<u8>>` (byte-wise volatile
//!   stores, a fence per byte) against `WipedBytes` (word-wise volatile stores, one fence).
//! * `seal_*` — one `busbar.journal.original-proof/1` seal step over a typical original: the
//!   portable `sha2` build against ring's SHA-256 (CPU SHA extensions where present).
//!
//! ```text
//! cargo bench -p busbar-kernel --bench store_buffers
//! ```

use criterion::{criterion_group, criterion_main, Criterion};
use sha2::{Digest as _, Sha256};
use std::hint::black_box;

const OUTPUT: usize = 4096;
const ORIGINAL: usize = 420;

fn wipe(c: &mut Criterion) {
    c.bench_function("wipe_zeroizing_4k", |b| {
        b.iter(|| drop(black_box(zeroize::Zeroizing::new(vec![0u8; OUTPUT]))));
    });
    c.bench_function("wipe_wiped_bytes_4k", |b| {
        b.iter(|| {
            drop(black_box(busbar_contract::abi::sdk::wipe::WipedBytes::new(
                vec![0u8; OUTPUT],
            )))
        });
    });
}

fn seal(c: &mut Criterion) {
    let body: Vec<u8> = (0..ORIGINAL).map(|i| i as u8).collect();
    let previous = [7u8; 32];
    c.bench_function("seal_sha2_420b", |b| {
        b.iter(|| {
            let mut hash = Sha256::new();
            hash.update(b"busbar.journal.original-proof/1\0");
            hash.update(black_box(previous));
            hash.update((body.len() as u64).to_be_bytes());
            hash.update(black_box(&body));
            let seal: [u8; 32] = hash.finalize().into();
            seal
        });
    });
    c.bench_function("seal_ring_420b", |b| {
        b.iter(|| {
            let mut hash = ring::digest::Context::new(&ring::digest::SHA256);
            hash.update(b"busbar.journal.original-proof/1\0");
            hash.update(black_box(&previous));
            hash.update(&(body.len() as u64).to_be_bytes());
            hash.update(black_box(&body));
            let mut seal = [0u8; 32];
            seal.copy_from_slice(hash.finish().as_ref());
            seal
        });
    });
}

criterion_group!(benches, wipe, seal);
criterion_main!(benches);
