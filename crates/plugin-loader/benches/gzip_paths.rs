// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! flate2 backend bench (SMALL-DEP-WINS F.4): the three gzip paths core runs.
//!
//! 1. `openapi_inflate`: the work `openapi_json()` does on every `GET /openapi.json`.
//! 2. `tarball_unpack_{1,64}MiB`: plugin admission, boot scan and fetch (`tarball::unpack`).
//! 3. `tarball_package_64MiB`: pack/seal tooling (`tarball::package`, `Compression::default()`).
//!
//! The payload is a fixed-seed mix of repeated code-like blocks and random runs, so the
//! compression ratio is realistic rather than all zeros or all random. It lands before any
//! backend change so the A/B (base = dev, head = the backend flip) has a base.

use busbar_plugin_loader::sign::Manifest;
use busbar_plugin_loader::tarball;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;
use std::io::Read as _;

const OPENAPI_GZ: &[u8] = include_bytes!("../../busbar-core-admin/src/v1/json/openapi.json.gz");

const MIB: usize = 1024 * 1024;

/// xorshift64*: a fixed-seed byte source, so every run and both arms see the same payload.
struct Seeded(u64);

impl Seeded {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

/// A library-like payload: code-like blocks repeated with small edits, interleaved with
/// random runs (relocations, constants, compressed sections).
fn library_like(len: usize) -> Vec<u8> {
    const BLOCKS: [&[u8]; 4] = [
        b"\x48\x89\xe5\x48\x83\xec\x20\x48\x89\x7d\xf8\x48\x8b\x45\xf8\xe8\x00\x00\x00\x00",
        b"core::result::Result<busbar_contract::abi::store::Reply, alloc::string::String>",
        b"\x55\x48\x89\xe5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x83\xec\x18\xc3\x90\x90",
        b"called `Option::unwrap()` on a `None` value\0src/lib.rs\0attempt to add with overflow",
    ];
    let mut rng = Seeded(0x5eed_0fb0_5ba7);
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        let r = rng.next();
        if r.is_multiple_of(4) {
            let run = 16 + (r >> 8) as usize % 240;
            for _ in 0..run {
                out.push(rng.next() as u8);
            }
        } else {
            let block = BLOCKS[(r >> 16) as usize % BLOCKS.len()];
            out.extend_from_slice(block);
            out.push((r >> 24) as u8);
        }
    }
    out.truncate(len);
    out
}

fn manifest() -> Manifest {
    Manifest {
        name: "busbar-store-bench-plugin".into(),
        alias: "bench".into(),
        kind: "store".into(),
        version: "1.6.0".into(),
        publisher: "busbar".into(),
        license: "Apache-2.0".into(),
        ..Manifest::default()
    }
}

fn openapi_inflate(c: &mut Criterion) {
    let mut group = c.benchmark_group("openapi_inflate");
    group.throughput(Throughput::Bytes(OPENAPI_GZ.len() as u64));
    group.bench_function("openapi_inflate", |b| {
        b.iter(|| {
            let mut text = String::new();
            flate2::read::GzDecoder::new(black_box(OPENAPI_GZ))
                .read_to_string(&mut text)
                .expect("the committed openapi.json.gz inflates");
            black_box(text)
        })
    });
    group.finish();
}

fn tarball_unpack(c: &mut Criterion) {
    let manifest = manifest();
    let mut group = c.benchmark_group("tarball_unpack");
    group.sample_size(10);
    for mib in [1usize, 64] {
        let lib = library_like(mib * MIB);
        let packed = tarball::package(&manifest, "libbusbar_store_bench.so", &lib)
            .expect("bench tarball packs");
        group.throughput(Throughput::Bytes(lib.len() as u64));
        group.bench_function(format!("tarball_unpack_{mib}MiB"), |b| {
            b.iter(|| {
                black_box(tarball::unpack(black_box(&packed)).expect("bench tarball unpacks"))
            })
        });
    }
    group.finish();
}

fn tarball_package(c: &mut Criterion) {
    let manifest = manifest();
    let lib = library_like(64 * MIB);
    let mut group = c.benchmark_group("tarball_package");
    group.sample_size(10);
    group.throughput(Throughput::Bytes(lib.len() as u64));
    group.bench_function("tarball_package_64MiB", |b| {
        b.iter(|| {
            black_box(
                tarball::package(&manifest, "libbusbar_store_bench.so", black_box(&lib))
                    .expect("bench tarball packs"),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, openapi_inflate, tarball_unpack, tarball_package);
criterion_main!(benches);
