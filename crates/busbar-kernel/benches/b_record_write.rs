// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! B-RECORD-WRITE: one record write through the write-behind batcher, made and released: the
//! write is built as the host builds it, pushed, and flushed against a store that takes every
//! call and keeps nothing, so the figure is the host's own work (what it allocates and copies for
//! the write, and gives back when the write is answered).
//!
//! Three writes, at 64 bytes and at the largest record a chained kind takes (the record cap,
//! `MAX_RECORD_BYTES`, less the chain's overhead):
//! - `overlay`: a put laid on the overlay of unacknowledged writes (it reads back until its batch
//!   is acknowledged); the flush acknowledges it.
//! - `chained`: an append to a chained record kind; it has no overlay row.
//! - `plain`: a put with no overlay row, the shape of a private work write.
//!
//! It prints, for each of `B_RECORD_WRITE_RUNS` runs (default 5), the median and p99 of
//! `B_RECORD_WRITE_SAMPLES` samples (default 400) in ns per write, timed in batches of
//! `B_RECORD_WRITE_BATCH` (default 64). The record bytes of a batch are made before its timer
//! starts: a write is handed its bytes. Same allocator as the shipped binary (jemalloc).

use std::sync::Arc;
use std::time::Instant;

use busbar_contract::abi::plane::{RecordChain, CHAIN_LENGTH_PREFIXED};
use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::{RecordBytes, StoreError};
use busbar_kernel::host_chains::{ChainBook, ChainFraming};
use busbar_kernel::host_records::{
    Owed, PendingRecords, RecordRows, Write, WriteBehind, WriteBytes,
};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// A store that takes every call and keeps nothing.
struct Sink;

impl RecordRows for Sink {
    fn record_put(
        &self,
        _schema: RecordSchemaId,
        _key: &[u8],
        _value: &RecordBytes,
    ) -> Result<(), StoreError> {
        Ok(())
    }

    fn record_get(
        &self,
        _schema: RecordSchemaId,
        _key: &[u8],
    ) -> Result<Option<RecordBytes>, StoreError> {
        Ok(None)
    }

    fn record_scan(
        &self,
        _schema: RecordSchemaId,
        _prefix: &[u8],
        _limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, StoreError> {
        Ok(Vec::new())
    }

    fn claim(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> Result<bool, StoreError> {
        Ok(true)
    }
}

#[derive(Clone, Copy)]
enum Path {
    Overlay,
    Chained,
    Plain,
}

impl Path {
    fn name(self) -> &'static str {
        match self {
            Path::Overlay => "overlay",
            Path::Chained => "chained",
            Path::Plain => "plain",
        }
    }
}

struct Rig {
    pending: PendingRecords,
    batcher: WriteBehind,
    chains: ChainBook,
    instance: Arc<str>,
    schema: RecordSchemaId,
    framing: ChainFraming,
}

impl Rig {
    /// One write of `path`, built as `KernelServices::record_write` builds it, and pushed.
    fn push(&self, path: Path, key: &[u8], value: RecordBytes) {
        let started = self.batcher.push_with(|| {
            let (seq, value, chain) = match path {
                Path::Overlay => {
                    let shared = Arc::new(value);
                    let seq =
                        self.pending
                            .enqueue(&self.instance, self.schema.as_str(), key, &shared);
                    (seq, WriteBytes::Shared(shared), None)
                }
                Path::Chained => (0, WriteBytes::Own(value), Some(self.framing)),
                Path::Plain => (0, WriteBytes::Own(value), None),
            };
            Write {
                instance: Arc::clone(&self.instance),
                schema: self.schema,
                key: key.to_vec(),
                value,
                seq,
                owed: Owed::new(Box::new(|_| {})),
                chain,
            }
        });
        assert!(started.is_some(), "the queue has room for the batch");
    }
}

fn env_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    let at = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[at.min(sorted.len() - 1)]
}

fn main() {
    let runs: usize = env_or("B_RECORD_WRITE_RUNS", 5);
    let samples: usize = env_or("B_RECORD_WRITE_SAMPLES", 400);
    let batch: usize = env_or("B_RECORD_WRITE_BATCH", 64);
    let framing = ChainFraming::of(&RecordChain {
        framing: CHAIN_LENGTH_PREFIXED,
        ..RecordChain::ZERO
    })
    .expect("a length-prefixed chain is a declared framing");
    // A put's keys are distinct within a batch; a chained write's key names its one chain.
    let keys: Vec<[u8; 8]> = (0..batch as u64).map(u64::to_be_bytes).collect();
    let largest = busbar_contract::bounded::MAX_RECORD_BYTES
        .saturating_sub(busbar_kernel::host_chains::CHAIN_OVERHEAD);
    for path in [Path::Overlay, Path::Chained, Path::Plain] {
        for size in [64usize, largest] {
            let rig = Rig {
                pending: PendingRecords::default(),
                batcher: WriteBehind::default(),
                chains: ChainBook::default(),
                instance: Arc::from("bench"),
                schema: RecordSchemaId::new("bench.record"),
                framing,
            };
            for run in 1..=runs {
                let mut times = Vec::with_capacity(samples);
                for _ in 0..samples {
                    let mut values = Vec::with_capacity(batch);
                    for _ in 0..batch {
                        values.push(RecordBytes::new(vec![7u8; size]).expect("under the cap"));
                    }
                    let start = Instant::now();
                    for (key, value) in keys.iter().zip(values) {
                        let key: &[u8] = match path {
                            Path::Chained => b"stream",
                            Path::Overlay | Path::Plain => key,
                        };
                        rig.push(path, key, value);
                    }
                    rig.batcher.flush(&rig.pending, &Sink, &rig.chains);
                    times.push(start.elapsed().as_nanos() as f64 / batch as f64);
                    assert_eq!(rig.pending.queued(), 0, "every write was acknowledged");
                }
                times.sort_by(f64::total_cmp);
                println!(
                    "B-RECORD-WRITE path={} bytes={size} run {run}: median {:.1} ns, p99 {:.1} ns per write",
                    path.name(),
                    percentile(&times, 0.5),
                    percentile(&times, 0.99)
                );
            }
        }
    }
}
