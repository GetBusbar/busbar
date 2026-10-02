// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared props: a durability token and a temp directory.

use busbar_contract::caps::{DurableWrite, Grant, KernelSeal, StepName};

use crate::record::Record;

/// A durability token. In production only the kernel mints one; in a test the kernel's own seal is
/// available, which is exactly the hole the capability crate names out loud.
pub fn durability_token() -> Grant<DurableWrite> {
    Grant::<DurableWrite>::mint(&KernelSeal::acquire_for_kernel())
}

/// The step a battery commits at. Any step will do; the log does not read it.
pub const METER: StepName = StepName::Meter;

/// `n` records with bodies of the given length, numbered from `first_seq`.
pub fn records(node: u64, first_seq: u64, n: u64, body_len: usize) -> Vec<Record> {
    (0..n)
        .map(|i| {
            let seq = first_seq + i;
            let body: Vec<u8> = (0..body_len)
                .map(|b| ((seq as usize + b) % 251) as u8)
                .collect();
            Record::new(node, seq, body)
        })
        .collect()
}

/// A directory nothing else is using, removed when the test ends.
pub struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    /// Make one, under the system temp directory.
    pub fn new(tag: &str) -> Self {
        TempDir::under(std::env::temp_dir(), tag)
    }

    fn under(parent: std::path::PathBuf, tag: &str) -> Self {
        let path = parent.join(format!(
            "busbar-unit-wal-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    /// Where it is.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The wall clock a test hands a log, in unix milliseconds — the reading the composition root
/// hands a production one. A test may read a clock; the crate under test may not.
pub fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
