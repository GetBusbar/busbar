// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared props: a durability token, a disk that can be told to fail, and a temp directory.

use std::io;
use std::sync::{Arc, Mutex};

use busbar_caps::{DurabilityToken, KernelSeal};

use crate::backend::{MemoryFactory, SegmentBackend, SegmentFactory};
use crate::record::Record;

/// A durability token. In production only the kernel mints one; in a test the kernel's own seal is
/// available, which is exactly the hole the capability crate names out loud.
pub fn durability_token() -> DurabilityToken {
    DurabilityToken::mint(&KernelSeal::acquire_for_kernel())
}

/// What a failing disk should do on its next operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Fault {
    /// Behave.
    #[default]
    None,
    /// Fail the sync with the error a medium returns when it cannot write.
    SyncEio,
    /// Fail the sync with the error a full volume returns.
    SyncEnospc,
    /// Fail the write itself.
    WriteEio,
}

/// A disk that can be told, from outside, to fail its next sync or write.
#[derive(Debug, Clone, Default)]
pub struct FaultSwitch {
    fault: Arc<Mutex<Fault>>,
    syncs: Arc<Mutex<u64>>,
}

impl FaultSwitch {
    /// A switch with nothing set.
    pub fn new() -> Self {
        FaultSwitch {
            fault: Arc::new(Mutex::new(Fault::None)),
            syncs: Arc::new(Mutex::new(0)),
        }
    }

    /// Arm the next operation to fail.
    pub fn arm(&self, fault: Fault) {
        *self.fault.lock().unwrap() = fault;
    }

    /// Disarm.
    pub fn clear(&self) {
        self.arm(Fault::None);
    }

    /// How many syncs the disk has been asked for. This is what makes "one sync per group commit"
    /// a measurement rather than a claim.
    pub fn syncs(&self) -> u64 {
        *self.syncs.lock().unwrap()
    }

    fn take(&self) -> Fault {
        let mut held = self.fault.lock().unwrap();
        let fault = *held;
        // One-shot: a real EIO is an event, not a mode, and a test that wants a permanently broken
        // disk arms it again.
        *held = Fault::None;
        fault
    }
}

/// A memory backing wearing the fault switch.
pub struct FaultyBackend {
    inner: crate::backend::MemorySegment,
    switch: FaultSwitch,
}

impl SegmentBackend for FaultyBackend {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
        // A write fault is decided before the bytes land, so nothing is written — which is the
        // pessimistic case the poison rule has to hold under anyway.
        let fault = { *self.switch.fault.lock().unwrap() };
        if fault == Fault::WriteEio {
            self.switch.clear();
            return Err(io::Error::other("simulated write error"));
        }
        self.inner.write_all_at(offset, bytes)
    }

    fn sync(&mut self) -> io::Result<()> {
        *self.switch.syncs.lock().unwrap() += 1;
        match self.switch.take() {
            Fault::SyncEio => Err(io::Error::other("simulated EIO at the sync point")),
            Fault::SyncEnospc => Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "simulated ENOSPC at the sync point",
            )),
            _ => self.inner.sync(),
        }
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_at(offset, buf)
    }

    fn len(&self) -> io::Result<u64> {
        self.inner.len()
    }

    fn set_len(&mut self, len: u64) -> io::Result<()> {
        self.inner.set_len(len)
    }
}

/// Hands out faulty backings over a shared set of memory segments.
pub struct FaultyFactory {
    inner: MemoryFactory,
    switch: FaultSwitch,
}

impl FaultyFactory {
    /// A factory and the switch that drives it.
    pub fn new() -> (Self, FaultSwitch, MemoryFactory) {
        let inner = MemoryFactory::new();
        let switch = FaultSwitch::new();
        (
            FaultyFactory {
                inner: inner.clone(),
                switch: switch.clone(),
            },
            switch,
            inner,
        )
    }
}

impl SegmentFactory for FaultyFactory {
    fn open(&mut self, index: u64) -> io::Result<Box<dyn SegmentBackend>> {
        Ok(Box::new(FaultyBackend {
            inner: crate::backend::MemorySegment::over(self.inner.segment_bytes(index)),
            switch: self.switch.clone(),
        }))
    }

    fn is_durable(&self) -> bool {
        true
    }
}

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
    /// Make one.
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
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

    /// Every path inside it, at any depth.
    pub fn walk(&self) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let mut stack = vec![self.path.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path.clone());
                }
                found.push(path);
            }
        }
        found
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
