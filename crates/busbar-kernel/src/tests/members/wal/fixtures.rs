// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::io;
use std::sync::{Arc, Mutex};

use busbar_contract::caps::{DurableWrite, Grant, KernelSeal, StepName};

use busbar_kernel_wal::backend::{MemoryFactory, SegmentBackend, SegmentFactory};
use busbar_kernel_wal::record::Record;

pub fn durability_token() -> Grant<DurableWrite> {
    Grant::<DurableWrite>::mint(&KernelSeal::acquire_for_kernel())
}

pub const METER: StepName = StepName::Meter;

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

/// A disk that can be told, from outside, to fail its next sync or write — or to refuse to create a
/// new segment at all.
#[derive(Debug, Clone, Default)]
pub struct FaultSwitch {
    fault: Arc<Mutex<Fault>>,
    syncs: Arc<Mutex<u64>>,
    refuse_opens: Arc<Mutex<bool>>,
}

impl FaultSwitch {
    pub fn new() -> Self {
        FaultSwitch {
            fault: Arc::new(Mutex::new(Fault::None)),
            syncs: Arc::new(Mutex::new(0)),
            refuse_opens: Arc::new(Mutex::new(false)),
        }
    }

    pub fn arm(&self, fault: Fault) {
        *self.fault.lock().unwrap() = fault;
    }

    pub fn clear(&self) {
        self.arm(Fault::None);
    }

    pub fn refuse_new_segments(&self, refuse: bool) {
        *self.refuse_opens.lock().unwrap() = refuse;
    }

    pub fn syncs(&self) -> u64 {
        *self.syncs.lock().unwrap()
    }

    fn take(&self) -> Fault {
        let mut held = self.fault.lock().unwrap();
        let fault = *held;

        *held = Fault::None;
        fault
    }
}

pub struct FaultyBackend {
    inner: busbar_kernel_wal::backend::MemorySegment,
    switch: FaultSwitch,
}

impl SegmentBackend for FaultyBackend {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> io::Result<()> {
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

pub struct FaultyFactory {
    inner: MemoryFactory,
    switch: FaultSwitch,
}

impl FaultyFactory {
    pub fn new() -> (Self, FaultSwitch, MemoryFactory) {
        FaultyFactory::over(MemoryFactory::new())
    }

    pub fn retaining() -> (Self, FaultSwitch, MemoryFactory) {
        FaultyFactory::over(MemoryFactory::retaining())
    }

    fn over(inner: MemoryFactory) -> (Self, FaultSwitch, MemoryFactory) {
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
        if *self.switch.refuse_opens.lock().unwrap() && self.inner.existing(index)?.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "simulated ENOSPC creating the next segment",
            ));
        }
        Ok(Box::new(FaultyBackend {
            inner: busbar_kernel_wal::backend::MemorySegment::over(self.inner.segment_bytes(index)),
            switch: self.switch.clone(),
        }))
    }

    fn highest_index(&self) -> io::Result<Option<u64>> {
        self.inner.highest_index()
    }

    fn existing(&self, index: u64) -> io::Result<Option<Box<dyn SegmentBackend>>> {
        self.inner.existing(index)
    }

    fn is_durable(&self) -> bool {
        true
    }

    fn segment_file(&self, index: u64) -> Option<std::path::PathBuf> {
        self.inner.segment_file(index)
    }

    fn quarantine(
        &mut self,
        index: u64,
        offset: u64,
        unix_ms: u64,
        bytes: &[u8],
    ) -> io::Result<Option<std::path::PathBuf>> {
        self.inner.quarantine(index, offset, unix_ms, bytes)
    }
}

/// A store that keeps every record it was handed, in order, behind a shared handle so whoever
/// configured it can see what reached it after handing ownership to the log.
#[derive(Debug, Default, Clone)]
pub struct KeepingShipper {
    records: Arc<Mutex<Vec<Record>>>,
}

impl KeepingShipper {
    pub fn new() -> Self {
        KeepingShipper::default()
    }

    pub fn records(&self) -> Vec<Record> {
        self.records.lock().unwrap().clone()
    }
}

impl busbar_kernel_wal::ship::Shipper<Record> for KeepingShipper {
    fn ship(&mut self, records: &[Record]) -> Result<(), busbar_kernel_wal::ship::ShipError> {
        self.records.lock().unwrap().extend_from_slice(records);
        Ok(())
    }
}

/// A store that will not take anything. What a memory-buffered node's durability failure looks like
/// from the log's side, and the only way to make the buffer grow at all.
#[derive(Debug, Default)]
pub struct RefusingShipper;

impl busbar_kernel_wal::ship::Shipper<Record> for RefusingShipper {
    fn ship(&mut self, _records: &[Record]) -> Result<(), busbar_kernel_wal::ship::ShipError> {
        Err(busbar_kernel_wal::ship::ShipError::Unavailable(
            "the store is not answering".into(),
        ))
    }
}

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

pub fn cwd_segment_names() -> std::collections::BTreeSet<String> {
    let Ok(entries) = std::fs::read_dir(".") else {
        return std::collections::BTreeSet::new();
    };
    entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".wal"))
        .collect()
}

pub struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        TempDir::under(std::env::temp_dir(), tag)
    }

    pub fn in_build_dir(tag: &str) -> Self {
        let build = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("target")
            .join("busbar-unit-wal-tmp");
        TempDir::under(build, tag)
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

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

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

pub fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}
