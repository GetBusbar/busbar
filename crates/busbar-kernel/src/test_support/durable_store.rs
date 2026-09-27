// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DURABLE STORE DOUBLE — a store whose plane records outlive the handle that wrote them, for the
//! kernel's own tests of what a plane's trust state does across a restart and across a fleet.
//!
//! ## Why a double, and why this one (ARCHITECT R-FIX3)
//!
//! A behaviour double the kernel's own tests need lives HERE, as a test-support module of the crate
//! under test, LINKED only — not a workspace crate, not an example plugin. What these tests judge is
//! the kernel's side of the seam (a demotion replayed at boot, a spent approval refused by a second
//! node), so what they need is a store that KEEPS what it was told: written by one handle, read by
//! the next. The other two questions live where they can be answered: that a store crossing the C
//! ABI answers exactly what it answers linked is the loader's both-ways fold
//! (`busbar-plugin-loader`'s `store_conformance_tests`), and that a real durable backend keeps its
//! rows across a real restart is that backend's own suite, in its own repo.
//!
//! ## How it keeps them
//!
//! The FILE IS THE STATE. Every plane-record write is appended to a journal on disk (published whole
//! through the kernel's durable-write primitive), and every operation — read or write — first
//! replays that journal into a fresh [`MemoryStore`], so the answers are the default store's own,
//! verb for verb, and nothing is cached between calls. Two handles on one file therefore behave as
//! two nodes on one database: each sees the other's writes, and a process-wide lock per file makes
//! each read-replay-write one critical section, so a test-and-set really is one. A fresh handle — a
//! restart — has nothing to start from but the file.
//!
//! Only the plane-record verbs are durable. The verbs the trait requires of every store (keys, usage,
//! metering) answer from a per-handle [`MemoryStore`] and are lost with it: these tests never read
//! them back, and a double that claimed to keep what it does not would be the defect it exists to
//! catch.

use crate::governance::MemoryStore;
use busbar_contract::records::{
    MeteringDelta, MeteringRow, PlaneRecord, PlaneSelector, RecordStore, RecordStoreError,
    RecordStoreResult, UsageLedger, VirtualKey,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// One journalled plane-record write, replayed in order to rebuild the state.
#[derive(serde::Serialize, serde::Deserialize)]
enum Write {
    Upsert(PlaneRecord),
    Append(PlaneRecord),
    Purge(String, u64),
    Delete(String, String),
    Redeem(String, String, u64, u64),
}

impl Write {
    /// Apply this write to `s`, answering what the store answered.
    fn apply(&self, s: &MemoryStore) -> RecordStoreResult<serde_json::Value> {
        use serde_json::json;
        Ok(match self {
            Write::Upsert(r) => json!(s.upsert_plane_record(r)?),
            Write::Append(r) => json!(s.append_plane_record(r)?),
            Write::Purge(kind, before) => json!(s.purge_plane_records_before(kind, *before)?),
            Write::Delete(kind, id) => json!(s.delete_plane_record(kind, id)?),
            Write::Redeem(k, token, exp, now) => json!(s.redeem_plane_token(k, token, *exp, *now)?),
        })
    }
}

fn err(e: &dyn std::fmt::Display) -> RecordStoreError {
    RecordStoreError(e.to_string())
}

/// The process-wide lock of each journal file: every handle on one file takes the same one.
fn file_lock(path: &Path) -> Arc<Mutex<()>> {
    static LOCKS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<()>>>>> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    Arc::clone(locks.entry(path.to_path_buf()).or_default())
}

/// A handle on one journal file. See the module doc.
pub struct DurableStore {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
    /// The verbs the trait requires that this double does NOT keep (see the module doc).
    required: MemoryStore,
}

impl DurableStore {
    /// The journal on disk, replayed into a fresh store.
    fn replay(&self) -> RecordStoreResult<(Vec<Write>, MemoryStore)> {
        let journal: Vec<Write> = match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| err(&e))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(err(&e)),
        };
        let store = MemoryStore::new();
        for write in &journal {
            write.apply(&store)?;
        }
        Ok((journal, store))
    }

    /// Answer a read from the state on disk NOW.
    fn read<T>(
        &self,
        f: impl FnOnce(&MemoryStore) -> RecordStoreResult<T>,
    ) -> RecordStoreResult<T> {
        let _held = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        f(&self.replay()?.1)
    }

    /// Apply `write` to the state on disk and, when the store accepted it, publish it durably — one
    /// critical section, so a write another handle landed in between is never lost.
    fn write<T: serde::de::DeserializeOwned>(&self, write: Write) -> RecordStoreResult<T> {
        let _held = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let (mut journal, store) = self.replay()?;
        let answer = write.apply(&store)?;
        journal.push(write);
        let bytes = serde_json::to_vec(&journal).map_err(|e| err(&e))?;
        crate::durable::write(&self.path, &bytes).map_err(|e| err(&e))?;
        serde_json::from_value(answer).map_err(|e| err(&e))
    }
}

/// A PRIVATE journal file for one test, and the store config that names it. Per-test and per-thread,
/// so the parallel harness cannot make two tests share one.
pub fn durable_cfg(tag: &str) -> (PathBuf, String) {
    let dir = super::scratch_dir(&format!(
        "busbar-durable-store-{}-{tag}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let file = dir.join("durable.json");
    let _ = std::fs::remove_file(&file);
    let cfg = serde_json::json!({ "durable_path": file.to_string_lossy() }).to_string();
    (file, cfg)
}

/// Open a handle on the journal `cfg` names — a restart, or a second node of a fleet, depending on
/// what the caller is asking about.
pub fn open_durable(cfg: &str) -> Arc<dyn RecordStore> {
    let cfg: serde_json::Value = serde_json::from_str(cfg).expect("a durable store config");
    let path = PathBuf::from(
        cfg["durable_path"]
            .as_str()
            .expect("names its `durable_path`"),
    );
    Arc::new(DurableStore {
        lock: file_lock(&path),
        path,
        required: MemoryStore::new(),
    })
}

impl RecordStore for DurableStore {
    fn put_key(&self, key: &VirtualKey) -> RecordStoreResult<()> {
        self.required.put_key(key)
    }
    fn get_key(&self, id: &str) -> RecordStoreResult<Option<VirtualKey>> {
        self.required.get_key(id)
    }
    fn list_keys(&self) -> RecordStoreResult<Vec<VirtualKey>> {
        self.required.list_keys()
    }
    fn delete_key(&self, id: &str) -> RecordStoreResult<()> {
        self.required.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> RecordStoreResult<UsageLedger> {
        self.required.get_usage(bucket_id, window_start)
    }
    fn put_usage(&self, bucket: &str, window: u64, ledger: &UsageLedger) -> RecordStoreResult<()> {
        self.required.put_usage(bucket, window, ledger)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> RecordStoreResult<()> {
        self.required.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.required.list_metering(bucket)
    }

    fn upsert_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()> {
        self.write(Write::Upsert(record.clone()))
    }
    fn append_plane_record(&self, record: &PlaneRecord) -> RecordStoreResult<()> {
        self.write(Write::Append(record.clone()))
    }
    fn purge_plane_records_before(&self, kind: &str, before: u64) -> RecordStoreResult<u64> {
        self.write(Write::Purge(kind.into(), before))
    }
    fn delete_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<()> {
        self.write(Write::Delete(kind.into(), id.into()))
    }
    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.write(Write::Redeem(kind.into(), token.into(), expires_at, now))
    }
    fn get_plane_record(&self, kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        self.read(|s| s.get_plane_record(kind, id))
    }
    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        self.read(|s| s.list_plane_records(kind, selector))
    }
    fn list_plane_record_parents(&self, kind: &str) -> RecordStoreResult<Vec<String>> {
        self.read(|s| s.list_plane_record_parents(kind))
    }
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> RecordStoreResult<bool> {
        self.read(|s| s.plane_token_live(kind, token, expires_at, now))
    }
}
