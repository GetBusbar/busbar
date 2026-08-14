// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: store` plugin** — a `cdylib` exporting the store C ABI, wrapping the
//! in-tree `MemoryStore`. It is the in-tree ABI-crossing coverage for the `kind: store` seam (the
//! store-seam analogue of `busbar-secret-example-plugin`). It does no real persistence beyond
//! `MemoryStore`'s own in-process map; its
//! job is to be a real, loadable, signable store plugin for the ABI to round-trip through, both in
//! this crate's own boundary tests and as the fixture `plugin-ci.yml`'s install-and-serve CI step
//! packs and installs against a real running busbar.
//!
//! ## The one exception: `{"durable_path": "…"}`
//!
//! Given that config key the plugin opens a [`FileStore`] instead — a tiny JSON-file-backed store
//! that keeps A2A task rows, task provenance events and MCP call records on DISK. It exists for one
//! reason: DURABILITY ACROSS A RESTART cannot be proven against a store whose state dies with the
//! process, and the durability of the A2A task table is a product claim that had never been
//! exercised over the path a deployment actually takes (the plugin ABI). `MemoryStore` survives one
//! plugin handle and no more, so a "write, restart, read it back" test needs a backend that puts
//! bytes somewhere a second `busbar_open` can find them.
//!
//! No config (or unparseable config) still means `MemoryStore`, so the CI install-and-serve fixture
//! and every existing over-the-ABI test are untouched.

use busbar_api::{McpCallRecord, McpDemotionRow};
use busbar_api::{
    MeteringDelta, MeteringRow, Store, StoreError, StoreResult, TaskEventRow, TaskRow, UsageLedger,
    VirtualKey,
};
use busbar_store_memory::MemoryStore;
use std::path::PathBuf;
use std::sync::Mutex;

/// The plugin's optional config. Every field optional; an absent/unparseable body means
/// "`MemoryStore`, no config", which is this fixture's original and default posture.
#[derive(serde::Deserialize)]
struct Cfg {
    /// Where [`FileStore`] keeps its JSON. Presence of this key is what selects the durable mode.
    durable_path: Option<String>,
}

/// Construct the module. With no `durable_path` no config is read at all (the wrapped `MemoryStore`
/// takes none); malformed JSON in `cfg` is accepted and ignored rather than a load error, since
/// there is nothing in this plugin's config shape that could be malformed — this mirrors
/// `busbar-auth-static-plugin`'s posture for a config-less module, not
/// `busbar-secret-example-plugin`'s (which has a real config to validate).
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    match serde_json::from_str::<Cfg>(cfg)
        .ok()
        .and_then(|c| c.durable_path)
    {
        Some(path) => Ok(Box::new(FileStore::open(PathBuf::from(path))?)),
        None => Ok(Box::new(MemoryStore::new())),
    }
}

/// Everything [`FileStore`] writes through to disk, as one JSON document. Rewritten whole on every
/// mutation: this is a test fixture holding a handful of rows, so the simplest thing that is
/// actually durable beats anything cleverer.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Durable {
    tasks: Vec<TaskRow>,
    task_events: Vec<TaskEventRow>,
    mcp_calls: Vec<McpCallRecord>,
    /// Recorded upstream demotions, keyed by `server`. `#[serde(default)]` so a file written by an
    /// earlier build of this fixture still opens.
    #[serde(default)]
    mcp_demotions: Vec<McpDemotionRow>,
    /// The spent-approval ledger: nonce -> the instant past which the entry is meaningless.
    #[serde(default)]
    spent_ask_states: Vec<(String, u64)>,
}

/// A JSON-file-backed store. The A2A task and MCP call-log methods are REAL — they read and write
/// `path`, so a row written by one plugin handle is found by the next one. Every other `Store`
/// method delegates to an inner `MemoryStore` (the required ones) or keeps the trait default: this
/// fixture exists to prove task durability over the ABI, and pretending to durably store keys and
/// credentials it never reads back would be exactly the kind of claim this crate is here to catch.
struct FileStore {
    path: PathBuf,
    inner: MemoryStore,
    /// Serialises this handle's own read-modify-write cycles. It holds no DATA, deliberately — see
    /// [`FileStore::load`].
    gate: Mutex<()>,
}

impl FileStore {
    /// Open (and create if absent) the backing file, VALIDATING whatever a previous handle left.
    ///
    /// The state read here is discarded: every operation re-reads. What this does is fail the LOAD
    /// on an unreadable file, so a misconfigured `durable_path` is an error an operator sees at
    /// startup rather than an empty store that looks exactly like a working one.
    fn open(path: PathBuf) -> Result<Self, String> {
        Self::load_from(&path).map_err(|e| e.0)?;
        Ok(Self {
            path,
            inner: MemoryStore::new(),
            gate: Mutex::new(()),
        })
    }

    /// THE FILE IS THE STATE, and it is re-read on every operation rather than cached at open.
    ///
    /// That is not tidiness. A cached snapshot makes two live handles on one file behave like two
    /// separate stores — the second one's writes are computed against whatever the file held when it
    /// opened, and silently overwrite anything the first wrote since. A real backend is one database
    /// that several nodes talk to, and the properties this fixture exists to prove are exactly the
    /// ones that live in the difference: a fleet is TWO HANDLES OPEN AT ONCE on one store, and a
    /// caching fixture would have reported the shared spent-approval ledger working while a second
    /// node happily double-redeemed.
    fn load(&self) -> StoreResult<Durable> {
        Self::load_from(&self.path)
    }

    fn load_from(path: &PathBuf) -> StoreResult<Durable> {
        match std::fs::read(path) {
            Ok(bytes) if !bytes.is_empty() => serde_json::from_slice(&bytes).map_err(|e| {
                StoreError(format!(
                    "durable_path '{}' is not readable state: {e}",
                    path.display()
                ))
            }),
            Ok(_) => Ok(Durable::default()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Durable::default()),
            Err(e) => Err(StoreError(format!(
                "durable_path '{}': {e}",
                path.display()
            ))),
        }
    }

    /// Read the file, apply `f`, and persist the result — one read-modify-write under one lock, so
    /// a test-and-set really is a test-and-set. The write is the whole point, so a failure to
    /// persist is an ERROR the caller sees, never a silent `Ok(())`, which is the exact shape of the
    /// defect this fixture proves.
    ///
    /// The persist is ATOMIC, through the one blessed publisher (`busbar_api::durable::write`:
    /// sibling temp, fsync, rename, temp cleaned on every error path). A plain `fs::write`
    /// truncates before it writes, so a reader on ANOTHER handle (the fleet case this fixture
    /// exists to model — `self.gate` is per-handle, not per-file) can observe an empty or
    /// half-written file: observed in practice as `list_mcp_calls` returning zero rows to a
    /// freshly reopened handle while a still-live handle was mid-record on another thread. The
    /// rename publish means a reader sees either the old complete state or the new complete
    /// state, never a tear.
    fn mutate<T>(&self, f: impl FnOnce(&mut Durable) -> T) -> StoreResult<T> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StoreError("poisoned".into()))?;
        let mut state = self.load()?;
        let out = f(&mut state);
        let bytes = serde_json::to_vec(&state).map_err(|e| StoreError(e.to_string()))?;
        busbar_api::durable::write(&self.path, &bytes).map_err(|e| StoreError(e.to_string()))?;
        Ok(out)
    }

    /// Read what is on disk NOW.
    fn read<T>(&self, f: impl FnOnce(&Durable) -> T) -> StoreResult<T> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StoreError("poisoned".into()))?;
        Ok(f(&self.load()?))
    }
}

impl Store for FileStore {
    // ── delegated to the inner MemoryStore (the methods the trait requires) ──────────────────
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.inner.list_metering(bucket)
    }

    // ── the durable ones: A2A task state ─────────────────────────────────────────────────────
    fn put_task(&self, task: &TaskRow) -> StoreResult<()> {
        self.mutate(|d| {
            match d.tasks.iter_mut().find(|t| t.task_id == task.task_id) {
                // UPSERT by `task_id`, as the trait requires — a second write for the same id
                // replaces the row rather than appending a rival one.
                Some(existing) => *existing = task.clone(),
                None => d.tasks.push(task.clone()),
            }
        })
    }
    fn get_task(&self, task_id: &str) -> StoreResult<Option<TaskRow>> {
        self.read(|d| d.tasks.iter().find(|t| t.task_id == task_id).cloned())
    }
    fn list_tasks(&self) -> StoreResult<Vec<TaskRow>> {
        self.read(|d| d.tasks.clone())
    }
    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64> {
        // TERMINAL rows only: an interrupted task waiting on a human is exactly the row that sits
        // still for a long time, and dropping it loses the work.
        const TERMINAL: [&str; 4] = ["completed", "failed", "canceled", "rejected"];
        self.mutate(|d| {
            let before_len = d.tasks.len();
            d.tasks
                .retain(|t| !(t.updated_at < before && TERMINAL.contains(&t.state.as_str())));
            (before_len - d.tasks.len()) as u64
        })
    }
    fn append_task_event(&self, event: &TaskEventRow) -> StoreResult<()> {
        self.mutate(|d| {
            match d
                .task_events
                .iter_mut()
                .find(|e| e.task_id == event.task_id && e.seq == event.seq)
            {
                // Upsert on `(task_id, seq)` so a replay is idempotent, per the trait's contract.
                Some(existing) => *existing = event.clone(),
                None => d.task_events.push(event.clone()),
            }
        })
    }
    fn list_task_events(&self, task_id: &str) -> StoreResult<Vec<TaskEventRow>> {
        self.read(|d| {
            let mut out: Vec<TaskEventRow> = d
                .task_events
                .iter()
                .filter(|e| e.task_id == task_id)
                .cloned()
                .collect();
            out.sort_by_key(|e| e.seq);
            out
        })
    }

    // ── the durable ones: the MCP call log ───────────────────────────────────────────────────
    fn append_mcp_call(&self, record: &McpCallRecord) -> StoreResult<()> {
        // Byte-identical on an existing `(principal, seq)` is the retry and is `Ok(())`; DIFFERENT
        // is a forked or tampered log and is an error, exactly as `append_audit` settles it.
        // ONE read-modify-write, not a `read` then a `mutate`: the fork check and the append have to
        // see the same state, and between two calls another handle on the same file can land a row.
        self.mutate(|d| {
            match d
                .mcp_calls
                .iter()
                .find(|r| r.principal == record.principal && r.seq == record.seq)
            {
                Some(prev) if prev == record => Ok(()),
                Some(_) => Err(StoreError(format!(
                    "mcp call log fork at ({}, {})",
                    record.principal, record.seq
                ))),
                None => {
                    d.mcp_calls.push(record.clone());
                    Ok(())
                }
            }
        })?
    }
    fn list_mcp_calls(&self, principal: &str) -> StoreResult<Vec<McpCallRecord>> {
        self.read(|d| {
            let mut out: Vec<McpCallRecord> = d
                .mcp_calls
                .iter()
                .filter(|r| r.principal == principal)
                .cloned()
                .collect();
            out.sort_by_key(|r| r.seq);
            out
        })
    }
    fn list_mcp_call_principals(&self) -> StoreResult<Vec<String>> {
        self.read(|d| {
            let mut out: Vec<String> = d.mcp_calls.iter().map(|r| r.principal.clone()).collect();
            out.sort();
            out.dedup();
            out
        })
    }
    fn purge_mcp_calls_before(&self, before: u64) -> StoreResult<u64> {
        self.mutate(|d| {
            let was = d.mcp_calls.len();
            d.mcp_calls.retain(|r| r.ts >= before);
            (was - d.mcp_calls.len()) as u64
        })
    }

    // ── the durable ones: the MCP demotion record ────────────────────────────────────────────
    fn put_mcp_demotion(&self, row: &McpDemotionRow) -> StoreResult<()> {
        self.mutate(
            |d| match d.mcp_demotions.iter_mut().find(|r| r.server == row.server) {
                // UPSERT by `server`, as the trait requires.
                Some(existing) => *existing = row.clone(),
                None => d.mcp_demotions.push(row.clone()),
            },
        )
    }
    fn list_mcp_demotions(&self) -> StoreResult<Vec<McpDemotionRow>> {
        self.read(|d| d.mcp_demotions.clone())
    }
    fn clear_mcp_demotion(&self, server: &str) -> StoreResult<()> {
        self.mutate(|d| d.mcp_demotions.retain(|r| r.server != server))
    }

    // ── the durable one: the spent-approval ledger ───────────────────────────────────────────
    fn redeem_ask_state(&self, nonce: &str, expires_at: u64, now: u64) -> StoreResult<bool> {
        // ONE critical section covering the expiry sweep, the lookup AND the insert. Splitting the
        // read from the write is the double-redemption this ledger exists to refuse, so the fixture
        // has to model it the way a real backend's single INSERT does.
        self.mutate(|d| {
            d.spent_ask_states.retain(|(_, expiry)| *expiry >= now);
            if d.spent_ask_states.iter().any(|(n, _)| n == nonce) {
                return false;
            }
            d.spent_ask_states.push((nonce.to_string(), expires_at));
            true
        })
    }
}

busbar_plugin_sdk::export_store_plugin!(open);
