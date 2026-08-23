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
    MeteringDelta, MeteringRow, PlaneRecord, PlaneSelector, Store, StoreError, StoreResult,
    TaskEventRow, TaskRow, UsageLedger, VirtualKey,
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
    /// The MCP per-call chain, kept as the OPAQUE stored BODIES a durable backend holds — the neutral
    /// `{seq,prev_hash,hash,content}` the P5 seam persists — keyed by `(principal, seq)`. The engine
    /// reframes them on read; this fixture no longer decodes the body on the write path, so a body
    /// written through the neutral seam (which names no plane type) persists and reads back verbatim.
    /// `#[serde(default)]` so a file this fixture wrote before the cleave still opens.
    #[serde(default)]
    call_bodies: Vec<CallBody>,
    /// Recorded upstream demotions, keyed by `server`. `#[serde(default)]` so a file written by an
    /// earlier build of this fixture still opens.
    #[serde(default)]
    mcp_demotions: Vec<McpDemotionRow>,
    /// The spent-approval ledger: nonce -> the instant past which the entry is meaningless.
    #[serde(default)]
    spent_ask_states: Vec<(String, u64)>,
}

/// One persisted MCP call: its `(principal, seq)` primary key plus the OPAQUE body the seam wrote.
/// The body is carried verbatim — this fixture does not interpret it — so both the neutral
/// `{seq,prev_hash,hash,content}` shape the engine now writes and a legacy `serde(McpCallRecord)` body
/// a prior build wrote round-trip through the same table.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct CallBody {
    principal: String,
    seq: u64,
    body: Vec<u8>,
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
    /// The RMW is serialised CROSS-HANDLE by an advisory whole-file lock ([`FileLock`], `flock`), not
    /// just by the per-handle `self.gate` Mutex. `gate` alone orders one handle's own calls; two
    /// handles on the same `durable_path` — the fleet this fixture exists to model — each hold their
    /// OWN `gate`, so without the file lock they would both `load()` the same state, both apply their
    /// mutation, and the second `write` would clobber the first: a classic lost update (a dropped MCP
    /// call row, a double-redeemed approval nonce). `flock(LOCK_EX)` on a persistent sibling lock file
    /// makes the load-apply-write one critical section across every handle and every process, so the
    /// read-modify-write really is atomic the way a real backend's single transaction is.
    ///
    /// The persist itself is ATOMIC, through the one blessed publisher (`busbar_api::durable::write`:
    /// sibling temp, fsync, rename, temp cleaned on every error path). The rename publish means even a
    /// reader that does NOT hold the lock (`read` below) sees either the old complete state or the new
    /// complete state, never a tear.
    fn mutate<T>(&self, f: impl FnOnce(&mut Durable) -> T) -> StoreResult<T> {
        let _guard = self
            .gate
            .lock()
            .map_err(|_| StoreError("poisoned".into()))?;
        // Cross-handle / cross-process critical section: held across load → apply → publish, released
        // on drop AFTER the durable write returns.
        let _flock = FileLock::acquire(&self.path)?;
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

/// The sibling advisory-lock file for a `durable_path`. A DEDICATED file (`.<name>.lock`), never the
/// data file: the data file is republished by an atomic rename on every write (`durable::write`), so
/// its inode changes and a lock taken on it would not span the rename. The lock file is created once
/// and never renamed or removed, so a lock on it is stable across the whole RMW. It shares the
/// data file's holding directory but has a name that cannot collide with `durable::write`'s temps
/// (`.<name>.<pid>-<seq>.tmp`).
fn lock_path_for(path: &std::path::Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_owned())
        .unwrap_or_else(|| std::ffi::OsString::from("store"));
    let mut lock_name = std::ffi::OsString::from(".");
    lock_name.push(name);
    lock_name.push(".lock");
    match path.parent().filter(|p| !p.as_os_str().is_empty()) {
        Some(dir) => dir.join(lock_name),
        None => PathBuf::from(lock_name),
    }
}

/// An RAII advisory whole-file lock over a `durable_path`, held for one read-modify-write and
/// released on drop. This is what serialises the RMW ACROSS HANDLES and processes — see
/// [`FileStore::mutate`]. On unix it is a real `flock(LOCK_EX)`; on non-unix it is a no-op holder
/// (the fixture's fleet/durability tests run on unix CI, and this keeps the crate compiling
/// everywhere — a non-unix build simply falls back to the pre-existing per-handle `gate` ordering).
struct FileLock {
    #[cfg(unix)]
    _file: std::fs::File,
}

impl FileLock {
    #[cfg(unix)]
    fn acquire(path: &std::path::Path) -> StoreResult<Self> {
        use std::os::unix::io::AsRawFd as _;
        let lock_path = lock_path_for(path);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(|e| StoreError(format!("lock file '{}' open: {e}", lock_path.display())))?;
        // Blocking exclusive advisory lock. `flock` is associated with the open file DESCRIPTION, so
        // two handles in one process (each with their own `open`) block each other just as two
        // processes do — exactly the fleet contention this closes. EINTR is retried.
        loop {
            // SAFETY: `file` owns the fd for the duration of this call.
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(StoreError(format!("flock LOCK_EX: {err}")));
        }
        Ok(Self { _file: file })
    }

    #[cfg(not(unix))]
    fn acquire(_path: &std::path::Path) -> StoreResult<Self> {
        Ok(Self {})
    }
}

#[cfg(unix)]
impl Drop for FileLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd as _;
        // Explicit unlock; closing the fd on drop would release it anyway, this just makes the
        // release a named part of the critical-section boundary.
        // SAFETY: `_file` still owns the fd here.
        let _ = unsafe { libc::flock(self._file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// The durable A2A-task / MCP-call-log / demotion / spent-ledger operations, kept as PRIVATE
/// inherent helpers now that the `Store` trait surface is neutral-only (1.6.0 Commit 4): the
/// eight neutral verbs in `impl Store` below delegate to these, and this crate's tests read
/// back through them to prove the neutral surface shares one on-disk table with them. The logic
/// is unchanged from when they were the protocol-named trait methods.
impl FileStore {
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
    //
    // The body is OPAQUE now (the engine writes the neutral seam envelope, and reframes on read), so
    // the write path stores it verbatim keyed by `(principal, seq)` — no decode. The typed reads below
    // decode the body for this fixture's OWN tests, which write typed `McpCallRecord` bodies; the
    // engine never calls them (it reads through `list_plane_records` and reframes itself).
    fn append_call_body(&self, record: &PlaneRecord) -> StoreResult<()> {
        // Byte-identical on an existing `(principal, seq)` is the retry and is `Ok(())`; a DIFFERENT
        // body is a forked or tampered log and is an error, exactly as `append_audit` settles it.
        // ONE read-modify-write, not a `read` then a `mutate`: the fork check and the append have to
        // see the same state, and between two calls another handle on the same file can land a row.
        let principal = record.parent.clone().unwrap_or_else(|| record.id.clone());
        let seq = record.seq;
        let body = record.body.clone();
        self.mutate(|d| {
            match d
                .call_bodies
                .iter()
                .find(|c| c.principal == principal && c.seq == seq)
            {
                Some(prev) if prev.body == body => Ok(()),
                Some(_) => Err(StoreError(format!(
                    "mcp call log fork at ({principal}, {seq})"
                ))),
                None => {
                    d.call_bodies.push(CallBody {
                        principal: principal.clone(),
                        seq,
                        body: body.clone(),
                    });
                    Ok(())
                }
            }
        })?
    }
    fn list_call_bodies(&self, principal: &str) -> StoreResult<Vec<Vec<u8>>> {
        self.read(|d| {
            let mut out: Vec<(u64, Vec<u8>)> = d
                .call_bodies
                .iter()
                .filter(|c| c.principal == principal)
                .map(|c| (c.seq, c.body.clone()))
                .collect();
            out.sort_by_key(|(seq, _)| *seq);
            out.into_iter().map(|(_, b)| b).collect()
        })
    }
    #[cfg(test)] // typed read used only by this fixture's own round-trip tests; the engine reads
                 // through `list_plane_records` (opaque bodies) and reframes them itself.
    fn list_mcp_calls(&self, principal: &str) -> StoreResult<Vec<McpCallRecord>> {
        // This fixture's tests write typed bodies; a body the engine wrote through the neutral seam
        // does not decode as a typed row and is skipped here.
        Ok(self
            .list_call_bodies(principal)?
            .iter()
            .filter_map(|b| decode::<McpCallRecord>(b).ok())
            .collect())
    }
    fn list_mcp_call_principals(&self) -> StoreResult<Vec<String>> {
        self.read(|d| {
            let mut out: Vec<String> = d.call_bodies.iter().map(|c| c.principal.clone()).collect();
            out.sort();
            out.dedup();
            out
        })
    }
    fn purge_call_bodies_before(&self, before: u64) -> StoreResult<u64> {
        self.mutate(|d| {
            let was = d.call_bodies.len();
            // The neutral seam leaves the envelope `ts` at 0, so the retention axis is read from the
            // body when it decodes as a typed row; an opaque neutral body carries no `ts` here and is
            // kept (retention-by-age of neutral call bodies is not a claim this fixture makes).
            d.call_bodies.retain(|c| {
                let ts = decode::<McpCallRecord>(&c.body).map(|r| r.ts).unwrap_or(0);
                ts >= before
            });
            (was - d.call_bodies.len()) as u64
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

    // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD VERBS (1.6.0, Commit 2) ──────────────────────────
    //
    // These implement the eight neutral verbs over the SAME on-disk tables the protocol-named
    // methods above own. Each maps its `kind` to a table, decodes the opaque `body` into that
    // table's typed row, and DELEGATES to the matching named method (re-encoding rows on the read
    // path) — so a write through the neutral surface and a read through the named one see one and the
    // same row, and behaviour is byte-identical to the named path (including the retention split:
    // `task` purges only terminal rows via `purge_tasks_before`, `call` purges all older via
    // `purge_mcp_calls_before`). A `kind` this store does not recognise falls through to the neutral
    // trait default (inert), exactly as an un-overridden backend would behave.
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        match record.kind.as_str() {
            "task" => self.put_task(&decode(&record.body)?),
            "demotion" => self.put_mcp_demotion(&decode(&record.body)?),
            _ => Ok(()),
        }
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        match kind {
            "task" => self.get_task(id)?.map(|r| encode(&r)).transpose(),
            _ => Ok(None),
        }
    }

    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        match record.kind.as_str() {
            "task_event" => self.append_task_event(&decode(&record.body)?),
            "call" => self.append_call_body(record),
            _ => Ok(()),
        }
    }

    fn list_plane_records(
        &self,
        kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        match (kind, selector) {
            ("task", PlaneSelector::All) => self.list_tasks()?.iter().map(encode).collect(),
            ("demotion", PlaneSelector::All) => {
                self.list_mcp_demotions()?.iter().map(encode).collect()
            }
            ("task_event", PlaneSelector::Parent(p)) => {
                self.list_task_events(p)?.iter().map(encode).collect()
            }
            // Bodies verbatim, in seq order — exactly what a durable backend returns; the engine
            // reframes them itself (the plane knows the call framing; this fixture does not).
            ("call", PlaneSelector::Parent(p)) => self.list_call_bodies(p),
            _ => Ok(Vec::new()),
        }
    }

    fn list_plane_record_parents(&self, kind: &str) -> StoreResult<Vec<String>> {
        match kind {
            "call" => self.list_mcp_call_principals(),
            _ => Ok(Vec::new()),
        }
    }

    fn purge_plane_records_before(&self, kind: &str, before: u64) -> StoreResult<u64> {
        match kind {
            "task" => self.purge_tasks_before(before),
            "call" => self.purge_call_bodies_before(before),
            _ => Ok(0),
        }
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> StoreResult<()> {
        match kind {
            "demotion" => self.clear_mcp_demotion(id),
            _ => Ok(()),
        }
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> StoreResult<bool> {
        match kind {
            "ask" => self.redeem_ask_state(token, expires_at, now),
            _ => Ok(true),
        }
    }
}

/// Decode an opaque plane `body` into the typed row a kind's table holds. A malformed body is a
/// STORE ERROR the caller sees, never a silently-dropped write.
fn decode<T: serde::de::DeserializeOwned>(body: &[u8]) -> StoreResult<T> {
    serde_json::from_slice(body).map_err(|e| StoreError(format!("plane body decode: {e}")))
}

/// Re-encode a typed row back to an opaque `body` on the read path — the exact inverse of [`decode`],
/// so a body written through the neutral surface reads back byte-for-byte.
fn encode<T: serde::Serialize>(row: &T) -> StoreResult<Vec<u8>> {
    serde_json::to_vec(row).map_err(|e| StoreError(e.to_string()))
}

busbar_plugin_sdk::export_store_plugin!(open);

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
