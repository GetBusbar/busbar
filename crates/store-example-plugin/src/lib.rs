// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A **hermetic trivial `kind: store` plugin** — a `cdylib` exporting the store C ABI over this
//! crate's OWN in-process backend, `RamStore` (see `src/ram.rs`), used when no config is given. It is
//! the in-tree ABI-crossing coverage for the `kind: store` seam (the store-seam analogue of
//! `busbar-secret-example-plugin`); its job is to be a real, loadable, signable store plugin for the
//! ABI to round-trip through, both in this crate's own boundary tests and as the fixture
//! `plugin-ci.yml`'s install-and-serve CI step packs and installs against a real running busbar.
//!
//! ## STANDALONE ON PURPOSE
//!
//! This crate is the copy-me template for `kind: store`, so it names NO other store: not
//! `busbar-store-memory`, not any sibling instance of its own kind. `docs/design/PLUGIN-TREE.md` §4
//! admits no exception to that rule, and a template that only compiles because the manifest
//! allow-list waived it for the first-party copy teaches every third-party store plugin a shape that
//! fails `kind-isolation:deps` on the day it ships. Everything this plugin needs is in this crate.
//!
//! ## The one exception: `{"durable_path": "…"}`
//!
//! Given that config key the plugin opens a [`FileStore`] instead — a tiny JSON-file-backed store
//! that keeps A2A task rows, task provenance events, MCP call records, virtual keys, the usage ledger
//! and metering on DISK (M4). It exists for one reason: DURABILITY ACROSS A RESTART cannot be proven
//! against a store whose state dies with the process, and the durability of these tables is a product
//! claim that had never been exercised over the path a deployment actually takes (the plugin ABI).
//! `RamStore` survives one plugin handle and no more, so a "write, restart, read it back" test needs a
//! backend that puts bytes somewhere a second `busbar_open` can find them.
//!
//! NO config still means `RamStore`, so the CI install-and-serve fixture and every existing
//! over-the-ABI test are untouched. A config that is PRESENT but unreadable is a load error: the
//! whole point of the durable mode is that the rows are on disk, and a plugin that quietly opens a
//! RAM store because it could not parse the line naming the file has taken that away silently.

use busbar_api::{
    MeteringDelta, MeteringRow, PlaneDisposition, PlaneRecord, PlaneSelector, Store, StoreError,
    StoreResult, UsageDelta, UsageLedger, VirtualKey,
};
mod ram;
use ram::RamStore;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Retention ceiling for tombstoned `keys` rows and old `usage`/`metering` rows, keyed by the row's
/// own epoch-second field (`deleted_at` / `window_start` / `bucket`) — the SAME bound and the SAME
/// reasoning as `ram::RamStore`'s own `MAX_RETENTION_SECS` (see that module's doc): a store that never
/// sweeps grows without bound for the life of the store, and for `FileStore` "the life of the store"
/// now spans restarts instead of dying with the process, which makes an unbounded table here WORSE
/// than the in-process one, not equivalent to it.
const MAX_RETENTION_SECS: u64 = 31 * 86_400;

/// Amortized sweep cadence, mirroring `ram::RamStore`'s: one `retain()` pass per this many writes to
/// the table being swept, so a durability fixture with a handful of rows does not pay a sweep on every
/// single call.
const SWEEP_INTERVAL: u64 = 256;

/// One tick of an amortized sweep counter; `true` on every `SWEEP_INTERVAL`-th call. A per-handle,
/// in-memory counter — like `ram::RamStore`'s, it does not itself need to survive a restart, since
/// missing one sweep window merely defers the next `retain()` pass rather than losing data.
fn tick(counter: &AtomicU64) -> bool {
    counter
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1)
        .is_multiple_of(SWEEP_INTERVAL)
}

/// The plugin's optional config. Every field optional; an ABSENT body means "`RamStore`, no
/// config", which is this fixture's original and default posture. A present body must parse.
#[derive(serde::Deserialize)]
struct Cfg {
    /// Where [`FileStore`] keeps its JSON. Presence of this key is what selects the durable mode.
    durable_path: Option<String>,
}

/// Construct the module. An EMPTY config means "no config at all", which is this fixture's original
/// posture: a wrapped `RamStore` that takes none. Anything else must PARSE — a config the
/// operator wrote and this plugin could not read is a load error, not a silent demotion to RAM. That
/// downgrade is the dangerous shape: a stray trailing comma in `{"durable_path": "/var/lib/…"}`
/// turned a durable store into an ephemeral one, the plugin loaded clean, and the rows only stopped
/// existing at the next restart.
fn open(cfg: &str) -> Result<Box<dyn Store>, String> {
    if cfg.trim().is_empty() {
        return Ok(Box::new(RamStore::new()));
    }
    let parsed: Cfg = serde_json::from_str(cfg)
        .map_err(|e| format!("invalid store-example plugin config: {e}"))?;
    match parsed.durable_path {
        Some(path) => Ok(Box::new(FileStore::open(PathBuf::from(path))?)),
        None => Ok(Box::new(RamStore::new())),
    }
}

/// Everything [`FileStore`] writes through to disk, as one JSON document. Rewritten whole on every
/// mutation: this is a test fixture holding a handful of rows, so the simplest thing that is
/// actually durable beats anything cleverer.
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Durable {
    /// The A2A task table, kept PURELY as OPAQUE envelope rows — this fixture never decodes a task
    /// body. Each row carries the `PlaneRecord`'s `id`, `ts`, `disposition` and opaque `body`; the
    /// `disposition` and `ts` sidecar columns are what `purge_tasks_before` reads to honour the
    /// terminal-only retention contract WITHOUT ever looking inside the body.
    tasks: Vec<TaskRecord>,
    /// The A2A per-task chain, kept as the OPAQUE stored BODIES a durable backend holds — the neutral
    /// `{seq,prev_hash,hash,content}` the seam persists — keyed by `(task_id, seq)`. The engine
    /// reframes them on read; this fixture never decodes the body, so a body written through the
    /// neutral seam (which names no plane type) persists and reads back verbatim.
    /// `#[serde(default)]` so a file this fixture wrote before the cleave still opens (its old typed
    /// `task_events` field is simply dropped — a test fixture keeps no cross-format migration).
    #[serde(default)]
    task_event_bodies: Vec<TaskEventBody>,
    /// The MCP per-call chain, kept as the OPAQUE stored BODIES a durable backend holds — the neutral
    /// `{seq,prev_hash,hash,content}` the P5 seam persists — keyed by `(principal, seq)`. The engine
    /// reframes them on read; this fixture never decodes the body, so a body written through the
    /// neutral seam (which names no plane type) persists and reads back verbatim.
    /// `#[serde(default)]` so a file this fixture wrote before the cleave still opens.
    #[serde(default)]
    call_bodies: Vec<CallBody>,
    /// Recorded upstream demotions, kept as OPAQUE envelope rows keyed by `id` (the upstream
    /// `server`). `#[serde(default)]` so a file written by an earlier build of this fixture still
    /// opens (its old typed `mcp_demotions` field is simply dropped).
    #[serde(default)]
    demotions: Vec<DemotionRecord>,
    /// The spent-approval ledger: nonce -> the instant past which the entry is meaningless.
    #[serde(default)]
    spent_ask_states: Vec<(String, u64)>,
    /// The push-notification configurations, kept as OPAQUE envelope rows keyed by `id` — the same
    /// `(id, ts, disposition, body)` shape a task row has, because the column that matters here is
    /// the same one: `disposition`. A push callback token is LIVE while its row is `Active` and goes
    /// dead the moment the write that made its task terminal flipped the row to `Terminal`, which is
    /// a typed column this fixture reads without ever decoding the body.
    #[serde(default)]
    push_configs: Vec<TaskRecord>,
    /// The virtual-key table, keyed by `VirtualKey::id`. `#[serde(default)]` so a file written
    /// before this table existed (when keys lived only in the in-process `RamStore` and were lost on
    /// every restart) still opens.
    #[serde(default)]
    keys: Vec<VirtualKey>,
    /// The per-(bucket, window) token ledger. `#[serde(default)]` for the same pre-durability-fix
    /// reason as `keys` above.
    #[serde(default)]
    usage: Vec<UsageRow>,
    /// The per-(key_id, bucket, model, provider) metering accumulation. `#[serde(default)]` for the
    /// same pre-durability-fix reason as `keys` above.
    #[serde(default)]
    metering: Vec<MeteringEntry>,
    /// Monotonic revision counter for `VirtualKey::revision`, persisted so it keeps counting up
    /// across a restart rather than resetting to 0 and making every reopened key look "unchanged"
    /// to `Store::list_keys_since`'s revision-delta default.
    #[serde(default)]
    next_revision: u64,
}

/// One persisted token ledger row: the `(bucket_id, window_start)` primary key plus the ledger
/// itself. A `Vec` (not a `HashMap`) because `serde_json` map keys must be strings and this key is a
/// tuple — mirrors every other table in this file.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct UsageRow {
    bucket_id: String,
    window_start: u64,
    ledger: UsageLedger,
}

/// One persisted metering accumulation row: the `bucket` primary-key component that
/// [`MeteringRow`] itself does not carry (it rides alongside the row here instead), plus the row.
/// Primary key is `(row.key_id, bucket, row.model, row.provider)`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct MeteringEntry {
    bucket: u64,
    row: MeteringRow,
}

/// One persisted A2A task: the `PlaneRecord`'s `id` primary key plus the OPAQUE body the seam wrote,
/// and the `ts`/`disposition` SIDECAR columns retention sweeps on. The body is carried verbatim — this
/// fixture never interprets it — so whatever the neutral seam writes reads back byte-for-byte, and
/// terminality is read from the typed `disposition` column, never decoded out of the body.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct TaskRecord {
    id: String,
    ts: u64,
    disposition: PlaneDisposition,
    body: Vec<u8>,
}

/// One persisted upstream demotion: the `PlaneRecord`'s `id` primary key (the `server`) plus the
/// OPAQUE body the seam wrote, carried verbatim.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct DemotionRecord {
    id: String,
    body: Vec<u8>,
}

/// One persisted MCP call: its `(principal, seq)` primary key, the envelope `ts` SIDECAR column
/// retention sweeps on, plus the OPAQUE body the seam wrote. The body is carried verbatim — this
/// fixture never interprets it — so both the neutral `{seq,prev_hash,hash,content}` shape the engine
/// writes and any other body round-trip through the same table, and age-based purge reads the typed
/// `ts` column rather than decoding the body.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct CallBody {
    principal: String,
    seq: u64,
    ts: u64,
    body: Vec<u8>,
}

/// One persisted A2A task event: its `(task_id, seq)` primary key plus the OPAQUE body the seam wrote.
/// The body is carried verbatim — this fixture never interprets it — so whatever the neutral
/// `{seq,prev_hash,hash,content}` shape the engine writes round-trips through the same table (the
/// engine's reframe reads it on the way out). The `call` kind's `CallBody`, mirrored for `task_event`.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct TaskEventBody {
    task_id: String,
    seq: u64,
    body: Vec<u8>,
}

/// A JSON-file-backed store. The A2A task/MCP-call-log methods, the virtual-key table, the usage
/// ledger and metering are ALL REAL — every one reads and writes `path`, so a row written by one
/// plugin handle is found by the next one. Only the credential methods (`put_key_with_credential`,
/// `list_credentials`, …) keep the trait default: this fixture exists to prove durability across a
/// restart, and pretending to durably store a credential it never reads back would be exactly the
/// kind of claim this crate is here to catch.
struct FileStore {
    path: PathBuf,
    /// Serialises this handle's own read-modify-write cycles. It holds no DATA, deliberately — see
    /// [`FileStore::load`].
    gate: Mutex<()>,
    /// Amortized sweep counters for the retention bound on `keys`/`usage`/`metering` — see
    /// `MAX_RETENTION_SECS`. Per-handle and in-memory, like `ram::RamStore`'s own tickers: losing
    /// them on restart only defers the next sweep, never data.
    keys_sweep_ticker: AtomicU64,
    usage_sweep_ticker: AtomicU64,
    metering_sweep_ticker: AtomicU64,
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
            gate: Mutex::new(()),
            keys_sweep_ticker: AtomicU64::new(0),
            usage_sweep_ticker: AtomicU64::new(0),
            metering_sweep_ticker: AtomicU64::new(0),
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
// Only the `#[cfg(unix)]` advisory-lock path calls this; on Windows the whole function is unused, and
// `-D warnings` turns that dead code into a hard error. It computes the lock file's path, which is a
// unix-only concept here, so gate the function to match its sole caller.
#[cfg(unix)]
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
/// inherent helpers now that the `Store` trait surface is neutral-only (1.6.0): the eight neutral
/// verbs in `impl Store` below delegate to these. Every one operates PURELY on the opaque envelope —
/// bodies are stored and returned verbatim and identity/ordering/retention read only the typed
/// sidecar columns; nothing here decodes a body into a named plane row.
impl FileStore {
    // ── the durable ones: A2A task state, stored PURELY OPAQUELY ──────────────────────────────
    //
    // A task rides as a `TaskRecord` envelope row — the `PlaneRecord`'s `id`, `ts`, `disposition` and
    // opaque `body`. This fixture NEVER decodes a task body: identity, ordering and retention all read
    // the typed sidecar columns, and the body is stored and returned verbatim.
    fn upsert_task(&self, record: &PlaneRecord) -> StoreResult<()> {
        let row = TaskRecord {
            id: record.id.clone(),
            ts: record.ts,
            disposition: record.disposition,
            body: record.body.clone(),
        };
        self.mutate(move |d| match d.tasks.iter_mut().find(|t| t.id == row.id) {
            // UPSERT by `id`, as the trait requires — a second write for the same id replaces the row
            // rather than appending a rival one.
            Some(existing) => *existing = row.clone(),
            None => d.tasks.push(row),
        })
    }
    fn get_task_body(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        self.read(|d| d.tasks.iter().find(|t| t.id == id).map(|t| t.body.clone()))
    }
    fn list_task_bodies(&self) -> StoreResult<Vec<Vec<u8>>> {
        self.read(|d| d.tasks.iter().map(|t| t.body.clone()).collect())
    }
    fn purge_tasks_before(&self, before: u64) -> StoreResult<u64> {
        // TERMINAL rows only: an interrupted task waiting on a human is exactly the row that sits
        // still for a long time, and dropping it loses the work. Terminality is read from the typed
        // `disposition` SIDECAR column — never decoded out of the opaque body.
        self.mutate(|d| {
            let purged: std::collections::HashSet<String> = d
                .tasks
                .iter()
                .filter(|t| t.ts < before && t.disposition == PlaneDisposition::Terminal)
                .map(|t| t.id.clone())
                .collect();
            d.tasks.retain(|t| !purged.contains(&t.id));
            // CASCADE: a task's event chain has no retention path of ITS own — nothing else ever
            // removes a `task_event` row — so purging the task and keeping its events grows the file
            // forever with chains whose parent no longer exists, and those events outlive the exact
            // retention decision that was just made about them. Only the chains under a task that
            // actually went are dropped: an event whose task is still retained (or was never
            // written) is untouched, so this can never be a second, wider retention rule in disguise.
            d.task_event_bodies.retain(|e| !purged.contains(&e.task_id));
            purged.len() as u64
        })
    }
    // ── the durable ones: the A2A task-event chain, stored OPAQUELY (mirrors the MCP call log) ────
    //
    // The body is OPAQUE (the engine writes the neutral seam envelope and reframes on read), so the
    // write path stores it verbatim keyed by `(task_id, seq)` — no decode ever. Decoding a neutral body
    // as a typed row would hard-fail (the neutral shape has none of those fields), which is the exact
    // bug this fixture carried for `task_event` after the `call` kind was already fixed.
    fn append_task_event_body(&self, record: &PlaneRecord) -> StoreResult<()> {
        // Byte-identical on an existing `(task_id, seq)` is the retry and is `Ok(())`; a DIFFERENT body
        // is a forked or tampered log and is an error — the same settlement `append_call_body` makes.
        let task_id = record.parent.clone().unwrap_or_else(|| record.id.clone());
        let seq = record.seq;
        let body = record.body.clone();
        self.mutate(|d| {
            match d
                .task_event_bodies
                .iter()
                .find(|e| e.task_id == task_id && e.seq == seq)
            {
                Some(prev) if prev.body == body => Ok(()),
                Some(_) => Err(StoreError(format!(
                    "a2a task-event log fork at ({task_id}, {seq})"
                ))),
                None => {
                    d.task_event_bodies.push(TaskEventBody {
                        task_id: task_id.clone(),
                        seq,
                        body: body.clone(),
                    });
                    Ok(())
                }
            }
        })?
    }
    fn list_task_event_bodies(&self, task_id: &str) -> StoreResult<Vec<Vec<u8>>> {
        self.read(|d| {
            let mut out: Vec<(u64, Vec<u8>)> = d
                .task_event_bodies
                .iter()
                .filter(|e| e.task_id == task_id)
                .map(|e| (e.seq, e.body.clone()))
                .collect();
            out.sort_by_key(|(seq, _)| *seq);
            out.into_iter().map(|(_, b)| b).collect()
        })
    }
    // ── the durable ones: the MCP call log ───────────────────────────────────────────────────
    //
    // The body is OPAQUE (the engine writes the neutral seam envelope, and reframes on read), so the
    // write path stores it verbatim keyed by `(principal, seq)` — no decode ever. The envelope `ts`
    // rides as a typed SIDECAR column so age-based purge sweeps without decoding the body.
    fn append_call_body(&self, record: &PlaneRecord) -> StoreResult<()> {
        // Byte-identical on an existing `(principal, seq)` is the retry and is `Ok(())`; a DIFFERENT
        // body is a forked or tampered log and is an error, exactly as `append_audit` settles it.
        // ONE read-modify-write, not a `read` then a `mutate`: the fork check and the append have to
        // see the same state, and between two calls another handle on the same file can land a row.
        let principal = record.parent.clone().unwrap_or_else(|| record.id.clone());
        let seq = record.seq;
        let ts = record.ts;
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
                        ts,
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
            // Age-based retention reads the typed `ts` SIDECAR column off the envelope — never decoded
            // out of the opaque body. The call log drops ALL rows older than the cutoff.
            d.call_bodies.retain(|c| c.ts >= before);
            (was - d.call_bodies.len()) as u64
        })
    }

    // ── the durable ones: the MCP demotion record, stored PURELY OPAQUELY ─────────────────────
    fn upsert_demotion(&self, record: &PlaneRecord) -> StoreResult<()> {
        let row = DemotionRecord {
            id: record.id.clone(),
            body: record.body.clone(),
        };
        self.mutate(
            move |d| match d.demotions.iter_mut().find(|r| r.id == row.id) {
                // UPSERT by `id` (the upstream `server`), as the trait requires.
                Some(existing) => *existing = row.clone(),
                None => d.demotions.push(row),
            },
        )
    }
    fn list_demotion_bodies(&self) -> StoreResult<Vec<Vec<u8>>> {
        self.read(|d| d.demotions.iter().map(|r| r.body.clone()).collect())
    }
    fn clear_demotion(&self, id: &str) -> StoreResult<()> {
        self.mutate(|d| d.demotions.retain(|r| r.id != id))
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

    // ── the multi-use one: the push-callback capability ──────────────────────────────────────
    fn upsert_push_config(&self, record: &PlaneRecord) -> StoreResult<()> {
        let row = TaskRecord {
            id: record.id.clone(),
            ts: record.ts,
            disposition: record.disposition,
            body: record.body.clone(),
        };
        self.mutate(
            move |d| match d.push_configs.iter_mut().find(|r| r.id == row.id) {
                Some(existing) => *existing = row.clone(),
                None => d.push_configs.push(row),
            },
        )
    }

    fn get_push_config_body(&self, id: &str) -> StoreResult<Option<Vec<u8>>> {
        self.read(|d| {
            d.push_configs
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.body.clone())
        })
    }

    fn delete_push_config(&self, id: &str) -> StoreResult<()> {
        self.mutate(|d| d.push_configs.retain(|r| r.id != id))
    }

    /// LIVE means all three, and the `&&` is the point: present, still `Active`, and inside its
    /// deadline. A missing row is not live (there is no capability), a `Terminal` row is not live
    /// (the task it named has finished, so the token is revoked), and a lapsed one is not live even
    /// if nothing has finished. Nothing is written: asking twice answers the same twice, which is
    /// what makes this usable for the several callbacks one task legitimately receives.
    fn push_config_live(&self, id: &str, expires_at: u64, now: u64) -> StoreResult<bool> {
        self.read(|d| {
            d.push_configs.iter().any(|r| {
                r.id == id && matches!(r.disposition, PlaneDisposition::Active) && now <= expires_at
            })
        })
    }

    // ── the durable ones (M4): virtual keys, the usage ledger, and metering ─────────────────────
    //
    // These used to delegate to the in-process `inner: RamStore`, which meant every key, every
    // rate-limit ledger and every metering row was lost the instant the plugin handle was dropped —
    // exactly the restart-durability claim this crate exists to prove, broken for the one config
    // (`durable_path`) whose entire point is proving it. They now read and write `self.path` like
    // every other table in this file, under the same cross-handle `flock` critical section.

    /// UPSERT by `id`, with the SAME tombstone precondition [`RamStore::put_key`] enforces: a write
    /// that does not itself carry a tombstone must never clear an existing one, tested and applied
    /// inside the ONE critical section `mutate` already holds — a caller-side read-then-write check
    /// cannot close the gap a concurrent `delete_key` opens between the read and the write.
    fn put_key_impl(&self, key: &VirtualKey) -> StoreResult<()> {
        let key = key.clone();
        self.mutate(move |d| {
            if key.deleted_at.is_none() {
                if let Some(existing) = d.keys.iter().find(|k| k.id == key.id) {
                    if existing.deleted_at.is_some() {
                        return Err(StoreError(format!(
                            "put_key: '{}' is tombstoned and its id is never reissued; refusing to \
                             clear the tombstone",
                            key.id
                        )));
                    }
                }
            }
            d.next_revision += 1;
            let mut key = key;
            key.revision = d.next_revision;
            match d.keys.iter_mut().find(|k| k.id == key.id) {
                Some(existing) => *existing = key,
                None => d.keys.push(key),
            }
            if tick(&self.keys_sweep_ticker) {
                let n = now();
                // NEVER prunes a live row: only `deleted_at.is_some()` rows are candidates, and only
                // past the same ceiling attribution already stops caring past — mirrors
                // `ram::RamStore::put_key`'s own sweep exactly.
                d.keys.retain(|k| match k.deleted_at {
                    None => true,
                    Some(deleted_at) => deleted_at.saturating_add(MAX_RETENTION_SECS) > n,
                });
            }
            Ok(())
        })?
    }

    fn get_key_impl(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.read(|d| d.keys.iter().find(|k| k.id == id).cloned())
    }

    fn list_keys_impl(&self) -> StoreResult<Vec<VirtualKey>> {
        // Deliberately UNFILTERED (tombstones included) — see `Store::list_keys`'s doc.
        self.read(|d| {
            let mut v = d.keys.clone();
            v.sort_by_key(|k| k.created_at);
            v
        })
    }

    /// TOMBSTONE `id`: the row SURVIVES (so attribution by key id — metering rows, audit records —
    /// keeps resolving forever) but its usage ledger is dropped, mirroring `RamStore::delete_key`'s
    /// cascade exactly. An unknown id is an ERROR, not a silent success; an already-tombstoned id is
    /// idempotent `Ok(())`.
    fn delete_key_impl(&self, id: &str) -> StoreResult<()> {
        let id = id.to_string();
        self.mutate(move |d| {
            let ts = now();
            let Some(key) = d.keys.iter_mut().find(|k| k.id == id) else {
                return Err(StoreError(format!("delete_key: unknown id '{id}'")));
            };
            if key.deleted_at.is_some() {
                return Ok(()); // idempotent: already tombstoned
            }
            key.enabled = false;
            key.deleted_at = Some(ts);
            d.next_revision += 1;
            let rev = d.next_revision;
            d.keys.iter_mut().find(|k| k.id == id).unwrap().revision = rev;
            d.usage.retain(|u| u.bucket_id != id);
            Ok(())
        })?
    }

    fn get_usage_impl(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.read(|d| {
            d.usage
                .iter()
                .find(|u| u.bucket_id == bucket_id && u.window_start == window_start)
                .map(|u| u.ledger.clone())
                .unwrap_or_default()
        })
    }

    /// Write-behind ABSOLUTE set: replaces the whole (bucket, window) ledger row.
    fn put_usage_impl(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        let bucket_id = bucket_id.to_string();
        let ledger = ledger.clone();
        self.mutate(move |d| {
            match d
                .usage
                .iter_mut()
                .find(|u| u.bucket_id == bucket_id && u.window_start == window_start)
            {
                Some(existing) => existing.ledger = ledger,
                None => d.usage.push(UsageRow {
                    bucket_id,
                    window_start,
                    ledger,
                }),
            }
        })
    }

    /// Write-behind ADDITIVE accumulate of a bucket's window ledger, mirroring `RamStore::add_usage`
    /// field-for-field: adds the signed delta to whatever is on disk NOW, inside the ONE `mutate`
    /// critical section, so two handles racing on the same `(bucket_id, window_start)` each read the
    /// other's committed write rather than clobbering it. Overriding the trait's own default here is
    /// the whole point — that default is `get_usage` then `put_usage`, which on this backend is TWO
    /// separate flock acquisitions with no atomicity between them: a second handle's `add_usage` could
    /// commit in the gap and have its delta silently discarded by the first handle's stale-based
    /// `put_usage`, the exact lost-update class `mutate`'s own doc warns a caller-side read-then-write
    /// cannot close.
    fn add_usage_impl(
        &self,
        bucket_id: &str,
        window_start: u64,
        delta: &UsageDelta,
    ) -> StoreResult<()> {
        let bucket_id = bucket_id.to_string();
        let delta = delta.clone();
        self.mutate(move |d| {
            match d
                .usage
                .iter_mut()
                .find(|u| u.bucket_id == bucket_id && u.window_start == window_start)
            {
                Some(existing) => existing.ledger.apply_delta(&delta),
                None => {
                    let mut ledger = UsageLedger::default();
                    ledger.apply_delta(&delta);
                    d.usage.push(UsageRow {
                        bucket_id,
                        window_start,
                        ledger,
                    });
                }
            }
            if tick(&self.usage_sweep_ticker) {
                let n = now();
                d.usage
                    .retain(|u| u.window_start.saturating_add(MAX_RETENTION_SECS) > n);
            }
        })
    }

    /// ACCUMULATE (UPSERT/add) one row per `(key_id, bucket, model, provider)`, mirroring
    /// `RamStore::add_metering` field-for-field.
    fn add_metering_impl(&self, delta: &MeteringDelta) -> StoreResult<()> {
        let delta = delta.clone();
        self.mutate(move |d| {
            match d.metering.iter_mut().find(|e| {
                e.bucket == delta.bucket
                    && e.row.key_id == delta.key_id
                    && e.row.model == delta.model
                    && e.row.provider == delta.provider
            }) {
                Some(e) => {
                    e.row.tokens_input = e.row.tokens_input.saturating_add(delta.tokens_input);
                    e.row.tokens_output = e.row.tokens_output.saturating_add(delta.tokens_output);
                    e.row.tokens_cache_read = e
                        .row
                        .tokens_cache_read
                        .saturating_add(delta.tokens_cache_read);
                    e.row.tokens_cache_write = e
                        .row
                        .tokens_cache_write
                        .saturating_add(delta.tokens_cache_write);
                    e.row.requests = e.row.requests.saturating_add(delta.requests);
                    e.row.billable_requests = e
                        .row
                        .billable_requests
                        .saturating_add(delta.billable_requests);
                }
                None => d.metering.push(MeteringEntry {
                    bucket: delta.bucket,
                    row: MeteringRow {
                        key_id: delta.key_id,
                        model: delta.model,
                        provider: delta.provider,
                        tokens_input: delta.tokens_input,
                        tokens_output: delta.tokens_output,
                        tokens_cache_read: delta.tokens_cache_read,
                        tokens_cache_write: delta.tokens_cache_write,
                        requests: delta.requests,
                        billable_requests: delta.billable_requests,
                        key_group_at_use: delta.key_group_at_use,
                        pricing_version: delta.pricing_version,
                    },
                }),
            }
            if tick(&self.metering_sweep_ticker) {
                let n = now();
                d.metering
                    .retain(|e| e.bucket.saturating_add(MAX_RETENTION_SECS) > n);
            }
        })
    }

    fn list_metering_impl(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.read(|d| {
            d.metering
                .iter()
                .filter(|e| e.bucket == bucket)
                .map(|e| e.row.clone())
                .collect()
        })
    }
}

impl Store for FileStore {
    // ── keys / usage / metering: REAL persistence to `self.path` (M4) ────────────────────────
    //
    // No longer delegated to an in-process `RamStore` — see the `_impl` helpers above for why.
    fn put_key(&self, key: &VirtualKey) -> StoreResult<()> {
        self.put_key_impl(key)
    }
    fn get_key(&self, id: &str) -> StoreResult<Option<VirtualKey>> {
        self.get_key_impl(id)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        self.list_keys_impl()
    }
    fn delete_key(&self, id: &str) -> StoreResult<()> {
        self.delete_key_impl(id)
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        self.get_usage_impl(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &UsageLedger,
    ) -> StoreResult<()> {
        self.put_usage_impl(bucket_id, window_start, ledger)
    }
    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        self.add_usage_impl(bucket_id, window_start, delta)
    }
    fn add_metering(&self, delta: &MeteringDelta) -> StoreResult<()> {
        self.add_metering_impl(delta)
    }
    fn list_metering(&self, bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        self.list_metering_impl(bucket)
    }

    // ── THE NEUTRAL KIND-TAGGED PLANE-RECORD VERBS (1.6.0, Commit 2) ──────────────────────────
    //
    // These implement the eight neutral verbs over the on-disk tables, operating PURELY on the opaque
    // envelope: nothing here decodes a `body` into a named plane row. Each maps its `kind` to a table,
    // stores/returns the `body` verbatim, and keys/orders/sweeps off the TYPED sidecar columns
    // (`id`, `parent`, `seq`, `ts`, `disposition`). The retention split rides those columns:
    // `task` purges only `Terminal` rows older than the cutoff, `call` purges all older. A `kind` this
    // store does not recognise falls through to the neutral trait default (inert), exactly as an
    // un-overridden backend would behave.
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        match record.kind.as_str() {
            "task" => self.upsert_task(record),
            "demotion" => self.upsert_demotion(record),
            "push_config" => self.upsert_push_config(record),
            _ => Ok(()),
        }
    }

    fn get_plane_record(&self, kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        match kind {
            "task" => self.get_task_body(id),
            "push_config" => self.get_push_config_body(id),
            _ => Ok(None),
        }
    }

    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        match record.kind.as_str() {
            "task_event" => self.append_task_event_body(record),
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
            // Bodies verbatim — exactly what a durable backend returns; the engine reframes them
            // itself (the plane knows the framing; this fixture does not). Every kind is stored and
            // served opaquely.
            ("task", PlaneSelector::All) => self.list_task_bodies(),
            ("demotion", PlaneSelector::All) => self.list_demotion_bodies(),
            ("task_event", PlaneSelector::Parent(p)) => self.list_task_event_bodies(p),
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
            "demotion" => self.clear_demotion(id),
            "push_config" => self.delete_push_config(id),
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

    /// A kind this fixture does not keep a capability table for falls through to `false`, NOT to
    /// `true` — the same direction the trait's own default takes, and for the same reason. The
    /// fall-through on `redeem_plane_token` just above goes the other way because the two verbs ask
    /// opposite questions; a store that keeps no ledger has spent nothing, but a store that keeps no
    /// capability rows holds no live capability either.
    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> StoreResult<bool> {
        match kind {
            "push_config" => self.push_config_live(token, expires_at, now),
            _ => Ok(false),
        }
    }
}

busbar_plugin_sdk::export_store_plugin!(open);

#[cfg(test)]
mod tests;
