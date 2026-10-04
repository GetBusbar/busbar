// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE EXPORT KIND ON THE ONE DISPATCHER (`BUSBAR-1.6.0.md` THE DESIGN §11; KERNEL<>PLUGINS steps
//! 26/27): [`ExportInstance`], one opened export instance, called through its table
//! (`abi::export`) and nothing else, whichever door it came in by. It implements the contract's
//! [`ExportCalls`], so the kernel feeds and scrapes it without naming this crate.
//!
//! * **deliver** — OFF the request path. A line joins the instance's BOUNDED queue
//!   ([`MAX_QUEUED_LINES`]; past it the line is shed, never queued) and the instance's flusher
//!   coalesces queued lines of one stream into ONE `deliver` batch (JSON LINES, at most
//!   [`MAX_BATCH_LINES`] lines and [`MAX_BATCH_BYTES`] bytes), each with its own host-minted
//!   `op_id` (THE DESIGN §11.11 H4). The batch crosses on a ticket in the write-behind deadline
//!   class, so a reload drain never waits on it (H5), and rides with the job as lent memory; a
//!   FAILED batch is retried with the SAME `op_id`, at most [`DELIVER_ATTEMPTS`] times. One batch
//!   is in flight per instance, so a sink sees its lines in the order they were handed over.
//! * **scrape** / **serve** / **status** / **check** — ticket-less, on the caller's thread (the
//!   watchdog can fault such a crossing but never abandon it, so the buffers lent need no owner);
//!   the host-owned exposition buffer grows ONCE on a short answer (the short-buffer rule); a
//!   leased answer is copied, then its lease released.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use busbar_contract::abi::export::{
    slot, CheckIn, CheckInstance, CheckOut, DeliverIn, ScrapeFamily, ScrapeIn, ScrapeLabel,
    ScrapeOut, ScrapeSample, ServeIn, ServeOut, StatusOut,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, BLOB_ABSENT, BLOB_JSON, BLOB_JSONL, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as lc, OpenIn, OpenOut, ReleaseIn, ValidateIn,
};
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::export_calls::{Delivered, ExportCalls, Family, ServeRequest, Served};

use crate::dispatch::kinds::export::{Export, ExportFacts};
use crate::dispatch::{in_head, out_head, Dispatcher, Frame, Plugin, NO_BLOB};

/// The most lines one instance may hold queued; past it a line is shed.
pub const MAX_QUEUED_LINES: usize = 4096;
/// The most lines one `deliver` batch carries.
pub const MAX_BATCH_LINES: usize = 256;
/// The most bytes one `deliver` batch carries (a single larger line still travels alone).
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// How many times one batch is offered (the first attempt included) before it is dropped.
pub const DELIVER_ATTEMPTS: u32 = 3;
/// The exposition buffer a scrape starts with; a short answer grows it once.
const SCRAPE_BUF: usize = 64 * 1024;
/// How long the flusher sleeps between looks at an empty queue or a reply that has not come.
const WAIT_SLICE: Duration = Duration::from_secs(1);
/// The most request headers a `serve` lends (64 name/value pairs).
const MAX_SERVE_HEADERS: usize = 64;

/// A string the host lends for a call.
fn lend(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// An optional string the host lends; `None` is absent (NULL).
fn lend_opt(s: Option<&str>) -> AbiStr {
    s.map_or(
        AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        lend,
    )
}

/// A list the host lends; empty is NULL.
fn lend_list<T>(l: &[T]) -> *const T {
    if l.is_empty() {
        std::ptr::null()
    } else {
        l.as_ptr()
    }
}

/// Bytes the host lends for a call, as a blob of `fmt`.
fn blob(b: &[u8], fmt: u32) -> Blob {
    if b.is_empty() {
        return NO_BLOB;
    }
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt,
        flags: 0,
    }
}

/// A plugin-owned blob's bytes, copied (the dispatcher's checks bounded them).
fn copy_blob(b: Blob) -> Vec<u8> {
    if b.len == 0 || b.ptr.is_null() || b.fmt == BLOB_ABSENT {
        return Vec::new();
    }
    // SAFETY: a checked plugin-owned blob, live under its lease until `release`.
    unsafe { std::slice::from_raw_parts(b.ptr, b.len) }.to_vec()
}

/// A plugin-owned string, copied.
fn copy_str(s: AbiStr) -> String {
    crate::dispatch::plugin::str_bytes(s)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

/// A plugin's error text, or the outcome's name.
fn why(outcome: Outcome, error: Option<Vec<u8>>) -> String {
    error.map_or_else(
        || format!("{outcome:?}"),
        |e| String::from_utf8_lossy(&e).into_owned(),
    )
}

/// Hand a lease back (ticket-less); `0` is none.
fn release(plugin: &Plugin<Export>, lease: u64) {
    if lease == 0 {
        return;
    }
    let mut f = Frame::new(
        ReleaseIn {
            head: in_head(),
            lease,
        },
        out_head(),
    );
    let _ = plugin.call(lc::RELEASE, &mut f);
}

/// `validate` the instance's `settings` (ticket-less): `Ok` when READY, else the plugin's words —
/// a refusal the host renders line by line (`abi::mechanism::lifecycle::refusal_lines`).
///
/// # Errors
/// The plugin's refusal, verbatim.
pub fn validate(plugin: &Plugin<Export>, settings: &[u8]) -> Result<(), String> {
    let mut f = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: blob(settings, BLOB_JSON),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    let called = plugin.call(lc::VALIDATE, &mut f);
    match called.outcome {
        Outcome::Ready => Ok(()),
        o => Err(why(o, called.error)),
    }
}

/// `check` across `instances` at `phase` (ticket-less, on an OPEN instance): the plugin's findings,
/// one line each, in its order (a JSON list of strings, `BLOB_JSON`).
///
/// # Errors
/// The plugin failed to answer, or answered findings that are not a list of strings.
pub fn check(
    plugin: &Plugin<Export>,
    phase: u32,
    instances: &[(String, Vec<u8>)],
) -> Result<Vec<String>, String> {
    let list: Vec<CheckInstance> = instances
        .iter()
        .map(|(name, settings)| CheckInstance {
            name: lend(name),
            settings: blob(settings, BLOB_JSON),
        })
        .collect();
    let mut f = Frame::new(
        CheckIn {
            head: in_head(),
            phase,
            _reserved: 0,
            instances: lend_list(&list),
            instances_len: list.len(),
        },
        CheckOut {
            head: out_head(),
            findings: NO_BLOB,
        },
    );
    let called = plugin.call(slot::CHECK, &mut f);
    if called.outcome != Outcome::Ready {
        return Err(why(called.outcome, called.error));
    }
    let bytes = copy_blob(f.out.findings);
    release(plugin, called.lease);
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_slice::<Vec<String>>(&bytes)
        .map_err(|e| format!("export plugin check findings are not a JSON list of strings: {e}"))
}

/// One queued line.
struct Line {
    stream: u8,
    bytes: Vec<u8>,
    _hold: Box<dyn Send>,
}

/// What the instance's flusher shares with its callers.
struct Shared {
    plugin: Plugin<Export>,
    dispatcher: Arc<Dispatcher>,
    facts: ExportFacts,
    queue: Mutex<VecDeque<Line>>,
    ready: Condvar,
    stop: AtomicBool,
    /// This process's `op_id` node half; the counter half is [`Shared::minted`].
    node: [u8; 8],
    minted: AtomicU64,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, VecDeque<Line>> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// A fresh `op_id`: this process's node, then a counter (little-endian), never reused.
    fn op_id(&self) -> [u8; 16] {
        let n = self.minted.fetch_add(1, Ordering::Relaxed);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&self.node);
        id[8..].copy_from_slice(&n.to_le_bytes());
        id
    }

    /// Take the next batch: queued lines of the first line's stream, in order, within the bounds.
    fn take(&self) -> Option<(u8, Vec<Line>)> {
        let mut q = self.lock();
        loop {
            if self.stop.load(Ordering::Acquire) {
                // Closing: what is still queued is shed (its holds drop with it).
                q.clear();
                return None;
            }
            if !q.is_empty() {
                break;
            }
            q = self
                .ready
                .wait_timeout(q, WAIT_SLICE)
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
        let stream = q.front()?.stream;
        let (mut lines, mut bytes) = (Vec::new(), 0usize);
        while let Some(l) = q.front() {
            let fits = lines.is_empty()
                || (lines.len() < MAX_BATCH_LINES && bytes + l.bytes.len() < MAX_BATCH_BYTES);
            if l.stream != stream || !fits {
                break;
            }
            bytes += l.bytes.len() + 1;
            lines.extend(q.pop_front());
        }
        Some((stream, lines))
    }

    /// Offer one batch on `ticket`, retrying a FAILED answer with the same `op_id`. The batch rides
    /// with the job: a crossing the watchdog answered still owns it until it returns.
    fn deliver(&self, ticket: Ticket, stream: u8, lines: &[Line]) {
        let mut batch = Vec::with_capacity(lines.iter().map(|l| l.bytes.len() + 1).sum());
        for l in lines {
            batch.extend_from_slice(&l.bytes);
            batch.push(b'\n');
        }
        let batch = Arc::new(batch);
        let op_id = self.op_id();
        for attempt in 1..=DELIVER_ATTEMPTS {
            let input = DeliverIn {
                head: in_head(),
                op_id,
                stream,
                _reserved: [0; 7],
                batch: blob(&batch, BLOB_JSONL),
            };
            let reply = self.dispatcher.submit_lent(
                &self.plugin,
                ticket,
                slot::DELIVER,
                Frame::new(input, out_head()),
                DeadlineClass::WriteBehind,
                0,
                batch.clone(),
            );
            // Every op is answered or ended by the dispatcher (its deadline, or the watchdog).
            let done = loop {
                if let Some(done) = reply.wait(WAIT_SLICE) {
                    break done;
                }
            };
            match done.outcome {
                Outcome::Ready => return,
                Outcome::Failed if attempt < DELIVER_ATTEMPTS => continue,
                o => {
                    tracing::warn!(
                        plugin = %self.plugin.name(),
                        lines = lines.len(),
                        error = %why(o, done.error),
                        "an export batch was not delivered and is dropped"
                    );
                    return;
                }
            }
        }
    }

    /// THE FLUSHER: one batch in flight per instance, on one ticket, until the instance is dropped.
    fn flush(self: Arc<Self>) {
        let mut ticket = None;
        while let Some((stream, lines)) = self.take() {
            if ticket.is_none() {
                let n = self.minted.load(Ordering::Relaxed);
                ticket = self
                    .dispatcher
                    .mint((n % u64::from(self.dispatcher.workers().max(1))) as u32);
            }
            match ticket {
                Some(t) => self.deliver(t, stream, &lines),
                None => tracing::warn!(
                    plugin = %self.plugin.name(),
                    "no ticket could be minted for an export batch; it is dropped"
                ),
            }
            // The lines' holds are released here: the batch has answered.
            drop(lines);
        }
        if let Some(t) = ticket {
            self.dispatcher.recycle(t);
        }
    }
}

/// This process's `op_id` node half: the process id and the boot instant, mixed.
fn node_id() -> [u8; 8] {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    (t ^ (u64::from(std::process::id()) << 40)).to_le_bytes()
}

/// ONE OPENED EXPORT INSTANCE, on the one dispatcher.
pub struct ExportInstance {
    shared: Arc<Shared>,
    flusher: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for ExportInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportInstance")
            .field("plugin", &self.shared.plugin.name())
            .field("streams", &self.shared.facts.streams)
            .finish_non_exhaustive()
    }
}

/// Dropping the instance stops its flusher: the batch in flight (if any) answers, the rest of the
/// queue is shed.
impl Drop for ExportInstance {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.ready.notify_all();
        let flusher = self
            .flusher
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(f) = flusher {
            let _ = f.join();
        }
    }
}

impl ExportInstance {
    /// OPEN `plugin` (bound to `dispatcher`) with `settings`, after `validate`: the instance, its
    /// flusher started.
    ///
    /// # Errors
    /// The plugin refused its settings (its words), or would not open (1.5.5's
    /// `plugin '<name>' open failed: <reason>`).
    pub fn open(
        plugin: Plugin<Export>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
    ) -> Result<Self, String> {
        validate(&plugin, settings)?;
        let mut f = Frame::new(
            OpenIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: blob(settings, BLOB_JSON),
                secrets: std::ptr::null(),
                secrets_len: 0,
                generation: 1,
                err_buf: std::ptr::null_mut(),
                err_cap: 0,
            },
            OpenOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                err_len: 0,
            },
        );
        let called = plugin.call(lc::OPEN, &mut f);
        if called.outcome != Outcome::Ready {
            return Err(called.open_failure(plugin.name()));
        }
        let facts = plugin.context::<ExportFacts>().cloned().unwrap_or_default();
        let shared = Arc::new(Shared {
            plugin,
            dispatcher,
            facts,
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            stop: AtomicBool::new(false),
            node: node_id(),
            minted: AtomicU64::new(0),
        });
        let flusher = shared.clone();
        let flusher = std::thread::Builder::new()
            .name("busbar-export-flush".into())
            .spawn(move || flusher.flush())
            .map_err(|e| format!("the export flusher did not start: {e}"))?;
        Ok(Self {
            shared,
            flusher: Mutex::new(Some(flusher)),
        })
    }

    /// The plugin handle.
    pub fn plugin(&self) -> &Plugin<Export> {
        &self.shared.plugin
    }

    /// Lines queued now (a witness).
    pub fn queued(&self) -> usize {
        self.shared.lock().len()
    }
}

/// The host snapshot, lowered to the `scrape` op's C layout. Every pointer names storage held
/// here, so the lowered families live exactly as long as this does.
struct Lowered {
    _labels: Vec<Vec<ScrapeLabel>>,
    _samples: Vec<Vec<ScrapeSample>>,
    families: Vec<ScrapeFamily>,
}

fn lower(families: &[Family]) -> Lowered {
    let labels: Vec<Vec<ScrapeLabel>> = families
        .iter()
        .flat_map(|f| f.samples.iter())
        .map(|s| {
            s.labels
                .iter()
                .map(|(k, v)| ScrapeLabel {
                    key: lend(k),
                    value: lend(v),
                })
                .collect()
        })
        .collect();
    let mut at = labels.iter();
    let samples: Vec<Vec<ScrapeSample>> = families
        .iter()
        .map(|f| {
            f.samples
                .iter()
                .zip(at.by_ref())
                .map(|(s, l)| ScrapeSample {
                    name: lend(&s.name),
                    labels: lend_list(l),
                    labels_len: l.len(),
                    value: lend(&s.value),
                })
                .collect()
        })
        .collect();
    let lowered = families
        .iter()
        .zip(&samples)
        .map(|(f, s)| ScrapeFamily {
            name: lend(&f.name),
            help: lend_opt(f.help.as_deref()),
            unit: lend_opt(f.unit.as_deref()),
            kind: f.kind,
            _reserved: [0; 7],
            samples: lend_list(s),
            samples_len: s.len(),
        })
        .collect();
    Lowered {
        _labels: labels,
        _samples: samples,
        families: lowered,
    }
}

impl ExportCalls for ExportInstance {
    fn streams(&self) -> &[u8] {
        &self.shared.facts.streams
    }

    fn routes(&self) -> &[Route] {
        &self.shared.facts.routes
    }

    fn deliver(&self, stream: u8, line: Vec<u8>, hold: Box<dyn Send>) -> Delivered {
        let sh = &self.shared;
        if sh.plugin.is_faulted() || !sh.plugin.is_open() {
            return Delivered::Shed;
        }
        {
            let mut q = sh.lock();
            if q.len() >= MAX_QUEUED_LINES {
                return Delivered::Shed;
            }
            q.push_back(Line {
                stream,
                bytes: line,
                _hold: hold,
            });
        }
        sh.ready.notify_one();
        Delivered::Queued
    }

    fn scrape(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        let plugin = &self.shared.plugin;
        let lowered = lower(families);
        let mut buf = vec![0u8; SCRAPE_BUF];
        let mut f = Frame::new(
            ScrapeIn {
                head: in_head(),
                families: lend_list(&lowered.families),
                families_len: lowered.families.len(),
                buf: buf.as_mut_ptr(),
                cap: buf.len(),
            },
            ScrapeOut {
                head: out_head(),
                written: 0,
                needed: 0,
            },
        );
        let mut called = plugin.call(slot::SCRAPE, &mut f);
        if let Some(token) = called.recall.take() {
            // The one re-call a short answer earns, into a buffer of the size it named.
            buf = vec![0u8; f.out.needed];
            f.input.buf = buf.as_mut_ptr();
            f.input.cap = buf.len();
            f.out = ScrapeOut {
                head: out_head(),
                written: 0,
                needed: 0,
            };
            called = plugin.recall(token, slot::SCRAPE, &mut f);
        }
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        buf.truncate(f.out.written.min(buf.len()));
        Ok(buf)
    }

    fn status(&self) -> Option<Vec<u8>> {
        let plugin = &self.shared.plugin;
        let mut f = Frame::new(
            in_head(),
            StatusOut {
                head: out_head(),
                status: NO_BLOB,
            },
        );
        let called = plugin.call(slot::STATUS, &mut f);
        if called.outcome != Outcome::Ready {
            if called.outcome != Outcome::Refused {
                tracing::warn!(
                    plugin = %plugin.name(),
                    error = %why(called.outcome, called.error),
                    "export plugin status failed"
                );
            }
            return None;
        }
        let bytes = copy_blob(f.out.status);
        release(plugin, called.lease);
        (!bytes.is_empty()).then_some(bytes)
    }

    fn serve(&self, req: &ServeRequest<'_>) -> Result<Served, String> {
        let plugin = &self.shared.plugin;
        let headers: Vec<AbiStr> = req
            .headers
            .iter()
            .take(MAX_SERVE_HEADERS)
            .flat_map(|(k, v)| [lend(k), lend(v)])
            .collect();
        let mut f = Frame::new(
            ServeIn {
                head: in_head(),
                method: lend(req.method),
                path: lend(req.path),
                query: lend_opt(req.query),
                headers: lend_list(&headers),
                headers_len: headers.len(),
                body: blob(req.body, BLOB_OCTETS),
            },
            ServeOut {
                head: out_head(),
                status_code: 0,
                _reserved: [0; 6],
                headers_out: std::ptr::null(),
                headers_out_len: 0,
                body: NO_BLOB,
            },
        );
        let called = plugin.call(slot::SERVE, &mut f);
        if called.outcome != Outcome::Ready {
            return Err(why(called.outcome, called.error));
        }
        let pairs = if f.out.headers_out_len == 0 || f.out.headers_out.is_null() {
            &[][..]
        } else {
            // SAFETY: `check_serve` bounded the list and refused a count behind NULL; it lives
            // under the lease until `release`.
            unsafe { std::slice::from_raw_parts(f.out.headers_out, f.out.headers_out_len) }
        };
        let served = Served {
            status: f.out.status_code,
            headers: pairs
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[k, v]| (copy_str(*k), copy_str(*v)))
                .collect(),
            body: copy_blob(f.out.body),
        };
        release(plugin, called.lease);
        Ok(served)
    }

    /// The host SHED one line for this instance (past its bound): count it on each counter the
    /// instance was GRANTED as its shed counter at open (a first-party manifest declaration marked
    /// `shed`), folded under its name through the one observability path, as the cold lane's sinks
    /// were counted (ARCHITECT ruling 2026-09-30, Q2).
    fn shed(&self) {
        crate::export::fold_shed(self.plugin().name());
    }
}

#[cfg(test)]
#[path = "tests/export_door_tests.rs"]
mod tests;
