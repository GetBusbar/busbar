// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Poll, Waker};
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt as _};

use busbar_contract::abi::export::{
    slot, CheckIn, CheckInstance, CheckOut, DeliverIn, ScrapeFamily, ScrapeIn, ScrapeLabel,
    ScrapeOut, ScrapeSample, ServeIn, ServeOut, StatusOut, SCRAPE_FLAG_HOOK_FAMILIES,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, Outcome, BLOB_JSON, BLOB_JSONL, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::slot as lc;
use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::export_calls::{Delivered, ExportCalls, Family, ServeRequest, Served};

use crate::dispatch::call::Ticketed;
use crate::dispatch::kinds::export::{Export, ExportFacts};
use crate::dispatch::lifecycle::{
    self, copy_blob, lend, lend_opt, open_frame, release, validate_call, why, AnswerLease,
};
use crate::dispatch::{in_head, out_head, Dispatcher, Frame, Plugin, NO_BLOB};

pub const MAX_QUEUED_LINES: usize = 4096;

pub const MAX_BATCH_LINES: usize = 256;

pub const MAX_BATCH_BYTES: usize = 1024 * 1024;

pub const DELIVER_ATTEMPTS: u32 = 3;

pub const STOP_GRACE: Duration = Duration::from_secs(2);

const SCRAPE_BUF: usize = 64 * 1024;

const MAX_SERVE_HEADERS: usize = 64;

fn lend_list<T>(l: &[T]) -> *const T {
    if l.is_empty() {
        std::ptr::null()
    } else {
        l.as_ptr()
    }
}

fn blob(b: &[u8], fmt: u32) -> Blob {
    lifecycle::blob(b, fmt, 0)
}

fn copy_str(s: AbiStr) -> String {
    crate::dispatch::plugin::str_bytes(s)
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .unwrap_or_default()
}

pub fn validate(plugin: &Plugin<Export>, settings: &[u8]) -> Result<(), String> {
    let called = validate_call(plugin, blob(settings, BLOB_JSON));
    let _lease = AnswerLease::new(plugin, called.lease);
    match called.outcome {
        Outcome::Ready => Ok(()),
        o => Err(why(o, called.error)),
    }
}

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

struct Line {
    stream: u8,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    _hold: Box<dyn Send>,
}

struct Shared {
    plugin: Plugin<Export>,
    dispatcher: Arc<Dispatcher>,
    facts: ExportFacts,
    queue: Mutex<VecDeque<Line>>,

    flusher: Mutex<Option<Waker>>,
    stop: AtomicBool,

    abandon: AtomicBool,

    node: [u8; 8],
    minted: AtomicU64,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, VecDeque<Line>> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn op_id(&self) -> [u8; 16] {
        let n = self.minted.fetch_add(1, Ordering::Relaxed);
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&self.node);
        id[8..].copy_from_slice(&n.to_le_bytes());
        id
    }

    fn notify(&self) {
        let waker = self
            .flusher
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn take(&self, room: usize) -> Option<(u8, Vec<Line>)> {
        let mut q = self.lock();
        let stream = q.front()?.stream;
        let share = q.len().div_ceil(room.max(1)).clamp(1, MAX_BATCH_LINES);
        let (mut lines, mut bytes) = (Vec::new(), 0usize);
        while let Some(l) = q.front() {
            let fits = lines.is_empty()
                || (lines.len() < share && bytes + l.bytes.len() < MAX_BATCH_BYTES);
            if l.stream != stream || !fits {
                break;
            }
            bytes += l.bytes.len() + 1;
            lines.extend(q.pop_front());
        }
        Some((stream, lines))
    }

    async fn deliver(self: Arc<Self>, worker: u32, stream: u8, lines: Vec<Line>) {
        let workers = self.dispatcher.workers().max(1);
        let call =
            (0..workers).find_map(|i| Ticketed::mint(&self.dispatcher, (worker + i) % workers));
        let Some(mut call) = call else {
            tracing::warn!(
                plugin = %self.plugin.name(),
                "no ticket could be minted for an export batch; it is dropped"
            );
            return;
        };
        let mut batch = zeroize::Zeroizing::new(Vec::with_capacity(
            lines.iter().map(|l| l.bytes.len() + 1).sum(),
        ));
        for l in &lines {
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

            call.submit(
                &self.plugin,
                slot::DELIVER,
                Frame::new(input, out_head()),
                DeadlineClass::WriteBehind,
                0,
                batch.clone(),
            );
            let done = (&mut call).await;
            let _lease = AnswerLease::new(&self.plugin, done.lease);
            match done.outcome {
                Outcome::Ready => break,
                Outcome::Failed if attempt < DELIVER_ATTEMPTS => continue,
                o => {
                    tracing::warn!(
                        plugin = %self.plugin.name(),
                        lines = lines.len(),
                        error = %why(o, done.error),
                        "an export batch was not delivered and is dropped"
                    );
                    break;
                }
            }
        }

        drop(lines);
    }

    fn flush(self: Arc<Self>) {
        static NEXT_WORKER: AtomicU32 = AtomicU32::new(0);
        let worker = NEXT_WORKER.fetch_add(1, Ordering::Relaxed) % self.dispatcher.workers().max(1);
        let cap = self.plugin.max_inflight().max(1) as usize;
        let mut inflight = FuturesUnordered::new();
        futures::executor::block_on(futures::future::poll_fn(|cx| loop {
            while let Poll::Ready(Some(())) = inflight.poll_next_unpin(cx) {}
            *self.flusher.lock().unwrap_or_else(|p| p.into_inner()) = Some(cx.waker().clone());
            if self.stop.load(Ordering::Acquire) {
                let shed = { std::mem::take(&mut *self.lock()) };
                if !shed.is_empty() {
                    tracing::warn!(
                        plugin = %self.plugin.name(),
                        lines = shed.len(),
                        "queued export lines are shed while the instance stops"
                    );
                    fold_shed_lines(self.dispatcher.observing(), self.plugin.name(), shed.len());
                }
                drop(shed);
                return if inflight.is_empty() || self.abandon.load(Ordering::Acquire) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                };
            }
            let mut started = false;
            while inflight.len() < cap {
                let Some((stream, lines)) = self.take(cap - inflight.len()) else {
                    break;
                };
                inflight.push(self.clone().deliver(worker, stream, lines));
                started = true;
            }
            if !started {
                return Poll::Pending;
            }
        }));
        if !inflight.is_empty() {
            tracing::warn!(
                plugin = %self.plugin.name(),
                deliveries = inflight.len(),
                "export deliveries still in flight when the instance was dropped are abandoned"
            );
        }
    }
}

fn node_id() -> [u8; 8] {
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    (t ^ (u64::from(std::process::id()) << 40)).to_le_bytes()
}

pub struct ExportInstance {
    shared: Arc<Shared>,

    flusher: Mutex<Option<(std::thread::JoinHandle<()>, Receiver<()>)>>,

    _grant: Option<crate::observe::SeriesGrant>,
}

impl std::fmt::Debug for ExportInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportInstance")
            .field("plugin", &self.shared.plugin.name())
            .field("streams", &self.shared.facts.streams)
            .finish_non_exhaustive()
    }
}

impl Drop for ExportInstance {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.notify();
        let flusher = self
            .flusher
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        if let Some((f, flushed)) = flusher {
            if let Err(RecvTimeoutError::Timeout) = flushed.recv_timeout(STOP_GRACE) {
                self.shared.abandon.store(true, Ordering::Release);
                self.shared.notify();
            }

            let _ = f.join();
        }
        let mut f = Frame::new(in_head(), out_head());
        let _ = self.shared.plugin.call(lc::CLOSE, &mut f);
    }
}

impl ExportInstance {
    pub fn open(
        plugin: Plugin<Export>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
    ) -> Result<Self, String> {
        validate(&plugin, settings)?;
        let mut f = open_frame(blob(settings, BLOB_JSON));
        let called = plugin.call(lc::OPEN, &mut f);
        let opened = AnswerLease::new(&plugin, called.lease);
        if called.outcome != Outcome::Ready {
            return Err(called.open_failure(plugin.name()));
        }
        drop(opened);
        let facts = plugin.context::<ExportFacts>().cloned().unwrap_or_default();
        let shared = Arc::new(Shared {
            plugin,
            dispatcher,
            facts,
            queue: Mutex::new(VecDeque::new()),
            flusher: Mutex::new(None),
            stop: AtomicBool::new(false),
            abandon: AtomicBool::new(false),
            node: node_id(),
            minted: AtomicU64::new(0),
        });
        let flusher = shared.clone();
        let (flushed, done) = std::sync::mpsc::channel();
        let flusher = std::thread::Builder::new()
            .name("busbar-export-flush".into())
            .spawn(move || {
                flusher.flush();
                let _ = flushed.send(());
            })
            .map_err(|e| format!("the export flusher did not start: {e}"))?;
        Ok(Self {
            shared,
            flusher: Mutex::new(Some((flusher, done))),
            _grant: None,
        })
    }

    #[must_use]
    pub fn holding(mut self, grant: crate::observe::SeriesGrant) -> Self {
        self._grant = Some(grant);
        self
    }

    pub fn plugin(&self) -> &Plugin<Export> {
        &self.shared.plugin
    }

    pub fn queued(&self) -> usize {
        self.shared.lock().len()
    }
}

struct Lowered {
    _labels: Vec<Vec<ScrapeLabel>>,
    _samples: Vec<Vec<ScrapeSample>>,
    families: Vec<ScrapeFamily>,
}

fn scrape_with(
    plugin: &Plugin<Export>,
    families: &[Family],
    flags: u32,
) -> Result<Vec<u8>, String> {
    let lowered = lower(families);
    let mut buf = vec![0u8; SCRAPE_BUF];
    let mut f = Frame::new(
        ScrapeIn {
            head: InHead { flags, ..in_head() },
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
    let mut _lease = AnswerLease::new(plugin, called.lease);
    if let Some(token) = called.recall.take() {
        buf = vec![0u8; f.out.needed];
        f.input.buf = buf.as_mut_ptr();
        f.input.cap = buf.len();
        f.out = ScrapeOut {
            head: out_head(),
            written: 0,
            needed: 0,
        };
        called = plugin.recall(token, slot::SCRAPE, &mut f);
        _lease = AnswerLease::new(plugin, called.lease);
    }
    if called.outcome != Outcome::Ready {
        return Err(why(called.outcome, called.error));
    }
    buf.truncate(f.out.written.min(buf.len()));
    Ok(buf)
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
    fn refresh(&self, settings: &serde_json::Value, generation: u64) -> Result<(), String> {
        let settings = Arc::new(zeroize::Zeroizing::new(
            serde_json::to_vec(settings).map_err(|error| error.to_string())?,
        ));
        let mut call = (0..self.shared.dispatcher.workers().max(1))
            .find_map(|worker| Ticketed::mint(&self.shared.dispatcher, worker))
            .ok_or_else(|| "no ticket could be minted for an export refresh".to_string())?;
        let frame = Frame::new(
            busbar_contract::abi::mechanism::lifecycle::RefreshIn {
                head: in_head(),
                generation,
                settings: blob(&settings, BLOB_JSON),
                secrets: std::ptr::null(),
                secrets_len: 0,
            },
            out_head(),
        );
        call.submit(
            &self.shared.plugin,
            lc::REFRESH,
            frame,
            DeadlineClass::Call,
            0,
            settings,
        );
        let done = futures::executor::block_on(&mut call);
        release(&self.shared.plugin, done.lease);
        match done.outcome {
            Outcome::Ready => Ok(()),
            outcome => Err(why(outcome, done.error)),
        }
    }

    fn streams(&self) -> &[u8] {
        &self.shared.facts.streams
    }

    fn routes(&self) -> &[Route] {
        &self.shared.facts.routes
    }

    fn public_routes(&self) -> &[String] {
        &self.shared.facts.public_routes
    }

    fn persistent_routes(&self) -> &[String] {
        &self.shared.facts.persistent_routes
    }

    fn deliver(&self, stream: u8, line: Vec<u8>, hold: Box<dyn Send>) -> Delivered {
        let line = zeroize::Zeroizing::new(line);
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
        sh.notify();
        Delivered::Queued
    }

    fn takes_span_records(&self) -> bool {
        self.shared.facts.span_records
    }

    fn scrape(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        scrape_with(&self.shared.plugin, families, 0)
    }

    fn scrape_hooks(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        scrape_with(&self.shared.plugin, families, SCRAPE_FLAG_HOOK_FAMILIES)
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

    fn start(&self) -> Result<(), String> {
        let sh = &self.shared;
        sh.plugin
            .ready(&sh.dispatcher, crate::dispatch::ready::READY_DEADLINE)
    }

    fn shed(&self) {
        fold_shed(self.shared.dispatcher.observing(), self.plugin().name());
    }
}

fn fold_shed(observing: &crate::observe::Observing, name: &str) {
    fold_shed_lines(observing, name, 1);
}

fn fold_shed_lines(observing: &crate::observe::Observing, name: &str, lines: usize) {
    let metrics = crate::observe::shed_series(name)
        .into_iter()
        .map(|n| serde_json::json!({"name": n, "type": "counter", "value": lines}))
        .collect();
    let report = busbar_contract::abi::mechanism::observe::Envelope {
        result: (),
        metrics,
        diagnostics: Vec::new(),
    };
    observing.fold(name, busbar_contract::abi::mechanism::kind::EXPORT, &report);
}

#[cfg(test)]
#[path = "tests/export_door_tests.rs"]
pub(crate) mod tests;
