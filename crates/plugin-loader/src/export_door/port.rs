// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export switch-over (WBS W2-SW-EXPORT, IF §8.5 round 33, §11.3, §12.21, §49): the kernel's export lane
//! ([`ExportCalls`]) driven over one instance's MIN-3 [`ExportPort`] in place of the old export door.
//!
//! The pump here is the round-33 shape: it mints every line set's `delivery` (one process-wide counter seeded
//! once from busbar-crypto's random draw, never a clock, 0 skipped), counts `attempt` (1 on first send, +1 on a
//! resend of the same lines, and the unaccepted rest after an `ACK{accepted}` is a new line set with a fresh
//! `delivery` and `attempt` + 1), and calls `ExportPort::deliver(cx, stream, delivery, attempt, lines)`. An
//! `Append` answer goes to the instance's [`DestAppend`] (core's disk lane, §12.21) with the delivered prefix
//! verbatim when the plugin sent no bytes. Custody is counted per (stream, level); in 1.6.0 every non-content
//! answer is at or above the required ACCEPTED, so the pump never confirms or pauses for it, and an APPEND counts
//! ACCEPTED (the disk lane does not sync). Nothing of the old `deliver(h, stream, batch)` shape, its time-derived
//! `op_id` or its `_reserved` field is read here.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::route::Route;
use busbar_contract::export_calls::{
    Delivered as Queued, ExportCalls, Family, RecorderRequirements, ServeRequest, Served,
};
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::{CallStack, InstanceLimits};
use busbar_plugin_abi::kinds::export::export as x;

use crate::ports::export::{Delivered, ExportPort, FamilyIn, SampleIn};
use crate::ports::{CallCx, PortError};

/// Lines one instance holds queued before the kernel's next line is shed (the old door's bound).
pub const MAX_QUEUED_LINES: usize = super::MAX_QUEUED_LINES;
/// Lines in one delivered line set at most.
pub const MAX_BATCH_LINES: usize = super::MAX_BATCH_LINES;
/// Bytes in one delivered line set at most (a single larger line still goes alone).
pub const MAX_BATCH_BYTES: usize = super::MAX_BATCH_BYTES;
/// Sends of one line set at most before its lines are dropped and counted.
pub const DELIVER_ATTEMPTS: u32 = super::DELIVER_ATTEMPTS;
/// The per-delivery deadline when the instance's `limits.timeout_ms` is 0 (no extra cap).
pub const DEFAULT_DELIVER_TIMEOUT: Duration = Duration::from_secs(30);
/// The Retry-After clamp of `RetrySite::ExportDeliver` (§12.3).
pub const RETRY_AFTER_CLAMP_S: u64 = 300;
/// The first resend's wait; each further resend doubles it, up to [`RETRY_AFTER_CLAMP_S`].
pub const RESEND_BASE: Duration = Duration::from_millis(50);

/// The bytes an `Append` answer asks core to append: the delivered prefix as handed to the plugin (no copy), or
/// the plugin's own rendered bytes (IF §12.21 `AppendBytes`).
pub enum AppendBytes<'a> {
    Batch(&'a [&'a [u8]]),
    Owned(Vec<u8>),
}

/// Why an append did not land (IF §12.21 `DiskDenied`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendDenied {
    /// `dest` names no binding of this instance: the lines are dropped and counted, never resent.
    Foreign,
    LaneFull,
    LaneGone,
    Failed(u32),
}

/// The instance's bound destinations, as core's disk lane serves them (IF §12.21 `DiskSink`, over the kept
/// `host_disk` lane; K8C implements it in the kernel and hands it in at boot).
pub trait DestAppend: Send + Sync + 'static {
    fn append(&self, dest: u32, bytes: AppendBytes<'_>) -> Result<(), AppendDenied>;
}

/// A [`DestAppend`] for an instance that binds no destination: every `Append` answer is foreign.
pub struct NoDest;

impl DestAppend for NoDest {
    fn append(&self, _dest: u32, _bytes: AppendBytes<'_>) -> Result<(), AppendDenied> {
        Err(AppendDenied::Foreign)
    }
}

static DELIVERY: OnceLock<AtomicU64> = OnceLock::new();

/// The next core-minted delivery id: never 0, never time-derived (§8.5 round 33).
pub fn mint_delivery() -> u64 {
    let next = DELIVERY.get_or_init(|| {
        let seed = busbar_contract::crypto::u64().unwrap_or_else(|_| {
            tracing::error!(
                "the random number generator failed; export delivery ids start from 1 this run"
            );
            1
        });
        AtomicU64::new(seed)
    });
    loop {
        let id = next.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

/// The streams of a D_STREAMS mask, ascending (`ExportStream::ALL` order).
#[must_use]
pub fn stream_ids(mask: u32) -> Vec<u8> {
    (0..x::STREAM_COUNT)
        .filter(|s| mask & (1 << s) != 0)
        .map(|s| s as u8)
        .collect()
}

struct Line {
    stream: u8,
    bytes: SecureVec,
    _hold: Box<dyn Send>,
}

struct Shared {
    port: Arc<dyn ExportPort>,
    disk: Arc<dyn DestAppend>,
    label: Box<str>,
    timeout: Duration,
    queue: Mutex<VecDeque<Line>>,
    wake: Condvar,
    stop: AtomicBool,
    shed: AtomicU64,
    delivered: AtomicU64,
    /// `export_custody_total{instance, stream, level}`, indexed `[stream][level]`.
    custody: [[AtomicU64; 4]; x::STREAM_COUNT as usize],
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, VecDeque<Line>> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Waits for the next line set: the front line's stream, up to the batch bounds. None once stopping.
    fn next_set(&self) -> Option<(u8, Vec<Line>)> {
        let mut q = self.lock();
        loop {
            if self.stop.load(Ordering::Acquire) {
                return None;
            }
            if let Some(stream) = q.front().map(|l| l.stream) {
                let (mut lines, mut bytes) = (Vec::new(), 0usize);
                while let Some(l) = q.front() {
                    let fits = lines.is_empty()
                        || (lines.len() < MAX_BATCH_LINES
                            && bytes + l.bytes.len() < MAX_BATCH_BYTES);
                    if l.stream != stream || !fits {
                        break;
                    }
                    bytes += l.bytes.len() + 1;
                    lines.extend(q.pop_front());
                }
                return Some((stream, lines));
            }
            q = self.wake.wait(q).unwrap_or_else(|p| p.into_inner());
        }
    }

    fn drop_lines(&self, n: usize, why: &str) {
        if n == 0 {
            return;
        }
        self.shed.fetch_add(n as u64, Ordering::Relaxed);
        tracing::warn!(instance = %self.label, lines = n, "{why}");
    }

    fn count_custody(&self, stream: u8, level: u32, n: usize) {
        if let Some(row) = self.custody.get(stream as usize) {
            if let Some(cell) = row.get(level as usize) {
                cell.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
    }

    fn cx(&self, delivery: u64) -> CallCx {
        CallCx {
            deadline: Instant::now() + self.timeout,
            request_id: delivery,
            stack: CallStack::default(),
        }
    }

    /// The wait before resend `attempt` (>= 2): the stated Retry-After, clamped, else the doubling base.
    fn resend_wait(attempt: u32, retry_after_s: Option<u64>) -> Duration {
        match retry_after_s {
            Some(s) => Duration::from_secs(s.min(RETRY_AFTER_CLAMP_S)),
            None => RESEND_BASE
                .saturating_mul(1 << attempt.saturating_sub(2).min(12))
                .min(Duration::from_secs(RETRY_AFTER_CLAMP_S)),
        }
    }

    /// Delivers one line set until every line is accepted, refused or out of attempts.
    fn deliver_set(&self, stream: u8, lines: &[Line]) {
        let mut delivery = mint_delivery();
        let mut attempt = 1u32;
        let mut start = 0usize;
        while start < lines.len() {
            if attempt > DELIVER_ATTEMPTS {
                self.drop_lines(
                    lines.len() - start,
                    "export lines were not delivered within their attempts and are dropped",
                );
                return;
            }
            let views: Vec<&[u8]> = lines[start..].iter().map(|l| l.bytes.as_slice()).collect();
            let answer = futures::executor::block_on(self.port.deliver(
                self.cx(delivery),
                u32::from(stream),
                delivery,
                attempt,
                &views,
            ));
            let resend = |attempt: &mut u32, retry_after_s: Option<u64>| {
                *attempt += 1;
                if *attempt <= DELIVER_ATTEMPTS && !self.stop.load(Ordering::Acquire) {
                    std::thread::sleep(Self::resend_wait(*attempt, retry_after_s));
                }
            };
            match answer {
                Ok(Delivered::Acked { accepted, custody }) => {
                    let n = usize::try_from(accepted).map_or(views.len(), |a| a.min(views.len()));
                    if n == 0 {
                        resend(&mut attempt, None);
                        continue;
                    }
                    self.count_custody(stream, custody.level, n);
                    self.delivered.fetch_add(n as u64, Ordering::Relaxed);
                    start += n;
                    if start < lines.len() {
                        delivery = mint_delivery();
                        resend(&mut attempt, None);
                    }
                }
                Ok(Delivered::Append {
                    dest,
                    bytes,
                    accepted,
                }) => {
                    let n = usize::try_from(accepted).map_or(views.len(), |a| a.min(views.len()));
                    if n == 0 {
                        resend(&mut attempt, None);
                        continue;
                    }
                    let appended = match bytes {
                        Some(b) => self.disk.append(dest, AppendBytes::Owned(b)),
                        None => self.disk.append(dest, AppendBytes::Batch(&views[..n])),
                    };
                    match appended {
                        Ok(()) => {
                            self.count_custody(stream, x::CUSTODY_ACCEPTED, n);
                            self.delivered.fetch_add(n as u64, Ordering::Relaxed);
                            start += n;
                            if start < lines.len() {
                                delivery = mint_delivery();
                                resend(&mut attempt, None);
                            }
                        }
                        Err(AppendDenied::Foreign) => {
                            self.drop_lines(
                                views.len(),
                                "an export append named no destination of this instance; its lines are dropped",
                            );
                            return;
                        }
                        Err(_) => resend(&mut attempt, None),
                    }
                }
                Err(PortError::Failed {
                    code: busbar_plugin_abi::fail::failed::F_LIMIT,
                    ..
                }) => {
                    self.drop_lines(
                        views.len(),
                        "an export delivery reached a terminal limit; its lines are dropped",
                    );
                    return;
                }
                Err(PortError::Failed { retry_after_s, .. }) => resend(&mut attempt, retry_after_s),
                Err(PortError::Call(CallError::Deadline)) => resend(&mut attempt, None),
                Err(e) => {
                    self.drop_lines(
                        views.len(),
                        &format!(
                            "an export delivery was refused ({}); its lines are dropped",
                            why(&e)
                        ),
                    );
                    return;
                }
            }
        }
    }

    fn pump(self: Arc<Self>) {
        while let Some((stream, lines)) = self.next_set() {
            self.deliver_set(stream, &lines);
        }
        let left = std::mem::take(&mut *self.lock());
        self.drop_lines(
            left.len(),
            "queued export lines are shed while the instance stops",
        );
    }
}

/// One export instance on the MIN-3 path, as the kernel's export lane drives it.
pub struct PortDoor {
    shared: Arc<Shared>,
    streams: Vec<u8>,
    pump: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for PortDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortDoor")
            .field("instance", &self.shared.label)
            .field("streams", &self.streams)
            .finish_non_exhaustive()
    }
}

impl PortDoor {
    /// Starts the instance's pump over `port`. `label` is the operator's instance name; `limits` its
    /// `limits` (only `timeout_ms` is read here: the per-delivery deadline, 0 = [`DEFAULT_DELIVER_TIMEOUT`]).
    pub fn open(
        label: &str,
        port: Arc<dyn ExportPort>,
        disk: Arc<dyn DestAppend>,
        limits: &InstanceLimits,
    ) -> Result<Arc<Self>, String> {
        let timeout = match limits.timeout_ms {
            0 => DEFAULT_DELIVER_TIMEOUT,
            ms => Duration::from_millis(u64::from(ms)),
        };
        let streams = stream_ids(port.streams());
        let shared = Arc::new(Shared {
            port,
            disk,
            label: label.into(),
            timeout,
            queue: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
            shed: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            custody: Default::default(),
        });
        let pump = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name(format!("export-{label}"))
                .spawn(move || shared.pump())
                .map_err(|e| format!("the export pump for `{label}` could not start: {e}"))?
        };
        Ok(Arc::new(Self {
            shared,
            streams,
            pump: Mutex::new(Some(pump)),
        }))
    }

    /// The custody ceiling the instance stated in its `open` answer (§8.5), read through L7.
    #[must_use]
    pub fn custody_ceiling(&self) -> Option<u32> {
        self.shared.port.custody_ceiling()
    }

    /// `export_custody_total{instance, stream, level}`.
    #[must_use]
    pub fn custody_total(&self, stream: u32, level: u32) -> u64 {
        self.shared
            .custody
            .get(stream as usize)
            .and_then(|row| row.get(level as usize))
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Lines accepted by the sink so far.
    #[must_use]
    pub fn delivered(&self) -> u64 {
        self.shared.delivered.load(Ordering::Relaxed)
    }

    /// Lines shed or dropped so far (queue full, refused, out of attempts, foreign destination, stop).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.shared.shed.load(Ordering::Relaxed)
    }

    fn render(&self, scope: u32, families: &[Family]) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        with_snapshot(families, |snapshot| {
            self.shared
                .port
                .render(scope, snapshot, &mut |_content_type, bytes| {
                    body.extend_from_slice(bytes)
                })
        })
        .map_err(|e| {
            format!(
                "export instance `{}` did not render ({})",
                self.shared.label,
                why(&e)
            )
        })?;
        Ok(body)
    }
}

impl Drop for PortDoor {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        let pump = self.pump.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(pump) = pump {
            if pump.thread().id() != std::thread::current().id() {
                let _ = pump.join();
            }
        }
    }
}

impl ExportCalls for PortDoor {
    fn recorder_requirements(&self) -> Option<RecorderRequirements> {
        self.shared.port.recorder().map(|r| RecorderRequirements {
            retention_seconds: r.retention_s,
            key_gauge_limit: usize::try_from(r.key_gauge_limit).unwrap_or(usize::MAX),
        })
    }

    fn streams(&self) -> &[u8] {
        &self.streams
    }

    /// MIN-3 exporters serve no routes of their own: core mounts each D_SCOPE path (§12.26).
    fn routes(&self) -> &[Route] {
        &[]
    }

    fn deliver(&self, stream: u8, line: Vec<u8>, hold: Box<dyn Send>) -> Queued {
        if !self.streams.contains(&stream) || self.shared.stop.load(Ordering::Acquire) {
            return Queued::Shed;
        }
        {
            let mut q = self.shared.lock();
            if q.len() >= MAX_QUEUED_LINES {
                return Queued::Shed;
            }
            q.push_back(Line {
                stream,
                bytes: SecureVec::from(line),
                _hold: hold,
            });
        }
        self.shared.wake.notify_one();
        Queued::Queued
    }

    fn takes_span_records(&self) -> bool {
        self.shared.port.span_records()
    }

    fn scrape(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        self.render(x::SCOPE_METRICS, families)
    }

    fn scrape_hooks(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        if !self
            .shared
            .port
            .scopes()
            .iter()
            .any(|s| s.scope == x::SCOPE_HOOKS)
        {
            return Err("this instance renders no hook families".to_string());
        }
        self.render(x::SCOPE_HOOKS, families)
    }

    fn status(&self) -> Option<Vec<u8>> {
        None
    }

    fn serve(&self, _req: &ServeRequest<'_>) -> Result<Served, String> {
        Err("a MIN-3 export instance serves no routes of its own".to_string())
    }

    fn shed(&self) {
        self.shared.shed.fetch_add(1, Ordering::Relaxed);
    }
}

/// Core's words for a port error: the code only, never the plugin's text (§12.16).
fn why(e: &PortError) -> String {
    match e {
        PortError::Refused { code, .. } => format!("refused, code {code}"),
        PortError::Failed { code, .. } => format!("failed, code {code}"),
        PortError::Call(c) => format!("{c:?}"),
    }
}

/// The FAMILY_* of a recorder family kind. Untyped families render as gauges: the MIN-3 snapshot has no
/// untyped family.
fn family_kind(kind: u8) -> u32 {
    match busbar_contract::export_calls::type_word(kind) {
        Some("counter") => x::FAMILY_COUNTER,
        Some("histogram") => x::FAMILY_HISTOGRAM,
        Some("summary") => x::FAMILY_SUMMARY,
        _ => x::FAMILY_GAUGE,
    }
}

fn number(v: &str) -> f64 {
    v.trim().parse::<f64>().unwrap_or(f64::NAN)
}

/// One sample's role, bound and the labels it keeps (the `le` / `quantile` coordinate becomes `bound`).
fn sample_shape<'f>(
    family: &'f Family,
    sample_name: &str,
    labels: &'f [(String, String)],
) -> (u32, f64, Vec<(&'f str, &'f str)>) {
    let suffix = sample_name.strip_prefix(family.name.as_str()).unwrap_or("");
    let coordinate = |key: &str| {
        labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| number(v))
    };
    let (role, bound, drop) = match suffix {
        "_bucket" => (
            x::SAMPLE_BUCKET,
            coordinate("le").unwrap_or(f64::NAN),
            Some("le"),
        ),
        "_sum" => (x::SAMPLE_SUM, f64::NAN, None),
        "_count" => (x::SAMPLE_COUNT, f64::NAN, None),
        _ if family_kind(family.kind) == x::FAMILY_SUMMARY => match coordinate("quantile") {
            Some(q) => (x::SAMPLE_QUANTILE, q, Some("quantile")),
            None => (x::SAMPLE_VALUE, f64::NAN, None),
        },
        _ => (x::SAMPLE_VALUE, f64::NAN, None),
    };
    let kept = labels
        .iter()
        .filter(|(k, _)| Some(k.as_str()) != drop)
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    (role, bound, kept)
}

/// Lowers the recorder snapshot into the port's borrowed snapshot and runs `f` over it.
fn with_snapshot<R>(families: &[Family], f: impl FnOnce(&[FamilyIn<'_>]) -> R) -> R {
    let shapes: Vec<Vec<(u32, f64, Vec<(&str, &str)>)>> = families
        .iter()
        .map(|fam| {
            fam.samples
                .iter()
                .map(|s| sample_shape(fam, &s.name, &s.labels))
                .collect()
        })
        .collect();
    let samples: Vec<Vec<SampleIn<'_>>> = families
        .iter()
        .zip(&shapes)
        .map(|(fam, shapes)| {
            fam.samples
                .iter()
                .zip(shapes)
                .map(|(s, (role, bound, labels))| SampleIn {
                    value: number(&s.value),
                    bound: *bound,
                    ts_ms: 0,
                    role: *role,
                    labels,
                })
                .collect()
        })
        .collect();
    let snapshot: Vec<FamilyIn<'_>> = families
        .iter()
        .zip(&samples)
        .map(|(fam, samples)| FamilyIn {
            kind: family_kind(fam.kind),
            name: &fam.name,
            help: fam.help.as_deref().unwrap_or(""),
            samples,
        })
        .collect();
    f(&snapshot)
}

#[cfg(test)]
#[path = "../tests/export_port_door_tests.rs"]
mod tests;
