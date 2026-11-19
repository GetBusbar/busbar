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

use arc_swap::ArcSwap;

use busbar_contract::export_calls::{
    Delivered as Queued, ExportCalls, ExportCustodyLevel, ExportDropReason, ExportLossKind,
    ExportObservation, ExportObserver, Family, RecorderRequirements, ServeRequest, Served,
};
use busbar_contract::route::{Route, RouteAuth, RouteMethod};
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::{CallStack, InstanceLimits};
use busbar_plugin_abi::kinds::export::export as x;

use busbar_ports::export::{Delivered, ExportPort, FamilyIn, SampleIn};
use busbar_ports::{CallCx, PortError};

/// Lines one instance holds queued before the kernel's next line is shed (the old door's bound).
pub const MAX_QUEUED_LINES: usize = 4096;
/// Lines in one delivered line set at most.
pub const MAX_BATCH_LINES: usize = 256;
/// Bytes in one delivered line set at most (a single larger line still goes alone).
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// Sends of one line set at most before its lines are dropped and counted.
pub const DELIVER_ATTEMPTS: u32 = 3;
/// The per-delivery deadline when the instance's `limits.timeout_ms` is 0 (no extra cap).
pub const DEFAULT_DELIVER_TIMEOUT: Duration = Duration::from_secs(30);
/// The Retry-After clamp of `RetrySite::ExportDeliver` (§12.3).
pub const RETRY_AFTER_CLAMP_S: u64 = 300;
/// The shared host schedule's first failure ceiling (IF §49 Q5).
pub const RESEND_BASE: Duration = Duration::from_millis(250);
/// Exponential backoff is capped independently of a backend's Retry-After hint.
pub const RESEND_CAP: Duration = Duration::from_secs(60);

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

/// One export instance's live binding: its port and its disk lane, always swapped together (DES-454 §4.1).
pub struct ExportBinding {
    pub port: Arc<dyn ExportPort>,
    pub disk: Arc<dyn DestAppend>,
}

/// Why [`PortDoor::swap_binding`] kept the binding it holds. The successor is handed back with it, so the caller
/// closes it explicitly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SwapRefused {
    /// The successor differs in streams, scopes, recorder needs, span records or custody ceiling.
    ShapeChanged,
    /// The door is draining or stopped.
    Stopping,
    /// The door no longer holds the binding the caller read (another swap won).
    Superseded,
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

#[derive(Default)]
struct Lifecycle {
    deadline: Option<Instant>,
    dropped_at_start: u64,
    finished: bool,
}

/// A bounded shutdown observation. A cancelled call is never reported as a clean drain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopReport {
    pub worker_stopped: bool,
    pub queued: u64,
    pub in_flight: u64,
    pub dropped: u64,
    pub cancelled: bool,
    pub dispatch_failed: bool,
}

impl StopReport {
    pub fn clean(self) -> bool {
        self.worker_stopped
            && self.queued == 0
            && self.in_flight == 0
            && self.dropped == 0
            && !self.cancelled
            && !self.dispatch_failed
    }
}

struct Shared {
    /// DES-454 §4.1: the port and its disk lane, one cell swapped whole. The pump loads it once per attempt;
    /// every other reader once per call.
    binding: ArcSwap<ExportBinding>,
    observer: Arc<dyn ExportObserver>,
    label: Box<str>,
    timeout: Duration,
    queue: Mutex<VecDeque<Line>>,
    wake: Condvar,
    stop: AtomicBool,
    abort: AtomicBool,
    in_flight: AtomicU64,
    lifecycle: Mutex<Lifecycle>,
    settled: Condvar,
    cancellation: Mutex<Option<futures::channel::oneshot::Sender<()>>>,
    shed: AtomicU64,
    delivered: AtomicU64,
    /// `export_custody_total{instance, stream, level}`, indexed `[stream][level]`.
    custody: [[AtomicU64; 4]; x::STREAM_COUNT as usize],
}

impl Shared {
    fn lifecycle(&self) -> MutexGuard<'_, Lifecycle> {
        self.lifecycle.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn expired(&self) -> bool {
        self.abort.load(Ordering::Acquire)
            || self
                .lifecycle()
                .deadline
                .is_some_and(|d| Instant::now() >= d)
    }

    fn abort(&self) {
        self.abort.store(true, Ordering::Release);
        if let Some(cancel) = self
            .cancellation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            let _ = cancel.send(());
        }
        // Pair with the queue lock so a waiter cannot miss the wake before parking.
        let _queue = self.lock();
        self.wake.notify_all();
    }

    fn wait_retry(&self, wait: Duration) {
        let until = Instant::now() + wait;
        let mut queue = self.lock();
        loop {
            if self.expired() {
                return;
            }
            let deadline = self.lifecycle().deadline.map_or(until, |d| d.min(until));
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            let (next, _) = self
                .wake
                .wait_timeout(queue, left)
                .unwrap_or_else(|p| p.into_inner());
            queue = next;
        }
    }

    fn call(
        &self,
        port: &dyn ExportPort,
        stream: u8,
        delivery: u64,
        attempt: u32,
        views: &[&[u8]],
    ) -> Option<Result<Delivered, PortError>> {
        let (send, receive) = futures::channel::oneshot::channel();
        {
            let mut slot = self.cancellation.lock().unwrap_or_else(|p| p.into_inner());
            if self.expired() {
                return None;
            }
            *slot = Some(send);
        }
        let result = futures::executor::block_on(futures::future::select(
            port.deliver(
                self.cx(delivery),
                u32::from(stream),
                delivery,
                attempt,
                views,
            ),
            receive,
        ));
        self.cancellation
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take();
        match result {
            futures::future::Either::Left((answer, _)) => Some(answer),
            futures::future::Either::Right((_, pending)) => {
                // Dropping the proxy future cancels its chain before releasing Need/input buffers.
                // If native cancellation blocks, this worker retains Shared and its live instance.
                drop(pending);
                None
            }
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<Line>> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Waits for the next line set: the front line's stream, up to the batch bounds. None once stopping.
    fn next_set(&self) -> Option<(u8, Vec<Line>)> {
        let mut q = self.lock();
        loop {
            if self.expired() {
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
                self.in_flight.store(lines.len() as u64, Ordering::Release);
                return Some((stream, lines));
            }
            if self.stop.load(Ordering::Acquire) {
                return None;
            }
            q = self.wake.wait(q).unwrap_or_else(|p| p.into_inner());
        }
    }

    fn drop_lines(&self, n: usize, reason: ExportDropReason) {
        if n == 0 {
            return;
        }
        self.shed.fetch_add(n as u64, Ordering::Relaxed);
        // The bound root observer owns coded, export-excluded diagnostics and durable evidence.
        // Logging here would feed this loss back into the same export queue.
        self.observer.observe(ExportObservation::Dropped {
            reason,
            lines: n as u64,
        });
    }

    fn count_custody(&self, stream: u8, level: u32, n: usize) {
        // The loader owns wire classification; the observer receives only neutral checked levels.
        let checked = match level {
            x::CUSTODY_ACCEPTED => ExportCustodyLevel::Accepted,
            x::CUSTODY_DURABLE => ExportCustodyLevel::Durable,
            x::CUSTODY_INDEXED => ExportCustodyLevel::Indexed,
            _ => return,
        };
        let Some(&stream_kind) =
            busbar_contract::export_stream::ExportStream::ALL.get(stream as usize)
        else {
            return;
        };
        if n == 0 {
            return;
        }
        if let Some(cell) = self
            .custody
            .get(stream as usize)
            .and_then(|row| row.get(level as usize))
        {
            cell.fetch_add(n as u64, Ordering::Relaxed);
        }
        self.observer.observe(ExportObservation::Custody {
            stream: stream_kind,
            level: checked,
            lines: n as u64,
        });
    }

    fn cx(&self, delivery: u64) -> CallCx {
        let timeout = Instant::now() + self.timeout;
        CallCx {
            deadline: self
                .lifecycle()
                .deadline
                .map_or(timeout, |d| d.min(timeout)),
            request_id: delivery,
            stack: CallStack::default(),
            // The pump made one clock reading for this delivery, the deadline above, on the
            // standard clock; none on the host's monotonic clock is handed in, and an exporter that
            // needs one asks the host once.
            mono_ns: 0,
        }
    }

    /// The shared backoff for the preceding failed attempt, never below Retry-After or the host floor.
    fn resend_wait(attempt: u32, retry_after_s: Option<u64>) -> Duration {
        busbar_contract::retry::Backoff::new(RESEND_BASE, RESEND_CAP)
            .delay(attempt.saturating_sub(1), busbar_contract::retry::unit())
            .max(Duration::from_secs(retry_after_s.unwrap_or(0)))
            .min(Duration::from_secs(RETRY_AFTER_CLAMP_S))
    }

    /// Delivers one line set until every line is accepted, refused or out of attempts.
    fn deliver_set(&self, stream: u8, lines: &[Line]) {
        // The set's views, made once: each attempt lends the tail not yet accepted. Released with the set.
        let mut views: Vec<&[u8]> = Vec::with_capacity(lines.len());
        views.extend(lines.iter().map(|l| l.bytes.as_slice()));
        let mut delivery = mint_delivery();
        let mut attempt = 1u32;
        let mut start = 0usize;
        while start < lines.len() {
            self.in_flight
                .store((lines.len() - start) as u64, Ordering::Release);
            if self.expired() {
                self.drop_lines(lines.len() - start, ExportDropReason::Stopped);
                return;
            }
            if attempt > DELIVER_ATTEMPTS {
                self.drop_lines(lines.len() - start, ExportDropReason::AttemptsExhausted);
                return;
            }
            let views = &views[start..];
            // Per attempt: an attempt already running on the old binding completes there; every later one
            // goes to whatever the cell holds then (DES-454 §4.3).
            let binding = self.binding.load_full();
            let Some(answer) = self.call(&*binding.port, stream, delivery, attempt, views) else {
                self.drop_lines(lines.len() - start, ExportDropReason::Stopped);
                return;
            };
            // DES-454 §4.3: a refusal or failure from a binding the door no longer holds is not final. Before any
            // backoff, the next attempt goes to the successor, and still counts against DELIVER_ATTEMPTS.
            if answer.is_err() && !Arc::ptr_eq(&self.binding.load(), &binding) {
                attempt += 1;
                continue;
            }
            let resend = |attempt: &mut u32, retry_after_s: Option<u64>| {
                *attempt += 1;
                if *attempt <= DELIVER_ATTEMPTS {
                    self.wait_retry(Self::resend_wait(*attempt, retry_after_s));
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
                        Some(b) => binding.disk.append(dest, AppendBytes::Owned(b)),
                        None => binding.disk.append(dest, AppendBytes::Batch(&views[..n])),
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
                            self.drop_lines(views.len(), ExportDropReason::ForeignDestination);
                            return;
                        }
                        Err(_) => resend(&mut attempt, None),
                    }
                }
                Err(PortError::Failed {
                    code: busbar_plugin_abi::fail::failed::F_LIMIT,
                    ..
                }) => {
                    self.drop_lines(views.len(), ExportDropReason::Refused);
                    return;
                }
                Err(PortError::Failed { retry_after_s, .. }) => resend(&mut attempt, retry_after_s),
                Err(PortError::Call(CallError::Deadline)) => resend(&mut attempt, None),
                Err(_) => {
                    self.drop_lines(views.len(), ExportDropReason::Refused);
                    return;
                }
            }
        }
    }

    fn discard_queue(&self) {
        let left = std::mem::take(&mut *self.lock());
        self.drop_lines(left.len(), ExportDropReason::Stopped);
        drop(left);
    }

    fn pump(self: Arc<Self>) {
        while let Some((stream, lines)) = self.next_set() {
            self.deliver_set(stream, &lines);
            self.in_flight.store(0, Ordering::Release);
        }
        self.discard_queue();
        self.lifecycle().finished = true;
        self.settled.notify_all();
    }
}

/// One export instance on the MIN-3 path, as the kernel's export lane drives it.
pub struct PortDoor {
    shared: Arc<Shared>,
    streams: Vec<u8>,
    routes: Vec<Route>,
    public_routes: Vec<String>,
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
    /// Close intake and drain accepted work. Repeated calls may shorten, never extend, the deadline.
    pub fn begin_drain(&self, deadline: Instant) {
        {
            let mut life = self.shared.lifecycle();
            if let Some(prior) = life.deadline {
                life.deadline = Some(prior.min(deadline));
            } else {
                life.deadline = Some(deadline);
                life.dropped_at_start = self.dropped();
            }
        }
        let _queue = self.shared.lock();
        self.shared.stop.store(true, Ordering::Release);
        self.shared.wake.notify_all();
        self.shared.settled.notify_all();
    }

    /// Wait only within the drain budget. Call on a blocking lifecycle thread, never a runtime worker.
    /// If native code cannot return, its worker retains the port and buffers; root must report incomplete
    /// shutdown and must not close the instance or native audit owner as though that worker quiesced.
    pub fn stop_until(&self, deadline: Instant) -> StopReport {
        self.begin_drain(deadline);
        let mut life = self.shared.lifecycle();
        while !life.finished {
            let until = life.deadline.unwrap_or(deadline);
            let Some(left) = until.checked_duration_since(Instant::now()) else {
                break;
            };
            let (next, _) = self
                .shared
                .settled
                .wait_timeout(life, left)
                .unwrap_or_else(|p| p.into_inner());
            life = next;
        }
        let finished = life.finished;
        let baseline = life.dropped_at_start;
        drop(life);
        if !finished {
            self.shared.abort();
        }
        let queued = self.shared.lock().len() as u64;
        let report = StopReport {
            worker_stopped: self.shared.lifecycle().finished,
            queued,
            in_flight: self.shared.in_flight.load(Ordering::Acquire),
            dropped: self.dropped().saturating_sub(baseline),
            cancelled: self.shared.abort.load(Ordering::Acquire),
            dispatch_failed: crate::dispatch::handle::latched(),
        };
        if report.worker_stopped {
            let mut worker = self.pump.lock().unwrap_or_else(|p| p.into_inner());
            if worker
                .as_ref()
                .is_some_and(std::thread::JoinHandle::is_finished)
            {
                if let Some(worker) = worker.take() {
                    let _ = worker.join();
                }
            }
        }
        report
    }

    /// Starts the instance's pump over `port`. `label` is the operator's instance name; `limits` its
    /// `limits` (only `timeout_ms` is read here: the per-delivery deadline, 0 = [`DEFAULT_DELIVER_TIMEOUT`]).
    pub fn open(
        label: &str,
        port: Arc<dyn ExportPort>,
        disk: Arc<dyn DestAppend>,
        limits: &InstanceLimits,
        observer: Arc<dyn ExportObserver>,
    ) -> Result<Arc<Self>, String> {
        let door = Self::prepare(label, port, disk, limits, observer);
        door.start()?;
        Ok(door)
    }

    /// Construct a candidate's complete delivery adapter without starting its pump.
    pub fn prepare(
        label: &str,
        port: Arc<dyn ExportPort>,
        disk: Arc<dyn DestAppend>,
        limits: &InstanceLimits,
        observer: Arc<dyn ExportObserver>,
    ) -> Arc<Self> {
        let timeout = match limits.timeout_ms {
            0 => DEFAULT_DELIVER_TIMEOUT,
            ms => Duration::from_millis(u64::from(ms)),
        };
        let streams = stream_ids(port.streams());
        let routes = port
            .scopes()
            .iter()
            .map(|scope| Route {
                path: scope.path.to_string(),
                method: RouteMethod::Get,
                auth: RouteAuth::None,
            })
            .collect();
        let public_routes = port
            .scopes()
            .iter()
            .map(|scope| scope.path.to_string())
            .collect();
        let shared = Arc::new(Shared {
            binding: ArcSwap::from_pointee(ExportBinding { port, disk }),
            observer,
            label: label.into(),
            timeout,
            queue: Mutex::new(VecDeque::new()),
            wake: Condvar::new(),
            stop: AtomicBool::new(false),
            abort: AtomicBool::new(false),
            in_flight: AtomicU64::new(0),
            lifecycle: Mutex::new(Lifecycle {
                finished: true,
                ..Lifecycle::default()
            }),
            settled: Condvar::new(),
            cancellation: Mutex::new(None),
            shed: AtomicU64::new(0),
            delivered: AtomicU64::new(0),
            custody: Default::default(),
        });
        Arc::new(Self {
            shared,
            streams,
            routes,
            public_routes,
            pump: Mutex::new(None),
        })
    }

    /// Start a prepared candidate once, after root's fallible serving assembly succeeds.
    pub fn start(&self) -> Result<(), String> {
        let mut pump = self.pump.lock().unwrap_or_else(|p| p.into_inner());
        let mut life = self.shared.lifecycle();
        if pump.is_some() || self.shared.stop.load(Ordering::Acquire) {
            return Err(format!(
                "the export pump for `{}` is already started or stopped",
                self.shared.label
            ));
        }
        life.finished = false;
        let shared = Arc::clone(&self.shared);
        match std::thread::Builder::new()
            .name(format!("export-{}", shared.label))
            .spawn(move || shared.pump())
        {
            Ok(worker) => {
                *pump = Some(worker);
                Ok(())
            }
            Err(error) => {
                life.finished = true;
                Err(format!(
                    "the export pump for `{}` could not start: {error}",
                    self.shared.label
                ))
            }
        }
    }

    /// The binding in service now.
    #[must_use]
    pub fn binding(&self) -> Arc<ExportBinding> {
        self.shared.binding.load_full()
    }

    /// DES-454 §4.2 step 6, the export swap seam (core #454; reload reuses it, #461): replace `expected` with
    /// `next` when `next` matches the served shape exactly, the door is not stopping, and the door still holds
    /// `expected`. Queued lines and the delivery and attempt of a set in flight carry over; the attempt already
    /// running finishes on `expected`. Ok: the predecessor, which the caller drops off the pump thread once the
    /// pump has released it (`Arc::strong_count == 1`, §4.4). Err: `next` comes back for the caller to close.
    pub fn swap_binding(
        &self,
        expected: &Arc<ExportBinding>,
        next: ExportBinding,
    ) -> Result<Arc<ExportBinding>, (SwapRefused, ExportBinding)> {
        // Under the queue lock: `begin_drain` sets `stop` under it, and swaps serialise on it.
        let _queue = self.shared.lock();
        if self.shared.stop.load(Ordering::Acquire) || self.shared.expired() {
            return Err((SwapRefused::Stopping, next));
        }
        if !Arc::ptr_eq(&self.shared.binding.load(), expected) {
            return Err((SwapRefused::Superseded, next));
        }
        if !same_shape(&*expected.port, &*next.port) {
            return Err((SwapRefused::ShapeChanged, next));
        }
        Ok(self.shared.binding.swap(Arc::new(next)))
    }

    /// The custody ceiling the instance stated in its `open` answer (§8.5), read through L7.
    #[must_use]
    pub fn custody_ceiling(&self) -> Option<u32> {
        self.shared.binding.load().port.custody_ceiling()
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

    fn render(
        &self,
        binding: &ExportBinding,
        scope: u32,
        families: &[Family],
    ) -> Result<Vec<u8>, String> {
        let mut body = Vec::new();
        with_snapshot(families, |snapshot| {
            binding
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
        self.shared.abort();
        let pump = self.pump.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(pump) = pump {
            if pump.is_finished() && pump.thread().id() != std::thread::current().id() {
                let _ = pump.join();
            }
            // A still-running worker owns Shared, including the live port and its buffers. Detaching
            // here is deliberate: Drop is not a shutdown protocol and must never wait without a bound.
        } else {
            // A rolled-back prepared candidate has no worker to account its retained lines.
            self.shared.discard_queue();
        }
    }
}

impl ExportCalls for PortDoor {
    fn recorder_requirements(&self) -> Option<RecorderRequirements> {
        self.shared
            .binding
            .load()
            .port
            .recorder()
            .map(|r| RecorderRequirements {
                retention_seconds: r.retention_s,
                key_gauge_limit: usize::try_from(r.key_gauge_limit).unwrap_or(usize::MAX),
            })
    }

    fn streams(&self) -> &[u8] {
        &self.streams
    }

    /// Core mounts these immutable D_SCOPE paths and supplies each scope's snapshot.
    fn routes(&self) -> &[Route] {
        &self.routes
    }

    fn public_routes(&self) -> &[String] {
        &self.public_routes
    }

    fn scope(&self, path: &str) -> Option<u32> {
        self.shared
            .binding
            .load()
            .port
            .scopes()
            .iter()
            .find(|scope| scope.path.as_ref() == path)
            .map(|scope| scope.scope)
    }

    fn render_scope(&self, scope: u32, families: &[Family]) -> Result<Served, String> {
        // One load serves both the check and the render.
        let binding = self.shared.binding.load_full();
        if !binding
            .port
            .scopes()
            .iter()
            .any(|declared| declared.scope == scope)
        {
            return Err("the export instance did not declare this snapshot scope".into());
        }
        let mut response = Served {
            status: 200,
            headers: Vec::new(),
            body: Vec::new(),
        };
        with_snapshot(families, |snapshot| {
            binding
                .port
                .render(scope, snapshot, &mut |content_type, bytes| {
                    response.headers = vec![("content-type".into(), content_type.into())];
                    response.body.extend_from_slice(bytes);
                })
        })
        .map_err(|error| {
            format!(
                "export instance `{}` did not render ({})",
                self.shared.label,
                why(&error)
            )
        })?;
        Ok(response)
    }

    fn deliver(&self, stream: u8, line: Vec<u8>, hold: Box<dyn Send>) -> Queued {
        if !self.streams.contains(&stream) {
            self.shed(ExportLossKind::CaptureRefused);
            return Queued::Shed;
        }
        {
            let mut q = self.shared.lock();
            if self.shared.stop.load(Ordering::Acquire) {
                drop(q);
                self.shared.drop_lines(1, ExportDropReason::Stopped);
                return Queued::Shed;
            }
            if q.len() >= MAX_QUEUED_LINES {
                drop(q);
                self.shared.drop_lines(1, ExportDropReason::QueueFull);
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
        self.shared.binding.load().port.span_records()
    }

    fn scrape(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        self.render(&self.shared.binding.load_full(), x::SCOPE_METRICS, families)
    }

    fn scrape_hooks(&self, families: &[Family]) -> Result<Vec<u8>, String> {
        let binding = self.shared.binding.load_full();
        if !binding
            .port
            .scopes()
            .iter()
            .any(|s| s.scope == x::SCOPE_HOOKS)
        {
            return Err("this instance renders no hook families".to_string());
        }
        self.render(&binding, x::SCOPE_HOOKS, families)
    }

    fn status(&self) -> Option<Vec<u8>> {
        None
    }

    fn serve(&self, _req: &ServeRequest<'_>) -> Result<Served, String> {
        Err("a MIN-3 export instance serves no routes of its own".to_string())
    }

    fn shed(&self, kind: ExportLossKind) {
        match kind {
            ExportLossKind::Dropped(reason) => self.shared.drop_lines(1, reason),
            ExportLossKind::CaptureRefused => self
                .shared
                .observer
                .observe(ExportObservation::CaptureRefused),
            ExportLossKind::IntegrityFailed => self
                .shared
                .observer
                .observe(ExportObservation::IntegrityFailed),
        }
    }
}

/// DES-454 §4.2 step 5: a successor serves in place of its predecessor only with the same streams, scopes,
/// recorder needs, span records and custody ceiling, because the door's routes and streams stay as they are.
fn same_shape(served: &dyn ExportPort, next: &dyn ExportPort) -> bool {
    let recorder = |port: &dyn ExportPort| {
        port.recorder()
            .map(|needs| (needs.retention_s, needs.key_gauge_limit))
    };
    served.streams() == next.streams()
        && served.span_records() == next.span_records()
        && served.custody_ceiling() == next.custody_ceiling()
        && recorder(served) == recorder(next)
        && served.scopes().len() == next.scopes().len()
        && served
            .scopes()
            .iter()
            .zip(next.scopes())
            .all(|(a, b)| a.scope == b.scope && a.path == b.path)
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

/// One sample's role, bound and the label it does not keep (the `le` / `quantile` coordinate becomes `bound`).
fn sample_shape(
    family: &Family,
    sample_name: &str,
    labels: &[(String, String)],
) -> (u32, f64, Option<&'static str>) {
    let suffix = sample_name.strip_prefix(family.name.as_str()).unwrap_or("");
    let coordinate = |key: &str| {
        labels
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| number(v))
    };
    match suffix {
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
    }
}

/// The labels a sample keeps, in recorder order: all but its `drop` coordinate.
fn kept<'f>(
    labels: &'f [(String, String)],
    drop: Option<&'static str>,
) -> impl Iterator<Item = (&'f str, &'f str)> {
    labels
        .iter()
        .filter(move |(k, _)| Some(k.as_str()) != drop)
        .map(|(k, v)| (k.as_str(), v.as_str()))
}

/// Lowers the recorder snapshot into the port's borrowed snapshot and runs `f` over it. Three lists per
/// scrape whatever the family count: every kept label, every sample, every family; each sample lends its run
/// of the labels and each family its run of the samples, in recorder order. Released when `f` returns.
fn with_snapshot<R>(families: &[Family], f: impl FnOnce(&[FamilyIn<'_>]) -> R) -> R {
    let all = || {
        families
            .iter()
            .flat_map(|fam| fam.samples.iter().map(move |s| (fam, s)))
    };
    let mut labels: Vec<(&str, &str)> =
        Vec::with_capacity(all().map(|(_, s)| s.labels.len()).sum());
    for (fam, s) in all() {
        let (_, _, drop) = sample_shape(fam, &s.name, &s.labels);
        labels.extend(kept(&s.labels, drop));
    }
    let mut samples: Vec<SampleIn<'_>> = Vec::with_capacity(all().count());
    let mut at = 0usize;
    for (fam, s) in all() {
        let (role, bound, drop) = sample_shape(fam, &s.name, &s.labels);
        let end = at + kept(&s.labels, drop).count();
        samples.push(SampleIn {
            value: number(&s.value),
            bound,
            ts_ms: 0,
            role,
            labels: &labels[at..end],
        });
        at = end;
    }
    let mut snapshot: Vec<FamilyIn<'_>> = Vec::with_capacity(families.len());
    let mut at = 0usize;
    for fam in families {
        let end = at + fam.samples.len();
        snapshot.push(FamilyIn {
            kind: family_kind(fam.kind),
            name: &fam.name,
            help: fam.help.as_deref().unwrap_or(""),
            samples: &samples[at..end],
        });
        at = end;
    }
    f(&snapshot)
}

/// W2-SW-EXPORT: one export instance on the MIN-3 path. Opens `spec` through the registry (`open_export`, L2/L7)
/// and hands the kernel's export lane a [`PortDoor`] over the port: the round-33 pump
/// (core-minted `delivery`, counted `attempt`), the image's FB_SPAN_RECORDS and custody ceiling read through
/// L7, APPEND answers handed to `disk` (core's bound destinations, §12.21).
pub async fn open_min3<N: busbar_plugin_abi::host_side::needs::Needs>(
    registry: &crate::instance::Registry,
    spec: &crate::instance::InstanceSpec<'_>,
    needs: &Arc<N>,
    refs: &Arc<dyn busbar_ports::binder::RefSource>,
    disk: Arc<dyn DestAppend>,
    observer: Arc<dyn ExportObserver>,
) -> Result<Arc<PortDoor>, String> {
    let port = registry
        .open_export(spec, needs, refs)
        .await
        .map_err(|e| crate::cold::export_pump::not_opened(spec.name, &e))?;
    PortDoor::open(spec.name, port, disk, &spec.limits, observer)
}

#[cfg(test)]
#[path = "tests/export_pump_tests.rs"]
mod tests;
