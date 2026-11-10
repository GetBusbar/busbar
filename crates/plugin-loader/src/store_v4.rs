// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Staged asynchronous primitive persistence binding. Selection remains explicit.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    Blob, DeadlineClass, OutHead, Outcome, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, ReadyIn};
use busbar_contract::abi::sdk::store::v4::{
    self as sdk, metadata,
    response::{self, ResponseError},
};
use busbar_contract::abi::store::{v4 as wire, HostBuf};
use busbar_contract::persistence::{self as owned, Failure, PersistenceBackend};
use zeroize::Zeroize;

use crate::dispatch::kinds::store_v4::StoreV4;
use crate::dispatch::lifecycle::{self, AnswerLease};
use crate::dispatch::{
    in_head, now_ns, out_head, Dispatcher, Frame, InFrame, Lent, OutFrame, Plugin,
};

const DEADLINE: Duration = Duration::from_secs(30);

/// Host resource admission dimensions, independent of protocol or record-size limits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Aggregate input descriptor allocation budget.
    pub descriptor_bytes: usize,
    /// Maximum initialized output descriptors per call.
    pub output_items: usize,
    /// Maximum initialized output byte allocation per call.
    pub output_bytes: usize,
    /// Aggregate owned decoded response allocation budget.
    pub decode_bytes: usize,
}

/// Host-owned Store v4 selection and opening resources.
pub struct DoorPersistenceAxis {
    /// Shared asynchronous crossing dispatcher.
    pub dispatcher: Arc<Dispatcher>,
    /// Per-instance plugin log configuration.
    pub logs: crate::dispatch::PluginLogConfig,
    /// Host connection capabilities made available to the plugin.
    pub conns: crate::dispatch::ConnTable,
    /// Explicit host resource admission budgets for opened instances.
    pub limits: Limits,
}

impl owned::axis::PersistenceAxis for DoorPersistenceAxis {
    fn prepare<'a>(
        &'a self,
        door: owned::axis::StoreDoor,
        label: &'a str,
        settings: &'a [u8],
    ) -> owned::lifecycle::PrepareCall<'a> {
        Box::pin(async move {
            use busbar_contract::abi::mechanism::KindCode;
            use owned::axis::StoreDoor;
            let sink = self
                .logs
                .sink(label, KindCode::Store, Arc::new(crate::dispatch::NoSink))
                .map_err(|e| {
                    eprintln!("store prepare '{label}': log sink unavailable: {e}");
                    owned::lifecycle::Error::Unavailable
                })?;
            let bind = crate::dispatch::Bind {
                instance: Arc::from(label),
                max_inflight_cap: u32::MAX,
                sink: Arc::new(sink),
                dispatcher: self.dispatcher.adopter(),
                conns: self.conns.clone(),
            };
            let plugin = match door {
                StoreDoor::Linked(door) => crate::dispatch::LinkedRow::of_kind::<StoreV4>(door)
                    .and_then(|row| crate::dispatch::load_linked::<StoreV4>(&row, bind)),
                StoreDoor::Dropped {
                    file,
                    bytes,
                    stated,
                } => crate::dispatch::load_dropped_bytes::<StoreV4>(&bytes, &file, &stated, bind),
            }
            .map_err(|e| {
                eprintln!("store prepare '{label}': plugin load refused: {e}");
                owned::lifecycle::Error::Unavailable
            })?;
            Ok(Arc::new(LoadedPrepared::new(
                plugin,
                self.dispatcher.clone(),
                settings,
                self.limits,
            )?) as owned::lifecycle::Prepared)
        })
    }
    fn open<'a>(
        &'a self,
        door: owned::axis::StoreDoor,
        label: &'a str,
        settings: &'a [u8],
    ) -> owned::axis::OpenCall<'a> {
        Box::pin(async move {
            use busbar_contract::abi::mechanism::KindCode;
            use owned::axis::StoreDoor;

            let sink = self
                .logs
                .sink(label, KindCode::Store, Arc::new(crate::dispatch::NoSink))?;
            let bind = crate::dispatch::Bind {
                instance: Arc::from(label),
                max_inflight_cap: u32::MAX,
                sink: Arc::new(sink),
                dispatcher: self.dispatcher.adopter(),
                conns: self.conns.clone(),
            };
            let plugin = match door {
                StoreDoor::Linked(door) => crate::dispatch::LinkedRow::of_kind::<StoreV4>(door)
                    .and_then(|row| crate::dispatch::load_linked::<StoreV4>(&row, bind)),
                StoreDoor::Dropped {
                    file,
                    bytes,
                    stated,
                } => crate::dispatch::load_dropped_bytes::<StoreV4>(&bytes, &file, &stated, bind),
            }
            .map_err(|error| error.to_string())?;
            let backend =
                LoadedPersistence::open(plugin, self.dispatcher.clone(), settings, self.limits)
                    .await?;
            Ok(Arc::new(backend) as owned::axis::OpenedBackend)
        })
    }
}

/// One explicitly admitted and opened Store v4 instance.
#[derive(Debug)]
pub struct LoadedPersistence {
    plugin: Arc<Plugin<StoreV4>>,
    _session: Arc<Session>,
    dispatcher: Arc<Dispatcher>,
    info: owned::BackendInfo,
    limits: Limits,
    next_worker: AtomicU32,
}

struct OpenFailure {
    code: owned::lifecycle::Error,
    message: String,
}

impl OpenFailure {
    fn new(code: owned::lifecycle::Error, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl LoadedPersistence {
    /// Open and ready the instance using only asynchronous dispatcher crossings.
    pub async fn open(
        plugin: Plugin<StoreV4>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        limits: Limits,
    ) -> Result<Self, String> {
        let plugin = Arc::new(plugin);
        let session = Arc::new(Session {
            plugin: plugin.clone(),
        });
        let mut open = OpenLent::new(plugin.secret_refs(), settings);
        open._session = Some(session.clone());
        let lent = Arc::new(open);
        Self::open_session(plugin, session, dispatcher, lent, limits, None, true)
            .await
            .map_err(|failure| failure.message)
    }

    async fn open_session(
        plugin: Arc<Plugin<StoreV4>>,
        session: Arc<Session>,
        dispatcher: Arc<Dispatcher>,
        open: Arc<OpenLent>,
        limits: Limits,
        binding: Option<Arc<sdk::bootstrap::OpenBindingBytes>>,
        serving: bool,
    ) -> Result<Self, OpenFailure> {
        let mut frame = lifecycle::open_frame(octets(&open.settings));
        frame.input.secrets = open.blobs.as_ptr();
        frame.input.secrets_len = open.blobs.len();
        if let Some(binding) = binding.as_ref() {
            frame.input.head.extensions = binding.extensions();
        }
        let lent = Arc::new(PreparedOpenLent {
            _open: open,
            _binding: binding,
        });
        let ticket = dispatcher.mint(0).ok_or_else(|| {
            OpenFailure::new(owned::lifecycle::Error::Busy, "no open ticket available")
        })?;
        let recycle = Recycle(&dispatcher, ticket);
        let done = dispatcher
            .submit_lent(
                &plugin,
                ticket,
                life::OPEN,
                frame,
                DeadlineClass::Call,
                deadline(),
                lent,
            )
            .await;
        let lease = AnswerLease::new(&plugin, done.lease);
        if done.detached || done.disposition.is_some() {
            return Err(OpenFailure::new(
                owned::lifecycle::Error::Unknown,
                "primitive store open failed",
            ));
        }
        if done.outcome != Outcome::Ready {
            let (code, name) = match done.outcome {
                Outcome::Refused => (owned::lifecycle::Error::Refused, "refused"),
                Outcome::Fault => (owned::lifecycle::Error::Corrupt, "fault"),
                _ => (owned::lifecycle::Error::Unknown, "unknown"),
            };
            return Err(OpenFailure::new(
                code,
                format!("primitive store open failed: plugin answered {name}"),
            ));
        }
        let info = done
            .frame
            .as_ref()
            .ok_or_else(|| "primitive store open has no frame".to_string())
            .and_then(|frame| instance_metadata(frame.out.head.extensions));
        drop(lease);
        drop(recycle);
        let info =
            info.map_err(|message| OpenFailure::new(owned::lifecycle::Error::Corrupt, message))?;
        let result = Self {
            plugin,
            _session: session,
            dispatcher,
            info,
            limits,
            next_worker: AtomicU32::new(0),
        };
        if serving {
            result.ready().await?;
        }
        Ok(result)
    }

    async fn ready(&self) -> Result<(), OpenFailure> {
        if self.plugin.has_ready() {
            let ticket = self.dispatcher.mint(0).ok_or_else(|| {
                OpenFailure::new(owned::lifecycle::Error::Busy, "no ready ticket available")
            })?;
            let _recycle = Recycle(&self.dispatcher, ticket);
            let frame = Frame::new(
                ReadyIn {
                    head: in_head(),
                    host: std::ptr::null(),
                },
                out_head(),
            );
            let done = self
                .dispatcher
                .submit_lent(
                    &self.plugin,
                    ticket,
                    life::READY,
                    frame,
                    DeadlineClass::Call,
                    deadline(),
                    self._session.clone() as Lent,
                )
                .await;
            let _lease = AnswerLease::new(&self.plugin, done.lease);
            if done.outcome != Outcome::Ready
                || done.frame.is_none()
                || done.detached
                || done.disposition.is_some()
            {
                let code = if !done.detached
                    && done.disposition.is_none()
                    && done.outcome == Outcome::Refused
                {
                    owned::lifecycle::Error::Refused
                } else {
                    owned::lifecycle::Error::Unknown
                };
                return Err(OpenFailure::new(code, "primitive store ready failed"));
            }
        }
        Ok(())
    }

    async fn submit<R: Request>(&self, request: R) -> Result<R::Value, Failure> {
        let worker =
            self.next_worker.fetch_add(1, Ordering::Relaxed) % self.dispatcher.workers().max(1);
        let ticket = self.dispatcher.mint(worker).ok_or(Failure::Overloaded)?;
        let _recycle = Recycle(&self.dispatcher, ticket);
        let retained = Arc::new(Retained(
            UnsafeCell::new(request),
            Some(self._session.clone()),
        ));
        let until = deadline();
        for attempt in 0..2 {
            let frame = retained.frame();
            let done = self
                .dispatcher
                .submit_lent(
                    &self.plugin,
                    ticket,
                    R::SLOT,
                    frame,
                    DeadlineClass::Call,
                    until,
                    retained.clone() as Lent,
                )
                .await;
            let _lease = AnswerLease::new(&self.plugin, done.lease);
            if done.detached || done.disposition.is_some() {
                return Err(if R::COMMIT {
                    Failure::Unknown
                } else {
                    Failure::Unavailable
                });
            }
            let Some(frame) = done.frame else {
                return Err(if R::COMMIT {
                    Failure::Unknown
                } else {
                    Failure::Unavailable
                });
            };
            let decoded = retained.get().decode(
                done.outcome,
                &frame,
                self.limits.decode_bytes,
                self.info.clock_authority,
            );
            match decoded {
                Err(ResponseError::Short {
                    needed_items,
                    needed_bytes,
                }) if done.short && attempt == 0 => {
                    // Release envelope ownership before reusing the same immutable request.
                    drop(_lease);
                    retained
                        .grow(needed_items, needed_bytes, self.limits)
                        .map_err(|_| {
                            if R::COMMIT {
                                Failure::Unknown
                            } else {
                                Failure::Overloaded
                            }
                        })?;
                }
                result => {
                    return result.map_err(|error| {
                        if R::COMMIT && attempt != 0 {
                            Failure::Unknown
                        } else {
                            classify(error, R::COMMIT)
                        }
                    })
                }
            }
        }
        Err(if R::COMMIT {
            Failure::Unknown
        } else {
            Failure::Corrupt
        })
    }
}

#[derive(Debug)]
struct Session {
    plugin: Arc<Plugin<StoreV4>>,
}
impl Drop for Session {
    fn drop(&mut self) {
        // Dispatcher::end gives back the inflight admission before JobOf releases its
        // Lent, and JobOf defers that drop until the worker state lock is released.
        // Thus the final session owner can close without racing its native crossing.
        lifecycle::close(&self.plugin);
    }
}

impl PersistenceBackend for LoadedPersistence {
    fn info(&self) -> owned::BackendInfo {
        self.info
    }
    fn read(&self, request: Arc<owned::Read>) -> owned::Call<'_, owned::ReadResult> {
        Box::pin(async move {
            if request.dataset != self.info.dataset {
                return Err(Failure::Refused);
            }
            if request.addresses.len() > self.limits.output_items {
                return Err(Failure::Overloaded);
            }
            let request_len = request.addresses.len();
            let source = sdk::Read::new(request, self.limits.descriptor_bytes)
                .map_err(|_| Failure::Overloaded)?;
            self.submit(ReadRequest {
                source,
                items: presized(
                    request_len,
                    self.limits,
                    wire::ReadValue {
                        found: 0,
                        _reserved: 0,
                        value: Blob::ABSENT,
                    },
                ),
                bytes: presized_bytes(request_len.saturating_mul(INITIAL_VALUE_BYTES), self.limits),
            })
            .await
        })
    }
    fn scan(&self, request: Arc<owned::Scan>) -> owned::Call<'_, owned::Page> {
        Box::pin(async move {
            if request.dataset != self.info.dataset {
                return Err(Failure::Refused);
            }
            if request.max_items > self.limits.output_items
                || request.max_bytes > self.limits.output_bytes
            {
                return Err(Failure::Overloaded);
            }
            if request.after.is_some() && request.generation.is_none() && !request.allow_change {
                return Err(Failure::Refused);
            }
            self.submit(ScanRequest {
                items: presized(
                    request.max_items,
                    self.limits,
                    wire::ScanRow {
                        key: wire::Bytes {
                            ptr: std::ptr::null(),
                            len: 0,
                        },
                        value: Blob::ABSENT,
                    },
                ),
                bytes: presized_bytes(request.max_bytes, self.limits),
                source: request,
            })
            .await
        })
    }
    fn commit(&self, candidate: owned::PreparedCandidate) -> owned::Call<'_, owned::Decision> {
        Box::pin(async move {
            if candidate.candidate().id.dataset != self.info.dataset {
                return Err(Failure::Refused);
            }
            let source = sdk::Commit::new(&candidate, self.limits.descriptor_bytes)
                .map_err(|_| Failure::Overloaded)?;
            self.submit(CommitRequest {
                original: candidate,
                source,
                bytes: zeroize::Zeroizing::new(Vec::new()),
            })
            .await
        })
    }
    fn clock(&self, dataset: owned::DatasetId) -> owned::Call<'_, owned::ClockObservation> {
        Box::pin(async move {
            if dataset != self.info.dataset {
                return Err(Failure::Refused);
            }
            self.submit(ClockRequest(dataset)).await
        })
    }
}

fn deadline() -> u64 {
    now_ns().saturating_add(DEADLINE.as_nanos() as u64)
}
fn classify(error: ResponseError, commit: bool) -> Failure {
    match error {
        ResponseError::Failure(failure) => failure,
        _ if commit => Failure::Unknown,
        ResponseError::Budget | ResponseError::Allocation => Failure::Overloaded,
        ResponseError::Pending => Failure::Unavailable,
        _ => Failure::Corrupt,
    }
}

struct Recycle<'a>(
    &'a Dispatcher,
    busbar_contract::abi::mechanism::ticket::Ticket,
);
impl Drop for Recycle<'_> {
    fn drop(&mut self) {
        self.0.recycle(self.1);
    }
}

trait Request: Send + 'static {
    type I: InFrame;
    type O: OutFrame;
    type Value;
    const SLOT: u32;
    const COMMIT: bool = false;
    fn frame(&mut self) -> Frame<Self::I, Self::O>;
    fn grow(&mut self, items: u64, bytes: u64, limits: Limits) -> Result<(), ()>;
    fn decode(
        &self,
        outcome: Outcome,
        frame: &Frame<Self::I, Self::O>,
        budget: usize,
        authority: [u8; 16],
    ) -> Result<Self::Value, ResponseError>;
}

struct Retained<R>(UnsafeCell<R>, #[allow(dead_code)] Option<Arc<Session>>);
// SAFETY: Only the caller accesses the request, before submission and after native
// completion. The dispatcher retains ownership without accessing this cell, including
// after caller cancellation; native code accesses only stable pointed-to allocations.
unsafe impl<R: Request> Send for Retained<R> {}
// SAFETY: the same exclusive crossing discipline applies to shared ownership.
unsafe impl<R: Request> Sync for Retained<R> {}
impl<R: Request> Retained<R> {
    fn get(&self) -> &R {
        unsafe { &*self.0.get() }
    }
    fn frame(&self) -> Frame<R::I, R::O> {
        unsafe { &mut *self.0.get() }.frame()
    }
    fn grow(&self, items: u64, bytes: u64, limits: Limits) -> Result<(), ()> {
        unsafe { &mut *self.0.get() }.grow(items, bytes, limits)
    }
}

fn blank<O: OutFrame>() -> O {
    // SAFETY: OutFrame consists of zero-valid C data, leading with OutHead.
    let mut out: O = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::from_mut(&mut out)
            .cast::<OutHead>()
            .write(OutHead {
                size: std::mem::size_of::<O>() as u32,
                ..out_head()
            })
    };
    out
}
fn output_bytes(bytes: &mut [u8]) -> HostBuf {
    HostBuf {
        ptr: bytes.as_mut_ptr(),
        cap: bytes.len(),
    }
}
fn allocate<T: Copy>(count: usize, zero: T) -> Result<Vec<T>, ()> {
    count
        .checked_mul(std::mem::size_of::<T>())
        .filter(|bytes| *bytes <= isize::MAX as usize)
        .ok_or(())?;
    let mut out = Vec::new();
    out.try_reserve_exact(count).map_err(|_| ())?;
    out.resize(count, zero);
    Ok(out)
}
fn grow<T: Copy>(
    items: &mut Vec<T>,
    bytes: &mut zeroize::Zeroizing<Vec<u8>>,
    needed_items: u64,
    needed_bytes: u64,
    limits: Limits,
    zero: T,
) -> Result<(), ()> {
    let count = usize::try_from(needed_items)
        .map_err(|_| ())?
        .max(items.len());
    let length = usize::try_from(needed_bytes)
        .map_err(|_| ())?
        .max(bytes.len());
    if count > limits.output_items
        || length > limits.output_bytes
        || (count == items.len() && length == bytes.len())
    {
        return Err(());
    }
    let new_items = allocate(count, zero)?;
    let new_bytes = zeroize::Zeroizing::new(allocate(length, 0)?);
    // Descriptor fields include raw addresses into wiped bytes: clear retired arrays too.
    wipe_items(items);
    *items = new_items;
    *bytes = new_bytes;
    Ok(())
}
/// Initial per-address value budget for a read; larger values take the Short retry.
const INITIAL_VALUE_BYTES: usize = 4096;

/// Zeroed output bytes sized up front, capped by the output byte limit.
fn presized_bytes(want: usize, limits: Limits) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(allocate(want.min(limits.output_bytes), 0).unwrap_or_default())
}
/// Descriptor array sized up front so a fitting answer needs one plugin crossing, not a Short retry.
fn presized<T: Copy>(count: usize, limits: Limits, zero: T) -> Vec<T> {
    if count == 0 || count > limits.output_items {
        return Vec::new();
    }
    allocate(count, zero).unwrap_or_default()
}
fn wipe_items<T>(items: &mut [T]) {
    // SAFETY: every use is a zero-valid C output descriptor. Volatile writes ensure
    // descriptor pointers and lengths are erased before the allocation is freed.
    for offset in 0..std::mem::size_of_val(items) {
        unsafe {
            std::ptr::write_volatile(items.as_mut_ptr().cast::<u8>().add(offset), 0);
        }
    }
}
fn authority(actual: [u8; 16], expected: [u8; 16]) -> Result<(), ResponseError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ResponseError::Malformed)
    }
}

struct ReadRequest {
    source: sdk::Read,
    items: Vec<wire::ReadValue>,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
struct ScanRequest {
    source: Arc<owned::Scan>,
    items: Vec<wire::ScanRow>,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
struct CommitRequest {
    original: owned::PreparedCandidate,
    source: sdk::Commit,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}
struct ClockRequest(owned::DatasetId);
// SAFETY: output pointers are host-owned allocations exclusively accessed by one
// native crossing; source marshallers retain immutable ownership through completion.
unsafe impl Send for ReadRequest {}
// SAFETY: as ReadRequest; Scan source owns its key/cursor allocations.
unsafe impl Send for ScanRequest {}
impl Drop for ReadRequest {
    fn drop(&mut self) {
        wipe_items(&mut self.items);
    }
}
impl Drop for ScanRequest {
    fn drop(&mut self) {
        wipe_items(&mut self.items);
    }
}

impl Request for ReadRequest {
    type I = wire::ReadIn;
    type O = wire::ReadOut;
    type Value = owned::ReadResult;
    const SLOT: u32 = wire::slot::READ;
    fn frame(&mut self) -> Frame<Self::I, Self::O> {
        Frame::new(
            self.source.frame(
                in_head(),
                wire::HostValues {
                    items: self.items.as_mut_ptr(),
                    items_cap: self.items.len(),
                    bytes: output_bytes(&mut self.bytes),
                },
            ),
            blank(),
        )
    }
    fn grow(&mut self, items: u64, bytes: u64, limits: Limits) -> Result<(), ()> {
        grow(
            &mut self.items,
            &mut self.bytes,
            items,
            bytes,
            limits,
            wire::ReadValue {
                found: 0,
                _reserved: 0,
                value: Blob::ABSENT,
            },
        )
    }
    fn decode(
        &self,
        outcome: Outcome,
        frame: &Frame<Self::I, Self::O>,
        budget: usize,
        expected: [u8; 16],
    ) -> Result<Self::Value, ResponseError> {
        let value = response::read(
            outcome,
            &frame.input,
            &frame.out,
            &self.items,
            &self.bytes,
            budget,
        )?;
        authority(frame.out.authority, expected)?;
        Ok(value)
    }
}
impl Request for ScanRequest {
    type I = wire::ScanIn;
    type O = wire::ScanOut;
    type Value = owned::Page;
    const SLOT: u32 = wire::slot::SCAN;
    fn frame(&mut self) -> Frame<Self::I, Self::O> {
        Frame::new(
            sdk::scan(
                &self.source,
                in_head(),
                wire::HostRows {
                    items: self.items.as_mut_ptr(),
                    items_cap: self.items.len(),
                    bytes: output_bytes(&mut self.bytes),
                },
            ),
            blank(),
        )
    }
    fn grow(&mut self, items: u64, bytes: u64, limits: Limits) -> Result<(), ()> {
        grow(
            &mut self.items,
            &mut self.bytes,
            items,
            bytes,
            limits,
            wire::ScanRow {
                key: wire::Bytes {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                value: Blob::ABSENT,
            },
        )
    }
    fn decode(
        &self,
        outcome: Outcome,
        frame: &Frame<Self::I, Self::O>,
        budget: usize,
        _: [u8; 16],
    ) -> Result<Self::Value, ResponseError> {
        response::scan(
            outcome,
            &self.source,
            &frame.input,
            &frame.out,
            &self.items,
            &self.bytes,
            budget,
        )
    }
}
impl Request for CommitRequest {
    type I = wire::CommitIn;
    type O = wire::CommitOut;
    type Value = owned::Decision;
    const SLOT: u32 = wire::slot::COMMIT;
    const COMMIT: bool = true;
    fn frame(&mut self) -> Frame<Self::I, Self::O> {
        Frame::new(
            self.source.frame(in_head(), output_bytes(&mut self.bytes)),
            blank(),
        )
    }
    fn grow(&mut self, _: u64, bytes: u64, limits: Limits) -> Result<(), ()> {
        grow(&mut Vec::<u8>::new(), &mut self.bytes, 0, bytes, limits, 0)
    }
    fn decode(
        &self,
        outcome: Outcome,
        frame: &Frame<Self::I, Self::O>,
        budget: usize,
        expected: [u8; 16],
    ) -> Result<Self::Value, ResponseError> {
        let value = response::commit(outcome, &frame.input, &frame.out, &self.bytes, budget)?;
        authority(frame.out.authority, expected)?;
        if let owned::Decision::Applied(ref result) = value {
            if result != &self.original.candidate().result {
                return Err(ResponseError::Malformed);
            }
        }
        Ok(value)
    }
}
impl Request for ClockRequest {
    type I = wire::ClockIn;
    type O = wire::ClockOut;
    type Value = owned::ClockObservation;
    const SLOT: u32 = wire::slot::CLOCK;
    fn frame(&mut self) -> Frame<Self::I, Self::O> {
        Frame::new(
            wire::ClockIn {
                head: in_head(),
                dataset: self.0 .0,
            },
            blank(),
        )
    }
    fn grow(&mut self, _: u64, _: u64, _: Limits) -> Result<(), ()> {
        Err(())
    }
    fn decode(
        &self,
        outcome: Outcome,
        frame: &Frame<Self::I, Self::O>,
        _: usize,
        expected: [u8; 16],
    ) -> Result<Self::Value, ResponseError> {
        let value = response::clock(outcome, &frame.out)?;
        authority(value.authority, expected)?;
        Ok(value)
    }
}

fn octets(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}
fn instance_metadata(blob: Blob) -> Result<owned::BackendInfo, String> {
    let invalid = || "primitive store returned invalid or missing instance metadata".to_string();
    if blob.fmt != BLOB_OCTETS
        || blob.flags != 0
        || blob.ptr.is_null()
        || blob.len as u64 > busbar_contract::abi::mechanism::check::HARD_MAX_BYTES
    {
        return Err(invalid());
    }
    // SAFETY: the dispatcher validated this leased extension span; OPEN's envelope
    // lease is retained until the complete fixed metadata has been copied.
    let bytes = unsafe { crate::dispatch::plugin::blob_bytes(blob) };
    // Reject incomplete/trailing entries and duplicate mandatory metadata keys.
    let mut at = 0usize;
    let mut result = None;
    while at < bytes.len() {
        let key_len = usize::from(u16::from_le_bytes(
            bytes
                .get(at..at + 2)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ));
        at += 2;
        let key = bytes
            .get(at..at.checked_add(key_len).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        at += key_len;
        let value_len = usize::try_from(u32::from_le_bytes(
            bytes
                .get(at..at + 4)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ))
        .map_err(|_| invalid())?;
        at += 4;
        let value = bytes
            .get(at..at.checked_add(value_len).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        at += value_len;
        if key == metadata::EXTENSION.as_bytes() {
            if result.is_some() {
                return Err(invalid());
            }
            result = Some(metadata::decode(value).map_err(|_| invalid())?);
        }
    }
    result.ok_or_else(invalid)
}

struct PreparedOpenLent {
    _open: Arc<OpenLent>,
    _binding: Option<Arc<sdk::bootstrap::OpenBindingBytes>>,
}

struct OpenLent {
    _session: Option<Arc<Session>>,
    settings: zeroize::Zeroizing<Vec<u8>>,
    _secrets: Vec<zeroize::Zeroizing<Vec<u8>>>,
    blobs: Vec<Blob>,
}
// SAFETY: all blob pointers borrow immutable allocations owned by this retained value.
unsafe impl Send for OpenLent {}
// SAFETY: the immutable OPEN owner has no shared mutation.
unsafe impl Sync for OpenLent {}
impl OpenLent {
    fn new(refs: &[String], settings: &[u8]) -> Self {
        let mut settings = zeroize::Zeroizing::new(settings.to_vec());
        let mut secrets = Vec::new();
        if !refs.is_empty() {
            if let Ok(mut block) = serde_json::from_slice::<serde_json::Value>(&settings) {
                let as_bytes = |value: Option<serde_json::Value>| match value {
                    Some(serde_json::Value::String(value)) => value.into_bytes(),
                    _ => Vec::new(),
                };
                let values = busbar_contract::secret_fields::lend(
                    &mut block,
                    refs,
                    false,
                    |_, value| Ok::<_, std::convert::Infallible>(as_bytes(value)),
                    |_, value| Ok(as_bytes(Some(value))),
                )
                .unwrap_or_else(|error| match error {});
                secrets = values.into_iter().map(zeroize::Zeroizing::new).collect();
                settings.zeroize();
                settings.extend_from_slice(&serde_json::to_vec(&block).unwrap_or_default());
            }
        }
        let blobs = secrets
            .iter()
            .map(|bytes| Blob {
                ptr: bytes.as_ptr(),
                len: bytes.len(),
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            })
            .collect();
        Self {
            _session: None,
            settings,
            _secrets: secrets,
            blobs,
        }
    }
}

#[cfg(test)]
#[path = "tests/store_v4_tests.rs"]
mod tests;

#[path = "store_v4/prepared.rs"]
mod prepared;
pub use prepared::LoadedPrepared;
