// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One boot-owned inbound budget. Data cannot consume the operator reserve. Storage custody
//! retains both its byte charge and the original request count through detached consumption.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore};

/// Buffered inbound payload, not allocator slack, outbound payload, or process RSS.
pub const BODY_BYTES: u32 = 256 * 1024 * 1024;
/// The part of BODY_BYTES unavailable to data listeners.
pub const OPERATOR_BODY_BYTES: u32 = 32 * 1024 * 1024;

/// Resource class assigned by trusted boot listener construction, never request contents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionClass {
    Data,
    /// Only the dedicated operator listener. This grants no operation authorization.
    Operator,
}

/// Capacity was unavailable; the caller must use its existing overload/termination path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityDenied;

impl std::fmt::Display for CapacityDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("inbound capacity is unavailable")
    }
}
impl std::error::Error for CapacityDenied {}

#[derive(Debug)]
struct Counts {
    total: Arc<Semaphore>,
    data: Arc<Semaphore>,
    data_limit: usize,
}

/// Construct once at boot; pass the same Arc to every ingress service and retain it on reload.
#[derive(Debug)]
pub struct ProcessAdmission {
    counts: Option<Counts>,
    byte_limit: u32,
    data_byte_limit: u32,
    /// Low word: all bytes. High word: Data bytes. Both change in one transaction.
    bytes: AtomicU64,
}

impl ProcessAdmission {
    /// `max_requests` has already passed configuration's Semaphore::MAX_PERMITS validation.
    /// Zero leaves count unlimited; one admits only Operator requests.
    #[must_use]
    pub fn new(max_requests: usize) -> Arc<Self> {
        Self::build(max_requests, BODY_BYTES, OPERATOR_BODY_BYTES)
    }

    fn build(max_requests: usize, byte_limit: u32, operator_bytes: u32) -> Arc<Self> {
        assert!(byte_limit > 0 && operator_bytes <= byte_limit);
        let counts = (max_requests != 0).then(|| {
            let reserved = (max_requests / 16).clamp(1, 32);
            let data_limit = max_requests - reserved;
            Counts {
                total: Arc::new(Semaphore::new(max_requests)),
                data: Arc::new(Semaphore::new(data_limit)),
                data_limit,
            }
        });
        Arc::new(Self {
            counts,
            byte_limit,
            data_byte_limit: byte_limit - operator_bytes,
            bytes: AtomicU64::new(0),
        })
    }

    /// Small isolated fixture budgets; production uses the fixed policy in `new`.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn with_limits(max_requests: usize, byte_limit: u32, operator_bytes: u32) -> Arc<Self> {
        Self::build(max_requests, byte_limit, operator_bytes)
    }

    /// Retained total and Data payload for deterministic custody tests.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn used(&self) -> (usize, usize) {
        let (total, data) = unpack(self.bytes.load(Ordering::Relaxed));
        (total as usize, data as usize)
    }

    /// Immediate admission for network listeners. Never wait behind another request.
    pub fn try_enter(
        self: &Arc<Self>,
        class: AdmissionClass,
    ) -> Result<RequestLease, CapacityDenied> {
        let mut permits = Permits::default();
        if let Some(counts) = &self.counts {
            if class == AdmissionClass::Data {
                permits.data = Some(
                    Arc::clone(&counts.data)
                        .try_acquire_owned()
                        .map_err(|_| denied("inbound"))?,
                );
            }
            // `permits` owns Data already. Every error/return destroys total before Data.
            permits.total = Some(
                Arc::clone(&counts.total)
                    .try_acquire_owned()
                    .map_err(|_| denied("inbound"))?,
            );
        }
        Ok(self.lease(class, permits))
    }

    /// Cancellable admission for the single stdio read loop. Network callers use try_enter.
    pub async fn enter(
        self: &Arc<Self>,
        class: AdmissionClass,
    ) -> Result<RequestLease, CapacityDenied> {
        let Some(counts) = &self.counts else {
            return Ok(self.lease(class, Permits::default()));
        };
        let data = if class == AdmissionClass::Data {
            if counts.data_limit == 0 {
                return Err(denied("inbound"));
            }
            Some(
                Arc::clone(&counts.data)
                    .acquire_owned()
                    .await
                    .map_err(|_| denied("inbound"))?,
            )
        } else {
            None
        };
        let permits = AcquirePair::new(Arc::clone(&counts.total), data)
            .await
            .map_err(|_| denied("inbound"))?;
        Ok(self.lease(class, permits))
    }

    fn lease(self: &Arc<Self>, class: AdmissionClass, permits: Permits) -> RequestLease {
        RequestLease(Arc::new(LeaseInner {
            _permits: permits,
            budget: Arc::clone(self),
            class,
        }))
    }

    fn reserve(&self, class: AdmissionClass, bytes: usize) -> Result<u32, CapacityDenied> {
        let bytes = u32::try_from(bytes).map_err(|_| CapacityDenied)?;
        self.bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
                let (total, data) = unpack(held);
                if bytes > self.byte_limit - total
                    || (class == AdmissionClass::Data && bytes > self.data_byte_limit - data)
                {
                    return None;
                }
                Some(pack(
                    total + bytes,
                    data + if class == AdmissionClass::Data {
                        bytes
                    } else {
                        0
                    },
                ))
            })
            .map_err(|_| CapacityDenied)?;
        Ok(bytes)
    }

    fn release(&self, class: AdmissionClass, bytes: u32) {
        // Each credit owns exactly this quantity in both words; the low-word subtraction
        // cannot borrow from the high word. One atomic release preserves the class invariant.
        self.bytes.fetch_sub(
            pack(
                bytes,
                if class == AdmissionClass::Data {
                    bytes
                } else {
                    0
                },
            ),
            Ordering::Relaxed,
        );
    }
}

fn pack(total: u32, data: u32) -> u64 {
    u64::from(total) | (u64::from(data) << 32)
}
fn unpack(bytes: u64) -> (u32, u32) {
    (bytes as u32, (bytes >> 32) as u32)
}
fn denied(gate: &'static str) -> CapacityDenied {
    metrics::counter!(crate::snapshot::ADMISSION_DENIED_TOTAL, "gate" => gate).increment(1);
    CapacityDenied
}

#[derive(Default)]
struct Permits {
    // The explicit Drop also enforces this declaration order: total BEFORE covering Data.
    total: Option<OwnedSemaphorePermit>,
    data: Option<OwnedSemaphorePermit>,
    #[cfg(test)]
    after_total: Option<Box<dyn FnOnce() + Send + Sync>>,
}
impl Drop for Permits {
    fn drop(&mut self) {
        drop(self.total.take());
        #[cfg(test)]
        if let Some(observe) = self.after_total.take() {
            observe();
        }
        drop(self.data.take());
    }
}
impl std::fmt::Debug for Permits {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Permits")
            .field("total", &self.total.is_some())
            .field("data", &self.data.is_some())
            .finish()
    }
}

type TotalAcquisition =
    Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>;

struct AcquirePair {
    // Rust drops fields in declaration order. This MUST cancel any assigned-but-unobserved
    // total permit before Permits releases its covering Data permit. The one stdio waiter
    // boxes only this total-acquisition future; the network path never allocates a waiter.
    pending_total: TotalAcquisition,
    permits: Permits,
    #[cfg(test)]
    hold_after_acquire: bool,
}
impl AcquirePair {
    fn new(total: Arc<Semaphore>, data: Option<OwnedSemaphorePermit>) -> Self {
        let mut permits = Permits::default();
        permits.data = data;
        Self {
            pending_total: Box::pin(total.acquire_owned()),
            permits,
            #[cfg(test)]
            hold_after_acquire: false,
        }
    }
}
impl Future for AcquirePair {
    type Output = Result<Permits, AcquireError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.permits.total.is_none() {
            match self.pending_total.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(total)) => self.permits.total = Some(total),
            }
        }
        #[cfg(test)]
        if self.hold_after_acquire {
            return Poll::Pending;
        }
        Poll::Ready(Ok(std::mem::take(&mut self.permits)))
    }
}

#[derive(Debug)]
struct LeaseInner {
    _permits: Permits,
    budget: Arc<ProcessAdmission>,
    class: AdmissionClass,
}

/// Clones share one admission; retain a share in every detached task and retained input owner.
#[derive(Clone, Debug)]
pub struct RequestLease(Arc<LeaseInner>);

impl RequestLease {
    #[must_use]
    pub fn class(&self) -> AdmissionClass {
        self.0.class
    }

    /// Reserve before retaining decoded input or making an independent copy.
    pub fn try_reserve(&self, bytes: usize) -> Result<ByteCredit, CapacityDenied> {
        self.try_reserve_unreported(bytes)
            .map_err(|_| denied("inbound_body_bytes"))
    }

    /// Pure capacity operation for capture beneath registry/serializer guards: no recorder,
    /// logging, allocation or callbacks, including on refusal. The outer admin boundary reports
    /// a capacity refusal once, only after all capture guards have been released.
    pub(crate) fn try_reserve_unreported(
        &self,
        bytes: usize,
    ) -> Result<ByteCredit, CapacityDenied> {
        let bytes = self.0.budget.reserve(self.0.class, bytes)?;
        Ok(ByteCredit {
            bytes,
            request: self.clone(),
        })
    }

    /// Adopt a framer's transient decoded allocation before it is queued or retained.
    pub fn adopt_input(&self, bytes: Vec<u8>) -> Result<OwnedInput, CapacityDenied> {
        let credit = self.try_reserve(bytes.len())?;
        Ok(OwnedInput { bytes, credit })
    }

    /// Charge before making a new independent retained allocation.
    pub fn copy_input(&self, bytes: &[u8]) -> Result<OwnedInput, CapacityDenied> {
        let credit = self.try_reserve(bytes.len())?;
        Ok(OwnedInput {
            bytes: bytes.to_vec(),
            credit,
        })
    }
}

/// Move-only byte reservation. Its request share prevents count retirement before the input.
#[derive(Debug)]
pub struct ByteCredit {
    bytes: u32,
    request: RequestLease,
}
impl ByteCredit {
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes as usize
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes == 0
    }
    #[must_use]
    pub fn request(&self) -> &RequestLease {
        &self.request
    }

    /// Move already charged decoded storage into its owner, for staged and queued handoffs.
    /// A length mismatch discards both the supplied storage and credit; it cannot undercharge.
    pub fn into_input(self, bytes: Vec<u8>) -> Result<OwnedInput, CapacityDenied> {
        let input = OwnedInput {
            bytes,
            credit: self,
        };
        if input.bytes.len() != input.credit.len() {
            return Err(CapacityDenied);
        }
        Ok(input)
    }

    /// Transfer part of this reservation without changing process usage.

    pub fn split(&mut self, bytes: usize) -> Result<Self, CapacityDenied> {
        let bytes = u32::try_from(bytes).map_err(|_| CapacityDenied)?;
        if bytes > self.bytes {
            return Err(CapacityDenied);
        }
        self.bytes -= bytes;
        Ok(Self {
            bytes,
            request: self.request.clone(),
        })
    }

    /// Gather only one request's input. Cross-request merging would retire another count early;
    /// rejection returns that reservation intact to its owner.
    pub fn try_merge(&mut self, mut other: Self) -> Result<(), Self> {
        if !Arc::ptr_eq(&self.request.0, &other.request.0) {
            return Err(other);
        }
        let Some(combined) = self.bytes.checked_add(other.bytes) else {
            return Err(other);
        };
        self.bytes = combined;
        other.bytes = 0;
        Ok(())
    }
}
impl Drop for ByteCredit {
    fn drop(&mut self) {
        self.request
            .0
            .budget
            .release(self.request.0.class, self.bytes);
    }
}

/// Unique ingress storage; bytes drop before their credit. Expose backed Bytes only after gather.
pub struct OwnedInput {
    bytes: Vec<u8>,
    credit: ByteCredit,
}
impl OwnedInput {
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    #[must_use]
    pub fn request(&self) -> &RequestLease {
        self.credit.request()
    }

    /// Incremental read growth reserves before appending. Failure leaves the input unchanged.
    pub fn try_extend_from_slice(&mut self, bytes: &[u8]) -> Result<(), CapacityDenied> {
        let credit = self.request().try_reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        self.credit
            .try_merge(credit)
            .expect("growth reserves on this input's request");
        Ok(())
    }

    /// Discard logical payload before releasing credit; allocator slack is outside this budget.
    pub fn truncate(&mut self, len: usize) {
        if len < self.bytes.len() {
            let removed = self.bytes.len() - len;
            self.bytes.truncate(len);
            drop(
                self.credit
                    .split(removed)
                    .expect("owned storage matches its credit"),
            );
        }
    }
    pub fn clear(&mut self) {
        self.truncate(0);
    }

    /// Synchronous transfer of unique chunks. No source alias may escape this gather.
    pub fn try_append(&mut self, other: Self) -> Result<(), Self> {
        if !Arc::ptr_eq(&self.credit.request.0, &other.credit.request.0) {
            return Err(other);
        }
        let Self { bytes, credit } = other;
        if self.bytes.is_empty() {
            self.bytes = bytes;
        } else {
            self.bytes.extend_from_slice(&bytes);
            drop(bytes);
        }
        self.credit
            .try_merge(credit)
            .expect("gather owns same-request reservations within the process limit");
        Ok(())
    }

    /// Clones/slices share the backing owner; the final one retires input and request custody.
    #[must_use]
    pub fn into_bytes(self) -> bytes::Bytes {
        bytes::Bytes::from_owner(self)
    }

    /// Existing session pump ownership, preserved through stalled crossings and cancellation.
    #[must_use]
    pub fn into_session_input(self) -> crate::plane_driver::SessionInput {
        crate::plane_driver::SessionInput {
            bytes: self.bytes,
            custody: Some(Arc::new(self.credit)),
        }
    }
}
impl AsRef<[u8]> for OwnedInput {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
impl std::fmt::Debug for OwnedInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedInput")
            .field("len", &self.len())
            .field("class", &self.request().class())
            .finish()
    }
}

#[cfg(test)]
#[path = "tests/process_admission_tests.rs"]
mod tests;
