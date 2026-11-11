// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-owned custody for common raw measurements. This is not a plugin service and does not
//! grant observation, persistence, principal selection, or pricing authority to any plugin kind.

use std::any::Any;
use std::cell::RefCell;
use std::future::Future;
use std::sync::{Arc, OnceLock};

use busbar_contract::abi::measurement::{MeasurementBatch, UnitCount};
use busbar_contract::abi::mechanism::rendering::ReadMeasurementClass;
use busbar_contract::conn::InstanceId;

/// Opaque host attribution. The authority must reject unknown concrete types; absence explicitly
/// denotes a system call, never permission to infer an arbitrary user.
pub type Context = Arc<dyn Any + Send + Sync>;

/// Immutable admission facts copied from the authenticated Statement and host binding.
#[derive(Clone, Debug)]
pub struct Binding {
    pub caller: busbar_contract::services::Caller,
    pub instance: InstanceId,
    pub statement_digest: [u8; 32],
    pub classes: Arc<[ReadMeasurementClass]>,
}

/// Owned data, copied before another callback or lease release can invalidate the envelope.
#[derive(Clone, Debug)]
pub struct CapturedBatch {
    pub revision: u64,
    pub counts: Vec<UnitCount>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Unavailable,
    Conflict,
    Malformed,
}

/// Kernel implementation reserves bounded custody before plugin work begins.
pub trait Authority: Send + Sync {
    /// Validate immutable configuration coverage at bind, including empty declarations.
    /// This performs no storage IO and may run under the dispatcher's adoption lock.
    fn admit(&self, _binding: &Binding) -> Result<(), Refusal> {
        Ok(())
    }
    fn reserve(
        &self,
        binding: &Binding,
        context: Option<&Context>,
        slot: u32,
    ) -> Result<Arc<dyn Operation>, Refusal>;
}

/// One host operation, retained across PENDING, SHORT, cancellation and failure. Implementations
/// own operation identity, cumulative deduplication/conflict checks, and durable recovery.
pub trait Operation: Send + Sync {
    fn revision(&self) -> u64;
    /// Only the host authority may issue this zero-cursor, empty-envelope maintenance mode.
    fn is_maintenance(&self) -> bool {
        false
    }
    /// Bounded memory custody only: no storage calls, blocking, or unreserved allocation.
    fn capture(&self, batch: CapturedBatch) -> Result<(), Refusal>;
    /// Invocation capacity is released. Schedule persistence without blocking the dispatcher;
    /// this may run under its queue lock. `terminal` is false for a capacity release, true
    /// when the last loader owner ends or abandons the operation. Both are idempotent.
    fn released(&self, terminal: bool);
}

pub(crate) type AuthoritySlot = Arc<OnceLock<Arc<dyn Authority>>>;

#[derive(Clone)]
pub(crate) struct Reservation {
    pub(crate) instance: InstanceId,
    operation: Arc<Owner>,
    revision: u64,
    context: Option<Context>,
}
struct Owner(Arc<dyn Operation>);
impl Drop for Owner {
    fn drop(&mut self) {
        self.0.released(true);
    }
}
impl Reservation {
    pub(crate) fn context(&self) -> Option<Context> {
        self.context.clone()
    }
    pub(crate) fn refreshed(&self) -> Self {
        Self {
            revision: self.operation.0.revision(),
            ..self.clone()
        }
    }
    pub(crate) fn may_invoke(&self) -> bool {
        self.revision != 0 || self.operation.0.is_maintenance()
    }
    pub(crate) fn released(&self) {
        self.operation.0.released(false);
    }
    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }
}
impl std::fmt::Debug for Reservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reservation")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

thread_local! {
    static CONTEXT: RefCell<Option<Option<Context>>> = const { RefCell::new(None) };
    static ACTIVE: RefCell<Option<Reservation>> = const { RefCell::new(None) };
}
tokio::task_local! {
    static TASK_CONTEXT: Option<Context>;
}

pub(crate) fn current_context() -> Option<Context> {
    CONTEXT
        .with(|context| context.borrow().clone())
        .unwrap_or_else(|| TASK_CONTEXT.try_with(Clone::clone).ok().flatten())
}

/// Scope an actual asynchronous operation, including every poll and its dispatcher submissions.
/// Constructing a future inside `with_context` does not scope its subsequent execution.
pub async fn scope<F: Future>(context: Option<Context>, future: F) -> F::Output {
    TASK_CONTEXT.scope(context, future).await
}

/// Scope synchronous host submissions. Async callers should use [`scope`].
pub fn with_context<R>(context: Option<Context>, run: impl FnOnce() -> R) -> R {
    struct Restore(Option<Option<Context>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CONTEXT.with(|context| {
                context.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(CONTEXT.with(|current| current.replace(Some(context))));
    run()
}

pub(crate) fn active(instance: InstanceId) -> Option<Reservation> {
    ACTIVE.with(|current| {
        current
            .borrow()
            .as_ref()
            .filter(|r| r.instance == instance)
            .cloned()
    })
}

pub(crate) fn with_reservation<R>(reservation: Option<Reservation>, run: impl FnOnce() -> R) -> R {
    struct Restore(Option<Reservation>);
    impl Drop for Restore {
        fn drop(&mut self) {
            ACTIVE.with(|active| {
                active.replace(self.0.take());
            });
        }
    }
    let _restore = Restore(ACTIVE.with(|active| active.replace(reservation)));
    run()
}

pub(crate) fn reserve(
    binding: &Binding,
    authority: &AuthoritySlot,
    context: Option<&Context>,
    slot: u32,
) -> Result<Option<Reservation>, Refusal> {
    if binding.classes.is_empty() {
        return Ok(None);
    }
    let operation = authority
        .get()
        .ok_or(Refusal::Unavailable)?
        .reserve(binding, context, slot)?;
    let reservation = Reservation {
        revision: operation.revision(),
        context: context.cloned(),
        instance: binding.instance,
        operation: Arc::new(Owner(operation)),
    };
    if !reservation.may_invoke() {
        return Err(Refusal::Malformed);
    }
    Ok(Some(reservation))
}

/// # Safety
/// The batch points at the current callback's live envelope storage.
pub(crate) unsafe fn capture(binding: &Binding, batch: &MeasurementBatch) -> Result<(), Refusal> {
    let active = active(binding.instance);
    let expected = active.as_ref().map_or(0, Reservation::revision);
    // SAFETY: the contract checker validates count, alignment and NULL before reading entries.
    unsafe {
        busbar_contract::abi::measurement::check_batch(batch, binding.classes.len(), expected)
    }
    .map_err(|_| Refusal::Malformed)?;
    if batch.revision == 0 {
        return Ok(());
    }
    let operation = active.ok_or(Refusal::Unavailable)?;
    let counts = if batch.counts_len == 0 {
        Vec::new()
    } else {
        // SAFETY: check_batch bounded the live array and checked each exact count.
        unsafe { std::slice::from_raw_parts(batch.counts, batch.counts_len) }.to_vec()
    };
    operation.operation.0.capture(CapturedBatch {
        revision: batch.revision,
        counts,
    })
}

#[cfg(test)]
#[path = "measurement_tests.rs"]
mod tests;
