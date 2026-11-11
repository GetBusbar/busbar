// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One shutdown tail for listener and line-serving modes. Request and audit
//! producers stop before this tail; every retained semantic owner drains before
//! journal staging closes and the native writer can retire.

use std::sync::{Arc, Mutex};

use busbar_kernel::governance::GovState;
use busbar_kernel::persistence::journal::runtime::RuntimeJournal;

use crate::root::durability::Durability;
use crate::root::serve::{drain_records, LateServices, RECORD_DRAIN};

/// Obtained only by a successful semantic drain and consumed by retirement.
/// Retaining the actual owners binds the final check to the drained generation.
pub struct Drained {
    governance: Option<Arc<GovState>>,
    runtime: Option<Arc<RuntimeJournal>>,
}

pub async fn tail_after_flusher(
    governance: Option<Arc<GovState>>,
    late: &LateServices,
    journal: Option<&Arc<Mutex<Durability>>>,
    shutdown: &tokio::sync::broadcast::Sender<()>,
    flusher: Option<tokio::task::JoinHandle<()>>,
) -> Result<Drained, String> {
    let _ = shutdown.send(());
    let flusher_failure = match flusher {
        Some(flusher) => flusher
            .await
            .err()
            .map(|error| format!("background accounting flusher did not complete: {error}")),
        None => None,
    };
    // Still drive all remaining owners after a failed periodic task. Their exact
    // candidates survive that task's cancellation or panic.
    let drained = tail(governance, late, journal).await;
    match (flusher_failure, drained) {
        (None, result) => result,
        (Some(error), Ok(_)) => Err(error),
        (Some(error), Err(drain)) => Err(format!("{error}; {drain}")),
    }
}

pub async fn tail(
    governance: Option<Arc<GovState>>,
    late: &LateServices,
    journal: Option<&Arc<Mutex<Durability>>>,
) -> Result<Drained, String> {
    let mut failures = Vec::new();
    if let Some(cards) = crate::root::kernel::ROOT_CARD.card_store() {
        if let Err(error) = cards.stop_background().await {
            failures.push(format!("price publisher did not stop: {error}"));
        }
    }
    let cleanup_started = std::time::Instant::now();
    if let Some(kernel) = late.kernel() {
        if !kernel.drain_plane_cleanup(RECORD_DRAIN).await {
            failures.push("plane cancellations remain pending".to_string());
        }
    }

    if let Some(gov) = &governance {
        // A failed driver must release its retained ownership and let independent
        // owners drain. Tokio task failure remains an explicit shutdown failure.
        let checkpoint_owner = gov.clone();
        match tokio::spawn(super::measurements::maintenance(async move {
            checkpoint_owner.flush_unit_checkpoints().await
        }))
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.push(format!("unit checkpoints remain unresolved: {error}")),
            Err(error) => failures.push(format!("unit checkpoint driver failed: {error}")),
        }
        let budget_owner = gov.clone();
        match tokio::spawn(super::measurements::maintenance(async move {
            budget_owner.flush_budgets_final().await
        }))
        .await
        {
            Ok(flushed) => tracing::info!(flushed, "budget shutdown flush completed"),
            Err(error) => failures.push(format!("budget final driver failed: {error}")),
        }
        let metering_owner = gov.clone();
        match tokio::spawn(super::measurements::maintenance(async move {
            metering_owner.flush_metering_final().await
        }))
        .await
        {
            Ok(flushed) => tracing::info!(flushed, "metering shutdown flush completed"),
            Err(error) => failures.push(format!("metering final driver failed: {error}")),
        }
    }

    let record_remaining = RECORD_DRAIN.saturating_sub(cleanup_started.elapsed());
    if !drain_records(late, record_remaining).await {
        failures.push("plane record writes remain queued".into());
    }
    if let Err(error) = drain_audit_queue().await {
        failures.push(error);
    }

    let runtime = journal.map(|book| {
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .runtime_journal()
    });
    if let Some(runtime) = &runtime {
        // Close the reservation lane atomically only after producers and their
        // audit queues drain. Existing originals remain confirmable and replayable.
        if let Err(error) = runtime.stop_staging() {
            failures.push(format!("journal staging did not close: {error:?}"));
        }
        let journal_owner = runtime.clone();
        let mut flush = tokio::spawn(async move { journal_owner.flush().await });
        match tokio::time::timeout(RECORD_DRAIN, &mut flush).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) => {
                failures.push(format!("journal originals remain unresolved: {error:?}"))
            }
            Ok(Err(error)) => failures.push(format!("journal final driver failed: {error}")),
            Err(_) => {
                flush.abort();
                let _ = flush.await;
                failures
                    .push("journal flush deadline reached; exact originals remain retained".into());
            }
        }
        if runtime.pending_records() != 0 {
            failures.push("native journal still owns unpublished originals".into());
        }
    }
    // A late audit producer must leave a visible failure after journal closure,
    // rather than turning a successful earlier queue snapshot into a clean exit.
    if let Err(error) = drain_audit_queue().await {
        failures.push(format!("final audit drain: {error}"));
    }
    if busbar_kernel::audit::auditlog::has_unsettled_audit() {
        failures.push("administrative audit still owns queued or active originals".into());
    }
    if governance
        .as_ref()
        .is_some_and(|gov| gov.has_unsettled_persistence())
    {
        failures.push("governance still owns unsettled persistence".into());
    }
    if failures.is_empty() {
        Ok(Drained {
            governance,
            runtime,
        })
    } else {
        Err(failures.join("; "))
    }
}

async fn drain_audit_queue() -> Result<(), String> {
    if !busbar_kernel::audit::auditlog::has_unsettled_audit() {
        return Ok(());
    }
    match tokio::spawn(busbar_kernel::audit::auditlog::flush_pending()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!(
            "administrative audit originals remain unresolved: {error}"
        )),
        Err(error) => Err(format!("administrative audit driver failed: {error}")),
    }
}

/// Native retirement requires the successful drain result from this same book.
/// The startup owner additionally refuses retirement while CoreStore retains any
/// uncertain physical attempt, including attempts owned outside governance.
pub async fn retire_storage(
    startup: &mut busbar_kernel::persistence::startup::Startup,
    book: Option<&crate::root::durability::NodeBook>,
    drained: Drained,
) -> Result<(), String> {
    use busbar_kernel::persistence::startup::Progress;
    let core = startup
        .store()
        .ok_or("Store was not admitted for retirement")?;
    if let Some(gov) = &drained.governance {
        if !Arc::ptr_eq(
            &core,
            &gov.core_store_handle().map_err(|error| error.to_string())?,
        ) {
            return Err("shutdown drain belongs to another governance Store".into());
        }
        if gov.has_unsettled_persistence() {
            return Err("governance acquired unsettled persistence after its final drain".into());
        }
    }
    match (book, &drained.runtime) {
        (Some(book), Some(runtime)) if Arc::ptr_eq(&book.runtime_journal, runtime) => {
            if !runtime.is_bound_to(&core) {
                return Err("shutdown journal belongs to another Store".into());
            }
            if runtime.pending_records() != 0 {
                return Err(
                    "native journal still owns unpublished originals; writer was not retired"
                        .into(),
                );
            }
            if let Some(lease) = &book.node_lease {
                lease.release().await?;
            }
        }
        (None, None) => {}
        _ => return Err("shutdown drain belongs to another journal generation".into()),
    }
    if busbar_kernel::audit::auditlog::has_unsettled_audit() {
        return Err("administrative audit acquired originals after its final drain".into());
    }
    startup
        .begin_retirement()
        .map_err(|error| format!("Store writer retirement refused: {error:?}"))?;
    loop {
        match startup
            .advance()
            .await
            .map_err(|error| format!("Store writer retirement: {error:?}"))?
        {
            Progress::Advanced => {}
            Progress::Retired => return Ok(()),
            _ => return Err("Store writer retirement remains unconfirmed".into()),
        }
    }
}

#[cfg(test)]
#[path = "tests/shutdown.rs"]
mod tests;
