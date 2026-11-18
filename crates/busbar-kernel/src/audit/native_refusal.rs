// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pre-allocation DATA refusal custody on the existing native audit queue.

use super::*;
use crate::auth::native_data::DataRefused;
use crate::inbound::native::{PhysicalRefusal, RouteTarget};

/// Retains the physical owner and its one frozen original before and after queue acceptance.
/// Dropping a confirmation future never removes or replaces that operation.
pub struct NativeRefusalAudit {
    refusal: PhysicalRefusal,
    native: Arc<NativeAudit>,
    confirmed: Arc<AtomicBool>,
    // The one already-framed original remains here until the existing queue accepts it.
    pending: Mutex<Option<PendingAudit>>,
}

/// Every failure returns its real original owner. Only NotQueued has a frozen operation that
/// can be retried; Unprepared remains an explicit incomplete disposition in its supervisor.
pub enum NativeRefusalError {
    Unprepared {
        refusal: PhysicalRefusal,
        error: RecordStoreError,
    },
    NotQueued {
        audit: NativeRefusalAudit,
        error: RecordStoreError,
    },
}

impl NativeRefusalAudit {
    pub fn binding(&self) -> &Arc<crate::inbound::native::RequestBinding> {
        self.refusal.binding()
    }

    /// Confirmation of this exact queued original, independent of output cancellation.
    /// Carrier/task retirement remains a separate obligation.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed.load(Ordering::Acquire)
    }

    /// On existing queue progress, transfer any still-held original and observe its confirmation.
    /// Store work remains with the existing queue driver; no new retry owner is created.
    pub async fn wait_original_confirmation(&self) {
        wait_confirmation(&AUDIT_LOG, &self.confirmed, || self.transfer_original()).await;
    }

    fn transfer_original(&self) -> RecordStoreResult<()> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        transfer_original(&PENDING_AUDIT, &mut pending)
    }

    /// Retry custody transfer and the existing queue with the same frozen logical operation.
    pub async fn confirm(&self) -> RecordStoreResult<()> {
        self.transfer_original()?;
        if !self.confirmed.load(Ordering::Acquire) {
            drain_native(&PENDING_AUDIT, &AUDIT_LOG, self.native.clone()).await?;
        }
        if !self.confirmed.load(Ordering::Acquire) {
            return Err(RecordStoreError(
                "native refusal original remains unconfirmed".into(),
            ));
        }
        self.refusal
            .check_output_live()
            .map_err(|_| RecordStoreError("native refusal output is no longer live".into()))
    }
}

pub(super) async fn wait_confirmation(
    log: &PlaneAuditLog,
    confirmed: &AtomicBool,
    mut transfer: impl FnMut() -> RecordStoreResult<()>,
) {
    loop {
        let notified = log.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        // Capacity refusal is known no-effect and retains the same pending owner. A real
        // queue confirmation wakes this existing observer when capacity can be retried.
        let _ = transfer();
        if confirmed.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

pub(super) fn transfer_original(
    queue: &PendingAuditQueue,
    held: &mut Option<PendingAudit>,
) -> RecordStoreResult<()> {
    let Some(original) = held.take() else {
        return Ok(());
    };
    match queue.try_enqueue_original(original) {
        Ok(()) => Ok(()),
        Err(refused) => {
            let (original, error) = *refused;
            *held = Some(original);
            Err(error)
        }
    }
}

/// Consume one actual pre-allocation denial. Capacity refusal returns the already-framed
/// operation in NotQueued; retry transfers it intact and never revisits the spent guard latch.
/// No unit, principal, current App, execution admission or HTTP status is fabricated here.
pub fn record_native_refusal(
    mut refusal: PhysicalRefusal,
) -> Result<NativeRefusalAudit, NativeRefusalError> {
    let (native, row) = match prepare_refusal(&refusal) {
        Ok(prepared) => prepared,
        Err(error) => return Err(NativeRefusalError::Unprepared { refusal, error }),
    };
    let confirmed = Arc::new(AtomicBool::new(false));
    let mut operation = [0; 16];
    if let Err(error) = busbar_contract::crypto::fill(&mut operation) {
        return Err(NativeRefusalError::Unprepared {
            refusal,
            error: RecordStoreError::from(format!("native refusal entropy: {error}")),
        });
    }
    let pending = PendingAudit {
        scope: ADMIN_LOG.into(),
        suffix: row_suffix(crate::store::now(), &row),
        origin: EventOrigin::Mutation,
        operation,
        prepared: None,
        confirmation: Some(confirmed.clone()),
    };
    if refusal.claim_preunit_audit().is_err() {
        return Err(NativeRefusalError::Unprepared {
            refusal,
            error: RecordStoreError(
                "native refusal audit ownership is already spent or unavailable".into(),
            ),
        });
    }
    let audit = NativeRefusalAudit {
        refusal,
        native,
        confirmed,
        pending: Mutex::new(Some(pending)),
    };
    match audit.transfer_original() {
        Ok(()) => Ok(audit),
        Err(error) => Err(NativeRefusalError::NotQueued { audit, error }),
    }
}

fn prepare_refusal(
    refusal: &PhysicalRefusal,
) -> RecordStoreResult<(Arc<NativeAudit>, AuditRowInput)> {
    refusal
        .check_output_live()
        .map_err(|_| RecordStoreError("native refusal output is not live".into()))?;
    let decision = refusal
        .preunit_data_reason()
        .ok_or_else(|| RecordStoreError("not a pre-allocation DATA refusal".into()))?;
    let reason = match decision {
        DataRefused::Credential => "credential",
        DataRefused::Policy => "policy",
        DataRefused::Replay => "replay",
        _ => {
            return Err(RecordStoreError(
                "native refusal is not an expected known denial".into(),
            ))
        }
    };
    let binding = refusal.binding();
    let RouteTarget::Plane(target) = binding.route().target() else {
        return Err(RecordStoreError(
            "native refusal has no selected DATA claimant".into(),
        ));
    };
    let generation = binding
        .app()
        .prepared_generation()
        .ok_or_else(|| RecordStoreError("native refusal generation is not prepared".into()))?;
    let store = binding
        .app()
        .governance
        .as_ref()
        .ok_or_else(|| RecordStoreError("native refusal has no governance attachment".into()))?
        .core_store_handle()
        .map_err(|error| RecordStoreError::from(error.to_string()))?;
    let native = native_owner(KIND_ID_AUDIT)
        .ok_or_else(|| RecordStoreError("native refusal audit is not installed".into()))?;
    validate_attachment(&native, &store)?;
    let route = &binding.route().line().route;
    let data = sonic_rs::json!({
        "reason": reason,
        "slot": binding.slot(),
        "route": route.path,
        "route_rung": route.rung,
        "invocation_id": binding.invocation().request_id().get(),
    });
    let data = sonic_rs::to_string(&data)
        .map_err(|_| RecordStoreError("native refusal facts could not be encoded".into()))?;
    let row = AuditRowInput {
        action: "request.refused".into(),
        resource: route.path.clone(),
        outcome: busbar_contract::vocab::OUTCOME_REJECTED.into(),
        principal: String::new(),
        request_id: Some(binding.invocation().request_id().get().to_string()),
        config_generation: Some(generation.to_string()),
        kind: Some("plane".into()),
        instance: Some(target.caller().namespace().to_string()),
        severity: "warning".into(),
        data: AuditData::from_json(&data)
            .map_err(|_| RecordStoreError("native refusal facts are not an object".into()))?,
        ..AuditRowInput::default()
    };
    Ok((native, row))
}

pub(super) fn validate_attachment(
    native: &NativeAudit,
    store: &Arc<CoreStore>,
) -> RecordStoreResult<()> {
    if !Arc::ptr_eq(&native.storage.store, store) || !native.storage.ready.load(Ordering::Acquire) {
        return Err(RecordStoreError(
            "native refusal audit attachment is foreign or unready".into(),
        ));
    }
    Ok(())
}
