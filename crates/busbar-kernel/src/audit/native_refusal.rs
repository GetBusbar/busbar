// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pre-allocation DATA refusal custody on the existing native audit queue.

use super::*;
use crate::auth::native_data::DataRefused;
use crate::inbound::native::{PhysicalRefusal, RouteTarget};

/// Retains the actual physical owner and the observer of its one queued original.
/// Dropping a confirmation future never removes or replaces that queued operation.
pub struct NativeRefusalAudit {
    refusal: PhysicalRefusal,
    native: Arc<NativeAudit>,
    confirmed: Arc<AtomicBool>,
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

    /// Observe the existing queue's actual progress without creating another retry owner.
    pub async fn wait_original_confirmation(&self) {
        wait_confirmation(&AUDIT_LOG, &self.confirmed).await;
    }

    /// Retry the existing queue with its original attachment. This never enqueues a new row.
    pub async fn confirm(&self) -> RecordStoreResult<()> {
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

    /// Transfer the original guard only after this exact queued event was confirmed.
    /// On uncertainty or cancellation, ownership remains in the returned error.
    pub fn take_confirmed(self) -> Result<PhysicalRefusal, Self> {
        if !self.confirmed.load(Ordering::Acquire) || self.refusal.check_output_live().is_err() {
            return Err(self);
        }
        Ok(self.refusal)
    }
}

pub(super) async fn wait_confirmation(log: &PlaneAuditLog, confirmed: &AtomicBool) {
    loop {
        let notified = log.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if confirmed.load(Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

/// Consume one actual pre-allocation denial. Errors retain its original physical owner;
/// once queue admission is attempted, its audit latch stays spent even on refusal.
/// No unit, principal, current App, execution admission or HTTP status is fabricated here.
pub fn record_native_refusal(
    mut refusal: PhysicalRefusal,
) -> Result<NativeRefusalAudit, (PhysicalRefusal, RecordStoreError)> {
    let prepared = prepare_refusal(&refusal);
    let (native, row) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => return Err((refusal, error)),
    };
    let confirmed = Arc::new(AtomicBool::new(false));
    let mut operation = [0; 16];
    if let Err(error) = busbar_contract::crypto::fill(&mut operation) {
        return Err((
            refusal,
            RecordStoreError(format!("native refusal entropy: {error}")),
        ));
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
        return Err((
            refusal,
            RecordStoreError(
                "native refusal audit ownership is already spent or unavailable".into(),
            ),
        ));
    }
    if let Err(error) = PENDING_AUDIT.try_enqueue_background(pending) {
        return Err((refusal, error));
    }
    Ok(NativeRefusalAudit {
        refusal,
        native,
        confirmed,
    })
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
        .map_err(|error| RecordStoreError(error.to_string()))?;
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
