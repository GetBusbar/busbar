// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::recovery::{
    RecoveryChild, RecoveryError, RecoveryEvent, RecoveryKind, RecoveryOrigin, RecoveryResolution,
    RecoveryState, RecoveryVerdict,
};
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct UsageCustody {
    pub(super) bucket: String,
    pub(super) window: u64,
    pub(super) plain: ExactUsageDelta,
    pub(super) dated: ExactUsageDelta,
    pub(super) chunk_plain: UsageDelta,
    pub(super) chunk_dated: UsageDelta,
    #[serde(default)]
    pub(super) absorbed_plain: ExactUsageDelta,
    #[serde(default)]
    pub(super) absorbed_dated: ExactUsageDelta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) origin: Option<RecoveryOrigin>,
    #[serde(default)]
    pub(super) handoffs: Vec<RecoveryChild>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) verdict: Option<RawVerdict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MeteringCustody {
    delta: MeteringDelta,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<RecoveryOrigin>,
    #[serde(default)]
    handoffs: Vec<RecoveryChild>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verdict: Option<RawVerdict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawVerdict {
    landed: bool,
    expected_revision: u64,
    actor: String,
    reason: String,
}

#[derive(Deserialize)]
struct Links {
    #[serde(default)]
    origin: Option<RecoveryOrigin>,
    #[serde(default)]
    handoffs: Vec<RecoveryChild>,
}

fn invalid(error: impl std::fmt::Display) -> RecordStoreError {
    RecordStoreError(format!("invalid raw recovery custody: {error}"))
}
fn encode<T: Serialize>(value: &T) -> RecordStoreResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(invalid)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> RecordStoreResult<T> {
    serde_json::from_slice(bytes).map_err(invalid)
}
fn fingerprint<T: Serialize>(kind: &[u8], value: &T) -> RecordStoreResult<[u8; 32]> {
    use sha2::Digest;
    let mut digest = sha2::Sha256::new();
    digest.update(kind);
    digest.update(encode(value)?);
    Ok(digest.finalize().into())
}
fn usage_fingerprint(custody: &UsageCustody) -> RecordStoreResult<[u8; 32]> {
    fingerprint(
        b"busbar.usage-recovery.body.v1\0",
        &(
            &custody.bucket,
            custody.window,
            &custody.chunk_plain,
            &custody.chunk_dated,
        ),
    )
}

impl GovState {
    pub(super) fn usage_recovery_child(
        bucket: &str,
        window: u64,
        plain: ExactUsageDelta,
        dated: ExactUsageDelta,
    ) -> RecordStoreResult<Option<RecoveryChild>> {
        if plain.is_zero() && dated.is_zero() {
            return Ok(None);
        }
        let custody = UsageCustody {
            bucket: bucket.into(),
            window,
            chunk_plain: plain.chunk(),
            chunk_dated: dated.chunk(),
            plain,
            dated,
            absorbed_plain: ExactUsageDelta::default(),
            absorbed_dated: ExactUsageDelta::default(),
            origin: None,
            handoffs: Vec::new(),
            verdict: None,
        };
        Ok(Some(RecoveryChild {
            operation_id: crate::door::op_id().0,
            kind: RecoveryKind::Usage,
            body_fingerprint: usage_fingerprint(&custody)?,
            first_sent_at_ms: Some(crate::store::now_ms()),
            payload: encode(&custody)?,
        }))
    }

    pub(super) fn metering_recovery_intent(
        &self,
        operation_id: [u8; 16],
        first_sent_at_ms: u64,
        delta: &MeteringDelta,
    ) -> RecordStoreResult<RecoveryEvent> {
        let custody = MeteringCustody {
            delta: delta.clone(),
            origin: None,
            handoffs: Vec::new(),
            verdict: None,
        };
        self.new_recovery_event(
            operation_id,
            RecoveryKind::Metering,
            fingerprint(b"busbar.metering-recovery.body.v1\0", delta)?,
            RecoveryState::Intent,
            Some(first_sent_at_ms),
            encode(&custody)?,
        )
        .map_err(invalid)
    }

    pub(super) fn validate_recovery_origin(&self, event: &RecoveryEvent) -> RecordStoreResult<()> {
        let links: Links = decode(&event.payload)?;
        let Some(origin) = links.origin else {
            return Ok(());
        };
        let parent = self
            .recovery_ancestor(origin.operation_id, origin.event_fingerprint)
            .ok_or_else(|| invalid("child origin is not in a selected predecessor chain"))?;
        let parent_links: Links = decode(&parent.payload)?;
        let descriptor = parent_links
            .handoffs
            .iter()
            .find(|child| child.operation_id == event.operation_id)
            .ok_or_else(|| invalid("selected parent does not authorize this child"))?;
        if descriptor.kind != event.kind
            || descriptor.body_fingerprint != event.body_fingerprint
            || descriptor.first_sent_at_ms != event.first_sent_at_ms
        {
            return Err(invalid("child identity differs from selected parent"));
        }
        // Later child checkpoints legitimately change raw custody. Compare the
        // original Intent against the exact parent template, never the latest tip.
        let initial = self
            .recovery_initial_event(event.operation_id)
            .unwrap_or_else(|| event.clone());
        let mut actual: serde_json::Value = decode(&initial.payload)?;
        actual
            .as_object_mut()
            .ok_or_else(|| invalid("child payload is not an object"))?
            .remove("origin");
        let mut expected: serde_json::Value = decode(&descriptor.payload)?;
        expected
            .as_object_mut()
            .ok_or_else(|| invalid("child template is not an object"))?
            .remove("origin");
        if actual != expected {
            return Err(invalid(
                "child raw body differs from selected parent template",
            ));
        }
        Ok(())
    }

    /// Select missing child Intents only after their exact parent checkpoint is
    /// confirmed. This also reconstructs the crash cut between parent and child.
    pub(super) fn drive_recovery_children(&self, parent: &RecoveryEvent) -> RecordStoreResult<()> {
        if self
            .recovery_ancestor(parent.operation_id, parent.fingerprint().map_err(invalid)?)
            .is_none()
        {
            return Err(invalid("unselected parent cannot authorize a child"));
        }
        let links: Links = decode(&parent.payload)?;
        for child in links.handoffs {
            if child.operation_id == parent.operation_id {
                return Err(invalid("recovery child reuses parent operation identity"));
            }
            if let Some(selected) = self.recovery_event(child.operation_id) {
                self.validate_recovery_origin(&selected)?;
                let initial = self
                    .recovery_initial_event(child.operation_id)
                    .ok_or_else(|| invalid("child lacks selected Intent"))?;
                let initial_links: Links = decode(&initial.payload)?;
                if initial_links
                    .origin
                    .as_ref()
                    .map(|origin| origin.operation_id)
                    != Some(parent.operation_id)
                    || initial.kind != child.kind
                    || initial.body_fingerprint != child.body_fingerprint
                    || initial.first_sent_at_ms != child.first_sent_at_ms
                {
                    return Err(invalid("child identity already belongs to another handoff"));
                }
                let mut actual: serde_json::Value = decode(&initial.payload)?;
                actual
                    .as_object_mut()
                    .ok_or_else(|| invalid("child payload is not an object"))?
                    .remove("origin");
                let mut expected: serde_json::Value = decode(&child.payload)?;
                expected
                    .as_object_mut()
                    .ok_or_else(|| invalid("child template is not an object"))?
                    .remove("origin");
                if actual != expected {
                    return Err(invalid("child differs from retained parent descriptor"));
                }
                continue;
            }
            let mut payload: serde_json::Value = decode(&child.payload)?;
            payload
                .as_object_mut()
                .ok_or_else(|| invalid("child template is not an object"))?
                .insert(
                    "origin".into(),
                    serde_json::to_value(RecoveryOrigin {
                        operation_id: parent.operation_id,
                        event_fingerprint: parent.fingerprint().map_err(invalid)?,
                    })
                    .map_err(invalid)?,
                );
            let event = self
                .new_recovery_event(
                    child.operation_id,
                    child.kind,
                    child.body_fingerprint,
                    RecoveryState::Intent,
                    child.first_sent_at_ms,
                    encode(&payload)?,
                )
                .map_err(invalid)?;
            self.keep_recovery_event(&event)?;
            self.validate_recovery_origin(&event)?;
            match event.kind {
                RecoveryKind::Correction => self.restore_correction_recovery(&event)?,
                RecoveryKind::Usage | RecoveryKind::Metering => {
                    self.restore_raw_recovery(&event)?
                }
            }
        }
        Ok(())
    }

    pub(super) fn restore_raw_recovery(&self, event: &RecoveryEvent) -> RecordStoreResult<()> {
        match event.kind {
            RecoveryKind::Usage => {
                let custody: UsageCustody = decode(&event.payload)?;
                if usage_fingerprint(&custody)? != event.body_fingerprint {
                    return Err(invalid("usage original fingerprint differs"));
                }
            }
            RecoveryKind::Metering => {
                let custody: MeteringCustody = decode(&event.payload)?;
                if fingerprint(b"busbar.metering-recovery.body.v1\0", &custody.delta)?
                    != event.body_fingerprint
                {
                    return Err(invalid("metering original fingerprint differs"));
                }
            }
            RecoveryKind::Correction => return Err(invalid("incorrect raw recovery kind")),
        }
        Ok(())
    }

    pub(super) fn resume_raw_recovery(&self) -> RecordStoreResult<()> {
        loop {
            let before: Vec<_> = self
                .selected_recovery_events()
                .iter()
                .map(|event| (event.operation_id, event.revision))
                .collect();
            for event in self.selected_recovery_events() {
                if event.kind != RecoveryKind::Correction && event.state != RecoveryState::Settled {
                    self.drive_raw_recovery(event.operation_id)?;
                }
            }
            let after: Vec<_> = self
                .selected_recovery_events()
                .iter()
                .map(|event| (event.operation_id, event.revision))
                .collect();
            if before == after {
                return Ok(());
            }
        }
    }

    pub(super) fn drive_raw_recovery(&self, operation_id: [u8; 16]) -> RecordStoreResult<()> {
        self.confirm_pending_recovery(operation_id)?;
        let runner = self.recovery_driver(operation_id)?;
        let _running = runner.enter(false).map_err(invalid)?;
        let mut event = self
            .recovery_event(operation_id)
            .ok_or_else(|| invalid("raw operation is not selected"))?;
        self.validate_recovery_origin(&event)?;
        self.restore_raw_recovery(&event)?;
        if event.state == RecoveryState::Intent {
            if self.recovery_retention_expired(event.operation_id) != Some(false) {
                let next = self
                    .new_recovery_event(
                        event.operation_id,
                        event.kind,
                        event.body_fingerprint,
                        RecoveryState::LandedUnknown,
                        event.first_sent_at_ms,
                        self.expired_raw_payload(&event)?,
                    )
                    .map_err(invalid)?;
                self.keep_recovery_event(&next)?;
                self.drive_recovery_children(&next)?;
                return Ok(());
            }
            match event.kind {
                RecoveryKind::Usage => {
                    let custody: UsageCustody = decode(&event.payload)?;
                    let era_bucket = era_bucket(&custody.bucket);
                    let mut cells = Vec::new();
                    if !custody.chunk_plain.is_zero() {
                        cells.push((custody.bucket.as_str(), custody.window, custody.chunk_plain));
                    }
                    if !custody.chunk_dated.is_zero() {
                        cells.push((era_bucket.as_str(), custody.window, custody.chunk_dated));
                    }
                    self.store.add_usage_batch_deduped(
                        busbar_contract::abi::store::OpId(operation_id),
                        &cells,
                    )?;
                }
                RecoveryKind::Metering => {
                    let custody: MeteringCustody = decode(&event.payload)?;
                    self.store.add_metering_batch_deduped(
                        busbar_contract::abi::store::OpId(operation_id),
                        &[custody.delta],
                    )?;
                }
                RecoveryKind::Correction => return Err(invalid("incorrect raw driver kind")),
            }
            let payload = self.applied_raw_payload(&event)?;
            let next = self
                .new_recovery_event(
                    event.operation_id,
                    event.kind,
                    event.body_fingerprint,
                    RecoveryState::Applied,
                    event.first_sent_at_ms,
                    payload,
                )
                .map_err(invalid)?;
            self.keep_recovery_event(&next)?;
            event = next;
        }
        match event.state {
            RecoveryState::Applied
            | RecoveryState::VerdictLanded
            | RecoveryState::VerdictNotLanded => {
                self.drive_recovery_children(&event)?;
                let settled = self
                    .new_recovery_event(
                        event.operation_id,
                        event.kind,
                        event.body_fingerprint,
                        RecoveryState::Settled,
                        event.first_sent_at_ms,
                        event.payload.clone(),
                    )
                    .map_err(invalid)?;
                self.keep_recovery_event(&settled)?;
            }
            RecoveryState::LandedUnknown => self.drive_recovery_children(&event)?,
            RecoveryState::Settled => {}
            _ => return Err(invalid("unsupported raw recovery state")),
        }
        Ok(())
    }

    fn expired_raw_payload(&self, event: &RecoveryEvent) -> RecordStoreResult<Vec<u8>> {
        if event.kind != RecoveryKind::Usage {
            return Ok(event.payload.clone());
        }
        let mut custody: UsageCustody = decode(&event.payload)?;
        let mut unsent_plain = custody.plain.clone();
        let mut unsent_dated = custody.dated.clone();
        unsent_plain.subtract(&custody.chunk_plain);
        unsent_dated.subtract(&custody.chunk_dated);
        custody.handoffs.extend(Self::usage_recovery_child(
            &custody.bucket,
            custody.window,
            unsent_plain,
            unsent_dated,
        )?);
        custody.plain = ExactUsageDelta::from_signed(&custody.chunk_plain);
        custody.dated = ExactUsageDelta::from_signed(&custody.chunk_dated);
        encode(&custody)
    }

    fn applied_raw_payload(&self, event: &RecoveryEvent) -> RecordStoreResult<Vec<u8>> {
        match event.kind {
            RecoveryKind::Usage => {
                let mut custody: UsageCustody = decode(&event.payload)?;
                custody.plain.subtract(&custody.chunk_plain);
                custody.dated.subtract(&custody.chunk_dated);
                custody.plain.merge(&custody.absorbed_plain);
                custody.dated.merge(&custody.absorbed_dated);
                let child = Self::usage_recovery_child(
                    &custody.bucket,
                    custody.window,
                    custody.plain.clone(),
                    custody.dated.clone(),
                )?;
                custody.handoffs.extend(child);
                custody.plain = ExactUsageDelta::default();
                custody.dated = ExactUsageDelta::default();
                custody.absorbed_plain = ExactUsageDelta::default();
                custody.absorbed_dated = ExactUsageDelta::default();
                encode(&custody)
            }
            RecoveryKind::Metering => Ok(event.payload.clone()),
            RecoveryKind::Correction => Err(invalid("incorrect applied raw kind")),
        }
    }

    pub(super) fn resolve_raw_recovery(
        &self,
        resolution: &RecoveryResolution,
    ) -> Result<(), RecoveryError> {
        let driver = self
            .recovery_driver(resolution.operation_id)
            .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        let running = driver
            .enter(false)
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
        self.confirm_pending_recovery(resolution.operation_id)
            .map_err(|error| RecoveryError::Unavailable(error.to_string()))?;
        let event = self
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| {
                RecoveryError::Invalid("raw recovery operation does not exist".into())
            })?;
        let verdict = RawVerdict {
            landed: resolution.verdict == RecoveryVerdict::Landed,
            expected_revision: resolution.expected_revision,
            actor: resolution.actor.clone(),
            reason: resolution.reason.clone(),
        };
        let map = |error: RecordStoreError| RecoveryError::Unavailable(error.to_string());
        let previous_verdict = match event.kind {
            RecoveryKind::Usage => decode::<UsageCustody>(&event.payload).map_err(map)?.verdict,
            RecoveryKind::Metering => {
                decode::<MeteringCustody>(&event.payload)
                    .map_err(map)?
                    .verdict
            }
            _ => {
                return Err(RecoveryError::Invalid(
                    "incorrect raw resolution kind".into(),
                ))
            }
        };
        if let Some(previous) = previous_verdict {
            if previous != verdict {
                return Err(RecoveryError::Conflict(
                    "recovery verdict differs from recorded decision".into(),
                ));
            }
            drop(running);
            self.drive_raw_recovery(event.operation_id).map_err(map)?;
            return Ok(());
        }
        if event.state != RecoveryState::LandedUnknown
            || event.revision != resolution.expected_revision
        {
            return Err(RecoveryError::Conflict(
                "raw recovery operation is not awaiting this verdict".into(),
            ));
        }
        let state = if verdict.landed {
            RecoveryState::VerdictLanded
        } else {
            RecoveryState::VerdictNotLanded
        };
        let payload = match event.kind {
            RecoveryKind::Usage => {
                let mut custody: UsageCustody = decode(&event.payload).map_err(map)?;
                if verdict.landed {
                    custody.plain.subtract(&custody.chunk_plain);
                    custody.dated.subtract(&custody.chunk_dated);
                }
                custody.plain.merge(&custody.absorbed_plain);
                custody.dated.merge(&custody.absorbed_dated);
                let child = Self::usage_recovery_child(
                    &custody.bucket,
                    custody.window,
                    custody.plain.clone(),
                    custody.dated.clone(),
                )
                .map_err(map)?;
                custody.handoffs.extend(child);
                custody.plain = ExactUsageDelta::default();
                custody.dated = ExactUsageDelta::default();
                custody.absorbed_plain = ExactUsageDelta::default();
                custody.absorbed_dated = ExactUsageDelta::default();
                custody.verdict = Some(verdict);
                encode(&custody).map_err(map)?
            }
            RecoveryKind::Metering => {
                let mut custody: MeteringCustody = decode(&event.payload).map_err(map)?;
                if !verdict.landed {
                    let child_custody = MeteringCustody {
                        origin: None,
                        handoffs: Vec::new(),
                        verdict: None,
                        delta: custody.delta.clone(),
                    };
                    custody.handoffs.push(RecoveryChild {
                        operation_id: crate::door::op_id().0,
                        kind: RecoveryKind::Metering,
                        body_fingerprint: event.body_fingerprint,
                        first_sent_at_ms: Some(crate::store::now_ms()),
                        payload: encode(&child_custody).map_err(map)?,
                    });
                }
                custody.verdict = Some(verdict);
                encode(&custody).map_err(map)?
            }
            _ => unreachable!(),
        };
        let candidate = self.new_recovery_event(
            event.operation_id,
            event.kind,
            event.body_fingerprint,
            state,
            event.first_sent_at_ms,
            payload,
        )?;
        self.keep_recovery_event(&candidate).map_err(map)?;
        drop(running);
        self.drive_raw_recovery(event.operation_id).map_err(map)?;
        self.resume_raw_recovery().map_err(map)
    }
}

pub(super) struct DurableUsageFlight {
    pub(super) child: Option<RecoveryChild>,
    pub(super) prerequisite: Option<RecoveryEvent>,
    pub(super) deferred_plain: ExactUsageDelta,
    pub(super) deferred_dated: ExactUsageDelta,
}

impl ExactUsageDelta {
    fn positive_capacity(chunk: &UsageDelta, absorbed: &Self) -> Self {
        let mut capacity = Self::from_signed(chunk);
        capacity.requests = capacity.requests.max(0);
        capacity.billable_requests = capacity.billable_requests.max(0);
        for model in &mut capacity.models {
            for count in model.usage_units.values_mut() {
                *count = (*count).max(0);
            }
        }
        capacity.merge(absorbed);
        capacity.requests = capacity.requests.max(0);
        capacity.billable_requests = capacity.billable_requests.max(0);
        for model in &mut capacity.models {
            for count in model.usage_units.values_mut() {
                *count = (*count).max(0);
            }
        }
        capacity
    }

    /// Remove only negatives whose matching positive may still be absent. Each
    /// unresolved operation owns at most its original positive, per raw field.
    fn take_capped_negatives(&mut self, capacity: &Self) -> Self {
        let take = |count: &mut i128, capacity: i128| {
            let amount = count.saturating_neg().max(0).min(capacity.max(0));
            *count += amount;
            -amount
        };
        let mut negative = Self {
            requests: take(&mut self.requests, capacity.requests),
            billable_requests: take(&mut self.billable_requests, capacity.billable_requests),
            models: Vec::new(),
        };
        for model in &mut self.models {
            let Some(capacity) = capacity.models.iter().find(|row| row.model == model.model) else {
                continue;
            };
            let units = model
                .usage_units
                .iter_mut()
                .filter_map(|(unit, count)| {
                    let amount = take(count, capacity.usage_units.get(unit).copied().unwrap_or(0));
                    (amount != 0).then(|| (unit.clone(), amount))
                })
                .collect();
            negative.models.push(super::exact_debt::ExactModelDelta {
                model: model.model.clone(),
                usage_units: units,
            });
        }
        negative
    }
}

impl GovState {
    /// Retire dependent negatives into a selected unresolved owner before any
    /// independent positive work is sent. The owner remains off the request path.
    pub(super) fn capture_usage_recovery(
        &self,
        bucket: &str,
        window: u64,
        mut plain: ExactUsageDelta,
        mut dated: ExactUsageDelta,
    ) -> RecordStoreResult<DurableUsageFlight> {
        let mut owners = Vec::new();
        let mut capacity_plain = ExactUsageDelta::default();
        let mut capacity_dated = ExactUsageDelta::default();
        // A selected parent may own an exact child template at the crash cut
        // before child Intent. Its positive also gates dependent negatives.
        for event in self.selected_recovery_events() {
            let links: Links = decode(&event.payload)?;
            for child in links.handoffs {
                if child.kind != RecoveryKind::Usage
                    || self.recovery_event(child.operation_id).is_some()
                {
                    continue;
                }
                let custody: UsageCustody = decode(&child.payload)?;
                if custody.bucket == bucket && custody.window == window {
                    capacity_plain.merge(&ExactUsageDelta::positive_capacity(
                        &custody.chunk_plain,
                        &custody.absorbed_plain,
                    ));
                    capacity_dated.merge(&ExactUsageDelta::positive_capacity(
                        &custody.chunk_dated,
                        &custody.absorbed_dated,
                    ));
                }
            }
            if event.kind != RecoveryKind::Usage
                || !matches!(
                    event.state,
                    RecoveryState::Intent | RecoveryState::LandedUnknown
                )
            {
                continue;
            }
            let custody: UsageCustody = decode(&event.payload)?;
            if custody.bucket != bucket || custody.window != window {
                continue;
            }
            let own_plain =
                ExactUsageDelta::positive_capacity(&custody.chunk_plain, &custody.absorbed_plain);
            let own_dated =
                ExactUsageDelta::positive_capacity(&custody.chunk_dated, &custody.absorbed_dated);
            capacity_plain.merge(&own_plain);
            capacity_dated.merge(&own_dated);
            owners.push((event, custody, own_plain, own_dated));
        }
        let mut prerequisite = None;
        // Exactly one immutable owner checkpoint is staged per capture. A later
        // capture handles any remaining dependent fields under another owner.
        for (event, mut custody, own_plain, own_dated) in owners {
            let mut remaining_plain = plain.clone();
            let mut remaining_dated = dated.clone();
            let negative_plain = remaining_plain.take_capped_negatives(&own_plain);
            let negative_dated = remaining_dated.take_capped_negatives(&own_dated);
            if negative_plain.is_zero() && negative_dated.is_zero() {
                continue;
            }
            let runner = self.recovery_driver(event.operation_id)?;
            let _running = runner.enter(false).map_err(invalid)?;
            // A concurrent definitive decision or pending immutable candidate
            // must finish before these fields can be assigned a new owner.
            if self.recovery_event(event.operation_id).as_ref() != Some(&event) {
                return Err(invalid("raw negative owner changed during capture"));
            }
            custody.absorbed_plain.merge(&negative_plain);
            custody.absorbed_dated.merge(&negative_dated);
            let candidate = self
                .new_recovery_event(
                    event.operation_id,
                    event.kind,
                    event.body_fingerprint,
                    event.state,
                    event.first_sent_at_ms,
                    encode(&custody)?,
                )
                .map_err(invalid)?;
            capacity_plain.merge(&negative_plain);
            capacity_dated.merge(&negative_dated);
            plain = remaining_plain;
            dated = remaining_dated;
            prerequisite = Some(candidate);
            break;
        }
        let deferred_plain = plain.take_capped_negatives(&capacity_plain);
        let deferred_dated = dated.take_capped_negatives(&capacity_dated);
        Ok(DurableUsageFlight {
            child: Self::usage_recovery_child(bucket, window, plain, dated)?,
            prerequisite,
            deferred_plain,
            deferred_dated,
        })
    }

    pub(super) fn drive_durable_usage_flight(
        &self,
        flight: &DurableUsageFlight,
    ) -> RecordStoreResult<()> {
        if let Some(parent) = &flight.prerequisite {
            self.keep_recovery_event(parent)?;
        }
        let Some(child) = &flight.child else {
            return Ok(());
        };
        self.confirm_pending_recovery(child.operation_id)?;
        if self.recovery_event(child.operation_id).is_none() {
            if let Some(parent) = &flight.prerequisite {
                let links: Links = decode(&parent.payload)?;
                if links
                    .handoffs
                    .iter()
                    .any(|descriptor| descriptor.operation_id == child.operation_id)
                {
                    self.drive_recovery_children(parent)?;
                } else {
                    let event = self
                        .new_recovery_event(
                            child.operation_id,
                            child.kind,
                            child.body_fingerprint,
                            RecoveryState::Intent,
                            child.first_sent_at_ms,
                            child.payload.clone(),
                        )
                        .map_err(invalid)?;
                    self.keep_recovery_event(&event)?;
                }
            } else {
                let event = self
                    .new_recovery_event(
                        child.operation_id,
                        child.kind,
                        child.body_fingerprint,
                        RecoveryState::Intent,
                        child.first_sent_at_ms,
                        child.payload.clone(),
                    )
                    .map_err(invalid)?;
                self.keep_recovery_event(&event)?;
            }
        }
        self.drive_raw_recovery(child.operation_id)
    }
}

impl GovState {
    pub(super) fn recovery_children_settled(
        &self,
        parent: &RecoveryEvent,
    ) -> RecordStoreResult<bool> {
        let mut queue = std::collections::VecDeque::from([parent.clone()]);
        let mut seen = std::collections::BTreeSet::new();
        while let Some(event) = queue.pop_front() {
            if !seen.insert(event.operation_id) {
                continue;
            }
            let links: Links = decode(&event.payload)?;
            for descriptor in links.handoffs {
                let Some(child) = self.recovery_event(descriptor.operation_id) else {
                    return Ok(false);
                };
                self.validate_recovery_origin(&child)?;
                if child.state != RecoveryState::Settled {
                    return Ok(false);
                }
                queue.push_back(child);
            }
        }
        Ok(true)
    }
}
