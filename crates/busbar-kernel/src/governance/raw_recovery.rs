// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::exact_debt::SegmentedUsage;
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
    pub(super) age_unknown: bool,
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
    #[serde(default)]
    age_unknown: bool,
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
    sender_quiesced: bool,
    backend_quiesced: bool,
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
        let (chunk_plain, chunk_dated) = SegmentedUsage::of(&plain, &dated)?.chunk();
        let custody = UsageCustody {
            bucket: bucket.into(),
            window,
            chunk_plain,
            chunk_dated,
            age_unknown: false,
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
            age_unknown: false,
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
        let current = self
            .recovery_event(parent.operation_id)
            .ok_or_else(|| invalid("parent selection disappeared"))?;
        self.keep_recovery_event(&current)?;
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
                SegmentedUsage::of(&custody.plain, &custody.dated)?;
                SegmentedUsage::of(&custody.absorbed_plain, &custody.absorbed_dated)?;
                SegmentedUsage::of(
                    &ExactUsageDelta::from_signed(&custody.chunk_plain),
                    &ExactUsageDelta::from_signed(&custody.chunk_dated),
                )?;
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
            self.keep_recovery_event(&event)?;
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
        let age_unknown = self
            .recovery_retention_expired(event.operation_id)
            .is_none();
        if event.kind == RecoveryKind::Metering {
            let mut custody: MeteringCustody = decode(&event.payload)?;
            custody.age_unknown = age_unknown;
            return encode(&custody);
        }
        let mut custody: UsageCustody = decode(&event.payload)?;
        custody.age_unknown = age_unknown;
        let mut unsent_plain = custody.plain.clone();
        let mut unsent_dated = custody.dated.clone();
        unsent_plain.subtract(&custody.chunk_plain);
        unsent_dated.subtract(&custody.chunk_dated);
        let mut unsent = SegmentedUsage::of(&unsent_plain, &unsent_dated)?;
        let mut absorbed = SegmentedUsage::of(&custody.absorbed_plain, &custody.absorbed_dated)?;
        // Refunds first net against never-sent positive segments. Only the
        // remainder can depend on the chunk whose backend outcome is unknown.
        let netted = absorbed.take_negatives(Some(&unsent.positive()));
        unsent.merge(&netted);
        let (unsent_plain, unsent_dated) = unsent.deltas();
        custody.handoffs.extend(Self::usage_recovery_child(
            &custody.bucket,
            custody.window,
            unsent_plain,
            unsent_dated,
        )?);
        custody.plain = ExactUsageDelta::from_signed(&custody.chunk_plain);
        custody.dated = ExactUsageDelta::from_signed(&custody.chunk_dated);
        (custody.absorbed_plain, custody.absorbed_dated) = absorbed.deltas();
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
        resolution.validate_quiescence()?;
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
            sender_quiesced: resolution.sender_quiesced,
            backend_quiesced: resolution.backend_quiesced,
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
                        age_unknown: false,
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
        let mut prerequisite =
            self.stage_quarantined_correction_negatives(bucket, window, &mut plain, &mut dated)?;
        let quarantine = self.quarantined_correction_owns_target(bucket, window);
        let mut remaining = SegmentedUsage::of(&plain, &dated)?;
        let mut owners = Vec::new();
        let mut capacity = SegmentedUsage::default();
        // A selected parent can own an exact child template before child Intent.
        // Those positive segments gate negatives without guessing Store rows.
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
                    let mut available = SegmentedUsage::of(&custody.plain, &custody.dated)?;
                    available.merge(&SegmentedUsage::of(
                        &custody.absorbed_plain,
                        &custody.absorbed_dated,
                    )?);
                    capacity.merge(&available.positive());
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
            let mut available = SegmentedUsage::of(&custody.plain, &custody.dated)?;
            available.merge(&SegmentedUsage::of(
                &custody.absorbed_plain,
                &custody.absorbed_dated,
            )?);
            let own_capacity = available.positive();
            capacity.merge(&own_capacity);
            owners.push((event, custody, own_capacity));
        }
        // Exactly one immutable checkpoint is staged per capture. Any remaining
        // negative segments keep their ordinary pending ownership for next tick.
        if prerequisite.is_none() {
            for (event, mut custody, own_capacity) in owners {
                let mut after = remaining.clone();
                let negative = after.take_negatives(Some(&own_capacity));
                if negative.is_zero() {
                    continue;
                }
                let runner = self.recovery_driver(event.operation_id)?;
                let _running = runner.enter(false).map_err(invalid)?;
                if self.recovery_event(event.operation_id).as_ref() != Some(&event) {
                    return Err(invalid("raw negative owner changed during capture"));
                }
                let (negative_plain, negative_dated) = negative.deltas();
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
                capacity.merge(&negative);
                remaining = after;
                prerequisite = Some(candidate);
                break;
            }
        }
        let deferred = remaining.take_negatives(if quarantine { None } else { Some(&capacity) });
        let (deferred_plain, deferred_dated) = deferred.deltas();
        let (plain, dated) = remaining.deltas();
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
