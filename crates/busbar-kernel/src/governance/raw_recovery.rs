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
pub(crate) struct UsageCustody {
    pub(super) bucket: String,
    pub(super) window: u64,
    pub(crate) plain: ExactUsageDelta,
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
    pub(crate) handoffs: Vec<RecoveryChild>,
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
    rendered_error(
        RecordStoreError,
        format_args!("invalid raw recovery custody: {error}"),
    )
}
/// [`invalid`] for an off-path helper that reports through a borrowed error.
fn invalid_dyn(error: &dyn std::fmt::Display) -> RecordStoreError {
    invalid(error)
}
fn encode<T: Serialize>(value: &T) -> RecordStoreResult<Vec<u8>> {
    crate::off_path::governance::runtime::raw_recovery_encode(value).map_err(invalid)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> RecordStoreResult<T> {
    serde_json::from_slice(bytes).map_err(invalid)
}
fn fingerprint<T: Serialize>(kind: &[u8], value: &T) -> RecordStoreResult<[u8; 32]> {
    let mut digest = crate::hashing::Sha256::new();
    digest.update(kind);
    serde_json::to_writer(DigestWriter(&mut digest), value).map_err(invalid)?;
    Ok(digest.finalize())
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

fn usage_operation_values(custody: UsageCustody) -> Vec<(String, u64, UsageDelta)> {
    // The dated bucket is named from the plain one before the plain name moves into its cell.
    let dated = (!custody.chunk_dated.is_zero()).then(|| {
        (
            era_bucket(&custody.bucket),
            custody.window,
            custody.chunk_dated,
        )
    });
    let plain = (!custody.chunk_plain.is_zero()).then_some((
        custody.bucket,
        custody.window,
        custody.chunk_plain,
    ));
    crate::off_path::governance::runtime::raw_recovery_cells(plain, dated)
}

#[cfg(test)]
#[path = "tests/raw_recovery_tests.rs"]
mod legacy_value_tests;

impl GovState {
    /// Original submitted values, validated under the recovery owner's stored
    /// fingerprint recipe. Pure inspection grants no new attempt or writer.
    pub(crate) fn legacy_usage_values(
        event: &RecoveryEvent,
    ) -> RecordStoreResult<Vec<(String, u64, UsageDelta)>> {
        if event.kind != RecoveryKind::Usage {
            return Err(invalid("incorrect usage recovery kind"));
        }
        Self::validate_raw_recovery(event)?;
        Ok(usage_operation_values(decode(&event.payload)?))
    }
    pub(crate) fn legacy_metering_values(
        event: &RecoveryEvent,
    ) -> RecordStoreResult<Vec<MeteringDelta>> {
        if event.kind != RecoveryKind::Metering {
            return Err(invalid("incorrect metering recovery kind"));
        }
        Self::validate_raw_recovery(event)?;
        let custody: MeteringCustody = decode(&event.payload)?;
        Ok(vec![custody.delta])
    }

    pub(crate) fn usage_recovery_child(
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
            bucket: crate::off_path::governance::runtime::raw_recovery_bucket(bucket),
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

    pub(super) async fn validate_recovery_origin(
        &self,
        event: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        let origin = event.origin_reference().map_err(invalid)?;
        let initial = self
            .recovery_initial_event(event.operation_id)
            .unwrap_or_else(|| event.clone());
        if initial.origin_reference().map_err(invalid)? != origin {
            return Err(invalid("child origin changed after its original Intent"));
        }
        let Some(origin) = origin else {
            return Ok(());
        };
        if let Some(parent) = self.recovery_ancestor(origin.operation_id, origin.event_fingerprint)
        {
            parent.authorizes_child(&initial).map_err(invalid)
        } else {
            self.verify_external_recovery_origin(&initial).await
        }
    }

    /// Select missing child Intents only after their exact parent checkpoint is
    pub(super) async fn drive_recovery_children(
        &self,
        parent: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        self.select_recovery_children(parent, false).await
    }

    async fn select_recovery_children(
        &self,
        parent: &RecoveryEvent,
        raw_only: bool,
    ) -> RecordStoreResult<()> {
        let links: Links = decode(&parent.payload)?;
        let mut children = links
            .handoffs
            .into_iter()
            .filter(|child| !raw_only || child.kind != RecoveryKind::Correction)
            .peekable();
        if children.peek().is_none() {
            return Ok(());
        }
        self.verify_recovery_checkpoint(parent).await?;
        let current = self
            .recovery_event(parent.operation_id)
            .ok_or_else(|| invalid("parent selection disappeared"))?;
        self.keep_recovery_event(&current).await?;
        for child in children {
            if child.operation_id == parent.operation_id {
                return Err(invalid("recovery child reuses parent operation identity"));
            }
            if let Some(selected) = self.recovery_event(child.operation_id) {
                self.validate_recovery_origin(&selected).await?;
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
                if !crate::off_path::governance::runtime::raw_recovery_same_child(
                    &initial.payload,
                    &child.payload,
                    invalid_dyn,
                )? {
                    return Err(invalid("child differs from retained parent descriptor"));
                }
                continue;
            }
            if self.observed_child_receipt(parent, &child).await?.is_some() {
                continue;
            }
            let initial = child.intent_with_origin(&RecoveryOrigin {
                operation_id: parent.operation_id,
                event_fingerprint: parent.fingerprint().map_err(invalid)?,
            })?;
            let event = self
                .new_recovery_event(
                    initial.operation_id,
                    initial.kind,
                    initial.body_fingerprint,
                    initial.state,
                    initial.first_sent_at_ms,
                    initial.payload,
                )
                .map_err(invalid)?;
            self.keep_recovery_event(&event).await?;
            self.validate_recovery_origin(&event).await?;
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
        Self::validate_raw_recovery(event)
    }

    fn validate_raw_recovery(event: &RecoveryEvent) -> RecordStoreResult<()> {
        match event.kind {
            RecoveryKind::Usage => {
                let custody: UsageCustody = decode(&event.payload)?;
                SegmentedUsage::of(&custody.plain, &custody.dated)?;
                SegmentedUsage::of(&custody.absorbed_plain, &custody.absorbed_dated)?;
                SegmentedUsage::of(
                    &ExactUsageDelta::try_from_signed(&custody.chunk_plain).map_err(invalid)?,
                    &ExactUsageDelta::try_from_signed(&custody.chunk_dated).map_err(invalid)?,
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

    pub(super) fn has_unsettled_raw_bucket(&self, bucket: &str) -> RecordStoreResult<bool> {
        for event in self.selected_recovery_events() {
            if event.kind == RecoveryKind::Usage && event.state != RecoveryState::Settled {
                let custody: UsageCustody = decode(&event.payload)?;
                if custody.bucket == bucket {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub(super) async fn resume_raw_recovery(&self) -> RecordStoreResult<()> {
        let mut first_error = None;
        loop {
            let before = crate::off_path::governance::runtime::raw_recovery_revisions(
                &self.selected_recovery_events(),
            );
            for event in self.selected_recovery_events() {
                if let Err(error) = self.select_recovery_children(&event, true).await {
                    first_error.get_or_insert(error);
                    continue;
                }
                if event.kind != RecoveryKind::Correction && event.state != RecoveryState::Settled {
                    if let Err(error) = self.drive_raw_recovery(event.operation_id).await {
                        first_error.get_or_insert(error);
                    }
                }
            }
            let after = crate::off_path::governance::runtime::raw_recovery_revisions(
                &self.selected_recovery_events(),
            );
            if before == after {
                return first_error.map_or(Ok(()), Err);
            }
        }
    }

    /// One operation through the raw recovery state machine: `drive_raw_recoveries` with a slice
    /// of one, so the single driver and the flush pass are one machine (SHUTDOWN-HANG F3.3).
    pub(super) async fn drive_raw_recovery(&self, operation_id: [u8; 16]) -> RecordStoreResult<()> {
        self.drive_raw_recoveries(&[operation_id])
            .await
            .pop()
            .unwrap_or_else(|| Err(invalid("raw recovery result missing")))
    }

    /// The raw recovery state machine over several operations in lockstep (SHUTDOWN-HANG F3.3):
    /// T re-keeps every retained candidate in one batch; V takes each operation's driver and
    /// validates it; A makes each ledger commit; K1 keeps every Applied and LandedUnknown event in
    /// one batch; C selects children; K2 keeps every Settled event in one batch. Per-operation
    /// order is unchanged (Intent, apply, Applied, children, Settled), and every phase isolates
    /// its operations: one that fails leaves the pass with its error while the rest continue.
    /// Returns a result per operation, in order.
    pub(super) async fn drive_raw_recoveries(
        &self,
        operation_ids: &[[u8; 16]],
    ) -> Vec<RecordStoreResult<()>> {
        let mut out: Vec<Option<RecordStoreResult<()>>> = Vec::with_capacity(operation_ids.len());
        out.resize_with(operation_ids.len(), || None);

        // T: every retained candidate is confirmed first, in one keep.
        let retained: Vec<(usize, RecoveryEvent)> = operation_ids
            .iter()
            .enumerate()
            .filter_map(|(at, id)| self.pending_recovery_event(*id).map(|event| (at, event)))
            .collect();
        self.keep_phase(&mut out, retained).await;

        // V: each operation's driver is held for the rest of the pass. The guards borrow
        // `runners`, declared before them.
        let mut runners = Vec::with_capacity(operation_ids.len());
        for (at, id) in operation_ids.iter().enumerate() {
            if out[at].is_some() {
                runners.push(None);
                continue;
            }
            match self.recovery_driver(*id) {
                Ok(runner) => runners.push(Some(runner)),
                Err(why) => {
                    out[at] = Some(Err(why));
                    runners.push(None);
                }
            }
        }
        let mut running = Vec::with_capacity(runners.len());
        let mut selected: Vec<(usize, RecoveryEvent)> = Vec::with_capacity(runners.len());
        for (at, runner) in runners.iter().enumerate() {
            let Some(runner) = runner else {
                continue;
            };
            match runner.try_enter() {
                Ok(guard) => running.push(guard),
                Err(why) => {
                    out[at] = Some(Err(invalid(why)));
                    continue;
                }
            }
            let event = match self.recovery_event(operation_ids[at]) {
                Some(event) => event,
                None => {
                    out[at] = Some(Err(invalid("raw operation is not selected")));
                    continue;
                }
            };
            if let Err(why) = self.validate_recovery_origin(&event).await {
                out[at] = Some(Err(why));
                continue;
            }
            if let Err(why) = self.restore_raw_recovery(&event) {
                out[at] = Some(Err(why));
                continue;
            }
            selected.push((at, event));
        }
        // The verify-only Intent re-keep: a no-op unless a candidate reappeared.
        let intents: Vec<(usize, RecoveryEvent)> = selected
            .iter()
            .filter(|(_, event)| event.state == RecoveryState::Intent)
            .cloned()
            .collect();
        let verified = self.keep_phase(&mut out, intents).await;

        // A: each Intent sent here is applied to the ledger, then staged Applied; an Intent never
        // sent here is staged LandedUnknown. Both are kept in K1.
        let mut k1: Vec<(usize, RecoveryEvent)> = Vec::new();
        let mut settle: Vec<(usize, RecoveryEvent)> = Vec::new();
        let mut children: Vec<(usize, RecoveryEvent)> = Vec::new();
        for (at, event) in selected {
            if out[at].is_some() {
                continue;
            }
            let step = match event.state {
                RecoveryState::Intent if verified.contains(&at) => {
                    let next = if self.recovery_sent_here(event.operation_id) {
                        self.apply_raw_intent(&event).await
                    } else {
                        Self::quarantined_raw_payload(&event).and_then(|payload| {
                            self.new_recovery_event(
                                event.operation_id,
                                event.kind,
                                event.body_fingerprint,
                                RecoveryState::LandedUnknown,
                                event.first_sent_at_ms,
                                payload,
                            )
                            .map_err(invalid)
                        })
                    };
                    next.map(|next| k1.push((at, next)))
                }
                RecoveryState::Intent => Ok(()),
                RecoveryState::Applied
                | RecoveryState::VerdictLanded
                | RecoveryState::VerdictNotLanded => {
                    settle.push((at, event));
                    Ok(())
                }
                RecoveryState::LandedUnknown => {
                    children.push((at, event));
                    Ok(())
                }
                RecoveryState::Settled => {
                    out[at] = Some(Ok(()));
                    Ok(())
                }
                _ => Err(invalid("unsupported raw recovery state")),
            };
            if let Err(why) = step {
                out[at] = Some(Err(why));
            }
        }

        // K1: every Applied and LandedUnknown event in one keep. An Applied event goes on to be
        // settled; a LandedUnknown one only selects its children.
        let kept = self.keep_phase(&mut out, k1.clone()).await;
        for (at, next) in k1 {
            if !kept.contains(&at) {
                continue;
            }
            if next.state == RecoveryState::Applied {
                settle.push((at, next));
            } else {
                children.push((at, next));
            }
        }
        for (at, event) in children {
            out[at] = Some(self.drive_recovery_children(&event).await);
        }

        // C, then K2: children selected for each settling operation, then every Settled event in
        // one keep.
        let mut k2: Vec<(usize, RecoveryEvent)> = Vec::with_capacity(settle.len());
        for (at, event) in settle {
            let settled = match self.drive_recovery_children(&event).await {
                Ok(()) => self
                    .new_recovery_event(
                        event.operation_id,
                        event.kind,
                        event.body_fingerprint,
                        RecoveryState::Settled,
                        event.first_sent_at_ms,
                        event.payload.clone(),
                    )
                    .map_err(invalid),
                Err(why) => Err(why),
            };
            match settled {
                Ok(settled) => k2.push((at, settled)),
                Err(why) => out[at] = Some(Err(why)),
            }
        }
        for at in self.keep_phase(&mut out, k2).await {
            out[at] = Some(Ok(()));
        }
        drop(running);
        out.into_iter()
            .map(|answer| answer.unwrap_or_else(|| Err(invalid("raw recovery result missing"))))
            .collect()
    }

    /// One keep phase: every event in one keep batch. A failure is written to its operation's
    /// slot in `out`; returns the positions whose event is now selected.
    async fn keep_phase(
        &self,
        out: &mut [Option<RecordStoreResult<()>>],
        events: Vec<(usize, RecoveryEvent)>,
    ) -> Vec<usize> {
        if events.is_empty() {
            return Vec::new();
        }
        let (at, events): (Vec<usize>, Vec<RecoveryEvent>) = events.into_iter().unzip();
        let mut kept = Vec::with_capacity(at.len());
        let mut results = self.keep_recovery_events(&events).await.into_iter();
        for at in at {
            match results.next() {
                Some(Ok(())) => kept.push(at),
                Some(Err(why)) => out[at] = Some(Err(why)),
                None => out[at] = Some(Err(invalid("raw recovery keep result missing"))),
            }
        }
        kept
    }

    /// Phase A for one Intent sent here: its exact ledger commit (deduplicated by operation id),
    /// then its Applied event, staged.
    async fn apply_raw_intent(&self, event: &RecoveryEvent) -> RecordStoreResult<RecoveryEvent> {
        let operation_id = event.operation_id;
        match event.kind {
            RecoveryKind::Usage => {
                let custody: UsageCustody = decode(&event.payload)?;
                let owned = usage_operation_values(custody);
                let cells = crate::off_path::governance::runtime::raw_recovery_cell_refs(&owned);
                self.core_store()?
                    .ledger()
                    .add_usage_batch_deduped(busbar_contract::records::OpId(operation_id), &cells)
                    .await?;
            }
            RecoveryKind::Metering => {
                let custody: MeteringCustody = decode(&event.payload)?;
                self.core_store()?
                    .ledger()
                    .add_metering_batch_deduped(
                        busbar_contract::records::OpId(operation_id),
                        &[custody.delta],
                    )
                    .await?;
            }
            RecoveryKind::Correction => return Err(invalid("incorrect raw driver kind")),
        }
        let payload = self.applied_raw_payload(event)?;
        self.new_recovery_event(
            event.operation_id,
            event.kind,
            event.body_fingerprint,
            RecoveryState::Applied,
            event.first_sent_at_ms,
            payload,
        )
        .map_err(invalid)
    }

    fn quarantined_raw_payload(event: &RecoveryEvent) -> RecordStoreResult<Vec<u8>> {
        if event.kind == RecoveryKind::Metering {
            let mut custody: MeteringCustody = decode(&event.payload)?;
            custody.age_unknown = true;
            return encode(&custody);
        }
        let mut custody: UsageCustody = decode(&event.payload)?;
        custody.age_unknown = true;
        let mut unsent_plain = custody.plain.clone();
        let mut unsent_dated = custody.dated.clone();
        unsent_plain.subtract(&custody.chunk_plain);
        unsent_dated.subtract(&custody.chunk_dated);
        let mut unsent = SegmentedUsage::of(&unsent_plain, &unsent_dated)?;
        let mut absorbed = SegmentedUsage::of(&custody.absorbed_plain, &custody.absorbed_dated)?;

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

    fn raw_verdict_payload(
        event: &RecoveryEvent,
        verdict: RawVerdict,
    ) -> Result<Vec<u8>, RecoveryError> {
        let map = |error: RecordStoreError| {
            crate::governance::rendered_error(RecoveryError::Unavailable, error)
        };
        match event.kind {
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
                encode(&custody).map_err(map)
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
                encode(&custody).map_err(map)
            }
            _ => unreachable!(),
        }
    }

    pub(super) async fn resolve_raw_recovery(
        &self,
        resolution: &RecoveryResolution,
    ) -> Result<(), RecoveryError> {
        resolution.validate_quiescence()?;
        let driver = self
            .recovery_driver(resolution.operation_id)
            .map_err(|error| {
                crate::governance::rendered_error(RecoveryError::Unavailable, error)
            })?;
        let running = driver
            .try_enter()
            .map_err(|reason| RecoveryError::Conflict(reason.into()))?;
        self.confirm_pending_recovery(resolution.operation_id)
            .await
            .map_err(|error| {
                crate::governance::rendered_error(RecoveryError::Unavailable, error)
            })?;
        let event = self
            .recovery_event(resolution.operation_id)
            .ok_or_else(|| {
                RecoveryError::Invalid("raw recovery operation does not exist".into())
            })?;
        let (actor, reason) = crate::off_path::governance::ledger::operator_provenance(
            &resolution.actor,
            &resolution.reason,
        );
        let verdict = RawVerdict {
            landed: resolution.verdict == RecoveryVerdict::Landed,
            expected_revision: resolution.expected_revision,
            sender_quiesced: resolution.sender_quiesced,
            backend_quiesced: resolution.backend_quiesced,
            actor,
            reason,
        };
        let map = |error: RecordStoreError| {
            crate::governance::rendered_error(RecoveryError::Unavailable, error)
        };
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
                ));
            }
        };
        if let Some(previous) = previous_verdict {
            if previous != verdict {
                return Err(RecoveryError::Conflict(
                    "recovery verdict differs from recorded decision".into(),
                ));
            }
            drop(running);
            self.drive_raw_recovery(event.operation_id)
                .await
                .map_err(map)?;
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
        let payload = Self::raw_verdict_payload(&event, verdict)?;
        let candidate = self.new_recovery_event(
            event.operation_id,
            event.kind,
            event.body_fingerprint,
            state,
            event.first_sent_at_ms,
            payload,
        )?;
        self.keep_recovery_event(&candidate).await.map_err(map)?;
        drop(running);
        self.drive_raw_recovery(event.operation_id)
            .await
            .map_err(map)?;
        self.resume_raw_recovery().await.map_err(map)
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
    pub(super) fn capture_usage_recovery(
        &self,
        bucket: &str,
        window: u64,
        mut plain: ExactUsageDelta,
        mut dated: ExactUsageDelta,
        settled: &ForeignSettledSnapshot,
    ) -> RecordStoreResult<DurableUsageFlight> {
        let epoch = self.recovery_selection_epoch();
        let (correction_plain, correction_dated) =
            self.quarantined_correction_negative_capacity(bucket, window)?;
        let observations = self.selected_recovery_events();
        if epoch != self.recovery_selection_epoch() {
            return Err(invalid("selected raw custody changed during capture"));
        }
        let owned_snapshot =
            crate::off_path::governance::runtime::raw_recovery_operation_ids(&observations);
        let before = SegmentedUsage::of(&plain, &dated)?;
        let mut prerequisite =
            self.stage_quarantined_correction_negatives(bucket, window, &mut plain, &mut dated)?;
        let mut remaining = SegmentedUsage::of(&plain, &dated)?;
        let mut allocated = before;
        allocated.subtract(&remaining)?;
        let mut capacity = SegmentedUsage::of(&correction_plain, &correction_dated)?;

        capacity.merge(&allocated);
        let selection_changed = epoch != self.recovery_selection_epoch();

        for event in &observations {
            let links: Links = decode(&event.payload)?;
            for child in links.handoffs {
                if child.kind != RecoveryKind::Usage
                    || owned_snapshot.contains(&child.operation_id)
                    || settled.excludes(event.operation_id, &child)
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
            if let Some((_, own_capacity)) = Self::usage_owner(event, bucket, window)? {
                capacity.merge(&own_capacity);
            }
        }

        if prerequisite.is_none() && !selection_changed {
            // The owners in selection order, as the capture pass above saw them.
            for event in &observations {
                let Some((mut custody, own_capacity)) = Self::usage_owner(event, bucket, window)?
                else {
                    continue;
                };
                let mut after = remaining.clone();
                let negative = after.take_negatives(Some(&own_capacity));
                if negative.is_zero() {
                    continue;
                }
                let runner = self.recovery_driver(event.operation_id)?;
                let _running = runner.try_enter().map_err(invalid)?;
                if self.recovery_event(event.operation_id).as_ref() != Some(event) {
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

        let changed = selection_changed || epoch != self.recovery_selection_epoch();
        let deferred = remaining.take_negatives(if changed { None } else { Some(&capacity) });
        let (deferred_plain, deferred_dated) = deferred.deltas();
        let (plain, dated) = remaining.deltas();
        Ok(DurableUsageFlight {
            child: Self::usage_recovery_child(bucket, window, plain, dated)?,
            prerequisite,
            deferred_plain,
            deferred_dated,
        })
    }

    /// A selected unresolved usage owner of this bucket and window: its custody and the
    /// positive capacity it holds (original plus absorbed counts).
    fn usage_owner(
        event: &RecoveryEvent,
        bucket: &str,
        window: u64,
    ) -> RecordStoreResult<Option<(UsageCustody, SegmentedUsage)>> {
        if event.kind != RecoveryKind::Usage
            || !matches!(
                event.state,
                RecoveryState::Intent | RecoveryState::LandedUnknown
            )
        {
            return Ok(None);
        }
        let custody: UsageCustody = decode(&event.payload)?;
        if custody.bucket != bucket || custody.window != window {
            return Ok(None);
        }
        let mut available = SegmentedUsage::of(&custody.plain, &custody.dated)?;
        available.merge(&SegmentedUsage::of(
            &custody.absorbed_plain,
            &custody.absorbed_dated,
        )?);
        let own_capacity = available.positive();
        Ok(Some((custody, own_capacity)))
    }

    pub(super) async fn drive_durable_usage_flight(
        &self,
        flight: &DurableUsageFlight,
    ) -> RecordStoreResult<()> {
        if let Some(parent) = &flight.prerequisite {
            let advanced = self
                .recovery_event(parent.operation_id)
                .is_some_and(|current| current.revision > parent.revision);
            if !advanced {
                self.keep_recovery_event(parent).await?;
            } else {
                self.confirm_owned_recovery_checkpoint(parent).await?;
            }
        }
        let Some(child) = &flight.child else {
            return Ok(());
        };
        self.confirm_pending_recovery(child.operation_id).await?;
        if self.recovery_event(child.operation_id).is_none() {
            if let Some(parent) = &flight.prerequisite {
                let links: Links = decode(&parent.payload)?;
                if links
                    .handoffs
                    .iter()
                    .any(|descriptor| descriptor.operation_id == child.operation_id)
                {
                    self.drive_recovery_children(parent).await?;
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
                    self.keep_recovery_event(&event).await?;
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
                self.keep_recovery_event(&event).await?;
            }
        }
        self.drive_raw_recovery(child.operation_id).await
    }
}

impl GovState {
    pub(super) async fn recovery_children_settled(
        &self,
        parent: &RecoveryEvent,
    ) -> RecordStoreResult<bool> {
        self.recovery_children_settled_inner(parent, false).await
    }

    async fn recovery_children_settled_inner(
        &self,
        parent: &RecoveryEvent,
        verify_current: bool,
    ) -> RecordStoreResult<bool> {
        let mut queue = crate::off_path::governance::runtime::raw_recovery_queue(parent.clone());
        let mut seen = std::collections::BTreeSet::new();
        while let Some(event) = queue.pop_front() {
            if !seen.insert(event.operation_id) {
                continue;
            }
            if verify_current {
                if event.state != RecoveryState::Settled {
                    return Ok(false);
                }
                self.verify_current_recovery_checkpoint(&event).await?;
            }
            let links: Links = decode(&event.payload)?;
            for descriptor in links.handoffs {
                let child = if let Some(child) = self.recovery_event(descriptor.operation_id) {
                    self.validate_recovery_origin(&child).await?;
                    child
                } else if let Some(receipt) =
                    self.observed_child_receipt(&event, &descriptor).await?
                {
                    receipt
                } else {
                    return Ok(false);
                };
                if verify_current {
                    self.verify_settled_descriptor(&event, &descriptor, &child)
                        .await?;
                }
                if child.state != RecoveryState::Settled {
                    return Ok(false);
                }
                queue.push_back(child);
            }
        }
        Ok(true)
    }
}

impl GovState {
    /// Resume this parent's raw descendants only. Correction Intents retain
    pub(super) async fn resume_recovery_children(
        &self,
        parent: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        let mut queue =
            crate::off_path::governance::runtime::raw_recovery_queue((parent.clone(), true));
        let mut seen = std::collections::BTreeSet::new();
        while let Some((snapshot, owned)) = queue.pop_front() {
            let event = if owned {
                self.recovery_event(snapshot.operation_id)
                    .ok_or_else(|| invalid("selected recovery parent disappeared"))?
            } else {
                snapshot
            };
            if !seen.insert((event.operation_id, event.revision)) {
                continue;
            }
            if owned {
                self.drive_recovery_children(&event).await?;
            }
            let current = if owned {
                self.recovery_event(event.operation_id)
                    .ok_or_else(|| invalid("selected recovery parent disappeared"))?
            } else {
                event
            };
            let links: Links = decode(&current.payload)?;
            for descriptor in links.handoffs {
                let Some(child) = self.recovery_event(descriptor.operation_id) else {
                    if let Some(receipt) =
                        self.observed_child_receipt(&current, &descriptor).await?
                    {
                        queue.push_back((receipt, false));
                        continue;
                    }
                    return Err(invalid(
                        "unresolved foreign child requires an explicit audited adoption",
                    ));
                };
                self.validate_recovery_origin(&child).await?;
                match child.kind {
                    RecoveryKind::Usage | RecoveryKind::Metering => {
                        self.drive_raw_recovery(child.operation_id).await?;
                        let refreshed = self
                            .recovery_event(child.operation_id)
                            .ok_or_else(|| invalid("selected recovery child disappeared"))?;
                        queue.push_back((refreshed, true));
                    }
                    RecoveryKind::Correction if child.state == RecoveryState::Settled => {
                        queue.push_back((child, true))
                    }
                    RecoveryKind::Correction => {}
                }
            }
        }
        Ok(())
    }

    pub(super) async fn observed_child_receipt(
        &self,
        parent: &RecoveryEvent,
        descriptor: &RecoveryChild,
    ) -> RecordStoreResult<Option<RecoveryEvent>> {
        let Some(receipt) = self
            .foreign_recovery_receipt(descriptor.operation_id)
            .await
            .map_err(invalid)?
        else {
            return Ok(None);
        };
        if receipt.kind != descriptor.kind
            || receipt.body_fingerprint != descriptor.body_fingerprint
            || receipt.first_sent_at_ms != descriptor.first_sent_at_ms
        {
            return Err(invalid(
                "foreign settled receipt differs from authorized child identity",
            ));
        }
        let origin = receipt
            .origin_reference()
            .map_err(invalid)?
            .ok_or_else(|| invalid("foreign settled child has no origin"))?;
        if origin.operation_id != parent.operation_id {
            return Err(invalid("foreign settled child belongs to another parent"));
        }
        if let Some(checkpoint) =
            self.recovery_ancestor(origin.operation_id, origin.event_fingerprint)
        {
            let links: Links = decode(&checkpoint.payload)?;
            if !links.handoffs.iter().any(|original| original == descriptor) {
                return Err(invalid(
                    "foreign settled receipt template differs from retained parent authorization",
                ));
            }
        }
        Ok(Some(receipt))
    }
}

impl RecoveryEvent {
    /// Read typed origin identity without interpreting custody counts or granting ownership.
    pub fn origin_reference(&self) -> Result<Option<RecoveryOrigin>, RecoveryError> {
        serde_json::from_slice::<Links>(&self.payload)
            .map(|links| links.origin)
            .map_err(|error| {
                rendered_error(
                    RecoveryError::Invalid,
                    format_args!("invalid recovery origin payload: {error}"),
                )
            })
    }

    /// Pure matching only: the caller must prove this exact parent checkpoint is
    pub fn authorizes_child(&self, child_genesis: &RecoveryEvent) -> Result<(), RecoveryError> {
        let invalid = |reason: &str| RecoveryError::Invalid(reason.into());
        child_genesis.follows(None)?;
        let origin = child_genesis
            .origin_reference()?
            .ok_or_else(|| invalid("child Intent has no origin"))?;
        if origin.operation_id != self.operation_id
            || origin.event_fingerprint != self.fingerprint()?
            || child_genesis.operation_id == self.operation_id
        {
            return Err(invalid("child origin differs from exact parent checkpoint"));
        }
        let links: Links = serde_json::from_slice(&self.payload).map_err(|error| {
            rendered_error(
                RecoveryError::Invalid,
                format_args!("invalid parent handoff: {error}"),
            )
        })?;
        let mut descriptors = links
            .handoffs
            .iter()
            .filter(|child| child.operation_id == child_genesis.operation_id);
        let descriptor = descriptors
            .next()
            .ok_or_else(|| invalid("parent does not authorize child"))?;
        if descriptors.next().is_some() {
            return Err(invalid("parent repeats child descriptor"));
        }
        if descriptor.kind != child_genesis.kind
            || descriptor.body_fingerprint != child_genesis.body_fingerprint
            || descriptor.first_sent_at_ms != child_genesis.first_sent_at_ms
        {
            return Err(invalid("child identity differs from exact parent template"));
        }
        crate::off_path::governance::runtime::raw_recovery_child_matches_template(
            &child_genesis.payload,
            &descriptor.payload,
        )
    }
}

impl GovState {
    pub(super) fn stage_foreign_raw_verdict(
        event: &RecoveryEvent,
        resolution: &RecoveryResolution,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Self::stage_foreign_raw_verdict_inner(event, resolution, None)
    }
    pub(crate) fn stage_imported_raw_verdict(
        event: &RecoveryEvent,
        resolution: &RecoveryResolution,
        context: &super::recovery::MigratedChildContext,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Self::stage_foreign_raw_verdict_inner(event, resolution, Some(context))
    }
    fn stage_foreign_raw_verdict_inner(
        event: &RecoveryEvent,
        resolution: &RecoveryResolution,
        context: Option<&super::recovery::MigratedChildContext>,
    ) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        resolution.validate_quiescence()?;
        if event.operation_id != resolution.operation_id
            || event.body_fingerprint != resolution.body_fingerprint
            || event.revision != resolution.expected_revision
        {
            return Err(RecoveryError::Conflict(
                "foreign recovery identity or revision differs".into(),
            ));
        }
        Self::validate_raw_recovery(event)
            .map_err(|error| crate::governance::rendered_error(RecoveryError::Invalid, error))?;
        let landed = resolution.verdict == RecoveryVerdict::Landed;
        match event.state {
            RecoveryState::Settled => return Ok(Vec::new()),
            RecoveryState::Applied if landed => {
                return Ok(vec![event.checkpoint(event.state, event.payload.clone())?]);
            }
            RecoveryState::VerdictLanded | RecoveryState::VerdictNotLanded => {
                if (event.state == RecoveryState::VerdictLanded) != landed {
                    return Err(RecoveryError::Conflict(
                        "foreign recovery already has the opposite verdict".into(),
                    ));
                }
                return Ok(vec![event.checkpoint(event.state, event.payload.clone())?]);
            }
            RecoveryState::Intent | RecoveryState::LandedUnknown => {}
            _ => {
                return Err(RecoveryError::Conflict(
                    "foreign raw state does not accept this verdict".into(),
                ));
            }
        }
        let preserved: Links = decode(&event.payload)
            .map_err(|error| crate::governance::rendered_error(RecoveryError::Invalid, error))?;
        let normalize = |payload: Vec<u8>| -> Result<Vec<u8>, RecoveryError> {
            let Some(context) = context else {
                return Ok(payload);
            };
            // The payload is rewritten as a tree so every other field keeps its exact stored form.
            crate::off_path::governance::runtime::raw_recovery_identify_handoffs(
                &payload,
                &preserved.handoffs,
                |child, index| context.identify(event.operation_id, child, index),
            )
        };
        let (quarantined, unknown) = if event.state == RecoveryState::Intent {
            let payload = Self::quarantined_raw_payload(event).map_err(|error| {
                crate::governance::rendered_error(RecoveryError::Invalid, error)
            })?;
            let unknown = event.checkpoint(RecoveryState::LandedUnknown, normalize(payload)?)?;
            (Some(unknown.clone()), unknown)
        } else {
            (None, event.clone())
        };
        let (actor, reason) = crate::off_path::governance::ledger::operator_provenance(
            &resolution.actor,
            &resolution.reason,
        );
        let verdict = RawVerdict {
            landed,
            expected_revision: resolution.expected_revision,
            sender_quiesced: resolution.sender_quiesced,
            backend_quiesced: resolution.backend_quiesced,
            actor,
            reason,
        };
        let payload = Self::raw_verdict_payload(&unknown, verdict)?;
        let state = if landed {
            RecoveryState::VerdictLanded
        } else {
            RecoveryState::VerdictNotLanded
        };
        let decided = unknown.checkpoint(state, normalize(payload)?)?;
        Ok(match quarantined {
            Some(quarantined) => vec![quarantined, decided],
            None => vec![decided],
        })
    }
}

/// One flush's readonly proofs. No foreign ownership or event history is cached.
#[derive(Default)]
pub(super) struct ForeignSettledSnapshot {
    descriptors: std::collections::BTreeSet<([u8; 16], [u8; 32])>,
}
impl ForeignSettledSnapshot {
    fn excludes(&self, parent: [u8; 16], child: &RecoveryChild) -> bool {
        fingerprint(b"busbar.recovery.settled-descriptor.v1\0", child)
            .is_ok_and(|digest| self.descriptors.contains(&(parent, digest)))
    }
}
impl RecoveryChild {
    fn intent_with_origin(&self, origin: &RecoveryOrigin) -> RecordStoreResult<RecoveryEvent> {
        // The template is extended as a tree so every field keeps its exact stored form.
        let payload = crate::off_path::governance::runtime::raw_recovery_stamp_origin(
            &self.payload,
            origin,
            invalid_dyn,
        )?;
        Ok(RecoveryEvent {
            operation_id: self.operation_id,
            revision: 0,
            previous_event: None,
            kind: self.kind,
            body_fingerprint: self.body_fingerprint,
            state: RecoveryState::Intent,
            first_sent_at_ms: self.first_sent_at_ms,
            payload,
        })
    }
}
impl GovState {
    /// Called only by the cold flusher before any shard lock. Failed proof leaves
    pub(super) async fn capture_foreign_settled_snapshot(&self) -> ForeignSettledSnapshot {
        let mut snapshot = ForeignSettledSnapshot::default();
        if !self.recovery_enabled() {
            return snapshot;
        }
        for parent in self.selected_recovery_events() {
            let Ok(links) = decode::<Links>(&parent.payload) else {
                continue;
            };
            for child in links.handoffs {
                if child.kind != RecoveryKind::Usage
                    || self.recovery_event(child.operation_id).is_some()
                {
                    continue;
                }
                let Ok(Some(receipt)) = self.observed_child_receipt(&parent, &child).await else {
                    continue;
                };
                if self
                    .verify_settled_descriptor(&parent, &child, &receipt)
                    .await
                    .is_err()
                    || !matches!(
                        self.recovery_children_settled_inner(&receipt, true).await,
                        Ok(true)
                    )
                {
                    continue;
                }
                if let Ok(digest) = fingerprint(b"busbar.recovery.settled-descriptor.v1\0", &child)
                {
                    snapshot.descriptors.insert((parent.operation_id, digest));
                }
            }
        }
        snapshot
    }
    async fn verify_settled_descriptor(
        &self,
        parent: &RecoveryEvent,
        descriptor: &RecoveryChild,
        receipt: &RecoveryEvent,
    ) -> RecordStoreResult<()> {
        if receipt.state != RecoveryState::Settled
            || receipt.kind != descriptor.kind
            || receipt.body_fingerprint != descriptor.body_fingerprint
            || receipt.first_sent_at_ms != descriptor.first_sent_at_ms
        {
            return Err(invalid("settled descriptor identity differs"));
        }
        let origin = receipt
            .origin_reference()
            .map_err(invalid)?
            .ok_or_else(|| invalid("settled child has no origin"))?;
        if origin.operation_id != parent.operation_id {
            return Err(invalid("settled child belongs to another parent"));
        }

        self.verify_external_recovery_origin(&descriptor.intent_with_origin(&origin)?)
            .await
    }
}
