// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A frozen legacy Applied decision is not a native executable receipt. This
//! immutable disposition authorizes the existing current-owner adoption path;
//! original selected heads and journal frames remain unchanged.
use super::*;
use crate::governance::recovery::MigratedChildContext;
use crate::governance::{recovery::RecoveryKind, GovState};
use crate::persistence::facade::{LogicalClaim, LogicalId};
use busbar_contract::persistence::{
    Candidate as NativeCandidate, Mutation, PreparedCandidate, CANDIDATE_VERSION,
};
use sha2::{Digest, Sha256};

const IMPORTED: NamespaceId = NamespaceId(*b"busbar.recimp1\0\0");
const CHILD_CONTEXT: NamespaceId = NamespaceId(*b"busbar.recctx1\0\0");

pub(super) fn guards_digest(guards: &[Predicate]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"busbar.recovery.adoption-guards/1\0");
    for guard in guards {
        digest.update(guard.address.namespace);
        digest.update((guard.address.key.len() as u64).to_be_bytes());
        digest.update(&guard.address.key);
        match &guard.expected {
            ExpectedValue::Absent => digest.update([0]),
            ExpectedValue::Exact(value) => {
                digest.update([1]);
                digest.update((value.expose(&crate::seal::lend()).len() as u64).to_be_bytes());
                digest.update(value.expose(&crate::seal::lend()));
            }
        }
    }
    digest.finalize().into()
}
pub(super) fn copy_guards(guards: &[Predicate]) -> Vec<Predicate> {
    guards
        .iter()
        .map(|guard| Predicate {
            address: guard.address.clone(),
            expected: match &guard.expected {
                ExpectedValue::Absent => ExpectedValue::Absent,
                ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
            },
        })
        .collect()
}

/// Stable facts supplied only after the migration provider checks its actual
/// native source fence, complete original ancestry, and matching old receipt.
/// A fresh fence challenge is deliberately not part of the immutable row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedImportEvidence {
    pub source_dataset: [u8; 16],
    pub source_snapshot: [u8; 16],
    pub source_content_digest: [u8; 32],
    pub source_schema_digest: [u8; 32],
    pub upgrade: [u8; 16],
    pub fence_enforcement: [u8; 32],
    pub route: [u8; 32],
    pub receipt_evidence: [u8; 32],
    pub historical_body_digest: [u8; 32],
    pub recovery_closure_digest: [u8; 32],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppliedProof {
    initial: RecoveryEvent,
    selected: RecoveryEvent,
    original_head: Vec<u8>,
    evidence: AppliedImportEvidence,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disposition {
    version: u8,
    proof: AppliedProof,
    digest: [u8; 32],
}
fn imported_address(operation: &[u8; 16]) -> Address {
    Address {
        namespace: IMPORTED.0,
        key: operation.to_vec(),
    }
}
pub fn applied_disposition_authorizes(address: &Address) -> bool {
    address.namespace == IMPORTED.0
        && address.key.len() == 16
        && address.key.iter().any(|byte| *byte != 0)
}
fn validate_original(event: &RecoveryEvent) -> Result<(), RecoveryError> {
    let checked = match event.kind {
        RecoveryKind::Usage => GovState::legacy_usage_values(event).map(|_| ()),
        RecoveryKind::Metering => GovState::legacy_metering_values(event).map(|_| ()),
        RecoveryKind::Correction => GovState::legacy_correction_fingerprint(event).map(|_| ()),
    };
    checked.map_err(invalid)
}
impl Disposition {
    fn checked(proof: AppliedProof) -> Result<Self, RecoveryError> {
        proof.initial.follows(None)?;
        let initial = &proof.initial;
        let selected = &proof.selected;
        if initial.operation_id == [0; 16]
            || initial.operation_id != selected.operation_id
            || initial.kind != selected.kind
            || initial.body_fingerprint != selected.body_fingerprint
            || initial.first_sent_at_ms != selected.first_sent_at_ms
            || (selected.revision == 0 && selected != initial)
            || (selected.revision > 0 && selected.previous_event.is_none())
            || !matches!(
                selected.state,
                RecoveryState::Intent
                    | RecoveryState::Applied
                    | RecoveryState::LandedUnknown
                    | RecoveryState::VerdictLanded
            )
        {
            return Err(invalid(
                "imported Applied decision differs from original custody",
            ));
        }
        validate_original(initial)?;
        validate_original(selected)?;
        let head: Head = serde_json::from_slice(&proof.original_head).map_err(invalid)?;
        if head.version != 1
            || head.node == 0
            || head.sequence == 0
            || head.revision != selected.revision
            || head.event_digest != selected.fingerprint()?
        {
            return Err(invalid(
                "imported Applied decision names another selected head",
            ));
        }
        let evidence = &proof.evidence;
        if evidence.source_dataset == [0; 16]
            || evidence.source_snapshot == [0; 16]
            || evidence.upgrade == [0; 16]
            || [
                evidence.source_content_digest,
                evidence.source_schema_digest,
                evidence.fence_enforcement,
                evidence.route,
                evidence.receipt_evidence,
                evidence.historical_body_digest,
                evidence.recovery_closure_digest,
            ]
            .contains(&[0; 32])
        {
            return Err(invalid(
                "imported Applied decision lacks checked source/fence/receipt facts",
            ));
        }
        let mut hash = Sha256::new();
        hash.update(b"busbar.recovery.imported-applied/1\0");
        hash.update(serde_json::to_vec(&proof).map_err(invalid)?);
        Ok(Self {
            version: 1,
            proof,
            digest: hash.finalize().into(),
        })
    }
    fn decode(address: &Address, bytes: &[u8]) -> Result<Self, RecoveryError> {
        let value: Self = serde_json::from_slice(bytes).map_err(invalid)?;
        let checked = Self::checked(value.proof.clone())?;
        if value != checked
            || !applied_disposition_authorizes(address)
            || address.key != value.proof.initial.operation_id
        {
            return Err(invalid("invalid imported Applied disposition"));
        }
        Ok(value)
    }
    fn resolution(&self, selected: &RecoveryEvent) -> RecoveryResolution {
        RecoveryResolution {
            operation_id: selected.operation_id,
            body_fingerprint: selected.body_fingerprint,
            expected_revision: selected.revision,
            verdict: RecoveryVerdict::Landed,
            sender_quiesced: true,
            backend_quiesced: true,
            actor: "core migration".into(),
            reason: format!(
                "verified frozen Applied receipt {}",
                hex::encode(self.digest)
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChildDescriptor {
    version: u8,
    disposition: [u8; 32],
    context: MigratedChildContext,
}
impl ChildDescriptor {
    fn new(disposition: [u8; 32], created_at_ms: u64) -> Self {
        let mut digest = Sha256::new();
        digest.update(b"busbar.recovery.imported-child-seed/1\0");
        digest.update(disposition);
        Self {
            version: 1,
            disposition,
            context: MigratedChildContext {
                seed: digest.finalize().into(),
                created_at_ms,
            },
        }
    }
    fn decode(bytes: &Secret<Vec<u8>>, disposition: [u8; 32]) -> Result<Self, RecoveryError> {
        let descriptor: Self =
            serde_json::from_slice(bytes.expose(&crate::seal::lend())).map_err(invalid)?;
        if descriptor != Self::new(disposition, descriptor.context.created_at_ms) {
            return Err(invalid(
                "migrated child descriptor differs from disposition",
            ));
        }
        Ok(descriptor)
    }
}

impl StoreRecovery {
    /// Fix native birth time once before planning any children. An Unknown
    /// retains the original native attempt; the next call retries it before
    /// obtaining another clock observation. Competing processes always read
    /// the winning immutable descriptor rather than retaining their proposal.
    async fn imported_context(
        &self,
        disposition: &Disposition,
        disposition_raw: &Secret<Vec<u8>>,
    ) -> Result<(ChildDescriptor, Predicate), RecoveryError> {
        let operation = disposition.proof.initial.operation_id;
        self.context_for(
            disposition.digest,
            operation,
            &Secret::new(disposition.proof.original_head.clone()),
            &[Predicate {
                address: imported_address(&operation),
                expected: ExpectedValue::Exact(disposition_raw.clone()),
            }],
        )
        .await
    }
    async fn context_for(
        &self,
        provenance: [u8; 32],
        operation: [u8; 16],
        selected_head: &Secret<Vec<u8>>,
        guards: &[Predicate],
    ) -> Result<(ChildDescriptor, Predicate), RecoveryError> {
        let context_address = Address {
            namespace: CHILD_CONTEXT.0,
            key: operation.to_vec(),
        };
        let claim = self
            .store
            .claim_logical(
                LogicalId {
                    namespace: CHILD_CONTEXT.0,
                    operation,
                },
                provenance,
            )
            .map_err(unavailable)?;
        let permit = match claim {
            LogicalClaim::Prepare(permit) => Some(permit),
            LogicalClaim::Retained(id) => {
                applied(WriteResult::Submitted(
                    self.store.retry(id).await.map_err(unavailable)?,
                ))?;
                None
            }
            LogicalClaim::Busy => {
                return Err(unavailable("migrated child descriptor has an active owner"));
            }
        };
        let existing = read(&self.store, vec![context_address.clone()])
            .await?
            .pop()
            .flatten();
        if existing.is_none() {
            let permit = permit.ok_or_else(|| {
                unavailable("migrated child descriptor retry requires reconciliation")
            })?;
            let clock = self
                .store
                .backend()
                .clock(self.store.info().dataset)
                .await
                .map_err(unavailable)?;
            if clock.authority != self.store.info().clock_authority {
                return Err(invalid("migrated child descriptor clock authority differs"));
            }
            let timestamp = clock
                .unix_seconds
                .checked_mul(1000)
                .ok_or_else(|| invalid("migrated child clock overflow"))?;
            let descriptor = ChildDescriptor::new(provenance, timestamp);
            let mut predicates = vec![
                Predicate {
                    address: context_address.clone(),
                    expected: ExpectedValue::Absent,
                },
                Predicate {
                    address: super::address(&operation),
                    expected: ExpectedValue::Exact(selected_head.clone()),
                },
            ];
            predicates.extend(guards.iter().map(|guard| Predicate {
                address: guard.address.clone(),
                expected: match &guard.expected {
                    ExpectedValue::Absent => ExpectedValue::Absent,
                    ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
                },
            }));
            let candidate = PreparedCandidate::new(NativeCandidate {
                id: self.store.next_id().map_err(unavailable)?,
                codec: CANDIDATE_VERSION,
                predicates,
                mutations: vec![Mutation::Put {
                    address: context_address.clone(),
                    value: Secret::new(serde_json::to_vec(&descriptor).map_err(invalid)?),
                }],
                time: None,
                result: Secret::default(),
            })
            .map_err(|_| invalid("invalid migrated child descriptor candidate"))?;
            applied(WriteResult::Submitted(
                permit.submit(candidate).await.map_err(unavailable)?,
            ))?;
        }
        let winner = read(&self.store, vec![context_address.clone()])
            .await?
            .pop()
            .flatten()
            .ok_or_else(|| {
                RecoveryError::Conflict("migrated child descriptor not selected".into())
            })?;
        let descriptor = ChildDescriptor::decode(&winner, provenance)?;
        Ok((
            descriptor,
            Predicate {
                address: context_address,
                expected: ExpectedValue::Exact(winner),
            },
        ))
    }

    pub(super) async fn adopt_imported(&self) -> Result<(), RecoveryError> {
        let retained = self
            .state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .adoptions
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for pending in retained {
            let proof = &pending.proof;
            let resolution = RecoveryResolution {
                operation_id: proof.operation_id,
                body_fingerprint: proof.body_fingerprint,
                expected_revision: proof.foreign_head.revision,
                verdict: if proof.landed {
                    RecoveryVerdict::Landed
                } else {
                    RecoveryVerdict::NotLanded
                },
                sender_quiesced: proof.sender_quiesced,
                backend_quiesced: proof.backend_quiesced,
                actor: proof.actor.clone(),
                reason: proof.reason.clone(),
            };
            self.adopt_at_with(&resolution, &pending.transitions, &pending.guards)
                .await?;
        }
        for (operation, tip) in heads(&self.store).await? {
            let imported = imported_address(&operation);
            let Some(raw) = read(&self.store, vec![imported.clone()])
                .await?
                .pop()
                .flatten()
            else {
                continue;
            };
            let disposition = Disposition::decode(&imported, raw.expose(&crate::seal::lend()))?;
            let original: Head =
                serde_json::from_slice(&disposition.proof.original_head).map_err(invalid)?;
            if tip != original {
                // A previous real adoption is reusable only through actual
                // selected ancestry, never from fabricated quiescence facts.
                let resolution = disposition.resolution(&disposition.proof.selected);
                let mut history = History::new(&self.store);
                let mut attested = false;
                let selection = history
                    .selection(&operation, &tip, |_, candidate| {
                        attested |= candidate.adoption.as_ref().is_some_and(|proof| {
                            proof.foreign_head == original && proof.matches(&resolution)
                        });
                        Ok(())
                    })
                    .await?;
                history.finish().await?;
                if !attested || selection.initial != disposition.proof.initial {
                    return Err(invalid(
                        "migrated Applied head lacks its selected adoption ancestry",
                    ));
                }
                continue;
            }
            let selection = self.selection(&operation, &tip).await?;
            if selection.initial != disposition.proof.initial
                || selection.selected != disposition.proof.selected
            {
                return Err(invalid(
                    "migrated Applied disposition differs from original selected ancestry",
                ));
            }
            let (descriptor, context_guard) = self.imported_context(&disposition, &raw).await?;
            let resolution = disposition.resolution(&selection.selected);
            let transitions = match selection.selected.kind {
                RecoveryKind::Correction => {
                    GovState::stage_foreign_correction_verdict(&selection.selected, &resolution)?
                }
                RecoveryKind::Usage | RecoveryKind::Metering => {
                    GovState::stage_imported_raw_verdict(
                        &selection.selected,
                        &resolution,
                        &descriptor.context,
                    )?
                }
            };
            self.adopt_at_with(
                &resolution,
                &transitions,
                &[
                    Predicate {
                        address: imported,
                        expected: ExpectedValue::Exact(raw),
                    },
                    context_guard,
                ],
            )
            .await?;
        }
        self.adopt_native_foreign().await
    }

    async fn retire_native_owner(&self, node: u64) -> Result<Vec<Predicate>, RecoveryError> {
        use crate::persistence::boot_identity::WriterRetirement;
        loop {
            let mut history = History::new(&self.store);
            let proof = history.proof(node).await?;
            let (epoch, writer) = proof.owner_identity().ok_or_else(|| {
                unavailable("current recovery journal has no native owner identity")
            })?;
            match self
                .retirements
                .retire(&self.store, epoch, writer)
                .await
                .map_err(unavailable)?
            {
                WriterRetirement::Retired(mut guards) => {
                    // Re-read after closure: a live writer may have appended or
                    // transferred custody while its lease was still running.
                    let mut closed = History::new(&self.store);
                    let current = closed.proof(node).await?;
                    if current.owner_identity() != Some((epoch, writer)) {
                        continue;
                    }
                    guards.extend(
                        StoreJournal::new(&self.store, node)
                            .map_err(unavailable)?
                            .selected_predicates(&current)
                            .map_err(unavailable)?,
                    );
                    closed.finish().await?;
                    return Ok(guards);
                }
                WriterRetirement::Live { retry_at_ms } => {
                    let clock = self
                        .store
                        .backend()
                        .clock(self.store.info().dataset)
                        .await
                        .map_err(unavailable)?;
                    if clock.authority != self.store.info().clock_authority {
                        return Err(invalid("writer retirement clock authority changed"));
                    }
                    let delay = retry_at_ms
                        .saturating_sub(clock.unix_seconds.saturating_mul(1000))
                        .clamp(50, 1000);
                    tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                }
                WriterRetirement::Pending => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await
                }
            }
        }
    }

    async fn adopt_native_foreign(&self) -> Result<(), RecoveryError> {
        use busbar_contract::records::{dedupe::Dedupe, OpId};
        for (operation, scanned_tip) in heads(&self.store).await? {
            if scanned_tip.node == self.node {
                continue;
            }
            let preliminary = self.selection(&operation, &scanned_tip).await?;
            if preliminary.selected.state == RecoveryState::Settled {
                continue;
            }
            let mut guards = self.retire_native_owner(scanned_tip.node).await?;
            let (tip, raw_head) = head(&self.store, &operation)
                .await?
                .ok_or_else(|| invalid("native recovery selection disappeared"))?;
            if tip.node == self.node {
                continue;
            }
            if tip.node != scanned_tip.node {
                return Err(RecoveryError::Conflict(
                    "native recovery ownership changed during retirement".into(),
                ));
            }
            let selection = self.selection(&operation, &tip).await?;
            let event = &selection.selected;
            let digest = match event.kind {
                RecoveryKind::Usage => {
                    let cells = GovState::legacy_usage_values(event).map_err(invalid)?;
                    let cells = cells
                        .iter()
                        .map(|(bucket, window, delta)| (bucket.as_str(), *window, delta.clone()))
                        .collect::<Vec<_>>();
                    *Dedupe::usage(&cells).body()
                }
                RecoveryKind::Metering => {
                    *Dedupe::metering(&GovState::legacy_metering_values(event).map_err(invalid)?)
                        .body()
                }
                RecoveryKind::Correction => {
                    GovState::canonical_correction_receipt_digest(event).map_err(invalid)?
                }
            };
            let (receipt, receipt_guard) = self
                .store
                .ledger()
                .recovery_receipt(OpId(operation), digest)
                .await
                .map_err(invalid)?;
            let known = match event.state {
                RecoveryState::Applied | RecoveryState::VerdictLanded => Some(true),
                RecoveryState::ConditionConflict | RecoveryState::VerdictNotLanded => Some(false),
                RecoveryState::Intent | RecoveryState::LandedUnknown => None,
                RecoveryState::Settled => continue,
            };
            let from_receipt = receipt.map(|result| result == 0);
            if event.kind != RecoveryKind::Correction && receipt == Some(1) {
                return Err(invalid(
                    "raw recovery receipt has an unsupported conditional result",
                ));
            }
            if known
                .zip(from_receipt)
                .is_some_and(|(known, receipt)| known != receipt)
            {
                return Err(invalid(
                    "native selected verdict contradicts its canonical receipt",
                ));
            }
            let landed = known.or(from_receipt).unwrap_or(false);
            guards.push(receipt_guard);
            let resolution = RecoveryResolution {
                operation_id: operation,
                body_fingerprint: event.body_fingerprint,
                expected_revision: event.revision,
                verdict: if landed {
                    RecoveryVerdict::Landed
                } else {
                    RecoveryVerdict::NotLanded
                },
                sender_quiesced: true,
                backend_quiesced: true,
                actor: "core cold recovery".into(),
                reason: "native writer permanently retired; canonical operation receipt checked"
                    .into(),
            };
            let imported = imported_address(&operation);
            let imported_raw = read(&self.store, vec![imported.clone()])
                .await?
                .pop()
                .flatten();
            let provenance = if let Some(raw) = imported_raw {
                let disposition = Disposition::decode(&imported, raw.expose(&crate::seal::lend()))?;
                guards.push(Predicate {
                    address: imported,
                    expected: ExpectedValue::Exact(raw),
                });
                disposition.digest
            } else {
                let mut hash = Sha256::new();
                hash.update(b"busbar.recovery.native-child-custody/1\0");
                hash.update(self.store.info().dataset.0);
                hash.update(selection.initial.fingerprint()?);
                hash.finalize().into()
            };
            let (descriptor, context_guard) = self
                .context_for(provenance, operation, &raw_head, &guards)
                .await?;
            guards.push(context_guard);
            let transitions = match event.kind {
                RecoveryKind::Correction => {
                    GovState::stage_foreign_correction_verdict(event, &resolution)?
                }
                RecoveryKind::Usage | RecoveryKind::Metering => {
                    GovState::stage_imported_raw_verdict(event, &resolution, &descriptor.context)?
                }
            };
            self.adopt_at_with(&resolution, &transitions, &guards)
                .await?;
        }
        Ok(())
    }
}

/// Emit BOTH the unchanged original selected head and its immutable disposition
/// in one migration candidate. This never writes a native operation receipt or
/// claims that an unsent remainder/authorized child is already settled.
type ImportRows = Vec<(Address, Secret<Vec<u8>>)>;
pub fn applied_disposition_rows(
    initial: &RecoveryEvent,
    selected: &RecoveryEvent,
    original_head: &[u8],
    evidence: &AppliedImportEvidence,
) -> Result<ImportRows, RecoveryError> {
    let disposition = Disposition::checked(AppliedProof {
        initial: initial.clone(),
        selected: selected.clone(),
        original_head: original_head.to_vec(),
        evidence: evidence.clone(),
    })?;
    Ok(vec![
        (
            super::address(&selected.operation_id),
            Secret::new(original_head.to_vec()),
        ),
        (
            imported_address(&selected.operation_id),
            Secret::new(serde_json::to_vec(&disposition).map_err(invalid)?),
        ),
    ])
}
