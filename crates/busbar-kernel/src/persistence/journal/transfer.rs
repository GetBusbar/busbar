// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Explicit host-only journal custody handover after a dataset cold cutover.

use super::*;
use busbar_contract::persistence::control;

const HANDOVER_MAGIC: &[u8; 8] = b"BBJXFER1";

/// Audit evidence supplied by the host recovery owner, never a replacement for
/// the native dataset/writer fence. It conveys no business replay permission.
pub(crate) struct Handover<'a> {
    pub(crate) actor: [u8; 16],
    pub(crate) reason: &'a str,
    pub(crate) evidence_digest: [u8; 32],
}

impl StoreJournal<'_> {
    /// Explicitly transfer only append custody of a fully verified journal.
    /// An old dataset writer epoch is irreversibly fenced by the native root;
    /// a same-epoch execution-retirement floor cannot authorize this operation.
    /// Unknown/cancellation retains one exact candidate before any new reads.
    pub(crate) async fn cold_transfer(
        &self,
        previous: &VerifiedHead,
        handover: Handover<'_>,
    ) -> Result<WriteResult> {
        if previous.dataset != self.store.info().dataset || previous.node != self.node {
            return Err(Error::Authority);
        }
        let old_owner = previous.owner.as_ref().ok_or(Error::Authority)?;
        if !valid_owner(old_owner) || previous.selected.is_none() || previous.head.count == 0 {
            return Err(Error::Authority);
        }
        let old_epoch = u64::from_le_bytes(
            old_owner.expose(&crate::seal::lend())[8..16]
                .try_into()
                .map_err(|_| Error::Corrupt)?,
        );
        let authority = self.store.authority()?;
        if old_epoch >= authority.writer_epoch {
            return Err(Error::Authority);
        }
        if handover.actor == [0; 16]
            || handover.reason.trim().is_empty()
            || handover.evidence_digest == [0; 32]
        {
            return Err(Error::Invalid);
        }
        // This is a separately admitted small custody record, never a new
        // protocol limit on the original historical frame representation.
        let capacity = 8usize + 16 + 8 + 56 + 32 + 32 + 16 + 8 + 32;
        let capacity = capacity
            .checked_add(handover.reason.len())
            .ok_or(Error::Overflow)?;
        if capacity > self.store.limits().scan_bytes {
            return Err(Error::Budget);
        }
        let new_owner = owner_bytes(authority);
        let mut metadata = Vec::new();
        metadata
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Budget)?;
        metadata.extend_from_slice(HANDOVER_MAGIC);
        metadata.extend_from_slice(&previous.dataset.0);
        metadata.extend_from_slice(&self.node.to_be_bytes());
        metadata.extend_from_slice(previous.head.encode().expose(&crate::seal::lend()));
        metadata.extend_from_slice(old_owner.expose(&crate::seal::lend()));
        metadata.extend_from_slice(new_owner.expose(&crate::seal::lend()));
        metadata.extend_from_slice(&handover.actor);
        metadata.extend_from_slice(&(handover.reason.len() as u64).to_le_bytes());
        metadata.extend_from_slice(handover.reason.as_bytes());
        metadata.extend_from_slice(&handover.evidence_digest);
        let metadata = Secret::new(metadata);
        let mut digest = Sha256::new();
        digest.update(b"busbar.journal.cold-transfer/1\0");
        digest.update(metadata.expose(&crate::seal::lend()));
        let mut operation = [0; 16];
        operation[..8].copy_from_slice(&self.node.to_be_bytes());
        let permit = match self.store.claim_logical(
            LogicalId {
                namespace: self.namespace.0,
                operation,
            },
            digest.finalize().into(),
        )? {
            LogicalClaim::Prepare(permit) => permit,
            LogicalClaim::Retained(id) => {
                return Ok(WriteResult::Submitted(self.store.retry(id).await?));
            }
            LogicalClaim::Busy => return Ok(WriteResult::Busy),
        };

        // Prove the cold fence from native authoritative state, rather than
        // accepting a caller boolean, a lease timeout, or an old retired floor.
        let root_address = Address {
            namespace: control::NAMESPACE.0,
            key: control::DATASET_KEY.to_vec(),
        };
        let writer_address = Address {
            namespace: control::NAMESPACE.0,
            key: control::writer_key(authority.writer).to_vec(),
        };
        let mut rows = self
            .read(vec![root_address.clone(), writer_address.clone()])
            .await?;
        let writer_raw = rows.pop().flatten().ok_or(Error::Authority)?;
        let root_raw = rows.pop().flatten().ok_or(Error::Authority)?;
        let root = control::Dataset::decode(root_raw.expose(&crate::seal::lend()))
            .ok_or(Error::Corrupt)?;
        let writer = control::Writer::decode(writer_raw.expose(&crate::seal::lend()))
            .ok_or(Error::Corrupt)?;
        if root.id != previous.dataset
            || root.writer_epoch != authority.writer_epoch
            || root.writer_epoch <= old_epoch
            || !writer.admits(authority.execution_epoch)
            || self.store.authority()? != authority
        {
            return Err(Error::Authority);
        }
        let handover_address = self.address(b'T', authority.writer_epoch);
        let candidate = PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates: vec![
                self.selected_head_predicate(previous)?,
                Predicate {
                    address: self.address(b'O', 0),
                    expected: ExpectedValue::Exact(old_owner.clone()),
                },
                Predicate {
                    address: root_address,
                    expected: ExpectedValue::Exact(root_raw),
                },
                Predicate {
                    address: writer_address,
                    expected: ExpectedValue::Exact(writer_raw),
                },
                Predicate {
                    address: handover_address.clone(),
                    expected: ExpectedValue::Absent,
                },
            ],
            mutations: vec![
                Mutation::Put {
                    address: self.address(b'O', 0),
                    value: new_owner,
                },
                Mutation::Put {
                    address: handover_address,
                    value: metadata,
                },
            ],
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)?;
        Ok(WriteResult::Submitted(permit.submit(candidate).await?))
    }
}
