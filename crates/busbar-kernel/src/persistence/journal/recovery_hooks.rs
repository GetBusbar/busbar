// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Trusted kernel recovery-owner hooks. These do not interpret accounting
//! events, ancestry, adoption attestations, or business recovery verdicts.

use super::*;
use busbar_contract::persistence::control;
use busbar_kernel_wal::{Entry, QuarantineNote, RecordClass};

pub(crate) struct Selection {
    pub(crate) operation_id: [u8; 16],
    pub(crate) address: Address,
    pub(crate) expected: ExpectedValue,
    pub(crate) value: Secret<Vec<u8>>,
}

impl<'a> StoreJournal<'a> {
    /// Historical verifier with constant retained state. A gap searches original
    /// frames for its existing quarantine authority; later ChainBreak records
    /// remain usable without buffering the whole history. Only finish grants a
    /// complete proof. No historical hash or sequence is reconstructed.
    pub(crate) async fn historical_replay(&self) -> Result<Replay<'_, 'a>> {
        let mut replay = self.replay().await?;
        replay.historical = true;
        Ok(replay)
    }

    pub(crate) fn selected_predicates(&self, proof: &VerifiedHead) -> Result<Vec<Predicate>> {
        Ok(vec![
            self.selected_head_predicate(proof)?,
            Predicate {
                address: self.address(b'O', 0),
                expected: proof.owner.as_ref().map_or(ExpectedValue::Absent, |value| {
                    ExpectedValue::Exact(value.clone())
                }),
            },
        ])
    }

    pub(crate) fn owned_predicates(&self, proof: &VerifiedHead) -> Result<Vec<Predicate>> {
        let owner = owner_bytes(self.store.authority()?);
        let empty_unclaimed =
            proof.owner.is_none() && proof.selected.is_none() && proof.head == Head::default();
        if !empty_unclaimed && proof.owner.as_ref() != Some(&owner) {
            return Err(Error::Authority);
        }
        self.selected_predicates(proof)
    }

    /// Recheck a read-only complete prefix proof without granting append or
    /// replay ownership. A later append changes H and requires a fresh proof.
    pub(crate) async fn confirm_selected(&self, proof: &VerifiedHead) -> Result<()> {
        let predicates = self.selected_predicates(proof)?;
        let values = self
            .read(
                predicates
                    .iter()
                    .map(|predicate| predicate.address.clone())
                    .collect(),
            )
            .await?;
        if predicates
            .iter()
            .zip(values)
            .any(|(predicate, value)| !matches_value(&predicate.expected, &value))
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    /// Read-only owned confirmation requires native live execution admission;
    /// equality to a cached local writer identity cannot prove that an old
    /// dataset epoch is still open after a cold cutover.
    pub(crate) async fn confirm_owned(&self, proof: &VerifiedHead) -> Result<()> {
        self.confirm_owned_with(proof, &[]).await
    }

    /// Include the recovery owner's selected row or scan-generation guards in
    /// the same authoritative observation as journal custody and admission.
    pub(crate) async fn confirm_owned_with(
        &self,
        proof: &VerifiedHead,
        extra: &[Predicate],
    ) -> Result<()> {
        let mut predicates = self.owned_predicates(proof)?;
        predicates
            .try_reserve_exact(extra.len())
            .map_err(|_| Error::Budget)?;
        predicates.extend(extra.iter().map(|predicate| Predicate {
            address: predicate.address.clone(),
            expected: match &predicate.expected {
                ExpectedValue::Absent => ExpectedValue::Absent,
                ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
            },
        }));
        let authority = self.store.authority()?;
        let mut addresses: Vec<_> = predicates
            .iter()
            .map(|predicate| predicate.address.clone())
            .collect();
        addresses.push(Address {
            namespace: control::NAMESPACE.0,
            key: control::DATASET_KEY.to_vec(),
        });
        addresses.push(Address {
            namespace: control::NAMESPACE.0,
            key: control::writer_key(authority.writer).to_vec(),
        });
        let mut values = self.read(addresses).await?;
        let writer = values.pop().flatten().ok_or(Error::Authority)?;
        let root = values.pop().flatten().ok_or(Error::Authority)?;
        let writer =
            control::Writer::decode(writer.expose(&crate::seal::lend())).ok_or(Error::Corrupt)?;
        let root =
            control::Dataset::decode(root.expose(&crate::seal::lend())).ok_or(Error::Corrupt)?;
        if root.id != proof.dataset
            || root.writer_epoch != authority.writer_epoch
            || !writer.admits(authority.execution_epoch)
            || self.store.authority()? != authority
            || predicates
                .iter()
                .zip(values)
                .any(|(predicate, value)| !matches_value(&predicate.expected, &value))
        {
            return Err(Error::Authority);
        }
        Ok(())
    }

    async fn original_at(&self, ordinal: u64) -> Result<(JournalRecord, Secret<Vec<u8>>)> {
        let value = self
            .read(vec![self.address(b'R', ordinal)])
            .await?
            .pop()
            .flatten()
            .ok_or(Error::Corrupt)?;
        let bytes = value.expose(&crate::seal::lend());
        if bytes.len() > self.store.limits().scan_bytes {
            return Err(Error::Budget);
        }
        Ok((decode_record(self.node, bytes)?, value))
    }

    pub(super) async fn bridge_covers(
        &self,
        proof: &VerifiedHead,
        previous: Head,
        current: &JournalRecord,
    ) -> Result<bool> {
        if current.node_seq <= previous.sequence {
            return Ok(false);
        }
        for ordinal in 1..=proof.head.count {
            let (record, _) = self.original_at(ordinal).await?;
            if record.class != RecordClass::ChainBreak {
                continue;
            }
            let Some(bridge) = QuarantineNote::read(&record.body).and_then(|note| note.bridge)
            else {
                continue;
            };
            if bridge.before.0 != self.node || current.node_seq <= bridge.before.1 {
                continue;
            }
            let named_after = bridge.after == Some(current.identity());
            if named_after && bridge.before == (self.node, previous.sequence) {
                return Ok(true);
            }
            if !(named_after || bridge.after.is_none()) || bridge.before.1 > previous.sequence {
                continue;
            }
            for anchor_ordinal in 1..=previous.count {
                let (anchor, _) = self.original_at(anchor_ordinal).await?;
                if anchor.identity() == bridge.before && anchor.hash == current.prev_hash {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    async fn locate_verified_record(
        &self,
        proof: &VerifiedHead,
        sequence: u64,
    ) -> Result<(u64, Record)> {
        self.selected_head_predicate(proof)?;
        if sequence == 0 || sequence > proof.head.sequence {
            return Err(Error::Invalid);
        }
        let mut replay = self.historical_replay().await?;
        let mut found = None;
        let mut ordinal = 0u64;
        while let Some(record) = replay.next().await? {
            ordinal = ordinal.checked_add(1).ok_or(Error::Overflow)?;
            if record.node_seq == sequence {
                found = Some((ordinal, record));
            }
        }
        let current = replay.finish()?;
        if current.dataset != proof.dataset
            || current.node != proof.node
            || current.head != proof.head
            || current.selected != proof.selected
            || current.owner != proof.owner
            || current.records_seal != proof.records_seal
        {
            return Err(Error::Corrupt);
        }
        found.ok_or(Error::Corrupt)
    }

    /// Lookup is scoped to a completed whole-node proof. The original ordinal
    /// and sealed identity must agree; an equivalent frame at another sequence
    /// is never accepted as evidence of this original record.
    pub(crate) async fn read_verified_record(
        &self,
        proof: &VerifiedHead,
        sequence: u64,
    ) -> Result<Record> {
        self.locate_verified_record(proof, sequence)
            .await
            .map(|(_, record)| record)
    }

    /// Use the unchanged WAL framing and digest recipe for a new host entry.
    /// The caller retains this exact original before awaiting append; sealing
    /// alone conveys no durability or permission to select a recovery verdict.
    pub(crate) fn seal(&self, proof: &VerifiedHead, entry: Entry) -> Result<Record> {
        self.selected_head_predicate(proof)?;
        let owner = owner_bytes(self.store.authority()?);
        if proof.owner.as_ref().is_some_and(|old| old != &owner) {
            return Err(Error::Authority);
        }
        if entry
            .body
            .len()
            .checked_add(busbar_kernel_wal::journal::JOURNAL_HEADER_BYTES)
            .ok_or(Error::Overflow)?
            > self.store.limits().scan_bytes
        {
            return Err(Error::Budget);
        }
        seal_record(self.node, proof.head, entry)
    }

    /// Seal and retain an entire adoption run before the caller first awaits.
    /// Its second record follows the first original frame, without advancing
    /// the selected journal head or claiming either frame has been persisted.
    pub(crate) fn seal_run(&self, proof: &VerifiedHead, entries: &[Entry]) -> Result<Vec<Record>> {
        self.selected_head_predicate(proof)?;
        let owner = owner_bytes(self.store.authority()?);
        if proof.owner.as_ref().is_some_and(|old| old != &owner) {
            return Err(Error::Authority);
        }
        if entries.is_empty() || entries.len() > self.store.limits().scan_items {
            return Err(Error::Budget);
        }
        let mut bytes = 0usize;
        for entry in entries {
            bytes = bytes
                .checked_add(entry.body.len())
                .and_then(|value| {
                    value.checked_add(busbar_kernel_wal::journal::JOURNAL_HEADER_BYTES)
                })
                .ok_or(Error::Overflow)?;
            if bytes > self.store.limits().scan_bytes {
                return Err(Error::Budget);
            }
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(entries.len())
            .map_err(|_| Error::Budget)?;
        let mut head = proof.head;
        for entry in entries {
            let record = seal_record(self.node, head, entry.clone())?;
            let decoded = decode_record(self.node, &record.body)?;
            head = advance(head, &decoded)?;
            records.push(record);
        }
        Ok(records)
    }

    /// Select already durable original candidates, including final-only
    /// selection of a two-record adoption. Domain ancestry/verdict validation
    /// remains the recovery owner's responsibility. One immutable candidate
    /// compares the full journal selection, custody and every original frame.
    pub(crate) async fn select_verified(
        &self,
        proof: &VerifiedHead,
        records: &[Record],
        selection: Selection,
    ) -> Result<WriteResult> {
        self.change_selection(proof, records, selection, false, &[])
            .await
    }

    pub(crate) async fn select_verified_with(
        &self,
        proof: &VerifiedHead,
        records: &[Record],
        selection: Selection,
        guards: &[Predicate],
    ) -> Result<WriteResult> {
        self.change_selection(proof, records, selection, false, guards)
            .await
    }

    /// Preserve a domain's exact selected-row deletion after audit confirmation;
    /// it has the same original-frame/custody guards and retained exact attempt
    /// as selection. This does not introduce a replacement tombstone schema.
    pub(crate) async fn delete_verified(
        &self,
        proof: &VerifiedHead,
        records: &[Record],
        operation_id: [u8; 16],
        address: Address,
        expected: ExpectedValue,
    ) -> Result<WriteResult> {
        self.change_selection(
            proof,
            records,
            Selection {
                operation_id,
                address,
                expected,
                value: Secret::default(),
            },
            true,
            &[],
        )
        .await
    }

    async fn change_selection(
        &self,
        proof: &VerifiedHead,
        records: &[Record],
        selection: Selection,
        delete: bool,
        guards: &[Predicate],
    ) -> Result<WriteResult> {
        self.selected_head_predicate(proof)?;
        if records.is_empty()
            || records.len() > self.store.limits().scan_items
            || selection.operation_id == [0; 16]
            || selection.address.namespace == self.namespace.0
            || selection.address.namespace == busbar_contract::persistence::control::NAMESPACE.0
        {
            return Err(Error::Invalid);
        }
        let mut digest = Sha256::new();
        digest.update(b"busbar.journal.recovery-selection/1\0");
        digest.update([u8::from(delete)]);
        digest.update(self.node.to_be_bytes());
        digest.update(proof.head.encode().expose(&crate::seal::lend()));
        if let Some(owner) = &proof.owner {
            digest.update(owner.expose(&crate::seal::lend()));
        }
        digest.update(selection.address.namespace);
        digest.update((selection.address.key.len() as u64).to_be_bytes());
        digest.update(&selection.address.key);
        match &selection.expected {
            ExpectedValue::Absent => digest.update([0]),
            ExpectedValue::Exact(value) => {
                digest.update([1]);
                digest.update((value.expose(&crate::seal::lend()).len() as u64).to_be_bytes());
                digest.update(value.expose(&crate::seal::lend()));
            }
        }
        digest.update((selection.value.expose(&crate::seal::lend()).len() as u64).to_be_bytes());
        digest.update(selection.value.expose(&crate::seal::lend()));
        if !guards.is_empty() {
            digest.update(b"guarded-selection/1\0");
            for guard in guards {
                digest.update(guard.address.namespace);
                digest.update((guard.address.key.len() as u64).to_be_bytes());
                digest.update(&guard.address.key);
                match &guard.expected {
                    ExpectedValue::Absent => digest.update([0]),
                    ExpectedValue::Exact(value) => {
                        digest.update([1]);
                        digest.update(
                            (value.expose(&crate::seal::lend()).len() as u64).to_be_bytes(),
                        );
                        digest.update(value.expose(&crate::seal::lend()));
                    }
                }
            }
        }
        for record in records {
            digest.update(record.node.to_be_bytes());
            digest.update(record.node_seq.to_be_bytes());
            digest.update((record.body.len() as u64).to_be_bytes());
            digest.update(&record.body);
        }
        let permit = match self.store.claim_logical(
            LogicalId {
                namespace: selection.address.namespace,
                operation: selection.operation_id,
            },
            digest.finalize().into(),
        )? {
            LogicalClaim::Prepare(permit) => permit,
            LogicalClaim::Retained(id) => {
                return Ok(WriteResult::Submitted(self.store.retry(id).await?));
            }
            LogicalClaim::Busy => return Ok(WriteResult::Busy),
        };
        let mut predicates = self.owned_predicates(proof)?;
        predicates.extend(guards.iter().map(|guard| Predicate {
            address: guard.address.clone(),
            expected: match &guard.expected {
                ExpectedValue::Absent => ExpectedValue::Absent,
                ExpectedValue::Exact(value) => ExpectedValue::Exact(value.clone()),
            },
        }));
        predicates
            .try_reserve_exact(records.len() + 1)
            .map_err(|_| Error::Budget)?;
        for record in records {
            let (ordinal, original) = self.locate_verified_record(proof, record.node_seq).await?;
            if original.identity() != record.identity() || original.body != record.body {
                return Err(Error::Corrupt);
            }
            predicates.push(Predicate {
                address: self.address(b'R', ordinal),
                expected: ExpectedValue::Exact(Secret::new(record.body.clone())),
            });
        }
        predicates.push(Predicate {
            address: selection.address.clone(),
            expected: selection.expected,
        });
        let candidate = PreparedCandidate::new(Candidate {
            id: self.store.next_id()?,
            codec: CANDIDATE_VERSION,
            predicates,
            mutations: vec![if delete {
                Mutation::Delete(selection.address)
            } else {
                Mutation::Put {
                    address: selection.address,
                    value: selection.value,
                }
            }],
            time: None,
            result: Secret::default(),
        })
        .map_err(|_| Error::Invalid)?;
        Ok(WriteResult::Submitted(permit.submit(candidate).await?))
    }
}

fn matches_value(expected: &ExpectedValue, value: &Option<Secret<Vec<u8>>>) -> bool {
    match expected {
        ExpectedValue::Absent => value.is_none(),
        ExpectedValue::Exact(expected) => value.as_ref() == Some(expected),
    }
}

pub(super) fn seal_record(node: u64, previous: Head, entry: Entry) -> Result<Record> {
    let mut record = JournalRecord {
        class: entry.class,
        node,
        node_seq: previous.sequence.checked_add(1).ok_or(Error::Overflow)?,
        lease_epoch: entry.lease_epoch,
        policy_epoch: entry.policy_epoch,
        wall: entry.wall,
        mono: entry.mono,
        body_hash: busbar_kernel_wal::journal::body_digest(&entry.body),
        body: entry.body,
        prev_hash: previous.hash,
        hash: [0; 32],
    };
    record.hash = record.digest_of_chain();
    Ok(Record::new(node, record.node_seq, record.encode()))
}
