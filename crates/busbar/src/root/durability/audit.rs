// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit chain on the book: each unit's one record sealed and journalled whole
//! (`audit.v4`), the in-memory cache of the newest [`AUDIT_RING`] rebuilt from the chain at boot, a
//! window older than the cache read back off the journal, and the walk of the retained chain that
//! `GET /admin/verify` reports.
//!
//! Split out of `durability/mod.rs` (structure-lint) — a private child module, as `replay` is; the
//! journal body itself ([`audit_body`]) stays with the other journal writers in the parent.

use super::*;
use busbar_kernel_audit::Audit as _;

impl Durability {
    /// REBUILD THE AUDIT CACHE FROM THE CHAIN and continue the audit chain from its tail: every
    /// `audit.v4` record is read back, the newest [`AUDIT_RING`] are kept, and the next record this
    /// boot seals links to the last one a predecessor sealed. A record that will not read back is a
    /// finding, never silently skipped. The first record journalled after a `Bootstrap` (the
    /// keyset's seal) is where [`Durability::audit_signed_from`] starts.
    pub(super) fn resume_audit(&mut self, records: &[JournalRecord]) {
        let mut sealed = Vec::new();
        let mut keyed = false;
        for record in records {
            keyed |= record.class == RecordClass::Bootstrap;
            match decode_audit(record) {
                Ok(Some(audit)) => {
                    if keyed && self.audit_signed_from.is_none() {
                        self.audit_signed_from = Some(audit.seq);
                    }
                    sealed.push(audit);
                }
                Ok(None) => {}
                Err(why) => self.audit_findings.push(format!(
                    "node {} record {}: {why}",
                    record.node, record.node_seq
                )),
            }
        }
        if let Some(last) = sealed.last() {
            self.record = AuditChain::resume(last.hash.clone(), last.seq.saturating_add(1));
        }
        let keep = sealed.len().saturating_sub(AUDIT_RING);
        self.audit_records = sealed.split_off(keep);
    }

    /// SEAL A UNIT'S ONE FIXED AUDIT RECORD and put it on the journal, where the unit's one line is
    /// written.
    ///
    /// `pass` is the audit pass the unit's own audit step was lent, handed back with its facts
    /// (`Units::audited`): a unit that never passed its audit step has none, so it has no record,
    /// and a pass seals once. The record is sealed under this boot's [`Durability::incarnation`] —
    /// a unit key restarts with the process, the incarnation does not — and journalled whole
    /// (`audit.v4`), so the journal can answer for it after the in-memory cache has let it go.
    ///
    /// # Errors
    ///
    /// The journal could not make the record durable. Without a data directory that means the store
    /// refused the batch; with one it means a write or a sync failed. The record is sealed on the
    /// chain and kept in the cache either way.
    pub fn seal_unit(
        &mut self,
        mut inputs: AuditInputs,
        pass: busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<AuditRecord, DurabilityLost> {
        inputs.what.incarnation = self.incarnation;
        let record = self.record.seal(inputs, &pass);
        if record.key_id.is_some() && self.audit_signed_from.is_none() {
            self.audit_signed_from = Some(record.seq);
        }
        let entry = audit_entry(&record);
        let appended = self.journal.append(token, StepName::Audit, &[entry]);
        self.audit_records.push(record.clone());
        if self.audit_records.len() > AUDIT_RING {
            let over = self.audit_records.len() - AUDIT_RING;
            self.audit_records.drain(..over);
        }
        appended.map(|_| record)
    }

    /// The sealed audit records at positions `from` through `to`, oldest first, at most
    /// [`AUDIT_RING`] of them. From the cache when it covers `from`; otherwise read back off the
    /// journal, which keeps every record — so a window older than the cache is never answered as
    /// empty.
    #[must_use]
    pub fn audit_window(&self, from: u64, to: u64) -> Vec<AuditRecord> {
        let covered = self.audit_records.first().is_some_and(|r| r.seq <= from);
        let pick = |r: &&AuditRecord| r.seq >= from && r.seq <= to;
        if covered || self.audit_records.is_empty() && !self.keeps_chain() {
            return self
                .audit_records
                .iter()
                .filter(pick)
                .take(AUDIT_RING)
                .cloned()
                .collect();
        }
        let Ok(Ok(records)) = self.journal.replay() else {
            return Vec::new();
        };
        records
            .iter()
            .filter_map(|r| decode_audit(r).ok().flatten())
            .filter(|r| r.seq >= from && r.seq <= to)
            .take(AUDIT_RING)
            .collect()
    }

    /// WHAT A WALK OF THE RETAINED AUDIT CHAIN FINDS, as `GET /admin/verify` reports it: a record
    /// whose digest, link or position does not hold, a signature that does not verify under the
    /// key it names, and a record with no signature at all at or after
    /// [`Durability::audit_signed_from`] — the signature is not in the digest, so stripping it
    /// leaves the chain whole and only this rule sees it. (What the boot could not read back is a restart finding.) Empty is the only
    /// good answer.
    #[must_use]
    pub fn retained_audit_findings(&self) -> Vec<String> {
        let mut findings = Vec::new();
        if let Err(broken) = AuditChain::verify_window(&self.audit_records) {
            findings.push(format!("{broken:?}"));
        }
        let keys = super::seal::keyset_of(&self.record);
        for record in &self.audit_records {
            let Some(key_id) = record.key_id.as_deref() else {
                if self
                    .audit_signed_from
                    .is_some_and(|from| record.seq >= from)
                {
                    findings.push(format!(
                        "record {} is unsigned, sealed after the keyset was bound",
                        record.seq
                    ));
                }
                continue;
            };
            let verified = keys
                .get(key_id)
                .ok_or(KeyError::Unsigned)
                .and_then(|key| AuditChain::verify_signature(record, key));
            if let Err(e) = verified {
                findings.push(format!("record {} signed by {key_id}: {e:?}", record.seq));
            }
        }
        findings
    }
}
