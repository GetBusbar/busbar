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
    /// boot seals links to the last one a predecessor sealed. The chain is resumed FROM THE RECORDS,
    /// so its head history is rebuilt with it: the head read answers with the tip the chain has,
    /// never a null head beside a `next_seq` above one, and a window's anchor is the one it had
    /// before the restart. A record that will not read back is a finding, never silently skipped.
    /// The first record journalled after a `Bootstrap` (the keyset's seal) is where
    /// [`Durability::audit_signed_from`] starts.
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
        if !sealed.is_empty() {
            // Resumed as the node this book seals as: a predecessor's records name their own node.
            self.record = AuditChain::resume(&sealed).sealing_as(self.record.node());
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
        // A record whose body cannot be written whole is a durability loss, reported as one: the
        // journal never holds a record cut to fit.
        let appended = match audit_entry(&record) {
            Ok(entry) => self.journal.append(token, StepName::Audit, &[entry]),
            Err(_) => Err(DurabilityLost::observed(token, StepName::Audit)),
        };
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
    ///
    /// `None` when the journal could not be read back, or does not verify: there is no window to
    /// answer with then, and an empty one would say the chain holds nothing there (audit R1#3).
    #[must_use]
    pub fn audit_window(&self, from: u64, to: u64) -> Option<Vec<AuditRecord>> {
        match self.audit_window_at(from, to) {
            AuditWindowAt::Cached(records) => Some(records),
            AuditWindowAt::OnChain { chain, .. } => chain.audit_window(from, to),
        }
    }

    /// [`Durability::audit_window`] as of this hold of the book's lock: the cache's records when
    /// it covers `from`, else the chain as of now ([`Durability::chain_at`]) to be read once the
    /// lock is let go — on a node resumed from the store that read scans the store through its
    /// plugin, which no unit's settle may wait on (THE DESIGN §11.2) — and finished under the lock
    /// again by [`Durability::audit_window_since`].
    #[must_use]
    pub fn audit_window_at(&self, from: u64, to: u64) -> AuditWindowAt {
        let covered = self.audit_records.first().is_some_and(|r| r.seq <= from);
        let pick = |r: &&AuditRecord| r.seq >= from && r.seq <= to;
        if covered || self.audit_records.is_empty() && !self.keeps_chain() {
            let cached = self.audit_records.iter().filter(pick).take(AUDIT_RING);
            return AuditWindowAt::Cached(cached.cloned().collect());
        }
        AuditWindowAt::OnChain {
            chain: self.chain_at(),
            sealed_before: self.record.next_seq(),
        }
    }

    /// FINISH A WINDOW READ OFF THE CHAIN, under the book's lock again: `window` is what
    /// [`ChainAt::audit_window`] read of the chain as of the hold when the audit chain's next
    /// position was `sealed_before`, and every record sealed since that falls in the window is
    /// added from the cache, so the window and the head a range read folds in beside it answer as of
    /// THIS hold (`AuditView::read`). `false` when the cache no longer reaches back to the first of
    /// them, which only a run of more than [`AUDIT_RING`] seals during the read can do: the window
    /// is then taken again.
    #[must_use]
    pub fn audit_window_since(
        &self,
        window: &mut Vec<AuditRecord>,
        sealed_before: u64,
        from: u64,
        to: u64,
    ) -> bool {
        let since = from.max(sealed_before);
        if since > to || window.len() >= AUDIT_RING || self.record.next_seq() <= since {
            return true;
        }
        match self.audit_records.first() {
            Some(oldest) if oldest.seq <= since => {}
            _ => return false,
        }
        window.extend(
            self.audit_records
                .iter()
                .filter(|r| r.seq >= since && r.seq <= to)
                .cloned(),
        );
        window.truncate(AUDIT_RING);
        true
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
        let keys = keyset_of(&self.record);
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

/// AN AUDIT WINDOW AS OF ONE HOLD OF THE BOOK'S LOCK ([`Durability::audit_window_at`]).
pub enum AuditWindowAt {
    /// The cache covers the window: its records, taken under the lock.
    Cached(Vec<AuditRecord>),
    /// The window is older than the cache: the chain as of the hold, read without the lock
    /// ([`ChainAt::audit_window`]), and the position the audit chain's next record took then.
    OnChain {
        /// The chain as of the hold.
        chain: ChainAt,
        /// The audit chain's next position at the hold: every record before it is on `chain`.
        sealed_before: u64,
    },
}

impl ChainAt {
    /// The sealed audit records at positions `from` through `to` on the chain as of the hold,
    /// oldest first, at most [`AUDIT_RING`] of them. `None` when the chain could not be read back,
    /// or does not verify, as [`Durability::audit_window`].
    #[must_use]
    pub fn audit_window(self, from: u64, to: u64) -> Option<Vec<AuditRecord>> {
        let store = self.store().map(str::to_string);
        let records = match self.read() {
            Ok(Ok(records)) => records,
            Ok(Err(broken)) => {
                tracing::error!(?broken, "the chain an audit window reads does not verify");
                return None;
            }
            Err(e) => {
                let why = unreadable_in(store.as_deref(), &e);
                tracing::error!(why = %why, "an audit window was not read back");
                return None;
            }
        };
        let window: Vec<AuditRecord> = records
            .iter()
            .filter_map(|r| decode_audit(r).ok().flatten())
            .filter(|r| r.seq >= from && r.seq <= to)
            .take(AUDIT_RING)
            .collect();
        Some(window)
    }
}

#[cfg(test)]
#[path = "../tests/durability_audit.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "../tests/durability_audit_node.rs"]
mod node_tests;
