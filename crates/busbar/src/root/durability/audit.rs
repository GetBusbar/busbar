// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel_audit::Audit as _;

impl Durability {
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
            self.record = AuditChain::resume(&sealed).sealing_as(self.record.node());
        }
        let keep = sealed.len().saturating_sub(AUDIT_RING);
        self.audit_records = sealed.split_off(keep);
    }

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

    #[must_use]
    pub fn audit_window(&self, from: u64, to: u64) -> Option<Vec<AuditRecord>> {
        match self.audit_window_at(from, to) {
            AuditWindowAt::Cached(records) => Some(records),
            AuditWindowAt::OnChain { chain, .. } => chain.audit_window(from, to),
        }
    }

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

pub enum AuditWindowAt {
    Cached(Vec<AuditRecord>),

    OnChain { chain: ChainAt, sealed_before: u64 },
}

impl ChainAt {
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
        let mut window = Vec::new();
        for record in &records {
            match decode_audit(record) {
                Ok(Some(audit)) if audit.seq >= from && audit.seq <= to => window.push(audit),
                Ok(_) => {}
                Err(_) => {
                    tracing::error!(
                        node = record.node,
                        record = record.node_seq,
                        "an audit window contains an audit record that does not decode"
                    );
                    return None;
                }
            }
            if window.len() == AUDIT_RING {
                break;
            }
        }
        Some(window)
    }
}

#[cfg(test)]
#[path = "../tests/durability_audit.rs"]
pub(super) mod tests;

#[cfg(test)]
#[path = "../tests/durability_audit_node.rs"]
mod node_tests;
