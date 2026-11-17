// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

use busbar_kernel::persistence::journal::head_cell::Head;
use busbar_kernel_audit::{Fingerprint, LineAt, Linked, Prepared};

/// Canonical terminal facts retained by the Node entry before any journal effect. The entry
/// also retains its original audit pass and the byte credit for this input plus preparation.
pub(crate) struct FrozenNativeAudit {
    inputs: AuditInputs,
    identity: LineIdentity,
    journal: Arc<RuntimeJournal>,
}

/// Why [`FrozenNativeAudit::prepare`] refused to freeze. The source bundle comes back with it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NativeFreezeRefusal<E> {
    /// The caller's own input building refused.
    Build(E),
    /// The canonical line can never become a journal body at any chain position: freezing it
    /// would leave an entry whose every stage refuses.
    Unencodable(busbar_kernel_audit::FieldTooLong),
}

/// A refused native preparation: the caller's original, unchanged source bundle and why.
#[derive(Debug)]
pub(crate) struct NativeFreezeRefused<S, E> {
    pub(crate) source: S,
    pub(crate) why: NativeFreezeRefusal<E>,
}

impl FrozenNativeAudit {
    /// The checked native preparation (native DATA audit r2, frozen input boundary): build
    /// canonical inputs from the borrowed source bundle, bind this book's identity and journal,
    /// and prove the line encodes as a journal body before any entry owns it. It has no journal
    /// effect. A refusal returns the original bundle unchanged; success returns it too, so the
    /// caller drops it only after the frozen inputs are installed in the entry. The pass is
    /// borrowed, never consumed.
    pub(crate) fn prepare<S, E>(
        source: S,
        book: &Arc<std::sync::Mutex<Durability>>,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        build: impl FnOnce(&S) -> Result<AuditInputs, E>,
    ) -> Result<(Self, S), NativeFreezeRefused<S, E>> {
        let inputs = match build(&source) {
            Ok(inputs) => inputs,
            Err(why) => {
                return Err(NativeFreezeRefused {
                    source,
                    why: NativeFreezeRefusal::Build(why),
                })
            }
        };
        let frozen = Self::new(inputs, book);
        if let Err(why) = frozen.encodable(pass) {
            return Err(NativeFreezeRefused {
                source,
                why: NativeFreezeRefusal::Unencodable(why),
            });
        }
        Ok((frozen, source))
    }

    /// Link a copy on a scratch chain of this node and encode it as the journal body
    /// `stage_prepared` would write. Sequence, link time and both hashes are fixed-width in the
    /// body, so the answer holds at every real chain position; the genesis's empty predecessor is
    /// widened to a full fingerprint. The scratch chain is dropped; the book's chain is untouched.
    fn encodable(
        &self,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
    ) -> Result<(), busbar_kernel_audit::FieldTooLong> {
        let prepared = AuditChain::prepare(self.inputs.clone(), self.identity.node);
        let mut record = AuditChain::new()
            .sealing_as(self.identity.node)
            .link(prepared, u64::MAX, pass)
            .into_record();
        if record.prev_hash.is_empty() {
            record.prev_hash = Fingerprint::ZERO.to_string();
        }
        audit_body(&record).map(drop)
    }

    pub(crate) fn new(mut inputs: AuditInputs, book: &Arc<std::sync::Mutex<Durability>>) -> Self {
        let held = book.lock().unwrap_or_else(|poison| poison.into_inner());
        let identity = held.line_identity();
        inputs.what.incarnation = identity.incarnation;
        Self {
            inputs,
            identity,
            journal: held.journal.clone(),
        }
    }
}

/// Exact original installed in the Node's preallocated terminal slot before chain publication.
/// A cloned driver loan never takes custody away from that entry. This is not signed coverage.
#[derive(Clone)]
pub(crate) struct NativeStagedAudit {
    journal: Arc<RuntimeJournal>,
    pub(super) run: Arc<StagedRun>,
    pub(super) line: LineAt,
    pub(super) original: Option<super::notary::original::OriginalLineWitness>,
}

impl NativeStagedAudit {
    pub(crate) fn line(&self) -> LineAt {
        self.line
    }

    /// Drive only the retained original. Success means journal Applied, never a notary receipt.
    pub(crate) async fn confirm_journal(
        &self,
    ) -> Result<(), busbar_kernel::persistence::journal::runtime::RuntimeError> {
        self.journal.confirm(&self.run).await?;
        records_pulse().notify_waiters();
        Ok(())
    }
}

impl Durability {
    /// Caller holds the native entry lock and has reserved preparation bytes. A failed prepare
    /// or stage leaves its frozen inputs/pass intact; a successful stage installs the exact run
    /// before advancing the chain. No await, callback into Node, or Store work occurs here.
    pub(crate) fn stage_native(
        book: &Arc<std::sync::Mutex<Self>>,
        frozen: &FrozenNativeAudit,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
        slot: &mut Option<NativeStagedAudit>,
    ) -> Result<(), DurabilityLost> {
        if slot.is_some() {
            return Err(DurabilityLost::observed(token, StepName::Audit));
        }
        let prepared = AuditChain::prepare(frozen.inputs.clone(), frozen.identity.node);
        let mut held = book.lock().unwrap_or_else(|poison| poison.into_inner());
        if held.line_identity() != frozen.identity || !Arc::ptr_eq(&held.journal, &frozen.journal) {
            return Err(DurabilityLost::observed(token, StepName::Audit));
        }
        let journal = held.journal.clone();
        held.stage_prepared_custody(prepared, pass, token, |line, run, original| {
            *slot = Some(NativeStagedAudit {
                journal,
                run,
                line,
                original,
            });
        })
    }

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
                    self.resumed_head_node_seq = record.node_seq;
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
        self.audit_ring = AuditRing::from_sealed(sealed);
    }

    /// Publish the chain's resumed tail to the head feed, so the notary starts from it.
    pub(super) fn publish_resumed_head(&mut self) {
        let Some(last) = self.audit_records().last() else {
            return;
        };
        let Some(fp) = Fingerprint::from_hex(&last.hash) else {
            return;
        };
        self.head.publish(&Head {
            seq: last.seq,
            node_seq: self.resumed_head_node_seq,
            fp: fp.0,
            wall_ms: last.linked_ms,
        });
    }

    /// The resumed head the notary starts from: everything at or below it was written before this
    /// boot took the node (the boot phase seals or records it), and is never live-stamped.
    #[must_use]
    pub(crate) fn notary_start(&self) -> super::notary::NotaryStart {
        let head = self.head.head();
        super::notary::NotaryStart {
            stamped_through: head.seq,
            stamped_node_seq: head.node_seq,
        }
    }

    /// The boot incarnation and node every line of this book names: boot constants, copied out
    /// once so a line can be prepared before the lock ([`AuditChain::prepare`]).
    #[must_use]
    pub(crate) fn line_identity(&self) -> LineIdentity {
        LineIdentity {
            node: self.record.node(),
            incarnation: self.incarnation,
        }
    }

    /// LINK, STAGE AND PUBLISH ONE PREPARED LINE under this book's lock (SEALING-FIX §3.2): read
    /// the clock, link, stage the one-record run; on success advance the chain, publish the head
    /// and move the record into the ring (no clone). A refused stage advances nothing: the next
    /// line links to the same tail. Signs nothing.
    pub(crate) fn stage_prepared(
        &mut self,
        prepared: Prepared,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<(LineAt, Arc<StagedRun>), DurabilityLost> {
        self.stage_prepared_custody(prepared, pass, token, |line, run, _| (line, run))
    }

    /// The private install callback is only an infallible move into already-owned storage.
    /// It runs after the RAM stage accepted the original and before any chain/head publication.
    fn stage_prepared_custody<T>(
        &mut self,
        prepared: Prepared,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
        install: impl FnOnce(
            LineAt,
            Arc<StagedRun>,
            Option<super::notary::original::OriginalLineWitness>,
        ) -> T,
    ) -> Result<T, DurabilityLost> {
        let linked_ms = busbar_kernel::store::now_ms();
        let linked: Linked = self.record.link(prepared, linked_ms, pass);
        let previous = linked
            .record()
            .seq
            .checked_sub(1)
            .ok_or_else(|| DurabilityLost::observed(token, StepName::Audit))?;
        let previous_fp = if previous == 0 && linked.record().prev_hash.is_empty() {
            Fingerprint::ZERO
        } else {
            Fingerprint::from_hex(&linked.record().prev_hash)
                .ok_or_else(|| DurabilityLost::observed(token, StepName::Audit))?
        };
        if !self.head.original.check_link(previous, previous_fp) {
            return Err(DurabilityLost::observed(token, StepName::Audit));
        }
        let entry = audit_entry(linked.record())
            .map_err(|_| DurabilityLost::observed(token, StepName::Audit))?;
        let run = self
            .journal
            .stage_run(&[entry])
            .map_err(|_| DurabilityLost::observed(token, StepName::Audit))?;
        let line = LineAt {
            chain_seq: linked.record().seq,
            node_seq: run.records().first().map_or(0, |r| r.node_seq),
            fp: linked.fingerprint(),
        };
        let head = Head {
            seq: line.chain_seq,
            node_seq: line.node_seq,
            fp: line.fp.0,
            wall_ms: linked_ms,
        };
        let original = self.head.original.witness(head, &run, &self.journal);
        let installed = install(line, run, original.clone());
        self.record.advance(&linked);
        self.head.publish_original(head, original.as_ref());
        let record = linked.into_record();
        if record.key_id.is_some() && self.audit_signed_from.is_none() {
            self.audit_signed_from = Some(record.seq);
        }
        self.audit_ring.push(record);
        Ok(installed)
    }

    /// The request path's stage when the caller could not prepare before the lock: prepare here,
    /// then [`Durability::stage_prepared`]. Returns the line's hint, never the record.
    pub(crate) fn stage_line(
        &mut self,
        mut inputs: AuditInputs,
        pass: busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<(LineAt, Arc<StagedRun>), DurabilityLost> {
        inputs.what.incarnation = self.incarnation;
        let prepared = AuditChain::prepare(inputs, self.record.node());
        self.stage_prepared(prepared, &pass, token)
    }

    /// Admin `seal_unit` and the tests that read the sealed record: [`Durability::stage_line`],
    /// then a clone of the record from the ring, off the request path.
    pub(crate) fn stage_unit(
        &mut self,
        inputs: AuditInputs,
        pass: busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<(AuditRecord, Arc<StagedRun>), DurabilityLost> {
        let (_, run) = self.stage_line(inputs, pass, token)?;
        let record = self
            .audit_records()
            .last()
            .cloned()
            .ok_or_else(|| DurabilityLost::observed(token, StepName::Audit))?;
        Ok((record, run))
    }

    pub(crate) async fn seal_unit(
        book: &Arc<std::sync::Mutex<Self>>,
        inputs: AuditInputs,
        pass: busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<AuditRecord, DurabilityLost> {
        let (journal, record, run) = {
            let mut book = book.lock().unwrap_or_else(|poison| poison.into_inner());
            let (record, run) = book.stage_unit(inputs, pass, token)?;
            (book.journal.clone(), record, run)
        };
        journal
            .confirm(&run)
            .await
            .map_err(|_| DurabilityLost::observed(token, StepName::Audit))?;
        records_pulse().notify_waiters();
        Ok(record)
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) async fn audit_window(&self, from: u64, to: u64) -> Option<Vec<AuditRecord>> {
        match self.audit_window_at(from, to) {
            AuditWindowAt::Cached(records) => Some(records),
            AuditWindowAt::OnChain { chain, .. } => chain.audit_window(from, to).await,
        }
    }

    #[must_use]
    pub(crate) fn audit_window_at(&self, from: u64, to: u64) -> AuditWindowAt {
        let covered = self.audit_records().first().is_some_and(|r| r.seq <= from);
        let pick = |r: &&AuditRecord| r.seq >= from && r.seq <= to;
        if covered || self.audit_records().is_empty() && !self.keeps_chain() {
            let cached = self.audit_records().iter().filter(pick).take(AUDIT_RING);
            return AuditWindowAt::Cached(cached.cloned().collect());
        }
        AuditWindowAt::OnChain {
            chain: self.chain_at(),
            sealed_before: self.record.next_seq(),
        }
    }

    #[must_use]
    pub(crate) fn audit_window_since(
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
        match self.audit_records().first() {
            Some(oldest) if oldest.seq <= since => {}
            _ => return false,
        }
        window.extend(
            self.audit_records()
                .iter()
                .filter(|r| r.seq >= since && r.seq <= to)
                .cloned(),
        );
        window.truncate(AUDIT_RING);
        true
    }

    #[must_use]
    pub(crate) fn retained_audit_findings(&self) -> Vec<String> {
        let mut findings = Vec::new();
        if let Err(broken) = AuditChain::verify_window(self.audit_records()) {
            findings.push(format!("{broken:?}"));
        }
        let keys = keyset_of(&self.record);
        for record in self.audit_records() {
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

pub(crate) enum AuditWindowAt {
    Cached(Vec<AuditRecord>),

    OnChain { chain: ChainAt, sealed_before: u64 },
}

impl ChainAt {
    #[must_use]
    pub(crate) async fn audit_window(self, from: u64, to: u64) -> Option<Vec<AuditRecord>> {
        let store = self.store().map(str::to_string);
        let records = match self.read().await {
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

#[cfg(test)]
#[path = "../tests/durability_native_audit.rs"]
mod native_tests;

/// THE BOOT CONSTANTS A LINE NAMES, copied out of the book at bind so the request path prepares
/// (hashes) its line before taking the book's lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct LineIdentity {
    /// The node the book seals as.
    pub(crate) node: u64,
    /// This boot's incarnation of the node's journal.
    pub(crate) incarnation: u64,
}
