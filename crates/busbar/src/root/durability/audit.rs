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

/// A refused native preparation and why. The source bundle is dropped unchanged.
#[derive(Debug)]
pub(crate) struct NativeFreezeRefused<E> {
    pub(crate) why: NativeFreezeRefusal<E>,
}

impl FrozenNativeAudit {
    /// The checked native preparation (native DATA audit r2, frozen input boundary): build
    /// canonical inputs from the borrowed source bundle, bind this book's identity and journal,
    /// and prove the line encodes as a journal body before any entry owns it. It has no journal
    /// effect. Success returns the original bundle, so the caller drops it only after the
    /// frozen inputs are installed in the entry. The pass is
    /// borrowed, never consumed.
    pub(crate) fn prepare<S, E>(
        source: S,
        book: &Arc<std::sync::Mutex<Durability>>,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        build: impl FnOnce(&S) -> Result<AuditInputs, E>,
    ) -> Result<(Self, S), NativeFreezeRefused<E>> {
        let inputs = match build(&source) {
            Ok(inputs) => inputs,
            Err(why) => {
                return Err(NativeFreezeRefused {
                    why: NativeFreezeRefusal::Build(why),
                })
            }
        };
        let frozen = Self::new(inputs, book);
        if let Err(why) = frozen.encodable(pass) {
            return Err(NativeFreezeRefused {
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
    /// Stage a Bootstrap-certified key into the ordinary audit chain. The caller confirms
    /// this exact run before publishing its WAL position as the live signer's key_cert.
    pub(crate) fn stage_notary_key(
        &mut self,
        prepared: busbar_kernel_audit::notary_key::PreparedNotaryKey,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<
        (
            busbar_kernel_audit::notary_key::NotaryKeyRecord,
            Arc<StagedRun>,
        ),
        DurabilityLost,
    > {
        let linked_ms = busbar_kernel::store::now_ms();
        let linked = self
            .record
            .link_notary_key(prepared, linked_ms, pass)
            .map_err(|_| DurabilityLost::observed(token, StepName::Audit))?;
        let body = busbar_kernel_audit::notary_key::notary_key_body(linked.record())
            .map_err(|_| DurabilityLost::observed(token, StepName::Audit))?;
        let entry = Entry::new(RecordClass::Transaction, body).at(linked_ms / 1_000, 0);
        let run = self
            .journal
            .stage_audit_run(&[entry], linked.record().seq, linked.record().fingerprint.0)
            .map_err(|_| DurabilityLost::observed(token, StepName::Audit))?;
        self.record
            .advance_notary_key(&linked)
            .map_err(|_| DurabilityLost::observed(token, StepName::Audit))?;
        self.head.publish(&Head {
            seq: linked.record().seq,
            node_seq: run.records().first().map_or(0, |row| row.node_seq),
            fp: linked.record().fingerprint.0,
            wall_ms: linked_ms,
        });
        Ok((linked.into_record(), run))
    }

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

    pub(super) fn resume_audit(&mut self, records: &[JournalRecord]) -> Result<(), String> {
        use busbar_kernel_audit::linked_record::{
            linked_record_from_journal_body, AuditLinkedRecord,
        };
        let mut sealed = Vec::new();
        let mut last_node_seq = 0;
        for record in records {
            if record.class != RecordClass::Transaction {
                continue;
            }
            match linked_record_from_journal_body(
                &record.body,
                &busbar_kernel::Registration::meter_class,
            ) {
                Ok(Some(audit)) => {
                    last_node_seq = record.node_seq;
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
            self.record = AuditChain::resume_linked(&sealed)?.sealing_as(self.record.node());
        }
        if let Some(last) = sealed.last() {
            let fp = last.fingerprint()?;
            self.head.publish(&Head {
                seq: last.chain_seq(),
                node_seq: last_node_seq,
                fp: fp.0,
                wall_ms: last.linked_ms(),
            });
        }
        // This ring is a unit-facts projection, never a complete mixed-chain authority proof.
        self.audit_ring = AuditRing::from_sealed(
            sealed
                .into_iter()
                .filter_map(|row| match row {
                    AuditLinkedRecord::Unit(record) => Some(*record),
                    AuditLinkedRecord::NotaryKey(_) => None,
                })
                .collect(),
        );
        Ok(())
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
        self.stage_linked_custody(linked, linked_ms, token, install)
            .map_err(|(lost, _)| lost)
    }

    /// THE FLUSHER'S STAGE: [`Durability::stage_prepared`], except that a refused line is handed
    /// back, unlinked, so the flusher keeps it in order for its next flush. A line is never
    /// dropped between lines that commit: a later commit could otherwise settle its waiter.
    pub(crate) fn stage_kept(
        &mut self,
        prepared: Prepared,
        pass: &busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<LineAt, Box<Prepared>> {
        let linked_ms = busbar_kernel::store::now_ms();
        let linked: Linked = self.record.link(prepared, linked_ms, pass);
        self.stage_linked_custody(linked, linked_ms, token, |line, _, _| line)
            .map_err(|(_, linked)| Box::new(linked.unlink()))
    }

    /// A line built for this node's chain (the boot incarnation copied in), not yet linked.
    pub(crate) fn prepare_line(&self, mut inputs: AuditInputs) -> Prepared {
        inputs.what.incarnation = self.incarnation;
        AuditChain::prepare(inputs, self.record.node())
    }

    /// Stage a line linked over this chain's tail at `linked_ms`. On a refusal the chain has not
    /// moved and the line comes back with the reason.
    fn stage_linked_custody<T>(
        &mut self,
        linked: Linked,
        linked_ms: u64,
        token: &Grant<DurableWrite>,
        install: impl FnOnce(
            LineAt,
            Arc<StagedRun>,
            Option<super::notary::original::OriginalLineWitness>,
        ) -> T,
    ) -> Result<T, (DurabilityLost, Box<Linked>)> {
        // The refused line rides back boxed: the refusal is the rare path and the result stays small.
        let refuse = |linked: Linked| {
            (
                DurabilityLost::observed(token, StepName::Audit),
                Box::new(linked),
            )
        };
        let Some(previous) = linked.record().seq.checked_sub(1) else {
            return Err(refuse(linked));
        };
        let previous_fp = if previous == 0 && linked.record().prev_hash.is_empty() {
            Fingerprint::ZERO
        } else {
            match Fingerprint::from_hex(&linked.record().prev_hash) {
                Some(fp) => fp,
                None => return Err(refuse(linked)),
            }
        };
        if !self.head.original.check_link(previous, previous_fp) {
            return Err(refuse(linked));
        }
        let Ok(entry) = audit_entry(linked.record()) else {
            return Err(refuse(linked));
        };
        // The line's chain seq and fingerprint ride with its run, so an Ephemeral journal's cut
        // writes the audit tail into its base without reading a row (SEALING-FIX §3.9).
        let run = match self.journal.stage_audit_run(
            &[entry],
            linked.record().seq,
            linked.fingerprint().0,
        ) {
            Ok(run) => run,
            Err(_) => return Err(refuse(linked)),
        };
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
        self.audit_ring.push(linked.into_record());
        Ok(installed)
    }

    /// The request path's stage when the caller could not prepare before the lock: prepare here,
    /// then [`Durability::stage_prepared`]. Returns the line's hint, never the record.
    pub(crate) fn stage_line(
        &mut self,
        inputs: AuditInputs,
        pass: busbar_contract::caps::Pass<busbar_contract::caps::Audit>,
        token: &Grant<DurableWrite>,
    ) -> Result<(LineAt, Arc<StagedRun>), DurabilityLost> {
        let prepared = self.prepare_line(inputs);
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
        // Each record by its version's rule: version 2 (chained, unsigned) is proved by the
        // window's links above up to a signed head; version 1 by its own signature.
        for record in self.audit_records() {
            let key_id = match (record.record_version(), record.key_id.as_deref()) {
                (Some(busbar_kernel_audit::RecordVersion::SignedHead), _) => continue,
                (Some(busbar_kernel_audit::RecordVersion::SignedLine), Some(key_id)) => key_id,
                _ => {
                    findings.push(format!(
                        "record {} carries a signature without its key or a key without its \
                         signature",
                        record.seq
                    ));
                    continue;
                }
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
