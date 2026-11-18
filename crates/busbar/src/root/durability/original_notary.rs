// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Same-process ordinary original receipts. These are producer capabilities, not SF4 proofs.

use busbar_contract::storage::StorageCredit;
use busbar_kernel::persistence::journal::head_cell::Head;
use busbar_kernel::persistence::journal::runtime::{RuntimeJournal, StagedRun};
use busbar_kernel_audit::{AuditVerifyingKey, Fingerprint, LineAt, Stamp, StampKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use super::super::audit::NativeStagedAudit;
use crate::root::plane_node::RetainedBook;

#[cfg(test)]
#[path = "../tests/durability_original_notary.rs"]
mod tests;

/// Finite scan position, never audit or completion authority. Every callback examines at
/// most 64 candidates, including nonmembers, using the same captured upper bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OriginalPageCursor {
    pub(crate) last: Option<u64>,
    pub(crate) upper: u64,
}

impl OriginalPageCursor {
    pub(super) fn start(upper: u64) -> Self {
        Self { last: None, upper }
    }

    pub(super) fn preserves(self, previous: Option<Self>, upper: Option<u64>) -> bool {
        upper.is_none_or(|upper| upper == self.upper)
            && self.last.is_none_or(|last| last <= self.upper)
            && previous
                .is_none_or(|previous| previous.upper == self.upper && self.last >= previous.last)
    }

    pub(super) fn advances(self, previous: Option<Self>, upper: Option<u64>) -> bool {
        self.preserves(previous, upper)
            && self.last.is_some()
            && previous.is_none_or(|previous| self.last > previous.last)
    }
}

pub(crate) enum PageFunding {
    Pending(OriginalPageCursor),
    Reserved(StorageCredit, u64),
    Empty(u64),
    Refused(Option<OriginalPageCursor>),
}

pub(crate) enum PageDelivery {
    Pending(OriginalPageCursor),
    Complete,
    Refused,
}

struct Binding {
    journal: Arc<RuntimeJournal>,
    key: AuditVerifyingKey,
    baseline: u64,
    tail: Head,
    receiver: Option<Weak<RetainedBook>>,
    exited: Option<Arc<AtomicBool>>,
    retention_bytes: Option<usize>,
}

#[derive(Default)]
struct State {
    binding: Option<Binding>,
    invalid: bool,
}

#[derive(Default)]
pub(in crate::root::durability) struct OriginalChain {
    state: Mutex<State>,
}

impl std::fmt::Debug for OriginalChain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginalChain").finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct OriginalNotaryReady {
    chain: Arc<OriginalChain>,
    bytes: usize,
}

impl OriginalNotaryReady {
    pub(crate) fn retention_bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn is_ready(&self) -> bool {
        self.chain.ready().is_some()
    }
}

/// A private target witness is made only while installing its actual original.
#[derive(Clone)]
pub(in crate::root::durability) struct OriginalLineWitness {
    chain: Arc<OriginalChain>,
    line: LineAt,
    wal_hash: [u8; 32],
}

/// A captured continuous original page, never a range supplied by a consumer.
#[derive(Clone)]
pub(crate) struct OriginalPageTarget {
    chain: Arc<OriginalChain>,
    from: u64,
    to: Head,
}

impl OriginalPageTarget {
    pub(super) fn head(&self) -> Head {
        self.to
    }
    pub(crate) fn covers(&self, staged: &NativeStagedAudit) -> bool {
        staged.original.as_ref().is_some_and(|original| {
            Arc::ptr_eq(&original.chain, &self.chain)
                && original.line == staged.line
                && original.line.chain_seq >= self.from
                && original.line.chain_seq <= self.to.seq
                && staged.run.carried().next().is_some_and(|wal| {
                    wal.seq == original.line.node_seq && wal.hash == original.wal_hash
                })
        })
    }
}

struct PageBacking {
    // Owned storage precedes its conserved credit in destruction order.
    run: Arc<StagedRun>,
    target: OriginalPageTarget,
    credit: StorageCredit,
}

#[derive(Clone)]
pub(crate) struct OriginalPageReceipt {
    backing: Arc<PageBacking>,
}

#[derive(Clone)]
pub(crate) struct OriginalLineReceipt {
    page: OriginalPageReceipt,
    line: LineAt,
}

impl OriginalPageReceipt {
    pub(crate) fn bind(&self, staged: &NativeStagedAudit) -> Option<OriginalLineReceipt> {
        self.backing
            .target
            .covers(staged)
            .then(|| OriginalLineReceipt {
                page: self.clone(),
                line: staged.line,
            })
    }
}

impl OriginalLineReceipt {
    pub(crate) fn confirms(&self, staged: &NativeStagedAudit) -> bool {
        self.line == staged.line
            && self.page.backing.target.covers(staged)
            && !self.page.backing.credit.is_empty()
            && self.page.backing.run.records().len() == 1
    }
}

impl OriginalChain {
    pub(super) fn is_bound(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .binding
            .is_some()
    }
    pub(super) fn bind(
        &self,
        journal: Arc<RuntimeJournal>,
        key: AuditVerifyingKey,
        head: Head,
    ) -> Result<(), &'static str> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.invalid || state.binding.is_some() {
            return Err("original notary binding already used");
        }
        state.binding = Some(Binding {
            journal,
            key,
            baseline: head.seq,
            tail: head,
            receiver: None,
            exited: None,
            retention_bytes: None,
        });
        Ok(())
    }

    pub(super) fn register(&self, receiver: Weak<RetainedBook>) -> Result<(), &'static str> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let binding = state
            .binding
            .as_mut()
            .ok_or("original notary is not bound")?;
        if binding.receiver.is_some() || receiver.upgrade().is_none() {
            return Err("original receiver unavailable or already registered");
        }
        binding.receiver = Some(receiver);
        Ok(())
    }

    pub(super) fn configure(&self, template: &Stamp) -> Result<(), &'static str> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.invalid {
            return Err("original chain continuity unavailable");
        }
        let binding = state
            .binding
            .as_mut()
            .ok_or("original notary is not bound")?;
        let body = busbar_kernel_audit::stamp_body(template)
            .map_err(|_| "original stamp cannot be encoded")?;
        // StorageCredit accounts requested backing, excluding allocator/Arc control overhead.
        // The canonical one-record stage uses exact WAL bytes, one Record and one hash.
        let bytes = body
            .len()
            .checked_add(busbar_kernel_wal::JOURNAL_HEADER_BYTES)
            .and_then(|n| n.checked_add(std::mem::size_of::<busbar_kernel_wal::Record>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<[u8; 32]>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<StagedRun>()))
            .and_then(|n| n.checked_add(std::mem::size_of::<PageBacking>()))
            .ok_or("original stamp storage overflows")?;
        binding.retention_bytes = Some(bytes);
        Ok(())
    }

    pub(super) fn started(&self, exited: Arc<AtomicBool>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(binding) = state.binding.as_mut() {
            binding.exited = Some(exited);
        }
    }

    pub(super) fn invalidate(&self) {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).invalid = true;
    }

    pub(super) fn unwitnessed(&self) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.binding.is_some() {
            state.invalid = true;
        }
    }

    pub(super) fn ready(self: &Arc<Self>) -> Option<OriginalNotaryReady> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let binding = state.binding.as_ref()?;
        if state.invalid
            || binding.exited.as_ref()?.load(Ordering::Acquire)
            || binding.receiver.as_ref()?.upgrade().is_none()
        {
            return None;
        }
        Some(OriginalNotaryReady {
            chain: self.clone(),
            bytes: binding.retention_bytes?,
        })
    }

    pub(in crate::root::durability) fn check_link(
        &self,
        previous: u64,
        previous_fp: Fingerprint,
    ) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(binding) = state.binding.as_ref() else {
            return true;
        };
        if state.invalid || binding.tail.seq != previous || binding.tail.fp != previous_fp.0 {
            state.invalid = true;
            return false;
        }
        true
    }

    pub(in crate::root::durability) fn witness(
        self: &Arc<Self>,
        head: Head,
        run: &Arc<StagedRun>,
        journal: &Arc<RuntimeJournal>,
    ) -> Option<OriginalLineWitness> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.invalid {
            return None;
        }
        let binding = state.binding.as_mut()?;
        let wal = run.carried().next()?;
        if !Arc::ptr_eq(&binding.journal, journal)
            || binding.tail.seq.checked_add(1) != Some(head.seq)
            || wal.seq != head.node_seq
        {
            state.invalid = true;
            return None;
        }
        Some(OriginalLineWitness {
            chain: self.clone(),
            line: LineAt {
                chain_seq: head.seq,
                node_seq: head.node_seq,
                fp: Fingerprint(head.fp),
            },
            wal_hash: wal.hash,
        })
    }

    pub(super) fn publish(&self, head: Head, witness: Option<&OriginalLineWitness>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(binding) = state.binding.as_mut() else {
            return;
        };
        if witness.is_none_or(|w| {
            w.line.chain_seq != head.seq
                || w.line.fp.0 != head.fp
                || w.line.node_seq != head.node_seq
        }) || binding.tail.seq.checked_add(1) != Some(head.seq)
        {
            state.invalid = true;
            return;
        }
        binding.tail = head;
    }

    pub(super) fn page(self: &Arc<Self>, from: u64, head: Head) -> Option<OriginalPageTarget> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let binding = state.binding.as_ref()?;
        if state.invalid
            || from <= binding.baseline
            || from > head.seq
            || binding.tail.seq != head.seq
            || binding.tail.fp != head.fp
            || binding.tail.node_seq != head.node_seq
        {
            return None;
        }
        Some(OriginalPageTarget {
            chain: self.clone(),
            from,
            to: head,
        })
    }

    pub(super) fn receiver(&self) -> Option<Arc<RetainedBook>> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.invalid {
            return None;
        }
        state.binding.as_ref()?.receiver.as_ref()?.upgrade()
    }

    pub(super) fn bytes(&self) -> Option<usize> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .binding
            .as_ref()?
            .retention_bytes
    }

    pub(super) fn verify(&self, target: &OriginalPageTarget, stamp: &Stamp) -> bool {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(binding) = state.binding.as_ref() else {
            return false;
        };
        !state.invalid
            && std::ptr::eq(self, target.chain.as_ref())
            && stamp.node == binding.journal.node()
            && stamp.sealer == stamp.node
            && stamp.kind == StampKind::Live
            && stamp.key_cert == 0
            && stamp.from == target.from
            && stamp.to == target.to.seq
            && stamp.fingerprint.0 == target.to.fp
            && stamp.down_from_ms == 0
            && stamp.down_to_ms == 0
            && stamp.verify(&binding.key).is_ok()
    }

    pub(super) fn applied(
        &self,
        target: OriginalPageTarget,
        run: Arc<StagedRun>,
        credit: StorageCredit,
    ) -> Result<OriginalPageReceipt, StorageCredit> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let Some(binding) = state.binding.as_ref() else {
            return Err(credit);
        };
        if state.invalid
            || !std::ptr::eq(self, target.chain.as_ref())
            || binding
                .retention_bytes
                .is_none_or(|bytes| credit.len() < bytes)
            || binding.journal.is_confirmed(&run) != Ok(true)
        {
            return Err(credit);
        }
        let valid = run
            .records()
            .first()
            .filter(|_| run.records().len() == 1)
            .and_then(|record| busbar_kernel_wal::JournalRecord::decode(&record.body).ok())
            .filter(|record| {
                record.node == binding.journal.node()
                    && record.class == busbar_kernel_wal::RecordClass::Transaction
            })
            .and_then(|record| {
                busbar_kernel_audit::stamp_from_journal_body(&record.body)
                    .ok()
                    .flatten()
            })
            .is_some_and(|stamp| {
                stamp.node == binding.journal.node()
                    && stamp.sealer == stamp.node
                    && stamp.kind == StampKind::Live
                    && stamp.key_cert == 0
                    && stamp.from == target.from
                    && stamp.to == target.to.seq
                    && stamp.fingerprint.0 == target.to.fp
                    && stamp.verify(&binding.key).is_ok()
            });
        if !valid {
            return Err(credit);
        }
        Ok(OriginalPageReceipt {
            backing: Arc::new(PageBacking {
                run,
                target,
                credit,
            }),
        })
    }
}
