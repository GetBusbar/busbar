// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CHAINED RECORD KINDS a plane declares (`PlaneTail::record_chains`): a record write of one
//! does not ride the write-behind's last-write-wins put; it is APPENDED to the kernel's generic
//! scope-keyed journal ([`crate::audit::journal`]). The host frames each record's prelude (previous
//! digest, scope if the chain digests it, sequence) in the framing the plane declared, joins the
//! plane's own field bytes RAW, digests, links and persists through the store's plane-record slots
//! (abi/plane `RecordChain`: "The host frames each record's prelude ... joins the plane's own field
//! bytes and verifies the chain"). The plane names no chain mechanism and holds no position.
//!
//! OWNER RULING RULE-CHECK 2026-09-30 (`1.6.0-TODO.md`): the call log MOVES to the mcp plane over
//! the generic journal append, and its sink folds into `audit::journal`. This is that append, for
//! any plane and any declared chained kind: it names no plane noun.
//!
//! A chain's store parent is the instance's: its label, length-counted, then the plane's scope
//! (the record write's key), so two instances of one plane never share a chain (the per-instance key
//! rule of [`crate::host_records::record_key`]). The stored body is the journal's neutral
//! `{seq, prev_hash, hash, content}` envelope. Positions resume from the store on an instance's first
//! append after boot ([`ChainedKind::append`] rehydrates once), so a restart never forks a chain at
//! sequence 1.

use std::sync::{Arc, Mutex, OnceLock};

use busbar_contract::abi::plane::{
    RecordChain, CHAIN_DIGESTS_SCOPE, CHAIN_LENGTH_PREFIXED, CHAIN_PIPE_SEPARATED,
};
use busbar_contract::records::RecordStoreResult;

use crate::audit::journal::{Journal, NeutralBody};
use crate::audit::Framing;
use crate::plane::store::{decode, PlaneStore};
use crate::plane_host::journal::{PlaneJournalInput, PlaneJournalRecord};

/// How many scope positions one chained kind of one instance caches before the coldest is evicted
/// (and resumed from the store on its next append).
const POSITIONS_CAP: usize = 4096;

/// The refusal of an append whose scope is not UTF-8: a chain's store parent is text.
pub const SCOPE_NOT_TEXT: &str = "a chained record's key is not UTF-8";
/// The answer of an append the store did not take.
pub const APPEND_FAILED: &str = "the store did not take the chained record";

/// The framing a declared chain keeps; `None` for a framing word this host does not know (the tail
/// check refuses it at load, so a bound plane never names one).
fn framing_of(chain: &RecordChain) -> Option<Framing> {
    match chain.framing {
        CHAIN_LENGTH_PREFIXED => Some(Framing::LengthPrefixed),
        CHAIN_PIPE_SEPARATED => Some(Framing::PipeSeparated),
        _ => None,
    }
}

/// The store parent of `scope` for the instance labelled `instance`: the label's byte length, the
/// label, then the scope, so the split is unambiguous whatever either holds.
#[must_use]
pub fn chain_parent(instance: &str, scope: &str) -> String {
    format!("{}:{instance}:{scope}", instance.len())
}

/// ONE CHAINED KIND of one instance: its framing, its journal, and whether its positions were
/// resumed from the store.
pub(crate) struct ChainedKind {
    kind: String,
    framing: Framing,
    digests_scope: bool,
    journal: Journal<PlaneJournalRecord>,
    restored: OnceLock<()>,
    /// Serialises the one-time rehydrate against a first append racing it.
    restoring: Mutex<()>,
}

impl ChainedKind {
    /// The chained kind `kind` under `chain`'s declaration; `None` for a framing this host does not
    /// know.
    pub(crate) fn new(kind: &str, chain: &RecordChain) -> Option<Self> {
        Some(ChainedKind {
            kind: kind.to_string(),
            framing: framing_of(chain)?,
            digests_scope: chain.flags & CHAIN_DIGESTS_SCOPE != 0,
            journal: Journal::new(POSITIONS_CAP),
            restored: OnceLock::new(),
            restoring: Mutex::new(()),
        })
    }

    /// The reframe of one stored neutral body under its store parent.
    fn reframe(&self) -> impl Fn(&str, &[u8]) -> RecordStoreResult<PlaneJournalRecord> + '_ {
        move |scope, body| {
            let b: NeutralBody = decode(body)?;
            Ok(PlaneJournalRecord::from_parts(
                scope.to_string(),
                b.seq,
                b.prev_hash,
                b.hash,
                b.content,
                self.framing,
                self.digests_scope,
            ))
        }
    }

    /// APPEND `content` (the plane's own field bytes, framed by it) to the chain of `scope` for the
    /// instance labelled `instance`, through `store`. Blocking: the caller runs it on the pool. The
    /// first append of the process rehydrates every position this kind holds in the store, so a
    /// restart resumes each chain from its tail. Durable before it answers `Ok`.
    ///
    /// # Errors
    ///
    /// [`SCOPE_NOT_TEXT`] or [`APPEND_FAILED`]; nothing is committed then, and the next append
    /// reuses the sequence.
    pub(crate) fn append(
        &self,
        store: &Arc<dyn PlaneStore>,
        instance: &str,
        scope: &[u8],
        content: Vec<u8>,
    ) -> Result<(), &'static str> {
        let scope = std::str::from_utf8(scope).map_err(|_| SCOPE_NOT_TEXT)?;
        let reframe = self.reframe();
        if self.restored.get().is_none() {
            let _one = self
                .restoring
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.restored.get().is_none() {
                self.journal.set_sink(Arc::clone(store));
                // A break is REPORTED and the chain still resumed from its tail (the journal's
                // rule); an unreadable store refuses the append rather than forking at seq 1.
                let restored = self
                    .journal
                    .restore_scoped(&self.kind, store.as_ref(), &reframe)
                    .map_err(|_| APPEND_FAILED)?;
                self.report(&restored.chain_breaks);
                let _ = self.restored.set(());
            }
        }
        let parent = chain_parent(instance, scope);
        let appended = self
            .journal
            .append_scoped(
                &self.kind,
                &parent,
                PlaneJournalInput::new(content, self.framing, self.digests_scope),
                &reframe,
            )
            .map(|_| ())
            .map_err(|_| APPEND_FAILED);
        self.report(&self.journal.take_resume_breaks());
        appended
    }

    /// Report each chain `breaks` names: tamper evidence, the chain resumed from its tail.
    fn report(&self, breaks: &[crate::audit::ChainBreak]) {
        for brk in breaks {
            crate::diagnostics::diag_error!(
                crate::diagnostics::PLANE_JOURNAL_RESUME_CHAIN_BROKEN,
                kind = %self.kind,
                error = %brk,
                "a plane's chained record kind does not verify from its stored tail; the chain \
                 resumes from that tail and the break stays in the store as evidence"
            );
        }
    }

    /// The next sequence `scope`'s chain will carry for the instance labelled `instance` (a
    /// witness).
    #[cfg(test)]
    #[must_use]
    pub(crate) fn next_seq(&self, instance: &str, scope: &str) -> u64 {
        self.journal.next_seq(&chain_parent(instance, scope))
    }

    /// Re-digest the stored chain of `scope` for the instance labelled `instance`: `None` when it
    /// verifies.
    ///
    /// # Errors
    ///
    /// The store's.
    #[cfg(test)]
    pub(crate) fn verify(
        &self,
        store: &dyn PlaneStore,
        instance: &str,
        scope: &str,
    ) -> RecordStoreResult<Option<crate::audit::ChainBreak>> {
        self.journal.verify_scoped(
            &self.kind,
            &chain_parent(instance, scope),
            store,
            &self.reframe(),
        )
    }
}
