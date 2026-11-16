// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! (red stub) THE EPHEMERAL JOURNAL CUT (SEALING-FIX r20 §3.9): the surface the tests name, with
//! no cut behind it yet.

use super::*;

/// What [`JournalCut::truncate_through`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutProgress {
    Idle,
    Cut { base: u64 },
    Retained,
    Dropped,
    Stopped,
}

/// (red stub) The one cut of an Ephemeral journal.
#[derive(Debug)]
pub struct JournalCut {
    _node: u64,
}

impl JournalCut {
    pub async fn truncate_through(&mut self, _floor: u64) -> CutProgress {
        CutProgress::Idle
    }
    pub async fn settle(&mut self) -> CutProgress {
        CutProgress::Idle
    }
    #[must_use]
    pub fn retained(&self) -> bool {
        false
    }
}

impl RuntimeJournal {
    #[must_use]
    pub fn cutter(self: &Arc<Self>) -> Option<JournalCut> {
        self.is_cut_capable()
            .then_some(JournalCut { _node: self.node })
    }
    #[must_use]
    pub fn is_cut_capable(&self) -> bool {
        self.store.info().durability == busbar_contract::persistence::Durability::Ephemeral
    }
    #[must_use]
    pub fn ordinal_of(&self, seq: u64) -> u64 {
        seq
    }
    #[must_use]
    pub fn pin(&self, _seq: u64) -> Option<Pin> {
        None
    }
    #[must_use]
    pub fn base_count(&self) -> u64 {
        0
    }
    #[must_use]
    pub fn base_tail(&self) -> Option<AuditTail> {
        None
    }
}
