// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CHECKPOINTS A NODE HOLDS, RE-DERIVED (Q128 kernel-ledger HIGH 1, ARCHITECT ruling A1).
//!
//! The node keeps each seal's head and not its balances ([`CheckpointHead`]); a reader that needs
//! the sealed figures has them re-derived here from the chain, through the configured store, in
//! ONE ordered walk of the WHOLE chain ([`Durability::chain`]: on a node resumed from the store, the
//! store's copy joined to the resident segment): the records fold into a single scratch book, and
//! at each held checkpoint's own record the book is the checkpoint's totals. The body digest then
//! says whether they are the sealed ones. A checkpoint whose figures the chain does not reproduce,
//! whose record is not on the chain, or whose journal cannot be read is a typed refusal naming its
//! sequence number — never zeros and never the wrong numbers.

use super::*;

/// Why a held checkpoint cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointUnreadable {
    /// The journal could not be read back, or does not verify.
    Journal {
        /// The first held checkpoint the read could not serve.
        checkpoint_seq: u64,
        /// What the journal answered.
        why: String,
    },
    /// No record on the chain carries this checkpoint.
    NotOnChain {
        /// Which checkpoint.
        checkpoint_seq: u64,
    },
    /// The chain re-derives figures that do not hash to this checkpoint's sealed digest: a figure
    /// the book moved with no record behind it, or a record changed since.
    Diverged {
        /// Which checkpoint.
        checkpoint_seq: u64,
    },
}

impl CheckpointUnreadable {
    /// The checkpoint the refusal names.
    #[must_use]
    pub fn checkpoint_seq(&self) -> u64 {
        match self {
            CheckpointUnreadable::Journal { checkpoint_seq, .. }
            | CheckpointUnreadable::NotOnChain { checkpoint_seq }
            | CheckpointUnreadable::Diverged { checkpoint_seq } => *checkpoint_seq,
        }
    }
}

impl std::fmt::Display for CheckpointUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckpointUnreadable::Journal {
                checkpoint_seq,
                why,
            } => write!(
                f,
                "checkpoint {checkpoint_seq}: the journal its figures are read from {why}"
            ),
            CheckpointUnreadable::NotOnChain { checkpoint_seq } => write!(
                f,
                "checkpoint {checkpoint_seq}: no record on the chain carries it"
            ),
            CheckpointUnreadable::Diverged { checkpoint_seq } => write!(
                f,
                "checkpoint {checkpoint_seq}: the chain re-derives figures that are not the sealed ones"
            ),
        }
    }
}

impl std::error::Error for CheckpointUnreadable {}

/// The checkpoint sequence a checkpoint record carries: the first field of its body.
fn record_checkpoint_seq(record: &JournalRecord) -> Option<u64> {
    (record.class == RecordClass::Checkpoint)
        .then(|| BodyReader::new(&record.body).num())
        .flatten()
}

impl Durability {
    /// EVERY CHECKPOINT THIS NODE HOLDS, OLDEST FIRST, each handed to `each` with the balances the
    /// chain re-derives for it (the same set the ring holds; nothing is rebuilt at boot).
    ///
    /// One ordered walk of the journal per distinct history the held checkpoints were sealed
    /// against (one, unless the card history moved between seals), folding into a single scratch
    /// book; a checkpoint is handed over as its own record is reached, so the read holds one
    /// scratch book and one checkpoint at a time.
    ///
    /// # Errors
    ///
    /// The first held checkpoint that cannot be served, by its sequence number.
    pub fn each_held_checkpoint(
        &self,
        each: &mut dyn FnMut(&Checkpoint),
    ) -> Result<(), CheckpointUnreadable> {
        let Some(first) = self.checkpoints.first() else {
            return Ok(());
        };
        // THE WHOLE CHAIN, as `/verify` reads it (`Durability::chain`): on a node resumed from the
        // store the journal's own replay is only its resident memory segment, a suffix once the
        // chain outgrows one, and a walk of a suffix re-derives nothing a held checkpoint sealed.
        let records = match self.chain() {
            Ok(Ok(records)) => records,
            Ok(Err(broken)) => {
                return Err(CheckpointUnreadable::Journal {
                    checkpoint_seq: first.checkpoint_seq,
                    why: format!("does not verify: {broken:?}"),
                })
            }
            Err(e) => {
                return Err(CheckpointUnreadable::Journal {
                    checkpoint_seq: first.checkpoint_seq,
                    why: format!("could not be read: {e}"),
                })
            }
        };
        let pinned = (self.history)();
        let mut at = 0;
        while let Some(head) = self.checkpoints.get(at) {
            let history_seq = head.history_seq;
            let view = match (pinned.as_ref(), history_seq) {
                (Some(pinned), Some(seq)) => Some(pinned.view_at(seq)),
                _ => None,
            };
            let mut scratch = Ledger::new();
            let mut replay = Replayer::new(view.as_ref(), false);
            let started = at;
            for record in &records {
                let Some(head) = self.checkpoints.get(at) else {
                    break;
                };
                if head.history_seq != history_seq {
                    break;
                }
                if record_checkpoint_seq(record) == Some(head.checkpoint_seq) {
                    // The chain still carries every window the book let go; the book this
                    // seal was taken from did not (row 159's retirement). They leave the scratch
                    // book here, at the seal that left them out, as they left the book; a posting
                    // on one after that rebuilds it from that posting alone, as it did the book's.
                    let left_behind = self.left_behind_at(head.checkpoint_seq, scratch.book());
                    scratch.retire_windows(&left_behind);
                    let checkpoint = head.with_totals(scratch.book().snapshot());
                    if !checkpoint.body_hash_verifies() {
                        return Err(CheckpointUnreadable::Diverged {
                            checkpoint_seq: head.checkpoint_seq,
                        });
                    }
                    each(&checkpoint);
                    at += 1;
                    continue;
                }
                replay.step(&mut scratch, record);
            }
            if at == started {
                return Err(CheckpointUnreadable::NotOnChain {
                    checkpoint_seq: head.checkpoint_seq,
                });
            }
        }
        Ok(())
    }
}
