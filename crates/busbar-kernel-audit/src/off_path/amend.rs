// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The amendment journal's restore half: a run read back off durable storage, and the held run
//! copied out to hand to one.

use crate::amend::{
    AmendChain, AmendCommit, AmendJournal, AmendPersistError, AmendSink, Amendment,
    AMENDMENTS_RETAINED,
};
use crate::record::{displays_as, Subject, SubjectValue};

/// The subject [`crate::amend::subject_fields`] wrote, or `None` for a pair it never writes.
pub fn subject_from_fields(tag: &str, value: &str) -> Option<Subject> {
    let subject = match tag {
        "principal" => Subject::principal(value),
        "arrival" => Subject::Arrival,
        "node" => Subject::Node(value.parse().ok()?),
        "aggregate" => Subject::Aggregate,
        _ => return None,
    };
    displays_as(SubjectValue(&subject), value).then_some(subject)
}

impl AmendJournal {
    /// REBUILD A JOURNAL FROM A WHOLE RUN read back off durable storage, oldest first from the
    /// genesis: verified whole, then the newest [`AMENDMENTS_RETAINED`] held.
    pub fn restore(run: Vec<Amendment>) -> Result<AmendJournal, crate::record::AuditBreak> {
        AmendChain::verify(&run)?;
        let chain = run.last().map_or_else(AmendChain::new, |a| {
            AmendChain::resume(a.hash.clone(), a.seq.saturating_add(1))
        });
        let released = run.len().saturating_sub(AMENDMENTS_RETAINED);
        let recent = run.into_iter().skip(released).collect();
        Ok(AmendJournal::from_parts(chain, recent, released as u64))
    }
}

/// Stage every amendment `journal` holds above `journalled_through` with `sink`, in order: what a
/// sink bound once at boot has not journalled yet.
pub(crate) fn stage_unjournalled(
    journal: &AmendJournal,
    sink: &dyn AmendSink,
    journalled_through: u64,
) -> Result<Vec<AmendCommit>, AmendPersistError> {
    let mut pending = Vec::new();
    for amendment in journal
        .recent()
        .filter(|amendment| amendment.seq > journalled_through)
    {
        pending.push(sink.sealed(amendment)?);
    }
    Ok(pending)
}

/// The run `journal` holds, oldest first, copied out whole to hand to a restore.
pub(crate) fn copy_run(journal: &AmendJournal) -> Vec<Amendment> {
    journal.recent().cloned().collect()
}
