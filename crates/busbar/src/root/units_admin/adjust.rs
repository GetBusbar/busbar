// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `adjust` VERB'S EFFECT** (item 404, OWNER RULING Q9): a root correction to a recorded
//! unit's COUNTS, never to a money figure.
//!
//! The kernel half ([`busbar_kernel::audit::amend::correct_counts`]) seals the correction on the
//! node amendment journal and refuses a count below zero, a blank reason and any scope below
//! `full`. This half is the composition root's: it decodes the body, reads what the book RECORDED
//! for the entry the correction names ([`recorded_in`]) — the lane, the card epoch (#79) and the
//! counts, never from the body, so a correction cannot misstate what it corrects — and hands both
//! to the kernel half.
//!
//! Money stays a read-time view (#71): what a recorded unit costs is the one function
//! (`cost::price_exact`) over the counts it stands at NOW
//! ([`busbar_kernel::audit::amend::counts_now`]) at its own card epoch. Nothing here prices.

use crate::root::durability::{Durability, Posting, PostingKind, RecordEra};
use busbar_contract::count::Count;
use busbar_core_admin::GovernanceError;
use busbar_kernel::audit::amend::{
    correct_counts, AmendBody, ClassCounts, CorrectionError, CountCorrection,
};

/// What the book recorded for one unit: whose it was, its lane, its card epoch (#79), its billable
/// request count and its counts per class. Read off the journal record the correction names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCounts {
    /// Whose unit it was — the principal the posting was written for.
    pub principal: String,
    /// The serving lane, the key a card entry is written against.
    pub lane: String,
    /// THE CARD EPOCH: the unit's arrival instant in milliseconds, whose card its counts price at.
    pub card_epoch_ms: u64,
    /// How many billable requests the unit is. A count correction never moves it.
    pub fee_count: u64,
    /// The counts per class, as recorded.
    pub classes: ClassCounts,
}

/// The counts the book recorded for the entry whose journal digest is `amends` (64 hex
/// characters, the record's chain hash), or `None` when the chain holds no such entry or the entry
/// carries no counts to correct: a hold, a claim, an overdraft carry, an audit record, or a
/// figures-era posting written before the chain carried counts.
///
/// Read-only: a replay of the node's own journal, nothing written.
#[must_use]
pub fn recorded_in(durability: &Durability, amends: &str) -> Option<RecordedCounts> {
    let Ok(Ok(records)) = durability.journal.replay() else {
        return None;
    };
    let record = records
        .iter()
        .find(|record| hex::encode(record.hash).eq_ignore_ascii_case(amends))?;
    let posting = Posting::from_record(record)?;
    if posting.kind == PostingKind::Carry || posting.era != RecordEra::Counts {
        return None;
    }
    let counts = posting.counts?;
    let classes = counts
        .classes
        .iter()
        .map(|(class, n)| Some((class.clone(), Count::from_integer(i128::from(*n)).ok()?)))
        .collect::<Option<ClassCounts>>()?;
    Some(RecordedCounts {
        principal: posting.principal,
        lane: counts.lane,
        card_epoch_ms: posting.arrived_ms,
        fee_count: counts.fee_count,
        classes,
    })
}

/// The effect half of `adjust`: decode a COUNT correction and hand it to the kernel half, which
/// seals it on the node amendment journal.
///
/// The body is `{ "amends": "<journal digest>", "now": { "<class>": "<decimal count>", … },
/// "reason": "…" }`. Counts are decimal TEXT (#81) and never a money figure (owner ruling Q9). The
/// principal, lane, card epoch and what the counts WERE come from the book (`recorded`), never the
/// body. `scope` is the scope the caller was admitted under; the verbs unit admits `adjust` at
/// `full` only, and the kernel half checks it again.
///
/// Refusals are client-safe: a malformed body, a count that is not an exact decimal, a count below
/// zero, a blank reason or a scope below `full` is `Validation` (400); an entry the book does not
/// hold is `NotFound`. The answer names the sealed amendment's position and digest and the counts
/// it now stands at.
pub(crate) fn adjust_effect(
    body: &[u8],
    scope: busbar_contract::authz::Scope,
    authorised_by: &str,
    recorded: impl FnOnce(&str) -> Option<RecordedCounts>,
) -> Result<Vec<u8>, GovernanceError> {
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let text = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or(GovernanceError::Validation)
    };
    let amends = text("amends")?;
    let reason = text("reason")?;
    let mut now = ClassCounts::new();
    for (class, count) in obj
        .get("now")
        .and_then(serde_json::Value::as_object)
        .filter(|m| !m.is_empty())
        .ok_or(GovernanceError::Validation)?
    {
        let count = count.as_str().ok_or(GovernanceError::Validation)?;
        let count = Count::parse(count).map_err(|_| GovernanceError::Validation)?;
        now.insert(class.clone(), count);
    }
    let was = recorded(amends).ok_or(GovernanceError::NotFound)?;
    let sealed = correct_counts(
        scope,
        &was.classes,
        CountCorrection {
            amends,
            principal: Some(&was.principal),
            lane: &was.lane,
            card_epoch_ms: was.card_epoch_ms,
            now,
            authorised_by,
            reason,
        },
    )
    .map_err(|e| match e {
        CorrectionError::NotRoot | CorrectionError::Refused(_) => GovernanceError::Validation,
    })?;
    let AmendBody::Adjust(adj) = &sealed.body else {
        return Err(GovernanceError::Store);
    };
    let counts: serde_json::Map<String, serde_json::Value> = adj
        .now
        .iter()
        .map(|(c, n)| (c.clone(), serde_json::Value::String(n.to_decimal_string())))
        .collect();
    serde_json::to_vec(&serde_json::json!({
        "seq": sealed.seq,
        "hash": sealed.hash,
        "amends": adj.amends_hash,
        "lane": adj.lane,
        "card_epoch_ms": adj.card_epoch_ms,
        "now": counts,
    }))
    .map_err(|_| GovernanceError::Store)
}
