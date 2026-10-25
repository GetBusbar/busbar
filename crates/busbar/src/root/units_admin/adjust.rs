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
//! The body NAMES THE POOL the corrected unit was dispatched through (owner ruling Q64/Q67), so a
//! pool-scoped group budget takes the correction too. It is required and must name a pool this node
//! has configured; a missing or unknown pool is a `400` that says which, and seals nothing.
//!
//! Money stays a read-time view (#71): what a recorded unit costs is the one function
//! (`cost::price_exact`) over the counts it stands at NOW
//! ([`busbar_kernel::audit::amend::counts_now`]) at its own card epoch. Nothing here prices.

use super::AdminAnswer;
use crate::root::durability::{ChainAt, Posting, PostingKind, RecordEra};
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
/// Read-only: a replay of the node's own journal as of the hold `chain` was taken under, read
/// without the book's lock ([`crate::root::durability::Durability::chain_at`]), nothing written.
#[must_use]
pub fn recorded_in(chain: ChainAt, amends: &str) -> Option<RecordedCounts> {
    let Ok(Ok(records)) = chain.read() else {
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
/// "reason": "…", "pool": "<pool name>" }`. Counts are decimal TEXT (#81) and never a money figure (owner ruling Q9). The
/// principal, lane, card epoch and what the counts WERE come from the book (`recorded`), never the
/// body. `scope` is the scope the caller was admitted under; the verbs unit admits `adjust` at
/// `full` only, and the kernel half checks it again.
///
/// Refusals are client-safe: a malformed body, a count that is not an exact decimal, a count below
/// zero, a blank reason or a scope below `full` is `Validation` (400); an entry the book does not
/// hold is `NotFound`. A missing `pool`, or one `pool_known` does not know, answers `400
/// invalid_request` whose message names the fault (Q64/Q67). The answer names the sealed
/// amendment's position and digest, the pool, and the counts it now stands at.
///
/// A COUNT CORRECTION IS A DURABLE VERB (ARCHITECT 2026-10-07 H3 ruling (d)): it moves money (#71).
/// With `journal` bound — the node's journal, which the node amendment journal's sink writes the
/// correction onto as it is sealed (`durability::bind_amendments`) — nothing is sealed while the
/// store is refusing the journal's records, and the answer waits for the store to keep the
/// correction: either refusal is a `503` with the reason. With none bound the node amendment
/// journal is memory-only and there is nothing to wait for.
pub(crate) fn adjust_effect(
    body: &[u8],
    scope: busbar_contract::authz::Scope,
    authorised_by: &str,
    pool_known: &dyn Fn(&str) -> bool,
    journal: Option<&super::AmendmentJournal>,
    recorded: impl FnOnce(&str) -> Option<RecordedCounts>,
) -> Result<AdminAnswer, GovernanceError> {
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
    let Ok(pool) = text("pool") else {
        return Ok(super::error_answer_with_message(
            400,
            "invalid_request",
            "`pool` is required: name the pool the corrected unit was dispatched through",
        ));
    };
    if !pool_known(pool) {
        return Ok(super::error_answer_with_message(
            400,
            "invalid_request",
            &format!("`pool` names `{pool}`, which is not a configured pool"),
        ));
    }
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
    // WHERE THE STORE KEEPS THE JOURNAL, nothing is sealed while it is refusing the journal's
    // records: the correction is refused 503 with the reason.
    if let Some(journal) = journal {
        if let Err(why) = journal.admit() {
            return Ok(super::bound::journal_unavailable(&why));
        }
    }
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
            pool: Some(pool),
        },
    )
    .map_err(|e| match e {
        CorrectionError::NotRoot | CorrectionError::Refused(_) => GovernanceError::Validation,
    })?;
    // AND THE ANSWER WAITS FOR THE STORE. The sink put the correction on the journal as it was
    // sealed, so it is at or below the journal's newest record: once that is kept, so is the
    // correction. Until then it is in force on this node, as the chain holds it, and not answered
    // as done.
    if let Some(journal) = journal {
        if let Err(why) = journal.acked(journal.sealed_through()) {
            return Ok(super::bound::journal_unavailable(&format!(
                "the correction is sealed as amendment {} and not yet kept by the store: {why}; \
                 do not re-submit",
                sealed.seq
            )));
        }
    }
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
        "pool": adj.pool,
        "now": counts,
    }))
    .map(super::json_answer)
    .map_err(|_| GovernanceError::Store)
}
