// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `amend_rate_history` — the signed, dual-controlled verb that back-dates a rate card.
//!
//! A booked line is never rewritten. That one sentence is the whole of this module: an amendment
//! **appends** a dated entry to the card history and emits an **adjusting entry** for every balance
//! the append moved, so the original figure and the correction are both on the record forever. The
//! money it moves rides the `adjustments` column, which the identity already carries, and `settled`
//! does not move by a nano-unit.
//!
//! ## What lives here and what does not
//!
//! This crate depends on `busbar-caps` and nothing else, so it cannot name the history type, the
//! ledger, the journal or a signature algorithm. What it owns is the ADMISSION of an amendment:
//!
//! - the canonical bytes the operator's signature is taken over ([`canonical_payload`]), which are
//!   also the bytes the idempotency slot is named by;
//! - the interval rules ([`check_interval`]) — a `from` in the future, an interval that covers no
//!   instant, and an entry that would predate the opening are each refused BEFORE anything is
//!   appended;
//! - the completeness rule — a partial card is refused, exactly as a partial card is refused on the
//!   config path;
//! - the signature rule — no valid operator signature, no amendment, and the refusal is a
//!   `Refused(Approve, …)` because it is the operator's authority that is missing, not the
//!   caller's scope;
//! - the two idempotencies — the `Idempotency-Key` replay slot every mutating verb takes, and the
//!   payload equality with the newest `Amend` entry that makes a re-sent amendment a no-op
//!   returning the seq it already produced.
//!
//! The effect itself — `History::append` with `Author::Amend`, `adjusting_entries(before, after,
//! …)`, the signed journal batch, `Ledger::record_repricing` — is [`RateHistory::apply_amendment`],
//! a `// contract:` seam the integrator binds. It is called only after every rule above has
//! admitted the call, which is what lets an amendment be refused while its effects are still
//! nothing but a plan.

use crate::refusal::{ReasonCode, Refusal, RefusalStep};
use busbar_caps::AdminToken;

/// The digest width the verb carries for the card and for the reason. Both are hashes taken by the
/// caller (this crate has no digest of its own), and both are fixed-width, which is what lets the
/// canonical encoding below frame them by construction rather than by a length prefix.
pub const DIGEST_LEN: usize = 32;

/// One amendment, as the admin plane decodes it off the wire.
///
/// `card_hash` and `reason_hash` are digests the caller computed: the reason is free text and is
/// hashed INTO the record rather than being the record, and the card is a whole document this
/// crate has no type for. `card_complete` is the decoder's answer to the one question about the
/// card this crate does have an opinion on — a partial card is refused, because a card that names
/// some lanes and not others prices the rest at nothing, silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AmendRequest<'a> {
    /// Inclusive start of the amended window, in wall-clock milliseconds — the same scale the
    /// posting's own arrival instant is in.
    pub from_ms: u64,
    /// Exclusive end, or `None` for an open-ended amendment.
    pub until_ms: Option<u64>,
    /// The digest of the complete card the window is to be priced at.
    pub card_hash: [u8; DIGEST_LEN],
    /// Whether the decoded card names every lane, every class and every currency the history's
    /// currency set declares. A `false` here is a refusal, never a fill-in.
    pub card_complete: bool,
    /// The digest of the operator's stated reason.
    pub reason_hash: [u8; DIGEST_LEN],
    /// Who is amending — the operator key's fingerprint, carried onto every adjusting entry.
    pub operator_fingerprint: &'a str,
    /// The detached operator signature over [`canonical_payload`].
    pub signature: &'a [u8],
}

/// The identity of an already-applied amendment: the four fields two amendments have to agree on
/// for the second to be the first one said twice.
///
/// The signature is deliberately NOT one of them. A detached signature may be randomised, so two
/// signatures over the same payload are not required to be equal bytes; what makes a replay a
/// replay is that the same operator asked for the same card over the same window, and that is
/// exactly these four.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendIdentity {
    /// The window's inclusive start.
    pub from_ms: u64,
    /// The window's exclusive end.
    pub until_ms: Option<u64>,
    /// The card digest.
    pub card_hash: [u8; DIGEST_LEN],
    /// The operator fingerprint.
    pub operator_fingerprint: String,
    /// The history seq the amendment produced, returned verbatim when a replay lands on it.
    pub history_seq: u64,
}

impl AmendIdentity {
    /// Whether `request` names the same amendment this entry already is.
    #[must_use]
    pub fn is_same_amendment(&self, request: &AmendRequest<'_>) -> bool {
        self.from_ms == request.from_ms
            && self.until_ms == request.until_ms
            && self.card_hash == request.card_hash
            && self.operator_fingerprint == request.operator_fingerprint
    }
}

/// What the history can say about itself before an amendment is admitted against it.
///
/// Three facts, and each one refuses a different amendment: the head is what the adjusting entries
/// will be computed FROM, the opening's `effective_from` is the floor no entry may be dated before,
/// and the newest `Amend` is what a re-sent payload is compared against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryBounds {
    /// The current head seq.
    pub head: u64,
    /// The opening entry's `effective_from`. Every instant at or after it is covered by something;
    /// no instant before it is covered by anything, which is why an entry dated before it is a hole
    /// rather than a correction.
    pub opening_effective_from: u64,
    /// The newest entry whose author is `Amend`, if the history holds one.
    pub newest_amend: Option<AmendIdentity>,
}

/// What an admitted amendment did, as the response body reports it.
///
/// `deltas` is per currency and never summed across currencies — two currencies never sum, so a
/// single total would be a number no auditor could reproduce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmendReceipt {
    /// The new head: the seq the appended entry was given.
    pub history_seq: u64,
    /// How many adjusting entries the append emitted.
    pub entries_adjusted: u64,
    /// The delta per currency, in nano-units of that currency's major unit.
    pub deltas: Vec<(String, i128)>,
}

/// The three ways an amendment call can end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmendOutcome {
    /// The amendment was appended and its adjusting entries were emitted.
    Applied(AmendReceipt),
    /// An `Idempotency-Key` replay: the previous call's receipt, verbatim. Nothing was appended and
    /// no figure moved on this call.
    Replayed(AmendReceipt),
    /// The payload equals the newest `Amend` entry's, so this is that amendment said twice: a
    /// no-op returning the `history_seq` it already produced. This is the idempotency that holds
    /// even when the caller sent no `Idempotency-Key` at all, and it is the one the design names —
    /// a signed amendment retried after a timeout must not append a second entry over the same
    /// window at a second seq, because the second would out-rank the first and every adjusting
    /// entry the first left would then describe a card that no longer wins.
    AlreadyAmended {
        /// The seq the original amendment produced.
        history_seq: u64,
    },
}

impl AmendOutcome {
    /// The history seq to report, whichever of the three this is.
    #[must_use]
    pub fn history_seq(&self) -> u64 {
        match self {
            AmendOutcome::Applied(r) | AmendOutcome::Replayed(r) => r.history_seq,
            AmendOutcome::AlreadyAmended { history_seq } => *history_seq,
        }
    }

    /// Whether this call appended anything. `false` for both idempotent outcomes.
    #[must_use]
    pub fn appended(&self) -> bool {
        matches!(self, AmendOutcome::Applied(_))
    }
}

/// The rate-history seam: the three things this crate needs an integrator to do, and nothing more.
///
/// Every method is `// contract:`. The crate holds no history type, no ledger, no journal and no
/// signature algorithm, so all three of these are the integrator's — bound over
/// `busbar_unit_cost::History` (`append`, `Author::Amend`) and
/// `busbar_unit_ledger::{adjusting_entries, Ledger::record_repricing}` in the target composition.
pub trait RateHistory {
    /// `// contract:` the three facts of [`HistoryBounds`], read from the sealed history.
    ///
    /// # Errors
    ///
    /// The history could not be read. A node that cannot read its own history refuses the
    /// amendment rather than appending against a head it guessed.
    fn bounds(&self) -> Result<HistoryBounds, crate::governance::GovernanceError>;

    /// `// contract:` verify a detached operator signature over `canonical` for the operator named
    /// by `fingerprint`.
    ///
    /// Returns `false` for every failure — an unknown fingerprint, a malformed signature, a
    /// signature over other bytes — because the caller has one decision to make and a taxonomy of
    /// cryptographic failures would only invite it to make a second. There is no default
    /// implementation ON PURPOSE: a default returning `true` is a fleet with no operator control at
    /// all, and a default returning `false` is a verb that can never be called, so the integrator
    /// binds this or does not bind the verb.
    fn verify_operator_signature(
        &self,
        fingerprint: &str,
        canonical: &[u8],
        signature: &[u8],
    ) -> bool;

    /// `// contract:` the amendment's whole effect, in one journal batch: append the dated entry
    /// (`Author::Amend { operator_fingerprint, reason_hash }`), compute the adjusting entries
    /// against the head recorded in `bounds`, sign and journal them, and move each balance by its
    /// delta alone.
    ///
    /// Called ONLY after every rule in this module has admitted the call, so an implementor is not
    /// asked to re-check a signature, an interval or a replay.
    ///
    /// # Errors
    ///
    /// The append or the journal batch failed. Nothing partial is expected to survive: the batch is
    /// the unit of durability, which is why the entry and its adjusting entries are one call and
    /// not two.
    fn apply_amendment(
        &self,
        admin: &AdminToken,
        request: &AmendRequest<'_>,
        canonical: &[u8],
    ) -> Result<AmendReceipt, crate::governance::GovernanceError>;
}

/// The canonical bytes an amendment is signed over, and the bytes its replay slot is named by.
///
/// **Every variable-width field is length-framed, and the two digests are fixed-width.** The
/// fingerprint is text the caller chooses and the window is a pair of numbers whose decimal
/// spellings run into each other; joining them on a separator would make
/// `("op:1", 2)` and `("op", "1:2")` one string, and a signature over one payload would then verify
/// against a different amendment — a different operator, or a different window, or both. Framing
/// each field by its own length puts the boundary somewhere no field's content can move it.
///
/// The encoding is deliberately not a serialization format: it is a byte string with one job, so it
/// has no schema to evolve, no map whose iteration order could differ between two nodes, and no
/// place a field could be omitted and still parse.
#[must_use]
pub fn canonical_payload(request: &AmendRequest<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    // A tag, so a signature over an amendment can never verify as a signature over anything else
    // this deployment ever asks an operator to sign.
    frame(&mut out, b"busbar.amend_rate_history.v1");
    frame(&mut out, request.from_ms.to_string().as_bytes());
    match request.until_ms {
        // The two arms are distinguishable BEFORE their contents: an open-ended amendment and one
        // that ends at instant 0 must not encode alike.
        None => frame(&mut out, b"open"),
        Some(until) => {
            frame(&mut out, b"until");
            frame(&mut out, until.to_string().as_bytes());
        }
    }
    frame(&mut out, &request.card_hash);
    frame(&mut out, &request.reason_hash);
    frame(&mut out, request.operator_fingerprint.as_bytes());
    out
}

/// Write one length-framed field: the length in decimal, a colon, then the bytes. The colon is
/// inside the frame the length already fixed, so a field containing a colon cannot move it.
fn frame(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(field.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(field);
}

/// The interval rules, checked before anything is appended.
///
/// Three refusals, and each names a different thing the caller got wrong:
///
/// - **A `from` in the future** is not an amendment at all. Back-dating means correcting what has
///   already happened; an entry effective from a time that has not arrived is the from-now append
///   path, which is `PUT /config/settings` and takes no operator signature because it moves no
///   money that was ever booked. Admitting it here would let the signed verb quietly become the
///   config path, with a ceremony nobody needed and an adjusting-entry batch over an empty set.
/// - **An interval that covers no instant** (`until <= from`) is refused as a hole. It claims a
///   window and prices nothing in it; the entry would sit in the history out-ranking nothing, and
///   the receipt would report an amendment that moved no line, which reads as "there was nothing to
///   correct" rather than as "you named an empty window".
/// - **An entry dated before the opening** is refused as a hole for the reason §3.4 of the design
///   gives: the opening is what makes a hole impossible, because it covers every instant from its
///   own start with no end. An entry effective before it claims instants the history has no opening
///   for, and pricing them would be pricing a period the deployment has no card for at all — which
///   the lookup answers as a refusal, never as a zero.
///
/// # Errors
///
/// One of the three above, as a [`Refusal`] at the `Verify` step — the call was properly
/// authorized, and it is the amendment's own arguments that are wrong.
pub fn check_interval(
    request: &AmendRequest<'_>,
    bounds: &HistoryBounds,
    now_ms: u64,
) -> Result<(), Refusal> {
    if request.from_ms > now_ms {
        return Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation));
    }
    if request.from_ms < bounds.opening_effective_from {
        return Err(Refusal::new(
            RefusalStep::Verify,
            ReasonCode::PredatesOpening,
        ));
    }
    if let Some(until) = request.until_ms {
        if until <= request.from_ms {
            return Err(Refusal::new(RefusalStep::Verify, ReasonCode::HistoryHole));
        }
    }
    Ok(())
}

/// The card-completeness rule: a partial card is refused, never completed.
///
/// The config path already refuses a partial card, and the reason is the same on both: the card's
/// class map is string-keyed and a class it is silent about prices at nothing. On the config path
/// that would under-bill from now on; here it would under-bill a window that has already been
/// invoiced, and leave an adjusting entry saying so in the operator's own name.
///
/// # Errors
///
/// The card does not name everything the history's currency set requires.
pub fn check_card_complete(request: &AmendRequest<'_>) -> Result<(), Refusal> {
    if request.card_complete {
        Ok(())
    } else {
        Err(Refusal::new(RefusalStep::Verify, ReasonCode::Validation))
    }
}

/// The signature rule.
///
/// Refused at the `Approve` step rather than `Admit`, and the distinction is the audit trail: an
/// `Admit` refusal says the caller was not allowed to ask, and this caller was — they hold a
/// full-scope admin credential and the fleet's dual control let them through. What is missing is
/// the OPERATOR's authority, which is a separate thing from the administrator's, and which is the
/// only thing standing between a full-scope credential and a rewrite of last month's invoice.
///
/// # Errors
///
/// The signature does not verify for the named fingerprint over the canonical payload.
pub fn check_signature<H: RateHistory>(
    history: &H,
    request: &AmendRequest<'_>,
    canonical: &[u8],
) -> Result<(), Refusal> {
    if history.verify_operator_signature(request.operator_fingerprint, canonical, request.signature)
    {
        Ok(())
    } else {
        Err(Refusal::new(
            RefusalStep::Approve,
            ReasonCode::OperatorSignatureInvalid,
        ))
    }
}

/// The replay-slot name for an amendment's `Idempotency-Key`.
///
/// The verb's own name, then the canonical payload, then the header value — **each length-framed**,
/// by exactly the rule `rotate_key` learned: both halves are text the caller chooses, so joining
/// them on a separator either may contain does not make a key, it makes a coincidence. Two
/// amendments over different windows sharing one header value must not land on one slot, and one
/// amendment retried must land on its own.
///
/// The canonical payload is IN the slot name on purpose. The two legacy replayable operations key
/// on the header alone, matching 1.5.5 exactly — a retry with the same key and a different body
/// replays the first response there. That parity clause is 1.5.5's and does not extend to a verb
/// 1.5.5 never had: here, a second amendment sent under a header value the caller happened to reuse
/// would replay a receipt for a window it never named, reporting a `history_seq` and a delta that
/// belong to somebody else's correction.
#[must_use]
pub fn replay_slot(canonical: &[u8], idempotency_key: &str) -> String {
    let mut slot = String::from("amend_rate_history:");
    slot.push_str(&canonical.len().to_string());
    slot.push(':');
    // The canonical payload is bytes, and a slot name is a string; the payload is already framed
    // internally, so its hex is a faithful, total encoding of it with no escaping question.
    for byte in canonical {
        slot.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        slot.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    slot.push(':');
    slot.push_str(&idempotency_key.len().to_string());
    slot.push(':');
    slot.push_str(idempotency_key);
    slot
}

#[cfg(test)]
#[path = "tests/amend_tests.rs"]
mod tests;
