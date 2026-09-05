// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The chain mechanism, ported from the previous release.
//!
//! Two jobs, and the second is what makes the move safe:
//!
//! 1. **THE FOUR TAMPERS.** A chain whose links are never recomputed proves nothing, because nobody
//!    ever finds out that it does not verify. So alteration, reordering, insertion and deletion are
//!    each performed here, and the verifier is required to NAME which one it was.
//!
//! 2. **THE DIGEST DID NOT MOVE.** The admin record was already hash-chained on disk before this
//!    crate existed. The golden vector below recomputes the formula independently, the old way, and
//!    requires the mechanism to agree byte for byte. A digest that changed would report every
//!    persisted chain as tampered at the next boot.
//!
//! And a third that is really the seam's acceptance test: a throwaway FOURTH record type is declared
//! here and nowhere else, and it chains, verifies and reports every tamper with no new mechanism. If
//! a future stream needs a chain type, a digest, a verifier or an error of its own, the seam failed.

use crate::legacy::chain::{
    digest, seal, sha256_hex, verify_chain, verify_window, Chain, ChainBreakKind, ChainLabels,
    ChainedRecord, Digest, Framing,
};
use crate::legacy::{AuditEntry, AuditInput, OUTCOME_APPLIED};

// ── THE FOURTH STREAM ────────────────────────────────────────────────────────────────────────────
//
// A record type that exists ONLY in this file, for a stream busbar does not have. Deliberately
// unlike the real one: a different scope noun, different field types, and a field the digest covers
// beside a field it does not.

/// A throwaway fourth record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nonsense {
    tenant: String,
    seq: u64,
    what: String,
    amount: u64,
    /// A join key, EXCLUDED from the digest exactly as the real streams exclude theirs.
    trace: String,
    prev_hash: String,
    hash: String,
}

struct NonsenseInput {
    what: String,
    amount: u64,
    trace: String,
}

impl ChainedRecord for Nonsense {
    type Input = NonsenseInput;

    const LABELS: &'static ChainLabels = &ChainLabels {
        chain: "the nonsense chain",
        scope: "tenant",
    };
    const FRAMING: Framing = Framing::LengthPrefixed;

    fn scope_of(&self) -> &str {
        &self.tenant
    }
    fn seq(&self) -> u64 {
        self.seq
    }
    fn prev_hash(&self) -> &str {
        &self.prev_hash
    }
    fn hash(&self) -> &str {
        &self.hash
    }
    fn link(scope: &str, seq: u64, prev_hash: String, input: NonsenseInput) -> Self {
        Nonsense {
            tenant: scope.to_string(),
            seq,
            what: input.what,
            amount: input.amount,
            trace: input.trace,
            prev_hash,
            hash: String::new(),
        }
    }
    fn set_hash(&mut self, hash: String) {
        self.hash = hash;
    }
    fn digest_fields(&self, d: &mut Digest) {
        d.text(&self.prev_hash)
            .text(&self.tenant)
            .num(self.seq)
            .text(&self.what)
            .num(self.amount);
    }
}

fn nonsense_input(what: &str, amount: u64) -> NonsenseInput {
    NonsenseInput {
        what: what.to_string(),
        amount,
        trace: format!("trace-{what}"),
    }
}

fn a_chain() -> Vec<Nonsense> {
    let mut chain: Chain<Nonsense> = Chain::new();
    ["made", "broke", "mended"]
        .into_iter()
        .enumerate()
        .map(|(i, what)| chain.append("acme", nonsense_input(what, i as u64 * 10)))
        .collect()
}

#[test]
fn a_fourth_stream_costs_a_record_type_and_nothing_else() {
    let records = a_chain();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].seq, 1);
    assert_eq!(records[0].prev_hash, "");
    assert_eq!(records[1].prev_hash, records[0].hash);
    assert_eq!(records[2].prev_hash, records[1].hash);
    assert!(verify_chain(&records).is_ok());
}

#[test]
fn altering_a_record_in_place_is_detected_and_located() {
    let mut records = a_chain();
    records[1].amount += 1;
    let brk = verify_chain(&records).unwrap_err();
    assert_eq!(brk.at_index, 2);
    assert!(matches!(brk.kind, ChainBreakKind::DigestMismatch { .. }));
    assert!(brk.to_string().contains("EDITED"));
}

#[test]
fn deleting_a_record_from_the_middle_is_detected() {
    let mut records = a_chain();
    records.remove(1);
    let brk = verify_chain(&records).unwrap_err();
    assert_eq!(brk.at_index, 2);
    assert!(matches!(brk.kind, ChainBreakKind::SequenceBreak { .. }));
}

#[test]
fn reordering_two_records_is_detected() {
    let mut records = a_chain();
    records.swap(1, 2);
    let brk = verify_chain(&records).unwrap_err();
    assert!(matches!(brk.kind, ChainBreakKind::SequenceBreak { .. }));
}

#[test]
fn inserting_a_self_consistent_forgery_is_detected_by_its_link() {
    let mut records = a_chain();
    // A forgery that hashes correctly ON ITS OWN — the interesting case, because a digest check
    // alone waves it through.
    let forged: Nonsense = seal(
        "acme",
        2,
        records[0].hash.clone(),
        nonsense_input("forged", 999),
    );
    assert_eq!(
        digest(&forged),
        forged.hash,
        "the forgery is self-consistent"
    );
    let mut inserted = records.clone();
    inserted.insert(1, forged.clone());
    let brk = verify_chain(&inserted).unwrap_err();
    // The forgery itself passes both checks; its SUCCESSOR is where the chain notices, and what it
    // notices first is the DUPLICATED position — an insertion pushes every later record's real
    // position out of line, and the sequence check names that more precisely than the link would.
    assert_eq!(brk.at_index, 3);
    assert!(matches!(brk.kind, ChainBreakKind::SequenceBreak { .. }));

    // SUBSTITUTION rather than insertion: the forgery takes the real record's place, so the
    // positions stay contiguous and the LINK is the only thing left to catch it.
    records[1] = forged;
    let brk = verify_chain(&records).unwrap_err();
    assert_eq!(brk.at_index, 3);
    assert!(matches!(brk.kind, ChainBreakKind::LinkMismatch { .. }));
}

#[test]
fn a_foreign_scopes_record_cannot_hide_inside_this_chain() {
    let mut records = a_chain();
    records[1].tenant = "somebody-else".to_string();
    let brk = verify_chain(&records).unwrap_err();
    assert!(matches!(brk.kind, ChainBreakKind::ForeignScope { .. }));
}

#[test]
fn truncating_the_tail_verifies_and_that_limit_is_deliberate() {
    // Removing records from the END leaves a chain that is internally consistent. Nothing in the
    // records themselves can distinguish "the log stops here" from "the last two were deleted"; the
    // other half of that is held by whoever knows how far the log should reach.
    let mut records = a_chain();
    records.truncate(1);
    assert!(verify_chain(&records).is_ok());
}

#[test]
fn an_empty_chain_verifies_and_the_limit_is_deliberate() {
    assert!(verify_chain::<Nonsense>(&[]).is_ok());
}

#[test]
fn the_digest_covers_the_chained_fields_and_excludes_the_join_key() {
    let records = a_chain();
    let mut with_other_trace = records[0].clone();
    with_other_trace.trace = "something else entirely".to_string();
    assert_eq!(
        digest(&with_other_trace),
        records[0].hash,
        "a pure join key must not be able to make an intact chain unverifiable"
    );

    let mut with_other_amount = records[0].clone();
    with_other_amount.amount += 1;
    assert_ne!(digest(&with_other_amount), records[0].hash);
}

#[test]
fn a_window_verifies_from_a_pruned_head_while_a_whole_chain_does_not() {
    let records = a_chain();
    let window = &records[1..];
    assert!(
        verify_chain(window).is_err(),
        "a whole-chain check must not silently excuse a missing head"
    );
    assert!(verify_window(window).is_ok());
}

#[test]
fn a_window_still_catches_a_tamper_after_its_first_record() {
    let mut records = a_chain();
    records[2].what = "edited".to_string();
    assert!(verify_window(&records[1..]).is_err());
}

#[test]
fn the_default_chain_is_the_new_chain_because_a_derived_default_starts_at_zero() {
    // A derived default would give a next sequence of zero, and the first record of a chain is one.
    // The two constructors are pinned against each other so a tidy-up cannot substitute one.
    let made: Chain<Nonsense> = Chain::new();
    let defaulted: Chain<Nonsense> = Chain::default();
    assert_eq!(made, defaulted);
    assert_eq!(made.next_seq(), 1);
}

#[test]
fn a_chain_resumed_from_a_broken_tail_reports_the_break_rather_than_laundering_it() {
    let mut records = a_chain();
    records[1].amount += 1;
    assert!(Chain::from_persisted(&records).is_err());
    // And the caller can still choose to keep recording, which is the point of the second door.
    let mut chain = Chain::from_persisted_unverified(&records);
    let next = chain.append("acme", nonsense_input("after", 1));
    assert_eq!(next.seq, 4);
}

#[test]
fn the_admin_audit_digest_is_unchanged() {
    // THE GOLDEN VECTOR. The formula is recomputed here the old way — a single formatted string,
    // joined by vertical bars — and the mechanism has to agree byte for byte.
    let entry: AuditEntry = seal(
        "admin",
        4,
        "deadbeef".to_string(),
        AuditInput {
            ts: 1_700_000_000,
            action: "hook.register".to_string(),
            resource: "hook:compress".to_string(),
            outcome: OUTCOME_APPLIED.to_string(),
            principal: "admin".to_string(),
        },
    );
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}",
        entry.prev_hash,
        entry.seq,
        entry.ts,
        entry.action,
        entry.resource,
        entry.outcome,
        entry.principal
    );
    assert_eq!(
        entry.hash,
        sha256_hex(canonical.as_bytes()),
        "an admin audit digest that moved would report every persisted chain as tampered"
    );
    // Pinned as a literal too, so that a change to BOTH sides of the comparison above is still red.
    assert_eq!(
        entry.hash,
        "63a37a3e0ef21edc33172093d00e991459c8b509575288d9796fefffaba166c3"
    );
}

#[test]
fn the_genesis_previous_hash_is_the_empty_string() {
    let entry: AuditEntry = seal(
        "admin",
        1,
        String::new(),
        AuditInput {
            ts: 1,
            action: "hook.register".into(),
            resource: "hook:a".into(),
            outcome: OUTCOME_APPLIED.into(),
            principal: "admin".into(),
        },
    );
    assert_eq!(entry.prev_hash, "");
    // The empty leading field still flips the separator on, so the digest input starts with a bar.
    let mut d = Digest::new(Framing::PipeSeparated);
    d.text("").num(1);
    assert_eq!(d.bytes(), b"|1");
}

#[test]
fn length_prefixing_makes_the_field_split_unforgeable_where_a_separator_does_not() {
    // Two records whose fields differ only in WHERE the boundary falls collide under a separator
    // join and do not under a length prefix. That is why a new record type takes the length prefix,
    // and why the admin chain keeps its separator only because its rows are already on disk.
    let mut pipe_a = Digest::new(Framing::PipeSeparated);
    pipe_a.text("ab").text("c");
    let mut pipe_b = Digest::new(Framing::PipeSeparated);
    pipe_b.text("ab|c");
    assert_eq!(
        pipe_a.finish(),
        pipe_b.finish(),
        "a separator join cannot distinguish these two, which is the hazard"
    );

    let mut framed_a = Digest::new(Framing::LengthPrefixed);
    framed_a.text("ab").text("c");
    let mut framed_b = Digest::new(Framing::LengthPrefixed);
    framed_b.text("ab|c");
    assert_ne!(framed_a.finish(), framed_b.finish());
}
