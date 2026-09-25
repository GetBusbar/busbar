// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The two amendment classes.

use busbar_contract::{
    caps::{Audit as AuditStep, KernelSeal, Pass},
    count::Count,
};

use crate::amend::{
    content_access, correction, AmendBody, AmendChain, AmendClass, AmendJournal, ClassCounts,
    CorrectionRefused, Reader, AMENDMENTS_RETAINED,
};
use crate::record::{AuditBreakKind, OpClassId, Subject};

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

/// The two constructors are pinned against each other, as the previous release's chain already pins
/// its own: a DERIVED default gives a next position of zero, which is not a position a chain has —
/// the first entry is one — and the position is DIGESTED, so a chain that quietly started at zero
/// would seal entries a verifier walking from one rejects.
#[test]
fn the_default_amend_chain_is_the_new_one_because_a_derived_default_starts_at_zero() {
    let made = AmendChain::new();
    let defaulted = AmendChain::default();
    assert_eq!(made.next_seq(), 1);
    assert_eq!(defaulted.next_seq(), made.next_seq());
    assert_eq!(defaulted.head(), made.head());
}

/// The same pinning for the fixed record's chain, which digests its position too.
#[test]
fn the_default_audit_chain_is_the_new_one() {
    let made = crate::record::AuditChain::new();
    let defaulted = crate::record::AuditChain::default();
    assert_eq!(made.next_seq(), 1);
    assert_eq!(defaulted.next_seq(), made.next_seq());
    assert_eq!(defaulted.head(), made.head());
}

fn an_access() -> AmendBody {
    content_access(
        Reader::Hook,
        "compress",
        Subject::PrincipalId("pseudonym-1".into()),
        OpClassId::new("chat.completion"),
        vec!["messages".into(), "system".into()],
        1_700_000_000,
    )
}

/// Whole-unit counts per class.
fn counts(pairs: &[(&str, i128)]) -> ClassCounts {
    pairs
        .iter()
        .map(|(class, n)| ((*class).to_string(), Count::from_integer(*n).unwrap()))
        .collect()
}

/// A correction of one count: `was`, then `now`, of the one class `input_tokens`.
fn one_count(amends: &str, subject: Subject, was: i128, now: i128) -> AmendBody {
    correction(
        amends,
        subject,
        "gpt-4o",
        1_700_000_000_000,
        counts(&[("input_tokens", was)]),
        counts(&[("input_tokens", now)]),
        "operator",
        "why",
        1,
    )
    .unwrap()
}

fn a_correction() -> AmendBody {
    correction(
        "the-entry-being-amended",
        Subject::PrincipalId("pseudonym-1".into()),
        "gpt-4o",
        1_700_000_000_000,
        counts(&[("input_tokens", 1_000), ("output_tokens", 200)]),
        counts(&[("input_tokens", 800), ("output_tokens", 200)]),
        "operator",
        "duplicate charge on a retried request",
        1_700_000_100,
    )
    .unwrap()
}

#[test]
fn an_access_records_who_read_what_and_never_what_they_read() {
    let mut chain = AmendChain::new();
    let amendment = chain.append(an_access(), &token());
    assert_eq!(amendment.class(), AmendClass::Access);
    match &amendment.body {
        AmendBody::Access(a) => {
            assert_eq!(a.reader, Reader::Hook);
            assert_eq!(a.name, "compress");
            // FIELD NAMES, not values. An amendment that carried the content would put content on a
            // chain that cannot be erased, which is the one thing the design forbids outright.
            assert_eq!(a.fields, vec!["messages".to_string(), "system".to_string()]);
        }
        other => panic!("expected an access, got {other:?}"),
    }
}

/// AN EXPORT ACCESS IS RECORDED THE SAME WAY A HOOK ACCESS IS — same class, same fields, same
/// position — and the ONE thing that differs, who read it, is sealed into the digest.
///
/// Both are appended at the same position of fresh chains with every other field equal, so the
/// only digested difference is the reader's word. If `Reader::Export` ever sealed as `"hook"`, an
/// export plugin shipping content off the node and a hook reading it in-process would seal to one
/// digest, and a stored export access could be swapped for a hook access and still verify.
#[test]
fn an_export_access_is_recorded_the_same_way_a_hook_access_is() {
    let access_by = |reader| {
        content_access(
            reader,
            "siem",
            Subject::Arrival,
            OpClassId::new("chat.completion"),
            vec!["response".into()],
            1,
        )
    };
    let hook = AmendChain::new().append(access_by(Reader::Hook), &token());
    let export = AmendChain::new().append(access_by(Reader::Export), &token());

    // The same way: one class, one position, one link, one shape of body.
    assert_eq!(export.class(), AmendClass::Access);
    assert_eq!(export.class(), hook.class());
    assert_eq!((export.seq, &export.prev_hash), (hook.seq, &hook.prev_hash));
    match (&hook.body, &export.body) {
        (AmendBody::Access(h), AmendBody::Access(e)) => {
            assert_eq!(h.reader, Reader::Hook);
            assert_eq!(e.reader, Reader::Export);
            assert_eq!(
                (&e.name, &e.subject, &e.op_class, &e.fields, e.wall),
                (&h.name, &h.subject, &h.op_class, &h.fields, h.wall)
            );
        }
        other => panic!("expected two accesses, got {other:?}"),
    }

    // The digested words for the two readers, pinned the way the class words are.
    assert_eq!(Reader::Hook.as_str(), "hook");
    assert_eq!(Reader::Export.as_str(), "export");

    // And the reader is SEALED: the two accesses differ only in who read, and so must their digests.
    assert_eq!(AmendChain::digest_of(&export), export.hash);
    assert_ne!(
        export.hash, hook.hash,
        "an export access sealed to the same digest as a hook access -- the chain can no longer \
         say whether content left the node or was read in-process"
    );
}

#[test]
fn a_correction_names_what_it_amends_and_why() {
    let mut chain = AmendChain::new();
    let amendment = chain.append(a_correction(), &token());
    assert_eq!(amendment.class(), AmendClass::Adjust);
    match &amendment.body {
        AmendBody::Adjust(a) => {
            assert_eq!(a.amends_hash, "the-entry-being-amended");
            assert_eq!(a.delta("input_tokens"), -200_000_000);
            assert_eq!(a.delta("output_tokens"), 0);
            assert!(
                !a.reason.is_empty(),
                "a correction nobody can question is not one to trust"
            );
            assert_eq!(a.authorised_by, "operator");
        }
        other => panic!("expected a correction, got {other:?}"),
    }
}

#[test]
fn the_original_figure_survives_the_correction() {
    // The point of an amendment being a new entry: there is no state in which the original amount
    // has quietly become something else.
    let mut chain = AmendChain::new();
    let amendment = chain.append(a_correction(), &token());
    match &amendment.body {
        AmendBody::Adjust(a) => {
            assert_eq!(
                a.was,
                counts(&[("input_tokens", 1_000), ("output_tokens", 200)])
            );
            assert_eq!(
                a.now,
                counts(&[("input_tokens", 800), ("output_tokens", 200)])
            );
            // Counts and the card epoch they price at — never a money figure (owner ruling Q9).
            assert_eq!(a.lane, "gpt-4o");
            assert_eq!(a.card_epoch_ms, 1_700_000_000_000);
        }
        other => panic!("expected a correction, got {other:?}"),
    }
}

#[test]
fn accesses_and_corrections_share_one_chain_so_their_order_survives() {
    let mut chain = AmendChain::new();
    let first = chain.append(an_access(), &token());
    let second = chain.append(a_correction(), &token());
    let third = chain.append(an_access(), &token());

    assert_eq!(first.seq, 1);
    assert_eq!(second.seq, 2);
    assert_eq!(third.seq, 3);
    assert_eq!(second.prev_hash, first.hash);
    assert_eq!(third.prev_hash, second.hash);
    assert!(AmendChain::verify(&[first, second, third]).is_ok());
}

#[test]
fn editing_an_amendment_is_caught() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    assert!(AmendChain::verify(&run).is_ok());

    match &mut run[1].body {
        AmendBody::Adjust(a) => {
            a.now
                .insert("input_tokens".into(), Count::from_integer(801).unwrap());
        }
        other => panic!("expected a correction, got {other:?}"),
    }
    let brk = AmendChain::verify(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::DigestMismatch);
    assert_eq!(brk.at_index, 2);
}

#[test]
fn removing_an_amendment_from_the_middle_is_caught() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    run.remove(1);
    let brk = AmendChain::verify(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

/// A DELTA THAT WOULD OVERRUN THE SIGNED RANGE PINS AT THE EXTREME, rather than panicking in a
/// debug build or wrapping — into a correction in the opposite direction — in a release one.
///
/// The two count maps themselves are what the chain digests and what a reader answers questions
/// from; this is a convenience over them, so saturating costs nothing and wrapping would mislead.
/// `now` may not go below zero, so the overrun that remains is `was` at the negative extreme.
#[test]
fn a_delta_too_large_for_the_range_saturates_instead_of_wrapping() {
    let mut was = ClassCounts::new();
    was.insert("c".into(), Count::from_micros(i128::MIN));
    let mut now = ClassCounts::new();
    now.insert("c".into(), Count::from_micros(i128::MAX));
    let far_apart = correction(
        "e",
        Subject::Aggregate,
        "lane",
        1,
        was,
        now,
        "operator",
        "a pair no meter could report",
        1,
    )
    .unwrap();
    match &far_apart {
        AmendBody::Adjust(a) => assert_eq!(a.delta("c"), i128::MAX),
        other => panic!("expected a correction, got {other:?}"),
    }
}

/// A CORRECTION THAT WOULD TAKE A COUNT BELOW ZERO IS REFUSED, before it reaches any chain: a
/// negative measurement is not a thing a meter reports, and a negative count prices as a credit
/// nobody authorised the card to give.
#[test]
fn a_correction_below_zero_is_refused() {
    let refused = correction(
        "e",
        Subject::Aggregate,
        "lane",
        1,
        counts(&[("input_tokens", 10)]),
        counts(&[("input_tokens", -1)]),
        "operator",
        "over-corrected",
        1,
    );
    assert_eq!(
        refused,
        Err(CorrectionRefused::NegativeCount {
            class: "input_tokens".into()
        })
    );
}

/// The reason is not optional, and a blank one is no reason.
#[test]
fn a_correction_with_no_reason_is_refused() {
    let refused = correction(
        "e",
        Subject::Aggregate,
        "lane",
        1,
        counts(&[("input_tokens", 10)]),
        counts(&[("input_tokens", 9)]),
        "operator",
        "  ",
        1,
    );
    assert_eq!(refused, Err(CorrectionRefused::NoReason));
}

/// THE JOURNAL READS AN ENTRY'S COUNTS THROUGH ITS LATEST CORRECTION, and leaves an uncorrected
/// entry at what was recorded.
#[test]
fn a_journal_answers_the_counts_an_entry_stands_at_now() {
    let mut journal = AmendJournal::new();
    let recorded = counts(&[("input_tokens", 1_000)]);
    assert_eq!(journal.counts_now("x", &recorded), recorded);
    journal.append(one_count("x", Subject::Aggregate, 1_000, 800), &token());
    journal.append(one_count("x", Subject::Aggregate, 800, 700), &token());
    journal.append(one_count("y", Subject::Aggregate, 5, 1), &token());
    assert_eq!(
        journal.counts_now("x", &recorded),
        counts(&[("input_tokens", 700)])
    );
    assert_eq!(journal.corrections().len(), 3);
    assert!(journal.verify().is_ok());
}

/// THE IN-MEMORY WINDOW IS BOUNDED; CORRECTIONS ARE NOT. Accesses arrive at request rate, so the
/// journal releases the oldest held amendment past [`AMENDMENTS_RETAINED`] — and still verifies the
/// window it holds to the chain's head — while every correction stays readable.
#[test]
fn a_journal_bounds_what_it_holds_but_never_drops_a_correction() {
    let mut journal = AmendJournal::new();
    journal.append(one_count("x", Subject::Aggregate, 10, 9), &token());
    for _ in 0..AMENDMENTS_RETAINED {
        journal.append(an_access(), &token());
    }
    assert_eq!(journal.recent().count(), AMENDMENTS_RETAINED);
    assert_eq!(journal.released(), 1);
    assert_eq!(journal.corrections().len(), 1);
    assert_eq!(
        journal.counts_now("x", &counts(&[("input_tokens", 10)])),
        counts(&[("input_tokens", 9)])
    );
    assert!(journal.verify().is_ok());
}

/// A correction DOWNWARD is the commonest one there is, so `was` exceeding `now` is an ordinary
/// amendment and not something to refuse.
#[test]
fn a_correction_downward_is_an_ordinary_amendment() {
    match &a_correction() {
        AmendBody::Adjust(a) => {
            assert!(a.was["input_tokens"] > a.now["input_tokens"]);
            assert_eq!(a.delta("input_tokens"), -200_000_000);
        }
        other => panic!("expected a correction, got {other:?}"),
    }
}

/// CUTTING THE HEAD OFF A CORRECTION HISTORY IS CAUGHT.
///
/// The survivors link perfectly to each other — every one still names the amendment before it — so
/// the only thing that says entries are missing is that the run does not begin where the chain
/// does. The earliest amendments are the ones somebody covering a correction would drop first.
#[test]
fn truncating_the_head_of_an_amendment_run_is_caught() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    assert!(AmendChain::verify(&run).is_ok());

    run.remove(0);
    let brk = AmendChain::verify(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(brk.at_index, 1, "the cut is reported at the run's start");
}

/// CUTTING THE TAIL OFF takes the chain's own head to notice, exactly as it does for records.
#[test]
fn truncating_the_tail_of_an_amendment_run_is_caught_against_the_chain_head() {
    let mut chain = AmendChain::new();
    let mut run = vec![
        chain.append(an_access(), &token()),
        chain.append(a_correction(), &token()),
        chain.append(an_access(), &token()),
    ];
    assert!(chain.verify_to_head(&run).is_ok());

    run.pop();
    // The survivors still walk from the genesis, which is precisely why the walk alone cannot see
    // this and the head check must.
    assert!(AmendChain::verify(&run).is_ok());
    let brk = chain.verify_to_head(&run).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

/// An EMPTY run verifies against itself and fails against a chain that sealed something: the two
/// readings of "no amendments" are only distinguishable with the chain on hand.
#[test]
fn an_empty_run_verifies_alone_and_fails_against_a_chain_that_sealed_one() {
    assert!(AmendChain::verify(&[]).is_ok());
    let mut chain = AmendChain::new();
    let _ = chain.append(a_correction(), &token());
    assert!(chain.verify_to_head(&[]).is_err());
}

#[test]
fn a_chain_resumed_from_a_persisted_tail_continues_it() {
    let mut chain = AmendChain::new();
    let first = chain.append(an_access(), &token());
    let mut resumed = AmendChain::resume(chain.head().to_string(), chain.next_seq());
    let second = resumed.append(a_correction(), &token());
    assert_eq!(second.seq, 2);
    assert_eq!(second.prev_hash, first.hash);
    assert!(AmendChain::verify(&[first, second]).is_ok());
}

/// EVERY SUBJECT TAG THE AMENDMENT DIGEST SEALS IS SPELLED OUT, not derived.
///
/// The digested text for the subject used to be whatever the derived `Debug` printed, which made
/// every sealed amendment hostage to a rename: an amendment is a correction to money, and a
/// correction that reports itself tampered because somebody renamed a variant is worse than no
/// correction at all. The spellings live in the production file now; this pins each one, so a
/// rename shows up here — as a difference somebody has to look at — instead of in the hash.
#[test]
fn the_frozen_subject_tags_are_the_ones_the_amendment_digest_seals() {
    use crate::record::{subject_tag, subject_value};

    assert_eq!(
        subject_tag(&Subject::PrincipalId("pseudonym-1".into())),
        "principal"
    );
    assert_eq!(subject_tag(&Subject::Arrival), "arrival");
    assert_eq!(subject_tag(&Subject::Node(7)), "node");
    assert_eq!(subject_tag(&Subject::Aggregate), "aggregate");

    // The value is the second half of the pair, and it is what stops a principal whose pseudonym
    // reads as another subject's tag from digesting as that subject.
    assert_eq!(
        subject_value(&Subject::PrincipalId("pseudonym-1".into())),
        "pseudonym-1"
    );
    assert_eq!(subject_value(&Subject::Arrival), "");
    assert_eq!(subject_value(&Subject::Node(7)), "7");
    assert_eq!(subject_value(&Subject::Aggregate), "");
}

/// A PRINCIPAL NAMED AFTER ANOTHER SUBJECT'S TAG STILL DIGESTS AS A PRINCIPAL.
///
/// The tag and the value are two digested fields rather than one joined string, which is the whole
/// reason this cannot collide.
#[test]
fn a_principal_pseudonym_that_reads_as_a_node_does_not_digest_as_one() {
    let mut one = AmendChain::new();
    let mut other = AmendChain::new();
    let as_principal = one.append(
        one_count("e", Subject::PrincipalId("7".into()), 10, 5),
        &token(),
    );
    let as_node = other.append(one_count("e", Subject::Node(7), 10, 5), &token());
    assert_ne!(as_principal.hash, as_node.hash);
}

/// THE SEALED AMENDMENT DIGEST IS A FROZEN VALUE, not whatever today's encoder happens to produce.
///
/// Every amendment a deployment has written is verified by recomputing this digest, so a change
/// that moves it makes a stored correction report itself TAMPERED. The hex below was produced by an
/// earlier build over the fixture in this test; it is a value to preserve, never one to re-capture
/// from a failing run. Moving it needs a migration for anything already on disk, not an edit here.
#[test]
fn the_sealed_digest_of_an_amendment_is_the_frozen_hex() {
    let mut chain = AmendChain::new();
    let access = chain.append(an_access(), &token());
    let adjust = chain.append(a_correction(), &token());
    assert_eq!(
        access.hash, "2a9ac567b083d3fc25768d98445737fb2aee7a20db291930467a7abbfa83944b",
        "the amendment digest MOVED. Every stored correction now reports itself tampered. Restore \
         the encoding; do not re-capture this constant."
    );
    assert_eq!(
        // RE-DERIVED, NOT RE-CAPTURED (item 404, owner ruling Q9): the adjustment's shape changed from
        // one money figure to counts per class plus the card epoch, and at that change NO adjustment
        // had ever been sealed in production (the item's own measurement: zero construction sites),
        // so no stored correction carries the previous encoding. The value is computed independently
        // of this crate, by hashing the length-prefixed framing of the fixture by hand
        // (`amend_digest.py` beside this file, which also reproduces the
        // access constant above and the retired adjustment constant 56addfe3…0a2bc byte for byte).
        adjust.hash,
        "2efa76937dfebe0452c23ac8dee4a1293c9fcb2b6488dfd9ed9ae183cb9ea940",
        "the amendment digest MOVED. Every stored correction now reports itself tampered. Restore \
         the encoding; do not re-capture this constant."
    );
}

/// Q64/Q67: AN ADJUSTMENT NAMES ITS POOL, and one sealed before the field existed keeps its hash.
/// The unscoped fixture still digests to the frozen `2efa7693…a940` above (so a stored adjustment
/// still verifies, and still reads unscoped); the same correction naming `pool-a` digests to its
/// own value, derived independently by `amend_digest.py` ("pooled adjust"), never captured from a
/// run. The pool is on the record the chain seals.
#[test]
fn a_pooled_adjustment_digests_its_pool_and_an_unscoped_one_digests_as_sealed() {
    let pooled = |pool: Option<&str>| {
        let mut body = a_correction();
        if let AmendBody::Adjust(a) = &mut body {
            a.pool = pool.map(str::to_string);
        }
        let mut chain = AmendChain::new();
        chain.append(an_access(), &token());
        chain.append(body, &token())
    };
    assert_eq!(
        pooled(None).hash,
        "2efa76937dfebe0452c23ac8dee4a1293c9fcb2b6488dfd9ed9ae183cb9ea940",
        "an unscoped adjustment digests exactly as it was sealed"
    );
    let sealed = pooled(Some("pool-a"));
    assert_eq!(
        sealed.hash, "3117c9fe26e2626ae153742164bb1b7874466e6c0f652b52ea4a35bd3bab64e7",
        "the pooled digest is the independently derived one"
    );
    assert!(matches!(&sealed.body, AmendBody::Adjust(a) if a.pool.as_deref() == Some("pool-a")));
}

#[test]
fn the_two_class_names_are_the_two_the_journal_knows() {
    assert_eq!(AmendClass::Access.as_str(), "access");
    assert_eq!(AmendClass::Adjust.as_str(), "adjust");
    assert_eq!(AmendClass::Access.to_string(), "access");
}

#[test]
fn an_amendment_names_the_audit_record_it_amends() {
    // The one place the two chains touch: an amendment carries the digest of the entry it concerns,
    // so a reader can go from one to the other without the two chains sharing a buffer.
    use crate::amend::amends;
    use crate::record::{
        Audit, AuditChain, AuditInputs, Controls, FinishClass, OutcomeFacts, Usage, What,
    };
    use busbar_contract::caps::{Origin, OriginKind, Outcome, UnitKey};

    let mut audit = AuditChain::new();
    let record = audit.seal(
        AuditInputs {
            subject: Subject::PrincipalId("p".into()),
            what: What {
                unit_key: UnitKey::new(1),
                op_class: OpClassId::new("chat.completion"),
                destination: None,
                parent: None,
                pre_hook_head: None,
                post_hook_head: None,
            },
            wall: 1,
            mono: 1,
            origin: Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client),
            outcome: OutcomeFacts {
                unit_end: Outcome::Completed,
                step: None,
                finish: FinishClass::Complete,
                hook_failed: false,
                emission_delta: 0,
                stale_policy: false,
            },
            usage: Usage {
                lines: Vec::new(),
                tier_bp: 10_000,
                fee_count: 0,
                currency: "USD".into(),
                rate_card_version: 1,
                bucket_chain_ref: String::new(),
            },
            controls: Controls::default(),
            correlation_label: None,
        },
        &token(),
    );

    let mut chain = AmendChain::new();
    let amendment = chain.append(
        correction(
            &amends(&record),
            Subject::PrincipalId("p".into()),
            "lane",
            1,
            counts(&[("input_tokens", 100)]),
            counts(&[("input_tokens", 0)]),
            "operator",
            "refunded in full",
            2,
        )
        .unwrap(),
        &token(),
    );
    match &amendment.body {
        AmendBody::Adjust(a) => assert_eq!(a.amends_hash, record.hash),
        other => panic!("expected a correction, got {other:?}"),
    }
}

/// A JOURNAL REBUILT FROM ITS WHOLE RUN is the journal that sealed it: the same head, the same
/// corrected counts, and the next amendment links on where the run ended. A run with its head cut
/// off is refused rather than rebuilt.
#[test]
fn a_journal_rebuilt_from_its_run_reads_and_continues_as_the_one_that_sealed_it() {
    let mut sealed = AmendJournal::new();
    sealed.append(an_access(), &token());
    sealed.append(a_correction(), &token());
    let run: Vec<_> = sealed.recent().cloned().collect();

    let mut rebuilt = AmendJournal::restore(run.clone()).expect("a whole run rebuilds");
    assert_eq!(rebuilt.head(), sealed.head());
    assert_eq!(rebuilt.corrections(), sealed.corrections());
    let recorded = counts(&[("input_tokens", 1_000), ("output_tokens", 200)]);
    assert_eq!(
        rebuilt.counts_now("the-entry-being-amended", &recorded),
        counts(&[("input_tokens", 800), ("output_tokens", 200)])
    );
    let next = rebuilt.append(an_access(), &token());
    assert_eq!((next.seq, next.prev_hash.as_str()), (3, sealed.head()));
    assert_eq!(rebuilt.verify(), Ok(()));

    assert!(
        AmendJournal::restore(run[1..].to_vec()).is_err(),
        "a run that does not start at the genesis is missing amendments"
    );
}

/// The two frozen subject fields read back as the subject they were written from, for every kind.
#[test]
fn a_subject_reads_back_from_the_fields_it_is_digested_by() {
    use crate::amend::{subject_fields, subject_from_fields};
    for subject in [
        Subject::PrincipalId("pseudonym-1".into()),
        Subject::Arrival,
        Subject::Node(7),
        Subject::Aggregate,
    ] {
        let (tag, value) = subject_fields(&subject);
        assert_eq!(subject_from_fields(tag, &value), Some(subject));
    }
    assert_eq!(subject_from_fields("arrival", "x"), None);
    assert_eq!(subject_from_fields("someone", ""), None);
    assert_eq!(AmendClass::parse("adjust"), Some(AmendClass::Adjust));
    assert_eq!(Reader::parse("export"), Some(Reader::Export));
    assert_eq!(Reader::parse("nobody"), None);
}
