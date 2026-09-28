// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: one shape, no content, and a chain that catches an edit.

use busbar_contract::caps::{
    Audit as AuditStep, KernelSeal, Origin, OriginKind, Outcome, Pass, ReasonCode, StepName,
    UnitKey,
};

use crate::record::{
    Audit, AuditBreakKind, AuditChain, AuditInputs, Controls, FinishClass, HookApplied, OpClassId,
    OutcomeFacts, QuantitySource, Subject, Usage, UsageLine, What,
};

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

fn origin() -> Origin {
    Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client)
}

fn inputs(unit: u64) -> AuditInputs {
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: None,
            pre_hook_head: Some("hook-head-before".into()),
            post_hook_head: Some("hook-head-after".into()),
        },
        wall: 1_700_000_000 + unit,
        mono: unit * 1_000,
        origin: origin(),
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: vec![UsageLine {
                class: busbar_contract::caps::MeterClassId::new("tokens_out"),
                quantity: 120,
                source: QuantitySource::Locator {
                    direction: busbar_contract::ClassDirection::Response,
                    ptr: busbar_contract::caps::LocatorPtr::new("/usage/output_tokens"),
                },
                estimated: false,
            }],
            tier_bp: 9_000,
            fee_count: 1,
            rate_card_version: 3,
            bucket_chain_ref: "chain:free>paid".into(),
        },
        controls: Controls {
            hold_ref: Some("hold-1".into()),
            settle_ref: Some("settle-1".into()),
            slice_ref: Some("slice-1".into()),
            lease_ref: Some("lease-1".into()),
            lease_epoch: 4,
            policy_epoch: 7,
            hooks_applied: vec![HookApplied {
                hook: "compress".into(),
            }],
            replayed: false,
            children: vec![UnitKey::new(unit + 1000)],
        },
        correlation_label: Some("customer-order-99".into()),
    }
}

/// The fully-populated record both frozen digests below are taken over: the enum arms that carry
/// payloads, because those are the ones whose encoding is easiest to move by accident.
fn frozen_record() -> crate::record::AuditRecord {
    let mut chain = AuditChain::new();
    let mut with_payloads = inputs(1);
    with_payloads.outcome.unit_end = Outcome::Refused(StepName::Admit, ReasonCode::OverBudget);
    with_payloads.outcome.step = Some(StepName::Admit);
    with_payloads.outcome.finish = FinishClass::Error;
    with_payloads.what.incarnation = 3;
    chain.seal(with_payloads, &token())
}

/// The `v3` digest [`frozen_record`]'s fields froze when `busbar.audit.digest.v3` was published: no
/// `currency`, and no `incarnation` either. Pinned, never re-captured: a record sealed under `v3`
/// carries exactly this and must keep verifying by it.
const FROZEN_V3: &str = "d181a17502af4f637b8e3cd8ec7a107f07d4dc9fafe95375626e4709e2e7e26c";

/// [`frozen_record`] AS A `v3` NODE SEALED AND STORED IT: the same fields and the `v3` digest. The
/// incarnation the record carries is not in a `v3` preimage, so it cannot move this value.
fn frozen_v3_record() -> crate::record::AuditRecord {
    let mut record = frozen_record();
    record.recipe = crate::recipe::Recipe::V3;
    record.hash = FROZEN_V3.to_string();
    record
}

/// The `v2` digest [`frozen_record`]'s fields froze when `busbar.audit.digest.v2` was published,
/// with `currency` `"USD"` in the preimage. Pinned, never re-captured: a record sealed under `v2`
/// carries exactly this and must keep verifying by it.
const FROZEN_V2: &str = "ea279d25a42d6345875b06b44fa7bb558f0d05655f985d376cd37fe2e0422293";

/// [`frozen_record`] AS A `v2` NODE SEALED AND STORED IT: the same fields, the `currency` text the
/// `v2` preimage framed, and the `v2` digest. This is what "an existing record" is on a node that
/// sealed before `v3` (#34): nothing is rewritten, it is read back and verified by its own recipe.
fn frozen_v2_record() -> crate::record::AuditRecord {
    let mut record = frozen_record();
    record.recipe = crate::recipe::Recipe::V2 {
        currency: "USD".into(),
    };
    record.hash = FROZEN_V2.to_string();
    record
}

/// THE SEALED DIGEST IS A FROZEN VALUE, not whatever today's encoder happens to produce.
///
/// Every record a deployment has already written is verified by recomputing this digest, so a
/// change that moves it makes every persisted chain report itself TAMPERED at the next boot. The
/// hex below is a value to preserve, never one to re-capture from a failing run.
///
/// History, and the rule it set. Moved once, before any release wrote a chain, when the record's
/// position entered the digest. Moved a second time — and NOT re-captured — when the recipe became
/// `busbar.audit.digest.v2` (#43, #71, #77(3): the record stores counts, never a price). Moved a
/// third time, the same way, when the recipe became `busbar.audit.digest.v3` (#34, OWNER
/// 2026-09-29: `currency` leaves the signed digest), and a fourth when it became
/// `busbar.audit.digest.v4` (the boot's `incarnation` enters the digest after `unit_key`, so two
/// boots that mint the same unit key seal two different records). Each move is a NEW RECIPE beside
/// the old one: the v3 value is still pinned by
/// [`a_record_sealed_under_v3_still_verifies_by_the_v3_rules`], the v2 value by
/// [`a_record_sealed_under_v2_still_verifies_by_the_v2_rules`], the v1 value by
/// [`the_v1_frozen_digest_is_reproduced_by_v1_rules_from_a_v2_record`], and this value is the v4
/// recipe's own, armed the day it was published. The next move needs a v5 beside these four.
#[test]
fn the_sealed_digest_of_a_fully_populated_record_is_the_frozen_hex() {
    let record = frozen_record();
    assert_eq!(record.recipe, crate::recipe::Recipe::V4);
    assert_eq!(
        record.hash, "1fa69b20a864d61bb6eacf4cad6bb719d43953db27cd941d410e39ff01be2004",
        "the sealed digest moved: every persisted chain would now report itself tampered"
    );
}

/// A `v3` PREIMAGE NAMES NO CURRENCY (#34). `v3` is `v2` less exactly `currency`: the same
/// fields, in the same order, with that one taken out.
#[test]
fn a_v3_preimage_names_no_currency() {
    use crate::recipe::digest_fields;
    let v3: Vec<_> = digest_fields(&frozen_v3_record())
        .into_iter()
        .map(|f| f.name)
        .collect();
    let v2: Vec<_> = digest_fields(&frozen_v2_record())
        .into_iter()
        .map(|f| f.name)
        .collect();
    assert!(
        !v3.contains(&"currency"),
        "a v3 preimage still frames a currency: {v3:?}"
    );
    let v2_less_currency: Vec<_> = v2.iter().copied().filter(|n| *n != "currency").collect();
    assert_eq!(v2.len(), v3.len() + 1);
    assert_eq!(v3, v2_less_currency, "v3 is not v2 less exactly `currency`");
    assert!(AuditChain::verify_chain(std::slice::from_ref(&frozen_v3_record())).is_ok());
}

/// A NEW RECORD IS SEALED UNDER `v4`, AND `v4` IS `v3` PLUS EXACTLY `incarnation`, framed as a
/// number straight after `unit_key`. Nothing else moves.
#[test]
fn a_new_record_is_sealed_under_v4_and_its_preimage_adds_only_the_incarnation() {
    use crate::recipe::digest_fields;
    let v4: Vec<_> = digest_fields(&frozen_record())
        .into_iter()
        .map(|f| f.name)
        .collect();
    let v3: Vec<_> = digest_fields(&frozen_v3_record())
        .into_iter()
        .map(|f| f.name)
        .collect();
    let at = v3
        .iter()
        .position(|n| *n == "unit_key")
        .expect("v3 frames unit_key")
        + 1;
    let mut v3_plus_incarnation = v3.clone();
    v3_plus_incarnation.insert(at, "incarnation");
    assert_eq!(
        v4, v3_plus_incarnation,
        "v4 is not v3 plus exactly `incarnation`"
    );
    assert_eq!(frozen_record().recipe, crate::recipe::Recipe::V4);
    assert!(AuditChain::verify_chain(std::slice::from_ref(&frozen_record())).is_ok());
}

/// A `v3` RECORD READ BACK AFTER THE UPGRADE STILL VERIFIES by the `v3` rules it was sealed under.
#[test]
fn a_record_sealed_under_v3_still_verifies_by_the_v3_rules() {
    let record = frozen_v3_record();
    assert_eq!(AuditChain::digest_of(&record), FROZEN_V3);
    assert!(AuditChain::verify_chain(std::slice::from_ref(&record)).is_ok());
}

/// TWO BOOTS THAT MINT THE SAME UNIT KEY SEAL TWO DIFFERENT RECORDS. A unit key restarts with the
/// process; the incarnation does not. Everything else equal, the digests differ and each record
/// verifies on its own, so a record from one boot can never stand in for the other's.
#[test]
fn two_boots_minting_the_same_unit_key_seal_distinct_verified_records() {
    let seal = |incarnation: u64| {
        let mut chain = AuditChain::new();
        let mut i = inputs(1);
        i.what.incarnation = incarnation;
        chain.seal(i, &token())
    };
    let (first, second) = (seal(1), seal(2));
    assert_eq!(first.what.unit_key, second.what.unit_key);
    assert_ne!(first.hash, second.hash, "the boot is not in the digest");
    assert!(AuditChain::verify_chain(std::slice::from_ref(&first)).is_ok());
    assert!(AuditChain::verify_chain(std::slice::from_ref(&second)).is_ok());
    let mut swapped = first.clone();
    swapped.what.incarnation = 2;
    assert_eq!(
        AuditChain::verify_chain(std::slice::from_ref(&swapped)).map_err(|b| b.kind),
        Err(AuditBreakKind::DigestMismatch),
        "a record relabelled to another boot still verifies"
    );
}

/// AN EXISTING RECORD STILL VERIFIES, BY THE RECIPE IT WAS SEALED UNDER (#34).
///
/// A `v2` record read back after the upgrade recomputes to the `v2` digest it froze, and walks as a
/// chain — the recipe change did not make a single stored record report itself tampered.
#[test]
fn a_record_sealed_under_v2_still_verifies_by_the_v2_rules() {
    let record = frozen_v2_record();
    assert_eq!(AuditChain::digest_of(&record), FROZEN_V2);
    assert!(AuditChain::verify_chain(std::slice::from_ref(&record)).is_ok());
}

/// TAMPERING FAILS UNDER EITHER RECIPE — and so does moving a record between them.
///
/// The RED arms. A `v2` record whose frozen `currency` text is edited, a `v2` record relabelled as
/// `v3` (dropping the field from its preimage), a `v3` record relabelled as `v2` (adding one), and
/// a `v3` record with a count edited: each must stop hashing to its sealed digest. The relabelling
/// arms are why the recipe does not itself need to be digested.
#[test]
fn tampering_fails_under_either_recipe_and_so_does_relabelling_one() {
    use crate::recipe::Recipe;
    type Edit = fn(&mut crate::record::AuditRecord);
    let arms: Vec<(&str, crate::record::AuditRecord, Edit)> = vec![
        ("a v2 record's currency text", frozen_v2_record(), |r| {
            r.recipe = Recipe::V2 {
                currency: "EUR".into(),
            }
        }),
        ("a v2 record relabelled v3", frozen_v2_record(), |r| {
            r.recipe = Recipe::V3
        }),
        ("a v3 record relabelled v2", frozen_v3_record(), |r| {
            r.recipe = Recipe::V2 {
                currency: "USD".into(),
            }
        }),
        ("a v3 record relabelled v4", frozen_v3_record(), |r| {
            r.recipe = Recipe::V4
        }),
        ("a v4 record relabelled v3", frozen_record(), |r| {
            r.recipe = Recipe::V3
        }),
        ("a v4 record's incarnation", frozen_record(), |r| {
            r.what.incarnation += 1
        }),
        ("a v2 record's count", frozen_v2_record(), |r| {
            r.usage.lines[0].quantity += 1
        }),
        ("a v3 record's count", frozen_v3_record(), |r| {
            r.usage.lines[0].quantity += 1
        }),
        ("a v4 record's count", frozen_record(), |r| {
            r.usage.lines[0].quantity += 1
        }),
    ];
    for (what, mut record, edit) in arms {
        assert!(AuditChain::verify_chain(std::slice::from_ref(&record)).is_ok());
        edit(&mut record);
        assert_eq!(
            AuditChain::verify_chain(std::slice::from_ref(&record)).map_err(|b| b.kind),
            Err(AuditBreakKind::DigestMismatch),
            "{what}: the edited record still verifies"
        );
    }
}

/// THE V1 FROZEN DIGEST SURVIVES THE V2 RECIPE, and it is reproduced here from a v2 record.
///
/// `busbar.audit.digest.v1` is `v2` plus three priced fields at three fixed places: `pre_tier` and
/// `priced` (text) after the usage lines and before `tier_bp`, and `hooks[].priced_delta` (text)
/// after each `hooks[].hook`. Putting the figures the v1 record carried (600, 540, -10) back at
/// those places and framing the list must give the v1 value this crate froze before v2 existed.
/// That says two things at once: a v1 record is still verifiable by the v1 rules its page
/// publishes, and v2 differs from v1 by exactly those three fields and nothing else — a v2 that
/// had also reordered, renamed or dropped a field would not reproduce the v1 bytes.
#[test]
fn the_v1_frozen_digest_is_reproduced_by_v1_rules_from_a_v2_record() {
    use crate::recipe::{digest_fields, digest_over, DigestField, DigestValue};
    let text = |name: &'static str, v: &str| DigestField {
        name,
        value: DigestValue::Text(v.to_string()),
    };
    let record = frozen_v2_record();
    let mut v1 = Vec::new();
    for field in digest_fields(&record) {
        match field.name {
            "tier_bp" => {
                v1.push(text("pre_tier", "600"));
                v1.push(text("priced", "540"));
                v1.push(field);
            }
            "hooks[].hook" => {
                v1.push(field);
                v1.push(text("hooks[].priced_delta", "-10"));
            }
            _ => v1.push(field),
        }
    }
    assert_eq!(
        digest_over(&v1),
        "0161f86736b3ed067dcdbaa80259c52ceb25946076879a8968e3f84570626358",
        "the v1 digest is no longer reproducible: a v1 record would stop verifying"
    );
    assert_ne!(digest_over(&v1), record.hash, "v2 is its own recipe");
}

#[test]
fn a_record_links_to_the_one_before_it_and_the_run_verifies() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4).map(|i| chain.seal(inputs(i), &token())).collect();
    assert_eq!(records[0].prev_hash, "");
    for pair in records.windows(2) {
        assert_eq!(pair[1].prev_hash, pair[0].hash);
    }
    assert!(AuditChain::verify_chain(&records).is_ok());
    assert_eq!(chain.head(), records[3].hash);
    assert_eq!(chain.sealed(), 4);
}

#[test]
fn the_correlation_label_is_hashed_and_the_label_itself_is_gone() {
    let mut chain = AuditChain::new();
    let record = chain.seal(inputs(1), &token());
    let hash = record.correlation_hash.clone().unwrap();
    assert_eq!(
        hash,
        crate::legacy::sha256_hex(b"customer-order-99"),
        "the record carries the digest of the label"
    );
    // And the label is nowhere in the record. Checked over the whole rendered record rather than
    // field by field, because the point is that there is NO path that keeps it.
    let rendered = format!("{record:?}");
    assert!(
        !rendered.contains("customer-order-99"),
        "the correlation label reached the record: {rendered}"
    );
}

#[test]
fn a_record_with_no_correlation_label_carries_no_hash() {
    let mut chain = AuditChain::new();
    let mut without = inputs(1);
    without.correlation_label = None;
    let record = chain.seal(without, &token());
    assert!(record.correlation_hash.is_none());
}

#[test]
fn editing_any_recorded_fact_is_caught() {
    let mut chain = AuditChain::new();
    let mut records: Vec<_> = (1..=3).map(|i| chain.seal(inputs(i), &token())).collect();

    // Every one of these is a fact somebody would have a reason to change.
    let edits: Vec<(&str, Edit)> = vec![
        ("the tier", |r| r.usage.tier_bp += 1),
        ("the fee count", |r| r.usage.fee_count += 1),
        ("a quantity", |r| r.usage.lines[0].quantity += 1),
        ("a quantity's source", |r| {
            r.usage.lines[0].source = QuantitySource::KernelBytes { divisor: 4 }
        }),
        ("the estimated mark", |r| r.usage.lines[0].estimated = true),
        ("the card version", |r| r.usage.rate_card_version += 1),
        ("the bucket chain", |r| {
            r.usage.bucket_chain_ref = "chain:other".into()
        }),
        ("the subject", |r| {
            r.subject = Subject::PrincipalId("somebody-else".into())
        }),
        ("the destination", |r| {
            r.what.destination = Some("upstream-b".into())
        }),
        ("the operation class", |r| {
            r.what.op_class = OpClassId::new("something.else")
        }),
        ("the finish class", |r| {
            r.outcome.finish = FinishClass::Error
        }),
        ("the outcome", |r| {
            r.outcome.unit_end = Outcome::Failed(StepName::Route, ReasonCode::OverBudget)
        }),
        ("the hook-failed mark", |r| r.outcome.hook_failed = true),
        ("the emission delta", |r| r.outcome.emission_delta -= 5),
        ("the stale-policy mark", |r| r.outcome.stale_policy = true),
        ("the hold reference", |r| {
            r.controls.hold_ref = Some("hold-2".into())
        }),
        ("the lease epoch", |r| r.controls.lease_epoch += 1),
        ("the policy epoch", |r| r.controls.policy_epoch += 1),
        ("a hook's name", |r| {
            r.controls.hooks_applied[0].hook = "decompress".into()
        }),
        ("the replay mark", |r| r.controls.replayed = true),
        ("the wall clock", |r| r.wall += 1),
        ("the correlation hash", |r| {
            r.correlation_hash = Some("something".into())
        }),
    ];

    for (what, edit) in edits {
        let mut edited = records.clone();
        edit(&mut edited[1]);
        let brk = AuditChain::verify_chain(&edited)
            .unwrap_err_or_else(|| panic!("editing {what} went undetected"));
        assert_eq!(brk.kind, AuditBreakKind::DigestMismatch, "editing {what}");
        assert_eq!(brk.at_index, 2);
    }

    // And a record removed from the middle breaks the link rather than the digest.
    records.remove(1);
    let brk = AuditChain::verify_chain(&records).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

#[test]
fn two_nodes_do_not_digest_the_same() {
    // A subject whose identity was left out of the digest would let one node's record stand in for
    // another's.
    let mut chain = AuditChain::new();
    let mut a = inputs(1);
    a.subject = Subject::Node(1);
    let first = chain.seal(a, &token());
    let mut chain = AuditChain::new();
    let mut b = inputs(1);
    b.subject = Subject::Node(2);
    let second = chain.seal(b, &token());
    assert_ne!(first.hash, second.hash);
}

#[test]
fn a_plane_contributes_exactly_two_identifiers() {
    // The claim the fixed record is FOR. A caller says what kind of operation this was and how it
    // finished; every other field is the same shape whichever door the request came in through.
    let mut chain = AuditChain::new();
    let mut other_plane = inputs(1);
    other_plane.what.op_class = OpClassId::new("tool.call");
    other_plane.outcome.finish = FinishClass::TurnComplete;
    let record = chain.seal(other_plane, &token());

    // Same shape, different two ids.
    assert_eq!(record.what.op_class.as_str(), "tool.call");
    assert_eq!(record.outcome.finish, FinishClass::TurnComplete);
    assert_eq!(record.recipe, crate::recipe::Recipe::V4);
    assert!(record.controls.hold_ref.is_some());
}

#[test]
fn a_chain_resumed_from_a_persisted_tail_continues_it() {
    let mut chain = AuditChain::new();
    let first: Vec<_> = (1..=2).map(|i| chain.seal(inputs(i), &token())).collect();

    let mut resumed = AuditChain::resume(chain.head().to_string(), chain.next_seq());
    let third = resumed.seal(inputs(3), &token());
    assert_eq!(third.prev_hash, first[1].hash);

    let mut all = first;
    all.push(third);
    assert!(AuditChain::verify_chain(&all).is_ok());
}

/// A record carries WHERE it sits, and the position is digested — so a run cannot be renumbered to
/// hide a hole, and a walk can tell a contiguous run from one with records taken out of it.
#[test]
fn a_record_carries_its_position_and_the_position_is_digested() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=3).map(|i| chain.seal(inputs(i), &token())).collect();
    assert_eq!(
        records.iter().map(|r| r.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    // Renumbering is caught twice over: the walk sees a position that is not the next one, and the
    // record no longer hashes to its own fields — so nobody can close a hole by renumbering what is
    // left of a run.
    let mut renumbered = records.clone();
    renumbered[1].seq = 7;
    assert_eq!(
        AuditChain::verify_chain(&renumbered).unwrap_err().kind,
        AuditBreakKind::SequenceMismatch {
            expected: 2,
            found: 7
        }
    );
    assert_ne!(
        AuditChain::digest_of(&renumbered[1]),
        renumbered[1].hash,
        "the position is inside the digest"
    );
}

/// HEAD truncation: the oldest records dropped. What is left links and numbers perfectly among
/// itself, and the only thing that says anything is missing is that the run does not begin where
/// the chain does — which is exactly what the genesis-anchored entry point requires.
#[test]
fn a_run_missing_its_oldest_records_does_not_verify_against_the_genesis() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4).map(|i| chain.seal(inputs(i), &token())).collect();

    let brk = AuditChain::verify_chain(&records[1..]).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(
        brk.at_index, 1,
        "the break is at the record that should be the genesis"
    );

    // The same run read as a WINDOW of a longer chain is fine: a bounded store's oldest retained
    // record has legitimately lost its predecessor.
    assert!(AuditChain::verify_window(&records[1..]).is_ok());
}

/// A cut INSIDE a window is still caught, so the window anchor excuses the missing head and
/// nothing else.
#[test]
fn a_window_verifies_a_contiguous_middle_run_and_not_a_gapped_one() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=6).map(|i| chain.seal(inputs(i), &token())).collect();

    assert!(AuditChain::verify_window(&records[2..5]).is_ok());

    let mut gapped = records[2..5].to_vec();
    gapped.remove(1);
    let brk = AuditChain::verify_window(&gapped).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
}

/// TAIL truncation: the newest records dropped. Nothing in the surviving records can say so — they
/// link, they number from one, they hash — so it takes the chain's own head to notice, which is
/// what verifying AGAINST THE HEAD is for.
#[test]
fn a_run_missing_its_newest_records_does_not_verify_against_the_head() {
    let mut chain = AuditChain::new();
    let records: Vec<_> = (1..=4).map(|i| chain.seal(inputs(i), &token())).collect();

    assert!(chain.verify_to_head(&records).is_ok());

    let cut = &records[..3];
    let brk = chain.verify_to_head(cut).unwrap_err();
    assert_eq!(brk.kind, AuditBreakKind::LinkMismatch);
    assert_eq!(brk.at_index, 3);

    // And the limit this makes explicit: reading only the records, a cut tail is a whole chain.
    assert!(AuditChain::verify_chain(cut).is_ok());

    // Emptied entirely, against a chain that has sealed records, is a truncation too.
    assert!(chain.verify_to_head(&[]).is_err());
}

#[test]
fn an_empty_run_verifies_and_the_limit_is_deliberate() {
    // Nothing in the records themselves can tell "no records" from "every record deleted", so
    // claiming otherwise would be claiming a guarantee this cannot provide.
    assert!(AuditChain::verify_chain(&[]).is_ok());
}

/// EVERY FROZEN TAG STILL SPELLS WHAT THE CHAIN FROZE.
///
/// The digested text for these enumerations used to be whatever the derived `Debug` printed, so a
/// rename moved the sealed hash and every stored record would have reported itself tampered. The
/// text is written out in the production file now; this checks each spelling against today's derive
/// output, so a rename shows up here — as a difference somebody has to look at — instead of in the
/// hash. If this test fails, the tag is the thing to keep and the rename is the thing to reconsider.
#[test]
fn the_frozen_tags_match_the_text_the_chain_was_sealed_with() {
    use crate::record::{
        abort_tag, direction_tag, finish_tag, outcome_tag, quantity_source_tag, reason_tag,
        step_tag,
    };
    use busbar_contract::caps::{Abort, LocatorPtr};

    for step in [
        StepName::Arrival,
        StepName::Decode,
        StepName::Authenticate,
        StepName::Verify,
        StepName::Approve,
        StepName::Admit,
        StepName::Route,
        StepName::Meter,
        StepName::Audit,
        StepName::Encode,
    ] {
        assert_eq!(step_tag(step), format!("{step:?}"), "step name");
    }

    // The reason list is open, so the tag is a RULE rather than a table: the wire name in upper
    // camel case. Checked against every reason declared today, which is what makes the rule safe to
    // apply to one declared tomorrow.
    for reason in ReasonCode::ALL {
        assert_eq!(
            reason_tag(*reason),
            format!("{reason:?}"),
            "reason `{}`",
            reason.as_str()
        );
    }

    for finish in [
        FinishClass::Complete,
        FinishClass::TurnComplete,
        FinishClass::Partial,
        FinishClass::Error,
    ] {
        assert_eq!(finish_tag(finish), format!("{finish:?}"), "finish class");
    }

    for abort in [
        Abort::Kernel {
            reason: ReasonCode::ClientGone,
        },
        Abort::Kernel {
            reason: ReasonCode::OverBudget,
        },
        Abort::Kernel {
            reason: ReasonCode::Drain,
        },
        Abort::Superseded {
            by: UnitKey::new(77),
        },
    ] {
        assert_eq!(abort_tag(abort), format!("{abort:?}"), "abort");
    }

    for outcome in [
        Outcome::Completed,
        Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
        Outcome::Failed(StepName::Route, ReasonCode::DestinationUnreachable),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Drain,
        }),
        Outcome::Aborted(Abort::Superseded {
            by: UnitKey::new(9),
        }),
        Outcome::TimedOut(StepName::Meter),
    ] {
        assert_eq!(outcome_tag(outcome), format!("{outcome:?}"), "outcome");
    }

    for direction in [
        busbar_contract::ClassDirection::Input,
        busbar_contract::ClassDirection::Response,
        busbar_contract::ClassDirection::CacheRead,
        busbar_contract::ClassDirection::CacheWrite,
        busbar_contract::ClassDirection::Kernel,
    ] {
        assert_eq!(
            direction_tag(direction),
            format!("{direction:?}"),
            "class direction"
        );
    }

    for source in [
        QuantitySource::Locator {
            direction: busbar_contract::ClassDirection::Response,
            // A pointer with a quote and a backslash in it, because the frozen text quotes and
            // escapes the pointer and an unescaped one would digest differently.
            ptr: LocatorPtr::new("/usage/\"odd\\name\""),
        },
        QuantitySource::KernelBytes { divisor: 4 },
        QuantitySource::KernelFrames { factor: 2 },
        QuantitySource::TransportUnits,
        QuantitySource::KernelElapsedMono,
        QuantitySource::Count,
        QuantitySource::PlaneCount {
            content_fact_key: "messages".into(),
        },
    ] {
        assert_eq!(
            quantity_source_tag(&source),
            format!("{source:?}"),
            "quantity source"
        );
    }
}

/// THE ON-DISK TAG VOCABULARY, AS LITERALS — the test the frozen table actually needed.
///
/// The test above compares every tag against today's derived `Debug`. That is a useful relation to
/// hold, but on its own it cannot do the job the table exists for, because BOTH SIDES MOVE
/// TOGETHER. Rename `FinishClass::Partial` to `PartialDelivery`: the compiler forces the tag arm to
/// be touched, the obvious edit returns `"PartialDelivery"`, `format!("{finish:?}")` now also says
/// `"PartialDelivery"`, and the suite stays green — while every audit record already on disk whose
/// finish class was `Partial` hashes differently at the next boot and reports itself as
/// `DigestMismatch`, which the operator reads as "EDITED". A tamper alarm that fires on a rename is
/// worse than no alarm, because the one time it does fire nobody will believe it.
///
/// So the spellings are written out here as string literals, with no `Debug` anywhere in the file's
/// path to them. This is the wire vocabulary: it is what is on disk in every chain already sealed,
/// and it is not a rendering of any type. A rename that must not move the hash keeps the literal and
/// this test stays green; a rename that people INTEND to move the hash comes here, goes red, and the
/// migration conversation happens before the records are unreadable rather than after.
///
/// The reason tags are the one open list (`ReasonCode` is `#[non_exhaustive]`, so no exhaustive
/// table could exist here) and are pinned as a representative spread of shapes — single word, two
/// words, an acronym-ish one — which pins the RULE the open list is generated by against fixed text.
#[test]
fn the_on_disk_tag_vocabulary_is_the_literal_text_and_not_a_rendering_of_a_type() {
    use crate::record::{
        abort_tag, direction_tag, finish_tag, outcome_tag, quantity_source_tag, reason_tag,
        step_tag, subject_tag,
    };
    use busbar_contract::caps::{Abort, LocatorPtr};
    use busbar_contract::ClassDirection;

    for (step, frozen) in [
        (StepName::Arrival, "Arrival"),
        (StepName::Decode, "Decode"),
        (StepName::Authenticate, "Authenticate"),
        (StepName::Verify, "Verify"),
        (StepName::Approve, "Approve"),
        (StepName::Admit, "Admit"),
        (StepName::Route, "Route"),
        (StepName::Meter, "Meter"),
        (StepName::Audit, "Audit"),
        (StepName::Encode, "Encode"),
    ] {
        assert_eq!(step_tag(step), frozen, "step name on disk");
    }

    for (finish, frozen) in [
        (FinishClass::Complete, "Complete"),
        (FinishClass::TurnComplete, "TurnComplete"),
        (FinishClass::Partial, "Partial"),
        (FinishClass::Error, "Error"),
    ] {
        assert_eq!(finish_tag(finish), frozen, "finish class on disk");
    }

    for (direction, frozen) in [
        (ClassDirection::Input, "Input"),
        (ClassDirection::Response, "Response"),
        (ClassDirection::CacheRead, "CacheRead"),
        (ClassDirection::CacheWrite, "CacheWrite"),
        (ClassDirection::Kernel, "Kernel"),
    ] {
        assert_eq!(direction_tag(direction), frozen, "class direction on disk");
    }

    for (reason, frozen) in [
        (ReasonCode::Drain, "Drain"),
        (ReasonCode::ClientGone, "ClientGone"),
        (ReasonCode::OverBudget, "OverBudget"),
        (ReasonCode::ScopeDenied, "ScopeDenied"),
        (ReasonCode::NoRate, "NoRate"),
        (ReasonCode::DestinationUnreachable, "DestinationUnreachable"),
    ] {
        assert_eq!(reason_tag(reason), frozen, "reason code on disk");
    }

    for (abort, frozen) in [
        (
            Abort::Kernel {
                reason: ReasonCode::ClientGone,
            },
            "Kernel { reason: ClientGone }",
        ),
        (
            Abort::Kernel {
                reason: ReasonCode::OverBudget,
            },
            "Kernel { reason: OverBudget }",
        ),
        (
            Abort::Kernel {
                reason: ReasonCode::Drain,
            },
            "Kernel { reason: Drain }",
        ),
        (
            Abort::Superseded {
                by: UnitKey::new(77),
            },
            "Superseded { by: UnitKey(77) }",
        ),
    ] {
        assert_eq!(abort_tag(abort), frozen, "abort on disk");
    }

    for (outcome, frozen) in [
        (Outcome::Completed, "Completed"),
        (
            Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
            "Refused(Admit, OverBudget)",
        ),
        (
            Outcome::Failed(StepName::Route, ReasonCode::DestinationUnreachable),
            "Failed(Route, DestinationUnreachable)",
        ),
        (
            Outcome::Aborted(Abort::Kernel {
                reason: ReasonCode::Drain,
            }),
            "Aborted(Kernel { reason: Drain })",
        ),
        (
            Outcome::Aborted(Abort::Superseded {
                by: UnitKey::new(9),
            }),
            "Aborted(Superseded { by: UnitKey(9) })",
        ),
        (Outcome::TimedOut(StepName::Meter), "TimedOut(Meter)"),
    ] {
        assert_eq!(outcome_tag(outcome), frozen, "outcome on disk");
    }

    for (source, frozen) in [
        (
            QuantitySource::Locator {
                direction: ClassDirection::Response,
                // The quote and the backslash are here because the frozen text quotes and escapes
                // the pointer, and an unescaped one would digest differently.
                ptr: LocatorPtr::new("/usage/\"odd\\name\""),
            },
            r#"Locator { direction: Response, ptr: LocatorPtr("/usage/\"odd\\name\"") }"#,
        ),
        (
            QuantitySource::Locator {
                direction: ClassDirection::Input,
                ptr: LocatorPtr::new("/usage/prompt_tokens"),
            },
            r#"Locator { direction: Input, ptr: LocatorPtr("/usage/prompt_tokens") }"#,
        ),
        (
            QuantitySource::KernelBytes { divisor: 4 },
            "KernelBytes { divisor: 4 }",
        ),
        (
            QuantitySource::KernelFrames { factor: 2 },
            "KernelFrames { factor: 2 }",
        ),
        (QuantitySource::TransportUnits, "TransportUnits"),
        (QuantitySource::KernelElapsedMono, "KernelElapsedMono"),
        (QuantitySource::Count, "Count"),
        (
            QuantitySource::PlaneCount {
                content_fact_key: "messages".into(),
            },
            r#"PlaneCount { content_fact_key: "messages" }"#,
        ),
    ] {
        assert_eq!(
            quantity_source_tag(&source),
            frozen,
            "quantity source on disk"
        );
    }

    // The subject tags were never derived from `Debug` at all — they are lowercase wire words — but
    // they are digested alongside the rest, so they belong to the same frozen vocabulary and are
    // pinned in the same place rather than left as the one part of it nobody wrote down.
    for (subject, frozen) in [
        (Subject::PrincipalId("pseudonym-1".into()), "principal"),
        (Subject::Arrival, "arrival"),
        (Subject::Node(7), "node"),
        (Subject::Aggregate, "aggregate"),
    ] {
        assert_eq!(subject_tag(&subject), frozen, "subject on disk");
    }
}

/// One hand-edit to a sealed record.
type Edit = fn(&mut crate::record::AuditRecord);

/// A small helper so the edit battery reads as one line per fact rather than four.
trait UnwrapErrOrElse<T, E> {
    fn unwrap_err_or_else(self, f: impl FnOnce() -> E) -> E;
}

impl<T, E> UnwrapErrOrElse<T, E> for Result<T, E> {
    fn unwrap_err_or_else(self, f: impl FnOnce() -> E) -> E {
        match self {
            Ok(_) => f(),
            Err(e) => e,
        }
    }
}

/// What a break SAYS, and the two halves of the checks that find one.
#[path = "break_reporting_tests.rs"]
mod break_reporting_tests;
