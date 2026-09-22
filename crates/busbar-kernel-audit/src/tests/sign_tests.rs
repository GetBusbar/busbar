// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Signing, the published recipe, the three reads, and the anchors that outlive the records.

// ONE `use`, not two, and the merge is deliberate rather than tidy: `kind-isolation`'s matrix
// counts every naming of another crate, so two import lines are two recorded couplings where the
// test needs exactly one. The types are the contract's own — a record is built out of them, so a
// test that builds a fully populated record cannot avoid naming them once.
use busbar_contract::{
    caps::{
        Audit as AuditStep, KernelSeal, LocatorPtr, MeterClassId, Origin, OriginKind, Outcome,
        Pass, ReasonCode, StepName, UnitKey,
    },
    ClassDirection,
};

use crate::expose;
use crate::heads::HeadHistory;
use crate::recipe::{digest_fields, digest_over, DigestValue};
use crate::record::{
    Amount, Audit, AuditChain, AuditInputs, AuditRecord, Controls, FinishClass, HookApplied,
    OpClassId, OutcomeFacts, QuantitySource, Subject, UsageLine, What,
};
use crate::sign::{AuditKeySet, AuditSigningKey, AuditVerifyingKey, KeyError};

/// A fixed seed, so every test here signs with the same key and a verifier can be handed the public
/// half. A TEST key and nothing else: it is in a public source file, which is exactly what makes it
/// unusable for anything real.
const TEST_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

fn token() -> Pass<AuditStep> {
    Pass::mint(&KernelSeal::acquire_for_kernel())
}

fn origin() -> Origin {
    Origin::seal(&KernelSeal::acquire_for_kernel(), OriginKind::Client)
}

fn signer() -> AuditSigningKey {
    AuditSigningKey::from_hex_seed(TEST_SEED_HEX).expect("the test seed is 64 lowercase hex")
}

/// A record with something in every arm that carries a payload, because those are the fields whose
/// encoding is easiest to move by accident.
fn inputs(unit: u64) -> AuditInputs {
    AuditInputs {
        subject: Subject::PrincipalId(format!("pseudonym-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            op_class: OpClassId::new("chat.completion"),
            destination: Some("upstream-a".into()),
            parent: Some(UnitKey::new(unit + 500)),
            pre_hook_head: Some("hook-head-before".into()),
            post_hook_head: Some("hook-head-after".into()),
        },
        wall: 1_700_000_000 + unit,
        mono: unit * 1_000,
        origin: origin(),
        outcome: OutcomeFacts {
            unit_end: Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
            step: Some(StepName::Admit),
            finish: FinishClass::Error,
            hook_failed: true,
            emission_delta: -7,
            stale_policy: true,
        },
        amount: Amount {
            lines: vec![
                UsageLine {
                    class: MeterClassId::new("tokens_out"),
                    quantity: 120,
                    source: QuantitySource::Locator {
                        direction: ClassDirection::Response,
                        ptr: LocatorPtr::new("/usage/output_tokens"),
                    },
                    estimated: false,
                },
                UsageLine {
                    class: MeterClassId::new("tokens_in"),
                    quantity: 44,
                    source: QuantitySource::Count,
                    estimated: true,
                },
            ],
            pre_tier: 600,
            priced: 540,
            tier_bp: 9_000,
            fee_count: 1,
            currency: "USD".into(),
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
                priced_delta: -10,
            }],
            replayed: true,
            children: vec![UnitKey::new(unit + 1000), UnitKey::new(unit + 1001)],
        },
        correlation_label: Some("customer-order-99".into()),
    }
}

/// A record with every repeatable group EMPTY, which is the shape the published body is easiest to
/// get wrong: a group that publishes nothing instead of an empty array leaves a reader unable to
/// tell "zero of these" from "this build did not send that member".
fn empty_group_inputs() -> AuditInputs {
    let mut i = inputs(9);
    i.amount.lines.clear();
    i.controls.hooks_applied.clear();
    i.controls.children.clear();
    i.what.destination = None;
    i.what.parent = None;
    i.what.pre_hook_head = None;
    i.what.post_hook_head = None;
    i.outcome.step = None;
    i.outcome.unit_end = Outcome::Completed;
    i.correlation_label = None;
    i.controls.hold_ref = None;
    i.controls.settle_ref = None;
    i.controls.slice_ref = None;
    i.controls.lease_ref = None;
    i.subject = Subject::Arrival;
    i
}

// ── THE RECIPE IS THE IMPLEMENTATION ─────────────────────────────────────────────────────────────

/// THE PUBLISHED RECIPE AND THE SEALED DIGEST ARE ONE COMPUTATION.
///
/// This is the test the whole publication rests on. `docs/audit-chain-digest-v1.md` describes the
/// field list in [`crate::recipe::digest_fields`]; if hashing that list did not reproduce what
/// [`AuditChain::digest_of`] seals, then the document would describe something the node does not
/// do, and every third-party verification would fail while looking — to the third party — exactly
/// like a tampered chain.
#[test]
fn the_published_recipe_hashes_to_the_digest_the_chain_seals() {
    let mut chain = AuditChain::new();
    for record in [
        chain.seal(inputs(1), &token()),
        chain.seal(empty_group_inputs(), &token()),
        chain.seal(inputs(3), &token()),
    ] {
        assert_eq!(
            digest_over(&digest_fields(&record)),
            AuditChain::digest_of(&record),
            "the published recipe does not reproduce the sealed digest"
        );
        assert_eq!(record.hash, digest_over(&digest_fields(&record)));
    }
}

/// Every field the recipe names is a field the published range body carries, under that name.
///
/// A recipe field with no published member is a preimage byte a third party cannot obtain, which
/// makes the recipe unusable however accurate it is.
#[test]
fn every_recipe_field_is_published_under_its_own_name() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(inputs(1), &token());
    let body = expose::range_body(&chain, std::slice::from_ref(&record), 1, 1);
    for field in digest_fields(&record) {
        let name = field
            .name
            .split("[]")
            .next()
            .expect("a split always yields one");
        assert!(
            body.contains(&format!("\"{name}\"")),
            "recipe field {} is not published in the range body",
            field.name
        );
    }
    // And the two things that are not digest inputs but are what a verifier checks AGAINST.
    assert!(body.contains("\"hash\""));
    assert!(body.contains("\"signature\""));
    assert!(body.contains("\"key_id\""));
}

// ── THE SIGNATURE ────────────────────────────────────────────────────────────────────────────────

/// A sealed record carries a signature that verifies against the published key, and names the key
/// by an identifier the verifier can DERIVE from that key rather than be told.
#[test]
fn a_sealed_record_verifies_against_the_published_key() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(inputs(1), &token());

    let published = AuditVerifyingKey::from_hex(&signer().public_key_hex())
        .expect("the published key is 64 lowercase hex");
    assert_eq!(record.key_id.as_deref(), Some(published.key_id()));
    assert_eq!(
        AuditChain::verify_signature(&record, &published),
        Ok(()),
        "a record this node sealed does not verify against the key this node publishes"
    );
    assert_eq!(
        record.signature.as_deref().map(str::len),
        Some(128),
        "an ed25519 signature is 64 bytes, which is 128 lowercase hex characters"
    );
}

/// ALTERING ANY DIGESTED FIELD BREAKS THE SIGNATURE — including the ones that look cosmetic.
///
/// The list below is deliberately stuffed with fields nobody would defend: the monotonic clock
/// (which is not even the timestamp a reader looks at), the `estimated` flag on a usage line, the
/// basis points of a tier that priced to the same number anyway, the origin kind. Every one of them
/// is in the preimage, so every one of them is evidence, and an editor who "only fixed a typo" is
/// caught by exactly the same mechanism as one who moved money.
#[test]
fn altering_any_field_breaks_the_signature_including_the_cosmetic_ones() {
    let mut chain = AuditChain::new().signing_with(signer());
    let sealed = chain.seal(inputs(1), &token());
    let published =
        AuditVerifyingKey::from_hex(&signer().public_key_hex()).expect("a published key");

    // Each edit is a thing somebody could argue is harmless. None of them is.
    type Edit = (&'static str, fn(&mut AuditRecord));
    let edits: Vec<Edit> = vec![
        ("the monotonic clock", |r| r.mono += 1),
        ("the wall clock", |r| r.wall += 1),
        ("where it came from", |r| r.origin_kind = "internal"),
        ("a usage line's estimated flag", |r| {
            r.amount.lines[0].estimated = !r.amount.lines[0].estimated
        }),
        ("the tier's basis points", |r| r.amount.tier_bp += 1),
        ("the currency's spelling", |r| {
            r.amount.currency = "usd".into()
        }),
        ("the rate card version", |r| r.amount.rate_card_version += 1),
        ("whether a hook failed", |r| {
            r.outcome.hook_failed = !r.outcome.hook_failed
        }),
        ("whether the policy was stale", |r| {
            r.outcome.stale_policy = !r.outcome.stale_policy
        }),
        ("whether it was replayed", |r| {
            r.controls.replayed = !r.controls.replayed
        }),
        ("a child unit's number", |r| {
            r.controls.children[1] = UnitKey::new(1)
        }),
        ("the order of two usage lines", |r| {
            r.amount.lines.swap(0, 1)
        }),
        ("a hook's priced delta", |r| {
            r.controls.hooks_applied[0].priced_delta += 1
        }),
        ("the correlation hash", |r| {
            r.correlation_hash = Some("0".repeat(64))
        }),
        ("the lease epoch", |r| r.controls.lease_epoch += 1),
        ("the position in the chain", |r| r.seq += 1),
        ("the link to the predecessor", |r| {
            r.prev_hash = "0".repeat(64)
        }),
        ("the amount it priced to", |r| r.amount.priced += 1),
        ("the destination", |r| {
            r.what.destination = Some("upstream-b".into())
        }),
    ];

    for (what, edit) in edits {
        let mut altered = sealed.clone();
        edit(&mut altered);
        assert_ne!(
            altered, sealed,
            "the edit to {what} did not actually change the record"
        );
        assert_eq!(
            AuditChain::verify_signature(&altered, &published),
            Err(KeyError::BadSignature),
            "editing {what} left a record that still verifies"
        );
        // And the same edit with the hash recomputed — the forger who remembered to rehash — still
        // fails, because the signature is over a digest they cannot re-mint without the key.
        let mut rehashed = altered.clone();
        rehashed.hash = AuditChain::digest_of(&rehashed);
        assert_eq!(
            AuditChain::verify_signature(&rehashed, &published),
            Err(KeyError::BadSignature),
            "editing {what} and rehashing left a record that still verifies"
        );
    }
}

/// A record signed by one key does not verify against another, and an unsigned record is reported
/// as unsigned rather than as a failure — the two are different findings.
#[test]
fn a_foreign_key_and_an_absent_signature_are_different_answers() {
    let mut signed_chain = AuditChain::new().signing_with(signer());
    let signed = signed_chain.seal(inputs(1), &token());
    let mut unsigned_chain = AuditChain::new();
    let unsigned = unsigned_chain.seal(inputs(1), &token());
    assert_eq!(unsigned.signature, None);
    assert_eq!(unsigned.key_id, None);

    let other = AuditSigningKey::from_seed(&[7u8; 32]);
    let other_published =
        AuditVerifyingKey::from_hex(&other.public_key_hex()).expect("a published key");
    assert_eq!(
        AuditChain::verify_signature(&signed, &other_published),
        Err(KeyError::BadSignature)
    );
    assert_eq!(
        AuditChain::verify_signature(&unsigned, &other_published),
        Err(KeyError::Unsigned)
    );
}

/// THE DIGEST DID NOT MOVE WHEN SIGNING ARRIVED.
///
/// The signature is computed FROM the digest and is not digested, which is what lets a chain
/// written before this release keep verifying. The frozen hex is the one in `record_tests`; it is
/// repeated here against a SIGNED chain to say the thing that test cannot: that turning signing on
/// does not move it either.
#[test]
fn turning_signing_on_does_not_move_the_sealed_digest() {
    let mut unsigned = AuditChain::new();
    let mut signed = AuditChain::new().signing_with(signer());
    let a = unsigned.seal(inputs(1), &token());
    let b = signed.seal(inputs(1), &token());
    assert_eq!(a.hash, b.hash, "the signature entered the digest");
    assert!(a.signature.is_none());
    assert!(b.signature.is_some());
}

/// A small-order public key verifies EVERY signature, so publishing one would turn the whole
/// mechanism into a rubber stamp. Refused at the door.
#[test]
fn a_small_order_public_key_is_refused() {
    // The order-1 identity point, and an order-8 point. Both decompress; neither is a key.
    let identity = "0100000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(
        AuditVerifyingKey::from_hex(identity),
        Err(KeyError::WeakKey)
    );
    assert_eq!(
        AuditVerifyingKey::from_hex("00".repeat(32).as_str()),
        Err(KeyError::WeakKey)
    );
}

// ── KEY MATERIAL NEVER REACHES A LOG ─────────────────────────────────────────────────────────────

/// THE SECRET IS NOT IN ANY `Debug`, AT ANY DEPTH.
///
/// Formatted three ways, because the leak nobody rehearses is the indirect one: a key is rarely
/// printed on purpose, it is printed because something CONTAINING it was. So this formats the key,
/// the chain that holds the key, and a tuple of both, and looks for the seed's hex, the seed's
/// bytes as a Rust debug slice, and the ed25519 crate's own rendering of a secret scalar.
#[test]
fn debug_never_shows_the_secret() {
    let key = signer();
    let chain = AuditChain::new().signing_with(signer());
    let rendered = format!("{key:?} | {chain:?} | {:?}", (&key, &chain));

    assert!(
        !rendered.contains(TEST_SEED_HEX),
        "the seed's hex is in a Debug rendering: {rendered}"
    );
    // The seed's bytes, as a derive would print them.
    let seed_bytes: Vec<u8> = (0..32)
        .map(|i| {
            u8::from_str_radix(&TEST_SEED_HEX[i * 2..i * 2 + 2], 16).expect("test seed is hex")
        })
        .collect();
    assert!(
        !rendered.contains(&format!("{seed_bytes:?}")),
        "the seed's bytes are in a Debug rendering: {rendered}"
    );
    // A derive on the dalek type would name its secret field; the identifier must be there instead.
    assert!(!rendered.contains("secret"), "a Debug named a secret field");
    assert!(
        rendered.contains(key.key_id()),
        "a Debug that shows nothing is not the same as one that shows the identifier"
    );
    assert!(rendered.contains("ed25519"));
}

/// AN ERROR NEVER QUOTES THE THING IT REFUSED.
///
/// A hex decoder from a general library names the offending character and its index. For a signing
/// seed that is a byte of the secret, printed into whatever caught the error — a log line, a
/// terminal, a support ticket. (The packaging CLI's own `$BUSBAR_SIGN_KEY` reader does exactly
/// that today and is a separate known defect, tracked outside this crate.) So every rejection here
/// is a
/// whole-input judgement, and this checks that no fragment of a bad key survives into the message.
#[test]
fn a_rejected_key_is_never_quoted_back() {
    let nearly = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7fZZ";
    let short = "9d61b19deffd5a60ba844af492ec2cc4";
    for bad in [nearly, short] {
        let err = AuditSigningKey::from_hex_seed(bad).expect_err("that is not a seed");
        let said = format!("{err} | {err:?}");
        for window in 4..=8 {
            for start in 0..bad.len().saturating_sub(window) {
                let fragment = &bad[start..start + window];
                assert!(
                    !said.contains(fragment),
                    "the error quoted {fragment:?} out of the rejected key: {said}"
                );
            }
        }
        // And it names no offset either — an index narrows what the rest can be.
        assert!(!said.contains("index"), "the error named an offset: {said}");
        assert!(
            !said.contains(&(bad.len() - 1).to_string()),
            "the error named a position: {said}"
        );
    }
}

/// The key set publishes the public half and there is no path to the other one.
#[test]
fn the_key_set_publishes_only_the_public_half() {
    let mut keys = AuditKeySet::new();
    keys.insert_signer(&signer());
    keys.insert_signer(&signer());
    assert_eq!(keys.len(), 1, "one key added twice is one key");

    let body = expose::keys_body(&keys);
    assert!(body.contains(&signer().public_key_hex()));
    assert!(body.contains(signer().key_id()));
    assert!(
        !body.contains(TEST_SEED_HEX),
        "the key set published the secret: {body}"
    );
    assert!(body.contains("\"algorithm\":\"ed25519\""));
}

// ── THE ANCHORS OUTLIVE THE RECORDS ──────────────────────────────────────────────────────────────

/// HEAD HISTORY SURVIVES A RETENTION PASS THAT PRUNES ITS RECORDS.
///
/// The pass is [`AuditChain::prune_records_before`] — the predicate every store in this tree
/// applies, a record whose own instant is before a cutoff goes. After it, the records for the
/// pruned window are gone, and the ANCHOR for that window is still here and still signed. A puller
/// that was offline across the cutoff lost the records, which was the deal, and can still say what
/// the chain's tip was while it was away.
#[test]
fn head_history_survives_a_retention_pass_that_prunes_its_records() {
    // One head per hour; a record every twenty minutes for six hours.
    let mut chain = AuditChain::new()
        .signing_with(signer())
        .sampling_heads_every(3_600);
    let start = 1_700_000_000u64;
    let mut records = Vec::new();
    for step in 0..18u64 {
        let mut i = inputs(step + 1);
        i.wall = start + step * 1_200;
        records.push(chain.seal(i, &token()));
    }
    assert_eq!(records.len(), 18);
    let anchors_before = chain.heads().anchors();
    assert_eq!(
        anchors_before.len(),
        7,
        "six hourly samples plus the live tip"
    );

    // Retention keeps the last two hours. Twelve records go.
    let cutoff = start + 4 * 3_600;
    let dropped = chain.prune_records_before(&mut records, cutoff);
    assert_eq!(dropped, 12);
    assert!(
        records.iter().all(|r| r.wall >= cutoff),
        "a record older than the cutoff survived the pass"
    );

    // THE ANCHORS ARE UNTOUCHED.
    assert_eq!(
        chain.heads().anchors(),
        anchors_before,
        "the retention pass reached the head history"
    );
    let vanished_window_anchor = chain
        .heads()
        .anchor_at(3)
        .expect("the anchor for a window whose records were pruned");
    assert!(
        vanished_window_anchor.wall < cutoff,
        "the surviving anchor is not for the pruned window"
    );
    assert!(
        vanished_window_anchor.signature.is_some(),
        "an anchor that is not signed is not evidence"
    );
    assert!(
        !records.iter().any(|r| r.seq == vanished_window_anchor.seq),
        "the record that anchor names should have been pruned"
    );

    // And a published head body still carries the whole series.
    let body = expose::heads_body(&chain);
    for anchor in &anchors_before {
        assert!(
            body.contains(&anchor.hash),
            "an anchor is missing from the published head history"
        );
    }
}

/// The genesis head always joins the series, whatever the sampling rate, because a window-verifier
/// needs it to know the chain started where it says it did.
#[test]
fn the_genesis_head_is_always_an_anchor() {
    let mut chain = AuditChain::new().sampling_heads_every(86_400);
    let first = chain.seal(inputs(1), &token());
    let _ = chain.seal(inputs(2), &token());
    assert_eq!(chain.heads().series().len(), 1);
    assert_eq!(chain.heads().series()[0].seq, first.seq);
    assert_eq!(chain.heads().series()[0].hash, first.hash);
}

/// A head history with nothing in it is a node that has sealed nothing, and the head read says so
/// rather than refusing: "this chain has no records" is a true answer.
#[test]
fn a_chain_that_has_sealed_nothing_publishes_a_null_head() {
    let chain = AuditChain::new();
    assert!(chain.heads().is_empty());
    let body = expose::head_body(&chain);
    assert!(body.contains("\"head\":null"), "{body}");
    assert!(body.contains("\"next_seq\":1"));
}

/// A head history has no way to lose anything: no pruning method, no cutoff, no capacity.
///
/// Stated as a test rather than only as a comment because the guarantee is the ABSENCE of an
/// operation, and an absence is the one thing a reader stops noticing. `observe` only ever grows
/// the series.
#[test]
fn nothing_shrinks_the_head_history() {
    let mut history = HeadHistory::every(0);
    let mut chain = AuditChain::new();
    let mut last = 0;
    for i in 1..=50u64 {
        let record = chain.seal(inputs(i), &token());
        history.observe(&record);
        assert!(
            history.series().len() > last,
            "a head history shrank or stalled"
        );
        last = history.series().len();
    }
    assert_eq!(history.series().len(), 50);
}

// ── THE COST ─────────────────────────────────────────────────────────────────────────────────────

/// WHERE THE SIGNATURE IS PAID FOR, MEASURED.
///
/// One signature per SEALED RECORD — one per finished unit, at the audit step, after the response
/// has been produced. Not one per frame, per token or per byte: the serving path does not call
/// `seal` at all, it calls it once when the unit is over. So the question #71 asks — does this add
/// measurable per-request cost to SERVING — is answered by where the call is, and this measures
/// what that one call costs so the answer is a number rather than an assurance.
///
/// Measured at 18.8µs/record in a release build on the machine this landed on (3.6µs to seal
/// without a signature, 22.4µs with). The bound asserted below is per-profile because ed25519's
/// curve arithmetic is ~170x slower unoptimized, and a bound tight enough to be interesting in
/// release is one a debug run fails for reasons that have nothing to do with this change.
///
/// What makes this a real check rather than a stopwatch is that the cost is BOUNDED PER RECORD at
/// all: if signing had been put anywhere per-byte or per-frame, this number would move with the
/// size of the record's payload, and a fixed bound would be the thing that caught it.
#[test]
fn signing_is_paid_once_per_sealed_record_and_the_cost_is_measured() {
    const N: u32 = 300;
    let mut unsigned = AuditChain::new();
    let started = std::time::Instant::now();
    for i in 0..N as u64 {
        std::hint::black_box(unsigned.seal(inputs(i + 1), &token()));
    }
    let without = started.elapsed() / N;

    let mut signed = AuditChain::new().signing_with(signer());
    let started = std::time::Instant::now();
    for i in 0..N as u64 {
        std::hint::black_box(signed.seal(inputs(i + 1), &token()));
    }
    let with = started.elapsed() / N;
    let cost = with.saturating_sub(without);

    let profile = if cfg!(debug_assertions) {
        "debug (ed25519 unoptimised)"
    } else {
        "release"
    };
    println!(
        "[{profile}] seal without a signature: {without:?}/record; with: {with:?}/record; \
         the signature costs {cost:?}/record"
    );
    // Release is the profile the claim is about; debug is allowed two orders of magnitude of slack
    // for the unoptimised curve arithmetic and still bounds the thing that matters — that the cost
    // is per RECORD and does not run away.
    let ceiling = if cfg!(debug_assertions) {
        std::time::Duration::from_millis(50)
    } else {
        std::time::Duration::from_micros(500)
    };
    assert!(
        cost < ceiling,
        "[{profile}] one ed25519 signature took {cost:?}, over the {ceiling:?} per-record ceiling"
    );
    assert_eq!(signed.sealed(), u64::from(N));
}

/// THE COST DOES NOT MOVE WITH THE SIZE OF THE RECORD.
///
/// The half of "it is not on the hot path" that a stopwatch cannot say. A signature is taken over a
/// 64-character digest, so its cost is the same for a record with two usage lines and one with two
/// hundred — which is what "per sealed record" MEANS. If signing had been put anywhere that saw the
/// payload, this ratio would grow with it.
#[test]
fn the_signature_costs_the_same_whatever_the_record_holds() {
    const N: u32 = 200;
    let time_one = |mut make: Box<dyn FnMut(u64) -> AuditInputs>| {
        let mut chain = AuditChain::new().signing_with(signer());
        let mut plain = AuditChain::new();
        let started = std::time::Instant::now();
        for i in 0..N as u64 {
            std::hint::black_box(chain.seal(make(i + 1), &token()));
        }
        let signed = started.elapsed() / N;
        let started = std::time::Instant::now();
        for i in 0..N as u64 {
            std::hint::black_box(plain.seal(make(i + 1), &token()));
        }
        signed.saturating_sub(started.elapsed() / N)
    };

    let small = time_one(Box::new(inputs));
    let large = time_one(Box::new(|i| {
        let mut wide = inputs(i);
        let line = wide.amount.lines[0].clone();
        wide.amount.lines = std::iter::repeat_n(line, 200).collect();
        wide.controls.children = (0..200).map(UnitKey::new).collect();
        wide
    }));
    println!("signature over a small record: {small:?}; over a 200-line record: {large:?}");
    // Generous, because two timings on a shared machine are two timings on a shared machine. What
    // it excludes is the shape that would matter: a cost that scales with the payload.
    assert!(
        large < small * 4 + std::time::Duration::from_micros(200),
        "the signature cost grew with the record's size ({small:?} -> {large:?}), which means it \
         is being taken over something other than the digest"
    );
}

// ── THE THREE READS ──────────────────────────────────────────────────────────────────────────────

/// The head read answers with the tip and the names a verifier needs to know which rules apply.
#[test]
fn the_head_read_answers_with_the_tip_and_the_recipe_it_was_sealed_under() {
    let mut chain = AuditChain::new().signing_with(signer());
    let last = (1..=3).map(|i| chain.seal(inputs(i), &token())).last();
    let last = last.expect("three records were sealed");
    let body = expose::head_body(&chain);
    assert!(
        body.contains("\"recipe\":\"busbar.audit.digest.v1\""),
        "{body}"
    );
    assert!(
        body.contains("\"signature_domain\":\"busbar.audit.record.v1\""),
        "{body}"
    );
    assert!(body.contains(&format!("\"seq\":{}", last.seq)), "{body}");
    assert!(body.contains(&last.hash), "{body}");
    assert!(
        body.contains(last.signature.as_deref().expect("a signed record")),
        "{body}"
    );
    assert!(body.contains("\"next_seq\":4"), "{body}");
}

/// The range read is inclusive at both ends, in position order, and a window that runs off either
/// end is shorter rather than an error.
#[test]
fn the_range_read_is_inclusive_and_clips_rather_than_refusing() {
    let mut chain = AuditChain::new().signing_with(signer());
    let records: Vec<_> = (1..=5).map(|i| chain.seal(inputs(i), &token())).collect();

    let two_three = expose::range_body(&chain, &records, 2, 3);
    assert_eq!(two_three.matches("\"prev_hash\"").count(), 2);
    assert!(two_three.contains(&records[1].hash));
    assert!(two_three.contains(&records[2].hash));

    let past_the_end = expose::range_body(&chain, &records, 4, 400);
    assert_eq!(past_the_end.matches("\"prev_hash\"").count(), 2);

    let empty = expose::range_body(&chain, &records, 90, 99);
    assert!(empty.contains("\"records\":[]"), "{empty}");
}

/// An empty repeated group publishes an EMPTY ARRAY, not nothing. A reader must be able to tell
/// "zero usage lines" from "this build did not send that member".
#[test]
fn an_empty_group_publishes_an_empty_array() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(empty_group_inputs(), &token());
    let body = expose::range_body(&chain, std::slice::from_ref(&record), 1, 1);
    assert!(body.contains("\"lines_count\":0,\"lines\":[]"), "{body}");
    assert!(body.contains("\"hooks_count\":0,\"hooks\":[]"), "{body}");
    assert!(
        body.contains("\"children_count\":0,\"children\":[]"),
        "{body}"
    );
}

/// A field holding arbitrary caller text comes out as valid, re-readable JSON — including the
/// characters a naive escaper drops.
#[test]
fn caller_named_text_survives_into_the_published_body() {
    let mut chain = AuditChain::new().signing_with(signer());
    let mut i = inputs(1);
    i.what.op_class = OpClassId::new("tool\"a\\b\nc\u{1}d|e");
    let record = chain.seal(i, &token());
    let body = expose::range_body(&chain, std::slice::from_ref(&record), 1, 1);
    // Built rather than written as a literal, so the expectation cannot be mangled by whatever
    // edits this file: backslash-quote, backslash-backslash, backslash-n, and the control
    // character as its six-character \u form.
    let expected = format!("tool{}\"a{}{}b{}nc{}u0001d|e", "\\", "\\", "\\", "\\", "\\");
    assert!(body.contains(&expected), "{body}");
    let parsed: serde_json::Value = serde_json::from_str(&body).expect("the body is valid JSON");
    assert_eq!(
        parsed["records"][0]["op_class"].as_str(),
        Some("tool\"a\\b\nc\u{1}d|e")
    );
}

/// Every published body parses, and the numeric members that are 128-bit come out as TEXT — a JSON
/// number wide enough to hold them is not safely readable, and through an `f64` it is not readable
/// at all.
#[test]
fn the_published_bodies_parse_and_the_wide_numbers_are_text() {
    let mut chain = AuditChain::new().signing_with(signer());
    let records: Vec<_> = (1..=2).map(|i| chain.seal(inputs(i), &token())).collect();
    let mut keys = AuditKeySet::new();
    keys.insert_signer(&signer());

    for body in [
        expose::head_body(&chain),
        expose::range_body(&chain, &records, 1, 2),
        expose::keys_body(&keys),
        expose::heads_body(&chain),
    ] {
        serde_json::from_str::<serde_json::Value>(&body).expect("every published body is JSON");
    }

    let parsed: serde_json::Value =
        serde_json::from_str(&expose::range_body(&chain, &records, 1, 2)).expect("JSON");
    assert_eq!(parsed["records"][0]["priced"].as_str(), Some("540"));
    assert_eq!(parsed["records"][0]["pre_tier"].as_str(), Some("600"));
    assert_eq!(parsed["records"][0]["emission_delta"].as_str(), Some("-7"));
    assert_eq!(
        parsed["records"][0]["hooks"][0]["priced_delta"].as_str(),
        Some("-10")
    );
    // And the fields the digest takes as numbers stay numbers, because the distinction is what the
    // framing turns on.
    assert!(parsed["records"][0]["seq"].is_u64());
    assert!(parsed["records"][0]["lines"][0]["quantity"].is_u64());
}

/// Every value the recipe calls `Num` is published as a JSON number and every `Text` as a JSON
/// string. A verifier reads the distinction off the body; getting it backwards computes a different
/// preimage and reports an honest chain as tampered.
#[test]
fn the_body_keeps_the_texts_texts_and_the_numbers_numbers() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(inputs(1), &token());
    let parsed: serde_json::Value = serde_json::from_str(&expose::range_body(
        &chain,
        std::slice::from_ref(&record),
        1,
        1,
    ))
    .expect("JSON");
    let published = &parsed["records"][0];
    for field in digest_fields(&record) {
        let Some(name) = field.name.strip_suffix("").filter(|n| !n.contains("[]")) else {
            continue;
        };
        match field.value {
            DigestValue::Text(_) => assert!(
                published[name].is_string(),
                "{name} is a recipe text but is not published as a string"
            ),
            DigestValue::Num(_) => assert!(
                published[name].is_u64(),
                "{name} is a recipe number but is not published as a number"
            ),
        }
    }
}

// ── A THIRD PARTY REPRODUCES THE CHAIN WITHOUT THE BUSBAR BINARY ─────────────────────────────────

/// Where the independent verifier lives, relative to this crate.
fn verifier_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/verify-audit-chain.py")
}

/// Write the three read bodies into a fresh directory and run the independent verifier over them.
fn run_verifier(dir: &std::path::Path, extra: &[&str]) -> (bool, String) {
    let mut cmd = std::process::Command::new("python3");
    cmd.arg(verifier_path())
        .arg("--range")
        .arg(dir.join("range.json"))
        .arg("--keys")
        .arg(dir.join("keys.json"))
        .arg("--head")
        .arg(dir.join("head.json"))
        .args(extra);
    let out = cmd.output().unwrap_or_else(|e| {
        panic!(
            "the independent verifier could not be run ({e}). It is a stdlib-only python3 script; \
             CI already runs python3 for scripts/method-inventory.py and friends."
        )
    });
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.success(), said)
}

/// Seal a five-record signed chain and write out exactly what the three reads answer with.
fn publish_a_chain(dir: &std::path::Path) -> Vec<AuditRecord> {
    let mut chain = AuditChain::new().signing_with(signer());
    let records: Vec<_> = (1..=5).map(|i| chain.seal(inputs(i), &token())).collect();
    let mut keys = AuditKeySet::new();
    keys.insert_signer(&signer());
    std::fs::create_dir_all(dir).expect("a scratch directory");
    std::fs::write(
        dir.join("range.json"),
        expose::range_body(&chain, &records, 1, 5),
    )
    .expect("write the range body");
    std::fs::write(dir.join("head.json"), expose::head_body(&chain)).expect("write the head body");
    std::fs::write(dir.join("keys.json"), expose::keys_body(&keys)).expect("write the key set");
    records
}

/// A scratch directory of this process's own, cleaned up on the way out.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("busbar-audit-verify-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Scratch(dir)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// THE ACCEPTANCE TEST FOR THE PUBLISHED RECIPE: a verifier that has never seen this repository
/// reproduces a real chain from the three reads alone.
///
/// `scripts/verify-audit-chain.py` imports nothing but the Python standard library — no busbar, no
/// `cryptography`, no `nacl`, no `openssl` subprocess. It rebuilds each preimage from the published
/// members, takes SHA-256 of it, and checks the ed25519 signature with the RFC 8032 arithmetic
/// written out in the script. If it cannot do that, the recipe is incomplete, and no amount of
/// asserting inside this crate would have found out.
#[test]
fn an_independent_verifier_reproduces_a_real_chain_from_the_published_reads() {
    let scratch = Scratch::new("ok");
    let records = publish_a_chain(scratch.path());
    let (ok, said) = run_verifier(scratch.path(), &["--require-signature"]);
    assert!(
        ok,
        "the independent verifier refused an honest chain:\n{said}"
    );
    assert!(
        said.contains("5 record(s) verified, 5 of them signed"),
        "{said}"
    );
    assert!(said.contains(&records[4].hash), "{said}");
}

/// AND IT SAYS NO. The same verifier, over a chain with one field edited, refuses — which is what
/// makes the green run above mean anything.
///
/// The edit is to `mono`, the monotonic clock: the field with the best claim to being cosmetic, the
/// one a reader never looks at, and the one an editor would most expect to get away with.
#[test]
fn the_independent_verifier_refuses_a_chain_with_one_cosmetic_field_edited() {
    let scratch = Scratch::new("edited");
    publish_a_chain(scratch.path());
    let range = scratch.path().join("range.json");
    let body = std::fs::read_to_string(&range).expect("the range body");
    let edited = body.replacen("\"mono\":3000", "\"mono\":3001", 1);
    assert_ne!(edited, body, "the edit did not land");
    std::fs::write(&range, edited).expect("rewrite the range body");

    let (ok, said) = run_verifier(scratch.path(), &[]);
    assert!(!ok, "the verifier accepted an edited chain:\n{said}");
    assert!(
        said.contains("does not hash to its own published fields"),
        "{said}"
    );
}

/// And it refuses a chain whose signature was replaced with one minted by a different key, even
/// though every digest still checks out. A forger who can rewrite the file cannot mint the
/// signature without the key.
#[test]
fn the_independent_verifier_refuses_a_signature_from_a_key_it_was_not_published_with() {
    let scratch = Scratch::new("forged");
    let records = publish_a_chain(scratch.path());
    let forger = AuditSigningKey::from_seed(&[42u8; 32]);
    let range = scratch.path().join("range.json");
    let body = std::fs::read_to_string(&range).expect("the range body");
    // Same key IDENTIFIER, so the verifier looks up the published key — and a signature minted by
    // somebody else fails against it. Claiming to be a key you are not is the whole attack.
    let forged = body.replacen(
        records[0].signature.as_deref().expect("a signed record"),
        &forger.sign_digest(&records[0].hash),
        1,
    );
    assert_ne!(forged, body, "the forgery did not land");
    std::fs::write(&range, forged).expect("rewrite the range body");

    let (ok, said) = run_verifier(scratch.path(), &[]);
    assert!(!ok, "the verifier accepted a forged signature:\n{said}");
    assert!(
        said.contains("does NOT verify against published key"),
        "{said}"
    );
}

/// And it refuses a truncated run: the records that are left link and number perfectly among
/// themselves, and it is the node's own published HEAD that says one is missing.
#[test]
fn the_independent_verifier_catches_a_tail_truncation_using_the_published_head() {
    let scratch = Scratch::new("truncated");
    let records = publish_a_chain(scratch.path());
    let mut chain = AuditChain::new().signing_with(signer());
    let reread: Vec<_> = (1..=5).map(|i| chain.seal(inputs(i), &token())).collect();
    assert_eq!(reread[4].hash, records[4].hash, "sealing is deterministic");
    // The node ANSWERS a request for 1..5 with only the first four. Nothing about those four is
    // wrong — they link, they number, they hash, they verify. The run is just short at the end,
    // which is the one defect a run of records cannot report about itself.
    std::fs::write(
        scratch.path().join("range.json"),
        expose::range_body(&chain, &reread[..4], 1, 5),
    )
    .expect("write a truncated range");

    let (ok, said) = run_verifier(scratch.path(), &[]);
    assert!(!ok, "the verifier accepted a truncated chain:\n{said}");
    assert!(
        said.contains("MISSING FROM THE END of this window"),
        "{said}"
    );
}
/// THE CANONICAL RECORD THE PUBLISHED SPEC'S WORKED EXAMPLE IS BUILT FROM.
///
/// Fixed in every field, including the ones a fixture usually varies, because the spec quotes its
/// digest and its signature as literal hex. Sealed with the RFC 8032 test key so a reader can check
/// the worked example against any ed25519 implementation they already trust.
fn worked_example_inputs() -> AuditInputs {
    let mut i = empty_group_inputs();
    i.subject = Subject::Node(7);
    i.what.op_class = OpClassId::new("chat.completion");
    i.wall = 1_700_000_000;
    i.mono = 42;
    i.amount.currency = "USD".into();
    i.amount.bucket_chain_ref = "chain:free>paid".into();
    i.amount.pre_tier = 600;
    i.amount.priced = 540;
    i.amount.tier_bp = 9_000;
    i.amount.fee_count = 1;
    i.amount.rate_card_version = 3;
    i
}

/// Pull the nth fenced `json` block out of the published spec.
fn spec_json_block(doc: &str, nth: usize) -> serde_json::Value {
    let block = doc
        .split("```json")
        .nth(nth + 1)
        .unwrap_or_else(|| panic!("the spec has no json block {nth}"))
        .split("```")
        .next()
        .expect("a fenced block closes");
    serde_json::from_str(block).expect("the spec's worked example is valid JSON")
}

/// THE PUBLISHED SPEC CANNOT DRIFT FROM THE CODE.
///
/// `docs/audit-chain-digest-v1.md` quotes three bodies and a digest as literal values. A document
/// that described something the node does not do would make every third-party verification fail
/// while looking, to the third party, exactly like a tampered chain — so the worked example is
/// asserted against this build rather than transcribed once and trusted.
///
/// Compared as PARSED JSON, not as bytes: the page pretty-prints for a human reader, and the
/// contract is the members and their values, not the whitespace.
#[test]
fn the_worked_example_in_the_published_spec_is_what_this_build_answers_with() {
    let doc = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/audit-chain-digest-v1.md"),
    )
    .expect("the published spec is in the tree");

    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(worked_example_inputs(), &token());
    let mut keys = AuditKeySet::new();
    keys.insert_signer(&signer());

    let parse = |body: String| -> serde_json::Value {
        serde_json::from_str(&body).expect("a published body is JSON")
    };
    assert_eq!(
        spec_json_block(&doc, 0),
        parse(expose::range_body(
            &chain,
            std::slice::from_ref(&record),
            1,
            1
        )),
        "the spec's range example is not what this build answers with"
    );
    assert_eq!(
        spec_json_block(&doc, 1),
        parse(expose::head_body(&chain)),
        "the spec's head example is not what this build answers with"
    );
    assert_eq!(
        spec_json_block(&doc, 2),
        parse(expose::keys_body(&keys)),
        "the spec's key-set example is not what this build answers with"
    );

    // And the three values the prose quotes outside a fence.
    assert!(
        doc.contains(&record.hash),
        "the spec quotes a digest this build does not produce"
    );
    assert!(doc.contains(&signer().public_key_hex()));
    assert!(doc.contains(signer().key_id()));
    assert!(
        doc.contains(&format!("preimage is {} bytes", 490)),
        "the spec quotes a preimage length this build does not produce"
    );
    assert_eq!(
        digest_over(&digest_fields(&record)).len(),
        64,
        "a digest is 64 lowercase hex characters"
    );
}

/// The preimage the spec's worked example quotes the LENGTH of is the one this build frames.
#[test]
fn the_worked_examples_preimage_is_the_length_the_spec_quotes() {
    let mut chain = AuditChain::new().signing_with(signer());
    let record = chain.seal(worked_example_inputs(), &token());
    let framed: usize = digest_fields(&record)
        .iter()
        .map(|f| {
            8 + match &f.value {
                DigestValue::Text(s) => s.len(),
                DigestValue::Num(_) => 8,
            }
        })
        .sum();
    assert_eq!(framed, 490);
}
