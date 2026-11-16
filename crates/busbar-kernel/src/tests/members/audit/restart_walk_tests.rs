// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SEALING-FIX r20 §3.6.0, the restart walk (MR-5): tests 4(j), 4(k), 4(l), 4(m), 16, 23 and 24's
//! walk rules, over a node's records as the journal holds them.

use busbar_contract::caps::{Audit as AuditStep, Pass};
use busbar_kernel_audit::record::{AuditChain, AuditRecord};
use busbar_kernel_audit::sign::{AuditSigningKey, AuditVerifyingKey};
use busbar_kernel_audit::{
    span_ms, walk_tail, BootstrapSigner, BreakAt, BreakReason, Fingerprint, LiveSigner, Notary,
    Stamp, StampKind, TailItem, WalkContext, WalkOutcome,
};

const NODE: u64 = 21;
const HOST: &str = "host-a";
const SEED: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const OTHER_SEED: &str = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
/// Line `k` of a default chain is linked at `T0 + k` ms.
const T0: u64 = 1_700_000_000_000;

fn key() -> AuditSigningKey {
    AuditSigningKey::from_hex_seed(SEED).expect("the test seed is 64 lowercase hex")
}

fn public() -> AuditVerifyingKey {
    AuditVerifyingKey::from_hex(&key().public_key_hex()).expect("a public key")
}

fn signers(seed: &str) -> (Notary, BootstrapSigner) {
    let (notary, bootstrap) = AuditSigningKey::from_hex_seed(seed)
        .expect("hex seed")
        .into_grants(LiveSigner::SameAsBootstrap)
        .expect("the software backend approves a local signer");
    (Notary::new(notary), BootstrapSigner::new(bootstrap))
}

fn pass() -> Pass<AuditStep> {
    Pass::<AuditStep>::mint(&crate::seal::acquire())
}

/// Link one line per entry of `at` (its `linked_ms`) onto `chain`, units from `unit0`.
fn link_at(chain: &mut AuditChain, unit0: u64, at: &[u64]) -> Vec<AuditRecord> {
    at.iter()
        .enumerate()
        .map(|(i, linked_ms)| {
            let mut inputs = super::sign_tests::rich_inputs(unit0 + i as u64);
            inputs.what.incarnation = 3;
            let line = chain.link(AuditChain::prepare(inputs, NODE), *linked_ms, &pass());
            chain.advance(&line);
            line.into_record()
        })
        .collect()
}

/// `n` link lines of [`NODE`], line `k` linked at `T0 + k`.
fn lines(n: u64) -> (AuditChain, Vec<AuditRecord>) {
    let mut chain = AuditChain::new().sealing_as(NODE);
    let at: Vec<u64> = (1..=n).map(|k| T0 + k).collect();
    let lines = link_at(&mut chain, 1, &at);
    (chain, lines)
}

/// A signed page of `kind` over `page` (oldest first), on `host`, stamped at `stamped_ms`.
fn stamp(page: &[AuditRecord], kind: StampKind, host: &str, stamped_ms: u64) -> Stamp {
    let last = page.last().expect("a page has lines");
    let unsigned = Stamp {
        node: NODE,
        from: page[0].seq,
        to: last.seq,
        fingerprint: Fingerprint::from_hex(&last.hash).expect("a link line's hash"),
        kind,
        sealer: NODE,
        host: host.into(),
        every: 1,
        stamped_ms,
        down_from_ms: 0,
        down_to_ms: 0,
        crypto: String::new(),
        sig_alg: String::new(),
        key_id: String::new(),
        key_cert: 0,
        signature: Vec::new(),
    };
    let (notary, bootstrap) = signers(SEED);
    match kind {
        StampKind::AfterRestart => bootstrap.sign_restart_page(unsigned),
        _ => notary.sign_stamp(unsigned),
    }
    .expect("the test signer signs")
}

/// Journal items: lines and stamps in the order given, WAL `node_seq` counting from 1.
struct Journal(Vec<TailItem>);

impl Journal {
    fn new() -> Self {
        Journal(Vec::new())
    }
    fn next(&self) -> u64 {
        self.0.len() as u64 + 1
    }
    fn lines(mut self, lines: &[AuditRecord]) -> Self {
        for record in lines {
            let node_seq = self.next();
            self.0.push(TailItem::Line {
                record: record.clone(),
                node_seq,
            });
        }
        self
    }
    fn stamp(mut self, stamp: Stamp) -> Self {
        let node_seq = self.next();
        self.0.push(TailItem::Stamp { stamp, node_seq });
        self
    }
    fn undecodable(mut self) -> Self {
        let node_seq = self.next();
        self.0.push(TailItem::Undecodable { node_seq });
        self
    }
    fn seq_of(&self, chain_seq: u64) -> u64 {
        self.0
            .iter()
            .find_map(|item| match item {
                TailItem::Line { record, node_seq } if record.seq == chain_seq => Some(*node_seq),
                _ => None,
            })
            .expect("the line is in the journal")
    }
    fn walk(&self) -> WalkOutcome {
        self.walk_as(HOST, true)
    }
    fn walk_as(&self, host: &str, complete: bool) -> WalkOutcome {
        let key = public();
        walk_tail(
            &self.0,
            &WalkContext {
                node: NODE,
                host,
                key: &key,
                complete,
            },
        )
    }
}

fn expect_break(outcome: WalkOutcome) -> BreakAt {
    match outcome {
        WalkOutcome::Break(at) => at,
        other => panic!("expected a break, got {other:?}"),
    }
}

/// A crash leftover after a live page on this host is one `after_restart` page over exactly the
/// unstamped lines, dated by the last line's `linked_ms`.
#[test]
fn a_clean_tail_after_a_live_page_is_sealed() {
    let (_, all) = lines(10);
    let journal = Journal::new()
        .lines(&all[..6])
        .stamp(stamp(&all[..6], StampKind::Live, HOST, T0 + 7))
        .lines(&all[6..]);
    match journal.walk() {
        WalkOutcome::Clean {
            from,
            to,
            from_node_seq,
            fingerprint,
            to_node_seq,
            every,
            down_from_ms,
        } => {
            assert_eq!((from, to), (7, 10));
            assert_eq!(from_node_seq, journal.seq_of(7));
            assert_eq!(Some(fingerprint), Fingerprint::from_hex(&all[9].hash));
            assert_eq!(to_node_seq, journal.seq_of(10));
            assert_eq!(every, 1);
            assert_eq!(down_from_ms, all[9].linked_ms);
        }
        other => panic!("expected a clean tail, got {other:?}"),
    }
}

/// M == T: a chain whose last page covers its tail needs no signature (after a clean shutdown
/// the final page is the anchor and the walk ends at once).
#[test]
fn a_tail_covered_by_its_last_page_is_nothing() {
    let (_, all) = lines(10);
    for kind in [StampKind::Live, StampKind::Final, StampKind::AfterRestart] {
        let journal = Journal::new()
            .lines(&all)
            .stamp(stamp(&all, kind, HOST, T0 + 11));
        assert_eq!(
            journal.walk(),
            WalkOutcome::Nothing {
                through: 10,
                through_node_seq: journal.seq_of(10),
            },
            "{kind:?}"
        );
    }
}

/// An `after_restart` page from an earlier same-node re-take is a valid anchor (G12 1).
#[test]
fn an_after_restart_anchor_passes() {
    let (_, all) = lines(8);
    let journal = Journal::new()
        .lines(&all[..5])
        .stamp(stamp(&all[..5], StampKind::AfterRestart, HOST, T0 + 6))
        .lines(&all[5..]);
    assert!(matches!(
        journal.walk(),
        WalkOutcome::Clean { from: 6, to: 8, .. }
    ));
}

/// Test 16, `boot_rejects_forged_last_stamp`: lines 1-100, real stamps through 40 and 90, line 50
/// rewritten and 51-100 re-linked, a forged stamp {to 100}. The forged stamp fails its signature,
/// stamp 90 no longer matches its line, stamp 40 is the anchor: a `stamp` break, never a seal.
#[test]
fn a_forged_last_stamp_is_a_stamp_break_from_the_last_genuine_one() {
    let (_, original) = lines(100);
    let s40 = stamp(&original[..40], StampKind::Live, HOST, T0 + 41);
    let s90 = stamp(&original[40..90], StampKind::Live, HOST, T0 + 91);
    let mut rewriter = AuditChain::resume(&original[..49]).sealing_as(NODE);
    let at: Vec<u64> = (50..=100).map(|k| T0 + k).collect();
    let rewritten = link_at(&mut rewriter, 1_000, &at);
    assert_ne!(
        rewritten[0].hash, original[49].hash,
        "line 50 was rewritten"
    );
    let mut forged = stamp(&rewritten[41..], StampKind::Live, HOST, T0 + 101);
    let (other, _) = signers(OTHER_SEED);
    forged = other.sign_stamp(forged).expect("a foreign key signs");
    forged.key_id = key().key_id().to_string();
    let journal = Journal::new()
        .lines(&original[..40])
        .stamp(s40)
        .lines(&original[40..49])
        .lines(&rewritten[..41])
        .stamp(s90)
        .lines(&rewritten[41..])
        .stamp(forged);
    let at = expect_break(journal.walk());
    assert_eq!(at.reason, BreakReason::Stamp);
    assert_eq!(
        (at.last_good, at.unsealed_from, at.unsealed_to),
        (40, 41, 100)
    );
    assert_eq!(at.journal_from, journal.seq_of(41));
    assert_eq!(at.journal_to, journal.seq_of(100));
}

/// Test 23, `unsigned_legacy_tail_is_a_break`: signed legacy lines 1-50, then legacy lines with no
/// signature. The anchor is line 50 (its own signature); line 51 is an `unsigned` break.
#[test]
fn an_unsigned_legacy_tail_is_an_unsigned_break() {
    let mut chain = AuditChain::new().signing_with(key()).sealing_as(NODE);
    let mut legacy: Vec<AuditRecord> = (1..=60)
        .map(|unit| {
            let mut inputs = super::sign_tests::rich_inputs(unit);
            inputs.what.incarnation = 3;
            chain
                .seal_for_journal(inputs, &pass(), |_| Ok::<(), ()>(()))
                .expect("the stage accepts")
                .0
        })
        .collect();
    for line in &mut legacy[50..] {
        line.signature = None;
        line.key_id = None;
    }
    let journal = Journal::new().lines(&legacy);
    let at = expect_break(journal.walk());
    assert_eq!(at.reason, BreakReason::Unsigned);
    assert_eq!((at.last_good, at.unsealed_from), (50, 51));
    assert_eq!(at.journal_from, journal.seq_of(51));
}

/// A legacy prefix written before any key was bound, with no signed line and no stamp, is walked
/// by digest and yields nothing (verify keeps reporting it as today).
#[test]
fn an_unkeyed_legacy_prefix_is_nothing() {
    let mut chain = AuditChain::new().sealing_as(NODE);
    let legacy: Vec<AuditRecord> = (1..=5)
        .map(|unit| {
            chain
                .seal_for_journal(super::sign_tests::rich_inputs(unit), &pass(), |_| {
                    Ok::<(), ()>(())
                })
                .expect("the stage accepts")
                .0
        })
        .collect();
    assert!(legacy.iter().all(|line| line.signature.is_none()));
    assert!(matches!(
        Journal::new().lines(&legacy).walk(),
        WalkOutcome::Nothing { through: 5, .. }
    ));
}

/// Test 4(j): link lines and no stamp at all: an `unanchored` break, no restart page.
#[test]
fn link_lines_with_no_stamp_are_unanchored() {
    let (_, all) = lines(5);
    let at = expect_break(Journal::new().lines(&all).walk());
    assert_eq!(at.reason, BreakReason::Unanchored);
    assert_eq!((at.last_good, at.unsealed_from, at.unsealed_to), (0, 1, 5));
}

/// Lines after a clean-shutdown page: an `after_final` break (a closed chain is never extended).
#[test]
fn lines_after_a_final_page_are_an_after_final_break() {
    let (_, all) = lines(7);
    let journal = Journal::new()
        .lines(&all[..5])
        .stamp(stamp(&all[..5], StampKind::Final, HOST, T0 + 6))
        .lines(&all[5..]);
    let at = expect_break(journal.walk());
    assert_eq!(at.reason, BreakReason::AfterFinal);
    assert_eq!((at.last_good, at.unsealed_from, at.unsealed_to), (5, 6, 7));
}

/// Test 4(f)/(i): an anchor of another host is `Foreign`: nothing is written for it.
#[test]
fn an_anchor_of_another_host_is_foreign() {
    let (_, all) = lines(7);
    let journal = Journal::new()
        .lines(&all[..5])
        .stamp(stamp(&all[..5], StampKind::Live, "host-b", T0 + 6))
        .lines(&all[5..]);
    assert_eq!(
        journal.walk(),
        WalkOutcome::Foreign {
            anchor_host: "host-b".into()
        }
    );
    // A process with no host name never matches a named host, nor the reverse.
    assert!(matches!(
        journal.walk_as("", true),
        WalkOutcome::Foreign { .. }
    ));
}

/// Test 4(k), `idle_gap_then_crash_is_sealed_not_broken`: the notary parks after an idle spell, so
/// the first unstamped line may follow the anchor by any time; only the tail's own span counts.
#[test]
fn an_idle_gap_before_the_tail_is_sealed_not_broken() {
    let mut chain = AuditChain::new().sealing_as(NODE);
    let head = link_at(&mut chain, 1, &[T0 + 1, T0 + 2, T0 + 3]);
    let after_idle = T0 + 3 + 5_000;
    let tail = link_at(&mut chain, 4, &[after_idle, after_idle + 2, after_idle + 4]);
    let journal = Journal::new()
        .lines(&head)
        .stamp(stamp(&head, StampKind::Live, HOST, T0 + 4))
        .lines(&tail);
    assert!(matches!(
        journal.walk(),
        WalkOutcome::Clean { from: 4, to: 6, down_from_ms, .. } if down_from_ms == after_idle + 4
    ));
}

/// Tests 4(l) and 4(m): dates are each line's `linked_ms`, never its arrival `wall`, so a request
/// that arrived 30 s before the anchor and ended after it, or a 5 s and a 1 ms request ending in
/// one tick, are one crash leftover.
#[test]
fn long_and_mixed_duration_requests_are_one_page() {
    let mut chain = AuditChain::new().sealing_as(NODE);
    let head = link_at(&mut chain, 1, &[T0 + 1, T0 + 2]);
    let stamped = T0 + 3;
    let mut long = super::sign_tests::rich_inputs(3);
    long.what.incarnation = 3;
    long.wall = (stamped - 30_000) / 1000;
    let line = chain.link(AuditChain::prepare(long, NODE), stamped + 1, &pass());
    chain.advance(&line);
    let mut tail = vec![line.into_record()];
    tail.extend(link_at(&mut chain, 4, &[stamped + 2]));
    let journal = Journal::new()
        .lines(&head)
        .stamp(stamp(&head, StampKind::Live, HOST, stamped))
        .lines(&tail);
    assert!(matches!(
        journal.walk(),
        WalkOutcome::Clean { from: 3, to: 4, .. }
    ));
}

/// Test 24's tail-span rule: a tail longer than `SPAN`, or one that claims to start well before
/// the page it follows, is a `span` break, never restart-sealed.
#[test]
fn a_tail_longer_than_its_span_is_a_span_break() {
    assert_eq!(span_ms(1), 1_000);
    assert_eq!(span_ms(1_000), 100_000);
    let mut chain = AuditChain::new().sealing_as(NODE);
    let head = link_at(&mut chain, 1, &[T0 + 1, T0 + 2]);
    let tail = link_at(&mut chain, 3, &[T0 + 10, T0 + 10 + 1_001]);
    let journal = Journal::new()
        .lines(&head)
        .stamp(stamp(&head, StampKind::Live, HOST, T0 + 3))
        .lines(&tail);
    let at = expect_break(journal.walk());
    assert_eq!(at.reason, BreakReason::Span);
    assert_eq!((at.last_good, at.unsealed_from, at.unsealed_to), (2, 3, 4));

    let mut chain = AuditChain::new().sealing_as(NODE);
    let head = link_at(&mut chain, 1, &[T0 + 1, T0 + 2]);
    let early = link_at(&mut chain, 3, &[T0 + 3]);
    let journal = Journal::new()
        .lines(&head)
        .stamp(stamp(&head, StampKind::Live, HOST, T0 + 3 + 1_001))
        .lines(&early);
    assert_eq!(expect_break(journal.walk()).reason, BreakReason::Span);
}

/// A link, a digest and an undecodable body after the anchor are each a break at the first
/// failing record, by its WAL position.
#[test]
fn a_damaged_line_after_the_anchor_is_a_break_at_it() {
    let (_, all) = lines(8);
    let anchor = stamp(&all[..4], StampKind::Live, HOST, T0 + 5);

    let mut relinked = all.clone();
    relinked[5].prev_hash = all[3].hash.clone();
    let journal = Journal::new()
        .lines(&relinked[..4])
        .stamp(anchor.clone())
        .lines(&relinked[4..]);
    let at = expect_break(journal.walk());
    assert_eq!((at.reason, at.last_good), (BreakReason::Link, 5));
    assert_eq!(at.journal_from, journal.seq_of(6));

    let mut edited = all.clone();
    edited[6].wall += 1;
    let journal = Journal::new()
        .lines(&edited[..4])
        .stamp(anchor.clone())
        .lines(&edited[4..]);
    assert_eq!(expect_break(journal.walk()).reason, BreakReason::Digest);

    let mut gap = all.clone();
    gap.remove(5);
    let journal = Journal::new()
        .lines(&gap[..4])
        .stamp(anchor.clone())
        .lines(&gap[4..]);
    let at = expect_break(journal.walk());
    assert!(matches!(
        at.reason,
        BreakReason::Link | BreakReason::Sequence
    ));
    assert_eq!(at.last_good, 5);

    let journal = Journal::new()
        .lines(&all[..4])
        .stamp(anchor.clone())
        .lines(&all[4..6])
        .undecodable()
        .lines(&all[6..]);
    let at = expect_break(journal.walk());
    assert_eq!(
        (at.reason, at.last_good, at.unsealed_from),
        (BreakReason::Decode, 6, 7)
    );
    assert_eq!(at.journal_from, journal.seq_of(6) + 1);

    // An undecodable body below the anchor is not re-walked.
    let journal = Journal::new()
        .undecodable()
        .lines(&all[..4])
        .stamp(anchor)
        .lines(&all[4..]);
    assert!(matches!(journal.walk(), WalkOutcome::Clean { from: 5, .. }));
}

/// A backward reader that has not reached the anchor's line yet is told to read more; a stamp
/// in an algorithm this build cannot verify stops the walk with nothing recorded.
#[test]
fn a_partial_read_needs_more_and_an_unknown_algorithm_is_unsupported() {
    let (_, all) = lines(8);
    let anchor = stamp(&all[..4], StampKind::Live, HOST, T0 + 5);
    let partial = Journal::new().stamp(anchor.clone()).lines(&all[4..]);
    assert_eq!(partial.walk_as(HOST, false), WalkOutcome::NeedMore);
    let no_stamp_yet = Journal::new().lines(&all[4..]);
    assert_eq!(no_stamp_yet.walk_as(HOST, false), WalkOutcome::NeedMore);

    let mut odd = anchor;
    odd.sig_alg = "ml-dsa-65".into();
    let journal = Journal::new().lines(&all[..4]).stamp(odd).lines(&all[4..]);
    assert_eq!(journal.walk(), WalkOutcome::Unsupported);
}

/// A stamp signed under a certified notary key (`key_cert` != 0) cannot be resolved by this build
/// (no `notary_key` line exists), so it never anchors a restart page.
#[test]
fn a_certified_key_stamp_never_anchors() {
    let (_, all) = lines(6);
    let mut certified = stamp(&all[..4], StampKind::Live, HOST, T0 + 5);
    certified.key_cert = 3;
    let (notary, _) = signers(SEED);
    let certified = notary.sign_stamp(certified).expect("signs");
    let journal = Journal::new()
        .lines(&all[..4])
        .stamp(certified)
        .lines(&all[4..]);
    let at = expect_break(journal.walk());
    assert_eq!((at.reason, at.last_good), (BreakReason::Stamp, 0));
}
