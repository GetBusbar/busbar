// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/audit/mod.rs` — THE ONE HASH CHAIN.
//!
//! Two jobs, and the second is the one that makes the unification worth doing:
//!
//! 1. **THE FOUR TAMPERS.** A chain whose links are never recomputed proves nothing, because nobody
//!    ever finds out that it does not verify. So alteration, reordering, insertion and deletion are
//!    each produced HERE, by actually performing one, and the verifier is required to name it. These
//!    ran RED first against a verifier with the corresponding check removed — a chain that cannot be
//!    watched to catch a deletion is not tamper-evidence.
//!
//! 2. **THE SEAM.** `A FOURTH STREAM COSTS A RECORD TYPE AND NOTHING ELSE` is the acceptance test
//!    for this design, so this file declares a throwaway fourth record type ([`Nonsense`]) that
//!    exists nowhere else in the tree and shows it chains, verifies and reports every one of the
//!    four tampers with NO new mechanism: no chain, no digest, no verifier, no error type.
//!
//! 3. **THE DIGESTS OF THE THREE REAL STREAMS DID NOT MOVE.** The three record types were already
//!    hash-chained on disk before this unification, and `busbar_api`'s store contract publishes
//!    their formulas. A digest that changed would make every existing deployment's chain fail to
//!    verify at the next boot — that is, report its own history as TAMPERED. The three golden
//!    vectors below recompute each formula independently, the old way, and require the new
//!    mechanism to agree byte for byte.

use super::*;

use busbar_api::{McpCallRecord, TaskEventRow};

use crate::a2a::provenance::EventInput;
use crate::admin::audit::{AuditEntry, AuditInput};
use crate::plane::calllog::CallInput;

// ══ THE FOURTH STREAM ════════════════════════════════════════════════════════════════════════════
//
// A record type that exists ONLY in this file, for a stream busbar does not have. It is deliberately
// unlike the three real ones — a different scope noun, different field types, a field the digest
// covers and a field it does not — so that "a fourth plane costs a record type" is demonstrated
// rather than assumed from a copy of an existing one.
//
// EVERYTHING BELOW IS THE WHOLE COST. There is no chain type, no `compute_hash`, no `verify_chain`,
// no `ChainBreak` and no `Display` for one. If a future stream needs any of those, the seam failed.

/// A throwaway fourth record: "widget `w` did `what` under tenant `t`".
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nonsense {
    tenant: String,
    seq: u64,
    what: String,
    amount: u64,
    /// A join key, EXCLUDED from the digest exactly as the three real streams exclude `request_id`.
    trace: String,
    prev_hash: String,
    hash: String,
}

/// The payload a caller of the fourth stream supplies. No `seq`, no `prev_hash`, no `hash`.
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

const TENANT: &str = "tenant-1";

fn nonsense_input(what: &str, amount: u64) -> NonsenseInput {
    NonsenseInput {
        what: what.to_string(),
        amount,
        trace: "trace-1".to_string(),
    }
}

/// A three-record chain of the fourth stream, built with nothing but [`Chain`].
fn a_chain() -> Vec<Nonsense> {
    let mut chain: Chain<Nonsense> = Chain::new();
    vec![
        chain.append(TENANT, nonsense_input("created", 1)),
        chain.append(TENANT, nonsense_input("updated", 2)),
        chain.append(TENANT, nonsense_input("deleted", 3)),
    ]
}

// ══ THE SEAM ═════════════════════════════════════════════════════════════════════════════════════

/// THE ACCEPTANCE TEST FOR THE WHOLE DESIGN: a stream that did not exist five minutes ago chains,
/// links, digests and verifies, and the only thing written for it was the record type above.
#[test]
fn a_fourth_stream_costs_a_record_type_and_nothing_else() {
    let records = a_chain();
    assert_eq!(records[0].seq, 1, "a chain with nothing in it starts at 1");
    assert_eq!(records[1].seq, 2);
    assert_eq!(records[2].seq, 3);
    assert_eq!(
        records[0].prev_hash, "",
        "the first record has no predecessor"
    );
    assert_eq!(records[1].prev_hash, records[0].hash);
    assert_eq!(records[2].prev_hash, records[1].hash);
    assert!(
        records.iter().all(|r| r.hash.len() == 64),
        "every digest is a full sha256 hex string"
    );
    assert_eq!(verify_chain(&records), Ok(()));
}

/// The fourth stream inherits the RESUME too: a restart continues the same chain rather than opening
/// a second one under the same scope — two chains that each verify and together describe nothing.
#[test]
fn a_fourth_stream_inherits_resume_and_refuses_to_launder_a_broken_tail() {
    let persisted = a_chain();
    let mut resumed =
        Chain::<Nonsense>::from_persisted(&persisted).expect("an intact chain resumes");
    assert_eq!(resumed.next_seq(), 4);
    let next = resumed.append(TENANT, nonsense_input("rehydrated", 4));
    assert_eq!(next.seq, 4);
    assert_eq!(next.prev_hash, persisted[2].hash);

    let mut broken = persisted;
    broken[0].what = "forged".to_string();
    Chain::<Nonsense>::from_persisted(&broken).expect_err("resume must verify before it trusts");
    // The unverified variant exists for the tamper-detected path, and it positions on the tail so
    // evidence CONTINUES rather than silently stopping the moment somebody corrupts one row.
    assert_eq!(
        Chain::<Nonsense>::from_persisted_unverified(&broken).next_seq(),
        4
    );
}

// ══ THE FOUR TAMPERS, on the fourth stream ═══════════════════════════════════════════════════════

/// TAMPER 1 — ALTERATION. Edit one record's fields in place. The single most important assertion in
/// this file: a chain that does not detect this is decoration.
#[test]
fn altering_a_record_in_place_is_detected_and_located() {
    let mut records = a_chain();
    let stored_hash = records[1].hash.clone();
    records[1].amount = 999;

    let brk = verify_chain(&records).expect_err("an edited record must break the chain");
    assert_eq!(brk.at_index, 2, "the break is located at the edited record");
    assert_eq!(brk.seq, 2);
    assert_eq!(brk.scope, TENANT);
    match &brk.kind {
        ChainBreakKind::DigestMismatch { stored, recomputed } => {
            assert_eq!(stored, &stored_hash, "the stored digest is the old one");
            assert_ne!(
                recomputed, stored,
                "the recomputed digest reflects the edit"
            );
        }
        other => panic!("expected a digest mismatch, got {other:?}"),
    }
    assert!(
        brk.to_string().contains("EDITED"),
        "the operator-facing message names what happened: {brk}"
    );
    assert!(
        brk.to_string().contains("the nonsense chain"),
        "and names WHICH log to go and look at: {brk}"
    );
}

/// TAMPER 2 — DELETION. Remove a record from the middle. Reported as a SEQUENCE break, which names
/// the real defect ("something is missing") rather than blaming the innocent successor.
#[test]
fn deleting_a_record_from_the_middle_is_detected() {
    let mut records = a_chain();
    records.remove(1);
    let brk = verify_chain(&records).expect_err("a deletion must break the chain");
    assert_eq!(brk.at_index, 2);
    assert_eq!(
        brk.kind,
        ChainBreakKind::SequenceBreak {
            expected: 2,
            found: 3
        }
    );
    assert!(brk.to_string().contains("REMOVED"), "{brk}");
}

/// TAMPER 3 — REORDERING. Swapping two records leaves every digest individually valid, which is
/// exactly why the position and the link are checked and not just the digests.
#[test]
fn reordering_two_records_is_detected() {
    let mut records = a_chain();
    records.swap(1, 2);
    let brk = verify_chain(&records).expect_err("a reorder must break the chain");
    assert_eq!(
        brk.kind,
        ChainBreakKind::SequenceBreak {
            expected: 2,
            found: 3
        }
    );
}

/// TAMPER 4 — INSERTION of a forgery that carries the right sequence number AND a correct digest
/// over its own fields. The forger controls everything except the predecessor's hash, and that is
/// what the link check catches.
#[test]
fn inserting_a_self_consistent_forgery_is_detected_by_its_link() {
    let records = a_chain();
    // Build the forgery on a chain of its own so its digest is internally valid. The rogue chain's
    // seed differs from the real one, which models the forger's actual position: it can produce a
    // self-consistent record, but it does not hold the real predecessor's digest. Where it DOES — a
    // host compromised deeply enough to replay the whole chain — this verifies, and that limit is
    // stated in the module doc rather than tested around.
    let mut rogue: Chain<Nonsense> = Chain::new();
    let _ = rogue.append(TENANT, nonsense_input("something-else", 77));
    let forged = rogue.append(TENANT, nonsense_input("updated", 2));
    assert_eq!(forged.seq, 2, "the forgery claims the right sequence");
    assert_eq!(
        digest(&forged),
        forged.hash,
        "and its own digest is self-consistent, so only the LINK can catch it"
    );

    let spliced = vec![records[0].clone(), forged.clone(), records[2].clone()];
    let brk = verify_chain(&spliced).expect_err("a spliced record must break the chain");
    assert_eq!(brk.at_index, 2);
    match &brk.kind {
        ChainBreakKind::LinkMismatch { expected, found } => {
            assert_eq!(expected, &records[0].hash);
            assert_eq!(found, &forged.prev_hash);
        }
        other => panic!("expected a link mismatch, got {other:?}"),
    }
    assert!(brk.to_string().contains("INSERTED"), "{brk}");
}

/// THE STREAMS STAY SEPARATE. One mechanism does not mean one chain: a record from another scope
/// appearing in this one is refused outright, so one caller's evidence can never be made to depend
/// on another caller's rows. store-mysql had a real cross-principal read defect of this exact shape.
#[test]
fn a_foreign_scopes_record_cannot_hide_inside_this_chain() {
    let mut records = a_chain();
    records[1].tenant = "tenant-2".to_string();
    let brk = verify_chain(&records).expect_err("a foreign scope's record must be refused");
    assert_eq!(
        brk.kind,
        ChainBreakKind::ForeignScope {
            expected: TENANT.to_string(),
            found: "tenant-2".to_string()
        }
    );
    assert!(
        brk.to_string().contains("tenant `tenant-2`"),
        "the message uses the RECORD TYPE's own scope noun, not a hardcoded one: {brk}"
    );
}

/// TRUNCATING THE TAIL is the one tamper a chain cannot catch alone: every remaining link is still
/// correct. Stated rather than papered over — what closes it is whoever holds the other half (the
/// store's principal enumeration, the task row's terminal state).
#[test]
fn truncating_the_tail_verifies_and_that_limit_is_deliberate() {
    let mut records = a_chain();
    records.pop();
    assert_eq!(verify_chain(&records), Ok(()));
    assert_eq!(records.last().unwrap().what, "updated");
}

/// An EMPTY chain verifies, and that is a stated limit rather than a loophole: "no records" and
/// "every record deleted" are indistinguishable from the records alone.
#[test]
fn an_empty_chain_verifies_and_the_limit_is_deliberate() {
    assert_eq!(verify_chain::<Nonsense>(&[]), Ok(()));
}

/// The digest covers what it claims to cover, and the JOIN KEY is deliberately outside it.
#[test]
fn the_digest_covers_the_chained_fields_and_excludes_the_join_key() {
    let records = a_chain();
    let rec = records[1].clone();

    for (field, perturb) in [
        (
            "prev_hash",
            Box::new(|r: &mut Nonsense| r.prev_hash.push('x')) as Box<dyn Fn(&mut Nonsense)>,
        ),
        ("tenant", Box::new(|r: &mut Nonsense| r.tenant.push('x'))),
        ("seq", Box::new(|r: &mut Nonsense| r.seq += 1)),
        ("what", Box::new(|r: &mut Nonsense| r.what.push('x'))),
        ("amount", Box::new(|r: &mut Nonsense| r.amount += 1)),
    ] {
        let mut m = rec.clone();
        perturb(&mut m);
        assert_ne!(
            digest(&m),
            rec.hash,
            "`{field}` is a chained field: changing it must change the digest"
        );
    }

    let mut join_only = rec.clone();
    join_only.trace = "a-completely-different-trace".to_string();
    assert_eq!(
        digest(&join_only),
        rec.hash,
        "a join key is not a chained field: a missing one must not make an intact chain unverifiable"
    );
}

// ══ THE WINDOW: a bounded ring is a chain with its head pruned ═══════════════════════════════════

/// The admin ring keeps the most recent `MAX_AUDIT_ENTRIES` and the durable store keeps the rest, so
/// the oldest retained record's predecessor is legitimately gone. [`verify_window`] takes that first
/// position as given and checks everything after it in full — while [`verify_chain`] on the same
/// slice REFUSES it, which is what stops a caller holding a whole chain from silently excusing a
/// missing head.
#[test]
fn a_window_verifies_from_a_pruned_head_while_a_whole_chain_does_not() {
    let records = a_chain();
    let window = &records[1..];
    assert_eq!(verify_window(window), Ok(()));
    let brk = verify_chain(window).expect_err("a whole-chain walk must refuse a pruned head");
    assert_eq!(
        brk.kind,
        ChainBreakKind::SequenceBreak {
            expected: 1,
            found: 2
        },
        "the whole-chain walk requires the genesis it was handed a window of"
    );
}

/// A WINDOW IS NOT A WEAKER CHECK past its first record: every tamper inside it is still caught.
#[test]
fn a_window_still_catches_a_tamper_after_its_first_record() {
    let mut records = a_chain();
    records[2].amount = 4242;
    let brk = verify_window(&records[1..]).expect_err("a window still verifies what it holds");
    assert_eq!(brk.at_index, 2);
    assert!(matches!(brk.kind, ChainBreakKind::DigestMismatch { .. }));
}

// ══ THE POSITION ════════════════════════════════════════════════════════════════════════════════

/// `Chain::default()` MUST equal `Chain::new()`. A derived `Default` gives `next_seq: 0`, which is
/// not a valid sequence, and it is exactly what a clippy suggestion to replace
/// `or_insert_with(Chain::new)` with `or_default()` once produced on the MCP call log. There is now
/// ONE `Default` for every stream, so this pins the hazard for all of them at once.
#[test]
fn the_default_chain_is_the_new_chain_because_a_derived_default_starts_at_zero() {
    assert_eq!(Chain::<Nonsense>::default(), Chain::<Nonsense>::new());
    assert_eq!(Chain::<Nonsense>::default().next_seq(), 1);
    // And the claim holds for the real streams too, on the same one implementation.
    assert_eq!(Chain::<McpCallRecord>::default().next_seq(), 1);
    assert_eq!(Chain::<TaskEventRow>::default().next_seq(), 1);
}

// ══ THE THREE REAL DIGESTS DID NOT MOVE ═════════════════════════════════════════════════════════

/// The MCP per-call digest is byte-for-byte what `mcp/calllog.rs` computed before the unification:
/// length-prefixed, in this field order. Recomputed here the OLD way and required to agree.
#[test]
fn the_mcp_call_digest_is_unchanged_by_the_unification() {
    let mut chain: Chain<McpCallRecord> = Chain::new();
    let rec = chain.append(
        "vk_alice",
        CallInput {
            ts: 1_700_000_000,
            server: "srv".to_string(),
            tool: "srv_tool".to_string(),
            outcome: crate::audit::vocab::OUTCOME_DISPATCHED,
            reason: String::new(),
            tool_digest: "abc123".to_string(),
            pin_generation: 7,
            request_id: "req-1".to_string(),
        },
    );

    let mut buf: Vec<u8> = Vec::new();
    let mut field = |bytes: &[u8]| {
        buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        buf.extend_from_slice(bytes);
    };
    field(rec.prev_hash.as_bytes());
    field(rec.principal.as_bytes());
    field(&rec.seq.to_be_bytes());
    field(&rec.ts.to_be_bytes());
    field(rec.server.as_bytes());
    field(rec.tool.as_bytes());
    field(rec.outcome.as_bytes());
    field(rec.reason.as_bytes());
    field(rec.tool_digest.as_bytes());
    field(&rec.pin_generation.to_be_bytes());
    assert_eq!(
        rec.hash,
        busbar_api::sha256_hex(&buf),
        "an MCP call digest that moved would report every deployment's persisted chain as tampered"
    );
}

/// The A2A task provenance digest is byte-for-byte what `a2a/provenance.rs` computed before the
/// unification, and byte-for-byte the formula `busbar_api::TaskEventRow` publishes.
#[test]
fn the_a2a_task_event_digest_is_unchanged_by_the_unification() {
    let mut chain: Chain<TaskEventRow> = Chain::new();
    let row = chain.append(
        "task-1",
        EventInput {
            kind: crate::a2a::provenance::EV_SUBMITTED,
            context_id: "ctx-1".to_string(),
            principal: "vk_alice".to_string(),
            agent_id: "planner".to_string(),
            state: "submitted".to_string(),
            request_id: "req-1".to_string(),
            ts: 1_700_000_000,
        },
    );
    let canonical = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}",
        row.prev_hash,
        row.task_id,
        row.seq,
        row.ts,
        row.kind,
        row.context_id,
        row.principal,
        row.agent_id,
        row.state
    );
    assert_eq!(
        row.hash,
        busbar_api::sha256_hex(canonical.as_bytes()),
        "an A2A provenance digest that moved would report every persisted chain as tampered"
    );
}

/// The admin audit digest is byte-for-byte what `admin/audit.rs` computed before the unification,
/// and byte-for-byte the formula `busbar_api::AuditRecord` publishes.
#[test]
fn the_admin_audit_digest_is_unchanged_by_the_unification() {
    let entry: AuditEntry = seal(
        "admin",
        4,
        "deadbeef".to_string(),
        AuditInput {
            ts: 1_700_000_000,
            action: "hook.register".to_string(),
            resource: "hook:compress".to_string(),
            outcome: crate::audit::vocab::OUTCOME_APPLIED.to_string(),
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
        busbar_api::sha256_hex(canonical.as_bytes()),
        "an admin audit digest that moved would report every persisted chain as tampered"
    );
}

/// THE FRAMING IS THE OTHER HALF OF THE DIGEST, and the two are not interchangeable. Length prefixes
/// make the split between fields unforgeable: two records whose fields differ only in WHERE the
/// boundary falls collide under a separator join and do not under a length prefix. This is why a new
/// record type takes `LengthPrefixed` and why the two legacy streams keep theirs only because their
/// rows are already on disk.
#[test]
fn length_prefixing_makes_the_field_split_unforgeable_where_a_separator_does_not() {
    let mut pipe_a = Digest::new(Framing::PipeSeparated);
    pipe_a.text("ab").text("c");
    let mut pipe_b = Digest::new(Framing::PipeSeparated);
    pipe_b.text("ab|c");
    assert_eq!(
        pipe_a.finish(),
        pipe_b.finish(),
        "a separator join is forgeable by a field that contains the separator"
    );

    let mut lp_a = Digest::new(Framing::LengthPrefixed);
    lp_a.text("ab").text("c");
    let mut lp_b = Digest::new(Framing::LengthPrefixed);
    lp_b.text("ab|c");
    assert_ne!(
        lp_a.finish(),
        lp_b.finish(),
        "length prefixes make the same shift a different byte stream"
    );
}
