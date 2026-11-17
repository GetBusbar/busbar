// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Shared Store v4 conformance cases for the slot-row commit rule
//! (STORE-TRANSACTIONS §2.5, §8). Every store's suite runs these through its real
//! host-side backend, so the behaviour is checked in any spelling (Rust, SQL, Lua).
//!
//! Each case takes a fresh [`Subject`] over an empty dataset. Slotted keys are minted
//! with the test-only [`SlotSeal`]; this module exists only under `test-seal`.

use std::sync::Arc;

use crate::caps::SlotSeal;
use crate::persistence::{
    control, Address, AttemptId, Candidate, CommitKey, Decision, ExpectedValue, Mutation,
    PersistenceBackend, Predicate, PreparedCandidate, Read, ReadResult, SelfFenced,
    CANDIDATE_VERSION, MAX_SLOTS,
};
use crate::Secret;

/// The writer's peak concurrency (leased slots) in the shared [`no_growth`] case.
pub const NO_GROWTH_PEAK: u32 = 64;
/// Full slot cycles the shared [`no_growth`] case runs: half before the clock jump, half after.
pub const NO_GROWTH_CYCLES: usize = 64;
/// Commits per writer in the shared [`no_growth`] case (8.10): [`NO_GROWTH_CYCLES`] full cycles of
/// [`NO_GROWTH_PEAK`] slots, 4,096 commits.
///
/// The property is "a writer's slot rows never exceed its peak", and the row bound decides it, not
/// the count: [`no_growth`] asserts the bound after every full cycle, so a store that keeps more
/// than one row per (writer, slot) fails at the end of its second cycle, a store that compacts only
/// every N commits fails at the first cycle boundary its backlog shows at, and one that holds rows
/// for a retention window fails long before the +48 h jump. Thirty-two cycles on each side of the
/// jump give every slot many leases with ever larger sequences under both clocks.
///
/// What the old 1,000,000 count guarded implicitly is now its own case: a counter that misbehaves
/// only at a width boundary is [`counter_wrap`]'s (seeded at each boundary, committed across it),
/// and growth that shows only over a long horizon is [`LONG_HORIZON_COMMITS`], run in core against
/// the in-memory store, where a million commits take seconds. Against a real database a million
/// commits take hours (9 to 25 ms a durable commit), so every store's CI runs this count unchanged.
pub const NO_GROWTH_COMMITS: usize = NO_GROWTH_CYCLES * NO_GROWTH_PEAK as usize;
/// Commits in the long-horizon [`no_growth`] run core makes against its in-memory store
/// (2^20, at [`NO_GROWTH_PEAK`]): every slot leased 16,384 times, the bound asserted at each cycle.
pub const LONG_HORIZON_COMMITS: usize = 1 << 20;
/// The lease sequences [`counter_wrap`] commits at, ascending: each side of every signed and
/// unsigned 32- and 64-bit boundary a store could hold a sequence in, up to `u64::MAX`.
pub const WRAP_SEQS: [u64; 8] = [
    0x7fff_ffff,
    0x8000_0000,
    0xffff_ffff,
    0x1_0000_0000,
    0x7fff_ffff_ffff_ffff,
    0x8000_0000_0000_0000,
    u64::MAX - 1,
    u64::MAX,
];
/// The slots [`counter_wrap`] commits on: each side of the signed 16-bit boundary, and the last
/// slot the contract admits (`MAX_SLOTS - 1`).
pub const WRAP_SLOTS: [u32; 3] = [0x7fff, 0x8000, MAX_SLOTS - 1];
/// The store-clock jump [`no_growth`] applies between its two halves (8.10).
pub const CLOCK_JUMP_SECS: u64 = 48 * 60 * 60;

/// One store instance under test, over an empty dataset.
pub trait Subject {
    /// The real host-side backend.
    fn backend(&self) -> &dyn PersistenceBackend;
    /// Slot rows the store holds for `writer`, read natively.
    fn slot_rows(&self, writer: [u8; 16]) -> usize;
    /// Move the store's authoritative clock forward. `false` when the store's clock
    /// is an external server's that a test cannot move; the case still runs.
    fn jump_clock(&self, seconds: u64) -> bool;
}

const NS: [u8; 16] = *b"conformance.v1\0\0";
const REGISTRAR: [u8; 16] = [0xA1; 16];

fn seal() -> SlotSeal {
    SlotSeal::acquire_for_tests()
}

/// A slotted key; panics on an invalid pair (a case bug).
#[must_use]
pub fn slot(slot: u32, seq: u64) -> CommitKey {
    CommitKey::slotted(slot, seq, &seal()).expect("valid conformance slot")
}

fn self_key(candidate: &PreparedCandidate) -> CommitKey {
    CommitKey::self_fenced(
        &SelfFenced::check(candidate).expect("self-fenced conformance candidate"),
    )
}

fn op(n: u64) -> [u8; 16] {
    let mut id = [0; 16];
    id[..8].copy_from_slice(&n.to_le_bytes());
    id[15] = 0x5C;
    id
}

fn at(key: &[u8]) -> Address {
    Address {
        namespace: NS,
        key: key.to_vec(),
    }
}

fn writer_at(writer: [u8; 16]) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::writer_key(writer).to_vec(),
    }
}

fn open() -> control::Writer {
    control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
}

fn candidate(
    backend: &dyn PersistenceBackend,
    writer: [u8; 16],
    operation: [u8; 16],
    predicates: Vec<Predicate>,
    mutations: Vec<Mutation>,
) -> PreparedCandidate {
    PreparedCandidate::new(Candidate {
        id: AttemptId {
            dataset: backend.info().dataset,
            writer_epoch: 1,
            writer,
            execution_epoch: 1,
            operation,
        },
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    })
    .expect("valid conformance candidate")
}

fn put(key: &[u8], value: &[u8]) -> Mutation {
    Mutation::Put {
        address: at(key),
        value: Secret::new(value.to_vec()),
    }
}

/// The initialization candidate for an empty dataset, registering `writer`.
#[must_use]
pub fn initialization(
    backend: &dyn PersistenceBackend,
    writer: [u8; 16],
    operation: u64,
) -> PreparedCandidate {
    let root = Address {
        namespace: control::NAMESPACE.0,
        key: control::DATASET_KEY.to_vec(),
    };
    let dataset = control::Dataset {
        id: backend.info().dataset,
        writer_epoch: 1,
    };
    let mut mutations = vec![Mutation::Put {
        address: root.clone(),
        value: Secret::new(dataset.encode().expect("root").to_vec()),
    }];
    mutations.extend(control::writer_put(writer, None, open()).expect("initial writer effects"));
    candidate(
        backend,
        writer,
        op(operation),
        vec![
            Predicate {
                address: root.clone(),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: writer_at(writer),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: control::epoch_row(writer, 1),
                expected: ExpectedValue::Absent,
            },
        ],
        mutations,
    )
}

fn closure(
    backend: &dyn PersistenceBackend,
    writer: [u8; 16],
    operation: u64,
) -> PreparedCandidate {
    let closed = control::Writer {
        retired_through: 1,
        admitted_through: 1,
    };
    candidate(
        backend,
        writer,
        op(operation),
        vec![Predicate {
            address: writer_at(writer),
            expected: ExpectedValue::Exact(Secret::new(open().encode().expect("open").to_vec())),
        }],
        vec![Mutation::Put {
            address: writer_at(writer),
            value: Secret::new(closed.encode().expect("closed").to_vec()),
        }],
    )
}

async fn commit(
    backend: &dyn PersistenceBackend,
    c: &PreparedCandidate,
    key: CommitKey,
) -> Decision {
    backend
        .commit(c.clone(), key)
        .await
        .expect("a definitive conformance answer")
}

async fn bootstrap(backend: &dyn PersistenceBackend) {
    let init = initialization(backend, REGISTRAR, 1);
    assert!(
        matches!(
            commit(backend, &init, self_key(&init)).await,
            Decision::Applied(_)
        ),
        "an empty dataset accepts its initialization"
    );
}

async fn value(backend: &dyn PersistenceBackend, address: Address) -> Option<Vec<u8>> {
    let read = backend
        .read(Arc::new(Read {
            dataset: backend.info().dataset,
            addresses: vec![address],
            time: None,
        }))
        .await
        .expect("conformance read");
    match read {
        ReadResult::Values { mut values, .. } => {
            values.pop().flatten().map(|secret| secret.0.clone())
        }
        ReadResult::TimeGuardFailed { .. } => panic!("unguarded read failed its guard"),
    }
}

/// 8.1 A detached original that lands after its slot was reused gets STALE and
/// writes nothing; the op counts once and the slot's next op stays intact.
pub async fn detached_original_after_reuse(subject: &impl Subject) {
    let b = subject.backend();
    bootstrap(b).await;
    let a = candidate(b, REGISTRAR, op(10), vec![], vec![put(b"counter", b"a")]);
    // A's first send is held (never reached the store); its retry applies.
    assert!(matches!(
        commit(b, &a, slot(3, 7)).await,
        Decision::Applied(_)
    ));
    let next = candidate(b, REGISTRAR, op(11), vec![], vec![put(b"counter", b"b")]);
    assert!(matches!(
        commit(b, &next, slot(3, 8)).await,
        Decision::Applied(_)
    ));
    // The held original is released now.
    assert!(matches!(commit(b, &a, slot(3, 7)).await, Decision::Stale));
    assert_eq!(value(b, at(b"counter")).await.as_deref(), Some(&b"b"[..]));
}

/// 8.2 A lost reply on a self-fenced Initialize that applied: its own registrar is
/// admitted, so the retry passes the fence and fails the root `Absent` predicate
/// (CONDITION_CONFLICT, §2.5 steps 4-5), never a fresh apply or a refusal. The host
/// readback then finds its writer row and resolves Applied. A peer's Initialize is
/// FENCED instead (`initialize_race_lost_reply`).
pub async fn initialize_lost_reply(subject: &impl Subject) {
    let b = subject.backend();
    let init = initialization(b, REGISTRAR, 1);
    assert!(matches!(
        commit(b, &init, self_key(&init)).await,
        Decision::Applied(_)
    ));
    assert!(matches!(
        commit(b, &init, self_key(&init)).await,
        Decision::ConditionConflict
    ));
}

/// 8.2b Racing initializers: the loser's Initialize answers FENCED, as an evaluated
/// answer, and the winner's writer row is unchanged.
pub async fn initialize_race_lost_reply(subject: &impl Subject) {
    let b = subject.backend();
    let winner = initialization(b, [0xB1; 16], 1);
    let loser = initialization(b, [0xB2; 16], 2);
    assert!(matches!(
        commit(b, &winner, self_key(&winner)).await,
        Decision::Applied(_)
    ));
    let before = value(b, writer_at([0xB1; 16])).await;
    for _ in 0..2 {
        assert!(matches!(
            commit(b, &loser, self_key(&loser)).await,
            Decision::Fenced
        ));
    }
    assert_eq!(value(b, writer_at([0xB1; 16])).await, before);
    assert_eq!(value(b, writer_at([0xB2; 16])).await, None);
}

/// 8.2c Racing first-start Register: the loser answers CONDITION_CONFLICT and the
/// winner's writer row stays open.
pub async fn register_race(subject: &impl Subject) {
    let b = subject.backend();
    bootstrap(b).await;
    let seed = candidate(
        b,
        REGISTRAR,
        op(20),
        vec![],
        vec![put(b"birth", b"pending")],
    );
    assert!(matches!(
        commit(b, &seed, slot(0, 1)).await,
        Decision::Applied(_)
    ));
    let register = |writer: [u8; 16], n: u64| {
        candidate(
            b,
            REGISTRAR,
            op(n),
            vec![
                Predicate {
                    address: writer_at(writer),
                    expected: ExpectedValue::Absent,
                },
                Predicate {
                    address: at(b"birth"),
                    expected: ExpectedValue::Exact(Secret::new(b"pending".to_vec())),
                },
            ],
            vec![
                Mutation::Put {
                    address: writer_at(writer),
                    value: Secret::new(open().encode().expect("open").to_vec()),
                },
                put(b"birth", &writer),
            ],
        )
    };
    let winner = register([0xC1; 16], 21);
    let loser = register([0xC2; 16], 22);
    assert!(matches!(
        commit(b, &winner, self_key(&winner)).await,
        Decision::Applied(_)
    ));
    assert!(matches!(
        commit(b, &loser, self_key(&loser)).await,
        Decision::ConditionConflict
    ));
    assert_eq!(
        value(b, writer_at([0xC1; 16])).await.as_deref(),
        Some(&open().encode().expect("open")[..])
    );
    assert_eq!(value(b, writer_at([0xC2; 16])).await, None);
}

/// 8.3 Identical resends replay (one effect, including a concurrent race); a
/// recorded conflict replays even after its predicate would hold; a different body
/// at the same (slot, seq) is OPID_CONFLICT.
pub async fn duplicate_and_conflict_replay(subject: &impl Subject) {
    let b = subject.backend();
    bootstrap(b).await;
    let first = candidate(
        b,
        REGISTRAR,
        op(30),
        vec![Predicate {
            address: at(b"once"),
            expected: ExpectedValue::Absent,
        }],
        vec![put(b"once", b"1")],
    );
    assert!(matches!(
        commit(b, &first, slot(1, 1)).await,
        Decision::Applied(_)
    ));
    assert!(matches!(
        commit(b, &first, slot(1, 1)).await,
        Decision::Applied(_)
    ));
    assert_eq!(value(b, at(b"once")).await.as_deref(), Some(&b"1"[..]));
    let raced = candidate(
        b,
        REGISTRAR,
        op(31),
        vec![Predicate {
            address: at(b"race"),
            expected: ExpectedValue::Absent,
        }],
        vec![put(b"race", b"1")],
    );
    let (left, right) = futures::join!(
        b.commit(raced.clone(), slot(2, 1)),
        b.commit(raced.clone(), slot(2, 1))
    );
    for answer in [left, right] {
        // A first-use deadlock may abort one side as unknown; its retry replays.
        let answer = match answer {
            Ok(decision) => decision,
            Err(_) => commit(b, &raced, slot(2, 1)).await,
        };
        assert!(
            matches!(answer, Decision::Applied(_)),
            "both sides see one effect"
        );
    }
    // A conflict is recorded and replays even once its predicate holds again.
    let guarded = candidate(
        b,
        REGISTRAR,
        op(32),
        vec![Predicate {
            address: at(b"once"),
            expected: ExpectedValue::Absent,
        }],
        vec![put(b"after", b"1")],
    );
    assert!(matches!(
        commit(b, &guarded, slot(4, 1)).await,
        Decision::ConditionConflict
    ));
    let clear = candidate(
        b,
        REGISTRAR,
        op(33),
        vec![],
        vec![Mutation::Delete(at(b"once"))],
    );
    assert!(matches!(
        commit(b, &clear, slot(5, 1)).await,
        Decision::Applied(_)
    ));
    assert!(matches!(
        commit(b, &guarded, slot(4, 1)).await,
        Decision::ConditionConflict
    ));
    assert_eq!(value(b, at(b"after")).await, None);
    let other = candidate(b, REGISTRAR, op(34), vec![], vec![put(b"other", b"1")]);
    assert!(matches!(
        commit(b, &other, slot(4, 1)).await,
        Decision::OpIdConflict
    ));
    assert_eq!(value(b, at(b"other")).await, None);
}

/// 8.4 A slotted op applied, its writer was closed (rows deleted), and its retry
/// is FENCED without applying again.
pub async fn zombie_fenced_in_doubt(subject: &impl Subject) {
    let b = subject.backend();
    bootstrap(b).await;
    let x = candidate(b, REGISTRAR, op(40), vec![], vec![put(b"zombie", b"1")]);
    assert!(matches!(
        commit(b, &x, slot(6, 1)).await,
        Decision::Applied(_)
    ));
    let close = closure(b, REGISTRAR, 41);
    assert!(matches!(
        commit(b, &close, self_key(&close)).await,
        Decision::Applied(_)
    ));
    assert_eq!(
        subject.slot_rows(REGISTRAR),
        0,
        "closure deletes the writer's rows"
    );
    assert!(matches!(commit(b, &x, slot(6, 1)).await, Decision::Fenced));
}

/// 8.10 No growth: `commits` slotted commits over `peak` slots, with a +48 h store clock
/// jump halfway, never leave more than `peak` rows for the writer. The bound is asserted
/// after every full cycle of `peak` commits and at the end, so storage that
/// grows with commits is caught while it grows, not only if it is still grown at the end.
/// `commits` must cover at least one full cycle on each side of the jump (the shared case
/// is [`NO_GROWTH_COMMITS`] at [`NO_GROWTH_PEAK`]). Returns whether the store's clock could
/// be moved.
pub async fn no_growth(subject: &impl Subject, commits: usize, peak: u32) -> bool {
    assert!(peak > 0 && peak <= MAX_SLOTS);
    let cycle = peak as usize;
    assert!(
        commits >= 2 * cycle,
        "{commits} commits do not cycle {peak} slots on both sides of the clock jump"
    );
    let bounded = |after: usize| {
        let rows = subject.slot_rows(REGISTRAR);
        assert!(
            rows <= cycle,
            "{rows} slot rows for a peak of {peak} after {after} commits"
        );
    };
    let b = subject.backend();
    bootstrap(b).await;
    let mut jumped = false;
    for n in 0..commits {
        if n > 0 && n.is_multiple_of(cycle) {
            bounded(n);
        }
        if n == commits / 2 {
            jumped = subject.jump_clock(CLOCK_JUMP_SECS);
        }
        let seq = n as u64 / u64::from(peak) + 1;
        let c = candidate(
            b,
            REGISTRAR,
            op(1_000 + n as u64),
            vec![],
            vec![put(b"hot", b"v")],
        );
        assert!(matches!(
            commit(b, &c, slot(n as u32 % peak, seq)).await,
            Decision::Applied(_)
        ));
    }
    bounded(commits);
    jumped
}

/// 8.10 Counter wrap: slot and sequence counters hold at every width boundary. On each of
/// [`WRAP_SLOTS`] the writer commits at every [`WRAP_SEQS`] sequence in turn, starting near
/// the boundary, as a long-lived writer would reach it. Each commit applies and its equal-sequence
/// replay answers its recorded Applied; a fresh candidate at the sequence just passed is STALE
/// and writes nothing, so a store that narrows or signs a sequence (and so sees the larger one as
/// smaller) is caught where it wraps. The writer ends with one row per slot it used. A
/// namespace generation is the store's own counter and cannot be seeded through the contract; the
/// long-horizon [`no_growth`] run ([`LONG_HORIZON_COMMITS`]) drives it past a million.
pub async fn counter_wrap(subject: &impl Subject) {
    let b = subject.backend();
    bootstrap(b).await;
    let mut n = 2_000;
    for (s, &index) in WRAP_SLOTS.iter().enumerate() {
        let mut passed = None;
        for &seq in &WRAP_SEQS {
            n += 1;
            let written = seq.to_be_bytes();
            let c = candidate(b, REGISTRAR, op(n), vec![], vec![put(b"wrap", &written)]);
            assert!(
                matches!(commit(b, &c, slot(index, seq)).await, Decision::Applied(_)),
                "slot {index} seq {seq:#x} did not apply"
            );
            assert!(
                matches!(commit(b, &c, slot(index, seq)).await, Decision::Applied(_)),
                "slot {index} seq {seq:#x} did not replay"
            );
            if let Some(before) = passed {
                n += 1;
                let late = candidate(b, REGISTRAR, op(n), vec![], vec![put(b"wrap", b"late")]);
                assert!(
                    matches!(commit(b, &late, slot(index, before)).await, Decision::Stale),
                    "slot {index}: seq {before:#x} after {seq:#x} was not STALE"
                );
            }
            assert_eq!(
                value(b, at(b"wrap")).await.as_deref(),
                Some(&written[..]),
                "slot {index} seq {seq:#x}"
            );
            passed = Some(seq);
        }
        let rows = subject.slot_rows(REGISTRAR);
        assert!(
            rows <= s + 1,
            "{rows} slot rows after {} wrapped slots",
            s + 1
        );
    }
}

/// 8.11 A clean exit (writer closure) leaves zero rows; a crashed writer keeps at
/// most its peak concurrency of rows.
pub async fn clean_exit_and_crash(subject: &impl Subject) {
    let b = subject.backend();
    bootstrap(b).await;
    let crashed = [0xD1; 16];
    let register = candidate(
        b,
        REGISTRAR,
        op(50),
        vec![Predicate {
            address: writer_at(crashed),
            expected: ExpectedValue::Absent,
        }],
        vec![Mutation::Put {
            address: writer_at(crashed),
            value: Secret::new(open().encode().expect("open").to_vec()),
        }],
    );
    assert!(matches!(
        commit(b, &register, self_key(&register)).await,
        Decision::Applied(_)
    ));
    for n in 0..5u32 {
        let c = candidate(
            b,
            crashed,
            op(60 + u64::from(n)),
            vec![],
            vec![put(b"crash", b"v")],
        );
        assert!(matches!(
            commit(b, &c, slot(n, 1)).await,
            Decision::Applied(_)
        ));
        let c = candidate(
            b,
            REGISTRAR,
            op(70 + u64::from(n)),
            vec![],
            vec![put(b"clean", b"v")],
        );
        assert!(matches!(
            commit(b, &c, slot(n, 1)).await,
            Decision::Applied(_)
        ));
    }
    assert_eq!(subject.slot_rows(crashed), 5);
    let close = closure(b, REGISTRAR, 80);
    assert!(matches!(
        commit(b, &close, self_key(&close)).await,
        Decision::Applied(_)
    ));
    assert_eq!(subject.slot_rows(REGISTRAR), 0);
    assert_eq!(
        subject.slot_rows(crashed),
        5,
        "a crashed writer keeps its peak rows"
    );
}
