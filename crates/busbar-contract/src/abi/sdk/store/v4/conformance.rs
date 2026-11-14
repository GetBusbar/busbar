// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE CASES FOR "NO RETENTION" (LR-118). A store keeps no per-commit state (a receipt, a
//! TTL row, an aging queue) and no clock decides what it holds. Every store's suite runs both
//! cases, each on a fresh, empty dataset:
//!
//! - [`state_does_not_grow_over_commits`]: [`COMMITS`] commits leave the store holding what it
//!   held after the first [`WARM`].
//! - [`nothing_changes_after_clock_jump`]: a [`JUMP`] of the host clock the store's code reads
//!   ([`Subject::jump`]) changes nothing it holds or answers.
//!
//! The subject counts what the store holds from outside the store's code, so the cases catch the
//! behaviour in any spelling: Rust, SQL or Lua. A store takes time only from the host's clock
//! (`clock.now`, CLOCK-INSTANT-BRIDGE; an OS read is R7's to refuse), so the subject's jump of
//! that clock reaches every clock its code reads. A server's own clock (SQL `now()`, a Valkey
//! `TIME`) is the server's and out of reach.
//!
//! ```ignore
//! #[test]
//! fn store_state_does_not_grow_over_commits() {
//!     block(conformance::state_does_not_grow_over_commits(&MySubject::fresh()));
//! }
//! ```

use std::sync::Arc;
use std::time::Duration;

use crate::persistence::{
    control, Address, AttemptId, Candidate, Decision, ExpectedValue, Mutation, PersistenceBackend,
    Predicate, PreparedCandidate, Read, ReadResult, CANDIDATE_VERSION,
};
use crate::Secret;

/// Commits the growth case makes.
pub const COMMITS: u64 = 1_000_000;
/// Commits before the first observation, so steady-state structures exist.
pub const WARM: u64 = 1_000;
/// Distinct data keys the commits overwrite: data stays this size.
pub const KEYS: u64 = 16;
/// The clock jump: past any 24 h horizon twice over.
pub const JUMP: Duration = Duration::from_secs(48 * 60 * 60);

/// Every case, in order.
pub const CASES: &[&str] = &[
    "state_does_not_grow_over_commits",
    "nothing_changes_after_clock_jump",
];

/// The prefix of the line each passing case prints.
pub const MARK: &str = "busbar-store-cases:";

const NAMESPACE: [u8; 16] = *b"busbar.lr118.v1\0";
const WRITER: [u8; 16] = [0x18; 16];
/// Operation ids of the data commits; the bootstrap commit is operation 1.
const OPS: u128 = 1 << 64;

/// One store under test, opened on a fresh, empty dataset the case bootstraps. Both observations
/// are synchronous: a store's own blocking client runs on a thread of its own (a blocking client
/// may not run inside the case's runtime).
pub trait Subject: Send + Sync {
    /// The opened store.
    fn store(&self) -> Arc<dyn PersistenceBackend>;
    /// Everything the store holds, counted outside the store's own code, in the store's unit:
    /// rows or keys across every table it owns (data, control, receipts, slots), or resident
    /// bytes ([`resident_bytes`]) for a store that lives in this process.
    fn retained(&self) -> u64;
    /// Move the host clock this store's code reads (`clock.now`, wall and monotonic) forward by
    /// `by`. A store whose code reads no host clock has nothing to move.
    fn jump(&self, by: Duration);
    /// How far `retained` moves between two observations of equal content (allocator or page
    /// noise). A row count has none.
    fn noise(&self) -> u64 {
        0
    }
}

/// Resident bytes of this process (Linux `/proc/self/statm`, 4 KiB pages), for the `retained`
/// of a store that lives in the test process.
#[must_use]
pub fn resident_bytes() -> u64 {
    let statm = std::fs::read_to_string("/proc/self/statm")
        .expect("resident bytes are read from /proc/self/statm (Linux)");
    let pages: u64 = statm
        .split_whitespace()
        .nth(1)
        .and_then(|pages| pages.parse().ok())
        .expect("/proc/self/statm names resident pages");
    pages.saturating_mul(4096)
}

/// GROWTH: [`COMMITS`] commits over [`KEYS`] keys hold what the first [`WARM`] held.
pub async fn state_does_not_grow_over_commits<S: Subject + ?Sized>(subject: &S) {
    const CASE: &str = "state_does_not_grow_over_commits";
    let store = subject.store();
    bootstrap(CASE, &*store).await;
    for n in 0..WARM {
        put(CASE, &*store, OPS + u128::from(n), n).await;
    }
    let warm = subject.retained();
    for n in WARM..COMMITS {
        put(CASE, &*store, OPS + u128::from(n), n).await;
    }
    let after = subject.retained();
    assert!(
        after <= warm.saturating_add(subject.noise()),
        "{CASE}: LR-118: the store held {warm} after {WARM} commits and {after} after {COMMITS}: \
         it keeps state per commit (a receipt, TTL row or horizon)"
    );
    passed(CASE);
}

/// CLOCK: after [`JUMP`], a commit that rewrites a value already held leaves the store holding
/// and answering exactly what it did before the jump.
pub async fn nothing_changes_after_clock_jump<S: Subject + ?Sized>(subject: &S) {
    const CASE: &str = "nothing_changes_after_clock_jump";
    let store = subject.store();
    bootstrap(CASE, &*store).await;
    for n in 0..=WARM {
        put(CASE, &*store, OPS + u128::from(n), n).await;
    }
    let held = values(CASE, &*store).await;
    let retained = subject.retained();

    subject.jump(JUMP);
    if let Err(failure) = store.clock(store.info().dataset).await {
        panic!("{CASE}: the clock after the jump answered {failure:?}");
    }
    // Rewrites key WARM % KEYS with the value it already holds: data is unchanged.
    put(CASE, &*store, OPS + u128::from(WARM) + 1, WARM).await;

    assert!(
        values(CASE, &*store).await == held,
        "{CASE}: LR-118: the store answers different values after a {JUMP:?} clock jump"
    );
    let after = subject.retained();
    assert!(
        after.abs_diff(retained) <= subject.noise(),
        "{CASE}: LR-118: the store held {retained} before a {JUMP:?} clock jump and {after} after: \
         time decides what it keeps"
    );
    passed(CASE);
}

fn passed(case: &str) {
    println!("{MARK} passed {case}");
}

fn attempt(store: &dyn PersistenceBackend, operation: u128) -> AttemptId {
    AttemptId {
        dataset: store.info().dataset,
        writer_epoch: 1,
        writer: WRITER,
        execution_epoch: 1,
        operation: operation.to_le_bytes(),
    }
}

fn data(key: u64) -> Address {
    Address {
        namespace: NAMESPACE,
        key: key.to_le_bytes().to_vec(),
    }
}

fn fence(key: Vec<u8>) -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key,
    }
}

async fn commit(
    case: &str,
    store: &dyn PersistenceBackend,
    operation: u128,
    predicates: Vec<Predicate>,
    mutations: Vec<Mutation>,
) {
    let candidate = PreparedCandidate::new(Candidate {
        id: attempt(store, operation),
        codec: CANDIDATE_VERSION,
        predicates,
        mutations,
        time: None,
        result: Secret::new(Vec::new()),
    })
    .unwrap_or_else(|invalid| panic!("{case}: candidate {operation} is invalid: {invalid:?}"));
    match store.commit(candidate).await {
        Ok(Decision::Applied(_)) => {}
        other => panic!("{case}: commit {operation} answered {other:?}"),
    }
}

/// The dataset root and this case's writer, admitted at epoch 1.
async fn bootstrap(case: &str, store: &dyn PersistenceBackend) {
    let root = fence(control::DATASET_KEY.to_vec());
    let writer = fence(control::writer_key(WRITER).to_vec());
    let dataset = control::Dataset {
        id: store.info().dataset,
        writer_epoch: 1,
    }
    .encode()
    .unwrap_or_else(|| panic!("{case}: the store's dataset id is unregistered"));
    let admitted = control::Writer {
        retired_through: 0,
        admitted_through: 1,
    }
    .encode()
    .unwrap_or_else(|| panic!("{case}: the writer row does not encode"));
    commit(
        case,
        store,
        1,
        vec![
            Predicate {
                address: root.clone(),
                expected: ExpectedValue::Absent,
            },
            Predicate {
                address: writer.clone(),
                expected: ExpectedValue::Absent,
            },
        ],
        vec![
            Mutation::Put {
                address: root,
                value: Secret::new(dataset.to_vec()),
            },
            Mutation::Put {
                address: writer,
                value: Secret::new(admitted.to_vec()),
            },
        ],
    )
    .await;
}

/// Writes value `n` at key `n % KEYS`.
async fn put(case: &str, store: &dyn PersistenceBackend, operation: u128, n: u64) {
    commit(
        case,
        store,
        operation,
        Vec::new(),
        vec![Mutation::Put {
            address: data(n % KEYS),
            value: Secret::new(n.to_le_bytes().to_vec()),
        }],
    )
    .await;
}

async fn values(case: &str, store: &dyn PersistenceBackend) -> Vec<Option<Secret<Vec<u8>>>> {
    let read = Arc::new(Read {
        dataset: store.info().dataset,
        addresses: (0..KEYS).map(data).collect(),
        time: None,
    });
    match store.read(read).await {
        Ok(ReadResult::Values { values, .. }) => values,
        Ok(ReadResult::TimeGuardFailed { .. }) => {
            panic!("{case}: an unguarded read failed its guard")
        }
        Err(failure) => panic!("{case}: the read answered {failure:?}"),
    }
}

#[cfg(test)]
#[path = "tests/conformance_tests.rs"]
mod tests;
