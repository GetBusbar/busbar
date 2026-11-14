// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STORE KIT: kernel-level Startup conformance for a store, run by the store's own tests
//! against the kernel at the core revision the store pins.
//!
//! A store's tests know how to open their backend on a dataset; everything else here is the
//! kernel's own admission code. Each case runs on its own fresh dataset and reads rows only
//! through the store's handles, so the same assertions hold for every store.
//!
//! ```ignore
//! #[tokio::test(flavor = "multi_thread")]
//! async fn kernel_startup_kit() {
//!     busbar_kernel::persistence::store_kit::run(&MyFixture).await
//! }
//! ```
//!
//! Real time, no `tokio::time::pause`: a store's I/O completes on other threads, so auto-advance
//! would fire timers while a commit is in flight. Every bound here is far below any startup window.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::persistence::{control, Address, PersistenceBackend, Read, ReadResult};

use super::facade::{CoreStore, Limits};
use super::first_start::{self, Binding, FirstStart};
use super::startup::{manifest_address, root_address, writer_address, Error, Progress, Startup};

/// Every drive-to-state loop is bounded; overrun is a failure naming the case and step.
const STEPS: usize = 32;
/// Real time between advances that answered `Pending`.
const WAIT: Duration = Duration::from_millis(50);

/// One store under test. `fresh` makes a new, empty dataset owned by one case; `open` returns a
/// handle on it as a second process sharing that dataset would hold one. A store whose dataset
/// lives inside one opened instance returns the same `Arc` each time. Both run inside the kit's
/// tokio runtime: open with the async `LoadedPersistence::open` directly, never through a helper
/// that builds its own runtime or blocks a worker thread.
#[async_trait::async_trait]
pub trait Fixture: Send + Sync {
    type Dataset: Send + Sync;
    async fn fresh(&self) -> Self::Dataset;
    async fn open(&self, dataset: &Self::Dataset) -> Arc<dyn PersistenceBackend>;
}

/// Every case `run` executes, in order.
pub const CASES: &[&str] = &[
    "k1_first_start_publication",
    "k2_empty_refuses_without_initialize",
    "k3_racing_initialize",
];

/// The prefix of the lines `run` and each case print: `cases <n>` once, `passed <case>` per case.
pub const MARK: &str = "busbar-store-kit:";

/// Every case, each on its own fresh dataset. Panics naming the case and step.
pub async fn run<F: Fixture>(fixture: &F) {
    println!("{MARK} cases {}", CASES.len());
    k1_first_start_publication(fixture).await;
    k2_empty_refuses_without_initialize(fixture).await;
    k3_racing_initialize(fixture).await;
}

/// K1: first start over an empty dataset publishes; a second writer is admitted with no first
/// start and retires nobody; the first writer then retires cleanly; a third is admitted.
pub async fn k1_first_start_publication<F: Fixture>(fixture: &F) {
    const CASE: &str = "k1_first_start_publication";
    let dataset = fixture.fresh().await;
    let h1 = fixture.open(&dataset).await;
    let mut a = startup(CASE, &h1, true);
    let store_a = admitted(CASE, "A over the empty dataset", &mut a).await;
    let proof = owner(CASE, "A", &store_a);
    publish(CASE, "A", &proof).await;
    let writer_a = proof.owner();

    let h2 = fixture.open(&dataset).await;
    let store_b = admitted(
        CASE,
        "B over the published dataset",
        &mut startup(CASE, &h2, false),
    )
    .await;
    assert!(
        store_b.first_start().is_none(),
        "{CASE}: B was admitted over a published dataset holding a first start"
    );
    let row = writer(CASE, &h1, writer_a).await;
    assert!(
        row.admits(1),
        "{CASE}: B's admission retired A (A's writer row {row:?})"
    );

    a.begin_retirement()
        .unwrap_or_else(|e| panic!("{CASE}: A cannot begin retirement: {e:?}"));
    retired(CASE, "A retires", &mut a).await;
    let h3 = fixture.open(&dataset).await;
    admitted(CASE, "C after A retired", &mut startup(CASE, &h3, false)).await;
    passed(CASE);
}

/// K2: an empty dataset refuses a Startup that may not initialize, and stays empty.
pub async fn k2_empty_refuses_without_initialize<F: Fixture>(fixture: &F) {
    const CASE: &str = "k2_empty_refuses_without_initialize";
    let dataset = fixture.fresh().await;
    let h = fixture.open(&dataset).await;
    match startup(CASE, &h, false).advance().await {
        Err(Error::InitializationNotAllowed) => {}
        other => {
            panic!("{CASE}: a non-initializing Startup over an empty dataset answered {other:?}")
        }
    }
    assert_eq!(
        rows(CASE, &h, birth_rows()).await,
        vec![None, None, None],
        "{CASE}: the refused Startup wrote root, manifest or birth"
    );
    let store = admitted(CASE, "initializing Startup", &mut startup(CASE, &h, true)).await;
    owner(CASE, "the initializing Startup", &store);
    passed(CASE);
}

/// K3: two writers race Initialize; the loser writes nothing and exactly one owns the first start.
/// The loser's answer differs by store and kernel revision (`Reconcile`, an `Err`, or a re-inspect
/// that waits until publication); the kit pins only the invariant.
pub async fn k3_racing_initialize<F: Fixture>(fixture: &F) {
    const CASE: &str = "k3_racing_initialize";
    let dataset = fixture.fresh().await;
    let h1 = fixture.open(&dataset).await;
    let h2 = fixture.open(&dataset).await;
    let mut sides = [
        Side::new("A", startup(CASE, &h1, true)),
        Side::new("B", startup(CASE, &h2, true)),
    ];
    for side in &mut sides {
        expect_advanced(
            CASE,
            side.name,
            "reads the empty dataset",
            side.startup.advance().await,
        );
    }
    expect_advanced(
        CASE,
        "A",
        "Initialize applies",
        sides[0].startup.advance().await,
    );
    let snapshot = rows(CASE, &h1, birth_rows()).await;
    assert!(
        snapshot.iter().all(Option::is_some),
        "{CASE}: A's applied Initialize left root, manifest or birth absent"
    );
    let losing = sides[1].startup.advance().await;
    assert!(
        !matches!(losing, Ok(Progress::Admitted)),
        "{CASE}: B was admitted by submitting its Initialize over an initialized dataset"
    );
    assert_eq!(
        rows(CASE, &h1, birth_rows()).await,
        snapshot,
        "{CASE}: B's Initialize over an initialized dataset changed root, manifest or birth"
    );
    sides[1].observe(CASE, losing);

    let winner = 'owner: {
        for _ in 0..STEPS {
            let mut waiting = false;
            for (index, side) in sides.iter_mut().enumerate() {
                if side.stopped.is_some() {
                    continue;
                }
                let progress = side.startup.advance().await;
                waiting |= matches!(progress, Ok(Progress::Pending));
                if side.observe(CASE, progress) {
                    let store = side.startup.store().expect("admitted store");
                    match store.first_start() {
                        Some(proof) => break 'owner (index, proof),
                        None => panic!(
                            "{CASE}: {} was admitted without a first start before publication",
                            side.name
                        ),
                    }
                }
            }
            if sides.iter().all(|side| side.stopped.is_some()) {
                panic!(
                    "{CASE}: both writers stopped and neither owns the first start: {:?}",
                    sides.iter().map(|side| side.stopped).collect::<Vec<_>>()
                );
            }
            if waiting {
                tokio::time::sleep(WAIT).await;
            }
        }
        panic!("{CASE}: no writer owned the first start within {STEPS} rounds");
    };
    let (index, proof) = winner;
    publish(CASE, sides[index].name, &proof).await;

    let loser = &mut sides[1 - index];
    if loser.stopped.is_none() {
        for step in 0..=STEPS {
            assert!(
                step < STEPS,
                "{CASE}: {} did not settle within {STEPS} steps after publication",
                loser.name
            );
            let progress = loser.startup.advance().await;
            let pending = matches!(progress, Ok(Progress::Pending));
            if loser.observe(CASE, progress) {
                let store = loser.startup.store().expect("admitted store");
                assert!(
                    store.first_start().is_none(),
                    "{CASE}: {} was admitted after publication holding a first start",
                    loser.name
                );
                break;
            }
            if loser.stopped.is_some() {
                break;
            }
            if pending {
                tokio::time::sleep(WAIT).await;
            }
        }
    }
    let after = rows(CASE, &h1, birth_rows()).await;
    assert_eq!(
        after[..2],
        snapshot[..2],
        "{CASE}: root or manifest is no longer A's Initialize"
    );
    passed(CASE);
}

/// One racing writer in K3.
struct Side {
    name: &'static str,
    startup: Startup,
    /// Set once the writer answered `Reconcile` or an error: it is not driven again.
    stopped: Option<Result<Progress, Error>>,
}

impl Side {
    fn new(name: &'static str, startup: Startup) -> Self {
        Self {
            name,
            startup,
            stopped: None,
        }
    }

    /// Whether the writer is now admitted. `Advanced` and `Pending` continue; `Reconcile` and
    /// errors stop it; anything else is a failure.
    fn observe(&mut self, case: &str, progress: Result<Progress, Error>) -> bool {
        match progress {
            Ok(Progress::Admitted) => true,
            Ok(Progress::Advanced | Progress::Pending) => false,
            Ok(Progress::Reconcile) | Err(_) => {
                self.stopped = Some(progress);
                false
            }
            Ok(other) => panic!("{case}: {} answered {other:?} during admission", self.name),
        }
    }
}

fn limits() -> Limits {
    Limits {
        pending_operations: 1024,
        conflict_retries: 8,
        scan_items: 128,
        scan_bytes: 1024 * 1024,
    }
}

fn startup(case: &str, backend: &Arc<dyn PersistenceBackend>, initialize_empty: bool) -> Startup {
    Startup::new(backend.clone(), limits(), initialize_empty)
        .unwrap_or_else(|e| panic!("{case}: the kernel refused the store's facts: {e:?}"))
}

/// Root, manifest and birth record: the rows one Initialize writes.
fn birth_rows() -> Vec<Address> {
    vec![root_address(), manifest_address(), first_start::address()]
}

async fn rows(
    case: &str,
    backend: &Arc<dyn PersistenceBackend>,
    addresses: Vec<Address>,
) -> Vec<Option<Vec<u8>>> {
    let count = addresses.len();
    let answer = backend
        .read(Arc::new(Read {
            dataset: backend.info().dataset,
            addresses,
            time: None,
        }))
        .await
        .unwrap_or_else(|e| panic!("{case}: the store refused a read: {e:?}"));
    let ReadResult::Values { values, .. } = answer else {
        panic!("{case}: an unguarded read did not answer values");
    };
    assert_eq!(
        values.len(),
        count,
        "{case}: the store answered the wrong number of values"
    );
    let seal = crate::seal::lend();
    values
        .into_iter()
        .map(|value| value.map(|value| value.expose(&seal).clone()))
        .collect()
}

async fn writer(
    case: &str,
    backend: &Arc<dyn PersistenceBackend>,
    id: [u8; 16],
) -> control::Writer {
    rows(case, backend, vec![writer_address(id)]).await[0]
        .as_deref()
        .and_then(control::Writer::decode)
        .unwrap_or_else(|| panic!("{case}: a registered writer's row is absent or undecodable"))
}

async fn admitted(case: &str, step: &str, startup: &mut Startup) -> Arc<CoreStore> {
    for _ in 0..STEPS {
        match startup.advance().await {
            Ok(Progress::Admitted) => return startup.store().expect("admitted store"),
            Ok(Progress::Advanced) => {}
            Ok(Progress::Pending) => tokio::time::sleep(WAIT).await,
            other => panic!("{case}: {step}: admission answered {other:?}"),
        }
    }
    panic!("{case}: {step}: not admitted within {STEPS} steps")
}

async fn retired(case: &str, step: &str, startup: &mut Startup) {
    for _ in 0..STEPS {
        match startup.advance().await {
            Ok(Progress::Retired) => return,
            Ok(Progress::Advanced) => {}
            Ok(Progress::Pending) => tokio::time::sleep(WAIT).await,
            other => panic!("{case}: {step}: retirement answered {other:?}"),
        }
    }
    panic!("{case}: {step}: not retired within {STEPS} steps")
}

fn owner(case: &str, who: &str, store: &CoreStore) -> Arc<FirstStart> {
    store.first_start().unwrap_or_else(|| {
        panic!("{case}: {who} was admitted over an empty dataset without a first start")
    })
}

/// Freeze a one-instance plan, complete it and publish, each step applied.
async fn publish(case: &str, who: &str, proof: &FirstStart) {
    let binding = Binding {
        instance: "kit".into(),
        digest: [7; 32],
    };
    expect_advanced(case, who, "freeze", proof.freeze(vec![binding]).await);
    expect_advanced(case, who, "complete", proof.complete("kit").await);
    expect_advanced(case, who, "publish", proof.publish().await);
    assert!(
        proof.published().await,
        "{case}: {who} published but the record is not published"
    );
}

fn expect_advanced(case: &str, who: &str, step: &str, progress: Result<Progress, Error>) {
    assert_eq!(progress, Ok(Progress::Advanced), "{case}: {who}: {step}");
}

fn passed(case: &str) {
    println!("{MARK} passed {case}");
}

#[cfg(test)]
#[path = "store_kit_tests.rs"]
mod tests;
