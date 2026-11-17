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

use busbar_contract::persistence::{
    control, Address, NamespaceId, PersistenceBackend, Read, ReadResult,
};

use busbar_contract::secure::SecureVec;

use super::facade::{CoreStore, Limits};
use super::first_start::{self, Abandoned, Binding, FirstStart};
use super::format_migration::MigrationOwner;
use super::import_target::r0::{Access, Commit, Outcome};
use super::startup::{
    classify, cursor_address, manifest_address, root_address, writer_address, Error, Format,
    FormatChain, Progress, Startup, RECORD_FORMAT,
};

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
    "t1_staggered_boot",
    "t2_waiter_restart",
    "t11_abandon_hands_over",
    "f1_format_opening_fences_the_old_epoch",
    "f2_racing_openings_have_one_owner",
    "f3_pages_and_final_publication",
];

/// The prefix of the lines `run` and each case print: `cases <n>` once, `passed <case>` per case.
pub const MARK: &str = "busbar-store-kit:";

/// Every case, each on its own fresh dataset. Panics naming the case and step.
pub async fn run<F: Fixture>(fixture: &F) {
    run_cases(fixture, None).await;
}

/// [`run`] with a deadline per case (DES-STOREKIT r2 §2.3): a case still running at `deadline`
/// panics as `TIMEOUT <case>`, so a hang is a red case, never a stuck job.
pub async fn run_within<F: Fixture>(fixture: &F, deadline: Duration) {
    run_cases(fixture, Some(deadline)).await;
}

async fn run_cases<F: Fixture>(fixture: &F, deadline: Option<Duration>) {
    println!("{MARK} cases {}", CASES.len());
    within(deadline, CASES[0], k1_first_start_publication(fixture)).await;
    within(
        deadline,
        CASES[1],
        k2_empty_refuses_without_initialize(fixture),
    )
    .await;
    within(deadline, CASES[2], k3_racing_initialize(fixture)).await;
    within(deadline, CASES[3], t1_staggered_boot(fixture)).await;
    within(deadline, CASES[4], t2_waiter_restart(fixture)).await;
    within(deadline, CASES[5], t11_abandon_hands_over(fixture)).await;
    within(
        deadline,
        CASES[6],
        f1_format_opening_fences_the_old_epoch(fixture),
    )
    .await;
    within(
        deadline,
        CASES[7],
        f2_racing_openings_have_one_owner(fixture),
    )
    .await;
    within(deadline, CASES[8], f3_pages_and_final_publication(fixture)).await;
}

/// One case, bounded by `deadline` when there is one.
async fn within(
    deadline: Option<Duration>,
    case: &str,
    run: impl std::future::Future<Output = ()>,
) {
    match deadline {
        None => run.await,
        Some(deadline) => {
            if tokio::time::timeout(deadline, run).await.is_err() {
                panic!("{MARK} TIMEOUT {case} ({} s)", deadline.as_secs());
            }
        }
    }
}

/// A store that holds its data across processes can also seed a raw record with its own driver,
/// as its `migrate` does before admission. Only durable stores implement it; `run_durable` runs
/// the cases that need it.
#[async_trait::async_trait]
pub trait DurableFixture: Fixture {
    async fn seed(&self, dataset: &Self::Dataset, namespace: NamespaceId, key: &[u8], value: &[u8]);
}

/// Every case `run_durable` executes, in order.
const DURABLE_CASES: &[&str] = &["t17_import_rows_do_not_block_initialize"];

/// The durable-only cases, each on its own fresh dataset. Run beside `run`.
pub async fn run_durable<F: DurableFixture>(fixture: &F) {
    println!("{MARK} durable cases {}", DURABLE_CASES.len());
    t17_import_rows_do_not_block_initialize(fixture).await;
}

/// T17 (FIRST-START-TAKEOVER §2.9 (b)): Initialize's emptiness proof ignores records in the
/// import namespace, which survive it untouched; a record in any other namespace still refuses it.
pub(crate) async fn t17_import_rows_do_not_block_initialize<F: DurableFixture>(fixture: &F) {
    const CASE: &str = "t17_import_rows_do_not_block_initialize";
    let import = |key: &[u8]| Address {
        namespace: control::IMPORT_NAMESPACE.0,
        key: key.to_vec(),
    };
    let dataset = fixture.fresh().await;
    fixture
        .seed(&dataset, control::IMPORT_NAMESPACE, &[0], b"kit-summary")
        .await;
    fixture
        .seed(
            &dataset,
            control::IMPORT_NAMESPACE,
            b"kit-row",
            b"kit-value",
        )
        .await;
    let h = fixture.open(&dataset).await;
    let started = std::time::Instant::now();
    let store = admitted(
        CASE,
        "Initialize over import rows",
        &mut startup(CASE, &h, true),
    )
    .await;
    println!(
        "{MARK} {CASE}: Initialize over import rows took {} ms",
        started.elapsed().as_millis()
    );
    owner(CASE, "the initializing Startup", &store);
    assert_eq!(
        rows(CASE, &h, vec![import(&[0]), import(b"kit-row")]).await,
        vec![Some(b"kit-summary".to_vec()), Some(b"kit-value".to_vec())],
        "{CASE}: Initialize changed the import rows"
    );

    let dataset = fixture.fresh().await;
    fixture
        .seed(&dataset, NamespaceId(*b"busbar.kit.other"), b"k", b"v")
        .await;
    let h = fixture.open(&dataset).await;
    let mut refused = startup(CASE, &h, true);
    for step in 0..=STEPS {
        assert!(
            step < STEPS,
            "{CASE}: Initialize over another record did not settle"
        );
        match refused.advance().await {
            Ok(Progress::Admitted) => {
                panic!("{CASE}: Initialize applied over a record outside the import namespace")
            }
            Ok(Progress::Advanced) => {}
            Ok(Progress::Pending) => tokio::time::sleep(WAIT).await,
            Ok(Progress::Reconcile) | Err(_) => break,
            other => panic!("{CASE}: Initialize over another record answered {other:?}"),
        }
    }
    assert_eq!(
        rows(CASE, &h, birth_rows()).await,
        vec![None, None, None],
        "{CASE}: a refused Initialize wrote root, manifest or birth"
    );
    passed(CASE);
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
pub(crate) async fn k2_empty_refuses_without_initialize<F: Fixture>(fixture: &F) {
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

/// T1 (FIRST-START-TAKEOVER §8): a writer that boots while another's first start is live waits,
/// writes nothing and retires nobody; it is admitted, with no first start, after publication.
async fn t1_staggered_boot<F: Fixture>(fixture: &F) {
    const CASE: &str = "t1_staggered_boot";
    let dataset = fixture.fresh().await;
    let h1 = fixture.open(&dataset).await;
    let h2 = fixture.open(&dataset).await;
    let mut a = startup(CASE, &h1, true);
    let store_a = admitted(CASE, "A over the empty dataset", &mut a).await;
    let proof = owner(CASE, "A", &store_a);
    let watched = vec![writer_address(proof.owner()), first_start::address()];
    let before = rows(CASE, &h1, watched.clone()).await;
    let mut b = startup(CASE, &h2, false);
    for step in 0..100 {
        assert_eq!(
            b.advance().await,
            Ok(Progress::Pending),
            "{CASE}: B advance {step} while A's first start is live"
        );
        assert_eq!(
            rows(CASE, &h1, watched.clone()).await,
            before,
            "{CASE}: B advance {step} changed A's writer row or the birth record"
        );
        tokio::time::sleep(WAIT).await;
    }
    publish(CASE, "A", &proof).await;
    let store_b = admitted(CASE, "B after publication", &mut b).await;
    assert!(
        store_b.first_start().is_none(),
        "{CASE}: B was admitted after publication holding a first start"
    );
    let row = writer(CASE, &h1, proof.owner()).await;
    assert!(row.admits(1), "{CASE}: A was retired ({row:?})");
    passed(CASE);
}

/// T2 (FIRST-START-TAKEOVER §8): a waiter that restarts during a long first start starts waiting
/// again; the owner is never retired, and the restarted waiter is admitted after publication.
async fn t2_waiter_restart<F: Fixture>(fixture: &F) {
    const CASE: &str = "t2_waiter_restart";
    let dataset = fixture.fresh().await;
    let h1 = fixture.open(&dataset).await;
    let mut a = startup(CASE, &h1, true);
    let store_a = admitted(CASE, "A over the empty dataset", &mut a).await;
    let proof = owner(CASE, "A", &store_a);
    let writer_a = proof.owner();
    let waits = |who: &'static str, mut waiter: Startup| {
        let h1 = h1.clone();
        async move {
            for step in 0..20 {
                assert_eq!(
                    waiter.advance().await,
                    Ok(Progress::Pending),
                    "{CASE}: {who} advance {step} while A's first start is live"
                );
                let row = writer(CASE, &h1, writer_a).await;
                assert!(
                    row.admits(1),
                    "{CASE}: {who} advance {step} retired A ({row:?})"
                );
                tokio::time::sleep(WAIT).await;
            }
            waiter
        }
    };
    let h2 = fixture.open(&dataset).await;
    drop(waits("B", startup(CASE, &h2, false)).await);
    let binding = Binding {
        instance: "kit".into(),
        digest: [7; 32],
    };
    expect_advanced(CASE, "A", "freeze", proof.freeze(vec![binding]).await);
    let h3 = fixture.open(&dataset).await;
    let mut restarted = waits("B'", startup(CASE, &h3, false)).await;
    publish(CASE, "A", &proof).await;
    let store = admitted(CASE, "B' after publication", &mut restarted).await;
    assert!(
        store.first_start().is_none(),
        "{CASE}: B' was admitted after publication holding a first start"
    );
    let row = writer(CASE, &h1, writer_a).await;
    assert!(row.admits(1), "{CASE}: A was retired ({row:?})");
    passed(CASE);
}

/// T11 (FIRST-START-TAKEOVER §8): an owner that leaves on purpose abandons its first start: its
/// own writer row is retired and the birth record is left exactly as it was, so the next writer
/// takes over at once, with no `Pending`, and the abandoned owner makes no further step. Run with
/// no plane done and with one plane done; after publication `abandon` writes nothing.
pub(crate) async fn t11_abandon_hands_over<F: Fixture>(fixture: &F) {
    const CASE: &str = "t11_abandon_hands_over";
    for done in [0usize, 1] {
        let dataset = fixture.fresh().await;
        let h1 = fixture.open(&dataset).await;
        let mut a = startup(CASE, &h1, true);
        let store_a = admitted(CASE, "A over the empty dataset", &mut a).await;
        let proof = owner(CASE, "A", &store_a);
        if done == 1 {
            expect_advanced(CASE, "A", "freeze", proof.freeze(vec![kit_binding()]).await);
            expect_advanced(CASE, "A", "complete", proof.complete("kit").await);
        }
        let writer_a = proof.owner();
        let birth = rows(CASE, &h1, vec![first_start::address()]).await;
        assert_eq!(
            proof.abandon().await,
            Ok(Abandoned::Retired),
            "{CASE}: A abandons with {done} plane(s) done"
        );
        let row = writer(CASE, &h1, writer_a).await;
        assert!(
            row.retired_through == row.admitted_through && !row.admits(1),
            "{CASE}: A's writer row is not retired after abandon ({row:?})"
        );
        assert_eq!(
            rows(CASE, &h1, vec![first_start::address()]).await,
            birth,
            "{CASE}: abandon changed the birth record"
        );
        assert_eq!(
            proof.freeze(vec![kit_binding()]).await,
            Err(Error::Authority),
            "{CASE}: A made a first-start step after abandon"
        );
        let retired = rows(CASE, &h1, vec![writer_address(writer_a)]).await;

        let h2 = fixture.open(&dataset).await;
        let mut b = startup(CASE, &h2, false);
        let store_b = admitted_at_once(CASE, "B after A abandoned", &mut b).await;
        let next = owner(CASE, "B", &store_b);
        assert_ne!(
            next.owner(),
            writer_a,
            "{CASE}: B took over under A's writer"
        );
        assert_eq!(
            rows(CASE, &h1, vec![writer_address(writer_a)]).await,
            retired,
            "{CASE}: B's takeover rewrote A's retired writer row"
        );
        publish(CASE, "B", &next).await;
    }

    let dataset = fixture.fresh().await;
    let h = fixture.open(&dataset).await;
    let mut a = startup(CASE, &h, true);
    let store_a = admitted(CASE, "A over the empty dataset", &mut a).await;
    let proof = owner(CASE, "A", &store_a);
    publish(CASE, "A", &proof).await;
    let watched = vec![writer_address(proof.owner()), first_start::address()];
    let before = rows(CASE, &h, watched.clone()).await;
    assert_eq!(
        proof.abandon().await,
        Ok(Abandoned::Published),
        "{CASE}: A abandons after publication"
    );
    assert_eq!(
        rows(CASE, &h, watched).await,
        before,
        "{CASE}: abandon after publication wrote A's writer row or the birth record"
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

// ---- #319 r4: record-format migration over the store's own serialization -------------------

/// The kit's synthetic record-format step 0 -> 1 (this kernel writes format 1). No production
/// step exists in 1.6.0; the cases prove the store serializes the kernel's opening, pages and
/// final publication exactly as the reference store does.
struct KitChain;

impl FormatChain for KitChain {
    fn has_step(&self, from: u32) -> bool {
        from == 0
    }
    fn initial_cursor(&self, from: u32) -> Option<Vec<u8>> {
        (from == 0).then(|| b"kit-cursor@0".to_vec())
    }
}

fn converting(case: &str, backend: &Arc<dyn PersistenceBackend>) -> Startup {
    startup(case, backend, false).with_format_chain(Arc::new(KitChain))
}

/// One business row, as any writer of the old epoch would put it.
fn business_row() -> Commit {
    Commit {
        put: vec![(
            Address {
                namespace: *b"busbar.kit.other",
                key: b"late".to_vec(),
            },
            SecureVec::from(b"late".to_vec()),
        )],
        ..Commit::default()
    }
}

/// A dataset whose first start published and whose manifest its own writer then rewrote to the
/// synthetic older format 0. That writer stays open: a process of the old epoch.
async fn older_dataset<F: Fixture>(fixture: &F, case: &str) -> (F::Dataset, Arc<CoreStore>) {
    let dataset = fixture.fresh().await;
    let h = fixture.open(&dataset).await;
    let old = admitted(case, "the old writer", &mut startup(case, &h, true)).await;
    publish(case, "the old writer", &owner(case, "the old writer", &old)).await;
    let current = rows(case, &h, vec![manifest_address()]).await[0]
        .clone()
        .unwrap_or_else(|| panic!("{case}: the admitted dataset has no manifest"));
    let mut older = current.clone();
    for at in [8, 12, 16, 20] {
        older[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
    }
    let rewrite = Commit {
        expect: vec![(manifest_address(), Some(SecureVec::from(current)))],
        put: vec![(manifest_address(), SecureVec::from(older))],
        ..Commit::default()
    };
    assert_eq!(
        Access::new(old.clone()).commit(rewrite).await,
        Ok(Outcome::Applied),
        "{case}: the old writer could not rewrite the manifest to format 0"
    );
    (dataset, old)
}

async fn epoch(case: &str, backend: &Arc<dyn PersistenceBackend>) -> u64 {
    rows(case, backend, vec![root_address()]).await[0]
        .as_deref()
        .and_then(control::Dataset::decode)
        .unwrap_or_else(|| panic!("{case}: the dataset root is absent or undecodable"))
        .writer_epoch
}

/// Drive `startup` until it owns the conversion.
async fn migrating(case: &str, step: &str, startup: &mut Startup) -> Arc<MigrationOwner> {
    for _ in 0..STEPS {
        match startup.advance().await {
            Ok(Progress::Migrate) => return startup.migration().expect("migration owner"),
            Ok(Progress::Advanced) => {}
            other => panic!("{case}: {step}: admission answered {other:?}, not Migrate"),
        }
    }
    panic!("{case}: {step}: no migration owner within {STEPS} steps")
}

/// Drive `startup` until it either owns the conversion or waits on another owner.
async fn opened_or_waiting(case: &str, startup: &mut Startup) -> Progress {
    for _ in 0..STEPS {
        match startup.advance().await {
            Ok(progress @ (Progress::Migrate | Progress::Pending)) => return progress,
            Ok(Progress::Advanced) => {}
            other => panic!("{case}: a contender answered {other:?}"),
        }
    }
    panic!("{case}: a contender settled on neither Migrate nor Pending within {STEPS} steps")
}

/// F1 (#319 r4 §6, §10): the opening advances the dataset epoch, names a fresh owner with the
/// tail and writes the cursor at one serialization point; a writer of the old epoch is fenced by
/// the store at its next commit and its row never lands.
pub async fn f1_format_opening_fences_the_old_epoch<F: Fixture>(fixture: &F) {
    const CASE: &str = "f1_format_opening_fences_the_old_epoch";
    let (dataset, old) = older_dataset(fixture, CASE).await;
    let h = fixture.open(&dataset).await;
    assert_eq!(epoch(CASE, &h).await, 1, "{CASE}: the fixture's epoch");
    let mut opener = converting(CASE, &h);
    let owner = migrating(CASE, "the opener", &mut opener).await;
    assert!(
        opener.store().is_none(),
        "{CASE}: a serving store was handed out while the tail is nonzero"
    );
    assert_eq!(epoch(CASE, &h).await, 2, "{CASE}: the opening's epoch");
    let observed = rows(CASE, &h, vec![manifest_address(), cursor_address()]).await;
    let manifest = observed[0].clone().expect("manifest");
    assert_eq!(
        classify(&manifest, |f| f == 0),
        Format::Migrating { from: 0, to: 1 },
        "{CASE}: the opened manifest"
    );
    assert_eq!(manifest.as_slice(), owner.manifest_bytes());
    assert_eq!(
        observed[1].as_deref(),
        Some(b"kit-cursor@0".as_slice()),
        "{CASE}: the opening's cursor"
    );
    assert_eq!(
        Access::new(old).commit(business_row()).await,
        Ok(Outcome::Fenced),
        "{CASE}: the old-epoch writer was not fenced"
    );
    let late = business_row().put[0].0.clone();
    assert_eq!(
        rows(CASE, &h, vec![late]).await,
        vec![None],
        "{CASE}: the old-epoch writer's row landed after the opening"
    );
    passed(CASE);
}

/// F2 (#319 r4 §6, §8): two processes open the same older dataset at once. Exactly one opening
/// applies (the epoch advances once); the other loses and waits on that owner, never adopting it.
pub async fn f2_racing_openings_have_one_owner<F: Fixture>(fixture: &F) {
    const CASE: &str = "f2_racing_openings_have_one_owner";
    let (dataset, _old) = older_dataset(fixture, CASE).await;
    let (ha, hb) = (fixture.open(&dataset).await, fixture.open(&dataset).await);
    let (mut a, mut b) = (converting(CASE, &ha), converting(CASE, &hb));
    let (pa, pb) = tokio::join!(
        opened_or_waiting(CASE, &mut a),
        opened_or_waiting(CASE, &mut b)
    );
    let owners = [pa, pb]
        .iter()
        .filter(|progress| **progress == Progress::Migrate)
        .count();
    assert_eq!(
        owners, 1,
        "{CASE}: {pa:?} and {pb:?}: not exactly one owner"
    );
    assert_eq!(
        epoch(CASE, &ha).await,
        2,
        "{CASE}: more than one opening applied"
    );
    let (winner, waiter) = if pa == Progress::Migrate {
        (&a, &b)
    } else {
        (&b, &a)
    };
    let waiting = waiter
        .waiting_on()
        .unwrap_or_else(|| panic!("{CASE}: the losing contender is not waiting"));
    assert!(
        waiting.migrating,
        "{CASE}: the wait is not a migration wait"
    );
    let manifest = rows(CASE, &ha, vec![manifest_address()]).await[0]
        .clone()
        .expect("manifest");
    assert_eq!(
        manifest.as_slice(),
        winner.migration().expect("owner").manifest_bytes(),
        "{CASE}: the manifest does not name the winning owner"
    );
    passed(CASE);
}

/// F3 (#319 r4 §7, §9): the owner commits a page under its own authority; the final publication
/// advances the epoch past it, names a fresh registrar and the Current manifest and deletes the
/// cursor in one transaction; reinspection then admits ordinarily at the new epoch, and both the
/// finished owner and the old-epoch writer are fenced.
pub async fn f3_pages_and_final_publication<F: Fixture>(fixture: &F) {
    const CASE: &str = "f3_pages_and_final_publication";
    let (dataset, old) = older_dataset(fixture, CASE).await;
    let h = fixture.open(&dataset).await;
    let mut converter = converting(CASE, &h);
    let owner = migrating(CASE, "the converter", &mut converter).await;
    let manifest = SecureVec::from(owner.manifest_bytes().to_vec());
    let page = Commit {
        expect: vec![
            (manifest_address(), Some(manifest.clone())),
            (
                cursor_address(),
                Some(SecureVec::from(b"kit-cursor@0".to_vec())),
            ),
        ],
        put: vec![(
            cursor_address(),
            SecureVec::from(b"kit-cursor@end".to_vec()),
        )],
        ..Commit::default()
    };
    assert_eq!(
        owner.access().commit(page).await,
        Ok(Outcome::Applied),
        "{CASE}: the owner's page"
    );
    let completion = Commit {
        expect: vec![
            (manifest_address(), Some(manifest)),
            (
                cursor_address(),
                Some(SecureVec::from(b"kit-cursor@end".to_vec())),
            ),
        ],
        delete: vec![cursor_address()],
        ..Commit::default()
    };
    assert_eq!(
        owner.finalize(completion, RECORD_FORMAT).await,
        Ok(Outcome::Applied),
        "{CASE}: the final publication"
    );
    assert_eq!(epoch(CASE, &h).await, 3, "{CASE}: the publication's epoch");
    let observed = rows(CASE, &h, vec![manifest_address(), cursor_address()]).await;
    assert_eq!(
        classify(observed[0].as_deref().expect("manifest"), |_| false),
        Format::Current,
        "{CASE}: the published manifest"
    );
    assert_eq!(
        observed[1], None,
        "{CASE}: the cursor outlived the publication"
    );
    converter
        .migration_finished()
        .unwrap_or_else(|e| panic!("{CASE}: finishing the conversion: {e:?}"));
    let store = admitted(CASE, "after the publication", &mut converter).await;
    assert_eq!(
        store.authority().expect("authority").writer_epoch,
        3,
        "{CASE}: ordinary admission's epoch"
    );
    assert_eq!(
        owner.access().commit(business_row()).await,
        Ok(Outcome::Fenced),
        "{CASE}: the finished owner was not fenced"
    );
    assert_eq!(
        Access::new(old).commit(business_row()).await,
        Ok(Outcome::Fenced),
        "{CASE}: the old-epoch writer was not fenced"
    );
    passed(CASE);
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

/// Admission that never waits: every advance is `Advanced` until `Admitted`.
async fn admitted_at_once(case: &str, step: &str, startup: &mut Startup) -> Arc<CoreStore> {
    for _ in 0..STEPS {
        match startup.advance().await {
            Ok(Progress::Admitted) => return startup.store().expect("admitted store"),
            Ok(Progress::Advanced) => {}
            other => panic!("{case}: {step}: admission answered {other:?}, not at once"),
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

/// The one-instance plan every case freezes.
fn kit_binding() -> Binding {
    Binding {
        instance: "kit".into(),
        digest: [7; 32],
    }
}

/// Freeze a one-instance plan, complete it and publish, each step applied.
async fn publish(case: &str, who: &str, proof: &FirstStart) {
    expect_advanced(case, who, "freeze", proof.freeze(vec![kit_binding()]).await);
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
