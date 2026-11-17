// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! T13 (FIRST-START-TAKEOVER §2.7, §8): the exit hand-over drives a dispatcher-backed store from a
//! thread whose `current_thread` runtime is blocked, as `exit` does from any exit site, and the
//! signal exit hands over before it leaves. `process::exit` is replaced by returning the outcome.

use super::*;
use std::time::Instant;

/// Everything the hand-over logs on this thread, as the fmt layer prints it.
#[derive(Clone, Default)]
struct Captured(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn install(&self) -> tracing::subscriber::DefaultGuard {
        let writer = self.clone();
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .with_writer(move || writer.clone())
                .finish(),
        )
    }
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
    fn count(&self, diagnostic: &busbar_contract::diagnostic::Diagnostic) -> usize {
        self.text()
            .matches(&format!("diag={}", diagnostic.banner()))
            .count()
    }
}

/// A first-start owner over the dispatcher-backed product store: admitted on an empty dataset,
/// unpublished, holding its `FirstStart`, as `arm` finds it right after admission.
async fn owner(
    backend: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
) -> (Arc<CoreStore>, Arc<FirstStart>) {
    let store = crate::root::real_store::core_over(backend).await;
    let first_start = store
        .first_start()
        .expect("an admission on an empty dataset owns its first start");
    (store, first_start)
}

#[tokio::test]
async fn t13_the_hand_over_retires_the_writer_from_a_blocked_current_thread_runtime() {
    let captured = Captured::default();
    let _guard = captured.install();
    let (_store, first_start) = owner(crate::root::real_store::native_backend().await).await;

    // Synchronous, on this runtime's only thread, as every exit site calls it.
    let started = Instant::now();
    let outcome = retire_on_exit(first_start.clone());
    let took = started.elapsed();
    assert!(
        matches!(outcome, Outcome::Done(Abandoned::Retired)),
        "the hand-over retires the writer"
    );
    assert!(took < EXIT_RETIRE_BUDGET, "the hand-over took {took:?}");
    report(&first_start, outcome);
    assert_eq!(
        captured.count(&FIRST_START_EXIT_RETIRED),
        1,
        "{}",
        captured.text()
    );
    assert_eq!(
        captured.count(&FIRST_START_EXIT_RETIRE_FAILED),
        0,
        "{}",
        captured.text()
    );

    // The writer row no longer admits this writer: a second hand-over finds nothing to retire.
    assert_eq!(first_start.abandon().await, Ok(Abandoned::NotAdmitted));
}

#[tokio::test]
async fn t13_a_store_that_never_answers_costs_the_budget_and_leaves_the_writer_open() {
    let captured = Captured::default();
    let _guard = captured.install();
    let faults = crate::root::store_double::NativeFaults::over(
        crate::root::real_store::native_backend().await,
    );
    let (_store, first_start) = owner(faults.clone()).await;

    faults.pause(true);
    let started = Instant::now();
    let outcome = retire_on_exit(first_start.clone());
    let took = started.elapsed();
    assert!(
        matches!(outcome, Outcome::Failed(_)),
        "an unanswered retire is not a hand-over"
    );
    assert!(
        took >= EXIT_RETIRE_BUDGET && took < EXIT_RETIRE_BUDGET + Duration::from_secs(2),
        "the hand-over returns after its budget, took {took:?}"
    );
    report(&first_start, outcome);
    assert_eq!(
        captured.count(&FIRST_START_EXIT_RETIRE_FAILED),
        1,
        "{}",
        captured.text()
    );
    assert_eq!(
        captured.count(&FIRST_START_EXIT_RETIRED),
        0,
        "{}",
        captured.text()
    );

    // Nothing was written: once the store answers again, the writer row still admits and the
    // retire applies now.
    faults.pause(false);
    assert_eq!(first_start.abandon().await, Ok(Abandoned::Retired));
}

#[tokio::test]
async fn t13_a_signal_before_the_listener_hands_over_and_leaves_with_143() {
    let captured = Captured::default();
    let _guard = captured.install();
    let (_store, first_start) = owner(crate::root::real_store::native_backend().await).await;

    let (left, code) = tokio::sync::oneshot::channel();
    let armed = first_start.clone();
    let _handoff = exit_on(std::future::ready(()), move |code| {
        hand_over(&armed);
        let _ = left.send(code);
    });
    assert_eq!(code.await, Ok(EXIT_SIGNALLED));
    assert_eq!(
        captured.count(&FIRST_START_EXIT_RETIRED),
        1,
        "{}",
        captured.text()
    );
    assert_eq!(first_start.abandon().await, Ok(Abandoned::NotAdmitted));
}

#[tokio::test]
async fn t13_a_signal_after_the_handoff_leaves_the_exit_to_the_listener() {
    let captured = Captured::default();
    let _guard = captured.install();
    let (_store, first_start) = owner(crate::root::real_store::native_backend().await).await;

    let (signal, signalled) = tokio::sync::oneshot::channel::<()>();
    let (left, code) = tokio::sync::oneshot::channel::<i32>();
    let armed = first_start.clone();
    let handoff = exit_on(
        async move {
            let _ = signalled.await;
        },
        move |code| {
            hand_over(&armed);
            let _ = left.send(code);
        },
    );
    handoff
        .send(())
        .expect("the early handler is still listening");
    let _ = signal.send(());
    // The early handler ends on the handoff and drops its exit path unused.
    assert!(code.await.is_err(), "no exit after the handoff");
    assert_eq!(
        captured.count(&FIRST_START_EXIT_RETIRED),
        0,
        "{}",
        captured.text()
    );
    // Nothing was retired: the writer row still admits this owner.
    assert_eq!(first_start.abandon().await, Ok(Abandoned::Retired));
}

/// DES-334 D1: docs/operations.md "Exit statuses" lists exactly the statuses the process exits
/// with, each bound to its named constant: 0 (retired), 75, 70 and 143, in that order.
#[test]
fn operations_doc_exit_statuses_match_the_exit_constants() {
    use busbar_kernel::governance::drain::{EXIT_SPEND_SAVED_STREAMS_CUT, EXIT_SPEND_UNSAVED};
    const OPERATIONS: &str = include_str!("../../../../../docs/operations.md");
    let section = OPERATIONS
        .split_once("\n### Exit statuses\n")
        .expect("docs/operations.md has an \"Exit statuses\" section")
        .1;
    let section = section.split("\n#").next().unwrap_or(section);
    let rows: Vec<(i32, &str)> = section
        .lines()
        .filter_map(|line| {
            let mut cells = line.strip_prefix('|')?.split('|').map(str::trim);
            let status = cells.next()?.parse().ok()?;
            Some((status, cells.next()?))
        })
        .collect();
    let want: [(i32, &str); 4] = [
        (0, "Clean: the writer retired"),
        (
            EXIT_SPEND_SAVED_STREAMS_CUT,
            "Spend saved; open streams were cut; the writer was not retired",
        ),
        (
            EXIT_SPEND_UNSAVED,
            "Spend not persisted (`unpersisted` or `in_doubt` non-empty at the cut)",
        ),
        (EXIT_SIGNALLED, "Signalled before the listener came up"),
    ];
    assert_eq!(
        rows, want,
        "the documented exit statuses drifted from the code"
    );
}
