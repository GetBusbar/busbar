// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ONE EXIT PATH (FIRST-START-TAKEOVER §2.7). A process that owns an unpublished first start
//! and leaves on purpose (a boot refusal, a signal before the listener, a one-shot command, the
//! end of `main`) first retires its own writer row, bounded and best-effort, so the next start of
//! the dataset takes over at once instead of waiting out the stall window. Only exits that run no
//! code (crash, SIGKILL, OOM, panic, hang) pay the window. A clippy rule keeps every other exit
//! call out of this crate.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use busbar_kernel::diagnostics::{FIRST_START_EXIT_RETIRED, FIRST_START_EXIT_RETIRE_FAILED};
use busbar_kernel::persistence::facade::CoreStore;
use busbar_kernel::persistence::first_start::{Abandoned, FirstStart};
use busbar_kernel::persistence::startup::{writer_hex, FIRST_START_STALL, READY_STEP};

static FIRST_START: OnceLock<Arc<FirstStart>> = OnceLock::new();

/// The longest an exit waits for the store to confirm the hand-over.
pub const EXIT_RETIRE_BUDGET: Duration = Duration::from_secs(5);

/// The status of an exit on SIGTERM, SIGINT or a console close: 128 + SIGTERM.
pub(crate) const EXIT_SIGNALLED: i32 = 143;

/// Right after Store admission: arm the exit path if this process owns a first start.
pub fn arm(store: &CoreStore) {
    if let Some(first_start) = store.first_start() {
        let _ = FIRST_START.set(first_start);
    }
}

/// Exit with `code`, handing an unpublished first start over first.
pub fn exit(code: i32) -> ! {
    if let Some(first_start) = FIRST_START.get() {
        hand_over(first_start);
    }
    std::process::exit(code);
}

/// Before the migrate-on-boot seam re-executes this process onto the upgraded config.yaml
/// (MIGRATE-ON-BOOT r42 §3 step 5): an exec leaves this image on purpose, so an armed first start
/// is handed over exactly as [`exit`] hands it over, and the new image takes over at once instead
/// of waiting out the stall window.
pub(crate) fn hand_over_before_exec() {
    if let Some(first_start) = FIRST_START.get() {
        hand_over(first_start);
    }
}

/// The first statement of `run`: until the listener's own handler owns signals, SIGTERM, SIGINT
/// and a console close exit through [`exit`] (status 143), so an armed owner hands over. Send on
/// the returned handoff (or drop it) once the listener's handler is installed.
pub(crate) fn exit_on_signal() -> tokio::sync::oneshot::Sender<()> {
    exit_on(crate::shutdown_signal(), |code| exit(code))
}

fn exit_on<S, L>(signal: S, leave: L) -> tokio::sync::oneshot::Sender<()>
where
    S: Future<Output = ()> + Send + 'static,
    L: FnOnce(i32) + Send + 'static,
{
    let (handoff, released) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        tokio::select! {
            biased;
            _ = released => {}
            () = signal => leave(EXIT_SIGNALLED),
        }
    });
    handoff
}

/// Retire `first_start`'s writer (bounded) and report the outcome on this thread.
fn hand_over(first_start: &Arc<FirstStart>) {
    report(first_start, retire_on_exit(first_start.clone()));
}

/// What the hand-over did, or why it did not finish.
enum Outcome {
    Done(Abandoned),
    Failed(String),
}

/// Drive `abandon` on a helper thread with its own runtime (the dying thread may be inside the
/// control runtime and cannot drive async work), bounded by [`EXIT_RETIRE_BUDGET`].
fn retire_on_exit(first_start: Arc<FirstStart>) -> Outcome {
    let (sent, received) = std::sync::mpsc::channel();
    let helper = std::thread::Builder::new()
        .name("busbar-exit-retire".into())
        .spawn(move || {
            let outcome = match busbar_kernel::rt::current_thread().enable_all().build() {
                Ok(runtime) => runtime.block_on(async {
                    match tokio::time::timeout(EXIT_RETIRE_BUDGET, first_start.abandon()).await {
                        Ok(Ok(abandoned)) => Outcome::Done(abandoned),
                        Ok(Err(error)) => Outcome::Failed(format!("refused: {error:?}")),
                        Err(_) => Outcome::Failed("the store did not answer in time".into()),
                    }
                }),
                Err(error) => Outcome::Failed(format!("no runtime: {error}")),
            };
            let _ = sent.send(outcome);
        });
    match helper {
        Ok(_) => received
            .recv_timeout(EXIT_RETIRE_BUDGET + Duration::from_secs(1))
            .unwrap_or_else(|_| Outcome::Failed("the store did not answer in time".into())),
        Err(error) => Outcome::Failed(format!("no helper thread: {error}")),
    }
}

/// Emitted on the exiting thread, outside any runtime, after the helper joined.
fn report(first_start: &FirstStart, outcome: Outcome) {
    let writer = writer_hex(&first_start.owner());
    match outcome {
        Outcome::Done(Abandoned::Retired) => tracing::info!(
            diag = %FIRST_START_EXIT_RETIRED.banner(),
            writer = %writer,
            "first start handed over on exit: writer {writer} retired; the next start of this \
             dataset takes over at once"
        ),
        Outcome::Done(Abandoned::Published | Abandoned::NotAdmitted) => {}
        Outcome::Done(Abandoned::Unconfirmed) => failed(&writer, "outcome unknown"),
        Outcome::Failed(reason) => failed(&writer, &reason),
    }
}

fn failed(writer: &str, reason: &str) {
    tracing::warn!(
        diag = %FIRST_START_EXIT_RETIRE_FAILED.banner(),
        writer = %writer,
        reason = %reason,
        "first start not handed over ({reason}); the next start of this dataset waits up to {} s, \
         plus {} s per plane already done",
        FIRST_START_STALL.as_secs(),
        READY_STEP.as_secs(),
    );
}

#[cfg(test)]
#[path = "tests/exit.rs"]
mod tests;
