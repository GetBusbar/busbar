// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE config-mutation choke point — `config_transaction`.
//!
//! Every admin operation that mutates the live config plane (hooks, groups, auth chain, settings,
//! overlay, plugins) runs inside `config_transaction`. Before this module the pattern was a raw
//! `CONFIG_MUTATION_LOCK.lock().await` followed by arbitrary handler code, and each of the ~17
//! holders re-derived BY HAND which snapshot to read and what was safe to call inside the section.
//! The prose contract ("held only across the SYNC build+swap+record — never across a network await")
//! was enforced by nothing, and the sites had drifted into four distinct defect classes: a stale
//! pre-lock snapshot (the key cap), a dangling-group bind TOCTOU, synchronous blocking store/disk
//! I/O executed on a Tokio worker while the async lock was held, and plugin install/remove sitting
//! OUTSIDE the section altogether so an install could overwrite the tarball a concurrent rollback
//! had just validated.
//!
//! This module makes all four **inexpressible** rather than "not currently done":
//!
//! 1. **Fresh snapshot is the only snapshot.** `config_transaction` takes the lock and THEN calls
//!    `handle.load()`. The body receives a [`Txn`] and nothing else — no `AppHandle`, no extractor
//!    `Arc<App>`. `txn.app()` IS the post-lock snapshot, so a pre-lock read cannot be performed
//!    inside the section: there is no other snapshot in scope.
//! 2. **The body is SYNCHRONOUS.** `F: FnOnce(&Txn) -> Result<Outcome<T>, AdminError>` has no
//!    `async`, so it cannot `.await`. The "never hold the lock across a network await" contract is
//!    now a type, not a comment — a configure-ack push physically cannot move inside the section.
//! 3. **Blocking work is structurally deferred.** The body never gets a `&dyn Store`, a
//!    `&GovState`, or a filesystem step it can run inline. Store/disk work is handed to
//!    [`Txn::read_store`] / [`Txn::store_write`] as a `FnOnce` that is *stored*, not called;
//!    `config_transaction` is the only caller and it invokes it inside `tokio::task::spawn_blocking`.
//!    A blocking round-trip therefore cannot stall the reactor from inside the critical section.
//! 4. **Atomic mutate → persist → swap, fail-closed.** The body returns a *plan*
//!    ([`Outcome`]), never a `Response`. The single application site is `config_transaction`, which
//!    routes the plan through [`crate::state::AppHandle::commit_and_swap`] (persist first; swap only
//!    if disk took it) while still holding the guard. A body that declares no plan swaps nothing.
//!
//! **Lock order.** `CONFIG_MUTATION_LOCK` is private to this file and is acquired ONLY by
//! `config_transaction`; it is always released last (it is the outermost lock). `EXISTENCE_GATE`
//! (the std `Mutex` serializing key-row check-then-write, `crate::admin::EXISTENCE_GATE`) is only
//! ever taken INSIDE a `spawn_blocking` closure and is never held across an await. There is thus a
//! single global acquisition order (config lock, then existence gate) and no cycle.
//!
//! **Lock hold time.** The apply phase (persist, swap, and every deferred store/disk step) runs on a
//! blocking thread that OWNS the guard, so the lock is held for as long as that work takes. It never
//! parks the reactor (the entire point), but it does extend how long other mutations queue behind a
//! slow store. That is the correct trade: before, the same read held the lock AND parked a worker
//! thread, stalling every request the runtime was serving, not just the other mutations. Config
//! mutations are rare admin operations.
//!
//! **Cancellation.** The guard is moved into that blocking task rather than held by the caller's
//! future, because admin handler futures are DROPPED on a client reset or timeout. See
//! [`config_transaction`] for why a borrowed guard let an abandoned section keep mutating the
//! plugins directory with its lock already released.

use std::sync::Arc;

use crate::admin::v1::contract::AdminError;
use crate::state::{App, AppHandle};

/// Serializes config-plane MUTATIONS so each `read current → build next → persist → swap → record`
/// runs atomically with respect to the others. READS stay lock-free (`handle.load()`), and mutations
/// are rare admin-only operations, so this never touches request-serving latency. Without it, two
/// concurrent mutations both read version N, both build N+1, and one swap is silently lost while the
/// version log gains two divergent N+1 entries.
///
/// PRIVATE TO THIS FILE, deliberately (`static`, no accessor). `lock().await`-then-arbitrary-code
/// cannot be written anywhere else in the tree because no other module can name this symbol —
/// [`config_transaction`] is the only door. `scripts/structure-lint.sh` Invariant 6 fails the build
/// on a second `tokio::sync::Mutex` config lock appearing outside this file.
///
/// Held as an `Arc` so the guard can be `lock_owned()` and MOVED off the caller's future — see
/// [`config_transaction`] on why a borrowed guard made the critical section cancellation-unsafe.
static CONFIG_MUTATION_LOCK: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

/// A durable-persist step, run by `commit_and_swap` BEFORE the swap. It returns the FINAL
/// operator-facing message on failure (each site keeps its own wording), which
/// [`config_transaction`] projects as `AdminError::Validation` — the exact shape the hand-rolled
/// sites returned.
pub(crate) type Persist = Box<dyn FnOnce() -> Result<(), String> + Send>;

/// A deferred blocking step: store I/O, disk I/O, tarball writes. Run on `spawn_blocking`, still
/// under the guard. It returns another [`Outcome`], so a read → decide → write op is ONE atomic
/// section (the count and the mint share the same critical region) while never touching the reactor.
pub(crate) type Deferred<T> = Box<dyn FnOnce() -> Result<Outcome<T>, AdminError> + Send>;

/// The PLAN a transaction body declares. The body returns one of these instead of applying anything
/// itself; `config_transaction` is the sole application site, so "forgot to swap" is a no-op
/// (fail-closed) and "swapped twice" is unrepresentable.
pub(crate) enum Outcome<T> {
    /// Read-only, or a decision already complete: nothing to persist, nothing to swap.
    Value(T),
    /// Mutate: PERSIST-then-SWAP through `AppHandle::commit_and_swap`, fail-closed. A persist error
    /// returns `Err` and swaps NOTHING — the running engine is left exactly as it was.
    Commit {
        next: Arc<App>,
        persist: Persist,
        then: Then<T>,
    },
    /// Blocking work to run on `spawn_blocking` (under the guard), yielding the next `Outcome`.
    Blocking(Deferred<T>),
}

/// What follows a commit. `Value` finishes the transaction; `Blocking` continues with store work
/// that must land AFTER the config change and inside the SAME guard — the mint-with-auto-provision
/// shape: provision the group leaf (persist + swap), then bind the key to it without ever releasing
/// the lock, so a concurrent group DELETE can neither slip between them nor observe a half state.
pub(crate) enum Then<T> {
    Value(T),
    Blocking(Deferred<T>),
}

impl<T> Outcome<T> {
    /// Declare the persist-then-swap plan. `next` is the candidate snapshot; `persist` writes the
    /// DESIRED state to disk and must return the final operator-facing message on failure.
    pub(crate) fn commit<P>(next: Arc<App>, persist: P, value: T) -> Self
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
    {
        Outcome::Commit {
            next,
            persist: Box::new(persist),
            then: Then::Value(value),
        }
    }

    /// Declare a persist-then-swap plan followed by MORE blocking work, all under the one guard.
    /// Used where a config change and a store write must be atomic with each other (`POST /keys`
    /// auto-provisioning a group leaf and then binding the key to it).
    pub(crate) fn commit_then<P, F>(next: Arc<App>, persist: P, then: F) -> Self
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
        F: FnOnce() -> Result<Outcome<T>, AdminError> + Send + 'static,
    {
        Outcome::Commit {
            next,
            persist: Box::new(persist),
            then: Then::Blocking(Box::new(then)),
        }
    }

    /// Declare a plan that swaps WITHOUT persisting (the live-only mutations: `config/apply`,
    /// `config/reload`, `plugins/reload`, `PUT /admin-auth` — each documented as "live until the
    /// next reload/restart returns to disk truth"). Still routed through `commit_and_swap`, with a
    /// no-op persist, so there is exactly one swap site.
    pub(crate) fn swap(next: Arc<App>, value: T) -> Self {
        Outcome::commit(next, || Ok(()), value)
    }

    /// Defer to a blocking thread. Constructed by [`Txn::read_store`] / [`Txn::store_write`] on the
    /// async side, and used directly inside an already-blocking step when it needs a further phase.
    pub(crate) fn blocking<F>(f: F) -> Self
    where
        F: FnOnce() -> Result<Outcome<T>, AdminError> + Send + 'static,
    {
        Outcome::Blocking(Box::new(f))
    }
}

/// The body's ONLY handle to config inside the critical section.
///
/// It deliberately exposes no `AppHandle` (so a body cannot swap out of band, §4 above), no
/// `&dyn Store` and no `&GovState` (so a body cannot run a blocking round-trip on the async thread,
/// §3), and no second snapshot (so a body cannot read a stale pre-lock config, §1).
pub(crate) struct Txn<'a> {
    /// The FRESH, post-lock snapshot. The only config the body can read.
    app: &'a Arc<App>,
}

impl<'a> Txn<'a> {
    /// The fresh post-lock snapshot. There is no other config accessor in scope, so every read a
    /// body performs is coherent with the lock it is holding — by construction, not by discipline.
    pub(crate) fn app(&self) -> &'a Arc<App> {
        self.app
    }

    /// Queue a store READ (and the decision that depends on it). The closure runs LATER, inside
    /// `spawn_blocking`, so it is impossible to park a Tokio worker here; because it runs while the
    /// guard is still held, the read and whatever it decides remain one atomic section.
    ///
    /// The closure captures OWNED values (it is `'static`), so it cannot smuggle `txn.app()` out —
    /// a body that needs the snapshot on the blocking side clones the `Arc` into the closure, which
    /// is the same snapshot, still frozen by the same lock.
    pub(crate) fn read_store<T, F>(&self, f: F) -> Outcome<T>
    where
        F: FnOnce() -> Result<Outcome<T>, AdminError> + Send + 'static,
    {
        Outcome::blocking(f)
    }

    /// Queue a store/filesystem WRITE (key mint, group rebind, plugin tarball, overlay rebuild).
    /// Same execution site and same guarantees as [`Txn::read_store`]; named separately so a call
    /// site reads as what it is. Fail-closed: an error from the closure aborts the transaction and
    /// nothing is swapped.
    pub(crate) fn store_write<T, F>(&self, f: F) -> Outcome<T>
    where
        F: FnOnce() -> Result<Outcome<T>, AdminError> + Send + 'static,
    {
        Outcome::blocking(f)
    }

    /// Declare the persist-then-swap plan (see [`Outcome::commit`]).
    pub(crate) fn commit<T, P>(&self, next: Arc<App>, persist: P, value: T) -> Outcome<T>
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
    {
        Outcome::commit(next, persist, value)
    }

    /// Declare a live-only swap with no durable persist (see [`Outcome::swap`]). Named
    /// `live_swap`, not `swap`, so the structure lint can ban the bare `.swap(` receiver form
    /// OUTRIGHT outside `txn.rs`/`state.rs` instead of carving out an exception for whichever
    /// variable name a transaction body happens to bind the `Txn` to.
    pub(crate) fn live_swap<T>(&self, next: Arc<App>, value: T) -> Outcome<T> {
        Outcome::swap(next, value)
    }

    // Exercised by the class-level harness (`tests/txn_tests.rs`); production bodies today all
    // declare a plan or defer, so this is dead outside a test build.
    #[cfg_attr(not(test), allow(dead_code))]
    /// Finish with a value and NO mutation (an idempotent no-op, or a decision that changed
    /// nothing). Fail-closed by construction: no plan ⇒ no swap.
    pub(crate) fn done<T>(&self, value: T) -> Outcome<T> {
        Outcome::Value(value)
    }
}

/// **The one door.** Acquire the config-plane mutation lock, hand `body` a FRESH post-lock snapshot,
/// run its (synchronous) decision, then hand the guard AND the whole apply phase to one blocking
/// task that runs `commit_and_swap` plus every deferred step to completion.
///
/// The four numbered steps below are the four guarantees in the module docs.
///
/// **Why the apply phase is one blocking task and not an `await` loop.** Admin handlers ARE
/// cancellable: each connection is served by its own task (`serve_connection_with_upgrades`), so a
/// client reset, disconnect, or timeout DROPS the service future wherever it is suspended. A guard
/// borrowed from a `static` and held across `spawn_blocking(f).await` dies with that future —
/// while the blocking task keeps running, because dropping a `JoinHandle` does NOT cancel a blocking
/// task. The critical section would then be executing with its lock RELEASED: a concurrent
/// `rollback_plugin` / `reload_plugins` could take the domain and `rebuild_app_from_disk` over a
/// plugins directory that the abandoned `install_plugin` was still writing into — exactly the hazard
/// this choke point exists to make impossible.
///
/// Moving the guard into the blocking task closes it BY CONSTRUCTION: the task OWNS the guard
/// (`lock_owned`), nothing can cancel it, and the domain is released only when the last deferred
/// step returns. Cancelling the caller now abandons only the RESULT, never the section. There is no
/// await between taking the lock and handing it over, so cancellation can only strike before any
/// mutation has begun (harmless) or after the section is already self-driving.
///
/// It also takes `commit_and_swap` off the reactor. Its persist step is real disk work — an overlay
/// read-modify-write plus two fsyncs — which the previous shape ran inline on a Tokio worker while
/// the lock was held, the same class of stall §3 defers store reads to avoid.
pub(crate) async fn config_transaction<F, T>(
    handle: &Arc<AppHandle>,
    body: F,
) -> Result<T, AdminError>
where
    // NOTE: SYNC. The body cannot `.await`, so it cannot hold the lock across a network await and
    // cannot inline a blocking store call that would park a worker under the lock.
    F: FnOnce(&Txn<'_>) -> Result<Outcome<T>, AdminError>,
    T: Send + 'static,
{
    // (1) the ONLY lock site in the tree. Owned, so the guard can outlive this future.
    let guard = Arc::clone(&CONFIG_MUTATION_LOCK).lock_owned().await;
    let snapshot = handle.load(); // (2) FRESH post-lock read — the body's only config
    let outcome = body(&Txn { app: &snapshot })?; // (3) synchronous decision → a plan
    let handle = Arc::clone(handle);
    // (4) apply the plan — atomic mutate → persist → swap, then any deferred steps — on ONE blocking
    // thread that owns the guard. A panic in the section is a JoinError, mapped fail-closed.
    tokio::task::spawn_blocking(move || {
        let _guard = guard; // dropped here, and ONLY here: when the section is genuinely over
        apply(&handle, outcome)
    })
    .await
    .map_err(|_| AdminError::Internal)?
}

/// Drive a plan to a value. Entirely synchronous: `commit_and_swap` and every deferred step are
/// blocking calls, and this runs on the blocking thread `config_transaction` hands the guard to, so
/// the whole section is one uninterruptible unit of work.
fn apply<T>(handle: &Arc<AppHandle>, mut outcome: Outcome<T>) -> Result<T, AdminError> {
    loop {
        match outcome {
            Outcome::Value(value) => return Ok(value),
            Outcome::Commit {
                next,
                persist,
                then,
            } => {
                handle
                    .commit_and_swap(next, persist)
                    .map_err(AdminError::Validation)?;
                match then {
                    Then::Value(value) => return Ok(value),
                    // Same guard, same thread: the follow-on store write cannot interleave with any
                    // other config mutation.
                    Then::Blocking(f) => outcome = Outcome::Blocking(f),
                }
            }
            Outcome::Blocking(f) => outcome = f()?,
        }
    }
}

#[cfg(test)]
#[path = "tests/txn_tests.rs"]
mod txn_tests;

// §5.3.4: THE COMPILE FENCE — a module that must NOT type-check. Behind the `txn-fence-red`
// feature; `scripts/txn-fence.sh` compiles it and asserts the compiler rejects it. See the file
// header for why this is an in-crate negative build rather than a `trybuild` ui case.
#[cfg(feature = "txn-fence-red")]
#[path = "tests/txn_fence.rs"]
mod txn_fence;

// §5.5: the targeted loom model of the swap lost-update invariant. Behind the OPTIONAL `loom-model`
// feature, so it is compiled ONLY by `scripts/loom.sh`, never by a normal build or CI test run.
#[cfg(all(test, feature = "loom-model"))]
#[path = "tests/txn_loom.rs"]
mod txn_loom;
