// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The ONE config-mutation choke point — `config_transaction`.
//!
//! RELOCATED out of `admin/v1/json/txn.rs` (1.6.0 de-alias, stage 2a): this is core config-apply
//! infrastructure, not admin-surface vocabulary — `auth::self_keys` (core, the self-serve
//! token-exchange seam) routes its personal-budget-group auto-provision through this SAME choke
//! point the admin mint uses, and a core module reaching into `admin::` to do that was the last
//! core→admin edge this stage exists to cut. GENERICIZED over the error type `E` (was hard-coded to
//! `admin::v1::contract::AdminError`) so this module names no admin type: every admin call site
//! still resolves `E = AdminError` by ordinary type inference (its closures construct
//! `AdminError::…` directly), and `auth::self_keys` resolves `E` to its own neutral error. The two
//! error constructions this module makes ITSELF (a `commit_and_swap` persist failure, and a
//! `spawn_blocking` join failure) go through [`TxnError`] + `E: From<TxnError>`, so every existing
//! call site's wire error is byte-identical (`AdminError` implements that conversion 1:1).
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
//! 2. **The body is SYNCHRONOUS.** `F: FnOnce(&Txn) -> Result<Outcome<T, E>, E>` has no
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
//!    Rebuilt generations also confirm their price candidate and activation before pointer
//!    publication. If prices refuse after config persistence, durable desired config remains in
//!    its Store and the old carrier requires explicit reload; there is no cross-Store rollback.
//!
//! **Lock order.** `CONFIG_MUTATION_LOCK` is private to this file and is acquired ONLY by
//! `config_transaction`; it is always released last (it is the outermost lock). `EXISTENCE_GATE`
//! (the per-key-id claim serializing key-row check-then-write in the admin crate) is only ever
//! claimed INSIDE a `spawn_blocking` closure and is never held across an await. There is thus a
//! single global acquisition order (config lock, then existence claim) and no cycle.
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

use crate::state::{App, AppHandle};

static CONFIG_MUTATION_LOCK: std::sync::LazyLock<Arc<tokio::sync::Mutex<()>>> =
    std::sync::LazyLock::new(|| Arc::new(tokio::sync::Mutex::new(())));

#[derive(Clone, Copy, PartialEq, Eq)]
enum TransactionMode {
    Mutation,
    Reload,
}

/// The two error shapes `config_transaction`'s OWN machinery can produce (never a call site's own
/// domain error, which rides the generic `E` untouched): a durable-persist failure
/// (`commit_and_swap`, message pre-formatted by the site's own `Persist` closure) and a
/// `spawn_blocking` join failure (a panic in the apply phase). Every instantiating error type `E`
/// converts FROM this via `E: From<TxnError>`, so each call site's wire error is exactly what it was
/// before this module was generic (e.g. `AdminError::Validation`/`AdminError::Internal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxnError {
    /// A `commit_and_swap` persist step failed; `String` is the final operator-facing message the
    /// site's own `Persist` closure produced.
    Validation(String),
    /// A TERMINAL state conflict surfaced by the extracted governance logic that shares this
    /// machinery (e.g. group auto-provisioning's re-home/base-shadow guards).
    Conflict(String),
    /// The apply phase's `spawn_blocking` task panicked (a `JoinError`) rather than returning.
    Internal,
}

impl TxnError {
    pub fn message(&self) -> String {
        match self {
            TxnError::Validation(msg) => msg.clone(),
            TxnError::Conflict(msg) => msg.clone(),
            TxnError::Internal => "internal error".to_string(),
        }
    }
}

pub type Persist = Box<dyn FnOnce() -> Result<(), String> + Send>;

pub type Deferred<T, E> = Box<dyn FnOnce() -> Result<Outcome<T, E>, E> + Send>;

pub enum Outcome<T, E> {
    Value(T),

    Commit {
        next: Arc<App>,
        persist: Persist,
        rates: Option<Box<(crate::appbuild::InstalledLimits, String)>>,
        then: Then<T, E>,
    },

    Blocking(Deferred<T, E>),
}

pub enum Then<T, E> {
    Value(T),
    Blocking(Deferred<T, E>),
}

impl<T, E> Outcome<T, E> {
    pub fn commit<P>(next: Arc<App>, persist: P, value: T) -> Self
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
    {
        Outcome::Commit {
            next,
            persist: Box::new(persist),
            rates: None,
            then: Then::Value(value),
        }
    }

    pub fn commit_then<P, F>(next: Arc<App>, persist: P, then: F) -> Self
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
        F: FnOnce() -> Result<Outcome<T, E>, E> + Send + 'static,
    {
        Outcome::Commit {
            next,
            persist: Box::new(persist),
            rates: None,
            then: Then::Blocking(Box::new(then)),
        }
    }

    pub fn commit_rates_then<P, F>(
        next: Arc<App>,
        persist: P,
        limits: crate::appbuild::InstalledLimits,
        origin: String,
        then: F,
    ) -> Self
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
        F: FnOnce() -> Result<Outcome<T, E>, E> + Send + 'static,
    {
        Outcome::Commit {
            next,
            persist: Box::new(persist),
            rates: Some(Box::new((limits, origin))),
            then: Then::Blocking(Box::new(then)),
        }
    }

    pub fn swap(next: Arc<App>, value: T) -> Self {
        Outcome::commit(next, || Ok(()), value)
    }

    pub fn blocking<F>(f: F) -> Self
    where
        F: FnOnce() -> Result<Outcome<T, E>, E> + Send + 'static,
    {
        Outcome::Blocking(Box::new(f))
    }
}

pub struct Txn<'a> {
    app: &'a Arc<App>,
}

impl<'a> Txn<'a> {
    pub fn app(&self) -> &'a Arc<App> {
        self.app
    }

    pub fn read_store<T, E, F>(&self, f: F) -> Outcome<T, E>
    where
        F: FnOnce() -> Result<Outcome<T, E>, E> + Send + 'static,
    {
        Outcome::blocking(f)
    }

    pub fn store_write<T, E, F>(&self, f: F) -> Outcome<T, E>
    where
        F: FnOnce() -> Result<Outcome<T, E>, E> + Send + 'static,
    {
        Outcome::blocking(f)
    }

    pub fn commit<T, E, P>(&self, next: Arc<App>, persist: P, value: T) -> Outcome<T, E>
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
    {
        Outcome::commit(next, persist, value)
    }

    pub fn live_swap<T, E>(&self, next: Arc<App>, value: T) -> Outcome<T, E> {
        Outcome::swap(next, value)
    }

    #[cfg_attr(not(test), allow(dead_code))]

    pub fn done<T, E>(&self, value: T) -> Outcome<T, E> {
        Outcome::Value(value)
    }
}

pub async fn config_transaction<F, T, E>(handle: &Arc<AppHandle>, body: F) -> Result<T, E>
where
    F: FnOnce(&Txn<'_>) -> Result<Outcome<T, E>, E>,
    T: Send + 'static,
    E: From<TxnError> + Send + 'static,
{
    run_transaction(handle, body, TransactionMode::Mutation).await
}

pub async fn config_reload_transaction<F, T, E>(handle: &Arc<AppHandle>, body: F) -> Result<T, E>
where
    F: FnOnce(&Txn<'_>) -> Result<Outcome<T, E>, E>,
    T: Send + 'static,
    E: From<TxnError> + Send + 'static,
{
    run_transaction(handle, body, TransactionMode::Reload).await
}

async fn run_transaction<F, T, E>(
    handle: &Arc<AppHandle>,
    body: F,
    mode: TransactionMode,
) -> Result<T, E>
where
    F: FnOnce(&Txn<'_>) -> Result<Outcome<T, E>, E>,
    T: Send + 'static,
    E: From<TxnError> + Send + 'static,
{
    let guard = Arc::clone(&CONFIG_MUTATION_LOCK).lock_owned().await;
    let snapshot = handle.load();
    if mode == TransactionMode::Mutation {
        if let Some(overlay) = &snapshot.overlay_path {
            overlay
                .ensure_published()
                .map_err(|msg| E::from(TxnError::Validation(msg)))?;
        }
    }
    let outcome = body(&Txn { app: &snapshot })?;
    let handle = Arc::clone(handle);

    tokio::task::spawn_blocking(move || {
        let result = apply(&handle, outcome, mode);
        drop(guard);
        crate::export::plugin::refresh_pending();
        result
    })
    .await
    .map_err(|_| E::from(TxnError::Internal))?
}

fn apply<T, E>(
    handle: &Arc<AppHandle>,
    mut outcome: Outcome<T, E>,
    mode: TransactionMode,
) -> Result<T, E>
where
    E: From<TxnError>,
{
    loop {
        match outcome {
            Outcome::Value(value) => return Ok(value),
            Outcome::Commit {
                next,
                persist,
                rates,
                then,
            } => {
                match rates {
                    Some(rates) => {
                        let (limits, origin) = *rates;
                        match mode {
                            TransactionMode::Mutation => {
                                handle.commit_rates_and_swap(next, persist, limits, &origin)
                            }
                            TransactionMode::Reload => {
                                handle.reload_rates_and_swap(next, persist, limits, &origin)
                            }
                        }
                    }
                    None => handle.commit_and_swap(next, persist),
                }
                .map_err(|msg| E::from(TxnError::Validation(msg)))?;
                match then {
                    Then::Value(value) => return Ok(value),

                    Then::Blocking(f) => outcome = Outcome::Blocking(f),
                }
            }
            Outcome::Blocking(f) => outcome = f()?,
        }
    }
}

#[cfg(txn_fence_red)]
#[path = "tests/txn_fence.rs"]
mod txn_fence;

#[cfg(all(test, feature = "loom-model"))]
#[path = "tests/txn_loom.rs"]
mod txn_loom;
