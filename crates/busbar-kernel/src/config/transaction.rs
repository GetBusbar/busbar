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
//! 2. **Planning is synchronous.** The body returns a deferred effect. Native persistence
//!    futures are awaited during application, under the configuration mutation guard.
//!    Authority is checked before effects; committed work finishes custody after revocation.
//! 3. **Blocking work is deferred.** Legacy callbacks execute on blocking workers, with a
//!    fresh authority check after queue admission. Native persistence uses [`Txn::store_write_async`]
//!    and never occupies a blocking worker for a Store round trip.
//! 4. **Atomic mutate → persist → swap, fail-closed.** The body returns a *plan*
//!    ([`Outcome`]), never a `Response`. The single application site is `config_transaction`, which
//!    routes the plan through [`crate::state::AppHandle::commit_and_swap`] (persist first; swap only
//!    if disk took it) while still holding the guard. A body that declares no plan swaps nothing.
//!    Rebuilt generations also confirm their price candidate and activation before pointer
//!    publication. If prices refuse after config persistence, durable desired config remains in
//!    its Store and the old carrier requires explicit reload; there is no cross-Store rollback.
//!
//! **Lock order.** Configuration mutation holds the outer async config guard before acquiring
//! governance's async identity guard. Store-only identity effects never acquire the config guard.
//!
//! **Cancellation.** An owned task retains the configuration guard through deferred effects and
//! publication even when the request future is dropped. Native persistence retains uncertain
//! attempts in CoreStore; a failed persistence result never authorizes pointer publication.

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
    /// Current authority no longer admits this effect. No mutation has started.
    Forbidden,
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
            TxnError::Forbidden => "current authority does not admit this effect".into(),
            TxnError::Conflict(msg) => msg.clone(),
            TxnError::Internal => "internal error".to_string(),
        }
    }
}

pub type Persist = Box<dyn FnOnce() -> Result<(), String> + Send>;
pub type AsyncPersist =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send>>;

pub type Deferred<T, E> = Box<dyn FnOnce() -> Result<Outcome<T, E>, E> + Send>;

pub type AsyncDeferred<T, E> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Outcome<T, E>, E>> + Send>>;

pub enum Outcome<T, E> {
    Value(T),

    Commit {
        next: Arc<App>,
        persist: Persist,
        rates: Option<Box<(crate::appbuild::InstalledLimits, String)>>,
        then: Then<T, E>,
    },

    Blocking(Deferred<T, E>),
    Async(AsyncDeferred<T, E>),
    CommitAsync {
        next: Arc<App>,
        persist: AsyncPersist,
        rates: Option<Box<(crate::appbuild::InstalledLimits, String)>>,
        then: AsyncDeferred<T, E>,
    },
}

pub enum Then<T, E> {
    Value(T),
    Blocking(Deferred<T, E>),
    Async(AsyncDeferred<T, E>),
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

    pub fn commit_then_async<P, F>(next: Arc<App>, persist: P, then: F) -> Self
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
        F: std::future::Future<Output = Result<Outcome<T, E>, E>> + Send + 'static,
    {
        Outcome::Commit {
            next,
            persist: Box::new(persist),
            rates: None,
            then: Then::Async(Box::pin(then)),
        }
    }

    pub fn asynchronous<F>(future: F) -> Self
    where
        F: std::future::Future<Output = Result<Outcome<T, E>, E>> + Send + 'static,
    {
        Outcome::Async(Box::pin(future))
    }

    /// Persist natively before publishing the new configuration. A failed or uncertain
    /// persistence answer leaves publication unchanged and remains in Store custody.
    pub fn commit_async_then<P, F>(next: Arc<App>, persist: P, then: F) -> Self
    where
        P: std::future::Future<Output = Result<(), String>> + Send + 'static,
        F: std::future::Future<Output = Result<Outcome<T, E>, E>> + Send + 'static,
    {
        Outcome::CommitAsync {
            next,
            persist: Box::pin(persist),
            rates: None,
            then: Box::pin(then),
        }
    }

    pub fn commit_async<P>(next: Arc<App>, persist: P, value: T) -> Self
    where
        T: Send + 'static,
        E: Send + 'static,
        P: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        Self::commit_async_then(next, persist, async move { Ok(Self::Value(value)) })
    }

    pub fn commit_rates_async_then<P, F>(
        next: Arc<App>,
        persist: P,
        limits: crate::appbuild::InstalledLimits,
        origin: String,
        then: F,
    ) -> Self
    where
        T: Send + 'static,
        E: Send + 'static,
        P: std::future::Future<Output = Result<(), String>> + Send + 'static,
        F: std::future::Future<Output = Result<Outcome<T, E>, E>> + Send + 'static,
    {
        Self::CommitAsync {
            next,
            persist: Box::pin(persist),
            rates: Some(Box::new((limits, origin))),
            then: Box::pin(then),
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

    pub fn store_write_async<T, E, F>(&self, future: F) -> Outcome<T, E>
    where
        F: std::future::Future<Output = Result<Outcome<T, E>, E>> + Send + 'static,
    {
        Outcome::asynchronous(future)
    }

    pub fn commit<T, E, P>(&self, next: Arc<App>, persist: P, value: T) -> Outcome<T, E>
    where
        P: FnOnce() -> Result<(), String> + Send + 'static,
    {
        Outcome::commit(next, persist, value)
    }

    pub fn commit_async<T, E, P>(&self, next: Arc<App>, persist: P, value: T) -> Outcome<T, E>
    where
        T: Send + 'static,
        E: Send + 'static,
        P: std::future::Future<Output = Result<(), String>> + Send + 'static,
    {
        Outcome::commit_async(next, persist, value)
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
    let context = crate::auth::effect::current();
    let guard = admit_effect(handle, context.as_ref())
        .await
        .map_err(E::from)?;
    let snapshot = handle.load();
    if mode == TransactionMode::Mutation {
        if let Some(overlay) = &snapshot.overlay_path {
            overlay
                .ensure_published()
                .map_err(|msg| E::from(TxnError::Validation(msg)))?;
        }
    }
    let outcome =
        super::security_policy::scoped(guard.authority, || body(&Txn { app: &snapshot }))?;
    let handle = Arc::clone(handle);

    tokio::spawn(crate::auth::effect::scope(context.clone(), async move {
        let result = apply(&handle, outcome, mode, context.as_ref(), guard.authority).await;
        drop(guard);
        crate::export::plugin::refresh_pending();
        result
    }))
    .await
    .map_err(|_| E::from(TxnError::Internal))?
}

async fn apply<T, E>(
    handle: &Arc<AppHandle>,
    mut outcome: Outcome<T, E>,
    mode: TransactionMode,
    context: Option<&crate::auth::effect::Context>,
    mut authority: Option<crate::auth::effect::Authority>,
) -> Result<T, E>
where
    T: Send + 'static,
    E: From<TxnError> + Send + 'static,
{
    let mut committed = false;
    loop {
        // spawn_blocking itself may queue. Recheck on its worker before the first Store/disk
        // step, and again before publication after a read/build. Once committed, finish custody
        // and preserve the receipt even if a provider revokes this credential during completion.
        if !committed && !matches!(outcome, Outcome::Value(_)) {
            if let Some(context) = context {
                authority = Some(context.revalidate(&handle.load()).await.map_err(E::from)?);
            }
        }
        match outcome {
            Outcome::Value(value) => return Ok(value),
            Outcome::Commit {
                next,
                persist,
                rates,
                then,
            } => {
                let expected = handle.load();
                let worker_handle = Arc::clone(handle);
                let worker_next = next.clone();
                let worker_context = context.cloned();
                authority = tokio::task::spawn_blocking(move || {
                    let authority = if !committed {
                        match &worker_context {
                            Some(context) => Some(
                                tokio::runtime::Handle::current()
                                    .block_on(context.revalidate(&worker_handle.load()))
                                    .map_err(E::from)?,
                            ),
                            None => authority,
                        }
                    } else {
                        authority
                    };
                    super::security_policy::admit(
                        &worker_handle.load(),
                        &worker_next,
                        worker_context.as_ref(),
                        authority,
                    )
                    .map_err(E::from)?;
                    super::security_policy::scoped(authority, || {
                        persist().map_err(|message| E::from(TxnError::Validation(message)))
                    })?;
                    Ok::<_, E>(authority)
                })
                .await
                .map_err(|_| E::from(TxnError::Internal))??;
                if !Arc::ptr_eq(&expected, &handle.load()) {
                    if let Some(overlay) = &expected.overlay_path {
                        overlay.require_reload();
                    }
                    return Err(E::from(TxnError::Conflict(
                        "App generation changed during persistence; reload before retrying".into(),
                    )));
                }
                match rates {
                    Some(rates) => {
                        let (limits, origin) = *rates;
                        match mode {
                            TransactionMode::Mutation => {
                                handle
                                    .commit_rates_and_swap(next, || Ok(()), limits, &origin)
                                    .await
                            }
                            TransactionMode::Reload => {
                                handle
                                    .reload_rates_and_swap(next, || Ok(()), limits, &origin)
                                    .await
                            }
                        }
                        .map_err(|message| E::from(TxnError::Validation(message)))?;
                    }
                    None => handle
                        .commit_and_swap(next, || Ok(()))
                        .await
                        .map_err(|message| E::from(TxnError::Validation(message)))?,
                }
                committed = true;
                match then {
                    Then::Value(value) => return Ok(value),

                    Then::Blocking(f) => outcome = Outcome::Blocking(f),
                    Then::Async(future) => outcome = Outcome::Async(future),
                }
            }
            Outcome::CommitAsync {
                next,
                persist,
                rates,
                then,
            } => {
                super::security_policy::admit(&handle.load(), &next, context, authority)
                    .map_err(E::from)?;
                let expected = handle.load();
                persist
                    .await
                    .map_err(|message| E::from(TxnError::Validation(message)))?;
                if !Arc::ptr_eq(&expected, &handle.load()) {
                    if let Some(overlay) = &expected.overlay_path {
                        overlay.require_reload();
                    }
                    return Err(E::from(TxnError::Conflict(
                        "App generation changed during persistence; reload before retrying".into(),
                    )));
                }
                match rates {
                    Some(rates) => {
                        let (limits, origin) = *rates;
                        match mode {
                            TransactionMode::Mutation => {
                                handle
                                    .commit_rates_and_swap(next, || Ok(()), limits, &origin)
                                    .await
                            }
                            TransactionMode::Reload => {
                                handle
                                    .reload_rates_and_swap(next, || Ok(()), limits, &origin)
                                    .await
                            }
                        }
                        .map_err(|message| E::from(TxnError::Validation(message)))?;
                    }
                    None => handle
                        .commit_and_swap(next, || Ok(()))
                        .await
                        .map_err(|message| E::from(TxnError::Validation(message)))?,
                }
                committed = true;
                outcome = Outcome::Async(then);
            }
            Outcome::Blocking(f) => {
                let context = context.cloned();
                let handle = Arc::clone(handle);
                outcome = tokio::task::spawn_blocking(move || {
                    let authority = if !committed {
                        match context {
                            Some(context) => Some(
                                tokio::runtime::Handle::current()
                                    .block_on(context.revalidate(&handle.load()))
                                    .map_err(E::from)?,
                            ),
                            None => authority,
                        }
                    } else {
                        authority
                    };
                    super::security_policy::scoped(authority, f)
                })
                .await
                .map_err(|_| E::from(TxnError::Internal))??;
            }
            Outcome::Async(future) => {
                outcome = super::security_policy::scoped_async(authority, future).await?
            }
        }
    }
}

#[cfg(txn_fence_red)]
#[path = "tests/txn_fence.rs"]
mod txn_fence;

#[cfg(all(test, feature = "loom-model"))]
#[path = "tests/txn_loom.rs"]
mod txn_loom;

/// Serializes effect admission with config-policy publication. Holding this guard means the
/// effect has started; revocation can deny queued callers, never undo an admitted Store write.
/// Native persistence and fresh authentication may await while this async guard is held.
pub struct EffectGuard {
    // Advance before releasing the config guard, including Store-only authority changes.
    _completion: crate::auth::effect::Completion,
    _guard: tokio::sync::OwnedMutexGuard<()>,
    authority: Option<crate::auth::effect::Authority>,
}

pub async fn effect_lock() -> tokio::sync::OwnedMutexGuard<()> {
    Arc::clone(&CONFIG_MUTATION_LOCK).lock_owned().await
}

pub async fn admit_effect(
    handle: &Arc<AppHandle>,
    context: Option<&crate::auth::effect::Context>,
) -> Result<EffectGuard, TxnError> {
    let guard = effect_lock().await;
    let authority = match context {
        Some(context) => Some(context.revalidate(&handle.load()).await?),
        None => None, // Internal kernel work has no administrative caller.
    };
    Ok(EffectGuard {
        _completion: crate::auth::effect::Completion::new(),
        _guard: guard,
        authority,
    })
}
