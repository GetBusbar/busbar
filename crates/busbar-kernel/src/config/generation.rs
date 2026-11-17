// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Exact, unpublished epoch custody across one retained configuration transaction.

use crate::state::{App, AppHandle};
use std::cell::RefCell;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

pub(crate) struct Reservation {
    epoch: u64,
    prior: Weak<App>,
    owner: Weak<Context>,
    published: AtomicBool,
}

impl Reservation {
    pub(crate) fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn pending(&self) -> bool {
        !self.published.load(Ordering::Acquire)
    }

    pub(crate) fn check(&self, handle: &AppHandle, prior: &Arc<App>) -> Result<(), String> {
        let owner = self
            .owner
            .upgrade()
            .and_then(|owner| owner.handle.upgrade());
        if !self.pending()
            || owner
                .as_ref()
                .is_none_or(|owner| !std::ptr::eq(owner.as_ref(), handle))
            || !self.prior.ptr_eq(&Arc::downgrade(prior))
        {
            return Err(
                "candidate epoch belongs to another publication; reload before retrying".into(),
            );
        }
        Ok(())
    }

    pub(crate) fn publish(&self) {
        self.published.store(true, Ordering::Release);
    }
}

pub(crate) struct Context {
    handle: Weak<AppHandle>,
    reservation: tokio::sync::Mutex<Option<Arc<Reservation>>>,
}

impl Context {
    pub(crate) fn new(handle: &Arc<AppHandle>) -> Arc<Self> {
        Arc::new(Self {
            handle: Arc::downgrade(handle),
            reservation: tokio::sync::Mutex::new(None),
        })
    }

    async fn reserve(self: &Arc<Self>, prior: &App) -> Result<Arc<Reservation>, String> {
        let handle = self
            .handle
            .upgrade()
            .ok_or("candidate publication owner was disposed")?;
        let expected = handle.load();
        if !std::ptr::eq(expected.as_ref(), prior) {
            return Err("candidate epoch requires the transaction's current App".into());
        }
        let mut held = self.reservation.lock().await;
        if let Some(reservation) = held.as_ref().filter(|reservation| reservation.pending()) {
            reservation.check(&handle, &expected)?;
            return Ok(Arc::clone(reservation));
        }
        let epoch = handle.reserve_generation().await?;
        if !Arc::ptr_eq(&expected, &handle.load()) {
            return Err("App generation changed during candidate epoch reservation".into());
        }
        let reservation = Arc::new(Reservation {
            epoch,
            prior: Arc::downgrade(&expected),
            owner: Arc::downgrade(self),
            published: AtomicBool::new(false),
        });
        *held = Some(Arc::clone(&reservation));
        Ok(reservation)
    }
}

thread_local! {
    static CONTEXT: RefCell<Option<Arc<Context>>> = const { RefCell::new(None) };
}

pub(crate) fn current() -> Option<Arc<Context>> {
    CONTEXT.with(|context| context.borrow().clone())
}

pub(crate) fn scoped<T>(context: Option<Arc<Context>>, body: impl FnOnce() -> T) -> T {
    struct Reset(Option<Arc<Context>>);
    impl Drop for Reset {
        fn drop(&mut self) {
            CONTEXT.with(|context| {
                context.replace(self.0.take());
            });
        }
    }
    let _reset = Reset(CONTEXT.with(|held| held.replace(context)));
    body()
}

pub(crate) async fn scoped_async<T>(
    context: Option<Arc<Context>>,
    future: impl Future<Output = T>,
) -> T {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(move |cx| scoped(context.clone(), || future.as_mut().poll(cx))).await
}

/// Capture before yielding: the context is installed only for each poll, never left on a worker.
pub(crate) async fn reserve(prior: Option<&App>) -> Result<Option<Arc<Reservation>>, String> {
    let context = current();
    match (context, prior) {
        (Some(context), Some(prior)) => context.reserve(prior).await.map(Some),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::transaction::{config_transaction, Outcome, TxnError};
    use std::sync::atomic::AtomicUsize;

    fn handle() -> Arc<AppHandle> {
        Arc::new(AppHandle::new(crate::inbound::native::tests::app()))
    }

    #[tokio::test]
    async fn exact_candidate_reservation_survives_blocking_build_and_publishes_once() {
        let handle = handle();
        let prior = handle.load();
        let old_epoch = prior.config_generation.load(Ordering::Acquire);
        let callbacks = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&callbacks);
        handle.on_apply(Box::new(move |_| {
            observed.fetch_add(1, Ordering::AcqRel);
        }));
        let result: Result<u64, TxnError> = config_transaction(&handle, |txn| {
            let prior = Arc::clone(txn.app());
            Ok(Outcome::blocking(move || {
                tokio::runtime::Handle::current().block_on(async move {
                    let first = reserve(Some(&prior))
                        .await
                        .map_err(TxnError::Validation)?
                        .unwrap();
                    let second = reserve(Some(&prior))
                        .await
                        .map_err(TxnError::Validation)?
                        .unwrap();
                    assert!(Arc::ptr_eq(&first, &second));
                    assert_eq!(prior.config_generation.load(Ordering::Acquire), old_epoch);
                    let mut next = (*prior).clone();
                    next.publication_generation = Some(Arc::clone(&first));
                    let epoch = next.prepared_generation().unwrap();
                    Ok(Outcome::commit(Arc::new(next), || Ok(()), epoch))
                })
            }))
        })
        .await;
        let epoch = result.unwrap();
        assert_ne!(epoch, old_epoch);
        assert!(!Arc::ptr_eq(&prior, &handle.load()));
        assert_eq!(
            handle.load().config_generation.load(Ordering::Acquire),
            epoch
        );
        assert_eq!(handle.load().prepared_generation(), None);
        assert_eq!(callbacks.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn failed_async_persistence_keeps_prior_pointer_epoch_and_callbacks() {
        let handle = handle();
        let prior = handle.load();
        let old_epoch = prior.config_generation.load(Ordering::Acquire);
        let callbacks = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&callbacks);
        handle.on_apply(Box::new(move |_| {
            observed.fetch_add(1, Ordering::AcqRel);
        }));
        let result: Result<(), TxnError> = config_transaction(&handle, |txn| {
            let prior = Arc::clone(txn.app());
            Ok(Outcome::asynchronous(async move {
                let reserved = reserve(Some(&prior))
                    .await
                    .map_err(TxnError::Validation)?
                    .unwrap();
                let mut next = (*prior).clone();
                next.publication_generation = Some(reserved);
                assert!(next.prepared_generation().is_some());
                Ok(Outcome::commit_async(
                    Arc::new(next),
                    async { Err("persist refused".into()) },
                    (),
                ))
            }))
        })
        .await;
        assert!(result.is_err());
        assert!(Arc::ptr_eq(&prior, &handle.load()));
        assert_eq!(prior.config_generation.load(Ordering::Acquire), old_epoch);
        assert_eq!(callbacks.load(Ordering::Acquire), 0);
        assert!(current().is_none());
    }

    #[tokio::test]
    async fn detached_response_waiter_does_not_dispose_reserved_publication() {
        let handle = handle();
        let prior = handle.load();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let applied = Arc::new(tokio::sync::Notify::new());
        let epoch = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observed = Arc::clone(&applied);
        handle.on_apply(Box::new(move |_| observed.notify_one()));
        let request_handle = Arc::clone(&handle);
        let opening = Arc::clone(&entered);
        let finish = Arc::clone(&release);
        let reserved_epoch = Arc::clone(&epoch);
        let waiter = tokio::spawn(async move {
            config_transaction(&request_handle, |txn| {
                let prior = Arc::clone(txn.app());
                Ok::<_, TxnError>(Outcome::asynchronous(async move {
                    let reservation = reserve(Some(&prior))
                        .await
                        .map_err(TxnError::Validation)?
                        .unwrap();
                    reserved_epoch.store(reservation.epoch(), Ordering::Release);
                    opening.notify_one();
                    finish.notified().await;
                    let mut next = (*prior).clone();
                    next.publication_generation = Some(reservation);
                    Ok(Outcome::commit(Arc::new(next), || Ok(()), ()))
                }))
            })
            .await
        });
        entered.notified().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(Arc::ptr_eq(&prior, &handle.load()));
        release.notify_one();
        applied.notified().await;
        assert!(!Arc::ptr_eq(&prior, &handle.load()));
        assert_eq!(
            handle.load().config_generation.load(Ordering::Acquire),
            epoch.load(Ordering::Acquire)
        );
    }

    #[tokio::test]
    async fn stale_candidate_reservation_cannot_publish_over_a_new_app() {
        let handle = handle();
        let prior = handle.load();
        let context = Context::new(&handle);
        let reserved = scoped_async(Some(Arc::clone(&context)), reserve(Some(&prior)))
            .await
            .unwrap()
            .unwrap();
        let mut next = (*prior).clone();
        next.publication_generation = Some(reserved);
        let replacement = Arc::new((*prior).clone());
        handle.swap(Arc::clone(&replacement)).await;
        let epoch = replacement.config_generation.load(Ordering::Acquire);
        assert!(handle
            .commit_and_swap(Arc::new(next), || Ok(()))
            .await
            .is_err());
        assert!(Arc::ptr_eq(&replacement, &handle.load()));
        assert_eq!(replacement.config_generation.load(Ordering::Acquire), epoch);
    }

    #[tokio::test]
    async fn reservation_cannot_publish_through_another_handle_of_the_same_app() {
        let handle = handle();
        let prior = handle.load();
        let other = Arc::new(AppHandle::new(Arc::clone(&prior)));
        let context = Context::new(&handle);
        let reserved = scoped_async(Some(Arc::clone(&context)), reserve(Some(&prior)))
            .await
            .unwrap()
            .unwrap();
        let mut next = (*prior).clone();
        next.publication_generation = Some(reserved);
        let persisted = AtomicUsize::new(0);
        assert!(other
            .commit_and_swap(Arc::new(next), || {
                persisted.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .await
            .is_err());
        assert_eq!(persisted.load(Ordering::Acquire), 0);
        assert!(Arc::ptr_eq(&prior, &handle.load()));
        assert!(Arc::ptr_eq(&prior, &other.load()));
    }

    #[tokio::test]
    async fn disposed_transaction_reservation_cannot_be_reused() {
        let handle = handle();
        let prior = handle.load();
        let context = Context::new(&handle);
        let reserved = scoped_async(Some(Arc::clone(&context)), reserve(Some(&prior)))
            .await
            .unwrap()
            .unwrap();
        let mut next = (*prior).clone();
        next.publication_generation = Some(reserved);
        drop(context);
        assert!(handle
            .commit_and_swap(Arc::new(next), || Ok(()))
            .await
            .is_err());
        assert!(Arc::ptr_eq(&prior, &handle.load()));
    }

    #[tokio::test]
    async fn reservation_does_not_retain_previous_app_or_escape_scope() {
        let handle = handle();
        let prior = handle.load();
        let before = Arc::strong_count(&prior);
        let context = Context::new(&handle);
        let reserved = scoped_async(Some(Arc::clone(&context)), reserve(Some(&prior)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(Arc::strong_count(&prior), before);
        assert!(current().is_none());
        assert!(reserved.pending());
        let replacement = Arc::new((*prior).clone());
        handle.swap(replacement).await;
        let weak = Arc::downgrade(&prior);
        drop(prior);
        assert!(weak.upgrade().is_none());
        assert!(reserved.prior.upgrade().is_none());
    }
    fn selected_groups(
        amount: u64,
    ) -> std::collections::BTreeMap<String, crate::config::groups::GroupCfg> {
        busbar_contract::yaml::from_str(&format!(
            "team:\n  limits:\n    - {{id: rpm, upstream_resource: p/r, requests: {amount}, per: minute, per_key: true, enforcement: process}}"
        )).unwrap()
    }

    fn selected_target() -> crate::governance::selected_policy::SelectedTargetConfig<'static> {
        use crate::governance::selected_policy::{SelectedTargetConfig, SelectedTargetKind};
        SelectedTargetConfig {
            instance: "p",
            kind: SelectedTargetKind::Model,
            pool: "pool",
            member: "p\u{1f}member",
            resource: Some("r"),
            attempt_accounting: true,
        }
    }

    async fn selected_handle() -> Arc<AppHandle> {
        let mut app = crate::inbound::native::tests::app();
        let app = Arc::get_mut(&mut app).unwrap();
        let groups = selected_groups(2);
        app.cost = Arc::new(crate::cost::CostModel::resolve_parts(None, 0, &groups));
        app.governance = Some(Arc::new(
            crate::governance::GovState::new_with_core(crate::real_store::core().await, None, None)
                .await
                .unwrap(),
        ));
        crate::governance::selected_policy::SelectedPolicy::compile(
            &groups,
            Arc::clone(&app.cost),
            &[selected_target()],
            None,
        )
        .unwrap()
        .install_initial(app)
        .unwrap();
        let snapshot = Arc::new(app.clone());
        Arc::new(AppHandle::new(snapshot))
    }

    async fn prepare_selected(prior: &Arc<App>, amount: u64) -> App {
        let mut next = (**prior).clone();
        next.publication_generation = reserve(Some(prior)).await.unwrap();
        next.selected_predecessor = prior.selected_policy.clone();
        let groups = selected_groups(amount);
        next.cost = Arc::new(crate::cost::CostModel::resolve_parts(None, 0, &groups));
        let pending = crate::governance::selected_policy::SelectedPolicy::compile(
            &groups,
            Arc::clone(&next.cost),
            &[selected_target()],
            next.selected_predecessor(),
        )
        .unwrap();
        next.prepare_selected_policy(pending).unwrap();
        next
    }

    #[tokio::test]
    async fn selected_publication_stamps_actual_predecessor_and_callbacks_observe_final_app() {
        let handle = selected_handle().await;
        let prior = handle.load();
        let old = prior.selected_policy.as_ref().unwrap().clone();
        let governor = prior.governance.as_ref().unwrap().selected_rates().clone();
        let observed = Arc::new(AtomicUsize::new(0));
        let callback_count = observed.clone();
        let weak = Arc::downgrade(&handle);
        handle.on_apply_async(Box::new(move |published| {
            let weak = weak.clone();
            let count = callback_count.clone();
            Box::pin(async move {
                assert!(Arc::ptr_eq(&published, &weak.upgrade().unwrap().load()));
                assert_eq!(published.selected_policy.as_ref().unwrap().revision(), 2);
                assert!(published.selected_predecessor().is_none());
                count.fetch_add(1, Ordering::AcqRel);
            })
        }));
        let result: Result<(), TxnError> = config_transaction(&handle, |txn| {
            let prior = txn.app().clone();
            Ok(Outcome::asynchronous(async move {
                let next = prepare_selected(&prior, 7).await;
                assert!(next.selected_policy.is_none());
                Ok(Outcome::commit_async(Arc::new(next), async { Ok(()) }, ()))
            }))
        })
        .await;
        result.unwrap();
        let current = handle.load();
        let policy = current.selected_policy.as_ref().unwrap();
        assert_eq!(policy.revision(), old.revision() + 1);
        assert!(policy.activated_minute() >= old.activated_minute());
        assert!(policy.matches_cost(&current.cost));
        assert!(Arc::ptr_eq(
            &governor,
            current.governance.as_ref().unwrap().selected_rates()
        ));
        assert!(Arc::ptr_eq(prior.selected_policy.as_ref().unwrap(), &old));
        assert_eq!(observed.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn selected_failed_persistence_keeps_original_policy_and_shared_governor() {
        let handle = selected_handle().await;
        let prior = handle.load();
        let policy = prior.selected_policy.as_ref().unwrap().clone();
        let governor = prior.governance.as_ref().unwrap().selected_rates().clone();
        let result: Result<(), TxnError> = config_transaction(&handle, |txn| {
            let prior = txn.app().clone();
            Ok(Outcome::asynchronous(async move {
                let next = prepare_selected(&prior, 9).await;
                Ok(Outcome::commit_async(
                    Arc::new(next),
                    async { Err("desired state refused".into()) },
                    (),
                ))
            }))
        })
        .await;
        assert!(result.is_err());
        let current = handle.load();
        assert!(Arc::ptr_eq(&prior, &current));
        assert!(Arc::ptr_eq(
            &policy,
            current.selected_policy.as_ref().unwrap()
        ));
        assert!(Arc::ptr_eq(
            &governor,
            current.governance.as_ref().unwrap().selected_rates()
        ));
    }

    #[tokio::test]
    async fn copied_policy_with_changed_cost_refuses_before_persistence() {
        let handle = selected_handle().await;
        let prior = handle.load();
        let mut next = (*prior).clone();
        next.cost = Arc::new(crate::cost::CostModel::resolve_parts(
            None,
            0,
            &selected_groups(8),
        ));
        let persisted = AtomicUsize::new(0);
        assert!(handle
            .commit_and_swap(Arc::new(next), || {
                persisted.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .await
            .is_err());
        assert_eq!(persisted.load(Ordering::Acquire), 0);
        assert!(Arc::ptr_eq(&prior, &handle.load()));
    }
    #[tokio::test]
    async fn shutdown_closes_admission_and_waits_for_detached_publication_callbacks() {
        let handle = handle();
        let prior = handle.load();
        let callback_entered = Arc::new(tokio::sync::Notify::new());
        let release_callback = Arc::new(tokio::sync::Notify::new());
        let callback_finished = Arc::new(AtomicUsize::new(0));
        let entered = callback_entered.clone();
        let release = release_callback.clone();
        let finished = callback_finished.clone();
        handle.on_apply_async(Box::new(move |_| {
            let entered = entered.clone();
            let release = release.clone();
            let finished = finished.clone();
            Box::pin(async move {
                entered.notify_one();
                release.notified().await;
                finished.fetch_add(1, Ordering::AcqRel);
            })
        }));
        let request_handle = handle.clone();
        let waiter = tokio::spawn(async move {
            config_transaction(&request_handle, |txn| {
                Ok::<_, TxnError>(Outcome::commit(
                    Arc::new((**txn.app()).clone()),
                    || Ok(()),
                    (),
                ))
            })
            .await
        });
        callback_entered.notified().await;
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        let shutdown_handle = handle.clone();
        let closing = Arc::new(tokio::sync::Notify::new());
        let closing_started = closing.clone();
        let closed = Arc::new(AtomicUsize::new(0));
        let closed_observed = closed.clone();
        let shutdown = tokio::spawn(async move {
            let mut close = Box::pin(shutdown_handle.close_config_publication());
            let first = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(close.as_mut(), cx))
            })
            .await;
            assert!(
                first.is_pending(),
                "retained callback still owns the actual effect guard"
            );
            closing_started.notify_one();
            close.await;
            closed_observed.fetch_add(1, Ordering::AcqRel);
        });
        closing.notified().await;
        assert_eq!(closed.load(Ordering::Acquire), 0);
        assert_eq!(callback_finished.load(Ordering::Acquire), 0);
        release_callback.notify_one();
        shutdown.await.unwrap();
        assert_eq!(callback_finished.load(Ordering::Acquire), 1);
        assert_eq!(closed.load(Ordering::Acquire), 1);
        assert!(
            !Arc::ptr_eq(&prior, &handle.load()),
            "already-admitted publication completed"
        );
        let body_calls = Arc::new(AtomicUsize::new(0));
        let observed = body_calls.clone();
        let rejected: Result<(), TxnError> = config_transaction(&handle, move |_| {
            observed.fetch_add(1, Ordering::AcqRel);
            Ok(Outcome::Value(()))
        })
        .await;
        assert!(matches!(rejected, Err(TxnError::Unavailable(_))));
        assert_eq!(body_calls.load(Ordering::Acquire), 0);
        let persist_calls = AtomicUsize::new(0);
        assert!(handle
            .commit_and_swap(Arc::new((*handle.load()).clone()), || {
                persist_calls.fetch_add(1, Ordering::AcqRel);
                Ok(())
            })
            .await
            .is_err());
        assert_eq!(persist_calls.load(Ordering::Acquire), 0);
        assert_eq!(callback_finished.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn interrupted_shutdown_wait_keeps_admission_closed_and_can_resume() {
        let handle = handle();
        let admitted = crate::config::transaction::admit_effect(&handle, None)
            .await
            .unwrap();
        {
            let mut close = Box::pin(handle.close_config_publication());
            let first = std::future::poll_fn(|cx| {
                std::task::Poll::Ready(std::future::Future::poll(close.as_mut(), cx))
            })
            .await;
            assert!(first.is_pending());
        }
        assert!(!handle.config_admission_open());
        drop(admitted);
        let while_closing = crate::config::transaction::admit_effect(&handle, None).await;
        assert!(matches!(while_closing, Err(TxnError::Unavailable(_))));
        handle.close_config_publication().await;
        let result = crate::config::transaction::admit_effect(&handle, None).await;
        assert!(matches!(result, Err(TxnError::Unavailable(_))));
        handle.close_config_publication().await;
    }
}
