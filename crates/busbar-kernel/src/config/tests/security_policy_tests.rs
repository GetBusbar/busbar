// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::{
    future::Future as _,
    task::{Context, Poll, Waker},
};

#[test]
fn typed_builder_refusal_survives_an_async_cleanup_without_lending_thread_authority() {
    let mut future = Box::pin(scoped_async::<(), TxnError>(None, async {
        BUILD_AUTHORITY.with(|held| held.borrow_mut().refusal = Some(TxnError::Forbidden));
        let mut first = true;
        std::future::poll_fn(move |_| {
            if std::mem::take(&mut first) {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        Err(TxnError::Validation(
            "a failed builder finished its cleanup".into(),
        ))
    }));
    let mut context = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut context).is_pending());
    assert!(BUILD_AUTHORITY.with(|held| held.borrow().refusal.is_none()));
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Err(TxnError::Forbidden))
    ));
    assert!(BUILD_AUTHORITY.with(|held| held.borrow().refusal.is_none()));
}
