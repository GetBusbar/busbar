// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One consumed FETCH script, held pending until its enclosing operation is dropped.

use std::future::{pending, Future};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Waker};

use super::{FetchNeed, NeedErr};

type Inspector = dyn for<'a> Fn(FetchNeed<'a>) + Send + Sync;

#[derive(Default)]
struct State {
    entered: AtomicBool,
    cancelled: AtomicBool,
}

/// Observation of a single scripted FETCH. Holds no request bytes or inspector captures.
pub struct ParkedFetch {
    state: Arc<State>,
}

impl ParkedFetch {
    /// The real FETCH reached its script and its borrowed inspector returned successfully.
    pub fn entered(&self) -> bool {
        self.state.entered.load(Ordering::Acquire)
    }

    /// The matching host Need future was dropped, including on inspector panic.
    pub fn cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub(crate) fn cancel<F: Future>(&self, future: F) {
        let fresh = !self.entered() && !self.cancelled();
        let mut owner = Box::pin(future);
        let pending = fresh
            && owner
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending();
        let entered_waiting = self.entered() && !self.cancelled();
        // This drops the actual future when the caller obeys the ownership contract. A borrowed
        // future wrapper only ends its borrow; the postcondition detects that misuse.
        drop(owner);
        assert!(fresh, "parked FETCH gate was already used");
        assert!(pending, "operation completed before its parked FETCH");
        assert!(
            entered_waiting,
            "operation was not pending at its fresh FETCH gate"
        );
        assert!(
            self.cancelled(),
            "operation future was borrowed or retained elsewhere"
        );
    }
}

pub(super) struct Script {
    state: Arc<State>,
    inspect: Box<Inspector>,
}

impl Script {
    pub(super) fn new(
        inspect: impl for<'a> Fn(FetchNeed<'a>) + Send + Sync + 'static,
    ) -> (Self, ParkedFetch) {
        let state = Arc::new(State::default());
        (
            Self {
                state: Arc::clone(&state),
                inspect: Box::new(inspect),
            },
            ParkedFetch { state },
        )
    }

    pub(super) async fn run(self, request: FetchNeed<'_>) -> Result<(), NeedErr> {
        // Arm before inspecting, so inspector panic unwinds the real Need and its captures.
        // The caller has already released FakeNeeds' mutex.
        let _guard = Cancelled(Arc::clone(&self.state));
        (self.inspect)(request);
        self.state.entered.store(true, Ordering::Release);
        pending().await
    }
}

struct Cancelled(Arc<State>);
impl Drop for Cancelled {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Release);
    }
}
