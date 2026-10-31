// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One op on a kept session: the body runs on the session it opened, which is handed back when
//! the body has answered; a session that does not open answers its failure and runs nothing.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use super::{on_kept, Kept, Pool, Wire};
use crate::abi::sdk::store::{Op, Step};

/// A session that opens unless told not to, and counts its hand-backs.
struct Session {
    done: Arc<AtomicU32>,
    ran: u32,
}

impl Kept for Session {
    type Shared = (Arc<AtomicU32>, bool);
    type Error = String;

    async fn open(_wire: Wire, (done, opens): Self::Shared) -> Result<Self, String> {
        if opens {
            Ok(Self { done, ran: 0 })
        } else {
            Err("the server refused the session".to_owned())
        }
    }

    async fn done(self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }
}

fn run(opens: bool, done: &Arc<AtomicU32>, body_ran: &Arc<AtomicU32>) -> Step<Result<u32, String>> {
    let body_ran = Arc::clone(body_ran);
    on_kept::<Session, _>(
        &mut Op::detached(),
        &Pool::new(1),
        (Arc::clone(done), opens),
        Err,
        move |s| {
            Box::pin(async move {
                body_ran.fetch_add(1, Ordering::Relaxed);
                s.ran += 1;
                Ok(s.ran)
            })
        },
    )
}

#[test]
fn an_op_runs_its_body_on_its_session_and_hands_the_session_back() {
    let (done, body_ran) = (Arc::default(), Arc::default());
    assert_eq!(run(true, &done, &body_ran), Step::Ready(Ok(1)));
    assert_eq!(body_ran.load(Ordering::Relaxed), 1);
    assert_eq!(done.load(Ordering::Relaxed), 1);
}

#[test]
fn a_session_that_does_not_open_answers_its_failure_and_runs_nothing() {
    let (done, body_ran) = (Arc::default(), Arc::default());
    assert_eq!(
        run(false, &done, &body_ran),
        Step::Ready(Err("the server refused the session".to_owned()))
    );
    assert_eq!(body_ran.load(Ordering::Relaxed), 0);
    assert_eq!(done.load(Ordering::Relaxed), 0);
}
