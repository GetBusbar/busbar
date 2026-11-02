// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Wake, Waker};

struct Reenter {
    sessions: Arc<Mutex<HashMap<u64, Arc<Notify>>>>,
    wakes: AtomicUsize,
}

impl Wake for Reenter {
    fn wake(self: Arc<Self>) {
        let open = self
            .sessions
            .try_lock()
            .expect("a session wake must run after the table lock releases");
        assert_eq!(open.len(), 1);
        self.wakes.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn a_ready_session_wakes_with_the_table_available_for_reentry() {
    let told = Arc::new(Notify::new());
    let sessions = Arc::new(Mutex::new(HashMap::from([(7, told.clone())])));
    let reenter = Arc::new(Reenter {
        sessions: sessions.clone(),
        wakes: AtomicUsize::new(0),
    });
    let waker = Waker::from(reenter.clone());
    let mut cx = Context::from_waker(&waker);
    let mut waiting = Box::pin(told.notified());
    assert!(waiting.as_mut().poll(&mut cx).is_pending());

    wake_ready(&sessions, &[99, 7]);
    assert_eq!(reenter.wakes.load(Ordering::SeqCst), 1);
    assert!(waiting.as_mut().poll(&mut cx).is_ready());
}
