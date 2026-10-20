// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BEAT: work handed to the kernel's clock is beaten while its owner holds it, and leaves the
//! clock when its owner lets it go.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::{beat, on_clock, ClockJob, ClockWork};

struct Counted(Arc<AtomicUsize>);

impl ClockWork for Counted {
    fn beat(&self, _now: std::time::SystemTime) -> Option<ClockJob> {
        let ran = Arc::clone(&self.0);
        Some(Box::pin(async move {
            ran.fetch_add(1, Ordering::SeqCst);
        }))
    }
}

#[tokio::test]
async fn work_is_beaten_while_held_and_leaves_when_let_go() {
    let ran = Arc::new(AtomicUsize::new(0));
    let work: Arc<dyn ClockWork> = Arc::new(Counted(Arc::clone(&ran)));
    on_clock(Arc::downgrade(&work));

    for job in beat(std::time::SystemTime::now()) {
        job.await;
    }
    assert_eq!(ran.load(Ordering::SeqCst), 1, "held work is beaten");

    drop(work);
    for job in beat(std::time::SystemTime::now()) {
        job.await;
    }
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "work its owner let go is never beaten again"
    );
}
