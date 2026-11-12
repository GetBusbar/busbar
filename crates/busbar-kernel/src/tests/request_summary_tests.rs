// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pure parts of the summary. What a subscriber sees of it (off, on, every field) is pinned by
//! `tests/debug_logging.rs`, in a process of its own: `tracing` caches callsite interest
//! process-wide, so filter-dependent assertions are not reliable beside other tests' subscribers.

use super::*;
use std::sync::Arc;

fn note(lane: &str, provider: &str, status: u32, us: u64, outcome: &'static str) -> AttemptNote {
    AttemptNote {
        lane: lane.into(),
        provider: provider.into(),
        status,
        elapsed_us: us,
        outcome,
        failover: None,
    }
}

#[test]
fn an_attempt_note_records_status_failover_and_its_end_once() {
    let log: AttemptLog = Arc::default();
    {
        let mut first = AttemptTrail::open(Arc::clone(&log), "a", "openai");
        first.status(429);
        first.status(500);
        first.failover(Some("rate_limited"));
        first.close("retry");
        first.close("complete");
    }
    {
        let mut second = AttemptTrail::open(Arc::clone(&log), "b", "anthropic");
        second.status(200);
        // Dropped without a close: the attempt was abandoned (its future dropped).
    }
    let notes = log.lock().unwrap().clone();
    assert_eq!(notes.len(), 2);
    assert_eq!(
        (notes[0].status, notes[0].outcome, notes[0].failover),
        (429, "retry", Some("rate_limited"))
    );
    assert_eq!((notes[1].status, notes[1].outcome), (200, "abandoned"));
}

#[test]
fn sub_millisecond_attempts_render_in_microseconds() {
    let a = [note("local", "", 0, 850, "answered_locally")];
    assert_eq!(Attempts(&a).to_string(), "local 850us answered_locally");
}
