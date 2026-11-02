// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST CLOCK THE FRAMER'S DEADLINES ARE STATED ON: one fixed epoch, so a reading names the

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::transport::{ROLE_FRAMER, YIELD_HAS_DEADLINE};

use super::{instant_of, now_ns, Call, Crossed, DoorFacts, FramerDoor};
use crate::datagram::{DatagramFraming, LineStep};

const FRAMING: u64 = 9;

#[test]
fn one_reading_maps_to_one_instant_however_often_and_whenever() {
    let past = now_ns();
    let future = past + 60_000_000_000;
    let past_first = instant_of(past);
    let future_first = instant_of(future);

    std::thread::sleep(Duration::from_millis(2));
    assert_eq!(instant_of(past), past_first, "an elapsed reading drifted");
    assert_eq!(instant_of(future), future_first, "a future reading drifted");
    assert_eq!(instant_of(past), instant_of(past));
    assert_eq!(instant_of(future), instant_of(future));
}

#[test]
fn an_elapsed_nonzero_deadline_is_due_at_a_now_captured_after_it_was_read() {
    let reading = now_ns();
    assert_ne!(reading, 0, "zero is reserved for no deadline");
    let now = Instant::now();
    std::thread::sleep(Duration::from_millis(2));
    assert!(
        instant_of(reading) <= now,
        "a reading taken before `now` must not map after it"
    );

    assert!(instant_of(1) <= now);
}

#[test]
fn mapped_future_readings_keep_their_exact_nanosecond_delta() {
    let base = now_ns() + 3_000_000_000;
    let delta = 7_500_000_123_u64;
    let earlier = instant_of(base);
    std::thread::sleep(Duration::from_millis(2));
    let later = instant_of(base + delta);
    assert_eq!(later.duration_since(earlier), Duration::from_nanos(delta));

    assert_eq!(
        instant_of(base + 1).duration_since(instant_of(base)),
        Duration::from_nanos(1)
    );
}

/// A datagram framer that states one deadline at `begin` (the host's reading then, plus `ahead`

struct Deadlined {
    facts: DoorFacts,
    ahead: u64,
    stated: AtomicU64,
    timers: AtomicUsize,
}

impl Deadlined {
    fn new(ahead: u64) -> Arc<Self> {
        Arc::new(Self {
            facts: DoorFacts {
                name: "deadlined".into(),
                claims: vec!["deadlined"],
                role: ROLE_FRAMER,
                composes_over: Vec::new(),
                ported: false,
                status_rows: Vec::new(),
                duplex: Vec::new(),
                datagram: true,
            },
            ahead,
            stated: AtomicU64::new(0),
            timers: AtomicUsize::new(0),
        })
    }

    fn stated(&self) -> u64 {
        self.stated.load(Ordering::SeqCst)
    }

    fn timers(&self) -> usize {
        self.timers.load(Ordering::SeqCst)
    }
}

impl FramerDoor for Deadlined {
    fn facts(&self) -> &DoorFacts {
        &self.facts
    }

    fn cross(&self, call: Call<'_>) -> Crossed {
        match call {
            Call::Begin(input, out) => {
                out.framing = FRAMING;
                let deadline = input.sink.now_monotonic_ns + self.ahead;
                self.stated.store(deadline, Ordering::SeqCst);
                out.yielded.flags = YIELD_HAS_DEADLINE;
                out.yielded.next_deadline_ns = deadline;
            }
            Call::Timer(..) => {
                self.timers.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }
}

fn framing(door: &Arc<Deadlined>) -> DatagramFraming {
    DatagramFraming::accept_minted(door.clone(), "127.0.0.1:9".parse().unwrap())
        .expect("the framing begins")
        .0
}

/// Run one `timeout_step` and every same-op continuation it owes to completion; the number of

fn step_to_completion(framing: &mut DatagramFraming, now: Instant) -> usize {
    let mut batches = 0;
    let mut step = framing.timeout_step(now).expect("the clock step");
    while let LineStep::Batch { .. } = step {
        batches += 1;
        assert!(batches < 8, "the clock step never completed");
        step = framing
            .line_step(None, false, now)
            .expect("the continuation");
    }
    assert!(matches!(step, LineStep::Complete), "the step needed credit");
    batches
}

#[test]
fn the_legacy_timeout_fires_an_elapsed_framer_deadline_once_and_states_no_replacement() {
    let door = Deadlined::new(0);
    let mut framing = framing(&door);
    let stated = door.stated();
    assert_ne!(stated, 0);
    assert_eq!(
        framing.deadline(),
        Some(instant_of(stated)),
        "the framer's deadline is the stable mapping of what it stated"
    );
    let now = Instant::now();
    assert!(instant_of(stated) <= now);

    framing.timeout(now).expect("the host's clock");
    assert_eq!(door.timers(), 1, "the elapsed deadline fires the Timer");
    assert_eq!(framing.deadline(), None, "the deadline was consumed");

    framing.timeout(now).expect("the host's clock");
    framing
        .timeout(now + Duration::from_secs(3600))
        .expect("the host's clock");
    assert_eq!(door.timers(), 1, "the deadline fired more than once");
    assert_eq!(framing.deadline(), None, "a replacement deadline appeared");
}

#[test]
fn the_incremental_timeout_step_fires_an_elapsed_framer_deadline_once_and_states_no_replacement() {
    let door = Deadlined::new(0);
    let mut framing = framing(&door);
    let stated = door.stated();
    assert_ne!(stated, 0);
    let now = Instant::now();
    assert!(instant_of(stated) <= now);
    assert_eq!(framing.deadline(), Some(instant_of(stated)));

    assert!(
        step_to_completion(&mut framing, now) >= 1,
        "no batch crossed"
    );
    assert_eq!(door.timers(), 1, "the elapsed deadline fires the Timer");
    assert_eq!(framing.deadline(), None, "the deadline was consumed");

    step_to_completion(&mut framing, now);
    step_to_completion(&mut framing, now + Duration::from_secs(3600));
    assert_eq!(door.timers(), 1, "the deadline fired more than once");
    assert_eq!(framing.deadline(), None, "a replacement deadline appeared");
}

#[test]
fn a_future_framer_deadline_waits_for_its_instant_in_both_clock_paths() {
    let ahead = 60_000_000_000_u64;
    for incremental in [false, true] {
        let door = Deadlined::new(ahead);
        let mut framing = framing(&door);
        let stated = door.stated();
        let due = instant_of(stated);
        assert_eq!(framing.deadline(), Some(due));
        assert_eq!(
            due.duration_since(instant_of(stated - ahead)),
            Duration::from_nanos(ahead),
            "the future deadline is exactly `ahead` after the reading it was stated from"
        );
        let early = Instant::now();
        assert!(early < due, "a minute ahead is not yet due");

        let clock = |framing: &mut DatagramFraming, now: Instant| {
            if incremental {
                step_to_completion(framing, now);
            } else {
                framing.timeout(now).expect("the host's clock");
            }
        };
        clock(&mut framing, early);
        assert_eq!(door.timers(), 0, "fired before its instant");
        assert_eq!(framing.deadline(), Some(due), "the pending deadline moved");

        clock(&mut framing, due);
        assert_eq!(door.timers(), 1, "not fired at its instant");
        assert_eq!(framing.deadline(), None);
        clock(&mut framing, due + Duration::from_secs(1));
        assert_eq!(door.timers(), 1, "fired twice");
    }
}
