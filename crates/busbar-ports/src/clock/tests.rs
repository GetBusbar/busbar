// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host clock's own tests (GROUP-time section 6, step 1).

use std::cell::Cell;
use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use super::*;

const START: Reading = Reading {
    wall_ns: 1_700_000_000_000_000_000,
    mono_ns: 5_000_000_000,
};

fn no_sleep(_: Instant) -> Sleep {
    Box::pin(std::future::ready(()))
}

fn poll_once<F: Future + ?Sized>(f: core::pin::Pin<&mut F>) -> Poll<F::Output> {
    f.poll(&mut Context::from_waker(Waker::noop()))
}

/// A future that counts its polls and never finishes.
struct Counted<'a>(&'a Cell<u32>);

impl Future for Counted<'_> {
    type Output = u32;
    fn poll(self: core::pin::Pin<&mut Self>, _: &mut Context<'_>) -> Poll<u32> {
        self.0.set(self.0.get() + 1);
        Poll::Pending
    }
}

#[test]
fn until_answers_expired_when_the_deadline_and_the_work_are_both_ready() {
    let (clock, _manual) = HostClock::manual(START);
    let fut = pin!(until(&clock, Deadline::PAST, std::future::ready(7_u32)));
    assert!(matches!(poll_once(fut), Poll::Ready(Err(Expired))));
    let fut = pin!(until(
        &clock,
        Deadline::at(START.mono_ns),
        std::future::ready(7_u32)
    ));
    assert!(matches!(poll_once(fut), Poll::Ready(Err(Expired))));
}

#[test]
fn until_does_not_poll_the_work_after_the_deadline_finished() {
    let (clock, manual) = HostClock::manual(START);
    let polls = Cell::new(0);
    let deadline = Deadline::after(START, Duration::from_millis(10));
    let mut fut = pin!(until(&clock, deadline, Counted(&polls)));
    assert!(poll_once(fut.as_mut()).is_pending());
    assert_eq!(polls.get(), 1);
    manual.advance(Duration::from_millis(10));
    assert!(matches!(poll_once(fut.as_mut()), Poll::Ready(Err(Expired))));
    assert_eq!(
        polls.get(),
        1,
        "the work is not polled once the deadline finished"
    );
}

#[test]
fn until_hands_back_the_reading_of_the_wake_that_finished_the_work() {
    let (clock, manual) = HostClock::manual(START);
    let fut = pin!(until(&clock, Deadline::NEVER, std::future::ready(3_u8)));
    let Poll::Ready(Ok(woke)) = poll_once(fut) else {
        panic!("ready work before NEVER finishes")
    };
    assert_eq!((woke.value, woke.at), (3, START));
    assert_eq!(manual.reads(), 1);
}

#[test]
fn manual_block_until_jumps_to_the_deadline_and_answers_due() {
    let (clock, manual) = HostClock::manual(START);
    let at = Deadline::after(START, Duration::from_secs(5));
    let mut asked = Vec::new();
    let blocked = clock.block_until(START, at, |left| {
        asked.push(left);
        None::<()>
    });
    assert_eq!(asked, [Duration::ZERO]);
    let Blocked::Due(r) = blocked else {
        panic!("nothing woke the wait")
    };
    assert_eq!(r.mono_ns, at.mono_ns());
    assert_eq!(r.wall_ns, START.wall_ns + 5_000_000_000);
    assert_eq!(manual.reads(), 1);
    assert_eq!(clock.now().mono_ns, at.mono_ns());
}

#[test]
fn manual_block_until_answers_the_event_that_woke_it() {
    let (clock, manual) = HostClock::manual(START);
    let blocked = clock.block_until(START, Deadline::NEVER, |_| Some(9_u8));
    assert!(matches!(blocked, Blocked::Woke(9, r) if r == START));
    assert_eq!(manual.reads(), 1);
}

#[test]
fn block_until_past_calls_wait_once_with_zero() {
    let system = HostClock::system(no_sleep);
    let (manual_clock, _manual) = HostClock::manual(START);
    for clock in [system, manual_clock] {
        let from = clock.now();
        let mut asked = Vec::new();
        let blocked = clock.block_until(from, Deadline::PAST, |left| {
            asked.push(left);
            None::<()>
        });
        assert_eq!(asked, [Duration::ZERO], "{clock:?}");
        assert!(matches!(blocked, Blocked::Due(_)), "{clock:?}");
    }
}

#[test]
fn manual_reads_count_one_per_now() {
    let (clock, manual) = HostClock::manual(START);
    assert_eq!(manual.reads(), 0);
    let _ = clock.now();
    assert_eq!(manual.reads(), 1);
    let _ = clock.now();
    let _ = clock.now();
    assert_eq!(manual.reads(), 3);
}

#[test]
fn a_manual_sleep_finishes_on_the_advance_that_reaches_it() {
    let (clock, manual) = HostClock::manual(START);
    let mut sleep = clock.sleep_until(Deadline::after(START, Duration::from_millis(3)));
    assert!(poll_once(sleep.as_mut()).is_pending());
    manual.advance(Duration::from_millis(2));
    assert!(poll_once(sleep.as_mut()).is_pending());
    manual.advance(Duration::from_millis(1));
    assert!(poll_once(sleep.as_mut()).is_ready());
    manual.set_wall(1);
    assert_eq!(clock.now().wall_ns, 1);
}

#[test]
fn deadlines_read_nothing_and_saturate() {
    let at = Deadline::after(START, Duration::from_secs(1));
    assert!(!at.passed(START));
    assert_eq!(at.left(START), Duration::from_secs(1));
    let later = Reading {
        mono_ns: at.mono_ns(),
        ..START
    };
    assert!(at.passed(later));
    assert_eq!(at.left(later), Duration::ZERO);
    assert_eq!(Deadline::after(START, Duration::MAX), Deadline::NEVER);
    assert!(Deadline::PAST.passed(Reading {
        wall_ns: 0,
        mono_ns: 0
    }));
    assert!(!Deadline::NEVER.passed(START));
}

#[test]
fn the_system_clock_reads_the_one_origin() {
    let clock = HostClock::system(no_sleep);
    let a = clock.now();
    let b = clock.now();
    assert!(b.mono_ns >= a.mono_ns);
    assert!(a.wall_ns > 0);
    let at = Deadline::at(a.mono_ns);
    let origin = super::os::origin();
    assert_eq!(clock.instant(at), origin + Duration::from_nanos(a.mono_ns));
    assert!(clock.instant(Deadline::NEVER) > clock.instant(at));
    assert!(clock.park_until(b, Deadline::PAST).mono_ns >= b.mono_ns);
}

#[test]
fn the_handle_free_reading_is_the_system_clock_s() {
    let first = system_now();
    let then = HostClock::system(no_sleep).now();
    assert!(then.mono_ns >= first.mono_ns);
    assert!(then.wall_ns >= first.wall_ns || then.wall_ns > 0);
}
