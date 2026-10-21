// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The inbound body's time policy at its one seam (row 192 C): the listener's bounds, their
//! arithmetic and their words, unchanged, over an injected clock reading.

use std::time::Duration;

use super::*;

/// The words each bound fails with are the listener's, byte for byte: the router's body read
/// names them in its `400 text/plain`.
#[test]
fn each_bound_fails_with_the_listeners_words() {
    assert_eq!(
        BodyBound::Idle.to_string(),
        "inbound request body read timed out (slow-loris body bound)"
    );
    assert_eq!(
        BodyBound::Total.to_string(),
        "inbound request body exceeded its total read deadline"
    );
    assert_eq!(
        BodyBound::Throughput.to_string(),
        "inbound request body fell below the minimum throughput floor"
    );
    let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(BodyBound::Total);
    assert_eq!(boxed.to_string(), TOTAL_TEXT);
}

/// The floor is 1 KiB/s after a 10 s grace, and the total deadline is the cap at the floor, in
/// whole seconds.
#[test]
fn the_total_deadline_is_the_cap_at_the_floor() {
    assert_eq!(MIN_THROUGHPUT_BYTES_PER_SEC, 1024);
    assert_eq!(THROUGHPUT_GRACE, Duration::from_secs(10));
    assert_eq!(total_deadline_for(2048), Duration::from_secs(2));
    assert_eq!(
        total_deadline_for(32 * 1024 * 1024),
        Duration::from_secs(32 * 1024)
    );
    assert_eq!(total_deadline_for(1023), Duration::ZERO);
    assert_eq!(total_deadline_for(1024 + 1023), Duration::from_secs(1));
}

/// Inside the grace no floor is judged; after it, fewer bytes than the floor times the whole
/// seconds elapsed is under the floor; past the total deadline (strictly) is the total, judged
/// first.
#[test]
fn the_bounds_at_a_reading() {
    let total = Duration::from_secs(100);
    assert_eq!(bounds(Duration::from_secs(5), 0, total), None);
    assert_eq!(
        bounds(THROUGHPUT_GRACE, 0, total),
        None,
        "the grace is inclusive"
    );
    assert_eq!(
        bounds(THROUGHPUT_GRACE + Duration::from_millis(1), 0, total),
        Some(BodyBound::Throughput)
    );
    assert_eq!(
        bounds(
            THROUGHPUT_GRACE + Duration::from_millis(1),
            10 * 1024,
            total
        ),
        None,
        "whole seconds: 10 s at 1 KiB/s"
    );
    assert_eq!(
        bounds(Duration::from_secs(11), 11 * 1024 - 1, total),
        Some(BodyBound::Throughput)
    );
    assert_eq!(bounds(Duration::from_secs(11), 11 * 1024, total), None);
    assert_eq!(
        bounds(total, u64::MAX, total),
        None,
        "the deadline itself is inside"
    );
    assert_eq!(
        bounds(total + Duration::from_millis(1), u64::MAX, total),
        Some(BodyBound::Total)
    );
    assert_eq!(
        bounds(total + Duration::from_secs(1), 0, total),
        Some(BodyBound::Total),
        "the total is judged before the floor"
    );
}

/// No frame within the read timeout is idle: at the timeout, as the listener's timer fires.
#[test]
fn the_inter_frame_bound_at_a_reading() {
    let timeout = Duration::from_secs(30);
    assert_eq!(idle(Duration::from_secs(29), timeout), None);
    assert_eq!(idle(timeout - Duration::from_nanos(1), timeout), None);
    assert_eq!(idle(timeout, timeout), Some(BodyBound::Idle));
    assert_eq!(
        idle(Duration::from_secs(31), timeout),
        Some(BodyBound::Idle)
    );
}
