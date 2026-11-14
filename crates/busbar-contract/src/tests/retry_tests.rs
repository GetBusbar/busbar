// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const S: Duration = Duration::from_secs(1);

#[test]
fn full_jitter_doubles_to_the_cap_and_never_waits_under_the_floor() {
    let b = Backoff::new(S, 8 * S);
    assert_eq!(b.ceiling(1), S);
    assert_eq!(b.ceiling(2), 2 * S);
    assert_eq!(b.ceiling(3), 4 * S);
    assert_eq!(b.ceiling(4), 8 * S, "the cap");
    assert_eq!(b.ceiling(40), 8 * S, "no overflow past the cap");
    for n in 1..8 {
        assert_eq!(
            b.delay(n, 0.0),
            FLOOR,
            "a zero draw waits the floor, never spins"
        );
        assert_eq!(b.delay(n, 1.0), b.ceiling(n));
        let mid = b.delay(n, 0.5);
        assert!(mid >= FLOOR && mid <= b.ceiling(n), "{mid:?}");
    }
}

#[test]
fn a_steady_retry_is_uniform_in_half_the_cap_to_the_cap() {
    let b = Backoff::new(S, 30 * S);
    assert_eq!(b.steady(0.0), 15 * S);
    assert_eq!(b.steady(1.0), 30 * S);
    assert!(b.steady(f64::NAN) >= 15 * S, "a broken draw stays bounded");
}

#[test]
fn a_spread_cadence_stays_within_its_band() {
    let every = 30 * S;
    assert_eq!(spread(every, 0.1, 0.0), 27 * S);
    assert_eq!(spread(every, 0.1, 1.0), 33 * S);
    assert_eq!(spread(every, 0.1, 0.5), every);
    assert_eq!(
        spread(Duration::ZERO, 0.1, 0.5),
        FLOOR,
        "never under the floor"
    );
}

#[test]
fn the_os_draw_is_a_unit() {
    for _ in 0..64 {
        let u = unit();
        assert!((0.0..1.0).contains(&u), "{u}");
    }
}
