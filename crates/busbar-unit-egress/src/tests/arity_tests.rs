// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The pick-face arity posture: a pooled pick fails over, a pinned one refuses carrying the member.

use crate::arity::{on_primary_unavailable, Arity, PinnedRefusal, Reroute};
use crate::ports::Unavailable;

/// Only the pool posture may fail over.
#[test]
fn only_choose_one_may_failover() {
    assert!(Arity::ChooseOne.may_failover());
    assert!(!Arity::ExactlyOne.may_failover());
}

/// A pooled (ChooseOne) primary that is unavailable fails over — the walk continues.
#[test]
fn a_pooled_primary_fails_over() {
    let cause = Unavailable::BreakerOpen { until: 1_000 };
    assert_eq!(
        on_primary_unavailable(Arity::ChooseOne, 7_usize, cause),
        Reroute::Failover
    );
}

/// A pinned (ExactlyOne) primary that is unavailable REFUSES, carrying the pinned member and cause,
/// rather than rerouting to a twin that does not hold the state.
#[test]
fn a_pinned_primary_refuses_carrying_the_member() {
    let cause = Unavailable::BreakerOpen { until: 1_000 };
    assert_eq!(
        on_primary_unavailable(Arity::ExactlyOne, 7_usize, cause),
        Reroute::Refuse(PinnedRefusal { pinned: 7, cause })
    );
}

/// A breaker-cooldown refusal yields the exact deadline as its retry hint; a cause with no deadline
/// yields none.
#[test]
fn a_pinned_breaker_refusal_carries_the_exact_deadline() {
    let breaker = PinnedRefusal {
        pinned: 3_usize,
        cause: Unavailable::BreakerOpen { until: 4_242 },
    };
    assert_eq!(breaker.retry_at(), Some(4_242));

    let dead = PinnedRefusal {
        pinned: 3_usize,
        cause: Unavailable::Dead,
    };
    assert_eq!(dead.retry_at(), None);
}
