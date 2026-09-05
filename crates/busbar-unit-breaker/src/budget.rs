//! The per-destination LIFETIME request budget (1.5.5's `ModelCfg.max_requests`): a `total`-window
//! cap scoped to the destination, not the principal. Moved byte-identical from
//! `busbar-core::store::in_memory::availability::{spend_budget, refund_budget}`.
//!
//! Spent AFTER the upstream's 2xx response headers (never on the client-facing status), and
//! reversed only when the response body then fails to transfer intact — a compensating refund, not
//! a general-purpose credit. An exhausted destination is excluded from the walk (never "ordered
//! last"); see [`crate::LaneState::BudgetExhausted`].

use std::sync::atomic::{AtomicI64, Ordering};

/// A destination's lifetime request budget. `-1` (or any negative value) means unlimited — spend
/// and refund are then no-ops that always report success, matching a destination configured with no
/// `max_requests` cap.
pub struct LifetimeBudget {
    remaining: AtomicI64,
    limited: bool,
}

impl LifetimeBudget {
    /// An unlimited budget: every spend succeeds, refund is a no-op.
    pub fn unlimited() -> Self {
        Self {
            remaining: AtomicI64::new(-1),
            limited: false,
        }
    }

    /// A budget capped at `max_requests` (must be `>= 0`; a negative value is unlimited — use
    /// [`Self::unlimited`] instead, since a negative cap has no unit to spend from).
    pub fn limited(max_requests: i64) -> Self {
        Self {
            remaining: AtomicI64::new(max_requests),
            limited: true,
        }
    }

    /// Remaining budget, or `None` for an unlimited destination.
    pub fn remaining(&self) -> Option<i64> {
        if self.limited {
            Some(self.remaining.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    /// Atomically consume one unit. Returns `false` when the budget was already exhausted (the
    /// spend was a no-op — the budget is never driven negative).
    ///
    /// A compare-and-swap loop makes the "is there budget" check and the decrement atomic: under a
    /// concurrent burst, a plain `fetch_sub` would let every one of `N` concurrently-admitted
    /// requests decrement before any of them observed the budget hit zero, overspending by up to
    /// `N`. The loop instead lets exactly the requests that observe a strictly positive budget
    /// spend, and the `(N+1)`th spender loses the CAS once the budget hits zero.
    #[must_use]
    pub fn spend(&self) -> bool {
        if !self.limited {
            return true;
        }
        let mut cur = self.remaining.load(Ordering::Relaxed);
        loop {
            if cur <= 0 {
                return false;
            }
            match self.remaining.compare_exchange_weak(
                cur,
                cur - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => cur = observed,
            }
        }
    }

    /// Return one previously-spent unit — the inverse of a single [`Self::spend`], used to
    /// compensate a spend charged optimistically on the response headers when the body then failed
    /// to transfer. Always paired with a prior successful spend on the same request, so a plain
    /// increment can never push the budget above its configured ceiling.
    pub fn refund(&self) {
        if !self.limited {
            return;
        }
        self.remaining.fetch_add(1, Ordering::Relaxed);
    }
}
