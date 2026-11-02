//! The per-destination LIFETIME request budget: a `total`-window cap scoped to the destination, not

use std::sync::atomic::{AtomicI64, Ordering};

/// A destination's lifetime request budget. `-1` (or any negative value) means unlimited — spend

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

    /// A budget capped at `max_requests`. A negative cap is the unlimited sentinel (1.5.5's `-1`,

    pub fn limited(max_requests: i64) -> Self {
        if max_requests < 0 {
            return Self::unlimited();
        }
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

    /// Carry a remaining figure across a rebuild. A no-op on an unlimited budget, which has no

    pub fn restore(&self, remaining: i64) {
        if self.limited {
            self.remaining.store(remaining.max(0), Ordering::Relaxed);
        }
    }

    /// Atomically consume one unit. Returns `false` when the budget was already exhausted (the

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

    pub fn refund(&self) {
        if !self.limited {
            return;
        }
        self.remaining.fetch_add(1, Ordering::Relaxed);
    }
}
