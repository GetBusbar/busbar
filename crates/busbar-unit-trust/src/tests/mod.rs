// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The unit's tests, ported with their assertions intact from the shipped guards' and pick's suites.

mod destination_tests;
mod guard_tests;
mod order_tests;
mod swrr_tests;
mod unit_tests;

use crate::guard::PoolView;
use crate::lane::{BreakerView, LaneTable, Unavailable};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

/// A pool table stated as data: who may use what, and what falls over to what.
pub(crate) struct Pools {
    pub(crate) has_key: bool,
    /// `None` means the key names no restriction and admits every pool. An explicit empty list is
    /// the empty set and denies every pool.
    pub(crate) allowed: Option<Vec<String>>,
    pub(crate) fallbacks: HashMap<String, String>,
    pub(crate) configured: HashSet<String>,
    pub(crate) pricing: bool,
    pub(crate) unpriced: HashSet<String>,
}

impl Default for Pools {
    fn default() -> Self {
        Pools {
            has_key: true,
            allowed: None,
            fallbacks: HashMap::new(),
            configured: HashSet::new(),
            pricing: false,
            unpriced: HashSet::new(),
        }
    }
}

impl Pools {
    pub(crate) fn allowing(pools: &[&str]) -> Self {
        Pools {
            allowed: Some(pools.iter().map(|p| (*p).to_string()).collect()),
            ..Pools::default()
        }
    }

    /// A card is present, and it does not price these names.
    pub(crate) fn with_card_missing(names: &[&str]) -> Self {
        Pools {
            pricing: true,
            unpriced: names.iter().map(|n| (*n).to_string()).collect(),
            ..Pools::default()
        }
    }

    /// Name a configured pool or single-lane entry — one boot already proved the card covers.
    pub(crate) fn configuring(mut self, name: &str) -> Self {
        self.configured.insert(name.to_string());
        self
    }

    /// Restrict the key to these pools.
    pub(crate) fn restricted_to(mut self, pools: &[&str]) -> Self {
        self.allowed = Some(pools.iter().map(|p| (*p).to_string()).collect());
        self
    }

    pub(crate) fn falls_back(mut self, from: &str, to: &str) -> Self {
        self.fallbacks.insert(from.to_string(), to.to_string());
        self
    }
}

impl PoolView for Pools {
    fn key_scopes(&self) -> Option<&[String]> {
        self.allowed.as_deref()
    }
    fn pool_allowed(&self, pool: &str) -> bool {
        match &self.allowed {
            None => true,
            Some(list) => list.iter().any(|p| p == pool),
        }
    }
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String> {
        self.fallbacks.get(pool).cloned()
    }
    fn is_configured(&self, name: &str) -> bool {
        self.configured.contains(name)
    }
    fn pricing_enabled(&self) -> bool {
        self.pricing
    }
    fn is_unpriced(&self, name: &str) -> bool {
        self.unpriced.contains(name)
    }
    fn has_key(&self) -> bool {
        self.has_key
    }
}

/// A lane table and breaker stated as data, plus a record of what was actually admitted — the only
/// way to tell "excluded before the walk" from "ordered last and attempted".
pub(crate) struct Lanes {
    pub(crate) dead: HashSet<usize>,
    pub(crate) exhausted: HashSet<usize>,
    pub(crate) open_breaker: HashSet<usize>,
    pub(crate) at_capacity: HashSet<usize>,
    /// Every lane the admission was actually called for, in call order.
    pub(crate) admissions: RefCell<Vec<usize>>,
    /// Every lane the readiness peek was called for, in call order.
    pub(crate) peeks: RefCell<Vec<usize>>,
}

impl Default for Lanes {
    fn default() -> Self {
        Lanes {
            dead: HashSet::new(),
            exhausted: HashSet::new(),
            open_breaker: HashSet::new(),
            at_capacity: HashSet::new(),
            admissions: RefCell::new(Vec::new()),
            peeks: RefCell::new(Vec::new()),
        }
    }
}

impl Lanes {
    pub(crate) fn with(f: impl FnOnce(&mut Lanes)) -> Self {
        let mut l = Lanes::default();
        f(&mut l);
        l
    }
}

impl LaneTable for Lanes {
    fn lane_admissible(&self, lane: usize) -> bool {
        !self.dead.contains(&lane) && !self.exhausted.contains(&lane)
    }
}

impl BreakerView for Lanes {
    fn ready(&self, _pool: &str, lane: usize, _now: u64) -> bool {
        self.peeks.borrow_mut().push(lane);
        !self.open_breaker.contains(&lane)
    }
    fn try_admit(&self, _pool: &str, lane: usize, _now: u64) -> Result<(), Unavailable> {
        self.admissions.borrow_mut().push(lane);
        if self.dead.contains(&lane) {
            return Err(Unavailable::Dead);
        }
        if self.exhausted.contains(&lane) {
            return Err(Unavailable::BudgetExhausted);
        }
        if self.open_breaker.contains(&lane) {
            return Err(Unavailable::BreakerOpen);
        }
        if self.at_capacity.contains(&lane) {
            return Err(Unavailable::AtCapacity);
        }
        Ok(())
    }
}

/// Candidates from index and weight pairs.
pub(crate) fn cands(pairs: &[(usize, u32)]) -> Vec<crate::lane::LaneCandidate> {
    pairs
        .iter()
        .map(|(idx, weight)| crate::lane::LaneCandidate {
            idx: *idx,
            weight: *weight,
        })
        .collect()
}
