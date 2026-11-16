// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The CA-5 hold at token exchange and verify (IF §12.29, W2-K8P).
//!
//! The index and its consistency model (store truth, `refresh_ms` bound, local swap before the answer, memory bound)
//! live in [`crate::directory`] (`Holds`, `HoldSet`, W1-K6P). This module is the request side: the serving
//! generation's `Holds`, published by the generation builder before the generation serves, and the probe a verdict
//! of inbound auth instance `<name>` goes through. An inbound instance no `link.auth` names has no entry: the probe
//! is one map miss and no `HoldSet` is touched. The request path costs one Relaxed load when nothing is held, else
//! one `ArcSwap::load` and one foldhash probe: no lock, no allocation, no await (B-HOLD).

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwapOption;

use crate::directory::{HoldSet, Holds};

/// One config generation's published index: the directory's `Holds` plus the runtime id of each inbound auth
/// instance by operator name (the verdict carries the name; `Holds` is keyed by id).
pub struct Published {
    holds: Holds,
    ids: HashMap<Box<str>, u64>,
}

impl Published {
    pub fn new(holds: Holds, ids: HashMap<Box<str>, u64>) -> Self {
        Self { holds, ids }
    }

    /// The hold sets of the provisioning instances linking inbound auth instance `inbound` (by name); None = none.
    pub fn for_inbound(&self, inbound: &str) -> Option<&[Arc<HoldSet>]> {
        self.holds.for_inbound(*self.ids.get(inbound)?)
    }
}

/// The first set in `sets` that holds `principal`. `sets` is what [`Published::for_inbound`] returned.
pub fn held_by<'a>(sets: Option<&'a [Arc<HoldSet>]>, principal: &str) -> Option<&'a Arc<HoldSet>> {
    sets?.iter().find(|set| set.holds(principal))
}

/// The serving generation's index: one per process, replaced whole by [`publish`].
static CURRENT: ArcSwapOption<Published> = ArcSwapOption::const_empty();

/// Publishes the generation's index (None = no provisioning instance links any inbound instance).
pub fn publish(index: Option<Arc<Published>>) {
    CURRENT.store(index);
}

/// The CA-5 probe for the chain walk (`auth::chain_run`): inbound auth instance `id` identified `principal`.
pub fn held_by_id(id: u64, principal: &str) -> bool {
    let current = CURRENT.load();
    let Some(index) = current.as_deref() else {
        return false;
    };
    held_by(index.holds.for_inbound(id), principal).is_some()
}

/// The CA-5 probe for a verdict of inbound auth instance `inbound` naming `principal`, against the serving
/// generation. true = refuse R_DENIED with no plugin asked.
pub fn held_now(inbound: &str, principal: &str) -> bool {
    let current = CURRENT.load();
    let Some(index) = current.as_deref() else {
        return false;
    };
    held_by(index.for_inbound(inbound), principal).is_some()
}

#[cfg(test)]
mod tests;
