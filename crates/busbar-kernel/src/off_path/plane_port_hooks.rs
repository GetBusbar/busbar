// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::port_hooks`' off-path code: a walk pool's route-policy counters, registered once
//! when the walk is bound (one handle per deciding name). A request only increments them.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use crate::plane_driver::port_hooks::{Call, Decider, RouteCounters};
use crate::snapshot::ROUTE_POLICY_SELECTIONS_TOTAL;

impl RouteCounters {
    /// Resolve `busbar_route_policy_selections_total` for every name that can decide the walk:
    /// each call of `calls` and their fallbacks, by [`Call::decider`].
    pub fn bind<'c>(pool: &str, calls: impl IntoIterator<Item = &'c Arc<Call>>) -> Self {
        let pool: Arc<str> = Arc::from(pool);
        let mut deciders = BTreeMap::new();
        let mut pending: Vec<&Arc<Call>> = calls.into_iter().collect();
        while let Some(call) = pending.pop() {
            pending.extend(&call.fallbacks);
            deciders
                .entry(Arc::clone(call.decider()))
                .or_insert_with_key(|policy: &Arc<str>| Decider {
                    selections: metrics::counter!(
                        ROUTE_POLICY_SELECTIONS_TOTAL,
                        "policy" => Arc::clone(policy),
                        "pool" => Arc::clone(&pool),
                    ),
                    rejections: Box::new(std::array::from_fn(|_| OnceLock::new())),
                });
        }
        Self { pool, deciders }
    }
}
