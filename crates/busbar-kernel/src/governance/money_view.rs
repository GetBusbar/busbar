// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{
    wall_ms, BudgetCell, DerivedUsage, EntryId, History, MoneyError, RawFeeEras, RawRateEra,
};

type Priced = Result<DerivedUsage, MoneyError>;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The recorded facts a bucket's figure is priced from.
#[derive(Clone, PartialEq)]
struct Facts {
    window_start: u64,
    requests: u64,
    billable_requests: u64,
    fee_eras: RawFeeEras,
    models: Vec<(Arc<str>, RawRateEra, BTreeMap<String, u64>)>,
}

/// Everything one bucket's derived figure depends on.
#[derive(Clone)]
pub(in crate::governance) struct Inputs {
    period: String,
    include_fee: bool,
    facts: Facts,
    card: u64,
    /// The dated history the read resolves through, held so its address cannot be reused, with the
    /// entry count it had and the card in force at the read.
    history: Option<(Arc<History>, usize, Option<EntryId>)>,
}

impl PartialEq for Inputs {
    fn eq(&self, other: &Self) -> bool {
        let history = match (&self.history, &other.history) {
            (None, None) => true,
            (Some((a, al, af)), Some((b, bl, bf))) => Arc::ptr_eq(a, b) && al == bl && af == bf,
            _ => false,
        };
        history
            && self.period == other.period
            && self.include_fee == other.include_fee
            && self.card == other.card
            && self.facts == other.facts
    }
}

impl Inputs {
    pub(in crate::governance) fn of(
        cost: &crate::cost::CostModel,
        period: &str,
        include_fee: bool,
        cell: &BudgetCell,
    ) -> Self {
        let history = crate::rate_apply::dated_history().map(|h| {
            let now_ms = wall_ms();
            let view = h.current();
            let (len, in_force) = (
                view.entries().len(),
                view.entry_at(now_ms).map(|entry| entry.id()),
            );
            (h, len, in_force)
        });
        Inputs {
            period: period.to_string(),
            include_fee,
            facts: Facts {
                window_start: cell.window_start,
                requests: cell.requests,
                billable_requests: cell.billable_requests,
                fee_eras: cell.fee_eras.clone(),
                models: (cell.models.iter())
                    .map(|m| (m.model.clone(), m.era, m.cur.clone()))
                    .collect(),
            },
            card: cost.generation(),
            history,
        }
    }
}

/// Each bucket's last derived figure (or the one function's refusal, which is as much an answer and
/// is kept the same way) and the inputs it was priced from.
#[derive(Default)]
pub(in crate::governance) struct MoneyView {
    memo: Mutex<HashMap<String, (Inputs, Priced)>>,
    /// How many times this view has priced. Read by the tests that prove a scrape reprices only
    /// what changed.
    pricings: AtomicU64,
}

impl MoneyView {
    pub(in crate::governance) fn fresh(&self, bucket_id: &str, inputs: &Inputs) -> Option<Priced> {
        let memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        memo.get(bucket_id)
            .filter(|(was, _)| was == inputs)
            .map(|(_, usage)| usage.clone())
    }

    pub(in crate::governance) fn keep(&self, bucket_id: &str, inputs: Inputs, usage: Priced) {
        let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        memo.insert(bucket_id.to_string(), (inputs, usage));
    }

    pub(in crate::governance) fn priced(&self) {
        self.pricings.fetch_add(1, Ordering::Relaxed);
    }

    #[cfg(test)]
    pub(in crate::governance) fn pricings(&self) -> u64 {
        self.pricings.load(Ordering::Relaxed)
    }

    pub(in crate::governance) fn forget(&self, bucket_id: &str) {
        let mut memo = self.memo.lock().unwrap_or_else(|p| p.into_inner());
        memo.remove(bucket_id);
    }
}
