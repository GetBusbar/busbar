// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Async ledger reads. Live admission cells remain in memory; cold views read only
//! through the core-owned ledger facade.
use super::*;

impl GovState {
    pub async fn metering_for_async(&self, bucket: u64) -> RecordStoreResult<Vec<MeteringRow>> {
        self.core_store()?.ledger().list_metering(bucket).await
    }

    pub async fn usage_for_async(
        &self,
        cost: &crate::cost::CostModel,
        id: &str,
        now: u64,
    ) -> RecordStoreResult<Option<DerivedUsage>> {
        if self.core_store()?.identity().get_key(id).await?.is_none() {
            return Ok(None);
        }
        self.derived_bucket_usage_async(cost, id, super::super::WINDOW_TOTAL, true, now)
            .await
            .map(Some)
    }

    pub async fn viewed_bucket_usage_async(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> RecordStoreResult<DerivedUsage> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell_async(bucket_id, window).await?;
        let observed = self.observation_total_async(bucket_id, window).await?;
        self.viewed_usage(
            cost,
            bucket_id,
            budget_period,
            include_request_fee,
            cell,
            observed,
        )
    }

    /// One bucket's viewed usage from a cell and observation total already read.
    fn viewed_usage(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        cell: BudgetCell,
        observed: crate::persistence::observations::BudgetTotal,
    ) -> RecordStoreResult<DerivedUsage> {
        if observed.spent_nanos != 0 || !observed.units.is_empty() {
            return self
                .price_observed_cell(cost, include_request_fee, cell, observed)?
                .map_err(|error| money_refusal(bucket_id, &error));
        }
        let inputs = money_view::Inputs::of(cost, budget_period, include_request_fee, &cell);
        let priced = match self.money_view.fresh(bucket_id, &inputs) {
            Some(priced) => priced,
            None => {
                let priced = self.price_cell(cost, include_request_fee, cell)?;
                self.money_view.keep(bucket_id, inputs, priced.clone());
                priced
            }
        };
        priced.map_err(|error| money_refusal(bucket_id, &error))
    }

    pub async fn bucket_model_tokens_async(
        &self,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
    ) -> RecordStoreResult<Vec<(String, std::collections::BTreeMap<String, Count>)>> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell_async(bucket_id, window).await?;
        let observed = self.observation_total_async(bucket_id, window).await?;
        model_lanes(&cell, &observed)
    }

    /// The /metrics view of many buckets (keys or group buckets, each with its
    /// budget period) in one pass: the accounting marker once, each bucket's
    /// usage cell once (shared by spend, tokens and per-model lanes) and the
    /// observation budgets in batches. A key listing the caller just read is
    /// the authority for this scrape, so no key record is re-read.
    pub async fn scrape_usage_async(
        &self,
        cost: &crate::cost::CostModel,
        buckets: &[(&str, &str)],
        now: u64,
    ) -> RecordStoreResult<Vec<KeyScrape>> {
        let mut cells = Vec::with_capacity(buckets.len());
        let mut windows = Vec::with_capacity(buckets.len());
        for (id, period) in buckets {
            let window = budget_window(period, now);
            cells.push(self.bucket_cell_async(id, window).await?);
            windows.push((*id, window));
        }
        let observed = self.observation_totals_async(&windows).await?;
        buckets
            .iter()
            .zip(cells)
            .zip(observed)
            .map(|((&(id, period), cell), observed)| {
                let models = model_lanes(&cell, &observed)?;
                let usage = self.viewed_usage(cost, id, period, true, cell, observed)?;
                Ok(KeyScrape { usage, models })
            })
            .collect()
    }

    /// Observation totals for many (bucket, window) pairs: one store open, one
    /// accounting-marker read, budgets read in batches of the store scan limit.
    async fn observation_totals_async(
        &self,
        buckets: &[(&str, u64)],
    ) -> RecordStoreResult<Vec<crate::persistence::observations::BudgetTotal>> {
        use crate::persistence::observations::{BudgetTotal, ObservationStore};
        let none = || buckets.iter().map(|_| BudgetTotal::default()).collect();
        if buckets.is_empty() || !ObservationStore::supports(&self.core) {
            return Ok(none());
        }
        let store = ObservationStore::open(self.core.clone())
            .map_err(|e| RecordStoreError(e.to_string()))?;
        if !store
            .has_accounting()
            .await
            .map_err(|e| RecordStoreError(e.to_string()))?
        {
            return Ok(none());
        }
        let ids: Vec<String> = buckets
            .iter()
            .map(|(bucket, window)| crate::plane_driver::observation_budget_id(bucket, *window))
            .collect();
        let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
        let totals = store
            .budgets(&ids)
            .await
            .map_err(|e| RecordStoreError(e.to_string()))?;
        for ((bucket, window), total) in buckets.iter().zip(&totals) {
            self.cache_observation_total(bucket, *window, total.clone());
        }
        Ok(totals)
    }
}

/// One key's scrape view: its viewed usage and per-model lane totals, both
/// folded from the same cell and observation total.
pub struct KeyScrape {
    pub usage: DerivedUsage,
    pub models: Vec<(String, std::collections::BTreeMap<String, Count>)>,
}

/// Per-model lane totals of one bucket: the cell's model counts plus the
/// observed lanes. Shared by the per-key view and the scrape so they agree.
fn model_lanes(
    cell: &BudgetCell,
    observed: &crate::persistence::observations::BudgetTotal,
) -> RecordStoreResult<Vec<(String, std::collections::BTreeMap<String, Count>)>> {
    let overflow = std::cell::Cell::new(false);
    let models = cell
        .models
        .iter()
        .map(|model| (&*model.model, model.cur.clone()));
    let by_lane = busbar_kernel_ledger::usage::by_lane(models, |a, b| {
        a.checked_add(b).unwrap_or_else(|_| {
            overflow.set(true);
            Count::ZERO
        })
    });
    if overflow.get() {
        return Err(RecordStoreError("lane count total overflow".into()));
    }
    let mut by_lane: BTreeMap<String, BTreeMap<String, Count>> = by_lane.into_iter().collect();
    for (lane, units) in &observed.units {
        let counts = by_lane.entry(lane.clone()).or_default();
        for (class, count) in units {
            let entry = counts.entry(class.clone()).or_default();
            *entry = entry
                .checked_add(*count)
                .map_err(|_| RecordStoreError("observation lane count overflow".into()))?;
        }
    }
    Ok(by_lane.into_iter().collect())
}

impl GovState {
    pub async fn derived_bucket_usage_async(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> RecordStoreResult<DerivedUsage> {
        self.derived_bucket_usage_priced_async(
            cost,
            bucket_id,
            budget_period,
            include_request_fee,
            now,
        )
        .await?
        .map_err(|error| money_refusal(bucket_id, &error))
    }

    pub async fn derived_bucket_usage_priced_async(
        &self,
        cost: &crate::cost::CostModel,
        bucket_id: &str,
        budget_period: &str,
        include_request_fee: bool,
        now: u64,
    ) -> RecordStoreResult<Result<DerivedUsage, MoneyError>> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell_async(bucket_id, window).await?;
        let observed = self.observation_total_async(bucket_id, window).await?;
        self.price_observed_cell(cost, include_request_fee, cell, observed)
    }

    pub(super) async fn observation_total_async(
        &self,
        bucket: &str,
        window: u64,
    ) -> RecordStoreResult<crate::persistence::observations::BudgetTotal> {
        use crate::persistence::observations::{BudgetTotal, ObservationStore};
        if !ObservationStore::supports(&self.core) {
            return Ok(BudgetTotal::default());
        }
        let store = ObservationStore::open(self.core.clone())
            .map_err(|e| RecordStoreError(e.to_string()))?;
        if !store
            .has_accounting()
            .await
            .map_err(|e| RecordStoreError(e.to_string()))?
        {
            return Ok(BudgetTotal::default());
        }
        let total = store
            .budget(&crate::plane_driver::observation_budget_id(bucket, window))
            .await
            .map_err(|e| RecordStoreError(e.to_string()))?;
        self.cache_observation_total(bucket, window, total.clone());
        Ok(total)
    }

    fn price_observed_cell(
        &self,
        cost: &crate::cost::CostModel,
        include_request_fee: bool,
        cell: BudgetCell,
        observed: crate::persistence::observations::BudgetTotal,
    ) -> RecordStoreResult<Result<DerivedUsage, MoneyError>> {
        if observed.spent_nanos == 0 && observed.units.is_empty() {
            return self.price_cell(cost, include_request_fee, cell);
        }
        let tokens = Count::total(
            std::iter::once(cell.total_tokens()).chain(
                observed
                    .units
                    .values()
                    .flat_map(|units| units.iter())
                    .filter(|(class, _)| is_token_class(class))
                    .map(|(_, count)| *count),
            ),
        )
        .map_err(|_| RecordStoreError("observation token count overflow".into()))?;
        let spend = cell
            .spend(cost, include_request_fee)
            .and_then(|ordinary| ordinary.checked_add(Money::of_nanos(observed.spent_nanos)?));
        // Reservations constrain admission but are not fabricated finalized usage.
        Ok(spend
            .and_then(Money::minor_i64)
            .map(|spend_cents| DerivedUsage {
                spend_cents,
                tokens,
                requests: cell.requests,
            }))
    }

    pub(super) async fn bucket_cell_async(
        &self,
        bucket_id: &str,
        window: u64,
    ) -> RecordStoreResult<BudgetCell> {
        let live = {
            let cells = self.budget.read(bucket_id);
            if cells
                .get(bucket_id)
                .is_some_and(|cell| cell.correction.is_some())
            {
                return Err(RecordStoreError(
                    "usage correction outcome unresolved".into(),
                ));
            }
            cells
                .get(bucket_id)
                .filter(|cell| cell.window_start == window)
                .cloned()
        };
        match live {
            Some(cell) => Ok(cell),
            None => self.stored_cell_async(bucket_id, window).await,
        }
    }

    pub(super) async fn stored_cell_async(
        &self,
        bucket_id: &str,
        window: u64,
    ) -> RecordStoreResult<BudgetCell> {
        let core = self.core_store()?;
        let (row, eras) = core
            .ledger()
            .get_usage_pair(bucket_id, &era_bucket(bucket_id), window)
            .await?;
        durable_cell(row, eras, window)
    }
}
