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

    pub async fn viewed_usage_for_async(
        &self,
        cost: &crate::cost::CostModel,
        id: &str,
        now: u64,
    ) -> RecordStoreResult<Option<DerivedUsage>> {
        if self.core_store()?.identity().get_key(id).await?.is_none() {
            return Ok(None);
        }
        self.viewed_bucket_usage_async(cost, id, super::super::WINDOW_TOTAL, true, now)
            .await
            .map(Some)
    }

    pub async fn bucket_model_tokens_async(
        &self,
        bucket_id: &str,
        budget_period: &str,
        now: u64,
    ) -> RecordStoreResult<Vec<(String, std::collections::BTreeMap<String, Count>)>> {
        let window = budget_window(budget_period, now);
        let cell = self.bucket_cell_async(bucket_id, window).await?;
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
        Ok(by_lane)
    }

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
        self.price_cell(cost, include_request_fee, cell)
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
