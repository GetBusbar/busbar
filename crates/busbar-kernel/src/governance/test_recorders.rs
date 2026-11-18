// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Usage and lane-metering recorders that only tests call. Each reads the price era from the clock
//! (or takes it from the test); the request path never runs them: it records through
//! `record_counts_served_on` and `record_lane_counts_in_era`, which take the unit's era. They live
//! here, compiled only for tests and the `test-support` feature, so they are not in the shipped build.

use super::*;

impl GovState {
    pub fn record_usage(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        self.record_usage_served(cost, key, pool, model, None, units, now);
    }

    pub fn record_usage_served(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        let era = crate::rate_apply::era_at(crate::store::now_ms());
        self.record_usage_served_in_era(cost, key, pool, model, provider, units, now, era);
    }

    pub fn record_usage_served_in_era(
        &self,
        cost: &crate::cost::CostModel,
        key: &VirtualKey,
        pool: &str,
        model: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
        era: RawRateEra,
    ) {
        self.record_counts_served_in_era(
            cost,
            key,
            pool,
            model,
            provider,
            &whole_counts(units),
            now,
            era,
        )
        .expect("whole usage accrual exceeds Count range");
    }

    pub fn record_lane_metering(
        &self,
        key_id: &str,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        self.record_lane_metering_attributed(
            key_id,
            "",
            lane,
            provider,
            &whole_counts(units),
            now,
            crate::rate_apply::era_at(crate::store::now_ms()),
        )
        .expect("whole metering accumulation exceeds Count range");
    }

    pub fn record_lane_metering_for_key(
        &self,
        key: &VirtualKey,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
    ) {
        self.record_lane_metering_in_era(
            key,
            lane,
            provider,
            units,
            now,
            crate::rate_apply::era_at(crate::store::now_ms()),
        );
    }

    pub fn record_lane_metering_in_era(
        &self,
        key: &VirtualKey,
        lane: &str,
        provider: Option<&str>,
        units: &std::collections::BTreeMap<String, u64>,
        now: u64,
        era: RawRateEra,
    ) {
        self.record_lane_counts_in_era(key, lane, provider, &whole_counts(units), now, era)
            .expect("whole metering accrual exceeds Count range");
    }
}
