// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::{MeteringDelta, MeteringRow, ModelTokens, ModelTokensDelta, UsageDelta, UsageLedger};
use crate::count::{Count, CountError, COUNT_SCALE};

pub(super) fn is_whole(scale: &u32) -> bool {
    *scale == 0
}

fn signed(value: i128, scale: u32) -> Result<i64, CountError> {
    let count = Count::from_stored(value, scale)?;
    i64::try_from(count.micros()).map_err(|_| CountError::OutOfRange)
}

fn unsigned(value: u64, scale: u32) -> Result<u64, CountError> {
    u64::try_from(signed(i128::from(value), scale)?).map_err(|_| CountError::Negative)
}

impl ModelTokens {
    /// Convert a legacy row exactly once. Failure leaves the entire row unchanged.
    pub fn normalize_scale6(&mut self) -> Result<(), CountError> {
        let values = self
            .usage_units
            .iter()
            .map(|(key, value)| unsigned(*value, self.scale).map(|v| (key.clone(), v)))
            .collect::<Result<_, _>>()?;
        // Validate an empty row's discriminator too.
        signed(0, self.scale)?;
        self.usage_units = values;
        self.scale = COUNT_SCALE;
        Ok(())
    }

    /// Decode the complete measurement map without rounding.
    pub fn counts(&self) -> Result<std::collections::BTreeMap<String, Count>, CountError> {
        Count::from_stored(0, self.scale)?;
        self.usage_units
            .iter()
            .map(|(key, value)| {
                Count::from_stored(i128::from(*value), self.scale).map(|count| (key.clone(), count))
            })
            .collect()
    }
}

impl ModelTokensDelta {
    /// Convert signed changes to micro-units, checking the complete row before mutation.
    pub fn normalize_scale6(&mut self) -> Result<(), CountError> {
        let values = self
            .usage_units
            .iter()
            .map(|(key, value)| signed(i128::from(*value), self.scale).map(|v| (key.clone(), v)))
            .collect::<Result<_, _>>()?;
        signed(0, self.scale)?;
        self.usage_units = values;
        self.scale = COUNT_SCALE;
        Ok(())
    }
}

impl UsageLedger {
    /// Apply a signed delta atomically at scale six, refusing aggregate overflow.
    pub fn checked_apply_delta(&mut self, delta: &UsageDelta) -> Result<(), CountError> {
        let mut row = self.clone();
        let mut delta = delta.clone();
        row.normalize_scale6()?;
        delta.normalize_scale6()?;
        for change in delta.models {
            let position = row
                .models
                .iter()
                .position(|model| model.model == change.model);
            let model = match position {
                Some(position) => &mut row.models[position],
                None => {
                    row.models.push(ModelTokens {
                        scale: COUNT_SCALE,
                        model: change.model,
                        usage_units: Default::default(),
                    });
                    row.models.last_mut().expect("inserted model")
                }
            };
            for (class, change) in change.usage_units {
                let count = model.usage_units.entry(class).or_default();
                let total = (i128::from(*count) + i128::from(change)).max(0);
                *count = unsigned(
                    u64::try_from(total).map_err(|_| CountError::Overflow)?,
                    COUNT_SCALE,
                )?;
            }
        }
        row.requests = row.requests.saturating_add_signed(delta.requests);
        row.billable_requests = row
            .billable_requests
            .saturating_add_signed(delta.billable_requests);
        *self = row;
        Ok(())
    }

    /// Normalize all models atomically in memory; admission and fee counters are unscaled.
    pub fn normalize_scale6(&mut self) -> Result<(), CountError> {
        let mut models = self.models.clone();
        for row in &mut models {
            row.normalize_scale6()?;
        }
        self.models = models;
        Ok(())
    }
}

impl UsageDelta {
    /// Normalize all signed models atomically; request deltas remain whole numbers.
    pub fn normalize_scale6(&mut self) -> Result<(), CountError> {
        let mut models = self.models.clone();
        for row in &mut models {
            row.normalize_scale6()?;
        }
        self.models = models;
        Ok(())
    }
}

macro_rules! metering {
    ($ty:ty) => {
        impl $ty {
            /// Normalize quantity columns and open counts atomically; request counters are unscaled.
            pub fn normalize_scale6(&mut self) -> Result<(), CountError> {
                let mut row = self.clone();
                row.tokens_input = unsigned(row.tokens_input, row.scale)?;
                row.tokens_output = unsigned(row.tokens_output, row.scale)?;
                row.tokens_cache_read = unsigned(row.tokens_cache_read, row.scale)?;
                row.tokens_cache_write = unsigned(row.tokens_cache_write, row.scale)?;
                for value in row.usage_units.values_mut() {
                    *value = unsigned(*value, row.scale)?;
                }
                row.scale = COUNT_SCALE;
                *self = row;
                Ok(())
            }
        }
    };
}
metering!(MeteringDelta);
metering!(MeteringRow);

impl MeteringRow {
    /// Add measurements atomically, rejecting a quantity outside the declared store range.
    pub fn checked_add_delta(&mut self, delta: &MeteringDelta) -> Result<(), CountError> {
        let mut row = self.clone();
        let mut delta = delta.clone();
        row.normalize_scale6()?;
        delta.normalize_scale6()?;
        let add =
            |a: u64, b: u64| unsigned(a.checked_add(b).ok_or(CountError::Overflow)?, COUNT_SCALE);
        row.tokens_input = add(row.tokens_input, delta.tokens_input)?;
        row.tokens_output = add(row.tokens_output, delta.tokens_output)?;
        row.tokens_cache_read = add(row.tokens_cache_read, delta.tokens_cache_read)?;
        row.tokens_cache_write = add(row.tokens_cache_write, delta.tokens_cache_write)?;
        for (class, amount) in delta.usage_units {
            let count = row.usage_units.entry(class).or_default();
            *count = add(*count, amount)?;
        }
        row.requests = row.requests.saturating_add(delta.requests);
        row.billable_requests = row
            .billable_requests
            .saturating_add(delta.billable_requests);
        *self = row;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn legacy_migration_is_exact_reentrant_and_atomic() {
        let mut ledger: UsageLedger = serde_json::from_str(
            r#"{"requests":1,"models":[{"model":"m","usage_units":{"input":27}}]}"#,
        )
        .unwrap();
        ledger.normalize_scale6().unwrap();
        assert_eq!(ledger.models[0].scale, 6);
        assert_eq!(ledger.models[0].usage_units["input"], 27_000_000);
        let once = ledger.clone();
        ledger.normalize_scale6().unwrap();
        assert_eq!(ledger, once);
        ledger.models.push(ModelTokens {
            scale: 0,
            model: "overflow".into(),
            usage_units: BTreeMap::from([("input".into(), i64::MAX as u64)]),
        });
        let before = ledger.clone();
        assert_eq!(ledger.normalize_scale6(), Err(CountError::OutOfRange));
        assert_eq!(ledger, before);
    }

    #[test]
    fn fractional_delta_adds_to_legacy_quantity_without_reinterpreting_it() {
        let mut ledger = UsageLedger {
            models: vec![ModelTokens {
                scale: 0,
                model: "m".into(),
                usage_units: BTreeMap::from([("input".into(), 27)]),
            }],
            ..Default::default()
        };
        ledger
            .checked_apply_delta(&UsageDelta {
                models: vec![ModelTokensDelta {
                    scale: 6,
                    model: "m".into(),
                    usage_units: BTreeMap::from([("input".into(), 500_000)]),
                }],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            ledger.models[0].counts().unwrap()["input"],
            Count::parse("27.5").unwrap()
        );
        let wire = serde_json::to_vec(&ledger).unwrap();
        let back: UsageLedger = serde_json::from_slice(&wire).unwrap();
        assert_eq!(back, ledger);
        let before = ledger.clone();
        assert!(ledger
            .checked_apply_delta(&UsageDelta {
                models: vec![ModelTokensDelta {
                    scale: 6,
                    model: "m".into(),
                    usage_units: BTreeMap::from([("input".into(), i64::MAX)])
                }],
                ..Default::default()
            })
            .is_err());
        assert_eq!(ledger, before);
    }

    #[test]
    fn decimal_json_stays_numeric_and_exact() {
        for text in ["27.5", "27.1", "27.0", "1e3", "0.000001"] {
            let count: Count = serde_json::from_str(text).unwrap();
            assert_eq!(count, Count::parse(text).unwrap());
            let back: Count =
                serde_json::from_str(&serde_json::to_string(&count).unwrap()).unwrap();
            assert_eq!(back, count);
        }
        assert!(serde_json::from_str::<Count>("0.0000001").is_err());
    }
}
