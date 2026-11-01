// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Raw write-behind debt stays exact even when one legacy signed batch cannot carry it.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Default)]
pub(super) struct ExactModelDelta {
    pub(super) model: String,
    pub(super) usage_units: BTreeMap<String, i128>,
}
#[derive(Clone, Default)]
pub(super) struct ExactUsageDelta {
    pub(super) requests: i128,
    pub(super) billable_requests: i128,
    pub(super) models: Vec<ExactModelDelta>,
}
impl ExactUsageDelta {
    pub(super) fn is_zero(&self) -> bool {
        self.requests == 0
            && self.billable_requests == 0
            && self
                .models
                .iter()
                .all(|model| model.usage_units.values().all(|count| *count == 0))
    }
    fn unit(&mut self, model: &str, unit: &str, change: i128) {
        if change == 0 {
            return;
        }
        let position = self.models.iter().position(|row| row.model == model);
        let row = match position {
            Some(position) => &mut self.models[position],
            None => {
                self.models.push(ExactModelDelta {
                    model: model.into(),
                    usage_units: BTreeMap::new(),
                });
                self.models.last_mut().expect("just inserted raw model")
            }
        };
        *row.usage_units.entry(unit.into()).or_default() += change;
    }
    pub(super) fn merge(&mut self, other: &Self) {
        self.requests += other.requests;
        self.billable_requests += other.billable_requests;
        for model in &other.models {
            for (unit, count) in &model.usage_units {
                self.unit(&model.model, unit, *count);
            }
        }
    }
    pub(super) fn from_signed(delta: &UsageDelta) -> Self {
        Self {
            requests: i128::from(delta.requests),
            billable_requests: i128::from(delta.billable_requests),
            models: delta
                .models
                .iter()
                .map(|model| ExactModelDelta {
                    model: model.model.clone(),
                    usage_units: model
                        .usage_units
                        .iter()
                        .map(|(unit, count)| (unit.clone(), i128::from(*count)))
                        .collect(),
                })
                .collect(),
        }
    }
    pub(super) fn signed(&self) -> Option<UsageDelta> {
        Some(UsageDelta {
            requests: i64::try_from(self.requests).ok()?,
            billable_requests: i64::try_from(self.billable_requests).ok()?,
            models: self
                .models
                .iter()
                .map(|model| {
                    Some(busbar_contract::records::ModelTokensDelta {
                        model: model.model.clone(),
                        usage_units: model
                            .usage_units
                            .iter()
                            .filter(|(_, count)| **count != 0)
                            .map(|(unit, count)| {
                                i64::try_from(*count)
                                    .ok()
                                    .map(|count| (unit.clone(), count))
                            })
                            .collect::<Option<_>>()?,
                    })
                })
                .collect::<Option<_>>()?,
        })
    }
    pub(super) fn of(cell: &BudgetCell, dated: bool) -> Self {
        let mut debt = Self::default();
        if !dated {
            debt.requests = i128::from(cell.requests) - i128::from(cell.flushed_requests);
            debt.billable_requests =
                i128::from(cell.billable_requests) - i128::from(cell.flushed_billable_requests);
        }
        for model in &cell.models {
            if dated && model.era == 0 {
                continue;
            }
            let name = if dated {
                format!("{}{ERA_MODEL_SEP}{}", model.era, model.model)
            } else {
                model.model.to_string()
            };
            let flushed = if dated {
                &model.flushed_era
            } else {
                &model.flushed
            };
            for unit in model
                .cur
                .keys()
                .chain(flushed.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                debt.unit(
                    &name,
                    unit,
                    i128::from(model.cur.get(unit).copied().unwrap_or(0))
                        - i128::from(flushed.get(unit).copied().unwrap_or(0)),
                );
            }
        }
        if dated {
            let current: BTreeMap<_, _> = cell.fee_eras.dated().iter().copied().collect();
            let flushed: BTreeMap<_, _> = cell.flushed_fee_eras.dated().iter().copied().collect();
            for era in current
                .keys()
                .chain(flushed.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                debt.unit(
                    &era.to_string(),
                    ERA_FEE_UNIT,
                    i128::from(current.get(era).copied().unwrap_or(0))
                        - i128::from(flushed.get(era).copied().unwrap_or(0)),
                );
            }
        }
        debt
    }
}
