// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Arithmetic over explicit logical facts and declared projection requirements.
use super::HistoricalFact;
use crate::{
    Error,
    legacy::{
        HistoricalRow, UsageCell, assemble_usage, attach_metering_units, attach_usage_units,
        canonical_metering, canonical_usage, transform::Output,
    },
};
use busbar_contract::{
    persistence::lifecycle::source::{AccountingRole, RequestAggregation},
    records::{MeteringRow, ModelTokens, RESERVED_UNITS, UsageLedger},
};
use std::collections::{BTreeMap, BTreeSet};
fn invalid(_: crate::legacy::Error) -> Error {
    Error::Verification
}
pub struct VerifiedAccounting {
    pub usage: Vec<(String, u64, UsageLedger)>,
    pub metering: Vec<(u64, MeteringRow)>,
}
type UsageKey = (String, u64);
type MeterKey = (u64, String, String, String, u64, String, String);
fn meter_key(bucket: u64, row: &MeteringRow) -> MeterKey {
    (
        bucket,
        row.key_id.clone(),
        row.provider.clone(),
        row.model.clone(),
        row.priced_from_ms,
        row.key_group_at_use.clone(),
        row.pricing_version.clone(),
    )
}
fn projected(value: i128) -> i128 {
    value.min(i128::from(i64::MAX))
}
fn projected_requests(value: u64) -> u64 {
    value.min(i64::MAX as u64)
}
fn projections<'a>(
    rows: impl IntoIterator<Item = Result<(bool, HistoricalRow<'a>), Error>>,
) -> Result<VerifiedAccounting, Error> {
    let mut exact_usage = BTreeMap::<UsageKey, UsageLedger>::new();
    let mut usage_mirrors = BTreeMap::<(UsageKey, String), UsageLedger>::new();
    let mut usage_units = BTreeMap::<(UsageKey, String, String), i128>::new();
    let mut exact_metering = BTreeMap::<MeterKey, MeteringRow>::new();
    let mut meter_mirrors = BTreeMap::<MeterKey, MeteringRow>::new();
    let mut meter_units = BTreeMap::<(MeterKey, String), i128>::new();
    for input in rows {
        let (authoritative, decoded) = input?;
        let duplicate = match decoded {
            HistoricalRow::ExactUsage {
                bucket,
                window,
                ledger,
            } => exact_usage.insert((bucket, window), ledger).is_some(),
            HistoricalRow::Usage(cell) => usage_mirrors
                .insert(((cell.bucket, cell.window), cell.model), cell.ledger)
                .is_some(),
            HistoricalRow::UsageUnit {
                bucket,
                window,
                model,
                unit,
                count,
            } => usage_units
                .insert(((bucket, window), model, unit), count)
                .is_some(),
            HistoricalRow::Metering { bucket, row } if authoritative => exact_metering
                .insert(meter_key(bucket, &row), row)
                .is_some(),
            HistoricalRow::Metering { bucket, row } if !authoritative => {
                meter_mirrors.insert(meter_key(bucket, &row), row).is_some()
            }
            HistoricalRow::MeteringUnit {
                bucket,
                key_id,
                provider,
                model,
                priced_from_ms,
                key_group_at_use: Some(group),
                pricing_version: Some(version),
                unit,
                count,
            } => meter_units
                .insert(
                    (
                        (
                            bucket,
                            key_id,
                            provider,
                            model,
                            priced_from_ms,
                            group,
                            version,
                        ),
                        unit,
                    ),
                    count,
                )
                .is_some(),
            _ => return Err(Error::UnsupportedPath),
        };
        if duplicate {
            return Err(Error::Verification);
        }
    }
    for (key, exact) in &exact_usage {
        let counts = usage_mirrors
            .remove(&(key.clone(), String::new()))
            .ok_or(Error::Verification)?;
        if counts.requests != projected_requests(exact.requests)
            || counts.billable_requests != projected_requests(exact.billable_requests)
            || !counts.models.is_empty()
        {
            return Err(Error::Verification);
        }
        for model in exact.models.iter().filter(|m| !m.model.is_empty()) {
            let actual = usage_mirrors
                .remove(&(key.clone(), model.model.clone()))
                .ok_or(Error::Verification)?;
            let expected = ModelTokens {
                scale: 6,
                model: model.model.clone(),
                usage_units: RESERVED_UNITS
                    .into_iter()
                    .map(|unit| {
                        (
                            unit.to_owned(),
                            projected(model.usage_units.get(unit).copied().unwrap_or(0)),
                        )
                    })
                    .collect(),
            };
            if actual.requests != 0 || actual.billable_requests != 0 || actual.models != [expected]
            {
                return Err(Error::Verification);
            }
            for (unit, count) in &model.usage_units {
                if RESERVED_UNITS.contains(&unit.as_str()) || *count == 0 {
                    continue;
                }
                if usage_units.remove(&(key.clone(), model.model.clone(), unit.clone()))
                    != Some(projected(*count))
                {
                    return Err(Error::Verification);
                }
            }
        }
    }
    // A valid writer may have persisted a zero open-unit mirror immediately
    // before omitting zero open units from its exact JSON. Keep its raw source
    // evidence and coverage; it must still name an existing exact model.
    for ((key, model, unit), count) in &usage_units {
        if *count != 0
            || RESERVED_UNITS.contains(&unit.as_str())
            || !exact_usage.get(key).is_some_and(|ledger| {
                ledger.models.iter().any(|m| {
                    m.model == *model
                        && !m.model.is_empty()
                        && m.usage_units.get(unit).copied().unwrap_or(0) == 0
                })
            })
        {
            return Err(Error::Verification);
        }
    }
    if !usage_mirrors.is_empty() {
        return Err(Error::Verification);
    }
    for (key, exact) in &exact_metering {
        let mut expected = exact.clone();
        expected.tokens_input = projected(expected.tokens_input);
        expected.tokens_output = projected(expected.tokens_output);
        expected.tokens_cache_read = projected(expected.tokens_cache_read);
        expected.tokens_cache_write = projected(expected.tokens_cache_write);
        expected.requests = projected_requests(expected.requests);
        expected.billable_requests = projected_requests(expected.billable_requests);
        for (unit, count) in &mut expected.usage_units {
            *count = projected(*count);
            if meter_units.remove(&(key.clone(), unit.clone())) != Some(*count) {
                return Err(Error::Verification);
            }
        }
        expected.usage_units.clear();
        if meter_mirrors.remove(key).as_ref() != Some(&expected) {
            return Err(Error::Verification);
        }
    }
    if !meter_mirrors.is_empty() || !meter_units.is_empty() {
        return Err(Error::Verification);
    }
    Ok(VerifiedAccounting {
        usage: exact_usage
            .into_iter()
            .map(|((bucket, window), ledger)| (bucket, window, ledger))
            .collect(),
        metering: exact_metering
            .into_iter()
            .map(|(key, row)| (key.0, row))
            .collect(),
    })
}

fn fragments(decoded: Vec<HistoricalRow<'_>>, out: &mut Output) -> Result<(), Error> {
    let mut usage = BTreeMap::<(String, u64), Vec<UsageCell>>::new();
    let mut meters = Vec::new();
    let mut units = Vec::new();
    for row in decoded {
        match row {
            HistoricalRow::Usage(cell) => usage
                .entry((cell.bucket.clone(), cell.window))
                .or_default()
                .push(cell),
            HistoricalRow::UsageUnit { .. } | HistoricalRow::MeteringUnit { .. } => units.push(row),
            HistoricalRow::Metering { bucket, row } => meters.push((bucket, row)),
            _ => return Err(Error::UnsupportedPath),
        }
    }
    // Historical readers explicitly allowed sparse open-unit-only
    // usage groups and supplied zero absent request/reserved columns.
    for unit in &units {
        if let HistoricalRow::UsageUnit { bucket, window, .. } = unit {
            usage.entry((bucket.clone(), *window)).or_default();
        }
    }
    let mut consumed = BTreeSet::new();
    for ((bucket, window), cells) in usage {
        let mut selected = Vec::new();
        for (i, unit) in units.iter().enumerate() {
            if let HistoricalRow::UsageUnit {
                bucket: b,
                window: w,
                model,
                unit,
                count,
            } = unit
            {
                if b == &bucket && *w == window {
                    consumed.insert(i);
                    selected.push(HistoricalRow::UsageUnit {
                        bucket: b.clone(),
                        window: *w,
                        model: model.clone(),
                        unit: unit.clone(),
                        count: *count,
                    });
                }
            }
        }
        let base = if cells.is_empty() {
            UsageLedger::default()
        } else {
            assemble_usage(&cells).map_err(invalid)?
        };
        let ledger = attach_usage_units(&bucket, window, &base, &selected).map_err(invalid)?;
        out.canonical(
            canonical_usage(&bucket, window, &ledger).map_err(invalid)?,
            true,
        )?;
    }
    for (bucket, row) in meters {
        let mut selected = Vec::new();
        for (i, unit) in units.iter().enumerate() {
            if let HistoricalRow::MeteringUnit {
                bucket: b,
                key_id,
                provider,
                model,
                priced_from_ms,
                key_group_at_use,
                pricing_version,
                unit,
                count,
            } = unit
            {
                if *b == bucket
                    && key_id == &row.key_id
                    && provider == &row.provider
                    && model == &row.model
                    && *priced_from_ms == row.priced_from_ms
                    && key_group_at_use
                        .as_ref()
                        .is_none_or(|v| v == &row.key_group_at_use)
                    && pricing_version
                        .as_ref()
                        .is_none_or(|v| v == &row.pricing_version)
                {
                    if !consumed.insert(i) {
                        return Err(Error::Verification);
                    }
                    selected.push(HistoricalRow::MeteringUnit {
                        bucket: *b,
                        key_id: key_id.clone(),
                        provider: provider.clone(),
                        model: model.clone(),
                        priced_from_ms: *priced_from_ms,
                        key_group_at_use: key_group_at_use.clone(),
                        pricing_version: pricing_version.clone(),
                        unit: unit.clone(),
                        count: *count,
                    });
                }
            }
        }
        let row = attach_metering_units(bucket, &row, &selected).map_err(invalid)?;
        out.canonical(canonical_metering(bucket, &row).map_err(invalid)?, true)?;
    }
    if consumed.len() != units.len() {
        return Err(Error::Verification);
    }
    Ok(())
}

fn row(fact: &HistoricalFact) -> Result<(AccountingRole, HistoricalRow<'static>), Error> {
    Ok(match fact {
        HistoricalFact::Usage {
            bucket,
            window,
            model,
            requests,
            ledger,
            role,
        } => (
            *role,
            if matches!(
                role,
                AccountingRole::Exact | AccountingRole::ExactWithSigned64Projection
            ) {
                HistoricalRow::ExactUsage {
                    bucket: bucket.clone(),
                    window: *window,
                    ledger: ledger.clone(),
                }
            } else {
                HistoricalRow::Usage(UsageCell {
                    bucket: bucket.clone(),
                    window: *window,
                    model: model.clone(),
                    sum_requests: *requests == RequestAggregation::Sum,
                    ledger: ledger.clone(),
                })
            },
        ),
        HistoricalFact::UsageUnit {
            bucket,
            window,
            model,
            unit,
            count,
            role,
        } => (
            *role,
            HistoricalRow::UsageUnit {
                bucket: bucket.clone(),
                window: *window,
                model: model.clone(),
                unit: unit.clone(),
                count: *count,
            },
        ),
        HistoricalFact::Metering { bucket, row, role } => (
            *role,
            HistoricalRow::Metering {
                bucket: *bucket,
                row: row.clone(),
            },
        ),
        HistoricalFact::MeteringUnit {
            bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            key_group_at_use,
            pricing_version,
            unit,
            count,
            role,
        } => (
            *role,
            HistoricalRow::MeteringUnit {
                bucket: *bucket,
                key_id: key_id.clone(),
                provider: provider.clone(),
                model: model.clone(),
                priced_from_ms: *priced_from_ms,
                key_group_at_use: key_group_at_use.clone(),
                pricing_version: pricing_version.clone(),
                unit: unit.clone(),
                count: *count,
            },
        ),
        _ => return Err(Error::Corrupt),
    })
}
pub(crate) fn convert(facts: &[super::FactRow], out: &mut Output) -> Result<(), Error> {
    let decoded = facts
        .iter()
        .map(|fact| row(fact.fact()))
        .collect::<Result<Vec<_>, _>>()?;
    if decoded.iter().any(|(role, _)| {
        matches!(
            role,
            AccountingRole::ExactWithSigned64Projection | AccountingRole::Signed64Projection
        )
    }) {
        if decoded
            .iter()
            .any(|(role, _)| matches!(role, AccountingRole::Fragment | AccountingRole::Exact))
        {
            return Err(Error::Verification);
        }
        let verified =
            projections(decoded.into_iter().map(|(role, row)| {
                Ok((role == AccountingRole::ExactWithSigned64Projection, row))
            }))?;
        for (bucket, window, ledger) in verified.usage {
            out.canonical(
                canonical_usage(&bucket, window, &ledger).map_err(invalid)?,
                true,
            )?;
        }
        for (bucket, row) in verified.metering {
            out.canonical(canonical_metering(bucket, &row).map_err(invalid)?, true)?;
        }
        return Ok(());
    }
    if decoded
        .iter()
        .any(|(role, _)| *role == AccountingRole::Exact)
    {
        for (role, row) in decoded {
            if role != AccountingRole::Exact {
                return Err(Error::Verification);
            }
            match row {
                HistoricalRow::ExactUsage {
                    bucket,
                    window,
                    ledger,
                } => out.canonical(
                    canonical_usage(&bucket, window, &ledger).map_err(invalid)?,
                    true,
                )?,
                HistoricalRow::Metering { bucket, row } => {
                    out.canonical(canonical_metering(bucket, &row).map_err(invalid)?, true)?
                }
                _ => return Err(Error::Verification),
            }
        }
        return Ok(());
    }
    fragments(decoded.into_iter().map(|(_, row)| row).collect(), out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_facts::FactRow;
    use busbar_contract::{
        Secret,
        persistence::lifecycle::{
            DocumentSemantics, SourceCodec, SourceReader,
            source::{HistoricalFamily, SourceChunk},
        },
    };
    fn fact(value: HistoricalFact) -> FactRow {
        FactRow {
            chunk: SourceChunk {
                reader: SourceReader::new(
                    SourceCodec::HistoricalV1,
                    DocumentSemantics::Current,
                    [1; 32],
                )
                .unwrap(),
                family: HistoricalFamily::Accounting,
                group: Secret::new(b"group".to_vec()),
                sequence: 0,
                complete: false,
                evidence: vec![],
                facts: vec![value],
            },
        }
    }
    fn ledger() -> UsageLedger {
        UsageLedger {
            requests: u64::MAX,
            billable_requests: 3,
            models: vec![ModelTokens {
                scale: 6,
                model: "m".into(),
                usage_units: BTreeMap::from([
                    ("input".into(), i128::from(i64::MAX) + 1),
                    ("seconds".into(), 9),
                ]),
            }],
        }
    }
    fn projected_group() -> Vec<FactRow> {
        let usage = |model: &str, ledger, role| {
            fact(HistoricalFact::Usage {
                bucket: "bucket".into(),
                window: 0,
                model: model.into(),
                requests: RequestAggregation::Dedicated,
                ledger,
                role,
            })
        };
        vec![
            usage("", ledger(), AccountingRole::ExactWithSigned64Projection),
            usage(
                "",
                UsageLedger {
                    requests: i64::MAX as u64,
                    billable_requests: 3,
                    models: vec![],
                },
                AccountingRole::Signed64Projection,
            ),
            usage(
                "m",
                UsageLedger {
                    requests: 0,
                    billable_requests: 0,
                    models: vec![ModelTokens {
                        scale: 6,
                        model: "m".into(),
                        usage_units: RESERVED_UNITS
                            .into_iter()
                            .map(|unit| {
                                (
                                    unit.into(),
                                    if unit == "input" {
                                        i128::from(i64::MAX)
                                    } else {
                                        0
                                    },
                                )
                            })
                            .collect(),
                    }],
                },
                AccountingRole::Signed64Projection,
            ),
            fact(HistoricalFact::UsageUnit {
                bucket: "bucket".into(),
                window: 0,
                model: "m".into(),
                unit: "seconds".into(),
                count: 9,
                role: AccountingRole::Signed64Projection,
            }),
        ]
    }
    fn output(facts: &[FactRow]) -> Result<Vec<crate::TargetRow>, Error> {
        let mut out = Output::new(crate::Bounds {
            items: 32,
            bytes: 65536,
        });
        convert(facts, &mut out)?;
        Ok(out.finish())
    }
    #[test]
    fn explicit_projection_requirement_preserves_wide_totals_and_refuses_missing_members() {
        let expected = canonical_usage("bucket", 0, &ledger()).unwrap();
        let rows = output(&projected_group()).unwrap();
        for (address, value) in expected {
            assert!(
                rows.iter()
                    .any(|r| r.address == address && r.value == value)
            );
        }
        for missing in 0..4 {
            let mut facts = projected_group();
            facts.remove(missing);
            assert!(
                matches!(output(&facts), Err(Error::Verification)),
                "missing {missing}"
            );
        }
        let mut wrong = projected_group();
        if let HistoricalFact::UsageUnit { count, .. } = &mut wrong[3].chunk.facts[0] {
            *count = 10;
        }
        assert!(matches!(output(&wrong), Err(Error::Verification)));
    }
    #[test]
    fn standalone_exact_fact_needs_no_physical_projection() {
        let input = fact(HistoricalFact::Usage {
            bucket: "bucket".into(),
            window: 0,
            model: String::new(),
            requests: RequestAggregation::Dedicated,
            ledger: ledger(),
            role: AccountingRole::Exact,
        });
        let rows = output(&[input]).unwrap();
        for (address, value) in canonical_usage("bucket", 0, &ledger()).unwrap() {
            assert!(
                rows.iter()
                    .any(|r| r.address == address && r.value == value)
            );
        }
    }
    #[test]
    fn duplicate_exact_and_orphan_projection_refuse_activation() {
        let mut duplicate = projected_group();
        duplicate.insert(0, projected_group().remove(0));
        assert!(output(&duplicate).is_err());
        let mut orphan = projected_group();
        orphan.remove(0);
        assert!(output(&orphan).is_err());
        let exact_only = vec![projected_group().remove(0)];
        assert!(output(&exact_only).is_err());
    }
}
