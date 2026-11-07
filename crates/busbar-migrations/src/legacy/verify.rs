// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete bounded SQLite schema-9 accounting inventory verification. Exact
//! JSON is authoritative; signed column mirrors are verified as projections and
//! never become the imported quantity. Every supplied row is consumed or fails.
use super::*;
use std::collections::BTreeMap;

pub struct PhysicalRow<'a> {
    pub table: &'a str,
    pub columns: &'a [&'a str],
    pub row: Row<'a>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Coverage {
    pub exact_usage: usize,
    pub usage_mirrors: usize,
    pub usage_units: usize,
    pub exact_metering: usize,
    pub metering_mirrors: usize,
    pub metering_units: usize,
}
pub struct VerifiedAccounting {
    pub usage: Vec<(String, u64, UsageLedger)>,
    pub metering: Vec<(u64, MeteringRow)>,
    pub coverage: Coverage,
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
fn bounded(rows: &[PhysicalRow<'_>], max_rows: usize, max_bytes: usize) -> Result<(), Error> {
    if rows.len() > max_rows || max_rows == 0 || max_bytes == 0 {
        return Err(Error::Range);
    }
    let mut bytes = 0usize;
    for row in rows {
        for cell in row.row.cells() {
            let size = match cell {
                Cell::Null => 1,
                Cell::Integer(_) | Cell::RealBits(_) => 9,
                Cell::Text(v) | Cell::Blob(v) => v.len().checked_add(9).ok_or(Error::Range)?,
            };
            bytes = bytes.checked_add(size).ok_or(Error::Range)?;
            if bytes > max_bytes {
                return Err(Error::Range);
            }
        }
    }
    Ok(())
}

/// The reader/coordinator must supply the complete accounting inventory of its
/// pinned frozen snapshot, or a complete union-key group. Coverage counts bind
/// this result to that inventory; a page or a highest key is not completeness.
/// Groups larger than the explicit budget refuse rather than truncate.
pub fn sqlite9(
    rows: &[PhysicalRow<'_>],
    max_rows: usize,
    max_bytes: usize,
) -> Result<VerifiedAccounting, Error> {
    bounded(rows, max_rows, max_bytes)?;
    sqlite9_decoded(rows.iter().map(|physical| {
        // Schema 8 has the identical mirror shape and explicit micro scale.
        // Decode mirrors under that profile solely for projection comparison.
        let profile = if matches!(
            physical.table,
            "usage_window_exact" | "usage_metering_exact"
        ) {
            Profile::SqliteDev9
        } else {
            Profile::SqliteDev8
        };
        let decoded = decode(profile, physical.table, physical.columns, physical.row)?;
        Ok((physical.table, decoded))
    }))
}

/// Incremental decoder entry: callers may stream protected physical rows and
/// retain only their owned accounting meaning, without source-row item limits.
pub fn sqlite9_decoded<'a, 't>(
    rows: impl IntoIterator<Item = Result<(&'t str, HistoricalRow<'a>), Error>>,
) -> Result<VerifiedAccounting, Error> {
    let mut exact_usage = BTreeMap::<UsageKey, UsageLedger>::new();
    let mut usage_mirrors = BTreeMap::<(UsageKey, String), UsageLedger>::new();
    let mut usage_units = BTreeMap::<(UsageKey, String, String), i128>::new();
    let mut exact_metering = BTreeMap::<MeterKey, MeteringRow>::new();
    let mut meter_mirrors = BTreeMap::<MeterKey, MeteringRow>::new();
    let mut meter_units = BTreeMap::<(MeterKey, String), i128>::new();
    let mut coverage = Coverage::default();
    for input in rows {
        let (table, decoded) = input?;
        let duplicate = match decoded {
            HistoricalRow::ExactUsage {
                bucket,
                window,
                ledger,
            } => {
                coverage.exact_usage += 1;
                exact_usage.insert((bucket, window), ledger).is_some()
            }
            HistoricalRow::Usage(cell) => {
                coverage.usage_mirrors += 1;
                usage_mirrors
                    .insert(((cell.bucket, cell.window), cell.model), cell.ledger)
                    .is_some()
            }
            HistoricalRow::UsageUnit {
                bucket,
                window,
                model,
                unit,
                count,
            } => {
                coverage.usage_units += 1;
                usage_units
                    .insert(((bucket, window), model, unit), count)
                    .is_some()
            }
            HistoricalRow::Metering { bucket, row } if table == "usage_metering_exact" => {
                coverage.exact_metering += 1;
                exact_metering
                    .insert(meter_key(bucket, &row), row)
                    .is_some()
            }
            HistoricalRow::Metering { bucket, row } if table == "usage_metering" => {
                coverage.metering_mirrors += 1;
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
            } => {
                coverage.metering_units += 1;
                meter_units
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
                    .is_some()
            }
            _ => return Err(Error::Unsupported),
        };
        if duplicate {
            return Err(Error::Invalid);
        }
    }
    for (key, exact) in &exact_usage {
        let counts = usage_mirrors
            .remove(&(key.clone(), String::new()))
            .ok_or(Error::Invalid)?;
        if counts.requests != projected_requests(exact.requests)
            || counts.billable_requests != projected_requests(exact.billable_requests)
            || !counts.models.is_empty()
        {
            return Err(Error::Invalid);
        }
        for model in exact.models.iter().filter(|m| !m.model.is_empty()) {
            let actual = usage_mirrors
                .remove(&(key.clone(), model.model.clone()))
                .ok_or(Error::Invalid)?;
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
                return Err(Error::Invalid);
            }
            for (unit, count) in &model.usage_units {
                if RESERVED_UNITS.contains(&unit.as_str()) || *count == 0 {
                    continue;
                }
                if usage_units.remove(&(key.clone(), model.model.clone(), unit.clone()))
                    != Some(projected(*count))
                {
                    return Err(Error::Invalid);
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
            return Err(Error::Invalid);
        }
    }
    if !usage_mirrors.is_empty() {
        return Err(Error::Invalid);
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
                return Err(Error::Invalid);
            }
        }
        expected.usage_units.clear();
        if meter_mirrors.remove(key).as_ref() != Some(&expected) {
            return Err(Error::Invalid);
        }
    }
    if !meter_mirrors.is_empty() || !meter_units.is_empty() {
        return Err(Error::Invalid);
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
        coverage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::persistence::legacy_row;
    busbar_contract::own_seal!(Own);
    #[test]
    fn synthetic_exact_authority_requires_every_mirror_and_preserves_wide_totals() {
        let exact = legacy_row::encode::<Own>(&[Cell::Integer(0),Cell::Text(b"bucket"),Cell::Blob(br#"{"requests":18446744073709551615,"billable_requests":3,"models":[{"scale":6,"model":"m","usage_units":{"input":9223372036854775808,"seconds":9}}]}"#)],4096).unwrap();
        let counts = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Text(b"bucket"),
                Cell::Text(b""),
                Cell::Integer(i64::MAX),
                Cell::Integer(3),
                Cell::Integer(0),
                Cell::Integer(0),
                Cell::Integer(0),
                Cell::Integer(0),
            ],
            4096,
        )
        .unwrap();
        let model = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Text(b"bucket"),
                Cell::Text(b"m"),
                Cell::Integer(0),
                Cell::Integer(0),
                Cell::Integer(i64::MAX),
                Cell::Integer(0),
                Cell::Integer(0),
                Cell::Integer(0),
            ],
            4096,
        )
        .unwrap();
        let unit = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Text(b"bucket"),
                Cell::Text(b"m"),
                Cell::Text(b"seconds"),
                Cell::Integer(9),
            ],
            4096,
        )
        .unwrap();
        let exact_columns = ["window_start", "bucket_id", "ledger"];
        let unit_columns = ["window_start", "bucket_id", "model", "unit", "count"];
        let rows = [
            PhysicalRow {
                table: "usage_window_exact",
                columns: &exact_columns,
                row: Row::decode(exact.expose_own(&Own::here())).unwrap(),
            },
            PhysicalRow {
                table: "usage_windows",
                columns: USAGE,
                row: Row::decode(counts.expose_own(&Own::here())).unwrap(),
            },
            PhysicalRow {
                table: "usage_windows",
                columns: USAGE,
                row: Row::decode(model.expose_own(&Own::here())).unwrap(),
            },
            PhysicalRow {
                table: "usage_window_units",
                columns: &unit_columns,
                row: Row::decode(unit.expose_own(&Own::here())).unwrap(),
            },
        ];
        let verified = sqlite9(&rows, 8, 16_384).unwrap();
        assert_eq!(verified.usage[0].2.requests, u64::MAX);
        assert_eq!(verified.usage[0].2.total_input(), 9223372036854775808);
        assert_eq!(verified.coverage.usage_mirrors, 2);
        for missing in 0..rows.len() {
            let incomplete = rows
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != missing)
                .map(|(_, row)| PhysicalRow {
                    table: row.table,
                    columns: row.columns,
                    row: row.row,
                })
                .collect::<Vec<_>>();
            assert!(
                sqlite9(&incomplete, 8, 16_384).is_err(),
                "missing physical row {missing}"
            );
        }
        assert!(sqlite9(&rows, 3, 16_384).is_err());
        assert!(sqlite9(&rows, 8, 1).is_err());
    }
    #[test]
    fn synthetic_orphan_mirror_and_duplicate_exact_rows_refuse_activation() {
        let exact = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Text(b"bucket"),
                Cell::Blob(br#"{"requests":0,"billable_requests":0,"models":[]}"#),
            ],
            4096,
        )
        .unwrap();
        let columns = ["window_start", "bucket_id", "ledger"];
        let row = Row::decode(exact.expose_own(&Own::here())).unwrap();
        let duplicate = [
            PhysicalRow {
                table: "usage_window_exact",
                columns: &columns,
                row,
            },
            PhysicalRow {
                table: "usage_window_exact",
                columns: &columns,
                row,
            },
        ];
        assert!(sqlite9(&duplicate, 8, 16_384).is_err());
        // An exact row without its required explicit counter mirror is incomplete,
        // even though its numeric totals happen to be zero.
        assert!(sqlite9(&duplicate[..1], 8, 16_384).is_err());
    }
}
