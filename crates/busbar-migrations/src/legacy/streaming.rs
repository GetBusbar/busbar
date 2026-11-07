// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Stream source fragments into owned accounting meaning. The semantic memory
//! budget is independent of native candidate item limits; physical evidence is
//! never retained here. Every source fragment is consumed before projection.
use super::*;
use crate::{Bounds, Record};

fn owned(row: HistoricalRow<'_>) -> Result<HistoricalRow<'static>, super::super::Error> {
    Ok(match row {
        HistoricalRow::Usage(cell) => HistoricalRow::Usage(cell),
        HistoricalRow::ExactUsage {
            bucket,
            window,
            ledger,
        } => HistoricalRow::ExactUsage {
            bucket,
            window,
            ledger,
        },
        HistoricalRow::Metering { bucket, row } => HistoricalRow::Metering { bucket, row },
        HistoricalRow::UsageUnit {
            bucket,
            window,
            model,
            unit,
            count,
        } => HistoricalRow::UsageUnit {
            bucket,
            window,
            model,
            unit,
            count,
        },
        HistoricalRow::MeteringUnit {
            bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            key_group_at_use,
            pricing_version,
            unit,
            count,
        } => HistoricalRow::MeteringUnit {
            bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            key_group_at_use,
            pricing_version,
            unit,
            count,
        },
        _ => return Err(super::super::Error::UnsupportedPath),
    })
}

pub fn sql_rows<'t>(
    source: &dyn projection::ProjectionSource,
    marker: &Record,
    profile: Profile,
    layouts: &'t std::collections::BTreeMap<String, Vec<String>>,
    bounds: Bounds,
) -> Result<Vec<(&'t str, HistoricalRow<'static>)>, super::super::Error> {
    use super::super::Error as MigrationError;
    projection::verify_marker(source, transform::ACCOUNTING, marker)?;
    let group = busbar_contract::Secret::new(marker.key.clone());
    let mut decoded = Vec::new();
    let mut charge = 0usize;
    let count = source.visit(
        transform::ACCOUNTING,
        &group,
        bounds.bytes as usize,
        &mut |record| {
            let seal = crate::seal::lend();
            let (table, _) =
                transform::source_parts(&record.key).map_err(|_| MigrationError::Corrupt)?;
            let (name, columns) = layouts
                .get_key_value(table)
                .ok_or(MigrationError::UnsupportedPath)?;
            // Charge a conservative upper bound for decoded String/Vec/BTree
            // allocations before invoking the owner decoder. It is a configurable
            // memory budget, never a source-fragment or schema protocol ceiling.
            let upper = record
                .value
                .expose(&seal)
                .len()
                .checked_mul(64)
                .and_then(|v| v.checked_add(std::mem::size_of::<HistoricalRow<'static>>() + 1024))
                .ok_or(MigrationError::Bounds)?;
            charge = charge.checked_add(upper).ok_or(MigrationError::Bounds)?;
            if charge > source.semantic_bytes() {
                return Err(MigrationError::Bounds);
            }
            let columns = columns.iter().map(String::as_str).collect::<Vec<_>>();
            let row =
                Row::decode(record.value.expose(&seal)).map_err(|_| MigrationError::Corrupt)?;
            let effective = if profile == Profile::SqliteDev9
                && !matches!(table, "usage_window_exact" | "usage_metering_exact")
            {
                Profile::SqliteDev8
            } else {
                profile
            };
            let row =
                decode(effective, table, &columns, row).map_err(|_| MigrationError::Corrupt)?;
            decoded.try_reserve(1).map_err(|_| MigrationError::Bounds)?;
            decoded.push((name.as_str(), owned(row)?));
            Ok(())
        },
    )?;
    if count == 0 || count != decoded.len() as u64 {
        return Err(MigrationError::Verification);
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::Secret;
    busbar_contract::own_seal!(Own);

    struct Source {
        rows: Vec<Record>,
        semantic: usize,
    }
    impl projection::ProjectionSource for Source {
        fn provenance(&self) -> archive::Provenance {
            archive::Provenance {
                dataset: [1; 16],
                catalogue: [2; 32],
            }
        }
        fn semantic_bytes(&self) -> usize {
            self.semantic
        }
        fn inventory_digest(
            &self,
            _: [u8; 16],
            _: &Secret<Vec<u8>>,
        ) -> Result<[u8; 32], crate::Error> {
            Ok([7; 32])
        }
        fn visit(
            &self,
            _: [u8; 16],
            _: &Secret<Vec<u8>>,
            _: usize,
            visitor: &mut dyn FnMut(&Record) -> Result<(), crate::Error>,
        ) -> Result<u64, crate::Error> {
            for row in &self.rows {
                visitor(row)?;
            }
            Ok(self.rows.len() as u64)
        }
    }

    #[test]
    fn synthetic_many_source_fragments_fit_one_logical_native_output() {
        let mut rows = Vec::new();
        for ordinal in 0..6 {
            let model = if ordinal == 0 {
                String::new()
            } else {
                format!("m{ordinal}")
            };
            let value = busbar_contract::persistence::legacy_row::encode::<Own>(
                &[
                    Cell::Integer(0),
                    Cell::Text(b"bucket"),
                    Cell::Text(model.as_bytes()),
                    Cell::Integer(if ordinal == 0 { 4 } else { 0 }),
                    Cell::Integer(if ordinal == 0 { 3 } else { 0 }),
                    Cell::Integer(if ordinal == 0 { 0 } else { 7 }),
                    Cell::Integer(0),
                    Cell::Integer(0),
                    Cell::Integer(0),
                ],
                4096,
            )
            .unwrap();
            rows.push(Record {
                key: transform::source_key("usage_windows", &[ordinal]).unwrap(),
                value: Secret::new(value.expose_own(&Own::here()).clone()),
                preserve_exact: true,
            });
        }
        let mut source = Source {
            rows,
            semantic: 1 << 20,
        };
        let group = Secret::new(b"group".to_vec());
        let marker = Record {
            key: b"group".to_vec(),
            value: projection::encode_marker(&group, [7; 32]).unwrap(),
            preserve_exact: false,
        };
        let layouts = BTreeMap::from([(
            "usage_windows".into(),
            USAGE.iter().map(|v| (*v).into()).collect(),
        )]);
        let bounds = Bounds {
            items: 2,
            bytes: 1 << 20,
        };
        let decoded =
            sql_rows(&source, &marker, Profile::SqliteReleased6, &layouts, bounds).unwrap();
        assert_eq!(decoded.len(), 6);
        let cells = decoded
            .into_iter()
            .map(|(_, row)| match row {
                HistoricalRow::Usage(cell) => cell,
                _ => panic!(),
            })
            .collect::<Vec<_>>();
        let exact = assemble_usage(&cells).unwrap();
        assert_eq!(
            (exact.requests, exact.billable_requests, exact.total_input()),
            (4, 3, 35_000_000)
        );
        assert_eq!(canonical_usage("bucket", 0, &exact).unwrap().len(), 2);
        source.semantic = 0;
        assert!(matches!(
            sql_rows(&source, &marker, Profile::SqliteReleased6, &layouts, bounds),
            Err(crate::Error::Bounds)
        ));
    }
}
