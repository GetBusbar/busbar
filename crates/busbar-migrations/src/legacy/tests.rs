// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::*;
use busbar_contract::persistence::legacy_row;
busbar_contract::own_seal!(Own);

// Synthetic semantic units. These are deliberately not represented as released
// nonempty credential fixtures; all recorded 1.5.5 SQL credential tables are empty.
fn with_row<T>(cells: &[Cell<'_>], f: impl FnOnce(Row<'_>) -> T) -> T {
    let encoded = legacy_row::encode::<Own>(cells, 4096).unwrap();
    f(Row::decode(encoded.expose_own(&Own::here())).unwrap())
}

#[test]
fn synthetic_metering_open_units_preserve_reserved_names_independently() {
    // MeteringRow stores scalar token counters separately from its open unit
    // map. Historical writers persisted every map entry, including "input".
    let row = MeteringRow {
        scale: 6,
        key_id: "k".into(),
        provider: "p".into(),
        model: "m".into(),
        tokens_input: 7,
        tokens_output: 0,
        tokens_cache_read: 0,
        tokens_cache_write: 0,
        requests: 0,
        billable_requests: 0,
        key_group_at_use: String::new(),
        pricing_version: String::new(),
        priced_from_ms: 0,
        usage_units: BTreeMap::new(),
    };
    let unit = HistoricalRow::MeteringUnit {
        bucket: 3,
        key_id: "k".into(),
        provider: "p".into(),
        model: "m".into(),
        priced_from_ms: 0,
        key_group_at_use: None,
        pricing_version: None,
        unit: "input".into(),
        count: 11,
    };
    let exact = attach_metering_units(3, &row, &[unit]).unwrap();
    assert_eq!(exact.tokens_input, 7);
    assert_eq!(exact.usage_units["input"], 11);
}

#[test]
fn synthetic_revoked_credential_keeps_exact_envelope_and_aad_identity() {
    let cells = [
        Cell::Text(b"credential-id"),
        Cell::Text(b"key-id"),
        Cell::Text(b"sigv4"),
        Cell::Integer(1),
        Cell::Text(b"public-id"),
        Cell::Text(b"v1:aead:key:nonce:ciphertext"),
        Cell::Text(b"recoverable"),
        Cell::Integer(1),
        Cell::Integer(3),
        Cell::Null,
        Cell::Integer(3),
        Cell::Text(b"rotated"),
        Cell::Integer(9),
    ];
    with_row(&cells, |row| {
        let HistoricalRow::Credential(value) =
            decode(Profile::SqliteReleased6, "credentials", CREDENTIALS, row).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            value.envelope,
            Some(b"v1:aead:key:nonce:ciphertext".as_slice())
        );
        assert_eq!(
            (
                value.meta.id.as_str(),
                value.meta.key_id.as_str(),
                value.meta.kind.as_str(),
                value.meta.public_id.as_str()
            ),
            ("credential-id", "key-id", "sigv4", "public-id")
        );
        assert_eq!(
            (value.meta.slot, value.meta.revoked_at, value.meta.revision),
            (1, Some(3), 9)
        );
    });
}

#[test]
fn synthetic_usage_whole_units_convert_once_and_requests_do_not_scale() {
    let cells = [
        Cell::Integer(0),
        Cell::Text(b"bucket"),
        Cell::Text(b"m"),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Integer(7),
        Cell::Integer(11),
        Cell::Integer(4),
        Cell::Integer(0),
    ];
    with_row(&cells, |row| {
        let HistoricalRow::Usage(value) =
            decode(Profile::SqliteReleased6, "usage_windows", USAGE, row).unwrap()
        else {
            panic!()
        };
        assert_eq!(value.ledger.models[0].scale, 6);
        assert_eq!(value.ledger.total_input(), 7_000_000);
        let mut count_cells = cells;
        count_cells[2] = Cell::Text(b"");
        count_cells[3] = Cell::Integer(4);
        count_cells[4] = Cell::Integer(3);
        count_cells[5..].fill(Cell::Integer(0));
        with_row(&count_cells, |row| {
            let HistoricalRow::Usage(counts) =
                decode(Profile::SqliteReleased6, "usage_windows", USAGE, row).unwrap()
            else {
                panic!()
            };
            let assembled = assemble_usage(&[value, counts]).unwrap();
            assert_eq!(
                (
                    assembled.requests,
                    assembled.billable_requests,
                    assembled.total_input()
                ),
                (4, 3, 7_000_000)
            );
        });
    });
}

#[test]
fn unknown_missing_duplicate_columns_and_negative_counts_are_errors() {
    let cells = [
        Cell::Integer(0),
        Cell::Text(b"bucket"),
        Cell::Text(b"m"),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Integer(-1),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Integer(0),
    ];
    with_row(&cells, |row| {
        assert!(matches!(
            decode(Profile::SqliteReleased6, "usage_windows", USAGE, row),
            Err(Error::Range)
        ));
        let mut columns = USAGE.to_vec();
        columns[8] = "unknown_scale";
        assert!(matches!(
            decode(Profile::SqliteReleased6, "usage_windows", &columns, row),
            Err(Error::Columns)
        ));
        columns[8] = "model";
        assert!(matches!(
            decode(Profile::SqliteReleased6, "usage_windows", &columns, row),
            Err(Error::Columns)
        ));
        assert!(matches!(
            decode(Profile::SqliteReleased6, "usage_windows", &USAGE[..8], row),
            Err(Error::Columns)
        ));
    });
}

#[test]
fn synthetic_mysql_preserves_released_sum_across_model_rows() {
    let columns = USAGE
        .iter()
        .copied()
        .chain(["bucket_scope"])
        .collect::<Vec<_>>();
    let cells = [
        Cell::Integer(0),
        Cell::Text(b"bucket"),
        Cell::Text(b"a"),
        Cell::Integer(4),
        Cell::Integer(3),
        Cell::Integer(7),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Text(b"key"),
    ];
    with_row(&cells, |row| {
        let HistoricalRow::Usage(first) =
            decode(Profile::MysqlReleased3, "usage_windows", &columns, row).unwrap()
        else {
            panic!()
        };
        let mut second = cells;
        second[2] = Cell::Text(b"b");
        with_row(&second, |row| {
            let HistoricalRow::Usage(second) =
                decode(Profile::MysqlReleased3, "usage_windows", &columns, row).unwrap()
            else {
                panic!()
            };
            let assembled = assemble_usage(&[first, second]).unwrap();
            assert_eq!(
                (
                    assembled.requests,
                    assembled.billable_requests,
                    assembled.total_input()
                ),
                (8, 6, 14_000_000)
            );
        });
    });
}

#[test]
fn synthetic_dev_micro_columns_are_not_scaled_twice() {
    let cells = [
        Cell::Integer(0),
        Cell::Text(b"bucket"),
        Cell::Text(b"m"),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Integer(7_000_001),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Integer(0),
    ];
    with_row(&cells, |row| {
        let HistoricalRow::Usage(value) =
            decode(Profile::SqliteDev8, "usage_windows", USAGE, row).unwrap()
        else {
            panic!()
        };
        assert_eq!(value.ledger.total_input(), 7_000_001);
        assert!(matches!(
            decode(Profile::SqliteDev9, "usage_windows", USAGE, row),
            Err(Error::Unsupported)
        ));
    });
}

#[test]
fn synthetic_exact_ledger_rejects_unknown_scale_fields_and_mismatched_identity() {
    let columns = ["window_start", "bucket_id", "ledger"];
    for json in [
        br#"{"requests":1,"billable_requests":1,"models":[{"scale":5,"model":"m","usage_units":{"input":7}}]}"#.as_slice(),
        br#"{"requests":1,"billable_requests":1,"models":[{"scale":6,"model":"m","usage_units":{"input":7},"unknown":0}]}"#.as_slice(),
        br#"{"requests":1,"billable_requests":1,"models":[{"model":"m","usage_units":{"input":7}}]}"#.as_slice(),
    ] {
        with_row(&[Cell::Integer(0),Cell::Text(b"b"),Cell::Blob(json)], |row| assert!(decode(Profile::SqliteDev9,"usage_window_exact",&columns,row).is_err()));
    }
    let json = br#"{"requests":1,"billable_requests":1,"models":[{"scale":6,"model":"m","usage_units":{"input":170141183460469231731687303715884105}}]}"#;
    with_row(
        &[Cell::Integer(0), Cell::Text(b"b"), Cell::Blob(json)],
        |row| {
            let HistoricalRow::ExactUsage { ledger, .. } =
                decode(Profile::SqliteDev9, "usage_window_exact", &columns, row).unwrap()
            else {
                panic!()
            };
            assert_eq!(ledger.total_input(), 170141183460469231731687303715884105);
        },
    );
}

#[test]
fn synthetic_dev_receipts_remain_opaque_original_bytes() {
    let columns = ["op_id", "body", "answer", "recorded_at"];
    with_row(
        &[
            Cell::Blob(b"original-op"),
            Cell::Text(b"old-uncertain-candidate"),
            Cell::Text(b"unknown"),
            Cell::Integer(1),
        ],
        |row| {
            let HistoricalRow::Opaque { original, .. } =
                decode(Profile::SqliteDev8, "store_ops", &columns, row).unwrap()
            else {
                panic!()
            };
            assert_eq!(
                original.cells().nth(1),
                Some(Cell::Text(b"old-uncertain-candidate"))
            );
        },
    );
}

#[test]
fn recorded_sqlite_155_rows_keep_published_quantities_and_hashes() {
    use sha2::{Digest, Sha256};
    let bytes = include_bytes!("fixtures/sqlite-1.5.5-rows.json");
    assert_eq!(
        hex::encode(Sha256::digest(bytes)),
        "690e23fe2f209e2aabd132fa3ff4c694f22d3fb7dddc5bdcbccc9bf81c253869"
    );
    let data: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    assert_eq!(data["credentials"].as_array().unwrap().len(), 0);
    for (table, columns) in [
        ("usage_windows", USAGE),
        ("usage_metering", METERING),
        ("audit_log", AUDIT),
        ("keys", KEYS),
    ] {
        for original in data[table].as_array().unwrap() {
            let cells = columns
                .iter()
                .map(|column| match &original[*column] {
                    serde_json::Value::Null => Cell::Null,
                    serde_json::Value::String(s) => Cell::Text(s.as_bytes()),
                    serde_json::Value::Number(n) => Cell::Integer(n.as_i64().unwrap()),
                    _ => panic!("unexpected recorded physical type"),
                })
                .collect::<Vec<_>>();
            with_row(&cells, |row| {
                match decode(Profile::SqliteReleased6, table, columns, row).unwrap() {
                    HistoricalRow::Usage(cell) => {
                        assert_eq!(cell.ledger.requests, original["requests"].as_u64().unwrap());
                        if !cell.model.is_empty() {
                            assert_eq!(
                                cell.ledger.total_input(),
                                i128::from(original["tokens_input"].as_i64().unwrap()) * 1_000_000
                            );
                        }
                    }
                    HistoricalRow::Metering { row, .. } => assert_eq!(
                        row.tokens_input,
                        i128::from(original["tokens_input"].as_i64().unwrap()) * 1_000_000
                    ),
                    HistoricalRow::Audit(row) => {
                        assert_eq!(row.hash, original["hash"].as_str().unwrap());
                        assert_eq!(row.prev_hash, original["prev_hash"].as_str().unwrap());
                    }
                    HistoricalRow::Key { key, .. } => assert_eq!(
                        key.generation_hash,
                        original["generation_hash"].as_str().unwrap()
                    ),
                    _ => panic!(),
                }
            });
        }
    }
}

#[test]
fn recorded_postgres_and_mysql_155_profiles_decode_native_column_shapes() {
    use sha2::{Digest, Sha256};
    for (profile, bytes, manifest) in [
        (
            Profile::PostgresReleased6,
            include_bytes!("fixtures/postgres-1.5.5-rows.json").as_slice(),
            include_str!("fixtures/postgres-1.5.5-MANIFEST.tsv"),
        ),
        (
            Profile::MysqlReleased3,
            include_bytes!("fixtures/mysql-1.5.5-rows.json").as_slice(),
            include_str!("fixtures/mysql-1.5.5-MANIFEST.tsv"),
        ),
    ] {
        let digest = manifest
            .lines()
            .find_map(|line| line.strip_prefix("file\trows.json "))
            .unwrap();
        assert_eq!(hex::encode(Sha256::digest(bytes)), digest);
        let data: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        assert!(data["credentials"].as_array().unwrap().is_empty());
        for table in [
            if profile == Profile::MysqlReleased3 {
                "api_keys"
            } else {
                "keys"
            },
            "usage_windows",
            "usage_metering",
            "audit_log",
        ] {
            for original in data[table].as_array().unwrap() {
                let columns = original
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                let json = columns
                    .iter()
                    .map(|name| match &original[*name] {
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            Some(serde_json::to_vec(&original[*name]).unwrap())
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let cells = columns
                    .iter()
                    .enumerate()
                    .map(|(index, column)| match &original[*column] {
                        serde_json::Value::Null => Cell::Null,
                        serde_json::Value::String(s) => Cell::Text(s.as_bytes()),
                        serde_json::Value::Bool(value) => Cell::Integer(i64::from(*value)),
                        serde_json::Value::Number(n) => Cell::Integer(n.as_i64().unwrap()),
                        _ => Cell::Text(json[index].as_ref().unwrap()),
                    })
                    .collect::<Vec<_>>();
                with_row(&cells, |row| {
                    assert!(
                        decode(profile, table, &columns, row).is_ok(),
                        "{profile:?}/{table}"
                    );
                });
            }
        }
    }
}

#[test]
fn synthetic_open_units_keep_exact_fraction_and_attribution() {
    let columns = ["window_start", "bucket_id", "model", "unit", "count"];
    with_row(
        &[
            Cell::Integer(0),
            Cell::Text(b"bucket"),
            Cell::Text(b"model"),
            Cell::Text(b"seconds"),
            Cell::Integer(7),
        ],
        |row| {
            let unit = decode(Profile::SqliteDev8, "usage_window_units", &columns, row).unwrap();
            let out = attach_usage_units("bucket", 0, &UsageLedger::default(), &[unit]).unwrap();
            assert_eq!(out.models[0].usage_units["seconds"], 7);
            assert_eq!(out.models[0].scale, 6);
        },
    );
}

#[test]
fn synthetic_wide_timestamp_bits_are_preserved_separately_from_counts() {
    let cells = [
        Cell::Text(b"id"),
        Cell::Text(b"key"),
        Cell::Text(b"sigv4"),
        Cell::Integer(0),
        Cell::Text(b"public"),
        Cell::Text(b"v1:plain:secret"),
        Cell::Text(b"recoverable"),
        Cell::Integer(i64::MIN),
        Cell::Integer(i64::MIN),
        Cell::Integer(i64::MIN + 1),
        Cell::Null,
        Cell::Null,
        Cell::Integer(1),
    ];
    with_row(&cells, |row| {
        let HistoricalRow::Credential(value) =
            decode(Profile::SqliteReleased6, "credentials", CREDENTIALS, row).unwrap()
        else {
            panic!()
        };
        assert_eq!(value.meta.created_at, 1u64 << 63);
        assert_eq!(value.meta.expires_at, Some((1u64 << 63) + 1));
        let canonical = canonical_identity(&HistoricalRow::Credential(value), false).unwrap();
        assert!(canonical
            .iter()
            .any(|(_, value)| value.expose(&crate::seal::lend()) == b"v1:plain:secret"));
    });
}

#[test]
fn synthetic_postgres_dev_profiles_discriminate_whole_micro_and_wide_decimal() {
    let columns = [
        "bucket_id",
        "window_start",
        "model",
        "tokens_input",
        "tokens_output",
        "tokens_cache_read",
        "tokens_cache_write",
    ];
    let cells = [
        Cell::Text(b"bucket"),
        Cell::Integer(0),
        Cell::Text(b"m"),
        Cell::Integer(7),
        Cell::Integer(0),
        Cell::Integer(0),
        Cell::Integer(0),
    ];
    for (profile, expected) in [
        (Profile::PostgresDev7, 7_000_000),
        (Profile::PostgresDev8, 7),
    ] {
        with_row(&cells, |row| {
            let HistoricalRow::Usage(cell) =
                decode(profile, "usage_ledger", &columns, row).unwrap()
            else {
                panic!()
            };
            assert_eq!(cell.ledger.total_input(), expected);
        });
    }
    let mut wide = cells;
    wide[3] = Cell::Text(b"170141183460469231731687303715884105");
    with_row(&wide, |row| {
        let HistoricalRow::Usage(cell) =
            decode(Profile::PostgresDev9, "usage_ledger", &columns, row).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            cell.ledger.total_input(),
            170141183460469231731687303715884105
        );
    });
}

#[test]
fn synthetic_mysql_dev_keeps_binary_identifiers_and_decimal_quantity() {
    let columns = USAGE
        .iter()
        .copied()
        .chain(["bucket_scope"])
        .collect::<Vec<_>>();
    let cells = [
        Cell::Integer(0),
        Cell::Blob(b"bucket"),
        Cell::Blob(b"m"),
        Cell::Integer(1),
        Cell::Integer(1),
        Cell::Text(b"170141183460469231731687303715884105"),
        Cell::Text(b"0"),
        Cell::Text(b"0"),
        Cell::Text(b"0"),
        Cell::Blob(b"key"),
    ];
    with_row(&cells, |row| {
        let HistoricalRow::Usage(cell) =
            decode(Profile::MysqlDev7, "usage_windows", &columns, row).unwrap()
        else {
            panic!()
        };
        assert_eq!(
            cell.ledger.total_input(),
            170141183460469231731687303715884105
        );
        assert_eq!(cell.ledger.requests, 1);
    });
}
