// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure historical decoding. Native readers own protected input and exact catalog
//! validation; this module owns column meaning. No native I/O, envelope rewrap,
//! historical receipt synthesis, or scale inference is permitted here.

use busbar_contract::persistence::legacy_row::{Cell, Row};
use busbar_contract::records::{
    AuditRecord, CredentialMeta, MeteringRow, ModelTokens, ScopeRef, SecretForm, UsageLedger,
    VirtualKey, RESERVED_UNITS,
};
pub mod archive;
pub mod group;
pub mod journal;
pub mod journal_binding;
pub mod overlay;
pub mod projection;
mod receipt_codec;
pub mod recovery;
mod streaming;
pub mod transform;
pub mod valkey;
pub mod valkey_transform;
pub mod verify;

use std::collections::BTreeMap;

/// Compiled source semantics, selected only after exact native catalog admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    SqliteReleased6,
    PostgresReleased6,
    MysqlReleased3,
    /// Development schema 7 stores whole quantities, schema 8 micro quantities.
    SqliteDev7,
    SqliteDev8,
    /// Schema 9's exact JSON rows are authoritative; mirrors are evidence only.
    SqliteDev9,
    PostgresDev7,
    PostgresDev8,
    PostgresDev9,
    MysqlDev4,
    MysqlDev5,
    MysqlDev7,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Columns,
    Type,
    Range,
    Invalid,
    Unsupported,
}

/// Credential bytes remain borrowed from the reader's wiping custody. In
/// particular a revoked historical envelope is evidence, not a new live secret.
pub struct Credential<'a> {
    pub meta: CredentialMeta,
    pub envelope: Option<&'a [u8]>,
}

/// One physical usage row. SQLite and PostgreSQL request counters occupy the
/// empty model row; MySQL released readers sum request columns across model rows.
/// The explicit source profile retains that distinction.
#[derive(Debug)]
pub struct UsageCell {
    pub bucket: String,
    pub window: u64,
    pub model: String,
    pub sum_requests: bool,
    pub ledger: UsageLedger,
}

pub enum HistoricalRow<'a> {
    Key {
        key: VirtualKey,
        updated_at: Option<u64>,
    },
    Credential(Credential<'a>),
    Denied {
        subject: String,
        reason: String,
        created_at: u64,
    },
    Revision(u64),
    Schema(u64),
    ExactUsage {
        bucket: String,
        window: u64,
        ledger: UsageLedger,
    },
    /// Development candidates and old receipts cannot be submitted using a new
    /// execution identity. Preserve the original frame in a separate archive.
    Opaque {
        table: String,
        original: Row<'a>,
    },
    MeteringUnit {
        bucket: u64,
        key_id: String,
        provider: String,
        model: String,
        priced_from_ms: u64,
        key_group_at_use: Option<String>,
        pricing_version: Option<String>,
        unit: String,
        count: i128,
    },
    UsageUnit {
        bucket: String,
        window: u64,
        model: String,
        unit: String,
        count: i128,
    },
    Usage(UsageCell),
    Metering {
        bucket: u64,
        row: MeteringRow,
    },
    /// The original encoded physical row must also be retained as the immutable
    /// preimage. Parsing never recomputes its hash or signs a replacement event.
    Audit(AuditRecord),
    Meta {
        name: &'a [u8],
        value: &'a [u8],
    },
}

const KEYS: &[&str] = &[
    "id",
    "name",
    "key_group",
    "allowed_pools",
    "labels",
    "enabled",
    "generation_hash",
    "created_at",
    "updated_at",
    "expires_at",
    "deleted_at",
    "revision",
];
const CREDENTIALS: &[&str] = &[
    "id",
    "key_id",
    "kind",
    "slot",
    "public_id",
    "secret",
    "secret_form",
    "created_at",
    "updated_at",
    "expires_at",
    "revoked_at",
    "revoke_reason",
    "revision",
];
const USAGE: &[&str] = &[
    "window_start",
    "bucket_id",
    "model",
    "requests",
    "billable_requests",
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];
const METERING: &[&str] = &[
    "bucket",
    "key_id",
    "provider",
    "model",
    "key_group_at_use",
    "pricing_version",
    "requests",
    "billable_requests",
    "tokens_input",
    "tokens_output",
    "tokens_cache_read",
    "tokens_cache_write",
];
const AUDIT: &[&str] = &[
    "seq",
    "ts",
    "action",
    "resource",
    "outcome",
    "principal",
    "prev_hash",
    "hash",
];

struct Columns<'a, 'b> {
    unsigned: bool,
    decimal: bool,
    names: &'b [&'b str],
    values: Vec<Cell<'a>>,
}
impl<'a, 'b> Columns<'a, 'b> {
    fn new(
        unsigned: bool,
        names: &'b [&'b str],
        row: Row<'a>,
        expected: &[&str],
    ) -> Result<Self, Error> {
        if names.len() != expected.len()
            || row.cells().len() != names.len()
            || names
                .iter()
                .enumerate()
                .any(|(i, n)| !expected.contains(n) || names[..i].contains(n))
        {
            return Err(Error::Columns);
        }
        Ok(Self {
            unsigned,
            decimal: false,
            names,
            values: row.cells().collect(),
        })
    }
    fn cell(&self, name: &str) -> Cell<'a> {
        self.values[self
            .names
            .iter()
            .position(|n| *n == name)
            .expect("validated columns")]
    }
    fn bytes(&self, name: &str) -> Result<&'a [u8], Error> {
        match self.cell(name) {
            Cell::Text(v) | Cell::Blob(v) => Ok(v),
            _ => Err(Error::Type),
        }
    }
    fn text(&self, name: &str) -> Result<String, Error> {
        std::str::from_utf8(self.bytes(name)?)
            .map(str::to_owned)
            .map_err(|_| Error::Type)
    }
    fn optional_text(&self, name: &str) -> Result<Option<String>, Error> {
        if self.cell(name) == Cell::Null {
            Ok(None)
        } else {
            self.text(name).map(Some)
        }
    }
    fn uint(&self, name: &str) -> Result<u64, Error> {
        match self.cell(name) {
            Cell::Integer(v) if self.unsigned => Ok(u64::from_le_bytes(v.to_le_bytes())),
            Cell::Integer(v) => v.try_into().map_err(|_| Error::Range),
            Cell::Text(v) if self.decimal => std::str::from_utf8(v)
                .map_err(|_| Error::Type)?
                .parse()
                .map_err(|_| Error::Range),
            _ => Err(Error::Type),
        }
    }
    fn quantity(&self, name: &str) -> Result<i128, Error> {
        let value = match self.cell(name) {
            Cell::Text(v) if self.decimal => std::str::from_utf8(v)
                .map_err(|_| Error::Type)?
                .parse()
                .map_err(|_| Error::Range)?,
            Cell::Integer(_) => i128::from(self.uint(name)?),
            _ => return Err(Error::Type),
        };
        if value < 0 {
            return Err(Error::Range);
        }
        Ok(value)
    }
    fn revision(&self) -> Result<u64, Error> {
        match self.cell("revision") {
            Cell::Integer(v) => u64::try_from(v).map_err(|_| Error::Range),
            _ => Err(Error::Type),
        }
    }
    fn timestamp(&self, name: &str) -> Result<u64, Error> {
        match self.cell(name) {
            Cell::Integer(v) => Ok(u64::from_le_bytes(v.to_le_bytes())),
            _ => Err(Error::Type),
        }
    }
    fn optional_timestamp(&self, name: &str) -> Result<Option<u64>, Error> {
        if self.cell(name) == Cell::Null {
            Ok(None)
        } else {
            self.timestamp(name).map(Some)
        }
    }
    fn boolean(&self, name: &str) -> Result<bool, Error> {
        match self.uint(name)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::Invalid),
        }
    }
    fn json<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<T, Error> {
        serde_json::from_slice(self.bytes(name)?).map_err(|_| Error::Invalid)
    }
    fn tokens(&self) -> Result<BTreeMap<String, i128>, Error> {
        let mut values = BTreeMap::new();
        for (column, unit) in [
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_write",
        ]
        .into_iter()
        .zip(RESERVED_UNITS)
        {
            values.insert(unit.to_owned(), self.quantity(column)?);
        }
        Ok(values)
    }
}

/// Decode exactly one admitted released SQL row. An unknown table or column is
/// rejected; absent quantities, unknown scales and unsupported native types never
/// become zero. Caller must retain the protected original row for evidence.
pub fn decode<'a>(
    profile: Profile,
    table: &str,
    columns: &[&str],
    row: Row<'a>,
) -> Result<HistoricalRow<'a>, Error> {
    let key_table = if matches!(
        profile,
        Profile::MysqlReleased3 | Profile::MysqlDev4 | Profile::MysqlDev5 | Profile::MysqlDev7
    ) {
        "api_keys"
    } else {
        "keys"
    };
    let sqlite_dev = matches!(
        profile,
        Profile::SqliteDev7 | Profile::SqliteDev8 | Profile::SqliteDev9
    );
    let scale = if matches!(
        profile,
        Profile::SqliteDev8
            | Profile::SqliteDev9
            | Profile::PostgresDev8
            | Profile::PostgresDev9
            | Profile::MysqlDev5
            | Profile::MysqlDev7
    ) {
        6
    } else {
        0
    };
    if sqlite_dev
        && matches!(
            table,
            "store_ops" | "schema_records" | "plane_records" | "plane_tokens"
        )
    {
        let expected: &[&str] = match table {
            "store_ops" => &["op_id", "body", "answer", "recorded_at"],
            "schema_records" => &["schema", "record_key", "value"],
            "plane_tokens" => &["kind", "token", "expires_at"],
            _ => &[
                "kind",
                "identity",
                "seq",
                "id",
                "parent",
                "ts",
                "disposition",
                "body",
            ],
        };
        Columns::new(false, columns, row, expected)?;
        return Ok(HistoricalRow::Opaque {
            table: table.to_owned(),
            original: row,
        });
    }
    if sqlite_dev && matches!(table, "usage_window_exact" | "usage_metering_exact") {
        return exact_sqlite(profile, table, columns, row);
    }
    if matches!(profile, Profile::SqliteDev7 | Profile::SqliteDev8) && table == "usage_window_units"
    {
        let c = Columns::new(
            false,
            columns,
            row,
            &["window_start", "bucket_id", "model", "unit", "count"],
        )?;
        let count = busbar_contract::count::Count::from_stored(i128::from(c.uint("count")?), scale)
            .map_err(|_| Error::Range)?
            .micros();
        return Ok(HistoricalRow::UsageUnit {
            bucket: c.text("bucket_id")?,
            window: c.timestamp("window_start")?,
            model: c.text("model")?,
            unit: c.text("unit")?,
            count,
        });
    }
    if profile == Profile::SqliteDev9
        && matches!(
            table,
            "usage_windows" | "usage_metering" | "usage_window_units" | "usage_metering_units"
        )
    {
        return Err(Error::Unsupported);
    }
    if matches!(profile, Profile::SqliteDev7 | Profile::SqliteDev8)
        && table == "usage_metering_units"
    {
        let c = Columns::new(
            false,
            columns,
            row,
            &[
                "bucket",
                "key_id",
                "provider",
                "model",
                "priced_from_ms",
                "key_group_at_use",
                "pricing_version",
                "unit",
                "count",
            ],
        )?;
        let count = busbar_contract::count::Count::from_stored(i128::from(c.uint("count")?), scale)
            .map_err(|_| Error::Range)?
            .micros();
        let bucket = std::str::from_utf8(c.bytes("bucket")?)
            .map_err(|_| Error::Type)?
            .parse()
            .map_err(|_| Error::Invalid)?;
        return Ok(HistoricalRow::MeteringUnit {
            bucket,
            key_id: c.text("key_id")?,
            provider: c.text("provider")?,
            model: c.text("model")?,
            priced_from_ms: c.timestamp("priced_from_ms")?,
            key_group_at_use: Some(c.text("key_group_at_use")?),
            pricing_version: Some(c.text("pricing_version")?),
            unit: c.text("unit")?,
            count,
        });
    }
    let pg = matches!(
        profile,
        Profile::PostgresReleased6
            | Profile::PostgresDev7
            | Profile::PostgresDev8
            | Profile::PostgresDev9
    );
    let mysql = matches!(
        profile,
        Profile::MysqlReleased3 | Profile::MysqlDev4 | Profile::MysqlDev5 | Profile::MysqlDev7
    );
    let pg_dev = pg && profile != Profile::PostgresReleased6;
    let mysql_dev = mysql && profile != Profile::MysqlReleased3;
    let dev = sqlite_dev || pg_dev || mysql_dev;
    if (pg_dev || mysql_dev)
        && matches!(
            table,
            "usage_ledger_units" | "usage_window_units" | "usage_metering_units"
        )
    {
        return decode_sql_units(pg, mysql, scale, table, columns, row);
    }
    let mut expected = if table == key_table {
        KEYS
    } else {
        match table {
            "credentials" => CREDENTIALS,
            "usage_windows" => USAGE,
            "usage_metering" => METERING,
            "audit_log" => AUDIT,
            "denylist" => &["sub", "reason", "created_at"],
            "store_revision" | "store_sequence" => &["id", "revision"],
            "store_meta" => &["k", "v"],
            "busbar_schema" => &["version"],
            "usage_ledger" if pg => &[
                "bucket_id",
                "window_start",
                "model",
                "tokens_input",
                "tokens_output",
                "tokens_cache_read",
                "tokens_cache_write",
            ],
            _ => return Err(Error::Unsupported),
        }
    };
    let adjusted;
    if dev && table == key_table {
        adjusted = KEYS
            .iter()
            .copied()
            .filter(|name| !pg || *name != "updated_at")
            .chain([
                if pg {
                    "allowed_scopes_by_kind"
                } else if mysql {
                    "allowed_scopes_ext"
                } else {
                    "scope_grants"
                },
                "idp_subject",
                "binding_mode",
                "minted_by",
                "idp_provider",
            ])
            .collect::<Vec<_>>();
        expected = &adjusted;
    } else if dev && table == "usage_metering" {
        adjusted = METERING
            .iter()
            .copied()
            .chain(["priced_from_ms"])
            .collect::<Vec<_>>();
        expected = &adjusted;
    } else if pg && table == key_table {
        adjusted = KEYS
            .iter()
            .copied()
            .filter(|n| *n != "updated_at")
            .collect::<Vec<_>>();
        expected = &adjusted;
    } else if pg && table == "store_revision" {
        expected = &["only_row", "revision"];
    } else if pg && table == "usage_windows" {
        expected = &["bucket_id", "window_start", "requests", "billable_requests"];
    } else if mysql && table == "usage_windows" {
        adjusted = USAGE
            .iter()
            .copied()
            .chain(["bucket_scope"])
            .collect::<Vec<_>>();
        expected = &adjusted;
    }
    let mut c = Columns::new(mysql, columns, row, expected)?;
    c.decimal = pg_dev || mysql_dev;
    if table == key_table {
        let group = c.optional_text("key_group")?;
        let group = if mysql {
            group.filter(|g| !g.is_empty())
        } else {
            group
        };
        let pools: Option<Vec<String>> = if c.cell("allowed_pools") == Cell::Null {
            None
        } else {
            Some(c.json("allowed_pools")?)
        };
        let mut key = VirtualKey {
            id: c.text("id")?,
            generation_hash: c.text("generation_hash")?,
            name: c.text("name")?,
            allowed_scopes: pools.map(|v| v.into_iter().map(ScopeRef::pool).collect()),
            enabled: c.boolean("enabled")?,
            created_at: c.timestamp("created_at")?,
            group,
            labels: c.json("labels")?,
            expires_at: c.optional_timestamp("expires_at")?,
            deleted_at: c.optional_timestamp("deleted_at")?,
            revision: c.revision()?,
            idp_subject: None,
            binding_mode: None,
            minted_by: None,
            idp_provider: None,
        };
        if dev {
            key.idp_subject = c.optional_text("idp_subject")?;
            key.binding_mode = c.optional_text("binding_mode")?;
            key.minted_by = c.optional_text("minted_by")?;
            key.idp_provider = c.optional_text("idp_provider")?;
            let scope_column = if pg {
                "allowed_scopes_by_kind"
            } else if mysql {
                "allowed_scopes_ext"
            } else {
                "scope_grants"
            };
            if c.cell(scope_column) != Cell::Null {
                let ext: BTreeMap<String, Vec<String>> = if mysql {
                    let pairs: Vec<(String, String)> = c.json(scope_column)?;
                    let mut map = BTreeMap::<String, Vec<String>>::new();
                    for (kind, value) in pairs {
                        map.entry(kind).or_default().push(value);
                    }
                    map
                } else {
                    c.json(scope_column)?
                };
                let scopes = key.allowed_scopes.get_or_insert_with(Vec::new);
                for (kind, values) in ext {
                    if kind == "pool" {
                        return Err(Error::Invalid);
                    }
                    for value in values {
                        if scopes.iter().any(|s| s.kind == kind && s.value == value) {
                            return Err(Error::Invalid);
                        }
                        scopes.push(ScopeRef {
                            kind: kind.clone(),
                            value,
                        });
                    }
                }
            }
        }
        if key.deleted_at.is_some() && key.enabled
            || key.expires_at.is_some_and(|v| v <= key.created_at)
        {
            return Err(Error::Invalid);
        }
        return Ok(HistoricalRow::Key {
            key,
            updated_at: if pg {
                None
            } else {
                Some(c.timestamp("updated_at")?)
            },
        });
    }
    Ok(match table {
        "credentials" => {
            let form = match c.bytes("secret_form")? {
                b"none" => SecretForm::None,
                b"recoverable" => SecretForm::Recoverable,
                b"digest" => SecretForm::Digest,
                _ => return Err(Error::Invalid),
            };
            let envelope = if c.cell("secret") == Cell::Null {
                None
            } else {
                Some(c.bytes("secret")?)
            };
            let meta = CredentialMeta {
                id: c.text("id")?,
                key_id: c.text("key_id")?,
                kind: c.text("kind")?,
                slot: c.uint("slot")?.try_into().map_err(|_| Error::Range)?,
                public_id: c.text("public_id")?,
                secret_form: form,
                created_at: c.timestamp("created_at")?,
                updated_at: c.timestamp("updated_at")?,
                expires_at: c.optional_timestamp("expires_at")?,
                revoked_at: c.optional_timestamp("revoked_at")?,
                revoke_reason: c.optional_text("revoke_reason")?,
                revision: c.revision()?,
            };
            if meta.slot > 1
                || (form == SecretForm::None && envelope.is_some())
                || (form != SecretForm::None
                    && envelope.is_none()
                    && !(dev && meta.revoked_at.is_some()))
                || meta.revoke_reason.is_some() && meta.revoked_at.is_none()
                || meta.expires_at.is_some_and(|v| v <= meta.created_at)
            {
                return Err(Error::Invalid);
            }
            HistoricalRow::Credential(Credential { meta, envelope })
        }
        "usage_windows" | "usage_ledger" => {
            let pg_requests = pg && table == "usage_windows";
            let pg_tokens = pg && table == "usage_ledger";
            let model = if pg_requests {
                String::new()
            } else {
                c.text("model")?
            };
            let mut ledger = UsageLedger {
                requests: if pg_tokens { 0 } else { c.uint("requests")? },
                billable_requests: if pg_tokens {
                    0
                } else {
                    c.uint("billable_requests")?
                },
                models: vec![],
            };
            let tokens = if pg_requests {
                BTreeMap::new()
            } else {
                c.tokens()?
            };
            if model.is_empty() {
                if tokens.values().any(|v| *v != 0) {
                    return Err(Error::Invalid);
                }
            } else {
                if !mysql && (ledger.requests != 0 || ledger.billable_requests != 0) {
                    return Err(Error::Invalid);
                }
                ledger.models.push(ModelTokens {
                    scale,
                    model: model.clone(),
                    usage_units: tokens,
                });
            }
            ledger.normalize_scale6().map_err(|_| Error::Range)?;
            if mysql && c.bytes("bucket_scope")? != b"key" {
                return Err(Error::Unsupported);
            }
            HistoricalRow::Usage(UsageCell {
                sum_requests: mysql,
                bucket: c.text("bucket_id")?,
                window: c.timestamp("window_start")?,
                model,
                ledger,
            })
        }
        "usage_metering" => {
            let bucket = if pg {
                c.uint("bucket")?
            } else {
                std::str::from_utf8(c.bytes("bucket")?)
                    .map_err(|_| Error::Type)?
                    .parse::<u64>()
                    .map_err(|_| Error::Invalid)?
            };
            let mut row = MeteringRow {
                scale,
                key_id: c.text("key_id")?,
                model: c.text("model")?,
                provider: c.text("provider")?,
                tokens_input: c.quantity("tokens_input")?,
                tokens_output: c.quantity("tokens_output")?,
                tokens_cache_read: c.quantity("tokens_cache_read")?,
                tokens_cache_write: c.quantity("tokens_cache_write")?,
                requests: c.uint("requests")?,
                billable_requests: c.uint("billable_requests")?,
                key_group_at_use: c.text("key_group_at_use")?,
                pricing_version: c.text("pricing_version")?,
                priced_from_ms: if dev {
                    c.timestamp("priced_from_ms")?
                } else {
                    0
                },
                usage_units: BTreeMap::new(),
            };
            row.normalize_scale6().map_err(|_| Error::Range)?;
            HistoricalRow::Metering { bucket, row }
        }
        "denylist" => HistoricalRow::Denied {
            subject: c.text("sub")?,
            reason: c.text("reason")?,
            created_at: c.timestamp("created_at")?,
        },
        "store_revision" | "store_sequence" => {
            let valid = if pg {
                c.boolean("only_row")?
            } else {
                c.uint("id")? == u64::from(mysql)
            };
            if !valid {
                return Err(Error::Invalid);
            }
            HistoricalRow::Revision(c.revision()?)
        }
        "busbar_schema" => {
            let version = c.uint("version")?;
            if version
                != match profile {
                    Profile::PostgresReleased6 => 6,
                    Profile::PostgresDev7 => 7,
                    Profile::PostgresDev8 => 8,
                    Profile::PostgresDev9 => 9,
                    _ => return Err(Error::Unsupported),
                }
            {
                return Err(Error::Unsupported);
            }
            HistoricalRow::Schema(version)
        }
        "store_meta" => HistoricalRow::Meta {
            name: c.bytes("k")?,
            value: c.bytes("v")?,
        },
        "audit_log" => HistoricalRow::Audit(AuditRecord {
            seq: c.uint("seq")?,
            ts: c.timestamp("ts")?,
            action: c.text("action")?,
            resource: c.text("resource")?,
            outcome: c.text("outcome")?,
            principal: c.text("principal")?,
            prev_hash: c.text("prev_hash")?,
            hash: c.text("hash")?,
        }),
        _ => return Err(Error::Unsupported),
    })
}

/// Reassemble one complete logical usage cell. The caller supplies exactly one
/// (bucket, window) group from its fenced snapshot, bounded before allocation.
/// Duplicate physical model rows fail. MySQL released readers SUM request columns
/// across models; preserving that historical behavior is required even when
/// physical rows happen to repeat the same totals.
pub fn assemble_usage(cells: &[UsageCell]) -> Result<UsageLedger, Error> {
    let Some(first) = cells.first() else {
        return Err(Error::Invalid);
    };
    let mut result = UsageLedger::default();
    let mut requests = None;
    let mut models = std::collections::BTreeSet::new();
    for cell in cells {
        if (cell.bucket.as_str(), cell.window, cell.sum_requests)
            != (first.bucket.as_str(), first.window, first.sum_requests)
            || !models.insert(cell.model.as_str())
        {
            return Err(Error::Invalid);
        }
        if cell.sum_requests {
            let (admitted, billable) = requests.unwrap_or((0u64, 0u64));
            requests = Some((
                admitted
                    .checked_add(cell.ledger.requests)
                    .ok_or(Error::Range)?,
                billable
                    .checked_add(cell.ledger.billable_requests)
                    .ok_or(Error::Range)?,
            ));
        } else if cell.model.is_empty() {
            if requests.is_some() {
                return Err(Error::Invalid);
            }
            requests = Some((cell.ledger.requests, cell.ledger.billable_requests));
        }
        result.models.extend(cell.ledger.models.iter().cloned());
    }
    let (admitted, billable) = requests.unwrap_or((0, 0));
    result.requests = admitted;
    result.billable_requests = billable;
    result.models.sort_by(|a, b| a.model.cmp(&b.model));
    Ok(result)
}

fn exact_sqlite<'a>(
    profile: Profile,
    table: &str,
    columns: &[&str],
    row: Row<'a>,
) -> Result<HistoricalRow<'a>, Error> {
    let metering = table == "usage_metering_exact";
    let expected: &[&str] = if metering {
        &[
            "bucket",
            "key_id",
            "provider",
            "model",
            "priced_from_ms",
            "key_group_at_use",
            "pricing_version",
            "ledger",
        ]
    } else {
        &["window_start", "bucket_id", "ledger"]
    };
    let c = Columns::new(false, columns, row, expected)?;
    let Cell::Blob(bytes) = c.cell("ledger") else {
        return Err(Error::Type);
    };
    // Inspect field names only. Domain decoding below reads original bytes, so
    // large signed i128 mantissas never pass through JSON floating point values.
    let fields: serde_json::Value = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
    let object = fields.as_object().ok_or(Error::Invalid)?;
    let known: &[&str] = if metering {
        &[
            "scale",
            "key_id",
            "model",
            "provider",
            "tokens_input",
            "tokens_output",
            "tokens_cache_read",
            "tokens_cache_write",
            "requests",
            "billable_requests",
            "key_group_at_use",
            "pricing_version",
            "priced_from_ms",
            "usage_units",
        ]
    } else {
        &["requests", "billable_requests", "models"]
    };
    if object.keys().any(|name| !known.contains(&name.as_str())) {
        return Err(Error::Columns);
    }
    if metering {
        let mut value: MeteringRow = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        if value.key_id != c.text("key_id")?
            || value.provider != c.text("provider")?
            || value.model != c.text("model")?
            || value.priced_from_ms != c.timestamp("priced_from_ms")?
            || value.key_group_at_use != c.text("key_group_at_use")?
            || value.pricing_version != c.text("pricing_version")?
        {
            return Err(Error::Invalid);
        }
        if profile != Profile::SqliteDev7 && value.scale != 6 {
            return Err(Error::Invalid);
        }
        value.normalize_scale6().map_err(|_| Error::Range)?;
        let bucket = std::str::from_utf8(c.bytes("bucket")?)
            .map_err(|_| Error::Type)?
            .parse()
            .map_err(|_| Error::Invalid)?;
        Ok(HistoricalRow::Metering { bucket, row: value })
    } else {
        let models = object
            .get("models")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::Invalid)?;
        for model in models {
            if model
                .as_object()
                .ok_or(Error::Invalid)?
                .keys()
                .any(|name| !["scale", "model", "usage_units"].contains(&name.as_str()))
            {
                return Err(Error::Columns);
            }
        }
        let mut ledger: UsageLedger = serde_json::from_slice(bytes).map_err(|_| Error::Invalid)?;
        let mut seen = std::collections::BTreeSet::new();
        if ledger.models.iter().any(|m| !seen.insert(m.model.as_str())) {
            return Err(Error::Invalid);
        }
        if profile != Profile::SqliteDev7 && ledger.models.iter().any(|m| m.scale != 6) {
            return Err(Error::Invalid);
        }
        ledger.normalize_scale6().map_err(|_| Error::Range)?;
        Ok(HistoricalRow::ExactUsage {
            bucket: c.text("bucket_id")?,
            window: c.timestamp("window_start")?,
            ledger,
        })
    }
}

/// Canonical output shares the runtime owner's byte framing.
pub type CanonicalRows = Vec<(
    busbar_contract::persistence::Address,
    busbar_contract::Secret<Vec<u8>>,
)>;

/// Canonical identity rows use the runtime owner's private encoders. This never
/// creates an operation receipt or sends a candidate. The original protected row
/// remains mandatory evidence, including any destroyed historical envelope.
pub fn canonical_identity(
    row: &HistoricalRow<'_>,
    owner_tombstoned: bool,
) -> Result<CanonicalRows, Error> {
    use busbar_kernel::persistence::import_target::records::identity;
    match row {
        HistoricalRow::Key { key, .. } => identity::migration_key(key).map_err(|_| Error::Invalid),
        HistoricalRow::Credential(value) => {
            let envelope = if value.meta.revoked_at.is_some() || owner_tombstoned {
                &[][..]
            } else {
                value.envelope.unwrap_or_default()
            };
            identity::migration_credential_rows(&value.meta, envelope, owner_tombstoned)
                .map_err(|_| Error::Invalid)
        }
        HistoricalRow::Denied {
            subject,
            reason,
            created_at,
        } => identity::migration_denied(subject, reason, *created_at)
            .map(|v| vec![v])
            .map_err(|_| Error::Invalid),
        HistoricalRow::Revision(revision) => identity::migration_revision(*revision)
            .map(|v| vec![v])
            .map_err(|_| Error::Invalid),
        _ => Err(Error::Unsupported),
    }
}

/// Encode only a fully assembled usage group, preserving the shared runtime
/// owner's key and partition framing. Import coordination must reject duplicate
/// business addresses; only identical partition index entries may be coalesced.
pub fn canonical_usage(
    bucket: &str,
    window: u64,
    ledger: &UsageLedger,
) -> Result<CanonicalRows, Error> {
    busbar_kernel::persistence::import_target::records::ledger::migration_usage(
        bucket, window, ledger,
    )
    .map_err(|_| Error::Invalid)
}

pub fn canonical_metering(bucket: u64, row: &MeteringRow) -> Result<CanonicalRows, Error> {
    busbar_kernel::persistence::import_target::records::ledger::migration_metering(bucket, row)
        .map_err(|_| Error::Invalid)
}

/// Merge open-unit sidecars into a completely assembled usage group. Counts
/// already carry scale six from the explicit source profile. Reserved-unit
/// sidecars are refused because they would alias native token columns.
pub fn attach_usage_units(
    bucket: &str,
    window: u64,
    ledger: &UsageLedger,
    units: &[HistoricalRow<'_>],
) -> Result<UsageLedger, Error> {
    let mut out = ledger.clone();
    let mut seen = std::collections::BTreeSet::new();
    for unit in units {
        let HistoricalRow::UsageUnit {
            bucket: source_bucket,
            window: source_window,
            model,
            unit,
            count,
        } = unit
        else {
            return Err(Error::Type);
        };
        if source_bucket != bucket
            || *source_window != window
            || RESERVED_UNITS.contains(&unit.as_str())
            || !seen.insert((model.as_str(), unit.as_str()))
        {
            return Err(Error::Invalid);
        }
        if let Some(existing) = out.models.iter_mut().find(|m| m.model == *model) {
            if existing.usage_units.insert(unit.clone(), *count).is_some() {
                return Err(Error::Invalid);
            }
        } else {
            out.models.push(ModelTokens {
                scale: 6,
                model: model.clone(),
                usage_units: BTreeMap::from([(unit.clone(), *count)]),
            });
        }
    }
    out.models.sort_by(|a, b| a.model.cmp(&b.model));
    Ok(out)
}

pub fn attach_metering_units(
    bucket: u64,
    row: &MeteringRow,
    units: &[HistoricalRow<'_>],
) -> Result<MeteringRow, Error> {
    let mut out = row.clone();
    for unit in units {
        let HistoricalRow::MeteringUnit {
            bucket: source_bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            key_group_at_use,
            pricing_version,
            unit,
            count,
        } = unit
        else {
            return Err(Error::Type);
        };
        if *source_bucket != bucket
            || key_id != &row.key_id
            || provider != &row.provider
            || model != &row.model
            || *priced_from_ms != row.priced_from_ms
            || key_group_at_use
                .as_ref()
                .is_some_and(|v| v != &row.key_group_at_use)
            || pricing_version
                .as_ref()
                .is_some_and(|v| v != &row.pricing_version)
            || out.usage_units.insert(unit.clone(), *count).is_some()
        {
            return Err(Error::Invalid);
        }
    }
    Ok(out)
}

fn decode_sql_units<'a>(
    pg: bool,
    mysql: bool,
    scale: u32,
    table: &str,
    columns: &[&str],
    row: Row<'a>,
) -> Result<HistoricalRow<'a>, Error> {
    let meter = table == "usage_metering_units";
    let attributed = columns.contains(&"key_group_at_use") || columns.contains(&"pricing_version");
    if attributed && !meter {
        return Err(Error::Columns);
    }
    if !meter && ((pg && table != "usage_ledger_units") || (mysql && table != "usage_window_units"))
    {
        return Err(Error::Unsupported);
    }
    let mut expected = if meter {
        vec![
            "bucket",
            "key_id",
            "provider",
            "model",
            "priced_from_ms",
            "unit",
            "count",
        ]
    } else {
        vec!["window_start", "bucket_id", "model", "unit", "count"]
    };
    if mysql && !meter {
        expected.push("bucket_scope");
    }
    if attributed {
        expected.extend(["key_group_at_use", "pricing_version"]);
    }
    let mut c = Columns::new(mysql, columns, row, &expected)?;
    c.decimal = true;
    let count = busbar_contract::count::Count::from_stored(c.quantity("count")?, scale)
        .map_err(|_| Error::Range)?
        .micros();
    if meter {
        let bucket = if pg {
            c.uint("bucket")?
        } else {
            std::str::from_utf8(c.bytes("bucket")?)
                .map_err(|_| Error::Type)?
                .parse()
                .map_err(|_| Error::Invalid)?
        };
        Ok(HistoricalRow::MeteringUnit {
            bucket,
            key_id: c.text("key_id")?,
            provider: c.text("provider")?,
            model: c.text("model")?,
            priced_from_ms: c.timestamp("priced_from_ms")?,
            key_group_at_use: if attributed {
                Some(c.text("key_group_at_use")?)
            } else {
                None
            },
            pricing_version: if attributed {
                Some(c.text("pricing_version")?)
            } else {
                None
            },
            unit: c.text("unit")?,
            count,
        })
    } else {
        if mysql && c.bytes("bucket_scope")? != b"key" {
            return Err(Error::Unsupported);
        }
        Ok(HistoricalRow::UsageUnit {
            bucket: c.text("bucket_id")?,
            window: c.timestamp("window_start")?,
            model: c.text("model")?,
            unit: c.text("unit")?,
            count,
        })
    }
}

/// One historical admin plane-record kind moved to a private schema. The ID,
/// body (including binding/held records), and expiry evidence stay exact; this
/// descriptor does not decode or issue a new operation under the old key.
pub fn private_schema_for_plane_kind(kind: &str) -> Option<(&'static str, &'static str)> {
    match kind {
        "busbar.admin-idempotency" => Some(("busbar.admin", "busbar.admin-idempotency")),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
