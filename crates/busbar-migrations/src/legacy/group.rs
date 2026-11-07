// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Trusted logical grouping for a streaming physical archive. The external
//! index owns protected group keys and charges their bytes plus each member
//! index before allocation. Payloads are lent one row at a time, never retained.
use super::transform::{ACCOUNTING, ARCHIVAL, AUDIT, IDENTITY};
use super::*;

pub struct LogicalGroup {
    pub family: [u8; 16],
    pub key: busbar_contract::Secret<Vec<u8>>,
}
fn framed(parts: &[&[u8]]) -> Result<Vec<u8>, Error> {
    busbar_kernel::persistence::import_target::records::keys::framed(b'G', parts)
        .map_err(|_| Error::Range)
}

/// Check the original identity allocator against every persisted revision before
/// publishing any imported identity. An absent allocator means the old reader's
/// initial zero; it cannot authorize restarting below an existing identity.
/// This pass retains only two counters and one wiping source row.
pub fn verify_sql_identity_inventory(
    profile: Profile,
    source: &mut dyn super::super::archive_source::ArchiveRows,
) -> Result<(), super::super::Error> {
    use super::super::Error as MigrationError;
    let format = profile.importer_format();
    if source.header().owner != format.owner || source.header().physical != format.physical {
        return Err(MigrationError::IdentityMismatch);
    }
    let mut highest = 0;
    let mut allocator = None;
    let seal = crate::seal::lend();
    for ordinal in 0..source.row_count() {
        let record = source.read_row(ordinal)?;
        let table = source
            .header()
            .tables
            .get(record.table as usize)
            .ok_or(MigrationError::Corrupt)?;
        if !matches!(
            table.name.as_str(),
            "keys" | "api_keys" | "credentials" | "store_revision" | "store_sequence"
        ) {
            continue;
        }
        let columns = table.columns.iter().map(String::as_str).collect::<Vec<_>>();
        let row = Row::decode(record.value.expose(&seal)).map_err(|_| MigrationError::Corrupt)?;
        match decode(profile, &table.name, &columns, row).map_err(|_| MigrationError::Corrupt)? {
            HistoricalRow::Key { key, .. } => highest = highest.max(key.revision),
            HistoricalRow::Credential(value) => highest = highest.max(value.meta.revision),
            HistoricalRow::Revision(value) => {
                if allocator.replace(value).is_some() {
                    return Err(MigrationError::Verification);
                }
            }
            _ => return Err(MigrationError::Corrupt),
        }
    }
    if allocator.unwrap_or(0) < highest {
        return Err(MigrationError::Verification);
    }
    Ok(())
}
/// Actual native cells select the complete logical group. Usage joins ALL model,
/// unit and exact rows for (bucket,window). Metering joins base attribution keys
/// excluding group/version: old unit tables omitted those fields, so multiple
/// possible parents must meet in one group and are rejected as ambiguous.
pub fn row_class_and_group(
    profile: Profile,
    table: &str,
    columns: &[&str],
    native_key: &[u8],
    row: Row<'_>,
) -> Result<LogicalGroup, Error> {
    let effective = if profile == Profile::SqliteDev9
        && !matches!(table, "usage_window_exact" | "usage_metering_exact")
    {
        Profile::SqliteDev8
    } else {
        profile
    };
    let family = super::transform::class(table)?;
    if family == ARCHIVAL {
        if matches!(table, "schema_records" | "store_records") {
            let mysql = matches!(
                profile,
                Profile::MysqlDev4 | Profile::MysqlDev5 | Profile::MysqlDev7
            );
            let (schema, keycol) = if table == "schema_records" {
                ("schema", "record_key")
            } else {
                ("schema_id", if mysql { "rkey" } else { "key" })
            };
            let c = Columns::new(mysql, columns, row, &[schema, keycol, "value"])?;
            if c.bytes(schema)? == b"busbar.journal.v1" {
                return Ok(LogicalGroup {
                    family,
                    key: journal_group_key(c.bytes(keycol)?)?,
                });
            }
        }
        return Ok(LogicalGroup {
            family,
            key: busbar_contract::Secret::new(framed(&[
                b"X".as_slice(),
                table.as_bytes(),
                native_key,
            ])?),
        });
    }
    let decoded = decode(effective, table, columns, row)?;
    let key = match decoded {
        HistoricalRow::Key { key, .. } => framed(&[b"O".as_slice(), key.id.as_bytes()])?,
        HistoricalRow::Credential(value) => {
            framed(&[b"O".as_slice(), value.meta.key_id.as_bytes()])?
        }
        HistoricalRow::Denied { subject, .. } => framed(&[b"D".as_slice(), subject.as_bytes()])?,
        HistoricalRow::Revision(_) => framed(&[b"V".as_slice()])?,
        HistoricalRow::Usage(cell) => framed(&[
            b"U".as_slice(),
            cell.bucket.as_bytes(),
            &cell.window.to_be_bytes(),
        ])?,
        HistoricalRow::ExactUsage { bucket, window, .. }
        | HistoricalRow::UsageUnit { bucket, window, .. } => {
            framed(&[b"U".as_slice(), bucket.as_bytes(), &window.to_be_bytes()])?
        }
        HistoricalRow::Metering { bucket, row } => framed(&[
            b"M".as_slice(),
            &bucket.to_be_bytes(),
            row.key_id.as_bytes(),
            row.provider.as_bytes(),
            row.model.as_bytes(),
            &row.priced_from_ms.to_be_bytes(),
        ])?,
        HistoricalRow::MeteringUnit {
            bucket,
            key_id,
            provider,
            model,
            priced_from_ms,
            ..
        } => framed(&[
            b"M".as_slice(),
            &bucket.to_be_bytes(),
            key_id.as_bytes(),
            provider.as_bytes(),
            model.as_bytes(),
            &priced_from_ms.to_be_bytes(),
        ])?,
        HistoricalRow::Audit(record) => framed(&[b"A".as_slice(), &record.seq.to_be_bytes()])?,
        _ => return Err(Error::Unsupported),
    };
    if !matches!(family, IDENTITY | ACCOUNTING | AUDIT) {
        return Err(Error::Unsupported);
    }
    Ok(LogicalGroup {
        family,
        key: busbar_contract::Secret::new(key),
    })
}
/// Charge index metadata using checked arithmetic. The index must additionally
/// charge actual allocator bookkeeping/capacity if its representation adds any.
/// Physical evidence is paged independently. Logical projection streams every
/// member under its semantic budget and bounds only the resulting candidate.
pub fn index_charge(group_key: &[u8], member_count: usize) -> Result<usize, Error> {
    group_key
        .len()
        .checked_add(16)
        .and_then(|v| {
            member_count
                .checked_mul(std::mem::size_of::<usize>())
                .and_then(|members| v.checked_add(members))
        })
        .ok_or(Error::Range)
}

/// Valkey physical cells use the same complete-group rules, with selected-DB
/// semantics explicit in validated native_layout. Other DBs and non-busbar keys
/// are retained as opaque physical rows, never interpreted as core identities.
pub fn valkey_row_class_and_group(
    profile: valkey::Profile,
    source_db: u32,
    table: &str,
    columns: &[&str],
    native_key: &[u8],
    row: Row<'_>,
) -> Result<LogicalGroup, Error> {
    use valkey::PhysicalKind as Kind;
    if table != "valkey" || columns != valkey::NATIVE_COLUMNS {
        return Err(Error::Columns);
    }
    let cell = valkey::physical(row)?;
    if !valkey::native_identity_matches(cell, native_key) {
        return Err(Error::Invalid);
    }
    let archive = || {
        Ok(LogicalGroup {
            family: ARCHIVAL,
            key: busbar_contract::Secret::new(framed(&[
                b"X",
                &cell.database.to_be_bytes(),
                native_key,
            ])?),
        })
    };
    if cell.database != source_db || !cell.key.starts_with(b"busbar:") {
        return archive();
    }
    let key = std::str::from_utf8(cell.key).map_err(|_| Error::Type)?;
    let family;
    let group = if let Some(id) = key.strip_prefix("busbar:key:") {
        family = IDENTITY;
        framed(&[b"O", id.as_bytes()])?
    } else if key == "busbar:revision" {
        family = IDENTITY;
        framed(&[b"V"])?
    } else if key == "busbar:keys" || key == "busbar:keys:byrev" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if !matches!(
            (key, cell.kind),
            ("busbar:keys", Kind::Set) | ("busbar:keys:byrev", Kind::SortedSet)
        ) {
            return Err(Error::Type);
        }
        family = IDENTITY;
        framed(&[b"O", cell.position])?
    } else if key == "busbar:creds:byrev" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::SortedSet {
            return Err(Error::Type);
        }
        let (owner, _, _) = valkey::pointer(cell.position)?;
        family = IDENTITY;
        framed(&[b"O", owner.as_bytes()])?
    } else if let Some(id) = key.strip_prefix("busbar:cred:ids:") {
        family = IDENTITY;
        framed(&[b"O", id.as_bytes()])?
    } else if key.starts_with("busbar:cred:id:") || key.starts_with("busbar:cred:pub:") {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::String {
            return Err(Error::Type);
        }
        let (owner, _, _) = valkey::pointer(cell.value)?;
        family = IDENTITY;
        framed(&[b"O", owner.as_bytes()])?
    } else if let Some(rest) = key.strip_prefix("busbar:cred:") {
        let (owner, _, _) = valkey::pointer(rest.as_bytes())?;
        family = IDENTITY;
        framed(&[b"O", owner.as_bytes()])?
    } else if key == "busbar:denylist" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::Set {
            return Err(Error::Type);
        }
        family = IDENTITY;
        framed(&[b"D", cell.position])?
    } else if let Some(subject) = key.strip_prefix("busbar:denylist:") {
        family = IDENTITY;
        framed(&[b"D", subject.as_bytes()])?
    } else if key.starts_with("busbar:usage:") {
        family = ACCOUNTING;
        framed(&[b"U", cell.key])?
    } else if let Some(rest) = key.strip_prefix("busbar:metering:") {
        if rest.contains(':') {
            family = ACCOUNTING;
            framed(&[b"M", cell.key])?
        } else if cell.kind == Kind::Header {
            return archive();
        } else if cell.kind == Kind::Set {
            family = ACCOUNTING;
            framed(&[b"M", cell.position])?
        } else {
            return Err(Error::Type);
        }
    } else if key == "busbar:audit" {
        if cell.kind == Kind::Header {
            return archive();
        }
        if cell.kind != Kind::SortedSet {
            return Err(Error::Type);
        }
        let record = valkey::audit(cell.position)?;
        family = AUDIT;
        framed(&[b"A", &record.seq.to_be_bytes()])?
    } else if key.starts_with("busbar:op:") && profile != valkey::Profile::Released6 {
        family = ARCHIVAL;
        framed(&[b"T", cell.key])?
    } else if let Some(rest) = key.strip_prefix("busbar:records:") {
        if profile == valkey::Profile::Released6 {
            return Err(Error::Unsupported);
        }
        if cell.kind == Kind::Header {
            return archive();
        }
        let (schema, suffix) = rest.rsplit_once(':').ok_or(Error::Invalid)?;
        if !matches!(
            (suffix, cell.kind),
            ("v", Kind::Hash) | ("k", Kind::SortedSet)
        ) {
            return Err(Error::Type);
        }
        let schema = hex::decode(schema).map_err(|_| Error::Invalid)?;
        if schema == b"busbar.journal.v1" {
            return Ok(LogicalGroup {
                family: ARCHIVAL,
                key: journal_group_key(cell.position)?,
            });
        }
        family = ARCHIVAL;
        framed(&[b"R", &schema, cell.position])?
    } else {
        // Development plane record sidecar and body fields share one position.
        if profile != valkey::Profile::Released6
            && key.starts_with("busbar:plane:")
            && cell.kind == Kind::Hash
        {
            let rest = key.strip_prefix("busbar:plane:").ok_or(Error::Invalid)?;
            let (kind, suffix) = rest.split_once(':').ok_or(Error::Invalid)?;
            if matches!(suffix, "rec" | "body") {
                return Ok(LogicalGroup {
                    family: ARCHIVAL,
                    key: busbar_contract::Secret::new(framed(&[
                        b"P",
                        kind.as_bytes(),
                        cell.position,
                    ])?),
                });
            }
        }
        return archive();
    };
    Ok(LogicalGroup {
        family,
        key: busbar_contract::Secret::new(group),
    })
}

/// Exact legacy journal key was nodeBE8||sequenceBE8||partBE2. All parts
/// (including Valkey's corresponding value/index entries) form one bounded
/// original frame group. This never assigns native append custody.
pub fn journal_group_key(key: &[u8]) -> Result<busbar_contract::Secret<Vec<u8>>, Error> {
    if key.len() != 18 || key[..8] == [0; 8] || key[8..16] == [0; 8] {
        return Err(Error::Invalid);
    }
    Ok(busbar_contract::Secret::new(framed(&[
        b"J",
        &key[..8],
        &key[8..16],
    ])?))
}
