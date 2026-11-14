// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Logical conversion of admitted historical facts into current native records.
//! Physical field names, units and layouts are interpreted by source owners.
use busbar_contract::records::{CredentialMeta, MeteringRow, UsageLedger, VirtualKey};
pub mod archive;
pub mod fact_transform;
pub mod group;
pub mod overlay;
pub mod projection;
pub mod transform;

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

/// One admitted usage fragment with explicit request-counter aggregation.
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
    ExactUsage {
        bucket: String,
        window: u64,
        ledger: UsageLedger,
    },
    Usage(UsageCell),
    Metering {
        bucket: u64,
        row: MeteringRow,
    },
}

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

#[cfg(test)]
mod tests;
