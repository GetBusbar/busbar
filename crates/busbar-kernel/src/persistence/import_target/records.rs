// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pure destination-owner codecs for offline import. These functions prepare
//! bytes and validate address classes; they grant no writer or source custody.
use busbar_contract::{persistence::Address, records::*, Secret};

pub type Rows = Vec<(Address, Secret<Vec<u8>>)>;

pub enum OriginalAccounting {
    Usage(Vec<(String, u64, UsageDelta)>),
    Metering(Vec<MeteringDelta>),
    CorrectionFingerprint([u8; 32]),
}
/// Inspect a stored candidate under its owner's unchanged payload/fingerprint
/// validation. Returned values describe the old attempt, never a new candidate.
pub fn original_accounting(
    event: &crate::governance::recovery::RecoveryEvent,
) -> RecordStoreResult<OriginalAccounting> {
    use crate::governance::{recovery::RecoveryKind, GovState};
    match event.kind {
        RecoveryKind::Usage => GovState::legacy_usage_values(event).map(OriginalAccounting::Usage),
        RecoveryKind::Metering => {
            GovState::legacy_metering_values(event).map(OriginalAccounting::Metering)
        }
        RecoveryKind::Correction => GovState::legacy_correction_fingerprint(event)
            .map(OriginalAccounting::CorrectionFingerprint),
    }
}

pub mod identity {
    use super::*;
    use crate::governance::persistence::identity as owner;
    pub use owner::{CONFIDENTIAL, NAMESPACE};
    pub fn migration_key(key: &VirtualKey) -> RecordStoreResult<Rows> {
        owner::migration_key(key)
    }
    pub fn migration_credential_rows(
        meta: &CredentialMeta,
        envelope: &[u8],
        owner_tombstoned: bool,
    ) -> RecordStoreResult<Rows> {
        owner::migration_credential_rows(meta, envelope, owner_tombstoned)
    }
    pub fn migration_revision(revision: u64) -> RecordStoreResult<(Address, Secret<Vec<u8>>)> {
        owner::migration_revision(revision)
    }
    pub fn migration_denied(
        subject: &str,
        reason: &str,
        created_at: u64,
    ) -> RecordStoreResult<(Address, Secret<Vec<u8>>)> {
        owner::migration_denied(subject, reason, created_at)
    }
    pub fn migration_authorizes(address: &Address) -> bool {
        owner::migration_authorizes(address)
    }
}
pub mod ledger {
    pub use crate::governance::persistence::ledger::{
        migration_authorizes, migration_metering, migration_usage, METERING, USAGE,
    };
}
pub mod history {
    pub use crate::host_records_async::{
        migration_audit_authorizes, migration_audit_rows, migration_authorizes, migration_rows,
        HistoryCollection, HistoryError, HistoryMode,
    };
}
pub mod scoped {
    pub use crate::persistence::scoped::{
        migration_address, migration_authorizes, migration_claim_authorizes, migration_claim_rows,
    };
}
pub mod bootstrap {
    pub use crate::host_record_bootstrap::{
        migration_receipt_address, migration_receipt_authorizes,
    };
}
pub mod trust {
    pub use crate::trust::demotion::{migration_trust_authorizes, migration_trust_rows};
}
pub mod ticket {
    use super::*;
    pub fn legacy_ticket_record(
        id: &str,
        expires_at: u64,
        body: &[u8],
    ) -> Result<(Address, Secret<Vec<u8>>), &'static str> {
        crate::governance::legacy_ticket_record(id, expires_at, body)
            .map_err(|_| "invalid imported ticket")
    }
    pub fn legacy_ticket_expiry(
        id: &str,
        expires_at: u64,
    ) -> Result<(Address, Secret<Vec<u8>>), &'static str> {
        crate::governance::legacy_ticket_expiry(id, expires_at)
            .map_err(|_| "invalid imported ticket expiry")
    }
    pub fn legacy_ticket_token(
        kind: &str,
        id: &str,
        expires_at: u64,
    ) -> Result<(Address, Secret<Vec<u8>>), &'static str> {
        crate::governance::legacy_ticket_token(kind, id, expires_at)
            .map_err(|_| "invalid imported ticket token")
    }
    pub fn legacy_ticket_authorizes(address: &Address) -> bool {
        crate::governance::legacy_ticket_authorizes(address)
    }
}
pub mod keys {
    pub use crate::persistence::keys::{components, framed, KeyError};
}
pub mod host_records {
    pub use crate::host_records::record_key;
}
pub mod recovery {
    use super::*;
    use crate::governance::persistence::recovery as owner;
    pub fn legacy_head_address(operation: &[u8], value: &[u8]) -> Result<Address, String> {
        owner::legacy_head_address(operation, value).map_err(|error| error.to_string())
    }
    pub fn legacy_head_authorizes(address: &Address) -> bool {
        owner::legacy_head_authorizes(address)
    }
}

pub const AUDIT_OWNER: &str = crate::audit::auditlog::PERSISTENCE_OWNER;

#[derive(Clone, Copy)]
pub enum RecordScope {
    Unscoped,
    Instance,
}
pub struct RecordBinding<'a> {
    pub instance: &'a str,
    pub private: bool,
    pub scope: RecordScope,
}

/// Resolve the current canonical owner for built-in logical records. Values
/// are used only to validate the two address-bearing recovery/receipt shapes.
pub fn builtin_record_address(
    schema: &str,
    key: &[u8],
    value: &[u8],
) -> Result<Option<Address>, String> {
    if schema == "busbar.record-bootstrap.v1" {
        if value.len() != 32 {
            return Err("invalid record-bootstrap witness value".into());
        }
        return bootstrap::migration_receipt_address(key)
            .map(Some)
            .map_err(str::to_owned);
    }
    if schema == "busbar.usage-recovery-head.v1" {
        return recovery::legacy_head_address(key, value).map(Some);
    }
    let instance = match schema {
        "busbar.principal-transition.v1" => "busbar.principal-transition",
        "busbar.config.overlay.v1" => "busbar.config.overlay",
        "busbar.node.v1"
        | "busbar.keyset.v1"
        | "busbar.plugin_floor.v1"
        | "busbar.release_keys_floor.v1" => "busbar.boot",
        _ => return Ok(None),
    };
    scoped::migration_address(true, instance, schema, key)
        .map(Some)
        .map_err(|error| format!("record owner address: {error:?}"))
}

/// Address an exact Store witness using the same owner route as imported
/// logical records. Unknown global records require an admitted owner binding.
pub fn witness_address(
    schema: &str,
    key: &[u8],
    expected: &[u8],
    binding: Option<RecordBinding<'_>>,
) -> Result<Address, String> {
    if let Some(address) = builtin_record_address(schema, key, expected)? {
        return Ok(address);
    }
    let binding = binding.ok_or("record witness requires an explicit canonical owner binding")?;
    let logical = match binding.scope {
        RecordScope::Unscoped => key,
        RecordScope::Instance => {
            let length = key
                .get(..2)
                .ok_or("invalid instance-qualified witness key")?;
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            let end = 2usize
                .checked_add(length)
                .ok_or("witness key length overflow")?;
            if key.get(2..end) != Some(binding.instance.as_bytes()) {
                return Err("witness key instance does not match owner binding".into());
            }
            key.get(end..)
                .ok_or("invalid instance-qualified witness key")?
        }
    };
    scoped::migration_address(binding.private, binding.instance, schema, logical)
        .map_err(|error| format!("record witness owner address: {error:?}"))
}

/// Validate the original legacy audit recipe through its live owner. Callers
/// separately prove that this is the complete frozen source inventory.
pub fn verify_audit_chain<'a>(
    records: impl IntoIterator<Item = &'a AuditRecord>,
) -> Result<(), String> {
    let framed = records
        .into_iter()
        .map(|record| {
            crate::audit::stream_registry::StreamRecord::from_parts(
                String::new(),
                record.seq,
                record.prev_hash.clone(),
                record.hash.clone(),
                crate::audit::auditlog::audit_suffix(
                    record.ts,
                    &record.action,
                    &record.resource,
                    &record.outcome,
                    &record.principal,
                ),
                crate::audit::Framing::PipeSeparated,
                false,
            )
        })
        .collect::<Vec<_>>();
    crate::audit::verify_chain(&framed).map_err(|error| error.to_string())
}
