// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Compiled offline SQL edges. Importer Format owner/logical/codec fields are
//! NEW registry discriminators: released databases never stored those envelopes.
//! A reader supplies complete logical groups, never independently truncated
//! SQLite exact/mirror tables. Every native physical row also gets an archive.
use super::super::{
    Bounds, Edge, Family, Format, Record, Registry, TargetRow, Transform, CORE_FORMAT,
};
use super::*;
use busbar_contract::{persistence::Address, Secret};
use busbar_kernel::persistence::import_target::records::history::{HistoryCollection, HistoryMode};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const IDENTITY: [u8; 16] = *b"legacy.identity1";
pub const ACCOUNTING: [u8; 16] = *b"legacy.account1\0";
pub const ARCHIVAL: [u8; 16] = *b"legacy.archive1\0";
pub const AUDIT: [u8; 16] = *b"legacy.audit.v1\0";

type ParsedSqlRow<'a> = (&'a str, &'a [u8], Row<'a>);
type OutputValue = (Secret<Vec<u8>>, Option<u32>, bool);

pub struct TableLayout {
    pub table: String,
    pub columns: Vec<String>,
}
#[derive(Clone)]
pub struct RecordBinding {
    pub schema: String,
    pub instance: String,
    pub private: bool,
    pub source_scope: archive::Scope,
}
#[derive(Clone)]
pub struct TokenBinding {
    pub source_kind: String,
    pub instance: String,
    pub kind: String,
}
#[derive(Clone)]
pub struct Collection {
    pub kind: String,
    pub mode: HistoryMode,
    pub retention: busbar_contract::records::Retention,
    pub parent: Option<String>,
}
#[derive(Clone)]
pub struct HistoryBinding {
    pub owner: String,
    pub collections: Vec<Collection>,
}
impl HistoryBinding {
    pub(crate) fn declarations(&self) -> impl Iterator<Item = HistoryCollection<'_>> {
        self.collections.iter().map(|c| HistoryCollection {
            kind: &c.kind,
            mode: c.mode,
            retention: c.retention,
            parent: c.parent.as_deref(),
        })
    }
}
pub struct SqlTransform {
    edge: Edge,
    profile: Profile,
    provenance: archive::Provenance,
    layouts: BTreeMap<String, Vec<String>>,
    records: Vec<RecordBinding>,
    histories: Vec<HistoryBinding>,
    tokens: Vec<TokenBinding>,
    journal: Option<std::sync::Arc<dyn super::journal_binding::JournalMigration>>,
    projection: Option<std::sync::Arc<dyn super::projection::ProjectionSource>>,
    recovery: Option<std::sync::Arc<super::recovery::FencedReceiptProofs>>,
    overlay: Option<std::sync::Arc<super::overlay::PreparedOverlay>>,
}

impl Profile {
    pub fn importer_format(self) -> Format {
        let (owner, physical) = match self {
            Self::SqliteReleased6 => (*b"legacy.sqlite.v1", 6),
            Self::SqliteDev7 => (*b"legacy.sqlite.v1", 7),
            Self::SqliteDev8 => (*b"legacy.sqlite.v1", 8),
            Self::SqliteDev9 => (*b"legacy.sqlite.v1", 9),
            Self::PostgresReleased6 => (*b"legacy.postgr.v1", 6),
            Self::PostgresDev7 => (*b"legacy.postgr.v1", 7),
            Self::PostgresDev8 => (*b"legacy.postgr.v1", 8),
            Self::PostgresDev9 => (*b"legacy.postgr.v1", 9),
            Self::MysqlReleased3 => (*b"legacy.mysql..v1", 3),
            Self::MysqlDev4 => (*b"legacy.mysql..v1", 4),
            Self::MysqlDev5 => (*b"legacy.mysql..v1", 5),
            Self::MysqlDev7 => (*b"legacy.mysql..v1", 7),
        };
        Format {
            owner,
            physical,
            logical: 1,
            codec: 1,
        }
    }
}

impl Profile {
    pub fn from_importer_format(format: super::super::Format) -> Result<Self, Error> {
        if format.logical != 1 || format.codec != 1 {
            return Err(Error::Unsupported);
        }
        let profile = match (format.owner, format.physical) {
            (owner, 6) if owner == *b"legacy.sqlite.v1" => Self::SqliteReleased6,
            (owner, 7) if owner == *b"legacy.sqlite.v1" => Self::SqliteDev7,
            (owner, 8) if owner == *b"legacy.sqlite.v1" => Self::SqliteDev8,
            (owner, 9) if owner == *b"legacy.sqlite.v1" => Self::SqliteDev9,
            (owner, 6) if owner == *b"legacy.postgr.v1" => Self::PostgresReleased6,
            (owner, 7) if owner == *b"legacy.postgr.v1" => Self::PostgresDev7,
            (owner, 8) if owner == *b"legacy.postgr.v1" => Self::PostgresDev8,
            (owner, 9) if owner == *b"legacy.postgr.v1" => Self::PostgresDev9,
            (owner, 3) if owner == *b"legacy.mysql..v1" => Self::MysqlReleased3,
            (owner, 4) if owner == *b"legacy.mysql..v1" => Self::MysqlDev4,
            (owner, 5) if owner == *b"legacy.mysql..v1" => Self::MysqlDev5,
            (owner, 7) if owner == *b"legacy.mysql..v1" => Self::MysqlDev7,
            _ => return Err(Error::Unsupported),
        };
        Ok(profile)
    }
}

/// Physical adapters use this stable envelope for native PK identities. Values
/// stay the original protected legacy_row frame; no secret is placed in Debug.
pub fn source_key(table: &str, native_key: &[u8]) -> Result<Vec<u8>, Error> {
    busbar_kernel::persistence::import_target::records::keys::framed(
        b'L',
        &[table.as_bytes(), native_key],
    )
    .map_err(|_| Error::Range)
}
pub(super) fn source_parts(key: &[u8]) -> Result<(&str, &[u8]), Error> {
    let parts = busbar_kernel::persistence::import_target::records::keys::components(key, b'L')
        .map_err(|_| Error::Invalid)?;
    if parts.len() != 2 {
        return Err(Error::Invalid);
    }
    Ok((
        std::str::from_utf8(parts[0]).map_err(|_| Error::Type)?,
        parts[1],
    ))
}
pub(super) fn class(table: &str) -> Result<[u8; 16], Error> {
    Ok(match table {
        "keys" | "api_keys" | "credentials" | "denylist" | "store_revision" | "store_sequence" => {
            IDENTITY
        }
        "usage_windows"
        | "usage_ledger"
        | "usage_metering"
        | "usage_window_units"
        | "usage_ledger_units"
        | "usage_metering_units"
        | "usage_window_exact"
        | "usage_metering_exact" => ACCOUNTING,
        "audit_log" => AUDIT,
        "store_meta" | "busbar_schema" | "schema_records" | "store_records" | "store_ops"
        | "plane_records" | "plane_chain" | "plane_tokens" => ARCHIVAL,
        _ => return Err(Error::Unsupported),
    })
}
pub(super) fn hash_field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}
pub(crate) fn code_digest() -> [u8; 32] {
    let mut hash = Sha256::new();
    for bytes in [
        include_bytes!("mod.rs").as_slice(),
        include_bytes!("group.rs"),
        include_bytes!("journal_binding.rs"),
        include_bytes!("journal.rs"),
        include_bytes!("projection.rs"),
        include_bytes!("recovery.rs"),
        include_bytes!("receipt_codec.rs"),
        include_bytes!("streaming.rs"),
        include_bytes!("overlay.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/config/overlay_native.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/recovery_import.rs"
        )),
        include_bytes!("../routes.rs"),
        include_bytes!("../routes/parents.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel-audit/src/digest.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/journal/migration.rs"
        )),
        include_bytes!("valkey.rs"),
        include_bytes!("valkey_transform.rs"),
        include_bytes!("../archive_source.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/persistence/archive.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/persistence/legacy_row.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/keys.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/partition.rs"
        )),
        include_bytes!("archive.rs"),
        include_bytes!("verify.rs"),
        include_bytes!("transform.rs"),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/import_target/records.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/raw_recovery.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/ledger_correction.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/ledger_correction_recovery.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/exact_debt.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-contract/src/records/correction.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/audit/mod.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/audit/auditlog.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/audit/stream_registry.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/identity.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/ledger.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/persistence/recovery.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/history.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/scoped.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/claims.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/persistence/host_records.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/host_record_bootstrap.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/governance/tickets.rs"
        )),
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../busbar-kernel/src/trust/demotion.rs"
        )),
    ] {
        hash_field(&mut hash, bytes);
    }
    hash.finalize().into()
}
fn migration_error(error: Error) -> super::super::Error {
    match error {
        Error::Range => super::super::Error::Bounds,
        Error::Unsupported => super::super::Error::UnsupportedPath,
        _ => super::super::Error::Corrupt,
    }
}
impl SqlTransform {
    /// Host constructs this only from the exact admitted native catalogue and
    /// compiled owner declarations. Reports/manifests cannot select mappings.
    pub fn registered(
        profile: Profile,
        provenance: archive::Provenance,
        layouts: Vec<TableLayout>,
        records: Vec<RecordBinding>,
        histories: Vec<HistoryBinding>,
        tokens: Vec<TokenBinding>,
        bounds: Bounds,
    ) -> Result<Self, super::super::Error> {
        bounds.validate()?;
        if provenance.dataset == [0; 16] || provenance.catalogue == [0; 32] || layouts.is_empty() {
            return Err(super::super::Error::IdentityMismatch);
        }
        let mut tables = BTreeMap::new();
        for layout in layouts {
            class(&layout.table).map_err(migration_error)?;
            if layout.columns.is_empty()
                || layout.columns.len() > 64
                || layout
                    .columns
                    .iter()
                    .enumerate()
                    .any(|(i, n)| layout.columns[..i].contains(n))
                || tables.insert(layout.table, layout.columns).is_some()
            {
                return Err(super::super::Error::InvalidManifest);
            }
        }
        let expected: &[&str] = match profile {
            Profile::SqliteReleased6 => &[
                "audit_log",
                "credentials",
                "denylist",
                "keys",
                "store_meta",
                "store_revision",
                "usage_metering",
                "usage_windows",
            ],
            Profile::PostgresReleased6 => &[
                "audit_log",
                "busbar_schema",
                "credentials",
                "denylist",
                "keys",
                "store_revision",
                "usage_ledger",
                "usage_metering",
                "usage_windows",
            ],
            Profile::MysqlReleased3 => &[
                "api_keys",
                "audit_log",
                "credentials",
                "denylist",
                "store_meta",
                "store_sequence",
                "usage_metering",
                "usage_windows",
            ],
            Profile::SqliteDev7 | Profile::SqliteDev8 | Profile::SqliteDev9 => &[
                "audit_log",
                "credentials",
                "denylist",
                "keys",
                "plane_records",
                "plane_tokens",
                "schema_records",
                "store_meta",
                "store_ops",
                "store_revision",
                "usage_metering",
                "usage_metering_exact",
                "usage_metering_units",
                "usage_window_exact",
                "usage_window_units",
                "usage_windows",
            ],
            Profile::PostgresDev7 | Profile::PostgresDev8 | Profile::PostgresDev9 => &[
                "audit_log",
                "busbar_schema",
                "credentials",
                "denylist",
                "keys",
                "plane_chain",
                "plane_records",
                "plane_tokens",
                "store_ops",
                "store_records",
                "store_revision",
                "usage_ledger",
                "usage_ledger_units",
                "usage_metering",
                "usage_metering_units",
                "usage_windows",
            ],
            Profile::MysqlDev4 | Profile::MysqlDev5 | Profile::MysqlDev7 => &[
                "api_keys",
                "audit_log",
                "credentials",
                "denylist",
                "plane_records",
                "plane_tokens",
                "store_meta",
                "store_ops",
                "store_records",
                "store_sequence",
                "usage_metering",
                "usage_metering_units",
                "usage_window_units",
                "usage_windows",
            ],
        };
        if tables.len() != expected.len()
            || expected.iter().any(|table| !tables.contains_key(*table))
        {
            return Err(super::super::Error::UnsupportedPath);
        }
        let mut kinds = BTreeSet::new();
        for history in &histories {
            if history.owner.is_empty() || history.collections.is_empty() {
                return Err(super::super::Error::InvalidManifest);
            }
            for collection in &history.collections {
                if !kinds.insert(collection.kind.as_str()) {
                    return Err(super::super::Error::InvalidManifest);
                }
            }
        }
        let mut preconditions = Sha256::new();
        hash_field(
            &mut preconditions,
            b"busbar.legacy.catalogue-and-bindings/1",
        );
        hash_field(&mut preconditions, &provenance.catalogue);
        for (table, columns) in &tables {
            hash_field(&mut preconditions, table.as_bytes());
            for column in columns {
                hash_field(&mut preconditions, column.as_bytes());
            }
        }
        bind_config(&mut preconditions, &records, &histories, &tokens);
        let preconditions_digest: [u8; 32] = preconditions.finalize().into();
        let mut families = Vec::new();
        for (family, anchor) in [
            (projection::PHYSICAL, projection::PHYSICAL),
            (
                IDENTITY,
                busbar_kernel::persistence::import_target::records::identity::NAMESPACE.0,
            ),
            (
                ACCOUNTING,
                busbar_kernel::persistence::import_target::records::ledger::USAGE.0,
            ),
            (ARCHIVAL, archive::NAMESPACE.0),
            (AUDIT, AUDIT),
        ] {
            if family == projection::PHYSICAL
                || tables.keys().any(|table| class(table).ok() == Some(family))
            {
                families.push(Family {
                    id: family,
                    source_schema: profile.importer_format().physical,
                    target_schema: 1,
                    target_namespace: anchor,
                });
            }
        }
        let edge = registered_edge(
            profile.importer_format(),
            preconditions_digest,
            families,
            bounds,
        )?;
        Ok(Self {
            edge,
            profile,
            provenance,
            layouts: tables,
            records,
            histories,
            tokens,
            journal: None,
            projection: None,
            recovery: None,
            overlay: None,
        })
    }
    pub fn with_projection(
        mut self,
        source: std::sync::Arc<dyn super::projection::ProjectionSource>,
    ) -> Result<Self, super::super::Error> {
        let provenance = source.provenance();
        if provenance.dataset != self.provenance.dataset
            || provenance.catalogue != self.provenance.catalogue
        {
            return Err(super::super::Error::IdentityMismatch);
        }
        self.projection = Some(source);
        Ok(self)
    }
    pub fn with_overlay(
        mut self,
        overlay: std::sync::Arc<super::overlay::PreparedOverlay>,
    ) -> Result<Self, super::super::Error> {
        if !self.matches_source(overlay.source()) {
            return Err(super::super::Error::IdentityMismatch);
        }
        let mut hash = Sha256::new();
        super::transform::hash_field(&mut hash, &self.edge.preconditions_digest);
        super::transform::hash_field(&mut hash, &overlay.descriptor_digest());
        let mut families = self.edge.families.clone();
        families.push(Family {
            id: super::overlay::FAMILY,
            source_schema: self.edge.source.physical,
            target_schema: 1,
            target_namespace: super::overlay::FAMILY,
        });
        self.edge = super::transform::registered_edge(
            self.edge.source,
            hash.finalize().into(),
            families,
            self.edge.bounds,
        )?;
        self.overlay = Some(overlay);
        Ok(self)
    }
    pub fn with_recovery(
        mut self,
        proofs: std::sync::Arc<super::recovery::FencedReceiptProofs>,
    ) -> Result<Self, super::super::Error> {
        let source = proofs.provenance();
        if source.dataset != self.provenance.dataset
            || source.catalogue != self.provenance.catalogue
        {
            return Err(super::super::Error::IdentityMismatch);
        }
        let mut hash = Sha256::new();
        super::transform::hash_field(&mut hash, &self.edge.preconditions_digest);
        super::transform::hash_field(&mut hash, &proofs.descriptor_digest());
        self.edge = super::transform::registered_edge(
            self.edge.source,
            hash.finalize().into(),
            self.edge.families.clone(),
            self.edge.bounds,
        )?;
        self.recovery = Some(proofs);
        Ok(self)
    }
    pub fn with_journal(
        mut self,
        plan: std::sync::Arc<dyn super::journal_binding::JournalMigration>,
    ) -> Result<Self, super::super::Error> {
        if !super::journal_binding::matches(plan.as_ref(), self.provenance) {
            return Err(super::super::Error::IdentityMismatch);
        }
        let mut hash = Sha256::new();
        hash_field(&mut hash, &self.edge.preconditions_digest);
        hash_field(&mut hash, &plan.descriptor_digest());
        self.edge = registered_edge(
            self.edge.source,
            hash.finalize().into(),
            self.edge.families.clone(),
            self.edge.bounds,
        )?;
        self.journal = Some(plan);
        Ok(self)
    }
    pub fn registry(&self) -> Result<Registry, super::super::Error> {
        Registry::new(vec![self.edge.clone()])
    }
    pub fn matches_source(&self, source: &super::super::Identity) -> bool {
        source.dataset == self.provenance.dataset
            && source.schema_digest == self.provenance.catalogue
            && source.format == self.edge.source
    }
    pub fn descriptor(&self) -> &Edge {
        &self.edge
    }
    fn bindings(&self) -> Vec<archive::Binding<'_>> {
        self.records
            .iter()
            .map(|b| archive::Binding {
                schema: &b.schema,
                instance: &b.instance,
                private: b.private,
                source_scope: b.source_scope,
            })
            .collect()
    }
    fn history(&self, kind: &str) -> Option<&HistoryBinding> {
        self.histories
            .iter()
            .find(|h| h.collections.iter().any(|c| c.kind == kind))
    }
    fn parsed<'a>(
        &self,
        records: &'a [Record],
        family: &Family,
        bounds: Bounds,
    ) -> Result<Vec<ParsedSqlRow<'a>>, super::super::Error> {
        bounds.validate()?;
        if !self.edge.families.contains(family) || records.len() > bounds.items as usize {
            return Err(super::super::Error::EdgeMismatch);
        }
        let mut size = 0usize;
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for record in records {
            size = size
                .checked_add(record.key.len())
                .and_then(|n| n.checked_add(record.value.expose(&crate::seal::lend()).len()))
                .ok_or(super::super::Error::Bounds)?;
            if size > bounds.bytes as usize || !seen.insert(record.key.as_slice()) {
                return Err(super::super::Error::Bounds);
            }
            let (table, key) = source_parts(&record.key).map_err(migration_error)?;
            if class(table).map_err(migration_error)? != family.id
                || !self.layouts.contains_key(table)
            {
                return Err(super::super::Error::EdgeMismatch);
            }
            out.push((
                table,
                key,
                Row::decode(record.value.expose(&crate::seal::lend()))
                    .map_err(|_| super::super::Error::Corrupt)?,
            ));
        }
        Ok(out)
    }
}

pub(crate) fn bind_config(
    hash: &mut Sha256,
    records: &[RecordBinding],
    histories: &[HistoryBinding],
    tokens: &[TokenBinding],
) {
    hash_field(hash, b"compiled-owner-bindings/1");
    hash_field(hash, &(records.len() as u64).to_le_bytes());
    for binding in records {
        hash_field(hash, binding.schema.as_bytes());
        hash_field(hash, binding.instance.as_bytes());
        hash_field(
            hash,
            &[
                u8::from(binding.private),
                u8::from(matches!(binding.source_scope, archive::Scope::Instance)),
            ],
        );
    }
    hash_field(hash, &(tokens.len() as u64).to_le_bytes());
    for token in tokens {
        hash_field(hash, token.source_kind.as_bytes());
        hash_field(hash, token.instance.as_bytes());
        hash_field(hash, token.kind.as_bytes());
    }
    hash_field(hash, &(histories.len() as u64).to_le_bytes());
    for history in histories {
        hash_field(hash, history.owner.as_bytes());
        hash_field(hash, &(history.collections.len() as u64).to_le_bytes());
        for collection in &history.collections {
            hash_field(hash, collection.kind.as_bytes());
            hash_field(hash, &[u8::from(collection.mode == HistoryMode::Append)]);
            hash_field(hash, &collection.retention.code().to_le_bytes());
            hash_field(hash, collection.parent.as_deref().unwrap_or("").as_bytes());
        }
    }
    hash_field(
        hash,
        busbar_kernel::persistence::import_target::records::AUDIT_OWNER.as_bytes(),
    );
}
pub(super) fn archival_authorizes(
    records: &[RecordBinding],
    histories: &[HistoryBinding],
    tokens: &[TokenBinding],
    address: &Address,
) -> bool {
    busbar_kernel::persistence::import_target::journal::authorizes(address)
        || busbar_kernel::persistence::import_target::records::trust::migration_trust_authorizes(address)
        || busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_authorizes(address)
        || busbar_kernel::persistence::import_target::records::recovery::legacy_head_authorizes(address)
        || busbar_kernel::persistence::import_target::records::bootstrap::migration_receipt_authorizes(address)
        || [
            (
                "busbar.principal-transition",
                "busbar.principal-transition.v1",
            ),
            ("busbar.config.overlay", "busbar.config.overlay.v1"),
            ("busbar.admin", "busbar.admin-idempotency"),
        ]
        .iter()
        .any(|(instance, schema)| {
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(true, instance, schema, address)
        })
        || [
            "busbar.node.v1",
            "busbar.keyset.v1",
            "busbar.plugin_floor.v1",
            "busbar.release_keys_floor.v1",
        ]
        .iter()
        .any(|schema| {
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(true, "busbar.boot", schema, address)
        })
        || busbar_kernel::persistence::import_target::records::scoped::migration_claim_authorizes(
            "busbar.auth-replay",
            "auth-replay",
            address,
        )
        || busbar_kernel::persistence::import_target::records::scoped::migration_claim_authorizes(
            "busbar.admin",
            "busbar.admin-idempotency",
            address,
        )
        || tokens.iter().any(|token| {
            busbar_kernel::persistence::import_target::records::scoped::migration_claim_authorizes(
                &token.instance,
                &token.kind,
                address,
            )
        })
        || records.iter().any(|b| {
            busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(
                b.private,
                &b.instance,
                &b.schema,
                address,
            )
        })
        || histories.iter().any(|h| {
            busbar_kernel::persistence::import_target::records::history::migration_authorizes(&h.owner, h.declarations(), address)
        })
}
pub(super) fn registered_edge(
    source: Format,
    preconditions_digest: [u8; 32],
    families: Vec<Family>,
    bounds: Bounds,
) -> Result<Edge, super::super::Error> {
    let code_digest = code_digest();
    let verification_rule_digest=Sha256::digest(b"busbar.legacy/native-readback+all-source-coverage+exact-mirror+graph+original-receipt-fenced-resolution/1").into();
    let mut identity = Sha256::new();
    hash_field(&mut identity, &code_digest);
    hash_field(&mut identity, &preconditions_digest);
    hash_field(&mut identity, &bounds.items.to_le_bytes());
    hash_field(&mut identity, &bounds.bytes.to_le_bytes());
    hash_field(&mut identity, &source.owner);
    hash_field(&mut identity, &source.physical.to_le_bytes());
    let digest = identity.finalize();
    let id = digest[..16]
        .try_into()
        .map_err(|_| super::super::Error::Corrupt)?;
    let edge = Edge {
        id,
        source,
        target: CORE_FORMAT,
        code_digest,
        preconditions_digest,
        verification_rule_digest,
        bounds,
        families,
    };
    Registry::new(vec![edge.clone()])?;
    Ok(edge)
}
pub(super) struct Output {
    rows: BTreeMap<Address, OutputValue>,
    bytes: usize,
    bounds: Bounds,
}
impl Output {
    pub(super) fn new(bounds: Bounds) -> Self {
        Self {
            rows: BTreeMap::new(),
            bytes: 0,
            bounds,
        }
    }
    pub(super) fn put(
        &mut self,
        address: Address,
        value: Secret<Vec<u8>>,
        source: Option<u32>,
        shared: bool,
    ) -> Result<(), super::super::Error> {
        let seal = crate::seal::lend();
        if let Some((previous, _, previous_shared)) = self.rows.get(&address) {
            if shared && *previous_shared && previous.expose(&seal) == value.expose(&seal) {
                return Ok(());
            }
            return Err(super::super::Error::Verification);
        }
        self.bytes = self
            .bytes
            .checked_add(16 + address.key.len())
            .and_then(|n| n.checked_add(value.expose(&seal).len()))
            .ok_or(super::super::Error::Bounds)?;
        if self.rows.len() >= self.bounds.items as usize || self.bytes > self.bounds.bytes as usize
        {
            return Err(super::super::Error::Bounds);
        }
        self.rows.insert(address, (value, source, shared));
        Ok(())
    }
    pub(super) fn canonical(
        &mut self,
        rows: CanonicalRows,
        shared_indices: bool,
    ) -> Result<(), super::super::Error> {
        for (i, (at, value)) in rows.into_iter().enumerate() {
            self.put(at, value, None, shared_indices && i > 0)?;
        }
        Ok(())
    }
    pub(super) fn finish(self) -> Vec<TargetRow> {
        self.rows
            .into_iter()
            .map(|(address, (value, preserved_source, _))| TargetRow {
                address,
                value,
                preserved_source,
            })
            .collect()
    }
}

impl Transform for SqlTransform {
    fn edge(&self) -> &Edge {
        &self.edge
    }
    fn authorize(&self, family: &Family, address: &Address) -> bool {
        if !self.edge.families.contains(family) {
            return false;
        }
        if family.id == super::overlay::FAMILY {
            return self
                .overlay
                .as_ref()
                .is_some_and(|overlay| overlay.authorizes(address));
        }
        if busbar_kernel::persistence::import_target::journal::inventory_address_class(address) {
            return family.id == ARCHIVAL
                && self
                    .journal
                    .as_ref()
                    .is_some_and(|plan| plan.inventory_authorizes(address));
        }
        if busbar_kernel::persistence::import_target::recovery::applied_disposition_authorizes(
            address,
        ) {
            return family.id == ARCHIVAL
                && self
                    .recovery
                    .as_ref()
                    .is_some_and(|proofs| proofs.authorizes(address));
        }
        if archive::authorizes(address) {
            let Ok(parts) = busbar_kernel::persistence::import_target::records::keys::components(
                &address.key,
                b'E',
            ) else {
                return false;
            };
            let Ok(table) = std::str::from_utf8(parts[2]) else {
                return false;
            };
            return parts[0] == self.provenance.dataset
                && parts[1] == self.provenance.catalogue
                && self.layouts.contains_key(table)
                && (family.id == projection::PHYSICAL || class(table).ok() == Some(family.id));
        }
        match family.id {
            IDENTITY => busbar_kernel::persistence::import_target::records::identity::migration_authorizes(address),
            ACCOUNTING => busbar_kernel::persistence::import_target::records::ledger::migration_authorizes(address),
            AUDIT => busbar_kernel::persistence::import_target::records::history::migration_audit_authorizes(
                busbar_kernel::persistence::import_target::records::AUDIT_OWNER,
                address,
            ),
            ARCHIVAL => archival_authorizes(&self.records, &self.histories, &self.tokens, address),
            _ => false,
        }
    }
    fn transform(
        &self,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
    ) -> Result<Vec<TargetRow>, super::super::Error> {
        if family.id == super::overlay::FAMILY {
            return self
                .overlay
                .as_ref()
                .ok_or(super::super::Error::MissingCapability)?
                .transform(records, bounds);
        }
        if super::projection::is_marker_page(records) {
            return super::projection::project_rows(
                self.projection
                    .as_deref()
                    .ok_or(super::super::Error::MissingCapability)?,
                self.provenance,
                self.journal.as_deref(),
                family,
                records,
                bounds,
                |marker| {
                    let frozen = self
                        .projection
                        .as_deref()
                        .ok_or(super::super::Error::MissingCapability)?;
                    if family.id == ACCOUNTING {
                        self.streaming_accounting(frozen, marker, bounds)
                    } else {
                        self.transform_impl(
                            family,
                            &projection::materialize(frozen, family.id, marker, bounds)?,
                            bounds,
                            false,
                        )
                    }
                },
            );
        }
        self.transform_impl(family, records, bounds, true)
    }
}

impl SqlTransform {
    fn streaming_accounting(
        &self,
        source: &dyn projection::ProjectionSource,
        marker: &Record,
        bounds: Bounds,
    ) -> Result<Vec<TargetRow>, super::super::Error> {
        let decoded = streaming::sql_rows(source, marker, self.profile, &self.layouts, bounds)?;
        let mut out = Output::new(bounds);
        if self.profile == Profile::SqliteDev9 {
            let verified =
                verify::sqlite9_decoded(decoded.into_iter().map(Ok)).map_err(migration_error)?;
            for (bucket, window, ledger) in verified.usage {
                out.canonical(
                    canonical_usage(&bucket, window, &ledger).map_err(migration_error)?,
                    true,
                )?;
            }
            for (bucket, row) in verified.metering {
                out.canonical(
                    canonical_metering(bucket, &row).map_err(migration_error)?,
                    true,
                )?;
            }
        } else {
            self.accounting_rows(decoded.into_iter().map(|(_, row)| row).collect(), &mut out)?;
        }
        Ok(out.finish())
    }
    fn accounting_rows(
        &self,
        decoded: Vec<HistoricalRow<'_>>,
        out: &mut Output,
    ) -> Result<(), super::super::Error> {
        let mut usage = BTreeMap::<(String, u64), Vec<UsageCell>>::new();
        let mut meters = Vec::new();
        let mut units = Vec::new();
        for row in decoded {
            match row {
                HistoricalRow::Usage(cell) => usage
                    .entry((cell.bucket.clone(), cell.window))
                    .or_default()
                    .push(cell),
                HistoricalRow::UsageUnit { .. } | HistoricalRow::MeteringUnit { .. } => {
                    units.push(row)
                }
                HistoricalRow::Metering { bucket, row } => meters.push((bucket, row)),
                _ => return Err(super::super::Error::UnsupportedPath),
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
                assemble_usage(&cells).map_err(migration_error)?
            };
            let ledger =
                attach_usage_units(&bucket, window, &base, &selected).map_err(migration_error)?;
            out.canonical(
                canonical_usage(&bucket, window, &ledger).map_err(migration_error)?,
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
                            return Err(super::super::Error::Verification);
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
            let row = attach_metering_units(bucket, &row, &selected).map_err(migration_error)?;
            out.canonical(
                canonical_metering(bucket, &row).map_err(migration_error)?,
                true,
            )?;
        }
        if consumed.len() != units.len() {
            return Err(super::super::Error::Verification);
        }
        Ok(())
    }
    fn transform_impl(
        &self,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        retain_physical: bool,
    ) -> Result<Vec<TargetRow>, super::super::Error> {
        if family.id == projection::PHYSICAL {
            if !self.edge.families.contains(family) {
                return Err(super::super::Error::EdgeMismatch);
            }
            return projection::physical_rows(
                self.provenance,
                records,
                bounds,
                |table, key, row| {
                    let columns = self
                        .layouts
                        .get(table)
                        .ok_or(super::super::Error::UnsupportedPath)?
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    group::row_class_and_group(self.profile, table, &columns, key, row)
                        .map(|_| ())
                        .map_err(migration_error)
                },
            );
        }
        let parsed = self.parsed(records, family, bounds)?;
        let mut out = Output::new(bounds);
        if retain_physical {
            for (i, (table, key, _)) in parsed.iter().enumerate() {
                let at = Address {
                    namespace: archive::NAMESPACE.0,
                    key: busbar_kernel::persistence::import_target::records::keys::framed(
                        b'E',
                        &[
                            &self.provenance.dataset,
                            &self.provenance.catalogue,
                            table.as_bytes(),
                            key,
                        ],
                    )
                    .map_err(|_| super::super::Error::Bounds)?,
                };
                out.put(
                    at,
                    Secret::new(records[i].value.expose(&crate::seal::lend()).clone()),
                    Some(i.try_into().map_err(|_| super::super::Error::Bounds)?),
                    false,
                )?;
            }
        }
        if family.id == ACCOUNTING && self.profile == Profile::SqliteDev9 {
            let column_sets = parsed
                .iter()
                .map(|(table, _, _)| {
                    self.layouts[*table]
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let physical = parsed
                .iter()
                .zip(&column_sets)
                .map(|((table, _, row), columns)| verify::PhysicalRow {
                    table,
                    columns,
                    row: *row,
                })
                .collect::<Vec<_>>();
            let verified = verify::sqlite9(&physical, bounds.items as usize, bounds.bytes as usize)
                .map_err(migration_error)?;
            for (bucket, window, ledger) in verified.usage {
                out.canonical(
                    canonical_usage(&bucket, window, &ledger).map_err(migration_error)?,
                    true,
                )?;
            }
            for (bucket, row) in verified.metering {
                out.canonical(
                    canonical_metering(bucket, &row).map_err(migration_error)?,
                    true,
                )?;
            }
            return Ok(out.finish());
        }
        let mut decoded = Vec::new();
        if family.id != ARCHIVAL {
            for (table, _, row) in &parsed {
                let columns = self.layouts[*table]
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>();
                decoded.push(decode(self.profile, table, &columns, *row).map_err(migration_error)?);
            }
        }
        match family.id {
            IDENTITY => {
                let mut owners = BTreeMap::new();
                for row in &decoded {
                    if let HistoricalRow::Key { key, .. } = row {
                        if owners
                            .insert(key.id.as_str(), key.deleted_at.is_some())
                            .is_some()
                        {
                            return Err(super::super::Error::Verification);
                        }
                    }
                }
                for row in &decoded {
                    let deleted = if let HistoricalRow::Credential(credential) = row {
                        *owners
                            .get(credential.meta.key_id.as_str())
                            .ok_or(super::super::Error::Verification)?
                    } else {
                        false
                    };
                    out.canonical(
                        canonical_identity(row, deleted).map_err(migration_error)?,
                        false,
                    )?;
                }
            }
            ACCOUNTING => self.accounting_rows(decoded, &mut out)?,
            AUDIT => {
                for row in decoded {
                    let HistoricalRow::Audit(record) = row else {
                        return Err(super::super::Error::UnsupportedPath);
                    };
                    out.canonical(
                        busbar_kernel::persistence::import_target::records::history::migration_audit_rows(
                            busbar_kernel::persistence::import_target::records::AUDIT_OWNER,
                            &record,
                        )
                        .map_err(|_| super::super::Error::Corrupt)?,
                        false,
                    )?;
                }
            }
            ARCHIVAL => {
                let bindings = self.bindings();
                let mut journal_parts =
                    BTreeMap::<[u8; 16], Vec<super::journal_binding::Part<'_>>>::new();
                for (i, (table, key, row)) in parsed.iter().enumerate() {
                    let columns = self.layouts[*table]
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    if matches!(*table, "store_meta" | "busbar_schema") {
                        decode(self.profile, table, &columns, *row).map_err(migration_error)?;
                        continue;
                    }
                    let retained = archive::sql(
                        self.profile,
                        self.provenance,
                        table,
                        &columns,
                        key,
                        records[i].value.expose(&crate::seal::lend()),
                        &bindings,
                    )
                    .map_err(migration_error)?;
                    match retained.route {
                        archive::Route::Record { address, value } => {
                            if self
                                .overlay
                                .as_ref()
                                .is_some_and(|overlay| overlay.replaces(&address))
                            {
                                continue;
                            }
                            if let Some(proofs) = &self.recovery {
                                out.canonical(proofs.record_rows(address, value)?, false)?;
                            } else {
                                out.put(address, Secret::new(value.to_vec()), None, false)?;
                            }
                        }
                        archive::Route::Prepared(rows) => out.canonical(rows, false)?,
                        archive::Route::JournalPart { key, value } => {
                            if key.len() != 18 {
                                return Err(super::super::Error::Corrupt);
                            }
                            journal_parts
                                .entry(
                                    key[..16]
                                        .try_into()
                                        .map_err(|_| super::super::Error::Corrupt)?,
                                )
                                .or_default()
                                .push(super::journal_binding::Part { key, value });
                        }
                        archive::Route::Receipt(_) => {}
                        archive::Route::RequiresBinding => {
                            return Err(super::super::Error::MissingCapability)
                        }
                        archive::Route::Token {
                            kind,
                            token,
                            expires_at,
                        } => {
                            let mut candidates = self
                                .tokens
                                .iter()
                                .filter(|binding| binding.source_kind == kind);
                            let matched = candidates.next();
                            if candidates.next().is_some() {
                                return Err(super::super::Error::Verification);
                            }
                            let (instance, native_kind) = if kind == "busbar.admin-idempotency" {
                                ("busbar.admin", kind)
                            } else if kind == "auth-replay" {
                                ("busbar.auth-replay", kind)
                            } else {
                                let binding =
                                    matched.ok_or(super::super::Error::MissingCapability)?;
                                (binding.instance.as_str(), binding.kind.as_str())
                            };
                            out.canonical(
                                busbar_kernel::persistence::import_target::records::scoped::migration_claim_rows(
                                    instance,
                                    native_kind,
                                    token,
                                    expires_at,
                                )
                                .map_err(|_| super::super::Error::Verification)?,
                                false,
                            )?;
                        }
                        archive::Route::Plane { record, append } => {
                            let binding = self
                                .history(record.kind)
                                .ok_or(super::super::Error::MissingCapability)?;
                            let declaration = binding
                                .collections
                                .iter()
                                .find(|c| c.kind == record.kind)
                                .ok_or(super::super::Error::MissingCapability)?;
                            if append
                                .is_some_and(|old| old != (declaration.mode == HistoryMode::Append))
                            {
                                return Err(super::super::Error::Verification);
                            }
                            let rows = busbar_kernel::persistence::import_target::records::history::migration_rows(
                                &binding.owner,
                                binding.declarations(),
                                record,
                                declaration.parent.as_ref().map(|_| 1),
                            )
                            .map_err(|_| super::super::Error::Verification)?;
                            for (i, (at, value)) in rows.into_iter().enumerate() {
                                out.put(at, value, None, i < 2)?;
                            }
                        }
                    }
                }
                if !journal_parts.is_empty() {
                    let plan = self
                        .journal
                        .as_ref()
                        .ok_or(super::super::Error::MissingCapability)?;
                    for parts in journal_parts.values() {
                        out.canonical(plan.copy_group(parts, bounds.bytes as usize)?, false)?;
                    }
                }
            }
            _ => return Err(super::super::Error::UnsupportedPath),
        }
        Ok(out.finish())
    }
}

/// Compiled native evidence provider. Parent existence must be read from the
/// same frozen source and verified against its copied source evidence. Audit
/// checks verify every original digest/ancestry member, including page boundary
/// anchors; modern NeutralBody streams retain their own declared codec.
pub trait NativeProofs: archive::HistoricalReceiptResolution {
    fn parent_present(
        &self,
        provenance: archive::Provenance,
        owner: &str,
        kind: &str,
        id: &str,
    ) -> Result<[u8; 32], super::super::Error>;
    fn historical_audit(
        &self,
        provenance: archive::Provenance,
        record: &busbar_contract::records::AuditRecord,
    ) -> Result<[u8; 32], super::super::Error>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageVerification {
    pub source_rows: u64,
    pub target_rows: u64,
    pub source_digest: [u8; 32],
    pub target_digest: [u8; 32],
    pub semantics_digest: [u8; 32],
}
impl SqlTransform {
    /// Native `Verifier::target_step` calls this after bounded actual target reads.
    /// Recomputing expected bytes is deterministic and performs no submissions.
    /// Missing/extra rows, any altered byte, unknown bindings, unresolved receipts,
    /// missing parents or invalid historical audit evidence refuse completion.
    pub fn verify_page(
        &self,
        source: &super::super::Identity,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        native_values: &[(Address, Secret<Vec<u8>>)],
        proofs: &dyn NativeProofs,
    ) -> Result<PageVerification, super::super::Error> {
        if family.id == super::overlay::FAMILY {
            if !self.matches_source(source) {
                return Err(super::super::Error::IdentityMismatch);
            }
            let expected = self.transform(family, records, bounds)?;
            return super::projection::verify_physical(
                records,
                &expected,
                native_values,
                &self.edge.verification_rule_digest,
            );
        }
        if !super::projection::is_marker_page(records) {
            return self.verify_raw(source, family, records, bounds, native_values, proofs, true);
        }
        if !self.matches_source(source) {
            return Err(super::super::Error::IdentityMismatch);
        }
        let expected = self.transform(family, records, bounds)?;
        let mut verified = super::projection::verify_physical(
            records,
            &expected,
            native_values,
            &self.edge.verification_rule_digest,
        )?;
        let frozen = self
            .projection
            .as_deref()
            .ok_or(super::super::Error::MissingCapability)?;
        let mut semantics = Sha256::new();
        super::transform::hash_field(&mut semantics, &verified.semantics_digest);
        for marker in records {
            super::projection::verify_marker(frozen, family.id, marker)?;
            if super::projection::is_journal_marker(marker)? {
                let journal = self
                    .journal
                    .as_deref()
                    .ok_or(super::super::Error::MissingCapability)?;
                super::transform::hash_field(&mut semantics, &journal.descriptor_digest());
                continue;
            }
            if family.id == ACCOUNTING {
                super::transform::hash_field(
                    &mut semantics,
                    &super::projection::decode_marker(marker)?,
                );
                super::transform::hash_field(&mut semantics, b"complete-streamed-accounting/1");
                continue;
            }
            let original = super::projection::materialize(frozen, family.id, marker, bounds)?;
            let projected = self.transform_impl(family, &original, bounds, false)?;
            let mut native = Vec::new();
            for row in &projected {
                let (_, value) = native_values
                    .iter()
                    .find(|(address, _)| address == &row.address)
                    .ok_or(super::super::Error::Verification)?;
                native.push((
                    row.address.clone(),
                    Secret::new(value.expose(&crate::seal::lend()).clone()),
                ));
            }
            let proof =
                self.verify_raw(source, family, &original, bounds, &native, proofs, false)?;
            super::transform::hash_field(&mut semantics, &proof.semantics_digest);
        }
        verified.semantics_digest = semantics.finalize().into();
        Ok(verified)
    }
    #[allow(clippy::too_many_arguments)]
    fn verify_raw(
        &self,
        source: &super::super::Identity,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        native_values: &[(Address, Secret<Vec<u8>>)],
        proofs: &dyn NativeProofs,
        retain_physical: bool,
    ) -> Result<PageVerification, super::super::Error> {
        if !self.matches_source(source) {
            return Err(super::super::Error::IdentityMismatch);
        }
        let expected = self.transform_impl(family, records, bounds, retain_physical)?;
        if family.id == projection::PHYSICAL {
            return projection::verify_physical(
                records,
                &expected,
                native_values,
                &self.edge.verification_rule_digest,
            );
        }
        if native_values.len() != expected.len() {
            return Err(super::super::Error::Verification);
        }
        let mut native = BTreeMap::new();
        for (address, value) in native_values {
            if native.insert(address, value).is_some() {
                return Err(super::super::Error::Verification);
            }
        }
        let seal = crate::seal::lend();
        let mut target_hash = Sha256::new();
        for row in &expected {
            if native.get(&row.address).map(|value| value.expose(&seal))
                != Some(row.value.expose(&seal))
            {
                return Err(super::super::Error::Verification);
            }
            hash_field(&mut target_hash, &row.address.namespace);
            hash_field(&mut target_hash, &row.address.key);
            hash_field(&mut target_hash, row.value.expose(&seal));
        }
        let parsed = self.parsed(records, family, bounds)?;
        let bindings = self.bindings();
        let mut source_hash = Sha256::new();
        let mut semantic_hash = Sha256::new();
        hash_field(&mut semantic_hash, &self.edge.verification_rule_digest);
        if let Some(plan) = &self.journal {
            hash_field(&mut semantic_hash, &plan.descriptor_digest());
        }
        for (i, (table, key, row)) in parsed.iter().enumerate() {
            hash_field(&mut source_hash, &records[i].key);
            hash_field(&mut source_hash, records[i].value.expose(&seal));
            let columns = self.layouts[*table]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            if family.id == ARCHIVAL && !matches!(*table, "store_meta" | "busbar_schema") {
                let retained = archive::sql(
                    self.profile,
                    self.provenance,
                    table,
                    &columns,
                    key,
                    records[i].value.expose(&seal),
                    &bindings,
                )
                .map_err(migration_error)?;
                let archived_value = if retain_physical {
                    native
                        .get(&retained.address)
                        .ok_or(super::super::Error::Verification)?
                        .expose(&seal)
                } else {
                    // The required PHYSICAL family independently reads these
                    // exact original bytes back from their archive addresses.
                    retained.original
                };
                if let Some(digest) = archive::verify_retained(
                    &retained,
                    &retained.address,
                    archived_value,
                    self.provenance,
                    proofs,
                )? {
                    hash_field(&mut semantic_hash, &digest);
                }
                if let archive::Route::Plane { record, .. } = retained.route {
                    let binding = self
                        .history(record.kind)
                        .ok_or(super::super::Error::MissingCapability)?;
                    let declaration = binding
                        .collections
                        .iter()
                        .find(|c| c.kind == record.kind)
                        .ok_or(super::super::Error::MissingCapability)?;
                    if let Some(parent_kind) = &declaration.parent {
                        let parent = record.parent.ok_or(super::super::Error::Verification)?;
                        let digest = proofs.parent_present(
                            self.provenance,
                            &binding.owner,
                            parent_kind,
                            parent,
                        )?;
                        if digest == [0; 32] {
                            return Err(super::super::Error::Verification);
                        }
                        hash_field(&mut semantic_hash, &digest);
                    }
                }
            } else if family.id == AUDIT {
                let HistoricalRow::Audit(record) =
                    decode(self.profile, table, &columns, *row).map_err(migration_error)?
                else {
                    return Err(super::super::Error::Verification);
                };
                let digest = proofs.historical_audit(self.provenance, &record)?;
                if digest == [0; 32] {
                    return Err(super::super::Error::Verification);
                }
                hash_field(&mut semantic_hash, &digest);
            }
        }
        hash_field(&mut semantic_hash, &records.len().to_le_bytes());
        Ok(PageVerification {
            source_rows: records
                .len()
                .try_into()
                .map_err(|_| super::super::Error::Bounds)?,
            target_rows: expected
                .len()
                .try_into()
                .map_err(|_| super::super::Error::Bounds)?,
            source_digest: source_hash.finalize().into(),
            target_digest: target_hash.finalize().into(),
            semantics_digest: semantic_hash.finalize().into(),
        })
    }
}

/// Concrete proof provider for released SQL snapshots, whose admitted catalogues
/// have neither generic operation receipts nor declared parent graphs. It proves
/// every legacy audit member from genesis using the existing historical framing.
/// The host obtains `source_count` from its pinned native table inventory; this
/// provider additionally verifies every hash/link/sequence, never counts alone.
pub struct ReleasedProofs {
    provenance: archive::Provenance,
    audit: BTreeMap<u64, busbar_contract::records::AuditRecord>,
    digest: [u8; 32],
}
pub type CompleteAuditProofs = ReleasedProofs;
impl ReleasedProofs {
    pub fn from_complete_audit(
        profile: Profile,
        provenance: archive::Provenance,
        records: Vec<busbar_contract::records::AuditRecord>,
        source_count: u64,
    ) -> Result<Self, super::super::Error> {
        if !matches!(
            profile,
            Profile::SqliteReleased6 | Profile::PostgresReleased6 | Profile::MysqlReleased3
        ) || u64::try_from(records.len()).ok() != Some(source_count)
        {
            return Err(super::super::Error::Verification);
        }
        Self::complete(provenance, records)
    }
    pub fn from_complete_source(
        source: super::super::Format,
        provenance: archive::Provenance,
        records: Vec<busbar_contract::records::AuditRecord>,
        source_count: u64,
    ) -> Result<Self, super::super::Error> {
        if source.logical != 1
            || source.codec != 1
            || !(Profile::from_importer_format(source).is_ok()
                || (source.owner == valkey::IMPORTER_OWNER && (6..=9).contains(&source.physical)))
        {
            return Err(super::super::Error::UnsupportedVersion);
        }
        if u64::try_from(records.len()).ok() != Some(source_count) {
            return Err(super::super::Error::Verification);
        }
        Self::complete(provenance, records)
    }
    fn complete(
        provenance: archive::Provenance,
        records: Vec<busbar_contract::records::AuditRecord>,
    ) -> Result<Self, super::super::Error> {
        let mut audit = BTreeMap::new();
        for record in records {
            if audit.insert(record.seq, record).is_some() {
                return Err(super::super::Error::Verification);
            }
        }
        busbar_kernel::persistence::import_target::records::verify_audit_chain(audit.values())
            .map_err(|_| super::super::Error::Verification)?;
        let mut hash = Sha256::new();
        hash_field(&mut hash, &provenance.dataset);
        hash_field(&mut hash, &provenance.catalogue);
        for record in audit.values() {
            hash_field(&mut hash, &record.seq.to_le_bytes());
            hash_field(&mut hash, record.hash.as_bytes());
            hash_field(&mut hash, record.prev_hash.as_bytes());
        }
        Ok(Self {
            provenance,
            audit,
            digest: hash.finalize().into(),
        })
    }
}
impl archive::HistoricalReceiptResolution for ReleasedProofs {
    fn resolve_original(
        &self,
        _provenance: archive::Provenance,
        _address: &Address,
        _receipt: &archive::Receipt<'_>,
    ) -> Result<[u8; 32], super::super::Error> {
        Err(super::super::Error::ReconciliationRequired)
    }
}
impl NativeProofs for ReleasedProofs {
    fn parent_present(
        &self,
        _provenance: archive::Provenance,
        _owner: &str,
        _kind: &str,
        _id: &str,
    ) -> Result<[u8; 32], super::super::Error> {
        Err(super::super::Error::MissingCapability)
    }
    fn historical_audit(
        &self,
        provenance: archive::Provenance,
        record: &busbar_contract::records::AuditRecord,
    ) -> Result<[u8; 32], super::super::Error> {
        if provenance.dataset != self.provenance.dataset
            || provenance.catalogue != self.provenance.catalogue
            || self.audit.get(&record.seq) != Some(record)
        {
            return Err(super::super::Error::Verification);
        }
        Ok(self.digest)
    }
}
