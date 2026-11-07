// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Async host adapters over the canonical record and history owners.
//! Authorization happens at construction from admitted instance facts; the old
//! synchronous RecordRows bridge is deliberately not used by these adapters.

use crate::persistence::{
    facade::{CoreStore, PendingId},
    history::{self, History},
    host_records::{self, HostRecords},
};
use busbar_contract::{
    host_records::conditional,
    records::{PlaneRecord, PlaneRecordRef, PlaneSelector, Retention},
    Secret,
};
use std::sync::Arc;

/// Normal plane records accept already instance-qualified keys. This preserves
/// the existing host's single authorization/key framing boundary.
pub(crate) struct AsyncRecords {
    store: Arc<CoreStore>,
    instance: String,
    schemas: Vec<String>,
}
impl AsyncRecords {
    pub(crate) fn authorized(
        store: Arc<CoreStore>,
        instance: &str,
        schemas: impl IntoIterator<Item = String>,
    ) -> Result<Self, host_records::Error> {
        let result = Self {
            store,
            instance: instance.into(),
            schemas: schemas.into_iter().collect(),
        };
        result.owner()?;
        Ok(result)
    }
    fn owner(&self) -> Result<HostRecords<'_>, host_records::Error> {
        HostRecords::authorized(
            &self.store,
            &self.instance,
            self.schemas.iter().map(String::as_str),
        )
    }
    pub(crate) async fn get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<Secret<Vec<u8>>>, host_records::Error> {
        self.owner()?.get(schema, key).await
    }
    pub(crate) async fn put(
        &self,
        schema: &str,
        key: &[u8],
        value: Secret<Vec<u8>>,
    ) -> Result<host_records::Outcome, host_records::Error> {
        self.owner()?.put(schema, key, value).await
    }
    pub(crate) async fn delete(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<host_records::Outcome, host_records::Error> {
        self.owner()?.delete(schema, key).await
    }
    pub(crate) async fn page(
        &self,
        schema: &str,
        prefix: &[u8],
        after: Option<&host_records::Cursor>,
    ) -> Result<host_records::Page, host_records::Error> {
        self.owner()?.scan(schema, prefix, after).await
    }
    pub(crate) async fn conditional(
        &self,
        request: &conditional::Request,
    ) -> Result<host_records::Outcome, host_records::Error> {
        self.owner()?.conditional(request).await
    }
    pub(crate) async fn retry(
        &self,
        id: PendingId,
    ) -> Result<host_records::Outcome, host_records::Error> {
        self.owner()?.retry(id).await
    }
}

pub use crate::persistence::history::{
    Collection as HistoryCollection, Error as HistoryError, Mode as HistoryMode,
    Outcome as HistoryOutcome,
};

/// Native rows produced by the trusted historical framing helpers.
pub type MigrationRows = Vec<(busbar_contract::persistence::Address, Secret<Vec<u8>>)>;

pub fn migration_rows<'a>(
    owner: &str,
    declarations: impl IntoIterator<Item = HistoryCollection<'a>>,
    record: PlaneRecordRef<'_>,
    parent_life: Option<u64>,
) -> Result<MigrationRows, HistoryError> {
    history::migration_rows(owner, declarations, record, parent_life)
}

pub fn migration_authorizes<'a>(
    owner: &str,
    declarations: impl IntoIterator<Item = HistoryCollection<'a>>,
    address: &busbar_contract::persistence::Address,
) -> bool {
    history::migration_authorizes(owner, declarations, address)
}

pub fn migration_audit_rows(
    owner: &str,
    record: &busbar_contract::records::AuditRecord,
) -> Result<MigrationRows, HistoryError> {
    history::migration_audit_rows(owner, record)
}
pub fn migration_audit_authorizes(
    owner: &str,
    address: &busbar_contract::persistence::Address,
) -> bool {
    history::migration_audit_authorizes(owner, address)
}

struct Declaration {
    kind: String,
    mode: history::Mode,
    retention: Retention,
    parent: Option<String>,
}

/// Immutable admitted collection declarations; every operation reconstructs a
/// borrowed owner over these same facts, without backend slots or blocking.
pub struct AsyncHistory {
    store: Arc<CoreStore>,
    instance: String,
    declarations: Vec<Declaration>,
}
impl AsyncHistory {
    /// Bind explicit host-owned collection declarations without plugin facts.
    pub fn authorized<'a>(
        store: Arc<CoreStore>,
        instance: &str,
        declarations: impl IntoIterator<Item = HistoryCollection<'a>>,
    ) -> Result<Self, HistoryError> {
        let result = Self {
            store,
            instance: instance.into(),
            declarations: declarations
                .into_iter()
                .map(|declaration| Declaration {
                    kind: declaration.kind.into(),
                    mode: declaration.mode,
                    retention: declaration.retention,
                    parent: declaration.parent.map(str::to_string),
                })
                .collect(),
        };
        result.owner()?;
        Ok(result)
    }

    /// Core envelope sinks use independently authorized upsert collections.
    /// An opaque envelope parent field does not declare a collection graph.
    pub fn authorized_upserts(
        store: Arc<CoreStore>,
        instance: &str,
        kinds: impl IntoIterator<Item = String>,
    ) -> Result<Self, HistoryError> {
        let result = Self {
            store,
            instance: instance.into(),
            declarations: kinds
                .into_iter()
                .map(|kind| Declaration {
                    kind,
                    mode: history::Mode::Upsert,
                    retention: Retention::Age,
                    parent: None,
                })
                .collect(),
        };
        result.owner()?;
        Ok(result)
    }
    pub fn admitted(
        store: Arc<CoreStore>,
        instance: &str,
        facts: &crate::host_services::InstanceFacts,
    ) -> Result<Self, history::Error> {
        let declarations = facts
            .record_collections
            .iter()
            .map(|d| {
                let kind = facts
                    .record_kinds
                    .get(d.kind as usize)
                    .ok_or(history::Error::Unauthorized)?
                    .as_str()
                    .to_string();
                let parent = d
                    .parent
                    .map(|index| {
                        facts
                            .record_kinds
                            .get(index as usize)
                            .map(|k| k.as_str().to_string())
                            .ok_or(history::Error::Unauthorized)
                    })
                    .transpose()?;
                let retention = facts
                    .record_retentions
                    .iter()
                    .find(|r| r.kind == d.kind)
                    .map(|r| Retention::from_code(r.rule).ok_or(history::Error::Invalid))
                    .transpose()?
                    .unwrap_or_default();
                let mode = match d.mode {
                    busbar_contract::abi::plane::CollectionMode::Upsert => history::Mode::Upsert,
                    busbar_contract::abi::plane::CollectionMode::Append => history::Mode::Append,
                };
                Ok(Declaration {
                    kind,
                    mode,
                    retention,
                    parent,
                })
            })
            .collect::<Result<Vec<_>, history::Error>>()?;
        let result = Self {
            store,
            instance: instance.into(),
            declarations,
        };
        result.owner()?;
        Ok(result)
    }
    fn owner(&self) -> Result<History<'_>, history::Error> {
        History::authorized(
            &self.store,
            &self.instance,
            self.declarations.iter().map(|d| history::Collection {
                kind: &d.kind,
                mode: d.mode,
                retention: d.retention,
                parent: d.parent.as_deref(),
            }),
        )
    }
    pub async fn get(&self, kind: &str, id: &str) -> Result<Option<PlaneRecord>, history::Error> {
        self.owner()?.get(kind, id).await
    }
    pub async fn upsert(
        &self,
        record: PlaneRecordRef<'_>,
    ) -> Result<history::Outcome, history::Error> {
        self.owner()?.upsert(record).await
    }
    pub async fn append(
        &self,
        record: PlaneRecordRef<'_>,
    ) -> Result<history::Outcome, history::Error> {
        self.owner()?.append(record).await
    }
    /// Retain operation before awaiting. Resubmitting it after cancellation
    /// discovers the original immutable native plan instead of replanning.
    pub async fn append_with_id(
        &self,
        operation: [u8; 16],
        record: PlaneRecordRef<'_>,
    ) -> Result<HistoryOutcome, HistoryError> {
        self.owner()?.append_with_id(operation, record).await
    }
    pub async fn upsert_with_id(
        &self,
        operation: [u8; 16],
        record: PlaneRecordRef<'_>,
    ) -> Result<HistoryOutcome, HistoryError> {
        self.owner()?.upsert_with_id(operation, record).await
    }
    pub async fn list(
        &self,
        kind: &str,
        selector: &PlaneSelector<'_>,
    ) -> Result<Vec<PlaneRecord>, history::Error> {
        self.owner()?.list(kind, selector).await
    }
    pub async fn parents(&self, kind: &str) -> Result<Vec<String>, history::Error> {
        self.owner()?.parents(kind).await
    }
    pub async fn delete(&self, kind: &str, id: &str) -> Result<history::Outcome, history::Error> {
        self.owner()?.delete(kind, id).await
    }
    pub async fn purge(
        &self,
        kind: &str,
        before: u64,
    ) -> Result<(history::Outcome, u64), history::Error> {
        self.owner()?.purge(kind, before).await
    }
    pub async fn retry(&self, id: PendingId) -> Result<history::Outcome, history::Error> {
        self.owner()?.retry(id).await
    }
}
