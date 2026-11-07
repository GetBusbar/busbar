// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Complete declared History parent membership over untouched frozen rows.
use super::*;
use crate::{archive_source::ArchiveRows, legacy::archive};
use busbar_contract::{persistence::legacy_row::Row, records::PlaneRecordRef};
use busbar_kernel::persistence::import_target::records::history::HistoryMode;
use std::collections::BTreeMap;

struct Inventory<'a> {
    bindings: &'a Bindings,
    parents: BTreeMap<(String, String, String), Digest32>,
    edges: Vec<(String, String, String)>,
    charge: usize,
    budget: usize,
}
impl Inventory<'_> {
    fn observe(
        &mut self,
        kind: &str,
        id: &str,
        parent: Option<&str>,
        append: Option<bool>,
        source_hash: Digest32,
    ) -> Result<(), Error> {
        let bindings = self.bindings;
        let Some((binding, collection)) = bindings.histories.iter().find_map(|binding| {
            binding
                .collections
                .iter()
                .find(|c| c.kind == kind)
                .map(|c| (binding, c))
        }) else {
            return Ok(());
        };
        if append.is_some_and(|old| old != (collection.mode == HistoryMode::Append)) {
            return Err(Error::Verification);
        }
        let size = binding
            .owner
            .len()
            .checked_add(kind.len())
            .and_then(|v| v.checked_add(id.len()))
            .and_then(|v| v.checked_add(parent.map_or(0, str::len)))
            .and_then(|v| v.checked_add(512))
            .ok_or(Error::Bounds)?;
        self.charge = self.charge.checked_add(size).ok_or(Error::Bounds)?;
        if self.charge > self.budget {
            return Err(Error::Bounds);
        }
        if collection.mode == HistoryMode::Upsert
            && self
                .parents
                .insert(
                    (binding.owner.clone(), kind.to_owned(), id.to_owned()),
                    source_hash,
                )
                .is_some()
        {
            return Err(Error::Verification);
        }
        if let Some(parent_kind) = &collection.parent {
            let parent = parent.ok_or(Error::Verification)?;
            if !binding
                .collections
                .iter()
                .any(|c| c.kind == *parent_kind && c.mode == HistoryMode::Upsert)
            {
                return Err(Error::Verification);
            }
            self.edges.try_reserve(1).map_err(|_| Error::Bounds)?;
            self.edges.push((
                binding.owner.clone(),
                parent_kind.clone(),
                parent.to_owned(),
            ));
        }
        Ok(())
    }
}
pub fn with_parent_graph_from_frozen(
    format: Format,
    provenance: Provenance,
    source: &mut dyn ArchiveRows,
    metadata_bytes: usize,
    bindings: &Bindings,
    base: Arc<dyn NativeProofs>,
) -> Result<Arc<dyn NativeProofs>, Error> {
    if source.header().owner != format.owner || source.header().physical != format.physical {
        return Err(Error::IdentityMismatch);
    }
    if metadata_bytes == 0 {
        return Err(Error::Bounds);
    }
    let sql = if format.owner == legacy::valkey::IMPORTER_OWNER {
        None
    } else {
        Some(legacy::Profile::from_importer_format(format).map_err(|_| Error::UnsupportedPath)?)
    };
    let valkey = if sql.is_none() {
        if source.header().tables.len() != 1 {
            return Err(Error::Corrupt);
        }
        let layout = legacy::valkey::NativeLayout::decode(&source.header().tables[0].native_layout)
            .map_err(|_| Error::Corrupt)?;
        if layout.importer_format() != format {
            return Err(Error::IdentityMismatch);
        }
        Some(layout)
    } else {
        None
    };
    let record_bindings = bindings
        .records
        .iter()
        .map(|b| archive::Binding {
            schema: &b.schema,
            instance: &b.instance,
            private: b.private,
            source_scope: b.source_scope,
        })
        .collect::<Vec<_>>();
    let mut inventory = Inventory {
        bindings,
        parents: BTreeMap::new(),
        edges: Vec::new(),
        charge: 0,
        budget: metadata_bytes,
    };
    let seal = crate::seal::lend();
    for ordinal in 0..source.row_count() {
        let original = source.read_row(ordinal)?;
        let table = source
            .header()
            .tables
            .get(original.table as usize)
            .ok_or(Error::Corrupt)?;
        if sql.is_some() && !matches!(table.name.as_str(), "plane_records" | "plane_chain") {
            continue;
        }
        let row = Row::decode(original.value.expose(&seal)).map_err(|_| Error::Corrupt)?;
        let mut hash = Sha256::new();
        field(&mut hash, original.native_key.expose(&seal));
        field(&mut hash, original.value.expose(&seal));
        let source_hash = hash.finalize().into();
        if let Some(profile) = sql {
            let columns = table.columns.iter().map(String::as_str).collect::<Vec<_>>();
            let retained = archive::sql(
                profile,
                provenance,
                &table.name,
                &columns,
                original.native_key.expose(&seal),
                original.value.expose(&seal),
                &record_bindings,
            )
            .map_err(|_| Error::Corrupt)?;
            if let archive::Route::Plane {
                record: PlaneRecordRef {
                    kind, id, parent, ..
                },
                append,
            } = retained.route
            {
                inventory.observe(kind, id, parent, append, source_hash)?;
            }
        } else {
            let layout = valkey.as_ref().ok_or(Error::Corrupt)?;
            let cell = legacy::valkey::physical(row).map_err(|_| Error::Corrupt)?;
            if cell.database != layout.source_db
                || cell.kind != legacy::valkey::PhysicalKind::Hash
                || !cell.key.starts_with(b"busbar:plane:")
            {
                continue;
            }
            let (kind, suffix) = legacy::valkey::plane_key(cell.key).map_err(|_| Error::Corrupt)?;
            if suffix != "rec" {
                continue;
            }
            let metadata = legacy::valkey::sidecar(cell.value).map_err(|_| Error::Corrupt)?;
            inventory.observe(
                &kind,
                &metadata.id,
                metadata.parent.as_deref(),
                None,
                source_hash,
            )?;
        }
    }
    for parent in &inventory.edges {
        if !inventory.parents.contains_key(parent) {
            return Err(Error::Verification);
        }
    }
    let mut hash = Sha256::new();
    field(&mut hash, b"busbar.frozen.history-parents/1");
    field(&mut hash, &provenance.dataset);
    field(&mut hash, &provenance.catalogue);
    legacy::transform::bind_config(
        &mut hash,
        &bindings.records,
        &bindings.histories,
        &bindings.tokens,
    );
    for ((owner, kind, id), digest) in &inventory.parents {
        field(&mut hash, owner.as_bytes());
        field(&mut hash, kind.as_bytes());
        field(&mut hash, id.as_bytes());
        field(&mut hash, digest);
    }
    inventory.edges.sort();
    for (owner, kind, id) in &inventory.edges {
        field(&mut hash, owner.as_bytes());
        field(&mut hash, kind.as_bytes());
        field(&mut hash, id.as_bytes());
    }
    Ok(Arc::new(GraphProofs {
        base,
        provenance,
        parents: inventory.parents,
        digest: hash.finalize().into(),
    }))
}
struct GraphProofs {
    base: Arc<dyn NativeProofs>,
    provenance: Provenance,
    parents: BTreeMap<(String, String, String), Digest32>,
    digest: Digest32,
}
impl archive::HistoricalReceiptResolution for GraphProofs {
    fn resolve_original(
        &self,
        p: Provenance,
        address: &Address,
        receipt: &archive::Receipt<'_>,
    ) -> Result<Digest32, Error> {
        self.base.resolve_original(p, address, receipt)
    }
}
impl NativeProofs for GraphProofs {
    fn parent_present(
        &self,
        p: Provenance,
        owner: &str,
        kind: &str,
        id: &str,
    ) -> Result<Digest32, Error> {
        if p.dataset != self.provenance.dataset || p.catalogue != self.provenance.catalogue {
            return Err(Error::IdentityMismatch);
        }
        if !self
            .parents
            .contains_key(&(owner.to_owned(), kind.to_owned(), id.to_owned()))
        {
            return Err(Error::MissingCapability);
        }
        Ok(self.digest)
    }
    fn historical_audit(
        &self,
        p: Provenance,
        record: &busbar_contract::records::AuditRecord,
    ) -> Result<Digest32, Error> {
        self.base.historical_audit(p, record)
    }
}
