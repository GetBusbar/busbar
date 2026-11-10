// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Compiled native startup routes. Inspection selects a closed source reader;
//! only the enforced immutable snapshot supplies import catalogue facts.
use crate::{
    legacy::{
        self,
        archive::Provenance,
        projection::ProjectionSource,
        transform::{HistoryBinding, NativeProofs, RecordBinding, TokenBinding},
    },
    *,
};
use busbar_contract::{
    persistence::{archive::Table, lifecycle, Address},
    Secret,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
mod parents;
pub use parents::with_parent_graph_from_facts;

#[derive(Clone, Default)]
pub struct Bindings {
    pub records: Vec<RecordBinding>,
    pub histories: Vec<HistoryBinding>,
    pub tokens: Vec<TokenBinding>,
}
#[derive(Clone)]
pub struct AdmittedStatement {
    pub owner: String,
    /// Digest of the complete admitted signed statement, including identity,
    /// kind, ABI and exact declaration/framing facts. Not an output-map hash.
    pub statement_sha256: Digest32,
    pub kind: u32,
    pub kind_abi: u32,
    pub layout_fingerprint: u64,
}
#[derive(Clone, Default)]
pub struct DeclarationInventory {
    pub bindings: Bindings,
    pub statements: Vec<AdmittedStatement>,
}
/// Preserve dormant scopes using the complete admitted inventory. Historical
/// history/token keys identify only a kind, so current configuration cannot
/// choose between competing owners. Leave those kinds unbound; an actual row
/// then refuses through the ordinary MissingCapability path.
pub fn dormant_safe_bindings(
    inventory: &DeclarationInventory,
    budget: usize,
) -> Result<Bindings, Error> {
    use legacy::archive::Scope;
    let mut admitted = inventory.bindings.clone();
    canonical_inventory(&mut admitted, budget)?;
    let records = admitted
        .records
        .iter()
        .filter(|record| {
            !admitted.records.iter().any(|other| {
                record.schema == other.schema
                    && !same_record(record, other)
                    && (matches!(record.source_scope, Scope::Unscoped)
                        || matches!(other.source_scope, Scope::Unscoped)
                        || record.instance == other.instance)
            })
        })
        .cloned()
        .collect();
    let mut histories = Vec::new();
    for history in &admitted.histories {
        let collections = history
            .collections
            .iter()
            .filter(|collection| {
                !admitted.histories.iter().any(|other| {
                    other.collections.iter().any(|candidate| {
                        candidate.kind == collection.kind
                            && (other.owner != history.owner
                                || !same_collection(collection, candidate))
                    })
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        if !collections.is_empty() {
            histories.push(HistoryBinding {
                owner: history.owner.clone(),
                collections,
            });
        }
    }
    // Separate signed statements can repeat the same collection. Merge exact
    // copies before canonical_bindings applies its unique-kind invariant.
    let mut merged =
        std::collections::BTreeMap::<String, Vec<legacy::transform::Collection>>::new();
    for history in histories {
        let collections = merged.entry(history.owner).or_default();
        for collection in history.collections {
            if !collections
                .iter()
                .any(|old| same_collection(old, &collection))
            {
                collections.push(collection);
            }
        }
    }
    for collections in merged.values_mut() {
        loop {
            let retained = collections
                .iter()
                .filter(|collection| {
                    collection.parent.as_ref().is_none_or(|parent| {
                        collections.iter().any(|candidate| {
                            candidate.kind == *parent
                                && candidate.mode
                                    == busbar_kernel::persistence::import_target::records::history::HistoryMode::Upsert
                        })
                    })
                })
                .cloned()
                .collect::<Vec<_>>();
            if retained.len() == collections.len() {
                break;
            }
            *collections = retained;
        }
    }
    let tokens = admitted
        .tokens
        .iter()
        .filter(|token| {
            !admitted.tokens.iter().any(|other| {
                token.source_kind == other.source_kind
                    && (token.instance != other.instance || token.kind != other.kind)
            })
        })
        .cloned()
        .collect();
    let mut bindings = Bindings {
        records,
        histories: merged
            .into_iter()
            .filter(|(_, collections)| !collections.is_empty())
            .map(|(owner, collections)| HistoryBinding { owner, collections })
            .collect(),
        tokens,
    };
    canonical_bindings(&mut bindings, budget)?;
    Ok(bindings)
}
#[derive(Default)]
pub struct FrozenCapabilities {
    pub journal: Option<Arc<dyn legacy::journal_binding::JournalMigration>>,
    pub overlay: Option<Arc<legacy::overlay::PreparedOverlay>>,
    pub recovery: Option<Arc<legacy::recovery::FencedReceiptProofs>>,
}
pub struct PreparedRoute {
    reader: lifecycle::SourceReader,
    source: lifecycle::SourceIdentity,
    target_format: Format,
    bounds: Bounds,
    digest: Digest32,
    inspection_digest: Digest32,
    bindings: Bindings,
    inventory: Bindings,
    bindings_resolved: bool,
}
impl PreparedRoute {
    pub fn inspect(
        source: &lifecycle::SourceIdentity,
        catalogue: &[Table],
        bounds: Bounds,
        target_format: Format,
        reader: lifecycle::SourceReader,
    ) -> Result<Self, Error> {
        bounds.validate()?;
        if source.dataset.0 == [0; 16]
            || source.native_anchor == [0; 32]
            || source.catalogue_digest == [0; 32]
            || source.layout_digest == [0; 32]
            || target_format != CORE_FORMAT
            || catalogue.is_empty()
        {
            return Err(Error::IdentityMismatch);
        }
        let format = importer_format(source.format.ok_or(Error::UnsupportedPath)?)?;
        let mut hash = Sha256::new();
        field(&mut hash, b"busbar.native.prepared-route/1");
        field(&mut hash, &legacy::transform::code_digest());
        field(&mut hash, &reader.decoder_digest());
        field(
            &mut hash,
            &[match reader.documents() {
                lifecycle::DocumentSemantics::Historical => 0,
                lifecycle::DocumentSemantics::Current => 1,
            }],
        );
        field(&mut hash, &source.native_anchor);
        field(&mut hash, &source.dataset.0);
        field(&mut hash, &source.catalogue_digest);
        field(&mut hash, &source.layout_digest);
        field(&mut hash, &format.owner);
        field(&mut hash, &format.physical.to_le_bytes());
        field(&mut hash, &bounds.items.to_le_bytes());
        field(&mut hash, &bounds.bytes.to_le_bytes());
        field(&mut hash, &target_format.owner);
        field(&mut hash, &target_format.physical.to_le_bytes());
        field(&mut hash, &target_format.logical.to_le_bytes());
        field(&mut hash, &target_format.codec.to_le_bytes());
        for table in catalogue {
            field(&mut hash, table.name.as_bytes());
            for column in &table.columns {
                field(&mut hash, column.as_bytes());
            }
            field(&mut hash, &table.native_layout);
        }
        let digest = hash.finalize().into();
        Ok(Self {
            reader,
            source: source.clone(),
            target_format,
            bounds,
            digest,
            inspection_digest: digest,
            bindings: Bindings::default(),
            inventory: Bindings::default(),
            bindings_resolved: true,
        })
    }
    pub fn reader(&self) -> lifecycle::SourceReader {
        self.reader
    }
    pub fn with_bindings(mut self, mut bindings: Bindings) -> Result<Self, Error> {
        canonical_bindings(&mut bindings, self.bounds.bytes as usize)?;
        let mut hash = Sha256::new();
        field(&mut hash, &self.inspection_digest);
        legacy::transform::bind_config(
            &mut hash,
            &bindings.records,
            &bindings.histories,
            &bindings.tokens,
        );
        self.digest = hash.finalize().into();
        self.bindings = bindings;
        self.inventory = self.bindings.clone();
        self.bindings_resolved = true;
        Ok(self)
    }
    pub fn with_binding_inventory(
        mut self,
        mut admitted: DeclarationInventory,
    ) -> Result<Self, Error> {
        let mut normalized = admitted.bindings.clone();
        let resolved = canonical_bindings(&mut normalized, self.bounds.bytes as usize).is_ok();
        if !resolved {
            canonical_inventory(&mut admitted.bindings, self.bounds.bytes as usize)?;
        } else {
            admitted.bindings = normalized.clone();
        }
        admitted.statements.sort_by(|a, b| {
            (
                &a.owner,
                a.kind,
                a.kind_abi,
                a.layout_fingerprint,
                a.statement_sha256,
            )
                .cmp(&(
                    &b.owner,
                    b.kind,
                    b.kind_abi,
                    b.layout_fingerprint,
                    b.statement_sha256,
                ))
        });
        if admitted
            .statements
            .iter()
            .any(|s| s.owner.is_empty() || s.statement_sha256 == [0; 32])
            || (admitted.statements.is_empty()
                && (!admitted.bindings.records.is_empty()
                    || !admitted.bindings.histories.is_empty()
                    || !admitted.bindings.tokens.is_empty()))
        {
            return Err(Error::InvalidManifest);
        }
        let mut hash = Sha256::new();
        field(&mut hash, &self.inspection_digest);
        field(&mut hash, b"admitted-signed-declarations/1");
        for statement in &admitted.statements {
            field(&mut hash, statement.owner.as_bytes());
            field(&mut hash, &statement.statement_sha256);
            field(&mut hash, &statement.kind.to_le_bytes());
            field(&mut hash, &statement.kind_abi.to_le_bytes());
            field(&mut hash, &statement.layout_fingerprint.to_le_bytes());
        }
        legacy::transform::bind_config(
            &mut hash,
            &admitted.bindings.records,
            &admitted.bindings.histories,
            &admitted.bindings.tokens,
        );
        self.digest = hash.finalize().into();
        self.inventory = admitted.bindings;
        // Admission proves which declarations may be selected, not which
        // instances were enabled by the source configuration. Even a unique
        // declaration inventory must be resolved against that frozen overlay.
        self.bindings = Bindings::default();
        self.bindings_resolved = false;
        Ok(self)
    }
    pub fn resolve_frozen_bindings(mut self, mut effective: Bindings) -> Result<Self, Error> {
        canonical_bindings(&mut effective, self.bounds.bytes as usize)?;
        if !binding_subset(&effective, &self.inventory) {
            return Err(Error::IdentityMismatch);
        }
        self.bindings = effective;
        self.bindings_resolved = true;
        Ok(self)
    }
    pub fn resolved_bindings(&self) -> Result<&Bindings, Error> {
        if !self.bindings_resolved {
            return Err(Error::MissingCapability);
        }
        Ok(&self.bindings)
    }
    /// Pins compiled code and actual inspection facts for native Begin. Frozen
    /// snapshot preconditions are separately bound by the final edge below.
    pub fn descriptor_digest(&self) -> Digest32 {
        self.digest
    }
    pub fn target_format(&self) -> Format {
        self.target_format
    }
    pub fn source(&self) -> &lifecycle::SourceIdentity {
        &self.source
    }
    pub fn bindings(&self) -> &Bindings {
        &self.bindings
    }
    pub fn bind_frozen(
        self,
        source: &Identity,
        target: &Identity,
        catalogue: &[Table],
        projection: Arc<dyn ProjectionSource>,
        proofs: Arc<dyn NativeProofs>,
        capabilities: FrozenCapabilities,
    ) -> Result<BoundRoute, Error> {
        self.resolved_bindings()?;
        let actual = importer_format(self.source.format.ok_or(Error::UnsupportedPath)?)?;
        if source.dataset != self.source.dataset.0
            || source.format != actual
            || source.artifact_digest == [0; 32]
            || source.schema_digest == [0; 32]
            || target.format != self.target_format
            || target.dataset == [0; 16]
        {
            return Err(Error::IdentityMismatch);
        }
        let provenance = Provenance {
            dataset: source.dataset,
            catalogue: source.schema_digest,
        };
        let Bindings {
            records,
            histories,
            tokens,
        } = self.bindings;
        let FrozenCapabilities {
            journal,
            overlay,
            recovery,
        } = capabilities;
        let view = projection
            .fact_view()
            .ok_or(Error::MissingCapability)?
            .clone();
        if view.reader() != self.reader {
            return Err(Error::IdentityMismatch);
        }
        let mut compiled = legacy::fact_transform::FactTransform::registered(
            source.format,
            provenance,
            catalogue,
            view,
            Bindings {
                records,
                histories,
                tokens,
            },
            self.bounds,
        )?;
        if let Some(journal) = journal {
            compiled = compiled.with_journal(journal)?;
        }
        if let Some(overlay) = overlay {
            compiled = compiled.with_overlay(overlay)?;
        }
        if let Some(recovery) = recovery {
            compiled = compiled.with_recovery(recovery)?;
        }
        let compiled = compiled.with_projection(projection)?;
        let compiled = Arc::new(compiled);
        let registry = Registry::new(vec![compiled.edge().clone()])?;
        Ok(BoundRoute {
            registry,
            transform: compiled.clone(),
            readback: Arc::new(Readback { compiled, proofs }),
            prepared_digest: self.digest,
            target: target.clone(),
        })
    }
}
fn importer_format(actual: lifecycle::Format) -> Result<Format, Error> {
    if !matches!(actual.logical, 0 | 1) || actual.codec != 1 {
        return Err(Error::UnsupportedPath);
    }
    // Zero records absence of a historical logical envelope. The registered
    // importer discriminator starts at one and is never a source-data claim.
    Ok(Format {
        owner: actual.owner,
        physical: actual.physical,
        logical: 1,
        codec: 1,
    })
}
fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}
fn canonical_bindings(bindings: &mut Bindings, budget: usize) -> Result<(), Error> {
    use busbar_contract::records::{PlaneDisposition, PlaneRecordRef};
    use busbar_kernel::persistence::import_target::records::{history, scoped};
    use legacy::archive::Scope;
    let mut charge = 0usize;
    let mut admit = |parts: &[&str]| -> Result<(), Error> {
        charge = charge.checked_add(256).ok_or(Error::Bounds)?;
        for part in parts {
            charge = charge.checked_add(part.len()).ok_or(Error::Bounds)?;
        }
        if charge > budget {
            return Err(Error::Bounds);
        }
        Ok(())
    };
    for record in &bindings.records {
        admit(&[&record.schema, &record.instance])?;
        if record.schema.is_empty() || record.instance.is_empty() {
            return Err(Error::InvalidManifest);
        }
        scoped::migration_address(record.private, &record.instance, &record.schema, b"")
            .map_err(|_| Error::InvalidManifest)?;
    }
    bindings.records.sort_by(|a, b| {
        (
            &a.schema,
            &a.instance,
            a.private,
            matches!(a.source_scope, Scope::Instance),
        )
            .cmp(&(
                &b.schema,
                &b.instance,
                b.private,
                matches!(b.source_scope, Scope::Instance),
            ))
    });
    for (i, record) in bindings.records.iter().enumerate() {
        if bindings.records[..i].iter().any(|old| {
            old.schema == record.schema
                && (matches!(old.source_scope, Scope::Unscoped)
                    || matches!(record.source_scope, Scope::Unscoped)
                    || old.instance == record.instance)
        }) {
            return Err(Error::InvalidManifest);
        }
    }
    let mut owners =
        std::collections::BTreeMap::<String, Vec<legacy::transform::Collection>>::new();
    for binding in std::mem::take(&mut bindings.histories) {
        admit(&[&binding.owner])?;
        if binding.owner.is_empty() || binding.collections.is_empty() {
            return Err(Error::InvalidManifest);
        }
        for collection in &binding.collections {
            admit(&[&collection.kind, collection.parent.as_deref().unwrap_or("")])?;
        }
        owners
            .entry(binding.owner)
            .or_default()
            .extend(binding.collections);
    }
    let mut kinds = std::collections::BTreeSet::new();
    for (owner, mut collections) in owners {
        collections.sort_by(|a, b| a.kind.cmp(&b.kind));
        for collection in &collections {
            if collection.kind.is_empty() || !kinds.insert(collection.kind.clone()) {
                return Err(Error::InvalidManifest);
            }
        }
        let binding = HistoryBinding { owner, collections };
        for collection in &binding.collections {
            history::migration_rows(
                &binding.owner,
                binding.declarations(),
                PlaneRecordRef {
                    kind: &collection.kind,
                    id: "binding-validation",
                    parent: collection.parent.as_ref().map(|_| "binding-parent"),
                    seq: if collection.mode == history::HistoryMode::Append {
                        1
                    } else {
                        0
                    },
                    ts: 0,
                    disposition: PlaneDisposition::Active,
                    body: b"",
                },
                collection.parent.as_ref().map(|_| 1),
            )
            .map_err(|_| Error::InvalidManifest)?;
        }
        bindings.histories.push(binding);
    }
    bindings.tokens.sort_by(|a, b| {
        (&a.source_kind, &a.instance, &a.kind).cmp(&(&b.source_kind, &b.instance, &b.kind))
    });
    for (i, token) in bindings.tokens.iter().enumerate() {
        admit(&[&token.source_kind, &token.instance, &token.kind])?;
        if token.source_kind.is_empty()
            || token.instance.is_empty()
            || token.kind.is_empty()
            || bindings.tokens[..i]
                .iter()
                .any(|old| old.source_kind == token.source_kind)
        {
            return Err(Error::InvalidManifest);
        }
        if token.source_kind == "auth-replay"
            && (token.instance != "busbar.auth-replay" || token.kind != "auth-replay")
        {
            return Err(Error::InvalidManifest);
        }
        if token.source_kind == "busbar.admin-idempotency"
            && (token.instance != "busbar.admin" || token.kind != "busbar.admin-idempotency")
        {
            return Err(Error::InvalidManifest);
        }
        scoped::migration_claim_rows(&token.instance, &token.kind, "binding-validation", 1)
            .map_err(|_| Error::InvalidManifest)?;
    }
    Ok(())
}
fn same_record(a: &RecordBinding, b: &RecordBinding) -> bool {
    a.schema == b.schema
        && a.instance == b.instance
        && a.private == b.private
        && matches!(a.source_scope, legacy::archive::Scope::Instance)
            == matches!(b.source_scope, legacy::archive::Scope::Instance)
}
fn same_collection(a: &legacy::transform::Collection, b: &legacy::transform::Collection) -> bool {
    a.kind == b.kind
        && a.mode == b.mode
        && a.retention.code() == b.retention.code()
        && a.parent == b.parent
}
fn canonical_inventory(bindings: &mut Bindings, budget: usize) -> Result<(), Error> {
    let mut charge = 0usize;
    for record in &bindings.records {
        charge = charge
            .checked_add(record.schema.len())
            .and_then(|v| v.checked_add(record.instance.len() + 256))
            .ok_or(Error::Bounds)?;
        canonical_bindings(
            &mut Bindings {
                records: vec![record.clone()],
                ..Bindings::default()
            },
            budget,
        )?;
    }
    for history in &bindings.histories {
        charge = charge
            .checked_add(history.owner.len() + 256)
            .ok_or(Error::Bounds)?;
        for c in &history.collections {
            charge = charge
                .checked_add(c.kind.len())
                .and_then(|v| v.checked_add(c.parent.as_ref().map_or(0, String::len) + 256))
                .ok_or(Error::Bounds)?;
        }
        canonical_bindings(
            &mut Bindings {
                histories: vec![history.clone()],
                ..Bindings::default()
            },
            budget,
        )?;
    }
    for token in &bindings.tokens {
        charge = charge
            .checked_add(token.source_kind.len())
            .and_then(|v| v.checked_add(token.instance.len()))
            .and_then(|v| v.checked_add(token.kind.len() + 256))
            .ok_or(Error::Bounds)?;
        canonical_bindings(
            &mut Bindings {
                tokens: vec![token.clone()],
                ..Bindings::default()
            },
            budget,
        )?;
    }
    if charge > budget {
        return Err(Error::Bounds);
    }
    bindings.records.sort_by(|a, b| {
        (
            &a.schema,
            &a.instance,
            a.private,
            matches!(a.source_scope, legacy::archive::Scope::Instance),
        )
            .cmp(&(
                &b.schema,
                &b.instance,
                b.private,
                matches!(b.source_scope, legacy::archive::Scope::Instance),
            ))
    });
    bindings.records.dedup_by(|a, b| same_record(a, b));
    for history in &mut bindings.histories {
        history.collections.sort_by(|a,b|(&a.kind,a.mode==busbar_kernel::persistence::import_target::records::history::HistoryMode::Append,a.retention.code(),&a.parent).cmp(&(&b.kind,b.mode==busbar_kernel::persistence::import_target::records::history::HistoryMode::Append,b.retention.code(),&b.parent)));
    }
    bindings.histories.sort_by(|a, b| {
        let owner = a.owner.cmp(&b.owner);
        if owner != std::cmp::Ordering::Equal {
            return owner;
        }
        let digest = |h: &HistoryBinding| {
            let mut hash = Sha256::new();
            legacy::transform::bind_config(&mut hash, &[], std::slice::from_ref(h), &[]);
            <[u8; 32]>::from(hash.finalize())
        };
        digest(a).cmp(&digest(b))
    });
    bindings.histories.dedup_by(|a, b| {
        a.owner == b.owner
            && a.collections.len() == b.collections.len()
            && a.collections
                .iter()
                .zip(&b.collections)
                .all(|(a, b)| same_collection(a, b))
    });
    bindings.tokens.sort_by(|a, b| {
        (&a.source_kind, &a.instance, &a.kind).cmp(&(&b.source_kind, &b.instance, &b.kind))
    });
    bindings.tokens.dedup_by(|a, b| {
        a.source_kind == b.source_kind && a.instance == b.instance && a.kind == b.kind
    });
    Ok(())
}
fn binding_subset(effective: &Bindings, inventory: &Bindings) -> bool {
    effective
        .records
        .iter()
        .all(|record| inventory.records.iter().any(|old| same_record(record, old)))
        && effective.tokens.iter().all(|token| {
            inventory.tokens.iter().any(|old| {
                old.source_kind == token.source_kind
                    && old.instance == token.instance
                    && old.kind == token.kind
            })
        })
        && effective.histories.iter().all(|history| {
            history.collections.iter().all(|collection| {
                inventory.histories.iter().any(|old| {
                    old.owner == history.owner
                        && old
                            .collections
                            .iter()
                            .any(|c| same_collection(collection, c))
                })
            })
        })
}
struct Readback {
    compiled: Arc<legacy::fact_transform::FactTransform>,
    proofs: Arc<dyn NativeProofs>,
}
impl NativeReadback for Readback {
    fn edge(&self) -> &Edge {
        self.compiled.edge()
    }
    fn verify(
        &self,
        source: &Identity,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        native: &[(Address, Secret<Vec<u8>>)],
    ) -> Result<Digest32, Error> {
        let proof = self.compiled.verify_page(
            source,
            family,
            records,
            bounds,
            native,
            self.proofs.as_ref(),
        )?;
        Ok(proof.semantics_digest)
    }
}
pub struct BoundRoute {
    pub target: Identity,
    pub registry: Registry,
    pub transform: Arc<dyn Transform>,
    pub readback: Arc<dyn NativeReadback>,
    pub prepared_digest: Digest32,
}

/// Extract and verify the complete admitted logical audit inventory.
pub fn proofs_from_facts(
    format: Format,
    provenance: Provenance,
    source: &mut dyn crate::archive_source::ArchiveRows,
    semantic_bytes: usize,
    ancestry: Option<Arc<dyn NativeProofs>>,
) -> Result<Arc<dyn NativeProofs>, Error> {
    if source.header().owner != format.owner
        || source.header().physical != format.physical
        || semantic_bytes == 0
    {
        return Err(Error::IdentityMismatch);
    }
    let mut audit = Vec::new();
    let mut charge = 0usize;
    crate::source_facts::visit(source, semantic_bytes, &mut |_, fact| {
        if let busbar_contract::persistence::lifecycle::source::HistoricalFact::Audit(record) =
            fact.fact()
        {
            let size = [
                &record.action,
                &record.resource,
                &record.outcome,
                &record.principal,
                &record.prev_hash,
                &record.hash,
            ]
            .iter()
            .try_fold(std::mem::size_of_val(record), |n, s| n.checked_add(s.len()))
            .ok_or(Error::Bounds)?;
            charge = charge.checked_add(size).ok_or(Error::Bounds)?;
            if charge > semantic_bytes {
                return Err(Error::Bounds);
            }
            audit.try_reserve_exact(1).map_err(|_| Error::Bounds)?;
            audit.push(record.clone());
        }
        Ok(())
    })?;
    let count = u64::try_from(audit.len()).map_err(|_| Error::Bounds)?;
    let audit =
        legacy::transform::CompleteAuditProofs::from_complete_facts(provenance, audit, count)?;
    Ok(Arc::new(FrozenProofs {
        audit: Arc::new(audit),
        ancestry,
    }))
}
pub fn with_ancestry(
    audit: Arc<dyn NativeProofs>,
    ancestry: Arc<dyn NativeProofs>,
) -> Arc<dyn NativeProofs> {
    Arc::new(FrozenProofs {
        audit,
        ancestry: Some(ancestry),
    })
}
struct FrozenProofs {
    audit: Arc<dyn NativeProofs>,
    ancestry: Option<Arc<dyn NativeProofs>>,
}
impl legacy::archive::HistoricalReceiptResolution for FrozenProofs {
    fn resolve_original(
        &self,
        provenance: Provenance,
        address: &Address,
        receipt: &legacy::archive::Receipt<'_>,
    ) -> Result<Digest32, Error> {
        self.ancestry
            .as_deref()
            .ok_or(Error::ReconciliationRequired)?
            .resolve_original(provenance, address, receipt)
    }
}
impl NativeProofs for FrozenProofs {
    fn parent_present(
        &self,
        provenance: Provenance,
        owner: &str,
        kind: &str,
        id: &str,
    ) -> Result<Digest32, Error> {
        match self.audit.parent_present(provenance, owner, kind, id) {
            Err(Error::MissingCapability) => self
                .ancestry
                .as_deref()
                .ok_or(Error::MissingCapability)?
                .parent_present(provenance, owner, kind, id),
            result => result,
        }
    }
    fn historical_audit(
        &self,
        provenance: Provenance,
        record: &busbar_contract::records::AuditRecord,
    ) -> Result<Digest32, Error> {
        self.audit.historical_audit(provenance, record)
    }
}

#[cfg(test)]
mod binding_tests {
    use super::*;

    fn collection(kind: &str) -> legacy::transform::Collection {
        legacy::transform::Collection {
            kind: kind.into(),
            mode: busbar_kernel::persistence::import_target::records::history::HistoryMode::Upsert,
            retention: busbar_contract::records::Retention::default(),
            parent: None,
        }
    }

    fn competing_inventory() -> DeclarationInventory {
        let mut inventory = inventory();
        inventory.bindings.tokens = ["dormant", "enabled"]
            .into_iter()
            .map(|owner| TokenBinding {
                source_kind: "shared".into(),
                instance: owner.into(),
                kind: "shared".into(),
            })
            .collect();
        inventory.bindings.histories = ["dormant", "enabled"]
            .into_iter()
            .map(|owner| HistoryBinding {
                owner: owner.into(),
                collections: vec![collection("shared")],
            })
            .collect();
        inventory
    }

    fn route() -> PreparedRoute {
        PreparedRoute::inspect(
            &lifecycle::SourceIdentity {
                native_anchor: [1; 32],
                dataset: busbar_contract::persistence::DatasetId([2; 16]),
                format: Some(lifecycle::Format {
                    owner: *b"fixture.source01",
                    physical: 6,
                    logical: 1,
                    codec: 1,
                }),
                catalogue_digest: [3; 32],
                layout_digest: [4; 32],
            },
            &[Table {
                name: "records".into(),
                columns: vec!["value".into()],
                native_layout: vec![1],
            }],
            Bounds {
                items: 16,
                bytes: 65536,
            },
            CORE_FORMAT,
            lifecycle::SourceReader::new(
                lifecycle::SourceCodec::HistoricalV1,
                lifecycle::DocumentSemantics::Historical,
                [8; 32],
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn inventory() -> DeclarationInventory {
        DeclarationInventory {
            bindings: Bindings {
                tokens: vec![TokenBinding {
                    source_kind: "example-token".into(),
                    instance: "example".into(),
                    kind: "token".into(),
                }],
                ..Bindings::default()
            },
            statements: vec![AdmittedStatement {
                owner: "example".into(),
                statement_sha256: [5; 32],
                kind: 1,
                kind_abi: 1,
                layout_fingerprint: 1,
            }],
        }
    }

    #[test]
    fn unique_inventory_still_requires_explicit_resolution() {
        let route = route().with_binding_inventory(inventory()).unwrap();
        assert!(matches!(
            route.resolved_bindings(),
            Err(Error::MissingCapability)
        ));
        // Inventory admission alone cannot select a scope. The trusted
        // resolver must explicitly provide even an otherwise unique mapping.
        let route = route.resolve_frozen_bindings(Bindings::default()).unwrap();
        assert!(route.resolved_bindings().unwrap().tokens.is_empty());
    }

    #[test]
    fn frozen_configuration_cannot_select_an_unadmitted_declaration() {
        let mut effective = inventory().bindings;
        effective.tokens[0].instance = "unadmitted".into();
        assert!(matches!(
            route()
                .with_binding_inventory(inventory())
                .unwrap()
                .resolve_frozen_bindings(effective),
            Err(Error::IdentityMismatch)
        ));
    }

    #[test]
    fn dormant_owner_records_and_unique_claims_survive_without_configuration_selection() {
        let mut inventory = inventory();
        inventory.bindings.tokens[0].instance = "dormant".into();
        inventory.bindings.histories.push(HistoryBinding {
            owner: "dormant".into(),
            collections: vec![collection("history")],
        });
        inventory.bindings.records = ["dormant", "enabled"]
            .into_iter()
            .map(|instance| RecordBinding {
                schema: "shared".into(),
                instance: instance.into(),
                private: false,
                source_scope: legacy::archive::Scope::Instance,
            })
            .collect();
        let bindings = dormant_safe_bindings(&inventory, 65536).unwrap();
        assert_eq!(bindings.tokens[0].instance, "dormant");
        assert_eq!(bindings.histories[0].owner, "dormant");
        let mapped = bindings
            .records
            .iter()
            .map(|r| legacy::archive::Binding {
                schema: &r.schema,
                instance: &r.instance,
                private: r.private,
                source_scope: r.source_scope,
            })
            .collect::<Vec<_>>();
        let mut key = ("dormant".len() as u16).to_be_bytes().to_vec();
        key.extend_from_slice(b"dormant");
        key.extend_from_slice(b"id");
        let legacy::archive::Route::Record { address, .. } =
            legacy::archive::route_record("shared", &key, b"body", &mapped).unwrap()
        else {
            panic!("dormant record lost its source binding")
        };
        assert_eq!(
            address,
            busbar_kernel::persistence::import_target::records::scoped::migration_address(
                false, "dormant", "shared", b"id"
            )
            .unwrap()
        );
    }

    #[test]
    fn unused_competing_declarations_do_not_block_route_and_exact_duplicates_collapse() {
        let admitted = competing_inventory();
        let bindings = dormant_safe_bindings(&admitted, 65536).unwrap();
        assert!(bindings.histories.is_empty());
        assert!(bindings.tokens.is_empty());
        route()
            .with_binding_inventory(admitted)
            .unwrap()
            .resolve_frozen_bindings(bindings)
            .unwrap();
        let mut inventory = inventory();
        inventory.bindings.histories = vec![
            HistoryBinding {
                owner: "example".into(),
                collections: vec![collection("history")]
            };
            2
        ];
        inventory
            .bindings
            .tokens
            .push(inventory.bindings.tokens[0].clone());
        let bindings = dormant_safe_bindings(&inventory, 65536).unwrap();
        assert_eq!(bindings.histories.len(), 1);
        assert_eq!(bindings.histories[0].collections.len(), 1);
        assert_eq!(bindings.tokens.len(), 1);
        let mut different = collection("history");
        different.mode =
            busbar_kernel::persistence::import_target::records::history::HistoryMode::Append;
        inventory.bindings.histories.push(HistoryBinding {
            owner: "example".into(),
            collections: vec![different],
        });
        assert!(dormant_safe_bindings(&inventory, 65536)
            .unwrap()
            .histories
            .is_empty());
    }

    #[tokio::test]
    async fn actual_token_fact_with_ambiguous_historical_owner_refuses() {
        let bindings = dormant_safe_bindings(&competing_inventory(), 65536).unwrap();
        let source = crate::source_facts::test_archive(
            vec![lifecycle::source::HistoricalFact::Token {
                kind: "shared".into(),
                token: Secret::new(b"spent".to_vec()),
                expires_at: 6000,
            }],
            65536,
        );
        let identity = source.identity();
        let bounds = Bounds {
            items: 16,
            bytes: 65536,
        };
        let transform = legacy::fact_transform::FactTransform::registered(
            identity.format,
            Provenance {
                dataset: identity.dataset,
                catalogue: source.header().catalogue_digest,
            },
            &source.header().tables,
            source.interpretation().unwrap().clone(),
            bindings,
            bounds,
        )
        .unwrap()
        .with_projection(source.clone())
        .unwrap();
        let family = transform
            .edge()
            .families
            .iter()
            .find(|family| family.id == legacy::transform::ARCHIVAL)
            .unwrap();
        let page = source
            .page(&source.snapshot(), family, 0, bounds)
            .await
            .unwrap();
        assert!(matches!(
            transform.transform(family, &page.records, bounds),
            Err(Error::MissingCapability)
        ));
    }
    #[test]
    fn exact_reader_identity_pins_resume_descriptor() {
        let first = route();
        let same = route();
        assert_eq!(first.descriptor_digest(), same.descriptor_digest());
        let changed = PreparedRoute::inspect(
            first.source(),
            &[Table {
                name: "records".into(),
                columns: vec!["value".into()],
                native_layout: vec![1],
            }],
            Bounds {
                items: 16,
                bytes: 65536,
            },
            CORE_FORMAT,
            lifecycle::SourceReader::new(
                lifecycle::SourceCodec::HistoricalV1,
                lifecycle::DocumentSemantics::Historical,
                [9; 32],
            )
            .unwrap(),
        )
        .unwrap();
        assert_ne!(first.descriptor_digest(), changed.descriptor_digest());
    }
}
