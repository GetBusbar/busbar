// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Registered Valkey importer over complete protected six-cell native groups.
use super::super::{Bounds, Edge, Family, Identity, Record, Registry, TargetRow, Transform};
use super::transform::{
    self, HistoryBinding, NativeProofs, Output, PageVerification, RecordBinding, TokenBinding,
    ACCOUNTING, ARCHIVAL, AUDIT, IDENTITY,
};
use super::*;
use busbar_contract::{
    persistence::Address,
    records::{CredentialSecret, PlaneRecordRef},
    Secret,
};
use busbar_kernel::persistence::import_target::records::history::HistoryMode;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use valkey::{PhysicalCell, PhysicalKind as Kind};
fn fail(error: Error) -> super::super::Error {
    match error {
        Error::Range => super::super::Error::Bounds,
        Error::Unsupported => super::super::Error::UnsupportedPath,
        _ => super::super::Error::Corrupt,
    }
}
fn text(bytes: &[u8]) -> Result<&str, super::super::Error> {
    std::str::from_utf8(bytes).map_err(|_| super::super::Error::Corrupt)
}
fn integer(bytes: &[u8]) -> Result<u64, super::super::Error> {
    text(bytes)?
        .parse()
        .map_err(|_| super::super::Error::Corrupt)
}
type ParsedValkeyRow<'a> = (Secret<Vec<u8>>, PhysicalCell<'a>);

pub struct ValkeyTransform {
    edge: Edge,
    provenance: archive::Provenance,
    layout: valkey::NativeLayout,
    records: Vec<RecordBinding>,
    histories: Vec<HistoryBinding>,
    tokens: Vec<TokenBinding>,
    journal: Option<std::sync::Arc<dyn super::journal_binding::JournalMigration>>,
    projection: Option<std::sync::Arc<dyn super::projection::ProjectionSource>>,
    recovery: Option<std::sync::Arc<super::recovery::FencedReceiptProofs>>,
    overlay: Option<std::sync::Arc<super::overlay::PreparedOverlay>>,
}
impl ValkeyTransform {
    pub fn registered(
        provenance: archive::Provenance,
        native_layout: &[u8],
        records: Vec<RecordBinding>,
        histories: Vec<HistoryBinding>,
        tokens: Vec<TokenBinding>,
        bounds: Bounds,
    ) -> Result<Self, super::super::Error> {
        bounds.validate()?;
        let layout = valkey::NativeLayout::decode(native_layout).map_err(fail)?;
        if provenance.dataset == [0; 16] || provenance.catalogue == [0; 32] {
            return Err(super::super::Error::IdentityMismatch);
        }
        let mut kinds = BTreeSet::new();
        for h in &histories {
            for c in &h.collections {
                if !kinds.insert(c.kind.as_str()) {
                    return Err(super::super::Error::InvalidManifest);
                }
            }
        }
        let mut hash = Sha256::new();
        transform::hash_field(&mut hash, &provenance.catalogue);
        transform::hash_field(&mut hash, native_layout);
        transform::bind_config(&mut hash, &records, &histories, &tokens);
        let source = layout.importer_format();
        let families = [
            (super::projection::PHYSICAL, super::projection::PHYSICAL),
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
        ]
        .into_iter()
        .map(|(id, target_namespace)| Family {
            id,
            source_schema: source.physical,
            target_schema: 1,
            target_namespace,
        })
        .collect();
        let edge = transform::registered_edge(source, hash.finalize().into(), families, bounds)?;
        Ok(Self {
            edge,
            provenance,
            layout,
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
        transform::hash_field(&mut hash, &self.edge.preconditions_digest);
        transform::hash_field(&mut hash, &plan.descriptor_digest());
        self.edge = transform::registered_edge(
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
    pub fn descriptor(&self) -> &Edge {
        &self.edge
    }
    pub fn matches_source(&self, source: &Identity) -> bool {
        source.dataset == self.provenance.dataset
            && source.schema_digest == self.provenance.catalogue
            && source.format == self.edge.source
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
        family: &Family,
        records: &'a [Record],
        bounds: Bounds,
    ) -> Result<Vec<ParsedValkeyRow<'a>>, super::super::Error> {
        if !self.edge.families.contains(family) || records.len() > bounds.items as usize {
            return Err(super::super::Error::EdgeMismatch);
        }
        let mut bytes = 0usize;
        let mut seen = BTreeSet::new();
        let mut cells = Vec::new();
        cells
            .try_reserve_exact(records.len())
            .map_err(|_| super::super::Error::Bounds)?;
        for record in records {
            bytes = bytes
                .checked_add(record.key.len())
                .and_then(|n| n.checked_add(record.value.expose(&crate::seal::lend()).len()))
                .ok_or(super::super::Error::Bounds)?;
            if bytes > bounds.bytes as usize || !seen.insert(record.key.as_slice()) {
                return Err(super::super::Error::Bounds);
            }
            let (table, key) = transform::source_parts(&record.key).map_err(fail)?;
            let row = Row::decode(record.value.expose(&crate::seal::lend()))
                .map_err(|_| super::super::Error::Corrupt)?;
            let group = group::valkey_row_class_and_group(
                self.layout.profile,
                self.layout.source_db,
                table,
                valkey::NATIVE_COLUMNS,
                key,
                row,
            )
            .map_err(fail)?;
            if group.family != family.id {
                return Err(super::super::Error::EdgeMismatch);
            }
            cells.push((group.key, valkey::physical(row).map_err(fail)?));
        }
        Ok(cells)
    }
    fn emit_plane(
        &self,
        out: &mut Output,
        record: PlaneRecordRef<'_>,
        position_identity: &str,
    ) -> Result<(), super::super::Error> {
        if matches!(record.kind, "demotion" | "trust_decision") {
            if record.seq != 0 || record.id != position_identity || record.parent.is_some() {
                return Err(super::super::Error::Verification);
            }
            return out.canonical(
                vec![busbar_kernel::persistence::import_target::records::trust::migration_trust_rows(
                    record.kind,
                    record.id,
                    record.body,
                )
                .map_err(|_| super::super::Error::Corrupt)?],
                false,
            );
        }
        if record.kind == "ticket" {
            if record.seq != 0
                || record.id != position_identity
                || record.parent.is_some()
                || record.disposition != busbar_contract::records::PlaneDisposition::Active
            {
                return Err(super::super::Error::Verification);
            }
            out.canonical(
                vec![
                    busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_record(record.id, record.ts, record.body)
                        .map_err(|_| super::super::Error::Corrupt)?,
                    busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_expiry(record.id, record.ts)
                        .map_err(|_| super::super::Error::Corrupt)?,
                ],
                false,
            )?;
            return Ok(());
        }
        if record.kind == "busbar.admin-idempotency" {
            if record.seq != 0 || record.id != position_identity || record.parent.is_some() {
                return Err(super::super::Error::Verification);
            }
            let address =
                busbar_kernel::persistence::import_target::records::scoped::migration_address(
                    true,
                    "busbar.admin",
                    record.kind,
                    record.id.as_bytes(),
                )
                .map_err(|_| super::super::Error::Corrupt)?;
            return out.put(address, Secret::new(record.body.to_vec()), None, false);
        }
        let binding = self
            .history(record.kind)
            .ok_or(super::super::Error::MissingCapability)?;
        let declaration = binding
            .collections
            .iter()
            .find(|c| c.kind == record.kind)
            .ok_or(super::super::Error::MissingCapability)?;
        let expected = if declaration.mode == HistoryMode::Upsert {
            if record.seq != 0 {
                return Err(super::super::Error::Verification);
            }
            record.id
        } else {
            record.parent.unwrap_or(record.id)
        };
        if expected != position_identity {
            return Err(super::super::Error::Verification);
        }
        let rows = busbar_kernel::persistence::import_target::records::history::migration_rows(
            &binding.owner,
            binding.declarations(),
            record,
            declaration.parent.as_ref().map(|_| 1),
        )
        .map_err(|_| super::super::Error::Verification)?;
        for (i, (address, value)) in rows.into_iter().enumerate() {
            out.put(address, value, None, i < 2)?;
        }
        Ok(())
    }
    fn claim(
        &self,
        out: &mut Output,
        kind: &str,
        token: &str,
        expires_at: u64,
    ) -> Result<(), super::super::Error> {
        if kind == "ticket-spent" {
            return out.canonical(
                vec![
                    busbar_kernel::persistence::import_target::records::ticket::legacy_ticket_token(kind, token, expires_at)
                        .map_err(|_| super::super::Error::Corrupt)?,
                ],
                false,
            );
        }
        let builtin = match kind {
            "busbar.admin-idempotency" => Some(("busbar.admin", kind)),
            "auth-replay" => Some(("busbar.auth-replay", kind)),
            _ => None,
        };
        let mut bindings = self.tokens.iter().filter(|b| b.source_kind == kind);
        let binding = bindings.next();
        if bindings.next().is_some() {
            return Err(super::super::Error::Verification);
        }
        let (instance, kind) = if let Some(v) = builtin {
            v
        } else {
            let b = binding.ok_or(super::super::Error::MissingCapability)?;
            (&*b.instance, &*b.kind)
        };
        out.canonical(
            busbar_kernel::persistence::import_target::records::scoped::migration_claim_rows(
                instance, kind, token, expires_at,
            )
            .map_err(|_| super::super::Error::Corrupt)?,
            false,
        )
    }
}
struct Group<'a> {
    key: Secret<Vec<u8>>,
    cells: Vec<PhysicalCell<'a>>,
}
fn groups<'a>(mut tagged: Vec<(Secret<Vec<u8>>, PhysicalCell<'a>)>) -> Vec<Group<'a>> {
    let seal = crate::seal::lend();
    tagged.sort_by(|a, b| a.0.expose(&seal).cmp(b.0.expose(&seal)));
    let mut out: Vec<Group<'a>> = Vec::new();
    for (key, cell) in tagged {
        if let Some(last) = out.last_mut() {
            if last.key == key {
                last.cells.push(cell);
                continue;
            }
        }
        out.push(Group {
            key,
            cells: vec![cell],
        });
    }
    out
}
fn physical_groups<'a>(cells: &[PhysicalCell<'a>]) -> BTreeMap<&'a [u8], Vec<PhysicalCell<'a>>> {
    let mut out = BTreeMap::<&[u8], Vec<PhysicalCell<'a>>>::new();
    for cell in cells {
        out.entry(cell.key).or_default().push(*cell);
    }
    out
}
fn complete<'a>(
    cells: &[PhysicalCell<'a>],
    bounds: Bounds,
) -> Result<valkey::CompleteGroup<'a>, super::super::Error> {
    valkey::complete_group(cells, bounds.items as usize, bounds.bytes as usize).map_err(fail)
}

impl Transform for ValkeyTransform {
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
            return parts[0] == self.provenance.dataset
                && parts[1] == self.provenance.catalogue
                && parts[2] == b"valkey";
        }
        match family.id {
            IDENTITY => busbar_kernel::persistence::import_target::records::identity::migration_authorizes(address),
            ACCOUNTING => busbar_kernel::persistence::import_target::records::ledger::migration_authorizes(address),
            AUDIT => busbar_kernel::persistence::import_target::records::history::migration_audit_authorizes(
                busbar_kernel::persistence::import_target::records::AUDIT_OWNER,
                address,
            ),
            ARCHIVAL => transform::archival_authorizes(
                &self.records,
                &self.histories,
                &self.tokens,
                address,
            ),
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
                            &super::projection::materialize(frozen, family.id, marker, bounds)?,
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

impl ValkeyTransform {
    fn transform_impl(
        &self,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        retain_physical: bool,
    ) -> Result<Vec<TargetRow>, super::super::Error> {
        if family.id == super::projection::PHYSICAL {
            if !self.edge.families.contains(family) {
                return Err(super::super::Error::EdgeMismatch);
            }
            return super::projection::physical_rows(
                self.provenance,
                records,
                bounds,
                |table, key, row| {
                    group::valkey_row_class_and_group(
                        self.layout.profile,
                        self.layout.source_db,
                        table,
                        valkey::NATIVE_COLUMNS,
                        key,
                        row,
                    )
                    .map(|_| ())
                    .map_err(fail)
                },
            );
        }
        let cells = self.parsed(family, records, bounds)?;
        let mut out = Output::new(bounds);
        if retain_physical {
            for (index, record) in records.iter().enumerate() {
                let (_, key) = transform::source_parts(&record.key).map_err(fail)?;
                let address = Address {
                    namespace: archive::NAMESPACE.0,
                    key: busbar_kernel::persistence::import_target::records::keys::framed(
                        b'E',
                        &[
                            &self.provenance.dataset,
                            &self.provenance.catalogue,
                            b"valkey",
                            key,
                        ],
                    )
                    .map_err(|_| super::super::Error::Bounds)?,
                };
                out.put(
                    address,
                    Secret::new(record.value.expose(&crate::seal::lend()).clone()),
                    Some(index.try_into().map_err(|_| super::super::Error::Bounds)?),
                    false,
                )?;
            }
        }
        for group in groups(cells) {
            match family.id {
                IDENTITY => self.identity(&mut out, &group.cells, bounds)?,
                ACCOUNTING => self.accounting(&mut out, &group.cells, bounds)?,
                AUDIT => {
                    for cell in &group.cells {
                        if cell.kind != Kind::SortedSet
                            || cell.key != b"busbar:audit"
                            || cell.expires_at_ms.is_some()
                        {
                            return Err(super::super::Error::Corrupt);
                        }
                        let record = valkey::audit(cell.position).map_err(fail)?;
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
                ARCHIVAL => self.archival(&mut out, &group.cells, bounds)?,
                _ => return Err(super::super::Error::UnsupportedPath),
            }
        }
        Ok(out.finish())
    }
}

impl ValkeyTransform {
    fn identity(
        &self,
        out: &mut Output,
        cells: &[PhysicalCell<'_>],
        bounds: Bounds,
    ) -> Result<(), super::super::Error> {
        if cells
            .iter()
            .any(|c| c.database != self.layout.source_db || c.expires_at_ms.is_some())
        {
            return Err(super::super::Error::Verification);
        }
        let by_key = physical_groups(cells);
        if let Some(raw) = by_key.get(b"busbar:revision".as_slice()) {
            if by_key.len() != 1 {
                return Err(super::super::Error::Verification);
            }
            let group = complete(raw, bounds)?;
            if group.header.value != b"string" {
                return Err(super::super::Error::Corrupt);
            }
            return out.canonical(
                canonical_identity(&HistoricalRow::Revision(integer(group.values[0].1)?), false)
                    .map_err(fail)?,
                false,
            );
        }
        let mut denied = None;
        let mut denied_member = None;
        for (key, raw) in &by_key {
            if let Some(subject) = text(key)?.strip_prefix("busbar:denylist:") {
                let group = complete(raw, bounds)?;
                if group.header.value != b"string"
                    || denied
                        .replace((subject, text(group.values[0].1)?))
                        .is_some()
                {
                    return Err(super::super::Error::Verification);
                }
            } else if *key == b"busbar:denylist" {
                for cell in raw {
                    if cell.kind != Kind::Set
                        || denied_member.replace(text(cell.position)?).is_some()
                    {
                        return Err(super::super::Error::Verification);
                    }
                }
            }
        }
        if denied.is_some() || denied_member.is_some() {
            let (subject, reason) = denied.ok_or(super::super::Error::Verification)?;
            if denied_member != Some(subject) || by_key.len() != 2 {
                return Err(super::super::Error::Verification);
            }
            // Valkey stored no creation instant for a denial. Canonical zero is
            // the explicit unstamped legacy discriminator, not an invented time.
            return out.canonical(
                canonical_identity(
                    &HistoricalRow::Denied {
                        subject: subject.to_owned(),
                        reason: reason.to_owned(),
                        created_at: 0,
                    },
                    false,
                )
                .map_err(fail)?,
                false,
            );
        }
        let mut owner = None;
        let mut credentials = Vec::<CredentialSecret>::new();
        let mut key_member = None;
        let mut key_revision = None;
        let mut slots = BTreeSet::new();
        let mut ids = BTreeMap::new();
        let mut publics = BTreeMap::new();
        let mut revisions = BTreeSet::new();
        for (raw_key, raw) in &by_key {
            let key = text(raw_key)?;
            if let Some(id) = key.strip_prefix("busbar:key:") {
                let group = complete(raw, bounds)?;
                if group.header.value != b"string" || owner.is_some() {
                    return Err(super::super::Error::Verification);
                }
                owner =
                    Some(valkey::key(self.layout.profile, id, group.values[0].1).map_err(fail)?);
            } else if key == "busbar:keys" {
                for cell in raw {
                    if cell.kind != Kind::Set || key_member.replace(text(cell.position)?).is_some()
                    {
                        return Err(super::super::Error::Verification);
                    }
                }
            } else if key == "busbar:keys:byrev" {
                for cell in raw {
                    if cell.kind != Kind::SortedSet
                        || key_revision.replace(text(cell.position)?).is_some()
                    {
                        return Err(super::super::Error::Verification);
                    }
                }
            } else if key == "busbar:creds:byrev" {
                for cell in raw {
                    if cell.kind != Kind::SortedSet || !revisions.insert(text(cell.position)?) {
                        return Err(super::super::Error::Verification);
                    }
                }
            } else if key.starts_with("busbar:cred:ids:") {
                let group = complete(raw, bounds)?;
                if group.header.value != b"set" {
                    return Err(super::super::Error::Verification);
                }
                for (slot, _) in group.values {
                    if !slots.insert(text(slot)?) {
                        return Err(super::super::Error::Verification);
                    }
                }
            } else if let Some(id) = key.strip_prefix("busbar:cred:id:") {
                for cell in raw {
                    if cell.kind != Kind::String || ids.insert(id, cell.value).is_some() {
                        return Err(super::super::Error::Verification);
                    }
                }
            } else if key.starts_with("busbar:cred:pub:") {
                for cell in raw {
                    if cell.kind != Kind::String || publics.insert(key, cell.value).is_some() {
                        return Err(super::super::Error::Verification);
                    }
                }
            } else if let Some(pointer) = key.strip_prefix("busbar:cred:") {
                let (id, kind, slot) = valkey::pointer(pointer.as_bytes()).map_err(fail)?;
                let group = complete(raw, bounds)?;
                if group.header.value != b"string" {
                    return Err(super::super::Error::Corrupt);
                }
                credentials.push(
                    valkey::credential(self.layout.profile, id, kind, slot, group.values[0].1)
                        .map_err(fail)?,
                );
            } else {
                return Err(super::super::Error::UnsupportedPath);
            }
        }
        let owner = owner.ok_or(super::super::Error::Verification)?;
        if key_member != Some(owner.id.as_str())
            || key_revision.is_some_and(|id| id != owner.id)
            || owner.revision != 0 && key_revision.is_none()
        {
            return Err(super::super::Error::Verification);
        }
        for credential in &credentials {
            let meta = &credential.meta;
            if meta.key_id != owner.id {
                return Err(super::super::Error::Verification);
            }
            let slot = format!("{}:{}", meta.kind, meta.slot);
            let pointer = format!("{}:{}:{}", meta.key_id, meta.kind, meta.slot);
            let public = format!("busbar:cred:pub:{}:{}", meta.kind, meta.public_id);
            if !slots.remove(slot.as_str())
                || ids.remove(meta.id.as_str()) != Some(pointer.as_bytes())
                || publics.remove(public.as_str()) != Some(pointer.as_bytes())
                || meta.revision != 0 && !revisions.remove(pointer.as_str())
            {
                return Err(super::super::Error::Verification);
            }
            revisions.remove(pointer.as_str());
            let envelope = if meta.revoked_at.is_some() || owner.deleted_at.is_some() {
                b"".as_slice()
            } else {
                credential.secret.as_bytes()
            };
            out.canonical(
                busbar_kernel::persistence::import_target::records::identity::migration_credential_rows(
                    meta,
                    envelope,
                    owner.deleted_at.is_some(),
                )
                .map_err(|_| super::super::Error::Corrupt)?,
                false,
            )?;
        }
        if !slots.is_empty() || !ids.is_empty() || !publics.is_empty() || !revisions.is_empty() {
            return Err(super::super::Error::Verification);
        }
        out.canonical(
            busbar_kernel::persistence::import_target::records::identity::migration_key(&owner)
                .map_err(|_| super::super::Error::Corrupt)?,
            false,
        )
    }
    fn streaming_accounting(
        &self,
        source: &dyn super::projection::ProjectionSource,
        marker: &Record,
        bounds: Bounds,
    ) -> Result<Vec<TargetRow>, super::super::Error> {
        use super::super::Error as MigrationError;
        super::projection::verify_marker(source, ACCOUNTING, marker)?;
        let group = Secret::new(marker.key.clone());
        let mut primary: Option<Vec<u8>> = None;
        let mut header = false;
        let mut fields = Vec::<(Vec<u8>, Vec<u8>)>::new();
        let mut membership = None;
        let mut charge = 0usize;
        let count = source.visit(ACCOUNTING, &group, bounds.bytes as usize, &mut |record| {
            let seal = crate::seal::lend();
            let (table, native) = transform::source_parts(&record.key).map_err(fail)?;
            if table != "valkey" {
                return Err(MigrationError::Corrupt);
            }
            let cell = valkey::physical(
                Row::decode(record.value.expose(&seal)).map_err(|_| MigrationError::Corrupt)?,
            )
            .map_err(fail)?;
            if cell.database != self.layout.source_db
                || cell.expires_at_ms.is_some()
                || !valkey::native_identity_matches(cell, native)
            {
                return Err(MigrationError::Verification);
            }
            let key = text(cell.key)?;
            let meter_index = key
                .strip_prefix("busbar:metering:")
                .filter(|rest| !rest.contains(':'));
            if let Some(bucket) = meter_index {
                if cell.kind != Kind::Set || membership.is_some() {
                    return Err(MigrationError::Verification);
                }
                let bytes = cell
                    .position
                    .len()
                    .checked_add(128)
                    .ok_or(MigrationError::Bounds)?;
                charge = charge.checked_add(bytes).ok_or(MigrationError::Bounds)?;
                if charge > source.semantic_bytes() {
                    return Err(MigrationError::Bounds);
                }
                membership = Some((integer(bucket.as_bytes())?, cell.position.to_vec()));
                return Ok(());
            }
            if !key.starts_with("busbar:usage:") && !key.starts_with("busbar:metering:") {
                return Err(MigrationError::UnsupportedPath);
            }
            if primary
                .as_deref()
                .is_some_and(|previous| previous != cell.key)
            {
                return Err(MigrationError::Verification);
            }
            if primary.is_none() {
                charge = charge
                    .checked_add(cell.key.len() + 128)
                    .ok_or(MigrationError::Bounds)?;
                if charge > source.semantic_bytes() {
                    return Err(MigrationError::Bounds);
                }
                primary = Some(cell.key.to_vec());
            }
            match cell.kind {
                Kind::Header if !header && cell.value == b"hash" && cell.position.is_empty() => {
                    header = true
                }
                Kind::Hash => {
                    let bytes = cell
                        .position
                        .len()
                        .checked_add(cell.value.len())
                        .and_then(|v| v.checked_add(512))
                        .ok_or(MigrationError::Bounds)?;
                    charge = charge.checked_add(bytes).ok_or(MigrationError::Bounds)?;
                    if charge > source.semantic_bytes() {
                        return Err(MigrationError::Bounds);
                    }
                    fields.try_reserve(1).map_err(|_| MigrationError::Bounds)?;
                    fields.push((cell.position.to_vec(), cell.value.to_vec()));
                }
                _ => return Err(MigrationError::Verification),
            }
            Ok(())
        })?;
        if count == 0 || !header {
            return Err(MigrationError::Verification);
        }
        let primary = primary.ok_or(MigrationError::Verification)?;
        let fields = fields
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect::<Vec<_>>();
        let mut out = Output::new(bounds);
        if let Some(rest) = text(&primary)?.strip_prefix("busbar:usage:") {
            if membership.is_some() {
                return Err(MigrationError::Verification);
            }
            let (bucket, window) = rest.rsplit_once(':').ok_or(MigrationError::Corrupt)?;
            let window = integer(window.as_bytes())?;
            let row = valkey::usage(self.layout.profile, &fields).map_err(fail)?;
            out.canonical(canonical_usage(bucket, window, &row).map_err(fail)?, true)?;
        } else {
            let rest = text(&primary)?
                .strip_prefix("busbar:metering:")
                .ok_or(MigrationError::Corrupt)?;
            let (bucket, _) = rest.split_once(':').ok_or(MigrationError::Corrupt)?;
            let bucket = integer(bucket.as_bytes())?;
            if membership.as_ref().map(|(b, k)| (*b, k.as_slice()))
                != Some((bucket, primary.as_slice()))
            {
                return Err(MigrationError::Verification);
            }
            let row = valkey::metering(self.layout.profile, &fields).map_err(fail)?;
            check_meter_identity(&primary, bucket, &row, self.layout.profile)?;
            out.canonical(canonical_metering(bucket, &row).map_err(fail)?, true)?;
        }
        Ok(out.finish())
    }
    fn accounting(
        &self,
        out: &mut Output,
        cells: &[PhysicalCell<'_>],
        bounds: Bounds,
    ) -> Result<(), super::super::Error> {
        if cells
            .iter()
            .any(|c| c.database != self.layout.source_db || c.expires_at_ms.is_some())
        {
            return Err(super::super::Error::Verification);
        }
        let by_key = physical_groups(cells);
        if let Some((key, raw)) = by_key
            .iter()
            .find(|(key, _)| key.starts_with(b"busbar:usage:"))
        {
            if by_key.len() != 1 {
                return Err(super::super::Error::Verification);
            }
            let group = complete(raw, bounds)?;
            if group.header.value != b"hash" {
                return Err(super::super::Error::Corrupt);
            }
            let rest = text(key)?
                .strip_prefix("busbar:usage:")
                .ok_or(super::super::Error::Corrupt)?;
            let (bucket, window) = rest.rsplit_once(':').ok_or(super::super::Error::Corrupt)?;
            let window = window
                .parse::<u64>()
                .map_err(|_| super::super::Error::Corrupt)?;
            let ledger = valkey::usage(self.layout.profile, &group.values).map_err(fail)?;
            return out.canonical(
                canonical_usage(bucket, window, &ledger).map_err(fail)?,
                true,
            );
        }
        let mut primary = None;
        let mut membership = None;
        for (key, raw) in &by_key {
            let rest = text(key)?
                .strip_prefix("busbar:metering:")
                .ok_or(super::super::Error::UnsupportedPath)?;
            if let Some((bucket, _)) = rest.split_once(':') {
                if primary.is_some() {
                    return Err(super::super::Error::Verification);
                }
                let group = complete(raw, bounds)?;
                if group.header.value != b"hash" {
                    return Err(super::super::Error::Corrupt);
                }
                let row = valkey::metering(self.layout.profile, &group.values).map_err(fail)?;
                let bucket = integer(bucket.as_bytes())?;
                check_meter_identity(key, bucket, &row, self.layout.profile)?;
                primary = Some((*key, bucket, row));
            } else {
                for cell in raw {
                    if cell.kind != Kind::Set
                        || membership
                            .replace((integer(rest.as_bytes())?, cell.position))
                            .is_some()
                    {
                        return Err(super::super::Error::Verification);
                    }
                }
            }
        }
        let (key, bucket, row) = primary.ok_or(super::super::Error::Verification)?;
        if membership != Some((bucket, key)) {
            return Err(super::super::Error::Verification);
        }
        out.canonical(canonical_metering(bucket, &row).map_err(fail)?, true)
    }
}
fn check_meter_identity(
    key: &[u8],
    bucket: u64,
    row: &busbar_contract::records::MeteringRow,
    profile: valkey::Profile,
) -> Result<(), super::super::Error> {
    let prefix = format!("busbar:metering:{bucket}:");
    let rest = text(key)?
        .strip_prefix(&prefix)
        .ok_or(super::super::Error::Verification)?;
    let mut fields = vec![String::new()];
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            if !matches!(ch, '\\' | '|') {
                return Err(super::super::Error::Corrupt);
            }
            fields
                .last_mut()
                .ok_or(super::super::Error::Corrupt)?
                .push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '|' {
            fields.push(String::new());
        } else {
            fields
                .last_mut()
                .ok_or(super::super::Error::Corrupt)?
                .push(ch);
        }
    }
    if escaped
        || !matches!(fields.len(), 3 | 4 | 6)
        || fields[0] != row.key_id
        || fields[1] != row.model
        || fields[2] != row.provider
        || profile == valkey::Profile::Released6 && fields.len() != 3
    {
        return Err(super::super::Error::Verification);
    }
    if fields.len() >= 4 && integer(fields[3].as_bytes())? != row.priced_from_ms
        || fields.len() == 3 && row.priced_from_ms != 0
    {
        return Err(super::super::Error::Verification);
    }
    if fields.len() == 6 && (fields[4] != row.key_group_at_use || fields[5] != row.pricing_version)
    {
        return Err(super::super::Error::Verification);
    }
    Ok(())
}

pub(super) struct ReceiptGroup<'a> {
    operation: [u8; 16],
    body: &'a [u8],
    expires_at_ms: Option<i64>,
    digest: Option<[u8; 32]>,
}
impl ReceiptGroup<'_> {
    pub(super) fn borrowed(&self) -> archive::Receipt<'_> {
        archive::Receipt {
            operation: &self.operation,
            body: self.body,
            answer: b"",
            recorded_at: None,
            expires_at_ms: self.expires_at_ms,
            historical_digest: self.digest,
            completed_shape: self.digest.is_some(),
        }
    }
}
pub(super) fn receipt_group<'a>(
    cells: &[PhysicalCell<'a>],
    bounds: Bounds,
) -> Result<ReceiptGroup<'a>, super::super::Error> {
    let group = complete(cells, bounds)?;
    if group.header.value != b"hash" || group.values.len() != 1 || group.values[0].0 != b"b" {
        return Err(super::super::Error::ReconciliationRequired);
    }
    let operation = text(group.header.key)?
        .strip_prefix("busbar:op:")
        .ok_or(super::super::Error::Corrupt)?;
    if operation.len() != 32
        || !operation
            .bytes()
            .all(|b| matches!(b,b'0'..=b'9'|b'a'..=b'f'))
    {
        return Err(super::super::Error::Corrupt);
    }
    let operation = hex::decode(operation)
        .map_err(|_| super::super::Error::Corrupt)?
        .try_into()
        .map_err(|_| super::super::Error::Corrupt)?;
    let body = group.values[0].1;
    let digest = if body.len() == 32 {
        Some(body.try_into().map_err(|_| super::super::Error::Corrupt)?)
    } else if body.len() == 64 && body.iter().all(|b| matches!(*b,b'0'..=b'9'|b'a'..=b'f')) {
        Some(
            hex::decode(body)
                .map_err(|_| super::super::Error::Corrupt)?
                .try_into()
                .map_err(|_| super::super::Error::Corrupt)?,
        )
    } else {
        None
    };
    Ok(ReceiptGroup {
        operation,
        body,
        expires_at_ms: group.header.expires_at_ms,
        digest,
    })
}
fn plane_group<'a>(
    cells: &[PhysicalCell<'a>],
) -> Result<(String, valkey::Sidecar, &'a str, &'a [u8]), super::super::Error> {
    if cells.len() != 2 {
        return Err(super::super::Error::Verification);
    }
    let mut metadata = None;
    let mut body = None;
    let mut kind = None;
    let mut position = None;
    for cell in cells {
        if cell.kind != Kind::Hash || cell.expires_at_ms.is_some() {
            return Err(super::super::Error::Corrupt);
        }
        let (actual_kind, suffix) = valkey::plane_key(cell.key).map_err(fail)?;
        if kind.as_ref().is_some_and(|k| k != &actual_kind)
            || position.is_some_and(|p| p != cell.position)
        {
            return Err(super::super::Error::Verification);
        }
        kind = Some(actual_kind);
        position = Some(cell.position);
        match suffix {
            "rec" => {
                if metadata
                    .replace(valkey::sidecar(cell.value).map_err(fail)?)
                    .is_some()
                {
                    return Err(super::super::Error::Verification);
                }
            }
            "body" => {
                if body.replace(cell.value).is_some() {
                    return Err(super::super::Error::Verification);
                }
            }
            _ => return Err(super::super::Error::UnsupportedPath),
        }
    }
    let sidecar = metadata.ok_or(super::super::Error::Verification)?;
    let (seq, identity) =
        valkey::plane_position(position.ok_or(super::super::Error::Verification)?).map_err(fail)?;
    if seq != sidecar.seq || identity != sidecar.id && sidecar.parent.as_deref() != Some(identity) {
        return Err(super::super::Error::Verification);
    }
    Ok((
        kind.ok_or(super::super::Error::Verification)?,
        sidecar,
        identity,
        body.ok_or(super::super::Error::Verification)?,
    ))
}
impl ValkeyTransform {
    fn archival(
        &self,
        out: &mut Output,
        cells: &[PhysicalCell<'_>],
        bounds: Bounds,
    ) -> Result<(), super::super::Error> {
        if cells
            .iter()
            .all(|c| c.database != self.layout.source_db || !c.key.starts_with(b"busbar:"))
        {
            return Ok(());
        }
        if cells.iter().any(|c| c.database != self.layout.source_db) {
            return Err(super::super::Error::Verification);
        }
        if cells.iter().any(|c| c.key.starts_with(b"busbar:op:")) {
            if self.layout.profile == valkey::Profile::Released6 {
                return Err(super::super::Error::UnsupportedPath);
            }
            receipt_group(cells, bounds)?;
            return Ok(());
        }
        if cells
            .iter()
            .any(|c| c.key.starts_with(b"busbar:records:") && c.kind != Kind::Header)
        {
            if self.layout.profile == valkey::Profile::Released6 {
                return Err(super::super::Error::UnsupportedPath);
            }
            let mut entries = BTreeMap::<&[u8], (String, Option<&[u8]>, bool)>::new();
            for cell in cells {
                if cell.expires_at_ms.is_some() {
                    return Err(super::super::Error::Verification);
                }
                let rest = text(cell.key)?
                    .strip_prefix("busbar:records:")
                    .ok_or(super::super::Error::Corrupt)?;
                let (encoded, suffix) =
                    rest.rsplit_once(':').ok_or(super::super::Error::Corrupt)?;
                let schema = String::from_utf8(
                    hex::decode(encoded).map_err(|_| super::super::Error::Corrupt)?,
                )
                .map_err(|_| super::super::Error::Corrupt)?;
                if hex::encode(schema.as_bytes()) != encoded {
                    return Err(super::super::Error::Corrupt);
                }
                let entry = entries
                    .entry(cell.position)
                    .or_insert_with(|| (schema.clone(), None, false));
                if entry.0 != schema {
                    return Err(super::super::Error::Verification);
                }
                match (suffix, cell.kind) {
                    ("v", Kind::Hash) => {
                        if entry.1.replace(cell.value).is_some() {
                            return Err(super::super::Error::Verification);
                        }
                    }
                    ("k", Kind::SortedSet) if cell.value == b"0" && !entry.2 => entry.2 = true,
                    _ => return Err(super::super::Error::Verification),
                }
            }
            if entries
                .values()
                .any(|(_, value, index)| value.is_none() || !*index)
            {
                return Err(super::super::Error::Verification);
            }
            if entries
                .values()
                .all(|(schema, _, _)| schema == "busbar.journal.v1")
            {
                let parts = entries
                    .iter()
                    .map(|(key, (_, value, _))| {
                        Ok(super::journal_binding::Part {
                            key,
                            value: value.ok_or(super::super::Error::Verification)?,
                        })
                    })
                    .collect::<Result<Vec<_>, super::super::Error>>()?;
                return out.canonical(
                    self.journal
                        .as_ref()
                        .ok_or(super::super::Error::MissingCapability)?
                        .copy_group(&parts, bounds.bytes as usize)?,
                    false,
                );
            }
            if entries.len() != 1 {
                return Err(super::super::Error::Verification);
            }
            let (key, (schema, value, _)) = entries
                .into_iter()
                .next()
                .ok_or(super::super::Error::Verification)?;
            let bindings = self.bindings();
            return match archive::route_record(
                &schema,
                key,
                value.ok_or(super::super::Error::Verification)?,
                &bindings,
            )
            .map_err(fail)?
            {
                archive::Route::Record { address, value } => {
                    if self
                        .overlay
                        .as_ref()
                        .is_some_and(|overlay| overlay.replaces(&address))
                    {
                        return Ok(());
                    }
                    if let Some(proofs) = &self.recovery {
                        out.canonical(proofs.record_rows(address, value)?, false)
                    } else {
                        out.put(address, Secret::new(value.to_vec()), None, false)
                    }
                }
                archive::Route::Prepared(rows) => out.canonical(rows, false),
                _ => Err(super::super::Error::MissingCapability),
            };
        }
        if cells.iter().any(|c| {
            c.key.starts_with(b"busbar:plane:")
                && c.kind == Kind::Hash
                && valkey::plane_key(c.key)
                    .is_ok_and(|(_, suffix)| matches!(suffix, "rec" | "body"))
        }) {
            let (kind, sidecar, identity, body) = plane_group(cells)?;
            return self.emit_plane(
                out,
                PlaneRecordRef {
                    kind: &kind,
                    id: &sidecar.id,
                    parent: sidecar.parent.as_deref(),
                    seq: sidecar.seq,
                    ts: sidecar.ts,
                    disposition: sidecar.disposition,
                    body,
                },
                identity,
            );
        }
        for cell in cells {
            let key = text(cell.key)?;
            if key == "busbar:schema" {
                if cell.expires_at_ms.is_some() {
                    return Err(super::super::Error::Verification);
                }
                match cell.kind {
                    Kind::Header if cell.value == b"string" => {}
                    Kind::String
                        if text(cell.value)?.parse::<i64>().ok()
                            == Some(i64::from(self.edge.source.physical)) => {}
                    _ => return Err(super::super::Error::Corrupt),
                };
                continue;
            }
            if cell.kind == Kind::Header {
                if cell.expires_at_ms.is_some() {
                    // Only spent-token and old-receipt physical keys had TTLs.
                    if !key.starts_with("busbar:plane:") {
                        return Err(super::super::Error::UnsupportedPath);
                    }
                }
                let known = matches!(
                    key,
                    "busbar:keys"
                        | "busbar:keys:byrev"
                        | "busbar:creds:byrev"
                        | "busbar:denylist"
                        | "busbar:audit"
                ) || key.starts_with("busbar:cred:id:")
                    || key.starts_with("busbar:cred:pub:")
                    || key.starts_with("busbar:metering:")
                    || self.layout.profile != valkey::Profile::Released6
                        && (key.starts_with("busbar:records:") || key.starts_with("busbar:plane:"));
                if !known {
                    return Err(super::super::Error::UnsupportedPath);
                }
                let expected = if matches!(key, "busbar:keys" | "busbar:denylist")
                    || key.starts_with("busbar:metering:")
                {
                    b"set".as_slice()
                } else if matches!(
                    key,
                    "busbar:keys:byrev" | "busbar:creds:byrev" | "busbar:audit"
                ) {
                    b"zset".as_slice()
                } else if key.starts_with("busbar:cred:") {
                    b"string".as_slice()
                } else if key.starts_with("busbar:records:") {
                    if key.ends_with(":k") {
                        b"zset".as_slice()
                    } else if key.ends_with(":v") {
                        b"hash".as_slice()
                    } else {
                        return Err(super::super::Error::UnsupportedPath);
                    }
                } else {
                    let (_, suffix) = valkey::plane_key(cell.key).map_err(fail)?;
                    if suffix.starts_with("tok:") {
                        b"string".as_slice()
                    } else if matches!(suffix, "rec" | "body" | "pcount") {
                        b"hash".as_slice()
                    } else if suffix == "byts" || suffix.starts_with("idx:") {
                        b"zset".as_slice()
                    } else {
                        return Err(super::super::Error::UnsupportedPath);
                    }
                };
                if cell.value != expected {
                    return Err(super::super::Error::Corrupt);
                }
                continue;
            }
            if self.layout.profile != valkey::Profile::Released6 && key.starts_with("busbar:plane:")
            {
                let (kind, suffix) = valkey::plane_key(cell.key).map_err(fail)?;
                if let Some(token) = suffix.strip_prefix("tok:") {
                    if cell.kind != Kind::String {
                        return Err(super::super::Error::Corrupt);
                    }
                    let token = String::from_utf8(
                        hex::decode(token).map_err(|_| super::super::Error::Corrupt)?,
                    )
                    .map_err(|_| super::super::Error::Corrupt)?;
                    let expires = integer(cell.value)?;
                    if let Some(physical) = cell.expires_at_ms {
                        let expected = expires
                            .checked_add(1)
                            .and_then(|v| v.checked_mul(1000))
                            .and_then(|v| i64::try_from(v).ok())
                            .ok_or(super::super::Error::Bounds)?;
                        if physical != expected {
                            return Err(super::super::Error::Verification);
                        }
                    }
                    self.claim(out, &kind, &token, expires)?;
                    continue;
                }
                // Source global inventory verifies these secondary references;
                // the target's exact native indexes are regenerated by owner.
                if matches!(
                    (suffix, cell.kind),
                    ("byts", Kind::SortedSet) | ("pcount", Kind::Hash)
                ) || suffix.starts_with("idx:") && cell.kind == Kind::SortedSet
                {
                    continue;
                }
            }
            return Err(super::super::Error::UnsupportedPath);
        }
        Ok(())
    }
}

impl ValkeyTransform {
    fn evidence_address(
        &self,
        cell: PhysicalCell<'_>,
        records: &[Record],
    ) -> Result<Address, super::super::Error> {
        for record in records {
            let (_, key) = transform::source_parts(&record.key).map_err(fail)?;
            if valkey::native_identity_matches(cell, key) {
                return Ok(Address {
                    namespace: archive::NAMESPACE.0,
                    key: busbar_kernel::persistence::import_target::records::keys::framed(
                        b'E',
                        &[
                            &self.provenance.dataset,
                            &self.provenance.catalogue,
                            b"valkey",
                            key,
                        ],
                    )
                    .map_err(|_| super::super::Error::Bounds)?,
                });
            }
        }
        Err(super::super::Error::Verification)
    }
    pub fn verify_page(
        &self,
        source: &Identity,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        actual: &[(Address, Secret<Vec<u8>>)],
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
                actual,
                &self.edge.verification_rule_digest,
            );
        }
        if !super::projection::is_marker_page(records) {
            return self.verify_raw(source, family, records, bounds, actual, proofs, true);
        }
        if !self.matches_source(source) {
            return Err(super::super::Error::IdentityMismatch);
        }
        let expected = self.transform(family, records, bounds)?;
        let mut verified = super::projection::verify_physical(
            records,
            &expected,
            actual,
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
                transform::hash_field(&mut semantics, &super::projection::decode_marker(marker)?);
                transform::hash_field(&mut semantics, b"complete-streamed-accounting/1");
                continue;
            }
            let original = super::projection::materialize(frozen, family.id, marker, bounds)?;
            let projected = self.transform_impl(family, &original, bounds, false)?;
            let mut native = Vec::new();
            for row in &projected {
                let (_, value) = actual
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
        source: &Identity,
        family: &Family,
        records: &[Record],
        bounds: Bounds,
        actual: &[(Address, Secret<Vec<u8>>)],
        proofs: &dyn NativeProofs,
        retain_physical: bool,
    ) -> Result<PageVerification, super::super::Error> {
        if !self.matches_source(source) {
            return Err(super::super::Error::IdentityMismatch);
        }
        let expected = self.transform_impl(family, records, bounds, retain_physical)?;
        if family.id == super::projection::PHYSICAL {
            return super::projection::verify_physical(
                records,
                &expected,
                actual,
                &self.edge.verification_rule_digest,
            );
        }
        if actual.len() != expected.len() {
            return Err(super::super::Error::Verification);
        }
        let seal = crate::seal::lend();
        let mut native = BTreeMap::new();
        for (at, value) in actual {
            if native.insert(at, value).is_some() {
                return Err(super::super::Error::Verification);
            }
        }
        let mut target_hash = Sha256::new();
        for row in &expected {
            if native.get(&row.address).map(|v| v.expose(&seal)) != Some(row.value.expose(&seal)) {
                return Err(super::super::Error::Verification);
            }
            transform::hash_field(&mut target_hash, &row.address.namespace);
            transform::hash_field(&mut target_hash, &row.address.key);
            transform::hash_field(&mut target_hash, row.value.expose(&seal));
        }
        let mut source_hash = Sha256::new();
        for row in records {
            transform::hash_field(&mut source_hash, &row.key);
            transform::hash_field(&mut source_hash, row.value.expose(&seal));
        }
        let mut semantics = Sha256::new();
        transform::hash_field(&mut semantics, &self.edge.verification_rule_digest);
        if let Some(plan) = &self.journal {
            transform::hash_field(&mut semantics, &plan.descriptor_digest());
        }
        for group in groups(self.parsed(family, records, bounds)?) {
            if family.id == AUDIT {
                for cell in &group.cells {
                    let record = valkey::audit(cell.position).map_err(fail)?;
                    let digest = proofs.historical_audit(self.provenance, &record)?;
                    if digest == [0; 32] {
                        return Err(super::super::Error::Verification);
                    }
                    transform::hash_field(&mut semantics, &digest);
                }
            }
            if family.id == ARCHIVAL {
                if group.cells.iter().any(|c| {
                    c.database == self.layout.source_db && c.key.starts_with(b"busbar:op:")
                }) {
                    let receipt = receipt_group(&group.cells, bounds)?;
                    let borrowed = receipt.borrowed();
                    let body = group
                        .cells
                        .iter()
                        .find(|c| c.kind == Kind::Hash && c.position == b"b")
                        .ok_or(super::super::Error::Verification)?;
                    let at = self.evidence_address(*body, records)?;
                    let digest = proofs.resolve_original(self.provenance, &at, &borrowed)?;
                    if digest == [0; 32] {
                        return Err(super::super::Error::Verification);
                    }
                    transform::hash_field(&mut semantics, &digest);
                }
                if group.cells.iter().any(|c| {
                    c.database == self.layout.source_db
                        && c.key.starts_with(b"busbar:plane:")
                        && c.kind == Kind::Hash
                        && valkey::plane_key(c.key)
                            .is_ok_and(|(_, suffix)| matches!(suffix, "rec" | "body"))
                }) {
                    let (kind, sidecar, _, _) = plane_group(&group.cells)?;
                    if let Some(binding) = self.history(&kind) {
                        let declaration = binding
                            .collections
                            .iter()
                            .find(|c| c.kind == kind)
                            .ok_or(super::super::Error::Verification)?;
                        if let Some(parent_kind) = &declaration.parent {
                            let parent = sidecar
                                .parent
                                .as_deref()
                                .ok_or(super::super::Error::Verification)?;
                            let digest = proofs.parent_present(
                                self.provenance,
                                &binding.owner,
                                parent_kind,
                                parent,
                            )?;
                            if digest == [0; 32] {
                                return Err(super::super::Error::Verification);
                            }
                            transform::hash_field(&mut semantics, &digest);
                        }
                    }
                }
            }
        }
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
            semantics_digest: semantics.finalize().into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_contract::persistence::legacy_row::{self, Cell};
    busbar_contract::own_seal!(Own);
    fn frame(kind: i64, key: &[u8], position: &[u8], value: &[u8]) -> Record {
        let native = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Integer(kind),
                Cell::Blob(key),
                Cell::Blob(position),
            ],
            16_384,
        )
        .unwrap();
        let physical = legacy_row::encode::<Own>(
            &[
                Cell::Integer(0),
                Cell::Integer(kind),
                Cell::Integer(-1),
                Cell::Blob(key),
                Cell::Blob(position),
                Cell::Blob(value),
            ],
            16_384,
        )
        .unwrap();
        Record {
            key: transform::source_key("valkey", native.expose_own(&Own::here())).unwrap(),
            value: Secret::new(physical.expose_own(&Own::here()).clone()),
            preserve_exact: true,
        }
    }
    // NEW importer frames over exact recorded published values. These frames
    // were not emitted by 1.5.5 and are not alleged released-format evidence.
    #[test]
    fn published_valkey_values_migrate_through_registered_edge_and_exact_readback() {
        let data: serde_json::Value =
            serde_json::from_slice(include_bytes!("fixtures/valkey-1.5.5-rows.json")).unwrap();
        let objects = data.as_object().unwrap();
        let counts = (objects.len() as u64).to_le_bytes();
        let native_layout = legacy_row::encode::<Own>(
            &[
                Cell::Text(b"busbar.valkey.native-inventory/1"),
                Cell::Integer(0),
                Cell::Integer(6),
                Cell::Integer(0x90103),
                Cell::Blob(&[1; 32]),
                Cell::Blob(&[2; 32]),
                Cell::Blob(&[3; 32]),
                Cell::Blob(&[4; 32]),
                Cell::Integer(1),
                Cell::Blob(&counts),
            ],
            16_384,
        )
        .unwrap();
        let provenance = archive::Provenance {
            dataset: [8; 16],
            catalogue: [9; 32],
        };
        let bounds = Bounds {
            items: 4096,
            bytes: 1024 * 1024,
        };
        let importer = ValkeyTransform::registered(
            provenance,
            native_layout.expose_own(&Own::here()),
            vec![],
            vec![],
            vec![],
            bounds,
        )
        .unwrap();
        let mut families = BTreeMap::<[u8; 16], Vec<Record>>::new();
        let mut audits = Vec::new();
        for (key, stored) in objects {
            assert_eq!(stored["has_ttl"], false);
            let kind = stored["type"].as_str().unwrap();
            let mut records = vec![frame(0, key.as_bytes(), b"", kind.as_bytes())];
            match kind {
                "string" => records.push(frame(
                    1,
                    key.as_bytes(),
                    b"",
                    stored["value"].as_str().unwrap().as_bytes(),
                )),
                "hash" => {
                    for (field, value) in stored["value"].as_object().unwrap() {
                        records.push(frame(
                            2,
                            key.as_bytes(),
                            field.as_bytes(),
                            value.as_str().unwrap().as_bytes(),
                        ));
                    }
                }
                "set" => {
                    for member in stored["value"].as_array().unwrap() {
                        records.push(frame(
                            3,
                            key.as_bytes(),
                            member.as_str().unwrap().as_bytes(),
                            b"",
                        ));
                    }
                }
                "zset" => {
                    for pair in stored["value"].as_array().unwrap() {
                        let member = pair[0].as_str().unwrap();
                        records.push(frame(
                            4,
                            key.as_bytes(),
                            member.as_bytes(),
                            pair[1].as_str().unwrap().as_bytes(),
                        ));
                        if key == "busbar:audit" {
                            audits.push(valkey::audit(member.as_bytes()).unwrap());
                        }
                    }
                }
                _ => panic!("unsupported recorded fixture type"),
            }
            for record in records {
                let (_, native_key) = transform::source_parts(&record.key).unwrap();
                let logical = group::valkey_row_class_and_group(
                    valkey::Profile::Released6,
                    0,
                    "valkey",
                    valkey::NATIVE_COLUMNS,
                    native_key,
                    Row::decode(record.value.expose(&crate::seal::lend())).unwrap(),
                )
                .unwrap();
                families.entry(logical.family).or_default().push(record);
            }
        }
        let proof = transform::CompleteAuditProofs::from_complete_source(
            importer.edge.source,
            provenance,
            audits,
            2,
        )
        .unwrap();
        let source = Identity {
            dataset: provenance.dataset,
            format: importer.edge.source,
            artifact_digest: [7; 32],
            schema_digest: provenance.catalogue,
            product_release: [1, 5, 5],
        };
        for family in &importer.edge.families {
            let records = families.remove(&family.id).unwrap_or_default();
            let rows = importer.transform(family, &records, bounds).unwrap();
            assert!(rows
                .iter()
                .all(|row| importer.authorize(family, &row.address)));
            let mut native = rows
                .iter()
                .map(|row| (row.address.clone(), row.value.clone()))
                .collect::<Vec<_>>();
            importer
                .verify_page(&source, family, &records, bounds, &native, &proof)
                .unwrap();
            if let Some((_, value)) = native.first_mut() {
                *value = Secret::new(b"changed".to_vec());
                assert!(importer
                    .verify_page(&source, family, &records, bounds, &native, &proof)
                    .is_err());
            }
        }
        assert!(families.is_empty());
    }
}
