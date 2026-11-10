// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
//! Logical import transforms consume admitted owner facts, never physical grammar.
use super::{
    archive, canonical_identity, projection,
    transform::{self, Output, *},
    Credential, HistoricalRow,
};
use crate::{
    source_facts::{FactRow, View},
    Bounds, Edge, Error, Family, Format, Record, Registry, TargetRow, Transform,
};
use busbar_contract::{
    persistence::{archive::Table, lifecycle::source::HistoricalFact, Address},
    Secret,
};
use busbar_kernel::persistence::import_target::records::{self, history::HistoryMode};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub struct FactTransform {
    edge: Edge,
    provenance: archive::Provenance,
    view: View,
    original_tables: BTreeSet<String>,
    fact_table: String,
    records: Vec<RecordBinding>,
    histories: Vec<HistoryBinding>,
    tokens: Vec<TokenBinding>,
    journal: Option<Arc<dyn super::journal_binding::JournalMigration>>,
    projection: Option<Arc<dyn projection::ProjectionSource>>,
    recovery: Option<Arc<super::recovery::FencedReceiptProofs>>,
    overlay: Option<Arc<super::overlay::PreparedOverlay>>,
}
fn invalid(_: super::Error) -> Error {
    Error::Verification
}
impl FactTransform {
    pub fn registered(
        source: Format,
        provenance: archive::Provenance,
        catalogue: &[Table],
        view: View,
        bindings: crate::routes::Bindings,
        bounds: Bounds,
    ) -> Result<Self, Error> {
        bounds.validate()?;
        if provenance.dataset == [0; 16] || provenance.catalogue == [0; 32] {
            return Err(Error::IdentityMismatch);
        }
        let original_tables = catalogue
            .iter()
            .enumerate()
            .filter(|(i, _)| view.is_original(*i as u32))
            .map(|(_, t)| t.name.clone())
            .collect::<BTreeSet<_>>();
        if original_tables.is_empty() {
            return Err(Error::Corrupt);
        }
        let fact_table = catalogue
            .get(view.facts_table() as usize)
            .ok_or(Error::Corrupt)?
            .name
            .clone();
        let mut hash = Sha256::new();
        hash_field(&mut hash, b"busbar.owner-facts/1");
        hash_field(&mut hash, &view.reader().decoder_digest());
        hash_field(&mut hash, &provenance.dataset);
        hash_field(&mut hash, &provenance.catalogue);
        bind_config(
            &mut hash,
            &bindings.records,
            &bindings.histories,
            &bindings.tokens,
        );
        let families = [
            (projection::PHYSICAL, projection::PHYSICAL),
            (IDENTITY, records::identity::NAMESPACE.0),
            (ACCOUNTING, records::ledger::USAGE.0),
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
        let edge = registered_edge(source, hash.finalize().into(), families, bounds)?;
        Ok(Self {
            edge,
            provenance,
            view,
            original_tables,
            fact_table,
            records: bindings.records,
            histories: bindings.histories,
            tokens: bindings.tokens,
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

    fn decode(&self, record: &Record, family: &Family, budget: usize) -> Result<FactRow, Error> {
        let (table, native) = transform::source_parts(&record.key).map_err(invalid)?;
        if table != self.fact_table {
            return Err(Error::IdentityMismatch);
        }
        let fact = self
            .view
            .decode(record.value.expose(&crate::seal::lend()), budget)?;
        if crate::source_facts::grouping::classify(fact.fact(), native)?.family != family.id {
            return Err(Error::EdgeMismatch);
        }
        Ok(fact)
    }
    fn load(&self, family: &Family, marker: &Record) -> Result<Vec<FactRow>, Error> {
        let source = self.projection.as_deref().ok_or(Error::MissingCapability)?;
        projection::verify_marker(source, family.id, marker)?;
        let budget = source.semantic_bytes();
        let mut charged = 0usize;
        let mut facts = Vec::new();
        let count = source.visit(
            family.id,
            &Secret::new(marker.key.to_vec()),
            budget,
            &mut |record| {
                charged = charged
                    .checked_add(
                        record
                            .value
                            .expose(&crate::seal::lend())
                            .len()
                            .checked_mul(128)
                            .ok_or(Error::Bounds)?,
                    )
                    .and_then(|n| n.checked_add(2048))
                    .ok_or(Error::Bounds)?;
                if charged > budget {
                    return Err(Error::Bounds);
                }
                let fact = self.decode(record, family, budget)?;
                let (_, native) = transform::source_parts(&record.key).map_err(invalid)?;
                if crate::source_facts::grouping::classify(fact.fact(), native)?
                    .key
                    .expose(&crate::seal::lend())
                    .as_slice()
                    != marker.key.as_slice()
                {
                    return Err(Error::Verification);
                }
                facts.push(fact);
                Ok(())
            },
        )?;
        if count == 0 || count != facts.len() as u64 {
            return Err(Error::Verification);
        }
        Ok(facts)
    }
    fn logical(
        &self,
        family: &Family,
        facts: &[FactRow],
        bounds: Bounds,
    ) -> Result<Vec<TargetRow>, Error> {
        let mut out = Output::new(bounds);
        let seal = crate::seal::lend();
        match family.id {
            ACCOUNTING => crate::source_facts::accounting::convert(facts, &mut out)?,
            IDENTITY => {
                let mut owners = BTreeMap::new();
                for fact in facts {
                    if let HistoricalFact::Key { value, .. } = fact.fact() {
                        if owners
                            .insert(value.id.as_str(), value.deleted_at.is_some())
                            .is_some()
                        {
                            return Err(Error::Verification);
                        }
                    }
                }
                for fact in facts {
                    let (row, deleted) = match fact.fact() {
                        HistoricalFact::Key { value, updated_at } => (
                            HistoricalRow::Key {
                                key: value.clone(),
                                updated_at: *updated_at,
                            },
                            false,
                        ),
                        HistoricalFact::Credential { meta, envelope } => (
                            HistoricalRow::Credential(Credential {
                                meta: meta.clone(),
                                envelope: Some(envelope.expose(&seal)),
                            }),
                            *owners
                                .get(meta.key_id.as_str())
                                .ok_or(Error::Verification)?,
                        ),
                        HistoricalFact::Denial {
                            subject,
                            reason,
                            created_at,
                        } => (
                            HistoricalRow::Denied {
                                subject: subject.clone(),
                                reason: reason.clone(),
                                created_at: *created_at,
                            },
                            false,
                        ),
                        HistoricalFact::Revision(value) => (HistoricalRow::Revision(*value), false),
                        _ => return Err(Error::Corrupt),
                    };
                    out.canonical(canonical_identity(&row, deleted).map_err(invalid)?, false)?;
                }
            }
            AUDIT => {
                for fact in facts {
                    let HistoricalFact::Audit(record) = fact.fact() else {
                        return Err(Error::Corrupt);
                    };
                    out.canonical(
                        records::history::migration_audit_rows(records::AUDIT_OWNER, record)
                            .map_err(|_| Error::Verification)?,
                        false,
                    )?;
                }
            }
            ARCHIVAL => self.archival(facts, bounds, &mut out)?,
            _ => return Err(Error::UnsupportedPath),
        }
        Ok(out.finish())
    }
    fn archival(&self, facts: &[FactRow], bounds: Bounds, out: &mut Output) -> Result<(), Error> {
        let seal = crate::seal::lend();
        let bindings = self.bindings();
        let mut journal = BTreeMap::<[u8; 16], Vec<super::journal_binding::Part<'_>>>::new();
        for fact in facts {
            match fact.fact() {
                HistoricalFact::Record { schema, key, value } => {
                    match archive::route_record(
                        schema,
                        key.expose(&seal),
                        value.expose(&seal),
                        &bindings,
                    )
                    .map_err(invalid)?
                    {
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
                                return Err(Error::Corrupt);
                            }
                            journal
                                .entry(key[..16].try_into().map_err(|_| Error::Corrupt)?)
                                .or_default()
                                .push(super::journal_binding::Part { key, value });
                        }
                        archive::Route::RequiresBinding => return Err(Error::MissingCapability),
                        _ => return Err(Error::Corrupt),
                    }
                }
                HistoricalFact::History {
                    kind,
                    id,
                    parent,
                    sequence,
                    timestamp,
                    disposition,
                    body,
                    append,
                } => {
                    let record = busbar_contract::records::PlaneRecordRef {
                        kind,
                        id,
                        parent: parent.as_deref(),
                        seq: *sequence,
                        ts: *timestamp,
                        disposition: *disposition,
                        body: body.expose(&seal),
                    };
                    if let Some(rows) = builtin_history(record, *append)? {
                        out.canonical(rows, false)?;
                        continue;
                    }
                    let binding = self.history(kind).ok_or(Error::MissingCapability)?;
                    let declaration = binding
                        .collections
                        .iter()
                        .find(|c| c.kind == *kind)
                        .ok_or(Error::MissingCapability)?;
                    if append.is_some_and(|old| old != (declaration.mode == HistoryMode::Append)) {
                        return Err(Error::Verification);
                    }
                    let rows = records::history::migration_rows(
                        &binding.owner,
                        binding.declarations(),
                        busbar_contract::records::PlaneRecordRef {
                            kind,
                            id,
                            parent: parent.as_deref(),
                            seq: *sequence,
                            ts: *timestamp,
                            disposition: *disposition,
                            body: body.expose(&seal),
                        },
                        declaration.parent.as_ref().map(|_| 1),
                    )
                    .map_err(|_| Error::Verification)?;
                    for (i, (at, value)) in rows.into_iter().enumerate() {
                        out.put(at, value, None, i < 2)?;
                    }
                }
                HistoricalFact::Token {
                    kind,
                    token,
                    expires_at,
                } => {
                    if kind == "ticket-spent" {
                        out.canonical(
                            vec![records::ticket::legacy_ticket_token(
                                kind,
                                std::str::from_utf8(token.expose(&seal))
                                    .map_err(|_| Error::Corrupt)?,
                                *expires_at,
                            )
                            .map_err(|_| Error::Verification)?],
                            false,
                        )?;
                        continue;
                    }
                    let mut candidates = self
                        .tokens
                        .iter()
                        .filter(|binding| binding.source_kind == *kind);
                    let matched = candidates.next();
                    if candidates.next().is_some() {
                        return Err(Error::Verification);
                    }
                    let (instance, native_kind) = match kind.as_str() {
                        "busbar.admin-idempotency" => ("busbar.admin", kind.as_str()),
                        "auth-replay" => ("busbar.auth-replay", kind.as_str()),
                        _ => {
                            let binding = matched.ok_or(Error::MissingCapability)?;
                            (&*binding.instance, &*binding.kind)
                        }
                    };
                    out.canonical(
                        records::scoped::migration_claim_rows(
                            instance,
                            native_kind,
                            std::str::from_utf8(token.expose(&seal)).map_err(|_| Error::Corrupt)?,
                            *expires_at,
                        )
                        .map_err(|_| Error::Verification)?,
                        false,
                    )?;
                }
                HistoricalFact::Receipt { .. } | HistoricalFact::EvidenceOnly => {}
                _ => return Err(Error::Corrupt),
            }
        }
        if !journal.is_empty() {
            let plan = self.journal.as_ref().ok_or(Error::MissingCapability)?;
            for parts in journal.values() {
                out.canonical(plan.copy_group(parts, bounds.bytes as usize)?, false)?;
            }
        }
        Ok(())
    }
}
impl Transform for FactTransform {
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
                && self.original_tables.contains(table)
                && family.id == projection::PHYSICAL;
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
        input: &[Record],
        bounds: Bounds,
    ) -> Result<Vec<TargetRow>, Error> {
        bounds.validate()?;
        if !self.edge.families.contains(family) {
            return Err(Error::EdgeMismatch);
        }
        if family.id == super::overlay::FAMILY {
            return self
                .overlay
                .as_ref()
                .ok_or(Error::MissingCapability)?
                .transform(input, bounds);
        }
        if family.id == projection::PHYSICAL {
            return projection::physical_rows(self.provenance, input, bounds, |table, _, _| {
                if self.original_tables.contains(table) {
                    Ok(())
                } else {
                    Err(Error::IdentityMismatch)
                }
            });
        }
        if !projection::is_marker_page(input) {
            return Err(Error::Verification);
        }
        projection::project_rows(
            self.projection.as_deref().ok_or(Error::MissingCapability)?,
            self.provenance,
            self.journal.as_deref(),
            family,
            input,
            bounds,
            |marker| self.logical(family, &self.load(family, marker)?, bounds),
        )
    }
}

impl FactTransform {
    pub fn verify_page(
        &self,
        source: &crate::Identity,
        family: &Family,
        input: &[Record],
        bounds: Bounds,
        native: &[(Address, Secret<Vec<u8>>)],
        proofs: &dyn NativeProofs,
    ) -> Result<PageVerification, Error> {
        if !self.matches_source(source) {
            return Err(Error::IdentityMismatch);
        }
        let expected = self.transform(family, input, bounds)?;
        let mut verified = projection::verify_physical(
            input,
            &expected,
            native,
            &self.edge.verification_rule_digest,
        )?;
        if family.id == projection::PHYSICAL || family.id == super::overlay::FAMILY {
            return Ok(verified);
        }
        let frozen = self.projection.as_deref().ok_or(Error::MissingCapability)?;
        let mut semantic = Sha256::new();
        hash_field(&mut semantic, &verified.semantics_digest);
        hash_field(&mut semantic, b"admitted-owner-facts/readback/1");
        for marker in input {
            projection::verify_marker(frozen, family.id, marker)?;
            hash_field(&mut semantic, &projection::decode_marker(marker)?);
            if projection::is_journal_marker(marker)? {
                hash_field(
                    &mut semantic,
                    &self
                        .journal
                        .as_ref()
                        .ok_or(Error::MissingCapability)?
                        .descriptor_digest(),
                );
                continue;
            }
            for fact in self.load(family, marker)? {
                let seal = crate::seal::lend();
                let proof = match fact.fact() {
                    HistoricalFact::Audit(record) => {
                        Some(proofs.historical_audit(self.provenance, record)?)
                    }
                    HistoricalFact::History { kind, .. } if builtin_history_kind(kind) => None,
                    HistoricalFact::History { kind, parent, .. } => {
                        let binding = self.history(kind).ok_or(Error::MissingCapability)?;
                        let declaration = binding
                            .collections
                            .iter()
                            .find(|c| c.kind == *kind)
                            .ok_or(Error::MissingCapability)?;
                        match &declaration.parent {
                            Some(parent_kind) => Some(proofs.parent_present(
                                self.provenance,
                                &binding.owner,
                                parent_kind,
                                parent.as_deref().ok_or(Error::Verification)?,
                            )?),
                            None => None,
                        }
                    }
                    HistoricalFact::Receipt {
                        operation,
                        body,
                        answer,
                        recorded_at,
                        expires_at_ms,
                        historical_digest,
                        completed_shape,
                    } => {
                        let origin = frozen.fact_origin_digest(&fact, frozen.semantic_bytes())?;
                        let address =
                            super::recovery::fact_receipt_reference(self.provenance, origin)?;
                        Some(proofs.resolve_original(
                            self.provenance,
                            &address,
                            &archive::Receipt {
                                operation,
                                body: body.expose(&seal),
                                answer: answer.expose(&seal),
                                recorded_at: *recorded_at,
                                expires_at_ms: *expires_at_ms,
                                historical_digest: *historical_digest,
                                completed_shape: *completed_shape,
                            },
                        )?)
                    }
                    _ => None,
                };
                if let Some(proof) = proof {
                    if proof == [0; 32] {
                        return Err(Error::Verification);
                    }
                    hash_field(&mut semantic, &proof);
                }
            }
        }
        verified.semantics_digest = semantic.finalize().into();
        Ok(verified)
    }
}

fn builtin_history_kind(kind: &str) -> bool {
    matches!(
        kind,
        "demotion" | "trust_decision" | "ticket" | "busbar.admin-idempotency"
    )
}
fn builtin_history(
    record: busbar_contract::records::PlaneRecordRef<'_>,
    append: Option<bool>,
) -> Result<Option<super::CanonicalRows>, Error> {
    if !builtin_history_kind(record.kind) {
        return Ok(None);
    }
    if append != Some(false) || record.seq != 0 || record.parent.is_some() {
        return Err(Error::Verification);
    }
    Ok(Some(match record.kind {
        "demotion" | "trust_decision" => {
            vec![
                records::trust::migration_trust_rows(record.kind, record.id, record.body)
                    .map_err(|_| Error::Verification)?,
            ]
        }
        "ticket" => {
            if record.disposition != busbar_contract::records::PlaneDisposition::Active {
                return Err(Error::Verification);
            }
            vec![
                records::ticket::legacy_ticket_record(record.id, record.ts, record.body)
                    .map_err(|_| Error::Verification)?,
                records::ticket::legacy_ticket_expiry(record.id, record.ts)
                    .map_err(|_| Error::Verification)?,
            ]
        }
        "busbar.admin-idempotency" => vec![(
            records::scoped::migration_address(
                true,
                "busbar.admin",
                record.kind,
                record.id.as_bytes(),
            )
            .map_err(|_| Error::Verification)?,
            Secret::new(record.body.to_vec()),
        )],
        _ => return Err(Error::Corrupt),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceReader as _;
    use busbar_contract::records::PlaneDisposition;
    fn history(kind: &str, id: &str, body: &[u8]) -> HistoricalFact {
        HistoricalFact::History {
            kind: kind.into(),
            id: id.into(),
            parent: None,
            sequence: 0,
            timestamp: 17,
            disposition: PlaneDisposition::Active,
            body: Secret::new(body.to_vec()),
            append: Some(false),
        }
    }
    #[tokio::test]
    async fn core_owned_historical_records_keep_routes_and_exact_readback() {
        let ticket = "0123456789abcdef0123456789abcdef";
        let body = b"original opaque consumer body";
        let demotion = br#"{"server":"upstream","reason":"held","recorded_at":17}"#;
        let source = crate::source_facts::test_archive(
            vec![
                history("ticket", ticket, body),
                history("busbar.admin-idempotency", "request", body),
                history("demotion", "upstream", demotion),
                HistoricalFact::Token {
                    kind: "ticket-spent".into(),
                    token: Secret::new(ticket.as_bytes().to_vec()),
                    expires_at: 17,
                },
            ],
            1 << 20,
        );
        let mut identity = source.identity();
        // This logical fixture has no native binding; the production binding
        // selects the admitted catalogue identity before constructing routes.
        identity.schema_digest = source.header().catalogue_digest;
        let provenance = archive::Provenance {
            dataset: identity.dataset,
            catalogue: identity.schema_digest,
        };
        let bounds = Bounds {
            items: 32,
            bytes: 1 << 20,
        };
        let transform = FactTransform::registered(
            identity.format,
            provenance,
            &source.header().tables,
            source.interpretation().unwrap().clone(),
            crate::routes::Bindings::default(),
            bounds,
        )
        .unwrap()
        .with_projection(source.clone())
        .unwrap();
        let family = transform
            .edge()
            .families
            .iter()
            .find(|f| f.id == ARCHIVAL)
            .unwrap();
        let page = source
            .page(&source.snapshot(), family, 0, bounds)
            .await
            .unwrap();
        assert!(page.complete);
        let output = transform.transform(family, &page.records, bounds).unwrap();
        let expected = [
            records::ticket::legacy_ticket_record(ticket, 17, body).unwrap(),
            records::ticket::legacy_ticket_expiry(ticket, 17).unwrap(),
            records::ticket::legacy_ticket_token("ticket-spent", ticket, 17).unwrap(),
            records::trust::migration_trust_rows("demotion", "upstream", demotion).unwrap(),
            (
                records::scoped::migration_address(
                    true,
                    "busbar.admin",
                    "busbar.admin-idempotency",
                    b"request",
                )
                .unwrap(),
                Secret::new(body.to_vec()),
            ),
        ];
        assert_eq!(output.len(), expected.len());
        for (address, value) in expected {
            assert!(output
                .iter()
                .any(|row| row.address == address && row.value == value));
        }
        let mut native = output
            .into_iter()
            .map(|row| (row.address, row.value))
            .collect::<Vec<_>>();
        let proofs = CompleteAuditProofs::from_complete_facts(provenance, vec![], 0).unwrap();
        transform
            .verify_page(&identity, family, &page.records, bounds, &native, &proofs)
            .unwrap();
        native[0].1 = Secret::new(vec![0]);
        assert!(matches!(
            transform.verify_page(&identity, family, &page.records, bounds, &native, &proofs),
            Err(Error::Verification)
        ));
    }
    #[test]
    fn builtin_history_keeps_parent_append_and_terminal_refusals() {
        let base = busbar_contract::records::PlaneRecordRef {
            kind: "ticket",
            id: "0123456789abcdef0123456789abcdef",
            parent: None,
            seq: 0,
            ts: 17,
            disposition: PlaneDisposition::Active,
            body: b"original",
        };
        assert!(builtin_history(base, Some(false)).unwrap().is_some());
        assert!(matches!(
            builtin_history(base, Some(true)),
            Err(Error::Verification)
        ));
        assert!(matches!(
            builtin_history(
                busbar_contract::records::PlaneRecordRef {
                    parent: Some("parent"),
                    ..base
                },
                Some(false)
            ),
            Err(Error::Verification)
        ));
        assert!(matches!(
            builtin_history(
                busbar_contract::records::PlaneRecordRef {
                    disposition: PlaneDisposition::Terminal,
                    ..base
                },
                Some(false)
            ),
            Err(Error::Verification)
        ));
    }
}
