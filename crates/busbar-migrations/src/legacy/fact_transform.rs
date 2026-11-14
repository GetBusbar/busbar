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
use busbar_contract::crypto::Sha256;
use busbar_contract::{
    persistence::{archive::Table, lifecycle::source::HistoricalFact, Address},
    Secret,
};
use busbar_kernel::persistence::import_target::records;
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
    projection: Option<Arc<dyn projection::ProjectionSource>>,
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
        let edge = registered_edge(source, hash.finish(), families, bounds)?;
        Ok(Self {
            edge,
            provenance,
            view,
            original_tables,
            fact_table,
            projection: None,
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
            hash.finish(),
            families,
            self.edge.bounds,
        )?;
        self.overlay = Some(overlay);
        Ok(self)
    }
    pub fn registry(&self) -> Result<Registry, super::super::Error> {
        Registry::new(vec![self.edge.clone()])
    }
    pub(crate) fn matches_source(&self, source: &super::super::Identity) -> bool {
        source.dataset == self.provenance.dataset
            && source.schema_digest == self.provenance.catalogue
            && source.format == self.edge.source
    }
    pub fn descriptor(&self) -> &Edge {
        &self.edge
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
            ARCHIVAL => self.archival(facts, &mut out)?,
            _ => return Err(Error::UnsupportedPath),
        }
        Ok(out.finish())
    }
    /// A released source carries only exact evidence and the core-owned config
    /// overlay in this family. Grouping already refuses records, histories,
    /// tokens and receipts written by an unreleased 1.6.0-dev build.
    fn archival(&self, facts: &[FactRow], out: &mut Output) -> Result<(), Error> {
        let seal = crate::seal::lend();
        for fact in facts {
            match fact.fact() {
                HistoricalFact::Record { schema, key, value }
                    if schema == super::overlay::SCHEMA =>
                {
                    let archive::Route::Record { address, value } =
                        archive::route_record(schema, key.expose(&seal), value.expose(&seal), &[])
                            .map_err(invalid)?
                    else {
                        return Err(Error::MissingCapability);
                    };
                    if self
                        .overlay
                        .as_ref()
                        .is_some_and(|overlay| overlay.replaces(&address))
                    {
                        continue;
                    }
                    out.put(address, Secret::new(value.to_vec()), None, false)?;
                }
                HistoricalFact::EvidenceOnly => {}
                _ => return Err(Error::UnsupportedPath),
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
            ARCHIVAL => busbar_kernel::persistence::import_target::records::scoped::migration_authorizes(
                true,
                "busbar.config.overlay",
                super::overlay::SCHEMA,
                address,
            ),
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
            for fact in self.load(family, marker)? {
                if let HistoricalFact::Audit(record) = fact.fact() {
                    let proof = proofs.historical_audit(self.provenance, record)?;
                    if proof == [0; 32] {
                        return Err(Error::Verification);
                    }
                    hash_field(&mut semantic, &proof);
                }
            }
        }
        verified.semantics_digest = semantic.finish();
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SourceReader as _;
    #[tokio::test]
    async fn many_admitted_fragments_fit_one_bounded_native_output() {
        use busbar_contract::{
            persistence::lifecycle::source::{AccountingRole, RequestAggregation},
            records::{ModelTokens, UsageLedger},
        };
        use std::collections::BTreeMap;
        fn facts() -> Vec<HistoricalFact> {
            (0..6)
                .map(|ordinal| {
                    let model = if ordinal == 0 {
                        String::new()
                    } else {
                        format!("m{ordinal}")
                    };
                    HistoricalFact::Usage {
                        bucket: "bucket".into(),
                        window: 0,
                        model: model.clone(),
                        requests: RequestAggregation::Dedicated,
                        role: AccountingRole::Fragment,
                        ledger: UsageLedger {
                            requests: if ordinal == 0 { 4 } else { 0 },
                            billable_requests: if ordinal == 0 { 3 } else { 0 },
                            models: if ordinal == 0 {
                                vec![]
                            } else {
                                vec![ModelTokens {
                                    scale: 6,
                                    model,
                                    usage_units: BTreeMap::from([("input".into(), 7_000_000)]),
                                }]
                            },
                        },
                    }
                })
                .collect()
        }
        for (semantic, expected_success) in [(1 << 20, true), (16_384, false)] {
            let source = crate::source_facts::test_archive(facts(), semantic);
            let identity = source.identity();
            let bounds = Bounds {
                items: 2,
                bytes: 1 << 20,
            };
            let transform = FactTransform::registered(
                identity.format,
                archive::Provenance {
                    dataset: identity.dataset,
                    catalogue: source.header().catalogue_digest,
                },
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
                .find(|f| f.id == ACCOUNTING)
                .unwrap();
            let page = source
                .page(&source.snapshot(), family, 0, bounds)
                .await
                .unwrap();
            assert!(page.complete);
            assert_eq!(page.records.len(), 1);
            let result = transform.transform(family, &page.records, bounds);
            if !expected_success {
                assert!(matches!(result, Err(Error::Bounds)));
                continue;
            }
            let rows = result.unwrap();
            assert_eq!(rows.len(), 2);
            let ledger = UsageLedger {
                requests: 4,
                billable_requests: 3,
                models: (1..6)
                    .map(|n| ModelTokens {
                        scale: 6,
                        model: format!("m{n}"),
                        usage_units: BTreeMap::from([("input".into(), 7_000_000)]),
                    })
                    .collect(),
            };
            assert_eq!(ledger.total_input(), 35_000_000);
            for (address, value) in super::super::canonical_usage("bucket", 0, &ledger).unwrap() {
                assert!(rows
                    .iter()
                    .any(|r| r.address == address && r.value == value));
            }
        }
    }
}
