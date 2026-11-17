// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE RECORD-FORMAT MIGRATION OWNER (#319 r4 §5-§9).
//!
//! A dataset whose records are at an older format is opened (or claimed) by [`super::startup`]
//! in one transaction that advances the dataset epoch and names a fresh migration owner in the
//! manifest's registrar field. Every writer of the old epoch is fenced at its next commit. This
//! type is that owner's only handle: record reads and page commits under its own authority
//! ([`MigrationOwner::access`]), and the final publication ([`MigrationOwner::finalize`]). It
//! exposes no serving store and no host service: ordinary admission begins only after the final
//! publication, by a fresh reinspection.
//!
//! The conversion itself is the migration library's (`busbar_migrate::records::evolve_with`), driven
//! by the composition root; the kernel owns authority and custody and never names that library.

use std::sync::Arc;

use busbar_contract::persistence::{
    control, Decision, ExpectedValue, Failure, NamespaceId, PersistenceBackend, Predicate,
};
use busbar_contract::Secret;

use super::commit::{Attempt, NoEffectCause, SubmitResult};
use super::facade::{CoreStore, WriterAuthority};
use super::import_target::r0::{Access, Commit, Outcome};
use super::startup::{
    dataset_put, exact, manifest_address, open_writer, prepare, random_id, root_address,
    writer_address, Manifest, RECORD_FORMAT,
};

/// How many times the final publication's one original attempt is sent again while its outcome
/// is in doubt, before the boot stops non-serving (the next boot reinspects; the publication's
/// witness, the fresh registrar's writer row, resolves a lost reply).
const IN_DOUBT_RETRIES: usize = 4;

/// The migration owner of one dataset, attached under the authority its opening or claim
/// installed. See the module documentation.
pub struct MigrationOwner {
    backend: Arc<dyn PersistenceBackend>,
    store: Arc<CoreStore>,
    manifest: Manifest,
    bytes: Vec<u8>,
    from: u32,
}

impl MigrationOwner {
    pub(super) fn new(
        backend: Arc<dyn PersistenceBackend>,
        store: Arc<CoreStore>,
        manifest: Manifest,
        bytes: Vec<u8>,
        from: u32,
    ) -> Self {
        Self {
            backend,
            store,
            manifest,
            bytes,
            from,
        }
    }

    /// The manifest's namespace and key; the step cursor lives beside it.
    #[must_use]
    pub fn manifest_at() -> (NamespaceId, Vec<u8>) {
        let address = manifest_address();
        (NamespaceId(address.namespace), address.key)
    }

    /// The manifest exactly as read when this owner attached.
    #[must_use]
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The format the records were at when this owner attached.
    #[must_use]
    pub fn format(&self) -> u32 {
        self.from
    }

    /// The step under way when this owner attached: `format() + 1`.
    #[must_use]
    pub fn migrating_to(&self) -> u32 {
        self.from + 1
    }

    /// This owner's manifest at `(format, tail)`: the bytes an intermediate step completion
    /// writes (the registrar, this owner, is unchanged until the final publication).
    #[must_use]
    pub fn encode_manifest(&self, format: u32, tail: u32) -> Vec<u8> {
        self.manifest.encode_at(format, tail).to_vec()
    }

    /// Record scans, reads and page commits under this owner's authority: slotted custody, the
    /// dataset epoch and this owner's execution epoch fenced on every commit.
    #[must_use]
    pub fn access(&self) -> Access {
        Access::new(self.store.clone())
    }

    /// THE FINAL PUBLICATION (#319 r4 §9): `commit` (the last step's zero-payload completion:
    /// exact on the manifest and the cursor, the cursor deleted, its RECORDS_EVOLVED evidence)
    /// together with a fresh ordinary registrar `a`, the dataset epoch advanced past this owner
    /// (fencing it in the same transaction that advertises Current) and the manifest at
    /// `(format, 0)` naming `a`. Stamped by this owner; witnessed by `a`'s fresh writer row, so a
    /// lost reply resolves to the original transaction's outcome and never a second publication.
    /// `a` is the persistent registrar only: ordinary admission registers its own process writer
    /// after reinspection.
    ///
    /// # Errors
    /// A `format` other than this kernel's, a `commit` that writes the manifest itself, an exhausted
    /// epoch or entropy, or an outcome still in doubt or needing reconciliation.
    pub async fn finalize(&self, commit: Commit, format: u32) -> Result<Outcome, String> {
        if format != RECORD_FORMAT {
            return Err(format!(
                "the final publication names format {format}; this busbar writes {RECORD_FORMAT}"
            ));
        }
        let manifest = manifest_address();
        if commit.put.iter().any(|(address, _)| *address == manifest)
            || commit.delete.contains(&manifest)
        {
            return Err("the final publication's completion writes the manifest itself".into());
        }
        let dataset = self.manifest.dataset;
        let owner = self.manifest.registrar;
        let epoch = owner
            .writer_epoch
            .checked_add(1)
            .ok_or("the dataset's writer epoch is exhausted")?;
        let registrar = WriterAuthority {
            writer_epoch: epoch,
            writer: random_id().map_err(|error| format!("{error:?}"))?,
            execution_epoch: 1,
        };
        let root = control::Dataset {
            id: dataset,
            writer_epoch: owner.writer_epoch,
        }
        .encode()
        .ok_or("the dataset root does not encode")?;
        let owner_row = open_writer()
            .encode()
            .ok_or("the owner's writer row does not encode")?;
        let registrar_rows = control::writer_put(registrar.writer, None, open_writer())
            .ok_or("the registrar's writer row does not encode")?;
        let (mut predicates, mut mutations) = commit.parts();
        predicates.push(exact(root_address(), root.to_vec()));
        predicates.push(exact(writer_address(owner.writer), owner_row.to_vec()));
        predicates.push(Predicate {
            address: writer_address(registrar.writer),
            expected: ExpectedValue::Absent,
        });
        mutations.push(dataset_put(dataset, epoch).map_err(|error| format!("{error:?}"))?);
        mutations.push(busbar_contract::persistence::Mutation::Put {
            address: manifest,
            value: Secret::new(
                Manifest { dataset, registrar }
                    .encode_at(format, 0)
                    .to_vec(),
            ),
        });
        mutations.extend(registrar_rows);
        let candidate = prepare(self.manifest, predicates, mutations).map_err(|error| {
            format!("the final publication is not a valid candidate: {error:?}")
        })?;
        let attempt = Attempt::proven(candidate, self.backend.clone())
            .map_err(|error| format!("the final publication has no witness: {error:?}"))?;
        let mut result = attempt.submit().await;
        for _ in 0..IN_DOUBT_RETRIES {
            match result {
                SubmitResult::Uncertain | SubmitResult::Busy => result = attempt.submit().await,
                _ => break,
            }
        }
        match result {
            SubmitResult::Decided(decision) => match decision.as_ref() {
                Decision::Applied(_) => Ok(Outcome::Applied),
                Decision::ConditionConflict => Ok(Outcome::Conflict),
                Decision::Fenced => Ok(Outcome::Fenced),
                other => Err(format!("the final publication was not applied: {other:?}")),
            },
            SubmitResult::NoEffect(failure) => match attempt.no_effect_cause() {
                Some(NoEffectCause::Backend(Failure::Refused)) => Ok(Outcome::Refused),
                cause => Err(format!(
                    "the store applied nothing of the final publication: {failure:?} ({cause:?})"
                )),
            },
            SubmitResult::Uncertain | SubmitResult::Busy | SubmitResult::Reconcile => Err(
                "the final publication is still in doubt; the next boot reinspects it".to_owned(),
            ),
        }
    }
}
