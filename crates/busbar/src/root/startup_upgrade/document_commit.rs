// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Publication of already normalized documents under a protected native checkpoint.
//! File failures never reverse the selected Store generation. No original is copied to disk.
use super::documents::{Documents, Publication, SecretPublication};
use busbar_contract::Secret;
use busbar_kernel::durable::{DocumentInspection, DocumentReplace, DurableFs};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
};
use zeroize::Zeroizing;

pub type CheckpointCall<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;
/// The adapter uses one exact native checkpoint candidate and previous-value predicate.
/// Unknown/cancellation retains that candidate. `confirm` returns authoritative readback only
/// after matching Applied, with the protected original payload unchanged. It never returns a bool.
pub trait Checkpoints: Send + Sync {
    fn durability(&self) -> busbar_contract::persistence::Durability;
    fn load(&self, migration: [u8; 16]) -> CheckpointCall<'_, Option<Secret<Vec<u8>>>>;
    fn confirm<'a>(
        &'a self,
        migration: [u8; 16],
        protected: &'a Secret<Vec<u8>>,
    ) -> CheckpointCall<'a, Secret<Vec<u8>>>;
    /// Atomically confirm the final protected payload and clear only this locator.
    /// Protected originals remain retained under the upgrade retention policy.
    fn complete<'a>(
        &'a self,
        migration: [u8; 16],
        protected: &'a Secret<Vec<u8>>,
    ) -> CheckpointCall<'a, Secret<Vec<u8>>>;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Intent,
    Validated,
    PendingReplace(u32),
    Published(u32),
    Deferred(u32),
    Complete,
}
struct Document {
    publication: Publication,
    metadata: Option<Zeroizing<Vec<u8>>>,
    read_only: bool,
}
pub struct Inventory {
    documents: Vec<Document>,
    secrets: Vec<SecretPublication>,
    digest: [u8; 32],
}
/// Constructed only after the checkpoint adapter confirms and returns exact native bytes.
pub struct IntentProof {
    migration: [u8; 16],
    digest: [u8; 32],
    phase: Phase,
}
pub struct EphemeralIntentProof {
    digest: [u8; 32],
}
/// Read-only access to checkpoint material, constructed only from confirmed custody.
pub struct RestoredDocuments<'a> {
    inventory: &'a Inventory,
    phase: Phase,
}
impl RestoredDocuments<'_> {
    pub fn publications(&self) -> impl Iterator<Item = &Publication> {
        self.inventory
            .documents
            .iter()
            .map(|held| &held.publication)
    }
    pub fn secrets(&self) -> impl Iterator<Item = &SecretPublication> {
        self.inventory.secrets.iter()
    }
    pub fn recoverable_missing(&self, path: &Path) -> bool {
        let Phase::PendingReplace(index) = self.phase else {
            return false;
        };
        self.inventory
            .documents
            .get(index as usize)
            .is_some_and(|held| {
                held.publication.path == path
                    && held.metadata.is_some()
                    && !held.publication.locked
                    && !held.read_only
            })
    }
}
/// Only the startup validation owner calls `validated`, after its actual candidate is validated.
/// This proof is distinct from the earlier intent that authorizes private secret artifacts.
pub struct ValidatedProof {
    migration: [u8; 16],
    digest: [u8; 32],
    phase: Phase,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOutcome {
    Published,
    AlreadyConverted,
    InMemoryOnly,
}
pub struct FileReport {
    pub path: PathBuf,
    pub outcome: FileOutcome,
}
pub struct Report {
    pub files: Vec<FileReport>,
    /// False keeps a native replacement's security and namespace recovery authority pending.
    pub complete: bool,
}
/// A host/location locator is stable across partial conversion and excludes document contents.
/// The caller supplies its existing stable host identity, never a boot-random node identifier.
pub fn custody_locator(documents: &Documents, host: &str) -> Result<[u8; 32], String> {
    if host.is_empty() {
        return Err("document custody requires a stable host identity".into());
    }
    let mut paths = documents
        .pending()?
        .into_iter()
        .map(|p| {
            std::path::absolute(p.path)
                .map_err(|_| "document location cannot be resolved".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.dedup();
    let mut hash = Sha256::new();
    hash.update(b"busbar.startup.document-locator.1\0");
    hash.update((host.len() as u64).to_le_bytes());
    hash.update(host.as_bytes());
    for path in paths {
        let bytes = path_bytes(&path);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    Ok(hash.finalize().into())
}
const MAGIC: &[u8; 8] = b"BBCDOC01";
fn failure() -> String {
    "protected document checkpoint is invalid or changed".into()
}
fn put(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    let size = u32::try_from(value.len()).map_err(|_| failure())?;
    out.try_reserve(4 + value.len())
        .map_err(|_| "document checkpoint allocation refused")?;
    out.extend_from_slice(&size.to_le_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn count(out: &mut Vec<u8>, n: usize) -> Result<(), String> {
    out.extend_from_slice(&u32::try_from(n).map_err(|_| failure())?.to_le_bytes());
    Ok(())
}
fn path_bytes(path: &Path) -> Vec<u8> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        path.as_os_str()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect()
    }
    #[cfg(not(windows))]
    {
        path.as_os_str().as_encoded_bytes().to_vec()
    }
}
fn path_from(bytes: &[u8]) -> Result<PathBuf, String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Ok(std::ffi::OsString::from_vec(bytes.to_vec()).into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt;
        if !bytes.len().is_multiple_of(2) {
            return Err(failure());
        }
        Ok(std::ffi::OsString::from_wide(
            &bytes
                .chunks_exact(2)
                .map(|v| u16::from_le_bytes([v[0], v[1]]))
                .collect::<Vec<_>>(),
        )
        .into())
    }
    #[cfg(not(any(unix, windows)))]
    {
        Ok(std::str::from_utf8(bytes).map_err(|_| failure())?.into())
    }
}
fn platform() -> u8 {
    if cfg!(windows) {
        2
    } else if cfg!(unix) {
        1
    } else {
        3
    }
}
struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let bytes = self.0.get(..n).ok_or_else(failure)?;
        self.0 = &self.0[n..];
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| failure())?,
        ))
    }
    fn field(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.take(n)
    }
    fn string(&mut self) -> Result<String, String> {
        String::from_utf8(self.field()?.to_vec()).map_err(|_| failure())
    }
    fn path(&mut self) -> Result<PathBuf, String> {
        path_from(self.field()?)
    }
}
impl Inventory {
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    fn capture(documents: &Documents, fs: &dyn DurableFs) -> Result<Self, String> {
        let mut captured = Vec::new();
        for publication in documents.pending()? {
            if Sha256::digest(&publication.original).as_slice() != publication.original_digest
                || Sha256::digest(&publication.converted).as_slice() != publication.target_digest
            {
                return Err(failure());
            }
            let (metadata, read_only) = match fs.inspect_document(
                &publication.path,
                &publication.original,
                &publication.converted,
            ) {
                Ok(DocumentInspection::Original {
                    metadata,
                    read_only,
                }) => (Some(metadata), read_only),
                Ok(DocumentInspection::Converted) => (None, false),
                Ok(DocumentInspection::Changed | DocumentInspection::Missing) => {
                    return Err(
                        "configuration changed before its migration intent was confirmed".into(),
                    );
                }
                Err(_) => (None, true),
            };
            captured.push(Document {
                publication,
                metadata,
                read_only,
            });
        }
        captured.sort_by(|a, b| a.publication.path.cmp(&b.publication.path));
        let mut secrets = documents.pending_secrets()?;
        secrets.sort_by(|a, b| a.path.cmp(&b.path));
        let mut inventory = Self {
            documents: captured,
            secrets,
            digest: [0; 32],
        };
        inventory.check()?;
        inventory.digest = Sha256::digest(&inventory.material()?).into();
        Ok(inventory)
    }
    fn check(&self) -> Result<(), String> {
        for pair in self.documents.windows(2) {
            if pair[0].publication.path >= pair[1].publication.path {
                return Err(failure());
            }
        }
        for pair in self.secrets.windows(2) {
            if pair[0].path >= pair[1].path {
                return Err(failure());
            }
        }
        for document in &self.documents {
            let p = &document.publication;
            if Sha256::digest(&p.original).as_slice() != p.original_digest
                || Sha256::digest(&p.converted).as_slice() != p.target_digest
            {
                return Err(failure());
            }
        }
        for secret in &self.secrets {
            if !self
                .documents
                .iter()
                .any(|d| d.publication.path == secret.config_path)
                || crate::root::loader::migration_secrets::externalized_path(
                    &secret.config_path,
                    &secret.site,
                    &secret.settings_path,
                )? != secret.path
            {
                return Err(failure());
            }
        }
        Ok(())
    }
    fn material(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(vec![platform()]);
        count(&mut out, self.documents.len())?;
        for document in &self.documents {
            let p = &document.publication;
            put(&mut out, &path_bytes(&p.path))?;
            out.extend_from_slice(&p.original_digest);
            out.extend_from_slice(&p.target_digest);
            out.extend_from_slice(&p.transform_id);
            out.push(u8::from(p.locked));
            out.push(u8::from(document.read_only));
            match &document.metadata {
                Some(bytes) => {
                    out.push(1);
                    put(&mut out, bytes)?;
                }
                None => out.push(0),
            };
            put(&mut out, &p.original)?;
            put(&mut out, &p.converted)?;
        }
        count(&mut out, self.secrets.len())?;
        for secret in &self.secrets {
            put(&mut out, &path_bytes(&secret.config_path))?;
            put(&mut out, secret.site.as_bytes())?;
            count(&mut out, secret.settings_path.len())?;
            for part in &secret.settings_path {
                put(&mut out, part.as_bytes())?;
            }
            put(&mut out, &secret.bytes)?;
            put(&mut out, &path_bytes(&secret.path))?;
        }
        Ok(out)
    }
    fn encoded(&self, migration: [u8; 16], phase: Phase) -> Result<Secret<Vec<u8>>, String> {
        let mut out = Zeroizing::new(MAGIC.to_vec());
        out.extend_from_slice(&migration);
        out.extend_from_slice(&self.digest);
        let (tag, index) = match phase {
            Phase::Intent => (0, 0),
            Phase::Validated => (1, 0),
            Phase::PendingReplace(i) => (2, i),
            Phase::Published(i) => (3, i),
            Phase::Deferred(i) => (4, i),
            Phase::Complete => (5, 0),
        };
        out.push(tag);
        out.extend_from_slice(&index.to_le_bytes());
        out.extend_from_slice(&self.material()?);
        Ok(Secret::new(std::mem::take(&mut *out)))
    }
    fn decode(protected: &Secret<Vec<u8>>, migration: [u8; 16]) -> Result<(Self, Phase), String> {
        let seal = busbar_kernel::seal::lend();
        let bytes = protected.expose(&seal);
        let mut r = Reader(bytes);
        if r.take(8)? != MAGIC || r.take(16)? != migration {
            return Err(failure());
        }
        let digest: [u8; 32] = r.take(32)?.try_into().map_err(|_| failure())?;
        let tag = r.take(1)?[0];
        let index = r.u32()?;
        let phase = match (tag, index) {
            (0, 0) => Phase::Intent,
            (1, 0) => Phase::Validated,
            (2, i) => Phase::PendingReplace(i),
            (3, i) => Phase::Published(i),
            (4, i) => Phase::Deferred(i),
            (5, 0) => Phase::Complete,
            _ => return Err(failure()),
        };
        let material = r.0;
        if Sha256::digest(material).as_slice() != digest || r.take(1)?[0] != platform() {
            return Err(failure());
        }
        let n = r.u32()? as usize;
        if n > r.0.len() / 110 {
            return Err(failure());
        }
        let mut documents = Vec::new();
        documents.try_reserve(n).map_err(|_| failure())?;
        for _ in 0..n {
            let path = r.path()?;
            let original_digest = r.take(32)?.try_into().map_err(|_| failure())?;
            let target_digest = r.take(32)?.try_into().map_err(|_| failure())?;
            let transform_id = r.take(32)?.try_into().map_err(|_| failure())?;
            let locked = match r.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(failure()),
            };
            let read_only = match r.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(failure()),
            };
            let metadata = match r.take(1)?[0] {
                0 => None,
                1 => Some(Zeroizing::new(r.field()?.to_vec())),
                _ => return Err(failure()),
            };
            let original = Zeroizing::new(r.field()?.to_vec());
            let converted = Zeroizing::new(r.field()?.to_vec());
            documents.push(Document {
                publication: Publication {
                    path,
                    original,
                    converted,
                    original_digest,
                    target_digest,
                    transform_id,
                    locked,
                },
                metadata,
                read_only,
            });
        }
        let n = r.u32()? as usize;
        if n > r.0.len() / 20 {
            return Err(failure());
        }
        let mut secrets = Vec::new();
        secrets.try_reserve(n).map_err(|_| failure())?;
        for _ in 0..n {
            let config_path = r.path()?;
            let site = r.string()?;
            let count = r.u32()? as usize;
            if count > r.0.len() / 4 {
                return Err(failure());
            }
            let mut settings_path = Vec::new();
            settings_path.try_reserve(count).map_err(|_| failure())?;
            for _ in 0..count {
                settings_path.push(r.string()?);
            }
            let bytes = Zeroizing::new(r.field()?.to_vec());
            let path = r.path()?;
            secrets.push(SecretPublication {
                config_path,
                site,
                settings_path,
                bytes,
                path,
            });
        }
        if !r.0.is_empty()
            || matches!(phase,Phase::PendingReplace(i)|Phase::Published(i)|Phase::Deferred(i) if i as usize>=documents.len())
        {
            return Err(failure());
        }
        let inventory = Self {
            documents,
            secrets,
            digest,
        };
        inventory.check()?;
        Ok((inventory, phase))
    }
    fn recognizes(&self, documents: &Documents) -> Result<(), String> {
        let current = documents.pending()?;
        if current.len() != self.documents.len() {
            return Err("document inventory changed during startup upgrade".into());
        }
        for document in current {
            let held = self
                .documents
                .iter()
                .find(|held| held.publication.path == document.path)
                .ok_or_else(failure)?;
            let original = document.original.as_slice();
            if (original != held.publication.original.as_slice()
                && original != held.publication.converted.as_slice())
                || document.converted.as_slice() != held.publication.converted.as_slice()
            {
                return Err("configuration was edited outside its retained startup upgrade".into());
            }
        }
        for secret in documents.pending_secrets()? {
            if !self.secrets.iter().any(|held| {
                held.path == secret.path
                    && held.bytes.as_slice() == secret.bytes.as_slice()
                    && held.site == secret.site
                    && held.settings_path == secret.settings_path
            }) {
                return Err("configuration secret binding changed during startup upgrade".into());
            }
        }
        Ok(())
    }
    async fn confirm(
        &self,
        checkpoints: &dyn Checkpoints,
        migration: [u8; 16],
        phase: Phase,
    ) -> Result<(), String> {
        let payload = self.encoded(migration, phase)?;
        let observed = if phase == Phase::Complete {
            checkpoints.complete(migration, &payload).await?
        } else {
            checkpoints.confirm(migration, &payload).await?
        };
        let seal = busbar_kernel::seal::lend();
        if payload.expose(&seal) != observed.expose(&seal) {
            return Err("document checkpoint readback differs from its exact candidate".into());
        }
        let (_, actual) = Self::decode(&observed, migration)?;
        if actual != phase {
            return Err(failure());
        }
        Ok(())
    }
    /// Load the retained original inventory on restart, recognizing only original or converted files.
    /// Otherwise capture the complete inventory and confirm its protected intent before artifacts.
    pub async fn prepare(
        documents: &Documents,
        fs: &dyn DurableFs,
        checkpoints: &dyn Checkpoints,
        migration: [u8; 16],
    ) -> Result<(Self, IntentProof), String> {
        if checkpoints.durability() == busbar_contract::persistence::Durability::Ephemeral {
            return Err(
                "ephemeral Store acknowledgement cannot authorize replacing authored documents"
                    .into(),
            );
        }
        let (inventory, phase) = if let Some(loaded) = checkpoints.load(migration).await? {
            let (inventory, phase) = Self::decode(&loaded, migration)?;
            documents.restore_from_checkpoint(RestoredDocuments {
                inventory: &inventory,
                phase,
            })?;
            inventory.recognizes(documents)?;
            (inventory, phase)
        } else {
            let inventory = Self::capture(documents, fs)?;
            inventory
                .confirm(checkpoints, migration, Phase::Intent)
                .await?;
            (inventory, Phase::Intent)
        };
        let proof = IntentProof {
            migration,
            digest: inventory.digest,
            phase,
        };
        Ok((inventory, proof))
    }
    /// Private retry-safe artifacts may be materialized after intent Applied, before full App validation.
    pub fn materialize_secrets(&self, proof: &IntentProof) -> Result<(), String> {
        if proof.digest != self.digest {
            return Err(failure());
        }
        self.materialize_artifacts()
    }
    /// Ephemeral deployments keep authored originals intact and retain only wiping memory intent.
    pub fn prepare_ephemeral(
        documents: &Documents,
        fs: &dyn DurableFs,
    ) -> Result<(Self, EphemeralIntentProof), String> {
        let inventory = Self::capture(documents, fs)?;
        let proof = EphemeralIntentProof {
            digest: inventory.digest,
        };
        Ok((inventory, proof))
    }
    pub fn materialize_ephemeral_secrets(
        &self,
        proof: &EphemeralIntentProof,
    ) -> Result<(), String> {
        if proof.digest != self.digest {
            return Err(failure());
        }
        self.materialize_artifacts()
    }
    pub fn ephemeral_report(&self, proof: &EphemeralIntentProof) -> Result<Report, String> {
        if proof.digest != self.digest {
            return Err(failure());
        }
        Ok(Report {
            complete: true,
            files: self
                .documents
                .iter()
                .map(|held| FileReport {
                    path: held.publication.path.clone(),
                    outcome: FileOutcome::InMemoryOnly,
                })
                .collect(),
        })
    }
    fn materialize_artifacts(&self) -> Result<(), String> {
        for secret in &self.secrets {
            let actual = crate::root::loader::migration_secrets::externalize(
                &secret.config_path,
                &secret.site,
                &secret.settings_path,
                &secret.bytes,
            )
            .map_err(|_| "protected startup credential artifact could not be materialized")?;
            if Path::new(&actual) != secret.path {
                return Err("credential artifact path differs from its protected intent".into());
            }
        }
        Ok(())
    }
    /// Invoke only after the actual selected target and candidate App pass their validation boundary.
    pub async fn validated(
        &self,
        proof: IntentProof,
        checkpoints: &dyn Checkpoints,
    ) -> Result<ValidatedProof, String> {
        if proof.digest != self.digest {
            return Err(failure());
        }
        let phase = if proof.phase == Phase::Intent {
            self.confirm(checkpoints, proof.migration, Phase::Validated)
                .await?;
            Phase::Validated
        } else {
            proof.phase
        };
        Ok(ValidatedProof {
            migration: proof.migration,
            digest: proof.digest,
            phase,
        })
    }
    pub async fn publish(
        &self,
        proof: ValidatedProof,
        checkpoints: &dyn Checkpoints,
        fs: &dyn DurableFs,
        documents: &Documents,
    ) -> Result<Report, String> {
        if proof.digest != self.digest {
            return Err(failure());
        }
        let mut report = Report {
            files: Vec::new(),
            complete: false,
        };
        let mut phase = proof.phase;
        for (index, document) in self.documents.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| failure())?;
            let p = &document.publication;
            let observed = fs.inspect_document(&p.path, &p.original, &p.converted);
            let missing = matches!(observed, Ok(DocumentInspection::Missing));
            let outcome = match observed {
                Ok(DocumentInspection::Changed) => {
                    return Err(
                        "configuration changed after target validation; serving remains blocked"
                            .into(),
                    );
                }
                Ok(DocumentInspection::Missing) if phase != Phase::PendingReplace(index) => {
                    return Err(
                        "configuration disappeared without its retained replacement intent".into(),
                    );
                }
                Ok(DocumentInspection::Converted) if phase != Phase::PendingReplace(index) => {
                    documents.mark_published(p)?;
                    FileOutcome::AlreadyConverted
                }
                Ok(DocumentInspection::Original { .. })
                    if p.locked || document.read_only || document.metadata.is_none() =>
                {
                    FileOutcome::InMemoryOnly
                }
                Err(_) => FileOutcome::InMemoryOnly,
                _ => {
                    let Some(metadata) = document.metadata.as_ref() else {
                        return Err("replacement recovery lacks original security metadata".into());
                    };
                    if phase != Phase::PendingReplace(index) {
                        self.confirm(checkpoints, proof.migration, Phase::PendingReplace(index))
                            .await?;
                    }
                    let result = if missing {
                        fs.recover_document(&p.path, &p.converted, metadata)
                    } else {
                        fs.replace_document(&p.path, &p.original, &p.converted, metadata)
                    };
                    match result {
                        Ok(DocumentReplace::Published) => {
                            documents.mark_published(p)?;
                            FileOutcome::Published
                        }
                        Ok(DocumentReplace::AlreadyConverted) => {
                            documents.mark_published(p)?;
                            FileOutcome::AlreadyConverted
                        }
                        Ok(DocumentReplace::Changed) => {
                            return Err(
                                "configuration changed immediately before publication".into()
                            );
                        }
                        Ok(DocumentReplace::Missing) => return Err(
                            "document replacement is incomplete; its protected intent is retained"
                                .into(),
                        ),
                        Ok(DocumentReplace::ReadOnly) => FileOutcome::InMemoryOnly,
                        Err(_) => {
                            // A native partial namespace failure must keep PendingReplace. An absent
                            // source is never silently declared compatible or generally recreated.
                            match fs.inspect_document(&p.path, &p.original, &p.converted) {
                                Ok(DocumentInspection::Original { .. }) => {}
                                Ok(DocumentInspection::Changed) => {
                                    return Err(
                                        "configuration changed during failed publication".into()
                                    );
                                }
                                Ok(DocumentInspection::Missing) => {
                                    match fs.recover_document(&p.path, &p.converted, metadata) {
                                        Ok(DocumentReplace::Published | DocumentReplace::AlreadyConverted) => {
                                            documents.mark_published(p)?;
                                            self.confirm(checkpoints, proof.migration, Phase::Published(index)).await?;
                                            report.files.push(FileReport { path: p.path.clone(), outcome: FileOutcome::Published });
                                            phase = Phase::Published(index);
                                            continue;
                                        },
                                        Ok(DocumentReplace::Changed) => return Err("configuration changed during exclusive replacement recovery".into()),
                                        _ => return Err("document replacement lost its pathname; protected recovery intent is retained".into()),
                                    }
                                }
                                _ => {
                                    report.files.push(FileReport {
                                        path: p.path.clone(),
                                        outcome: FileOutcome::InMemoryOnly,
                                    });
                                    // A visible converted file is not proof that its namespace barrier
                                    // survived. Keep PendingReplace so a crash can recover a missing name.
                                    return Ok(report);
                                }
                            }
                            FileOutcome::InMemoryOnly
                        }
                    }
                }
            };
            phase = match outcome {
                FileOutcome::InMemoryOnly => Phase::Deferred(index),
                _ => Phase::Published(index),
            };
            self.confirm(checkpoints, proof.migration, phase).await?;
            report.files.push(FileReport {
                path: p.path.clone(),
                outcome,
            });
        }
        self.confirm(checkpoints, proof.migration, Phase::Complete)
            .await?;
        report.complete = true;
        Ok(report)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    };
    struct CheckpointMemory {
        stored: Mutex<Option<Secret<Vec<u8>>>>,
        fault: AtomicU8,
    }
    impl Checkpoints for CheckpointMemory {
        fn durability(&self) -> busbar_contract::persistence::Durability {
            busbar_contract::persistence::Durability::Local
        }
        fn load(&self, _: [u8; 16]) -> CheckpointCall<'_, Option<Secret<Vec<u8>>>> {
            Box::pin(async { Ok(self.stored.lock().unwrap().clone()) })
        }
        fn confirm<'a>(
            &'a self,
            migration: [u8; 16],
            protected: &'a Secret<Vec<u8>>,
        ) -> CheckpointCall<'a, Secret<Vec<u8>>> {
            Box::pin(async move {
                let (_, phase) = Inventory::decode(protected, migration)?;
                if self.fault.load(Ordering::SeqCst) == 1 {
                    return Ok(Secret::new(b"different readback".to_vec()));
                }
                *self.stored.lock().unwrap() = Some(protected.clone());
                if phase == Phase::PendingReplace(1) && self.fault.swap(0, Ordering::SeqCst) == 2 {
                    return Err("checkpoint reply lost".into());
                }
                Ok(protected.clone())
            })
        }
        fn complete<'a>(
            &'a self,
            migration: [u8; 16],
            protected: &'a Secret<Vec<u8>>,
        ) -> CheckpointCall<'a, Secret<Vec<u8>>> {
            self.confirm(migration, protected)
        }
    }
    struct Fixture {
        path: PathBuf,
        publications: Vec<(PathBuf, busbar_kernel::appbuild::ConfigDocument)>,
    }
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().canonicalize().unwrap();
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let path = base.join(format!("document-checkpoint-{}", hex::encode(random)));
            std::fs::create_dir(&path).unwrap();
            let publications = vec![
                (
                    path.join("config.yaml"),
                    busbar_kernel::appbuild::ConfigDocument::Deployment,
                ),
                (
                    path.join("providers.yaml"),
                    busbar_kernel::appbuild::ConfigDocument::Providers,
                ),
            ];
            std::fs::write(&publications[0].0, b"store: {module: custom}\n").unwrap();
            std::fs::write(&publications[1].0, b"{}\n").unwrap();
            Self { path, publications }
        }
        fn documents(&self) -> Arc<Documents> {
            let documents = Arc::new(Documents::default());
            for (path, kind) in &self.publications {
                let raw = Zeroizing::new(std::fs::read_to_string(path).unwrap());
                documents.normalize(*kind, path, &raw).unwrap();
            }
            documents
        }
        fn retained(&self, documents: &Documents) -> Inventory {
            let mut inventory =
                Inventory::capture(documents, &crate::root::admission::DURABLE).unwrap();
            for doc in &mut inventory.documents {
                doc.publication
                    .converted
                    .extend_from_slice(b"# normalized\n");
                doc.publication.target_digest = Sha256::digest(&doc.publication.converted).into();
                doc.publication.transform_id =
                    Sha256::digest(doc.publication.path.as_os_str().as_encoded_bytes()).into();
            }
            inventory.digest = Sha256::digest(&inventory.material().unwrap()).into();
            inventory
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
    #[tokio::test]
    async fn a_different_checkpoint_readback_never_grants_publication_authority() {
        let fixture = Fixture::new();
        let documents = fixture.documents();
        let inventory = fixture.retained(&documents);
        let checkpoint = CheckpointMemory {
            stored: Mutex::new(None),
            fault: AtomicU8::new(1),
        };
        assert!(inventory
            .confirm(&checkpoint, [3; 16], Phase::Intent)
            .await
            .is_err());
        assert_eq!(
            std::fs::read(&fixture.publications[0].0).unwrap(),
            b"store: {module: custom}\n"
        );
        assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 2);
    }
    #[tokio::test]
    async fn partial_multifile_publication_resumes_the_same_protected_pairs() {
        let fixture = Fixture::new();
        let original = fixture.documents();
        let inventory = fixture.retained(&original);
        let migration = [4; 16];
        let checkpoint = CheckpointMemory {
            stored: Mutex::new(Some(
                inventory.encoded(migration, Phase::Validated).unwrap(),
            )),
            fault: AtomicU8::new(2),
        };
        let (inventory, intent) = Inventory::prepare(
            &original,
            &crate::root::admission::DURABLE,
            &checkpoint,
            migration,
        )
        .await
        .unwrap();
        let proof = inventory.validated(intent, &checkpoint).await.unwrap();
        assert!(inventory
            .publish(
                proof,
                &checkpoint,
                &crate::root::admission::DURABLE,
                &original
            )
            .await
            .is_err());
        assert!(std::fs::read(&fixture.publications[0].0)
            .unwrap()
            .ends_with(b"# normalized\n"));
        assert_eq!(std::fs::read(&fixture.publications[1].0).unwrap(), b"{}\n");
        let restarted = fixture.documents();
        let (resumed, intent) = Inventory::prepare(
            &restarted,
            &crate::root::admission::DURABLE,
            &checkpoint,
            migration,
        )
        .await
        .unwrap();
        assert_eq!(resumed.digest(), inventory.digest());
        let proof = resumed.validated(intent, &checkpoint).await.unwrap();
        let report = resumed
            .publish(
                proof,
                &checkpoint,
                &crate::root::admission::DURABLE,
                &restarted,
            )
            .await
            .unwrap();
        assert!(report.complete);
        for (path, _) in &fixture.publications {
            assert!(std::fs::read(path).unwrap().ends_with(b"# normalized\n"));
        }
        assert_eq!(std::fs::read_dir(&fixture.path).unwrap().count(), 2);
    }
    #[tokio::test]
    async fn restart_refuses_a_third_party_document_edit_before_any_replacement() {
        let fixture = Fixture::new();
        let original = fixture.documents();
        let inventory = fixture.retained(&original);
        let migration = [5; 16];
        let checkpoint = CheckpointMemory {
            stored: Mutex::new(Some(
                inventory.encoded(migration, Phase::Validated).unwrap(),
            )),
            fault: AtomicU8::new(0),
        };
        std::fs::write(&fixture.publications[1].0, b"# operator edit\n{}\n").unwrap();
        let restarted = fixture.documents();
        assert!(Inventory::prepare(
            &restarted,
            &crate::root::admission::DURABLE,
            &checkpoint,
            migration
        )
        .await
        .is_err());
        assert_eq!(
            std::fs::read(&fixture.publications[0].0).unwrap(),
            b"store: {module: custom}\n"
        );
        assert_eq!(
            std::fs::read(&fixture.publications[1].0).unwrap(),
            b"# operator edit\n{}\n"
        );
    }
}
