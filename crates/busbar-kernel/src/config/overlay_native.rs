// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native overlay custody. The existing head and immutable chunk bytes retain their layout;
//! one guarded core transaction installs a generation and retires its predecessor.
use std::sync::{Arc, Mutex};

use busbar_contract::Secret;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::overlay::{OverlayDoc, OverlayReadState};
use crate::persistence::{
    facade::CoreStore,
    scoped::{Expected, Mutation, Outcome, Predicate, Request, ScopedStore},
};

const SCHEMA: &str = "busbar.config.overlay.v1";
const HEAD: &[u8] = b"head";
type Observed = Arc<Mutex<Option<Option<Vec<u8>>>>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u32,
    generation: [u8; 16],
    length: u64,
    digest: [u8; 32],
}

/// Current-layout rows for a validated overlay, streamed one immutable chunk at a
/// time. The final row is its head. Importers must confirm every preceding chunk
/// before installing that head, and must keep their target inactive until activation.
/// This encoder performs no historical interpretation or backend access.
pub struct MigrationRows<'a> {
    bytes: &'a [u8],
    generation: [u8; 16],
    chunk: usize,
    head: Option<Secret<Vec<u8>>>,
}

pub fn migration_rows(
    bytes: &Secret<Vec<u8>>,
    generation: [u8; 16],
) -> Result<MigrationRows<'_>, String> {
    let bytes = bytes.expose(&crate::seal::lend()).as_slice();
    let doc: OverlayDoc = serde_json::from_slice(bytes)
        .map_err(|_| "migration target overlay does not match the current schema")?;
    if doc.version == 0 || doc.version > super::overlay::OVERLAY_VERSION {
        return Err("migration target overlay version is unsupported".into());
    }
    let head = Head {
        version: 1,
        generation,
        length: u64::try_from(bytes.len())
            .map_err(|_| "migration target overlay length is unsupported")?,
        digest: Sha256::digest(bytes).into(),
    };
    let head = Secret::new(
        serde_json::to_vec(&head).map_err(|_| "migration target overlay head encoding failed")?,
    );
    Ok(MigrationRows {
        bytes,
        generation,
        chunk: 0,
        head: Some(head),
    })
}

impl Iterator for MigrationRows<'_> {
    type Item = Result<(busbar_contract::persistence::Address, Secret<Vec<u8>>), String>;
    fn next(&mut self) -> Option<Self::Item> {
        let chunks = self.bytes.len().div_ceil(busbar_contract::MAX_RECORD_BYTES);
        let (key, value) = if self.chunk < chunks {
            let index = self.chunk;
            self.chunk += 1;
            let start = index * busbar_contract::MAX_RECORD_BYTES;
            let end = (self.bytes.len() - start).min(busbar_contract::MAX_RECORD_BYTES) + start;
            (
                chunk_key(&self.generation, index as u64),
                Secret::new(self.bytes[start..end].to_vec()),
            )
        } else {
            (HEAD.to_vec(), self.head.take()?)
        };
        Some(
            crate::persistence::scoped::migration_address(
                true,
                "busbar.config.overlay",
                SCHEMA,
                &key,
            )
            .map(|address| (address, value))
            .map_err(|_| "migration target overlay address encoding failed".into()),
        )
    }
}

struct Candidate {
    request: Request,
    head: Vec<u8>,
    stages: Vec<Request>,
    staged: usize,
    conflicted: bool,
    cleanup: Option<Request>,
}

enum State {
    Idle,
    Busy,
    Pending(Candidate),
    NeedsReload,
}

pub(super) struct NativeOverlay {
    store: ScopedStore,
    core: Arc<CoreStore>,
    observed: Observed,
    state: Mutex<State>,
}

struct Operation<'a> {
    overlay: &'a NativeOverlay,
    candidate: Option<Candidate>,
    needs_reload: bool,
}

impl Drop for Operation<'_> {
    fn drop(&mut self) {
        let next = self.candidate.take().map_or(
            if self.needs_reload {
                State::NeedsReload
            } else {
                State::Idle
            },
            State::Pending,
        );
        *self
            .overlay
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = next;
    }
}

impl NativeOverlay {
    pub(super) fn new(core: Arc<CoreStore>, observed: Observed) -> Result<Self, String> {
        let store =
            ScopedStore::host_private(core.clone(), "busbar.config.overlay", [SCHEMA.to_string()])
                .map_err(|error| format!("config overlay scope: {error:?}"))?;
        Ok(Self {
            store,
            core,
            observed,
            state: Mutex::new(State::Idle),
        })
    }

    pub(super) fn core_store_handle(&self) -> Arc<CoreStore> {
        self.core.clone()
    }

    #[cfg(test)]
    pub(super) fn observed(&self) -> Observed {
        self.observed.clone()
    }

    pub(super) fn require_reload(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if matches!(*state, State::Idle) {
            *state = State::NeedsReload;
        }
    }

    fn begin(&self, reload: bool) -> Result<Operation<'_>, String> {
        let previous = {
            let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
            if matches!(*state, State::Busy) {
                return Err("config overlay Store operation is already in progress".into());
            }
            if !reload && matches!(*state, State::NeedsReload) {
                return Err("config overlay recovery requires a successful config reload before further mutation".into());
            }
            std::mem::replace(&mut *state, State::Busy)
        };
        let needs_reload = matches!(previous, State::NeedsReload | State::Pending(_));
        Ok(Operation {
            overlay: self,
            candidate: match previous {
                State::Pending(candidate) => Some(candidate),
                _ => None,
            },
            needs_reload,
        })
    }

    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        self.store
            .get(SCHEMA, key)
            .await
            .map(|value| value.map(|bytes| bytes.expose(&crate::seal::lend()).clone()))
            .map_err(|error| format!("config overlay read: {error:?}"))
    }

    async fn snapshot(&self) -> Result<(Option<Vec<u8>>, Option<Vec<u8>>), String> {
        loop {
            let Some(raw) = self.get(HEAD).await? else {
                return Ok((None, None));
            };
            let head: Head = serde_json::from_slice(&raw)
                .map_err(|error| format!("invalid config overlay head: {error}"))?;
            if head.version != 1 || head.length == 0 {
                return Err("invalid config overlay generation".into());
            }
            let length = usize::try_from(head.length)
                .map_err(|_| "config overlay length cannot be represented")?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(length)
                .map_err(|_| "config overlay allocation could not be reserved")?;
            let mut complete = true;
            for index in 0..length.div_ceil(busbar_contract::MAX_RECORD_BYTES) {
                let key = chunk_key(&head.generation, index as u64);
                let Some(chunk) = self.get(&key).await? else {
                    complete = false;
                    break;
                };
                let expected = (length - bytes.len()).min(busbar_contract::MAX_RECORD_BYTES);
                if chunk.len() != expected {
                    return Err("config overlay chunk length mismatch".into());
                }
                bytes.extend_from_slice(&chunk);
            }
            if complete {
                if <[u8; 32]>::from(Sha256::digest(&bytes)) != head.digest {
                    return Err("config overlay digest mismatch".into());
                }
                return Ok((Some(raw), Some(bytes)));
            }
            if self.get(HEAD).await?.as_deref() == Some(raw.as_slice()) {
                return Err("config overlay generation is incomplete".into());
            }
        }
    }

    fn decode(bytes: Option<Vec<u8>>) -> Result<Option<OverlayDoc>, String> {
        match super::overlay::classify_bytes(bytes) {
            OverlayReadState::Absent => Ok(None),
            OverlayReadState::Loaded(doc) => Ok(Some(*doc)),
            OverlayReadState::Unreadable => Err(
                "config overlay in Store is unreadable; use --safe-mode to quarantine it".into(),
            ),
            OverlayReadState::VersionTooNew(version) => Err(format!(
                "config overlay version {version} is newer than this binary; use --safe-mode to quarantine it"
            )),
        }
    }

    pub(super) async fn read_bytes(&self) -> Result<Option<Vec<u8>>, String> {
        self.snapshot().await.map(|(_, bytes)| bytes)
    }

    pub(super) async fn read_required(&self) -> Result<Option<OverlayDoc>, String> {
        let (head, bytes) = self.snapshot().await?;
        let doc = Self::decode(bytes)?;
        let mut observed = self
            .observed
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if observed.is_none() {
            *observed = Some(head);
        }
        Ok(doc)
    }

    pub(super) async fn reopen(&self) -> Result<(Self, Option<OverlayDoc>), String> {
        let mut operation = self.begin(true)?;
        if let Some(candidate) = operation.candidate.as_mut() {
            self.submit(candidate).await?;
            operation.candidate.take();
        }
        let (head, bytes) = self.snapshot().await?;
        let doc = Self::decode(bytes)?;
        let observed = {
            let mut observed = self
                .observed
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            match observed.as_ref() {
                None => {
                    *observed = Some(head);
                    self.observed.clone()
                }
                Some(previous) if previous == &head => self.observed.clone(),
                Some(_) => {
                    operation.needs_reload = true;
                    Arc::new(Mutex::new(Some(head)))
                }
            }
        };
        Ok((
            Self {
                store: self.store.clone(),
                core: self.core.clone(),
                observed,
                state: Mutex::new(State::Idle),
            },
            doc,
        ))
    }

    async fn submit(&self, candidate: &mut Candidate) -> Result<bool, String> {
        if candidate.conflicted {
            self.retire_conflicted(candidate).await?;
            return Ok(false);
        }
        while let Some(stage) = candidate.stages.get(candidate.staged) {
            let outcome = self
                .store
                .conditional_native(stage)
                .await
                .map_err(|error| format!("config overlay chunk persistence: {error:?}"))?;
            match outcome {
                Outcome::Applied => {}
                Outcome::ConditionConflict => {
                    let Mutation::Put { key, value, .. } = &stage.mutations[0] else {
                        unreachable!("chunk stage is one immutable put")
                    };
                    let saved = self
                        .store
                        .get(SCHEMA, key)
                        .await
                        .map_err(|error| format!("config overlay chunk read: {error:?}"))?;
                    if saved
                        .as_ref()
                        .map(|bytes| bytes.expose(&crate::seal::lend()).as_slice())
                        != Some(value.expose(&crate::seal::lend()).as_slice())
                    {
                        return Err(
                            "immutable config overlay chunk conflicts with its generation".into(),
                        );
                    }
                }
                other => {
                    return Err(format!(
                        "config overlay chunk persistence was not confirmed; exact stage retained: {other:?}"
                    ));
                }
            }
            candidate.staged += 1;
        }
        match self
            .store
            .conditional_native(&candidate.request)
            .await
            .map_err(|error| format!("config overlay persistence: {error:?}"))?
        {
            Outcome::Applied => Ok(true),
            Outcome::ConditionConflict => {
                candidate.conflicted = true;
                self.retire_conflicted(candidate).await?;
                Ok(false)
            }
            outcome => Err(format!(
                "config overlay persistence was not confirmed; exact candidate retained: {outcome:?}"
            )),
        }
    }

    async fn retire_conflicted(&self, candidate: &mut Candidate) -> Result<(), String> {
        if candidate.cleanup.is_none() {
            let expected = self.get(HEAD).await?;
            // A competing identical import may already expose these immutable chunks.
            if expected.as_deref() == Some(candidate.head.as_slice()) {
                return Ok(());
            }
            let head: Head =
                serde_json::from_slice(&candidate.head).map_err(|error| error.to_string())?;
            let prefix = chunk_prefix(&head.generation);
            candidate.cleanup = Some(Request {
                op_id: crate::door::op_id().0,
                predicates: vec![Predicate {
                    schema: SCHEMA.into(),
                    key: HEAD.to_vec(),
                    expected: expected.map_or(Expected::Absent, |bytes| {
                        Expected::Exact(Secret::new(bytes))
                    }),
                }],
                mutations: vec![Mutation::DeleteRange {
                    schema: SCHEMA.into(),
                    exact_key_length: (prefix.len() + 8) as u64,
                    prefix,
                }],
            });
        }
        let cleanup = candidate
            .cleanup
            .as_ref()
            .expect("cleanup candidate installed before await");
        match self
            .store
            .conditional_native(cleanup)
            .await
            .map_err(|error| format!("config overlay conflict cleanup: {error:?}"))?
        {
            Outcome::Applied => Ok(()),
            Outcome::ConditionConflict => {
                candidate.cleanup.take();
                Err("config overlay conflict cleanup must retry against its new head".into())
            }
            outcome => Err(format!(
                "config overlay conflict cleanup pending; exact candidate retained: {outcome:?}"
            )),
        }
    }

    pub(super) async fn import_once(
        &self,
        source_sha256: [u8; 32],
        doc: &OverlayDoc,
    ) -> Result<bool, String> {
        use super::overlay_store::import::{canonicalize, check_receipt, Receipt};
        const RECEIPT: &[u8] = b"migration:1.5.5:file";
        let mut value = serde_json::to_value(doc.authoring(&crate::seal::acquire()))
            .map_err(|error| error.to_string())?;
        value["version"] = super::overlay::OVERLAY_VERSION.into();
        canonicalize(&mut value);
        let bytes = serde_json::to_vec(&value).map_err(|error| error.to_string())?;
        let receipt = Receipt {
            version: 1,
            source_sha256,
            overlay_sha256: Sha256::digest(&bytes).into(),
        };
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
        let mut hash = Sha256::new();
        hash.update(b"busbar.overlay.file-import.v1\0");
        hash.update(&receipt_bytes);
        let digest: [u8; 32] = hash.finalize().into();
        let generation: [u8; 16] = digest[..16].try_into().expect("fixed digest width");
        let mut operation = self.begin(false)?;
        if let Some(candidate) = operation.candidate.as_mut() {
            if candidate.request.op_id != generation {
                return Err(
                    "config overlay import cannot replace another pending candidate".into(),
                );
            }
            self.submit(candidate).await?;
            operation.candidate.take();
        }
        if let Some(saved) = self.get(RECEIPT).await? {
            check_receipt(&saved, &receipt)?;
            self.read_required()
                .await?
                .ok_or("overlay migration receipt has no readable destination head")?;
            return Ok(false);
        }
        if self.get(HEAD).await?.is_some() {
            return Err("overlay migration refuses an existing Store overlay without its matching migration receipt".into());
        }
        let head = Head {
            version: 1,
            generation,
            length: bytes.len() as u64,
            digest: receipt.overlay_sha256,
        };
        let head = serde_json::to_vec(&head).map_err(|error| error.to_string())?;
        let mutations = vec![
            Mutation::Put {
                schema: SCHEMA.into(),
                key: HEAD.to_vec(),
                value: Secret::new(head.clone()),
            },
            Mutation::Put {
                schema: SCHEMA.into(),
                key: RECEIPT.to_vec(),
                value: Secret::new(receipt_bytes),
            },
        ];
        let stages = stage_chunks(&generation, &bytes);
        operation.candidate = Some(Candidate {
            head,
            stages,
            staged: 0,
            conflicted: false,
            cleanup: None,
            request: Request {
                op_id: generation,
                predicates: vec![
                    Predicate {
                        schema: SCHEMA.into(),
                        key: HEAD.to_vec(),
                        expected: Expected::Absent,
                    },
                    Predicate {
                        schema: SCHEMA.into(),
                        key: RECEIPT.to_vec(),
                        expected: Expected::Absent,
                    },
                ],
                mutations,
            },
        });
        let applied = self
            .submit(
                operation
                    .candidate
                    .as_mut()
                    .expect("import candidate installed"),
            )
            .await?;
        operation.candidate.take();
        if applied {
            return Ok(true);
        }
        let saved = self
            .get(RECEIPT)
            .await?
            .ok_or("overlay changed while migration was committing; no import receipt exists")?;
        check_receipt(&saved, &receipt)?;
        self.read_required()
            .await?
            .ok_or("overlay migration receipt has no readable destination head")?;
        Ok(false)
    }

    pub(super) async fn update(
        &self,
        edit: impl FnOnce(&mut OverlayDoc) + Send,
    ) -> Result<(), String> {
        let mut operation = self.begin(false)?;
        let recovering = operation.candidate.is_some();
        if operation.candidate.is_none() {
            let (expected, bytes) = self.snapshot().await?;
            let changed = {
                let mut observed = self
                    .observed
                    .lock()
                    .unwrap_or_else(|error| error.into_inner());
                match observed.as_ref() {
                    None => {
                        *observed = Some(expected.clone());
                        false
                    }
                    Some(previous) => previous != &expected,
                }
            };
            if changed {
                operation.needs_reload = true;
                return Err("config overlay changed since this App generation was recovered; reload before mutation".into());
            }
            let mut doc = Self::decode(bytes)?.unwrap_or_default();
            edit(&mut doc);
            doc.version = super::overlay::OVERLAY_VERSION;
            let bytes = serde_json::to_vec(&doc.authoring(&crate::seal::acquire()))
                .map_err(|error| error.to_string())?;
            let op_id = crate::door::op_id().0;
            let head = Head {
                version: 1,
                generation: op_id,
                length: bytes.len() as u64,
                digest: Sha256::digest(&bytes).into(),
            };
            let head = serde_json::to_vec(&head).map_err(|error| error.to_string())?;
            let mut mutations = vec![Mutation::Put {
                schema: SCHEMA.into(),
                key: HEAD.to_vec(),
                value: Secret::new(head.clone()),
            }];
            if let Some(raw) = &expected {
                let old: Head = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
                let prefix = chunk_prefix(&old.generation);
                mutations.push(Mutation::DeleteRange {
                    schema: SCHEMA.into(),
                    exact_key_length: (prefix.len() + 8) as u64,
                    prefix,
                });
            }
            let stages = stage_chunks(&op_id, &bytes);
            operation.candidate = Some(Candidate {
                head,
                stages,
                staged: 0,
                conflicted: false,
                cleanup: None,
                request: Request {
                    op_id,
                    predicates: vec![Predicate {
                        schema: SCHEMA.into(),
                        key: HEAD.to_vec(),
                        expected: expected.map_or(Expected::Absent, |bytes| {
                            Expected::Exact(Secret::new(bytes))
                        }),
                    }],
                    mutations,
                },
            });
        }
        let candidate = operation
            .candidate
            .as_mut()
            .expect("candidate custody installed");
        let applied = self.submit(candidate).await?;
        if applied && !recovering {
            *self
                .observed
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = Some(Some(candidate.head.clone()));
        }
        operation.needs_reload |= !applied;
        operation.candidate.take();
        if !applied {
            Err("config overlay changed in Store; reload before retrying".into())
        } else if recovering {
            Err("a prior config overlay candidate was resolved; reload configuration before retrying this mutation".into())
        } else {
            Ok(())
        }
    }
}

fn chunk_prefix(generation: &[u8; 16]) -> Vec<u8> {
    let mut key = b"chunk:".to_vec();
    key.extend_from_slice(generation);
    key
}
fn chunk_key(generation: &[u8; 16], index: u64) -> Vec<u8> {
    let mut key = chunk_prefix(generation);
    key.extend_from_slice(&index.to_be_bytes());
    key
}

fn stage_chunks(generation: &[u8; 16], bytes: &[u8]) -> Vec<Request> {
    bytes
        .chunks(busbar_contract::MAX_RECORD_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let mut hash = Sha256::new();
            hash.update(b"busbar.overlay.chunk-stage.v1\0");
            hash.update(generation);
            hash.update((index as u64).to_be_bytes());
            let digest: [u8; 32] = hash.finalize().into();
            let op_id = digest[..16].try_into().expect("fixed digest width");
            let key = chunk_key(generation, index as u64);
            Request {
                op_id,
                predicates: vec![Predicate {
                    schema: SCHEMA.into(),
                    key: key.clone(),
                    expected: Expected::Absent,
                }],
                mutations: vec![Mutation::Put {
                    schema: SCHEMA.into(),
                    key,
                    value: Secret::new(chunk.to_vec()),
                }],
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::overlay::{persist_root_async, OverlayStore, RootSettings};
    use super::*;
    use busbar_contract::persistence::{
        BackendInfo, Call, ClockObservation, DatasetId, Decision, Failure, Page,
        PersistenceBackend, PreparedCandidate, Read, ReadResult, Scan,
    };
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn migration_rows_stream_bounded_current_chunks_before_manifest() {
        let doc = OverlayDoc {
            deleted: vec!["x".repeat(busbar_contract::MAX_RECORD_BYTES + 17)],
            ..Default::default()
        };
        let bytes =
            Secret::new(serde_json::to_vec(&doc.authoring(&crate::seal::acquire())).unwrap());
        let seal = crate::seal::lend();
        let mut rows = migration_rows(&bytes, [9; 16]).unwrap();
        let mut assembled = Vec::new();
        let chunks = bytes
            .expose(&seal)
            .len()
            .div_ceil(busbar_contract::MAX_RECORD_BYTES);
        for index in 0..chunks {
            let (address, chunk) = rows.next().unwrap().unwrap();
            assert_eq!(
                address,
                crate::persistence::scoped::migration_address(
                    true,
                    "busbar.config.overlay",
                    SCHEMA,
                    &chunk_key(&[9; 16], index as u64)
                )
                .unwrap()
            );
            assert!(chunk.expose(&seal).len() <= busbar_contract::MAX_RECORD_BYTES);
            assembled.extend_from_slice(chunk.expose(&seal));
        }
        assert_eq!(&assembled, bytes.expose(&seal));
        let (address, manifest) = rows.next().unwrap().unwrap();
        assert_eq!(
            address,
            crate::persistence::scoped::migration_address(
                true,
                "busbar.config.overlay",
                SCHEMA,
                HEAD
            )
            .unwrap()
        );
        let manifest: Head = serde_json::from_slice(manifest.expose(&seal)).unwrap();
        assert_eq!(manifest.length as usize, assembled.len());
        assert_eq!(
            manifest.digest,
            <[u8; 32]>::from(Sha256::digest(&assembled))
        );
        assert!(rows.next().is_none());
        assert!(migration_rows(&Secret::new(br#"{"version":999}"#.to_vec()), [9; 16]).is_err());
    }

    fn settings(fee: i64) -> RootSettings {
        RootSettings {
            per_request_fee: Some(fee),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn native_import_is_exact_and_a_later_edit_does_not_reimport() {
        let overlay = OverlayStore::from_core(crate::real_store::core().await).unwrap();
        let doc = OverlayDoc {
            root: Some(settings(7)),
            ..Default::default()
        };
        assert!(overlay.import_once_async([5; 32], &doc).await.unwrap());
        persist_root_async(Some(&overlay), &settings(9))
            .await
            .unwrap();
        assert!(!overlay.import_once_async([5; 32], &doc).await.unwrap());
        assert!(overlay.import_once_async([6; 32], &doc).await.is_err());
        assert_eq!(
            overlay
                .read_required_async()
                .await
                .unwrap()
                .unwrap()
                .root
                .unwrap()
                .per_request_fee,
            Some(9)
        );
    }

    #[tokio::test]
    async fn native_overlay_rejects_a_stale_carrier_until_explicit_reload() {
        let core = crate::real_store::core().await;
        let first = OverlayStore::from_core(core.clone()).unwrap();
        assert!(first.read_required_async().await.unwrap().is_none());
        let other = OverlayStore::from_core(core).unwrap();
        persist_root_async(Some(&other), &settings(2))
            .await
            .unwrap();
        assert!(persist_root_async(Some(&first), &settings(3))
            .await
            .is_err());
        let (reloaded, doc) = first.reopen_for_reload_async().await.unwrap();
        assert_eq!(doc.unwrap().root.unwrap().per_request_fee, Some(2));
        persist_root_async(Some(&reloaded), &settings(3))
            .await
            .unwrap();
        assert!(persist_root_async(Some(&first), &settings(4))
            .await
            .is_err());
    }

    struct LostPublication {
        inner: Arc<dyn PersistenceBackend>,
        lose: AtomicBool,
        sent: Mutex<Vec<([u8; 16], [u8; 32])>>,
    }
    impl PersistenceBackend for LostPublication {
        fn info(&self) -> BackendInfo {
            self.inner.info()
        }
        fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
            self.inner.read(request)
        }
        fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
            self.inner.scan(request)
        }
        fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
            self.inner.clock(dataset)
        }
        fn commit(&self, candidate: PreparedCandidate) -> Call<'_, Decision> {
            Box::pin(async move {
                let publication = candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, busbar_contract::persistence::Mutation::Put { address, .. } if address.key.ends_with(HEAD)));
                if publication {
                    self.sent
                        .lock()
                        .unwrap()
                        .push((candidate.candidate().id.operation, candidate.fingerprint()));
                }
                let answer = self.inner.commit(candidate).await?;
                if publication && self.lose.swap(false, Ordering::SeqCst) {
                    Err(Failure::Unknown)
                } else {
                    Ok(answer)
                }
            })
        }
    }

    #[tokio::test]
    async fn lost_native_publication_replays_its_exact_candidate_before_new_edits() {
        let backend = Arc::new(LostPublication {
            inner: crate::real_store::native_backend().await,
            lose: AtomicBool::new(false),
            sent: Mutex::new(Vec::new()),
        });
        let core = crate::real_store::core_over(backend.clone()).await;
        let overlay = OverlayStore::from_core(core).unwrap();
        backend.sent.lock().unwrap().clear();
        backend.lose.store(true, Ordering::SeqCst);
        assert!(persist_root_async(Some(&overlay), &settings(7))
            .await
            .is_err());
        assert!(persist_root_async(Some(&overlay), &settings(99))
            .await
            .is_err());
        let sent = backend.sent.lock().unwrap().clone();
        assert!(sent.len() >= 2);
        assert_eq!(sent[0], sent[1]);
        let (reloaded, doc) = overlay.reopen_for_reload_async().await.unwrap();
        assert_eq!(doc.unwrap().root.unwrap().per_request_fee, Some(7));
        persist_root_async(Some(&reloaded), &settings(8))
            .await
            .unwrap();
    }
}
