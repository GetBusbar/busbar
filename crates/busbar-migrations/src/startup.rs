// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Retained normal-startup upgrade owner. Native OPEN is performed only through
//! the inspected session's exact admission binding.

use crate::{CompletionReceipt, Digest32, Error, Identity, IntentStore, CORE_FORMAT};
use busbar_contract::persistence::{axis::OpenedBackend, lifecycle as native};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// Backend and binding consumed by the one normal application construction.
pub struct RecoveryPending {
    pub backend: OpenedBackend,
    pub upgrade_id: [u8; 16],
    pub target: Identity,
    /// Present only after native activation; observing a marker is not admission.
    pub recovery: Option<native::RecoveryReady>,
}

/// Preparation does not grant permission to expose listeners.
pub enum Preparation {
    Recovery(Box<RecoveryPending>),
    Pending,
}

struct ReadinessLatch {
    target: Identity,
    digest: Mutex<Option<Digest32>>,
}

#[derive(Clone)]
struct SourceResources {
    spool: Arc<dyn crate::native_source::SpoolFactory>,
    limits: busbar_contract::persistence::archive::Limits,
    index_bytes: usize,
    semantic_bytes: usize,
    bindings_resolver: Option<Arc<dyn FrozenBindingResolver>>,
}

/// Trusted composition-root projection of effective declarations from the exact
/// frozen source overlay. Implementations perform no Store I/O or App creation.
pub trait FrozenBindingResolver: Send + Sync {
    fn resolve(
        &self,
        source: &Identity,
        rows: &mut dyn crate::archive_source::ArchiveRows,
    ) -> Result<FrozenResolution, Error>;
}
pub struct FrozenResolution {
    pub bindings: crate::routes::Bindings,
    pub overlay: Option<Arc<crate::legacy::overlay::PreparedOverlay>>,
}
struct Initializing {
    plan: crate::Manifest,
    registry: Arc<crate::Registry>,
    source: Arc<dyn crate::SourceReader>,
    transform: Arc<dyn crate::Transform>,
    readback: Arc<dyn crate::NativeReadback>,
    fence: Arc<crate::NativeSourceFence>,
    snapshot: crate::SnapshotEvidence,
    bootstrap: crate::TargetBootstrap,
    registration: crate::ColdWriterRegistration,
    authority: busbar_kernel::persistence::facade::WriterAuthority,
    bootstrapped: bool,
}
type BuildFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Initializing, Error>> + Send>>;

/// Actual registered custody for host-scoped authored-document checkpoints.
pub struct DocumentCustody {
    backend: OpenedBackend,
    authority: busbar_kernel::persistence::facade::WriterAuthority,
    intent: Arc<crate::StoreIntent>,
    migration: [u8; 16],
}
impl DocumentCustody {
    pub fn backend(&self) -> OpenedBackend {
        self.backend.clone()
    }
    pub fn authority(&self) -> busbar_kernel::persistence::facade::WriterAuthority {
        self.authority
    }
    pub fn intent(&self) -> Arc<crate::StoreIntent> {
        self.intent.clone()
    }
    pub fn custody_id(&self) -> [u8; 16] {
        self.migration
    }
}
struct DocumentRegistration {
    migration: [u8; 16],
    authority: busbar_kernel::persistence::facade::WriterAuthority,
    registration: crate::ColdWriterRegistration,
    intent: Option<Arc<crate::StoreIntent>>,
    budget: usize,
}
#[async_trait::async_trait]
impl crate::TargetRecoveryProbe for ReadinessLatch {
    async fn verify_reopened_hydrated(&self, target: &Identity) -> Result<Digest32, Error> {
        if target != &self.target {
            return Err(Error::IdentityMismatch);
        }
        self.digest
            .lock()
            .map_err(|_| Error::Corrupt)?
            .ok_or(Error::Verification)
    }
}

/// Session owner retained through semantic hydration and final native Finish.
pub struct StartupUpgrade {
    prepared: native::Prepared,
    bounds: native::Bounds,
    inspection: Option<Arc<native::Response>>,
    opened: Option<OpenedBackend>,
    binding: Option<([u8; 16], Identity)>,
    begin_request: Option<Arc<native::Request>>,
    native_upgrade: Option<Arc<native::Response>>,
    target: Option<native::TargetBackend>,
    route: Option<crate::routes::PreparedRoute>,
    coordinator: Option<crate::Coordinator>,
    intent: Option<Arc<crate::StoreIntent>>,
    finish_request: Option<Arc<native::Request>>,
    recovery_ready: Option<native::RecoveryReady>,
    readiness: Option<Arc<ReadinessLatch>>,
    resources: Option<SourceResources>,
    initializing: Option<Initializing>,
    route_digest: Option<Digest32>,
    documents: Option<DocumentRegistration>,
    building: Option<BuildFuture>,
    bindings: Option<crate::routes::Bindings>,
    declaration_inventory: Option<crate::routes::DeclarationInventory>,
}

impl StartupUpgrade {
    pub async fn checked_source_fence(&self) -> Result<crate::CheckedNativeFence, Error> {
        let native::Response::Begun(upgrade) =
            self.native_upgrade.as_deref().ok_or(Error::InvalidState)?
        else {
            return Err(Error::Corrupt);
        };
        let reply = self
            .prepared
            .bootstrap(Arc::new(native::Request::CheckFence {
                upgrade: upgrade.reference.clone(),
            }))
            .await
            .map_err(native_error)?;
        let native::Response::Fence(fence) = reply.as_ref() else {
            return Err(Error::Corrupt);
        };
        if fence.upgrade != upgrade.reference.id
            || fence.source != upgrade.source
            || fence.snapshot != upgrade.snapshot
            || fence.enforcement_digest == [0; 32]
            || fence.observation_digest == [0; 32]
        {
            return Err(Error::FenceRequired);
        }
        Ok(crate::CheckedNativeFence {
            source: fence.source.clone(),
            upgrade: fence.upgrade,
            snapshot: fence.snapshot,
            enforcement: fence.enforcement_digest,
            observation: fence.observation_digest,
            route: self.route_digest.ok_or(Error::InvalidState)?,
        })
    }
    pub fn new(prepared: native::Prepared, bounds: native::Bounds) -> Self {
        Self {
            prepared,
            bounds,
            inspection: None,
            opened: None,
            binding: None,
            begin_request: None,
            native_upgrade: None,
            target: None,
            route: None,
            coordinator: None,
            intent: None,
            finish_request: None,
            recovery_ready: None,
            readiness: None,
            resources: None,
            initializing: None,
            route_digest: None,
            documents: None,
            building: None,
            bindings: Some(crate::routes::Bindings::default()),
            declaration_inventory: None,
        }
    }

    pub fn with_source_spool(
        mut self,
        spool: Arc<dyn crate::native_source::SpoolFactory>,
        limits: busbar_contract::persistence::archive::Limits,
        index_bytes: usize,
        semantic_bytes: usize,
    ) -> Result<Self, Error> {
        if limits.frame_bytes == 0
            || limits.total_bytes == 0
            || limits.rows == 0
            || limits.tables == 0
            || limits.columns == 0
            || limits.index_bytes == 0
            || index_bytes == 0
            || semantic_bytes == 0
        {
            return Err(Error::Bounds);
        }
        self.resources = Some(SourceResources {
            spool,
            limits,
            index_bytes,
            semantic_bytes,
            bindings_resolver: None,
        });
        Ok(self)
    }

    pub fn with_bindings(mut self, bindings: crate::routes::Bindings) -> Result<Self, Error> {
        if self.begin_request.is_some() || self.route.is_some() {
            return Err(Error::InvalidState);
        }
        self.bindings = Some(bindings);
        self.declaration_inventory = None;
        Ok(self)
    }

    pub fn with_binding_inventory(
        mut self,
        inventory: crate::routes::DeclarationInventory,
        resolver: Arc<dyn FrozenBindingResolver>,
    ) -> Result<Self, Error> {
        if self.begin_request.is_some() || self.route.is_some() {
            return Err(Error::InvalidState);
        }
        self.resources
            .as_mut()
            .ok_or(Error::MissingCapability)?
            .bindings_resolver = Some(resolver);
        self.declaration_inventory = Some(inventory);
        Ok(self)
    }

    /// Register separate, host/document-scoped custody using the actual writer
    /// admitted by Startup. The caller supplies its stable locator-bound ID;
    /// neither current file bytes nor the data migration ID may substitute.
    pub async fn document_custody(
        &mut self,
        custody_id: [u8; 16],
        authority: busbar_kernel::persistence::facade::WriterAuthority,
        budget: usize,
    ) -> Result<Option<DocumentCustody>, Error> {
        let (upgrade, _) = self.binding.as_ref().ok_or(Error::InvalidState)?;
        if custody_id == [0; 16] || &custody_id == upgrade || budget < 160 {
            return Err(Error::IdentityMismatch);
        }
        let backend = self.opened.as_ref().ok_or(Error::InvalidState)?.clone();
        if self.documents.is_none() {
            let derive = |domain: &[u8]| {
                let mut hash = Sha256::new();
                hash.update(domain);
                hash.update(backend.info().dataset.0);
                hash.update(custody_id);
                let digest: Digest32 = hash.finalize().into();
                let mut id = [0; 16];
                id.copy_from_slice(&digest[..16]);
                id
            };
            let cold = derive(b"busbar.documents.cold.v1");
            let operation = derive(b"busbar.documents.register.v1");
            let registration = crate::ColdWriterRegistration::for_current(
                backend.clone(),
                custody_id,
                authority,
                cold,
                operation,
            )?;
            self.documents = Some(DocumentRegistration {
                migration: custody_id,
                authority,
                registration,
                intent: None,
                budget,
            });
        }
        let session = self.documents.as_mut().ok_or(Error::InvalidState)?;
        if session.migration != custody_id
            || session.authority != authority
            || session.budget != budget
        {
            return Err(Error::IdentityMismatch);
        }
        match session.registration.advance().await? {
            crate::BootstrapProgress::Advanced | crate::BootstrapProgress::Pending => {
                return Ok(None)
            }
            crate::BootstrapProgress::Ready => {}
        }
        if session.intent.is_none() {
            session.intent = Some(Arc::new(
                crate::StoreIntent::open(backend.clone(), custody_id, budget).await?,
            ));
        }
        let intent = session.intent.as_ref().ok_or(Error::InvalidState)?.clone();
        match intent.reconcile(custody_id).await? {
            crate::ReconciliationProgress::Advanced | crate::ReconciliationProgress::Pending => {
                return Ok(None)
            }
            crate::ReconciliationProgress::Unresolved => return Err(Error::ReconciliationRequired),
            crate::ReconciliationProgress::Resolved => {}
        }
        Ok(Some(DocumentCustody {
            backend,
            authority,
            intent,
            migration: custody_id,
        }))
    }

    /// Inspect without OPEN or native mutation, for source-bound authored input
    /// normalization before the retained upgrade is claimed.
    pub async fn inspect_released(&mut self) -> Result<Option<crate::ReleasedSourceProof>, Error> {
        if self.inspection.is_none() {
            self.inspection = Some(
                self.prepared
                    .bootstrap(Arc::new(native::Request::Inspect {
                        bounds: self.bounds,
                    }))
                    .await
                    .map_err(|error| match error {
                        native::Error::Pending | native::Error::Busy | native::Error::Unknown => {
                            Error::IntentPending
                        }
                        _ => native_error(error),
                    })?,
            );
        }
        let native::Response::Inspected(inspection) =
            self.inspection.as_deref().ok_or(Error::InvalidState)?
        else {
            return Err(Error::Corrupt);
        };
        match inspection.state {
            native::InspectionState::Empty | native::InspectionState::Current => return Ok(None),
            native::InspectionState::Busy => {
                self.inspection = None;
                return Err(Error::IntentPending);
            }
            native::InspectionState::Unsupported => return Err(Error::UnsupportedPath),
            native::InspectionState::Legacy | native::InspectionState::InProgress => {}
        }
        crate::ReleasedSourceProof::inspected(inspection.source.as_ref().ok_or(Error::Corrupt)?)
    }

    /// Advance native preparation. Repeated calls retain the original session.
    pub async fn prepare(&mut self) -> Result<Preparation, Error> {
        if let (Some(backend), Some((upgrade_id, target))) = (&self.opened, &self.binding) {
            return Ok(Preparation::Recovery(Box::new(RecoveryPending {
                backend: backend.clone(),
                upgrade_id: *upgrade_id,
                target: target.clone(),
                recovery: self.recovery_ready.clone(),
            })));
        }
        if self.inspection.is_none() {
            self.inspection = Some(
                match self
                    .prepared
                    .bootstrap(Arc::new(native::Request::Inspect {
                        bounds: self.bounds,
                    }))
                    .await
                {
                    Ok(response) => response,
                    Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => {
                        return Ok(Preparation::Pending)
                    }
                    Err(error) => return Err(native_error(error)),
                },
            );
        }
        let native::Response::Inspected(inspection) =
            self.inspection.as_deref().ok_or(Error::InvalidState)?
        else {
            return Err(Error::Corrupt);
        };
        let (binding, artifact, schema) = match inspection.state {
            native::InspectionState::Empty => (native::OpenBinding::Empty, [0; 32], [0; 32]),
            native::InspectionState::Current => {
                let source = inspection.source.as_ref().ok_or(Error::Corrupt)?;
                let marker = inspection.admission_marker.as_ref().ok_or(Error::Corrupt)?;
                let digest: Digest32 = Sha256::digest(marker.expose(&crate::seal::lend())).into();
                (
                    native::OpenBinding::Current {
                        source: source.clone(),
                        admission_marker_digest: digest,
                    },
                    digest,
                    source.layout_digest,
                )
            }
            native::InspectionState::Busy => {
                self.inspection = None;
                return Ok(Preparation::Pending);
            }
            native::InspectionState::Unsupported => return Err(Error::UnsupportedPath),
            // Historical preparation is installed by the compiled source adapter;
            // an unbound adapter cannot invoke ordinary OPEN as a fallback.
            native::InspectionState::Legacy | native::InspectionState::InProgress => {
                let source = inspection.source.clone().ok_or(Error::Corrupt)?;
                let catalogue = inspection.catalogue.clone();
                return self.prepare_legacy(source, catalogue).await;
            }
        };
        let backend = match self.prepared.open(binding).await {
            Ok(backend) => backend,
            Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => {
                return Ok(Preparation::Pending)
            }
            Err(error) => return Err(native_error(error)),
        };
        let mut hash = Sha256::new();
        hash.update(b"busbar.startup.current.v1");
        hash.update(backend.info().dataset.0);
        hash.update(backend.info().atomic_domain);
        hash.update(backend.info().physical_version.to_le_bytes());
        let digest: Digest32 = hash.finalize().into();
        let mut upgrade_id = [0; 16];
        upgrade_id.copy_from_slice(&digest[..16]);
        let target = Identity {
            dataset: backend.info().dataset.0,
            format: CORE_FORMAT,
            artifact_digest: artifact,
            schema_digest: schema,
            product_release: [1, 6, 0],
        };
        self.opened = Some(backend.clone());
        self.binding = Some((upgrade_id, target.clone()));
        Ok(Preparation::Recovery(Box::new(RecoveryPending {
            backend,
            upgrade_id,
            target,
            recovery: None,
        })))
    }

    async fn prepare_legacy(
        &mut self,
        source: native::SourceIdentity,
        catalogue: Vec<busbar_contract::persistence::archive::Table>,
    ) -> Result<Preparation, Error> {
        if self.coordinator.is_some() {
            return self.advance_migration().await;
        }
        if self.initializing.is_some() {
            return self.initialize_migration().await;
        }
        if self.building.is_some() {
            if !self.build_initialization().await? {
                return Ok(Preparation::Pending);
            }
            return self.initialize_migration().await;
        }
        if self.route.is_none() {
            let route = crate::routes::PreparedRoute::inspect(
                &source,
                &catalogue,
                crate::Bounds {
                    items: self.bounds.items,
                    bytes: self.bounds.bytes,
                },
                CORE_FORMAT,
            )?;
            self.route = Some(match self.declaration_inventory.take() {
                Some(inventory) => route.with_binding_inventory(inventory)?,
                None => route.with_bindings(self.bindings.take().unwrap_or_default())?,
            });
            self.route_digest = Some(
                self.route
                    .as_ref()
                    .ok_or(Error::InvalidState)?
                    .descriptor_digest(),
            );
        }
        if self.begin_request.is_none() {
            let route_digest = self
                .route
                .as_ref()
                .ok_or(Error::InvalidState)?
                .descriptor_digest();
            let mut hash = Sha256::new();
            hash.update(b"busbar.native.begin.v1");
            hash.update(source.native_anchor);
            hash.update(source.dataset.0);
            hash.update(route_digest);
            let digest: Digest32 = hash.finalize().into();
            let mut operation_id = [0; 16];
            operation_id.copy_from_slice(&digest[..16]);
            self.begin_request = Some(Arc::new(native::Request::BeginOrResume {
                expected_source: source.clone(),
                route_digest,
                target_format: native::CORE_FORMAT,
                operation_id,
            }));
        }
        if self.native_upgrade.is_none() {
            let request = self
                .begin_request
                .as_ref()
                .ok_or(Error::InvalidState)?
                .clone();
            self.native_upgrade = Some(match self.prepared.bootstrap(request).await {
                Ok(response) => response,
                Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => {
                    return Ok(Preparation::Pending)
                }
                Err(error) => return Err(native_error(error)),
            });
        }
        let native::Response::Begun(upgrade) =
            self.native_upgrade.as_deref().ok_or(Error::InvalidState)?
        else {
            return Err(Error::Corrupt);
        };
        if upgrade.reference.id == [0; 16]
            || upgrade.snapshot == [0; 16]
            || upgrade.source != source
            || upgrade.target.dataset.0 == [0; 16]
        {
            return Err(Error::IdentityMismatch);
        }
        if self.target.is_none() {
            self.target = Some(
                match self.prepared.target(upgrade.reference.clone()).await {
                    Ok(target) => target,
                    Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => {
                        return Ok(Preparation::Pending)
                    }
                    Err(error) => return Err(native_error(error)),
                },
            );
        }
        let target = self.target.as_ref().ok_or(Error::InvalidState)?;
        if target.upgrade_id() != upgrade.reference.id || target.info() != upgrade.target {
            return Err(Error::IdentityMismatch);
        }
        if !self.build_initialization().await? {
            return Ok(Preparation::Pending);
        }
        self.initialize_migration().await
    }

    async fn build_initialization(&mut self) -> Result<bool, Error> {
        if self.building.is_none() {
            let prepared = self.prepared.clone();
            let response = self
                .native_upgrade
                .as_ref()
                .ok_or(Error::InvalidState)?
                .clone();
            let resources = self
                .resources
                .as_ref()
                .ok_or(Error::MissingCapability)?
                .clone();
            let backend: OpenedBackend = self.target.as_ref().ok_or(Error::InvalidState)?.clone();
            let route = self.route.take().ok_or(Error::InvalidState)?;
            self.building = Some(Box::pin(Self::build_setup(
                prepared,
                response,
                resources,
                self.bounds,
                backend,
                route,
                self.route_digest.ok_or(Error::InvalidState)?,
            )));
        }
        let result = match tokio::time::timeout(
            std::time::Duration::from_millis(50),
            self.building.as_mut().ok_or(Error::InvalidState)?,
        )
        .await
        {
            Ok(result) => result,
            Err(_) => return Ok(false),
        };
        self.building = None;
        self.initializing = Some(result?);
        Ok(true)
    }

    async fn build_setup(
        prepared: native::Prepared,
        native_response: Arc<native::Response>,
        resources: SourceResources,
        native_bounds: native::Bounds,
        backend: OpenedBackend,
        mut prepared_route: crate::routes::PreparedRoute,
        route_digest: Digest32,
    ) -> Result<Initializing, Error> {
        use crate::{
            archive_source::{Grouping, SqlGroups, ValkeyGroups},
            legacy::{
                self,
                journal::{Budget, JournalPlan, Layout},
                projection::ProjectionSource,
            },
            native_source::NativeSnapshot,
        };
        let native::Response::Begun(upgrade) = native_response.as_ref() else {
            return Err(Error::Corrupt);
        };
        let mut snapshot = NativeSnapshot::capture(
            prepared.clone(),
            upgrade,
            native_bounds,
            resources.spool.as_ref(),
            resources.limits,
        )
        .await?;
        let identity = snapshot.identity();
        let mut overlay = None;
        if let Some(resolver) = &resources.bindings_resolver {
            let effective = resolver.resolve(&identity, snapshot.rows())?;
            prepared_route = prepared_route.resolve_frozen_bindings(effective.bindings)?;
            overlay = effective.overlay;
        }
        prepared_route.resolved_bindings()?;
        let provenance = legacy::archive::Provenance {
            dataset: identity.dataset,
            catalogue: identity.schema_digest,
        };
        let audit = crate::routes::proofs_from_frozen(
            identity.format,
            provenance,
            snapshot.rows(),
            resources.semantic_bytes,
            None,
        )?;
        let audit = crate::routes::with_parent_graph_from_frozen(
            identity.format,
            provenance,
            snapshot.rows(),
            resources.index_bytes,
            prepared_route.resolved_bindings()?,
            audit,
        )?;
        let (grouping, layout): (Arc<dyn Grouping>, Layout) =
            if identity.format.owner == native::VALKEY_SOURCE_OWNER {
                let table = snapshot.catalogue().first().ok_or(Error::Corrupt)?;
                let layout = legacy::valkey::NativeLayout::decode(&table.native_layout)
                    .map_err(|_| Error::Corrupt)?;
                (
                    Arc::new(ValkeyGroups::new(snapshot.header())?),
                    Layout::Valkey {
                        profile: layout.profile,
                        database: layout.source_db,
                    },
                )
            } else {
                let profile = legacy::Profile::from_importer_format(identity.format)
                    .map_err(|_| Error::UnsupportedPath)?;
                (Arc::new(SqlGroups::new(profile)), Layout::Sql(profile))
            };
        let snapshot_evidence = snapshot.snapshot();
        let catalogue = snapshot.catalogue().to_vec();
        let source = snapshot.into_source(
            grouping,
            resources.index_bytes,
            resources.semantic_bytes,
            [0, 0, 0],
        )?;
        if let Some(overlay) = &overlay {
            source.bind_overlay(overlay.clone())?;
        }
        if source.identity() != identity {
            return Err(Error::IdentityMismatch);
        }
        let bounds = crate::Bounds {
            items: native_bounds.items,
            bytes: native_bounds.bytes,
        };
        let journal = Arc::new(JournalPlan::verify(
            source.clone(),
            layout,
            bounds,
            Budget {
                metadata_bytes: resources.index_bytes,
                max_frame_bytes: resources.limits.frame_bytes,
                // A source may permit every representable row count. This is
                // an upper bound, so cap the derived read allowance rather
                // than rejecting that valid configuration on multiplication.
                max_frame_reads: resources.limits.rows.saturating_mul(8),
            },
        )?);
        let mut recovery = legacy::recovery::FrozenRecovery::verify(
            source.clone(),
            journal.clone(),
            layout,
            bounds,
            resources.index_bytes,
            resources.limits.frame_bytes,
        )?;
        let checked = checked_native_fence(&prepared, upgrade, route_digest).await?;
        let ancestry = Arc::new(recovery.fenced_receipt_proofs(&checked, resources.index_bytes)?);
        let proofs = crate::routes::with_ancestry(audit, ancestry.clone());
        let target = target_identity(backend.info())?;
        let projection: Arc<dyn ProjectionSource> = source.clone();
        let route = prepared_route.bind_frozen(
            &identity,
            &target,
            &catalogue,
            projection,
            proofs,
            crate::routes::FrozenCapabilities {
                journal: Some(journal),
                overlay,
                recovery: Some(ancestry),
            },
        )?;
        source.bind_output_budget(Arc::downgrade(&route.transform))?;
        let registry = Arc::new(route.registry);
        let plan = registry.plan(
            upgrade.reference.id,
            identity.clone(),
            target,
            &[route.transform.edge().id],
        )?;
        let ids = crate::BootstrapIds::for_plan(&plan, &registry)?;
        let bootstrap =
            crate::TargetBootstrap::new(backend.clone(), ids.authority, ids.initialize_operation)?;
        let registration = crate::ColdWriterRegistration::new(
            backend,
            plan.migration,
            ids.authority,
            ids.cold_writer,
            ids.cold_registration_operation,
        )?;
        let fence = Arc::new(crate::NativeSourceFence::from_native(
            identity,
            prepared.clone(),
            upgrade,
        )?);
        Ok(Initializing {
            plan,
            registry,
            source,
            transform: route.transform,
            readback: route.readback,
            fence,
            snapshot: snapshot_evidence,
            bootstrap,
            registration,
            authority: ids.authority,
            bootstrapped: false,
        })
    }

    async fn initialize_migration(&mut self) -> Result<Preparation, Error> {
        let setup = self.initializing.as_mut().ok_or(Error::InvalidState)?;
        let backend: OpenedBackend = self.target.as_ref().ok_or(Error::InvalidState)?.clone();
        if !setup.bootstrapped
            && crate::status(backend.as_ref(), setup.plan.migration, &setup.registry)
                .await?
                .is_some()
        {
            setup.bootstrapped = true;
        }
        if !setup.bootstrapped {
            match setup.bootstrap.advance().await? {
                crate::BootstrapProgress::Ready => setup.bootstrapped = true,
                crate::BootstrapProgress::Advanced | crate::BootstrapProgress::Pending => {
                    return Ok(Preparation::Pending)
                }
            }
        }
        match setup.registration.advance().await? {
            crate::BootstrapProgress::Ready => {}
            crate::BootstrapProgress::Advanced | crate::BootstrapProgress::Pending => {
                return Ok(Preparation::Pending)
            }
        }
        let budget = (self.bounds.bytes as usize)
            .checked_mul(4)
            .and_then(|v| v.checked_add(4 * crate::MAX_MANIFEST_BYTES))
            .ok_or(Error::Bounds)?;
        if self.intent.is_none() {
            self.intent = Some(Arc::new(
                crate::StoreIntent::open(backend.clone(), setup.plan.migration, budget).await?,
            ));
        }
        let intent = self.intent.as_ref().ok_or(Error::InvalidState)?.clone();
        match intent.reconcile(setup.plan.migration).await? {
            crate::ReconciliationProgress::Advanced | crate::ReconciliationProgress::Pending => {
                return Ok(Preparation::Pending)
            }
            crate::ReconciliationProgress::Unresolved => return Err(Error::ReconciliationRequired),
            crate::ReconciliationProgress::Resolved => {}
        }
        let readiness = Arc::new(ReadinessLatch {
            target: setup.plan.target.clone(),
            digest: Mutex::new(None),
        });
        let verifier = Arc::new(crate::ArchiveVerifier::new(
            backend.clone(),
            setup.source.clone(),
            setup.transform.clone(),
            setup.readback.clone(),
            setup.fence.clone(),
            setup.snapshot.clone(),
            readiness.clone(),
        )?);
        let services = crate::Services {
            source: setup.source.clone(),
            transform: setup.transform.clone(),
            verifier,
            activation: Some(Arc::new(crate::CoreActivation::new(backend.clone()))),
            intent: intent.clone(),
        };
        let coordinator = if crate::status(backend.as_ref(), setup.plan.migration, &setup.registry)
            .await?
            .is_some()
        {
            crate::Coordinator::resume(
                &setup.plan,
                setup.registry.clone(),
                backend,
                setup.authority,
                services,
            )
            .await?
        } else {
            crate::Coordinator::start(
                setup.plan.clone(),
                setup.registry.clone(),
                backend,
                setup.authority,
                services,
            )
            .await?
        };
        self.intent = Some(intent);
        self.coordinator = Some(coordinator);
        self.readiness = Some(readiness);
        self.initializing = None;
        Ok(Preparation::Pending)
    }

    async fn advance_migration(&mut self) -> Result<Preparation, Error> {
        let coordinator = self.coordinator.as_mut().ok_or(Error::InvalidState)?;
        if !matches!(
            coordinator.manifest().state,
            crate::State::Activated | crate::State::Retired
        ) {
            return match match coordinator.advance().await {
                Err(Error::IntentPending) => return Ok(Preparation::Pending),
                other => other?,
            } {
                crate::Progress::Advanced | crate::Progress::Pending => Ok(Preparation::Pending),
                crate::Progress::Reconcile => Err(Error::ReconciliationRequired),
                crate::Progress::Complete => Err(Error::InvalidState),
            };
        }
        let target = coordinator.manifest().target.clone();
        let upgrade_id = coordinator.manifest().migration;
        let proof = match coordinator.checkpoint_receipt(native::CompletionPhase::Activation) {
            Some(proof) => proof,
            None => self
                .intent
                .as_ref()
                .ok_or(Error::InvalidState)?
                .confirmed_checkpoint_phase(upgrade_id, native::CompletionPhase::Activation)
                .await?
                .ok_or(Error::ReconciliationRequired)?,
        };
        if proof.phase != native::CompletionPhase::Activation {
            return Err(Error::InvalidState);
        }
        let Some(response) = self.finish_checkpoint(proof).await? else {
            return Ok(Preparation::Pending);
        };
        let native::Response::RecoveryReady(recovery) = response.as_ref() else {
            return Err(Error::Corrupt);
        };
        if recovery.upgrade != upgrade_id
            || recovery.target.0 != target.dataset
            || recovery.activation_receipt_digest == [0; 32]
            || recovery.selector_digest == [0; 32]
        {
            return Err(Error::IdentityMismatch);
        }
        self.recovery_ready = Some(recovery.clone());
        let backend = match self
            .prepared
            .open(native::OpenBinding::Recovery(recovery.clone()))
            .await
        {
            Ok(backend) => backend,
            Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => {
                return Ok(Preparation::Pending)
            }
            Err(error) => return Err(native_error(error)),
        };
        if backend.info() != self.target.as_ref().ok_or(Error::InvalidState)?.info() {
            return Err(Error::IdentityMismatch);
        }
        self.opened = Some(backend.clone());
        self.binding = Some((upgrade_id, target.clone()));
        Ok(Preparation::Recovery(Box::new(RecoveryPending {
            backend,
            upgrade_id,
            target,
            recovery: self.recovery_ready.clone(),
        })))
    }

    async fn finish_checkpoint(
        &mut self,
        proof: Arc<native::ActivationReceipt>,
    ) -> Result<Option<Arc<native::Response>>, Error> {
        let native::Response::Begun(upgrade) =
            self.native_upgrade.as_deref().ok_or(Error::InvalidState)?
        else {
            return Err(Error::Corrupt);
        };
        if proof.attempt.dataset != upgrade.target.dataset {
            return Err(Error::IdentityMismatch);
        }
        let replace = match self.finish_request.as_deref() {
            Some(native::Request::Finish {
                activation_receipt, ..
            }) => activation_receipt.phase != proof.phase,
            None => true,
            _ => return Err(Error::InvalidState),
        };
        if replace {
            self.finish_request = Some(Arc::new(native::Request::Finish {
                upgrade: upgrade.reference.clone(),
                activation_receipt: native::ActivationReceipt {
                    attempt: proof.attempt,
                    candidate_fingerprint: proof.candidate_fingerprint,
                    original_result: proof.original_result.clone(),
                    checkpoint_address: proof.checkpoint_address.clone(),
                    checkpoint_value_digest: proof.checkpoint_value_digest,
                    phase: proof.phase,
                },
            }));
        }
        match self
            .prepared
            .bootstrap(
                self.finish_request
                    .as_ref()
                    .ok_or(Error::InvalidState)?
                    .clone(),
            )
            .await
        {
            Ok(response) => Ok(Some(response)),
            Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => Ok(None),
            Err(error) => Err(native_error(error)),
        }
    }

    /// Complete the same candidate after actual semantic readiness. For current
    /// storage the native serving capability must already match this OPEN.
    pub async fn finalize(&mut self, readiness: Digest32) -> Result<CompletionReceipt, Error> {
        if readiness == [0; 32] {
            return Err(Error::Verification);
        }
        if self.coordinator.is_some() {
            let latch = self.readiness.as_ref().ok_or(Error::InvalidState)?;
            {
                let mut digest = latch.digest.lock().map_err(|_| Error::Corrupt)?;
                if digest.is_some_and(|old| old != readiness) {
                    return Err(Error::IdentityMismatch);
                }
                *digest = Some(readiness);
            }
            let coordinator = self.coordinator.as_mut().ok_or(Error::InvalidState)?;
            if coordinator.manifest().state != crate::State::Retired {
                match coordinator.advance().await? {
                    crate::Progress::Pending => return Err(Error::IntentPending),
                    crate::Progress::Reconcile => return Err(Error::ReconciliationRequired),
                    crate::Progress::Advanced | crate::Progress::Complete => {}
                }
            }
            // A Complete attempt retained by this coordinator must bind this
            // run's exact readiness. On restart, the durable Complete capsule
            // instead proves the earlier candidate; the latch above binds the
            // newly hydrated live candidate independently without rewriting it.
            if coordinator.manifest().state != crate::State::Retired
                || (coordinator
                    .checkpoint_receipt(native::CompletionPhase::Complete)
                    .is_some()
                    && coordinator.manifest().readiness_digest != Some(readiness))
            {
                return Err(Error::Verification);
            }
            let migration = coordinator.manifest().migration;
            let proof = match coordinator.checkpoint_receipt(native::CompletionPhase::Complete) {
                Some(proof) => proof,
                None => self
                    .intent
                    .as_ref()
                    .ok_or(Error::InvalidState)?
                    .confirmed_checkpoint_phase(migration, native::CompletionPhase::Complete)
                    .await?
                    .ok_or(Error::ReconciliationRequired)?,
            };
            if proof.phase != native::CompletionPhase::Complete {
                return Err(Error::InvalidState);
            }
            let checkpoint_digest = proof.checkpoint_value_digest;
            let response = self
                .finish_checkpoint(proof)
                .await?
                .ok_or(Error::IntentPending)?;
            let native::Response::ServingReady(serving) = response.as_ref() else {
                return Err(Error::Corrupt);
            };
            if Some(&serving.recovery) != self.recovery_ready.as_ref()
                || serving.completed_checkpoint_digest != checkpoint_digest
            {
                return Err(Error::IdentityMismatch);
            }
        }
        let (upgrade, target) = self.binding.as_ref().ok_or(Error::InvalidState)?;
        let serving = self.prepared.serving().map_err(native_error)?;
        let opened = self.opened.as_ref().ok_or(Error::InvalidState)?;
        if !Arc::ptr_eq(&serving, opened) {
            return Err(Error::IdentityMismatch);
        }
        Ok(CompletionReceipt {
            upgrade: *upgrade,
            target: target.clone(),
            readiness,
        })
    }
}

async fn checked_native_fence(
    prepared: &native::Prepared,
    upgrade: &native::Upgrade,
    route: Digest32,
) -> Result<crate::CheckedNativeFence, Error> {
    let request = Arc::new(native::Request::CheckFence {
        upgrade: upgrade.reference.clone(),
    });
    let reply = loop {
        match prepared.bootstrap(request.clone()).await {
            Ok(reply) => break reply,
            Err(native::Error::Pending | native::Error::Busy | native::Error::Unknown) => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await
            }
            Err(error) => return Err(native_error(error)),
        }
    };
    let native::Response::Fence(fence) = reply.as_ref() else {
        return Err(Error::Corrupt);
    };
    if fence.upgrade != upgrade.reference.id
        || fence.source != upgrade.source
        || fence.snapshot != upgrade.snapshot
        || fence.enforcement_digest == [0; 32]
        || fence.observation_digest == [0; 32]
    {
        return Err(Error::FenceRequired);
    }
    Ok(crate::CheckedNativeFence {
        source: fence.source.clone(),
        upgrade: fence.upgrade,
        snapshot: fence.snapshot,
        enforcement: fence.enforcement_digest,
        observation: fence.observation_digest,
        route,
    })
}

fn target_identity(info: busbar_contract::persistence::BackendInfo) -> Result<Identity, Error> {
    if info.dataset.0 == [0; 16] || info.physical_version != 1 {
        return Err(Error::IdentityMismatch);
    }
    let mut hash = Sha256::new();
    hash.update(b"busbar.native.target.v1");
    hash.update(info.dataset.0);
    hash.update(info.atomic_domain);
    hash.update(info.clock_authority);
    hash.update(info.physical_version.to_le_bytes());
    hash.update([match info.durability {
        busbar_contract::persistence::Durability::Ephemeral => 0,
        busbar_contract::persistence::Durability::Local => 1,
        busbar_contract::persistence::Durability::Quorum => 2,
    }]);
    let artifact_digest = hash.finalize().into();
    let mut schema = Sha256::new();
    schema.update(b"busbar.core.format.v1");
    schema.update(CORE_FORMAT.owner);
    schema.update(CORE_FORMAT.logical.to_le_bytes());
    schema.update(CORE_FORMAT.physical.to_le_bytes());
    schema.update(CORE_FORMAT.codec.to_le_bytes());
    Ok(Identity {
        dataset: info.dataset.0,
        format: CORE_FORMAT,
        artifact_digest,
        schema_digest: schema.finalize().into(),
        product_release: [1, 6, 0],
    })
}

pub(crate) fn native_error(error: native::Error) -> Error {
    match error {
        native::Error::Bounds => Error::Bounds,
        native::Error::UnsupportedFormat => Error::UnsupportedPath,
        native::Error::SourceChanged => Error::IdentityMismatch,
        native::Error::Corrupt => Error::Corrupt,
        native::Error::Pending | native::Error::Busy => Error::IntentPending,
        native::Error::Unknown => Error::ReconciliationRequired,
        native::Error::Refused => Error::FenceRequired,
        native::Error::Unavailable | native::Error::MissingCapability => Error::MissingCapability,
    }
}
