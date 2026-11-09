// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native pre-open session ownership and capability routing, without migration policy.
use super::*;
use busbar_contract::persistence::lifecycle::{self as native, PreparedStore};
use futures::future::{BoxFuture, Shared};
use futures::FutureExt;
use std::sync::{Mutex, Weak};

type BootstrapFuture = Shared<BoxFuture<'static, Result<Arc<native::Response>, native::Error>>>;
type OpenFuture = Shared<BoxFuture<'static, Result<Arc<LoadedPersistence>, native::Error>>>;
type ReadyFuture = Shared<BoxFuture<'static, Result<(), native::Error>>>;
struct Attempt {
    body: Arc<sdk::bootstrap::Bootstrap>,
    future: BootstrapFuture,
}
#[derive(Default)]
struct State {
    last: Option<Attempt>,
    inspected: Option<Arc<native::Response>>,
    begun: Option<Arc<native::Response>>,
    begin_body: Option<Arc<sdk::bootstrap::Bootstrap>>,
    target: Option<Arc<native::Response>>,
    target_backend: Option<native::TargetBackend>,
    source_digest: Option<native::Digest>,
    recovery: Option<native::RecoveryReady>,
    serving: Option<native::ServingReady>,
    open_binding: Option<native::OpenBinding>,
    opening: Option<OpenFuture>,
    open_lent: Weak<sdk::bootstrap::OpenBindingBytes>,
    readying: Option<ReadyFuture>,
    backend: Option<Arc<LoadedPersistence>>,
}
/// Bound Store with retained settings, native instance and immutable pending calls.
/// Construction performs no ordinary OPEN and no schema mutation.
pub struct LoadedPrepared {
    session: Arc<Session>,
    dispatcher: Arc<Dispatcher>,
    settings: Arc<OpenLent>,
    limits: Limits,
    bounds: native::Bounds,
    state: Arc<Mutex<State>>,
}
impl std::fmt::Debug for LoadedPrepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoadedPrepared")
            .field("phase", &self.phase())
            .finish_non_exhaustive()
    }
}
impl LoadedPrepared {
    /// Retain the admitted native door and its protected settings before inspection.
    pub fn new(
        plugin: Plugin<StoreV4>,
        dispatcher: Arc<Dispatcher>,
        settings: &[u8],
        limits: Limits,
    ) -> Result<Self, native::Error> {
        if settings.len() > limits.descriptor_bytes {
            return Err(native::Error::Bounds);
        }
        let bounds = native::Bounds {
            items: u32::try_from(limits.output_items).map_err(|_| native::Error::Bounds)?,
            bytes: u32::try_from(limits.output_bytes.min(limits.decode_bytes))
                .map_err(|_| native::Error::Bounds)?,
        };
        if bounds.items == 0 || bounds.bytes == 0 {
            return Err(native::Error::Bounds);
        }
        let session = Arc::new(Session {
            plugin: Arc::new(plugin),
        });
        let mut settings = OpenLent::new(session.plugin.secret_refs(), settings);
        settings._session = Some(session.clone());
        Ok(Self {
            session,
            dispatcher,
            settings: Arc::new(settings),
            limits,
            bounds,
            state: Arc::default(),
        })
    }
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn validate_call(
        &self,
        body: &Arc<sdk::bootstrap::Bootstrap>,
        state: &State,
    ) -> Result<(), native::Error> {
        use native::{Phase, Request};
        let request = body.request().as_ref();
        match request {
            Request::Inspect { .. } if matches!(self.phase(), Phase::Bound | Phase::Prepared) => {
                Ok(())
            }
            Request::BeginOrResume {
                expected_source, ..
            } if matches!(
                self.phase(),
                Phase::Prepared | Phase::Upgrading | Phase::RecoveryReady
            ) =>
            {
                if let Some(prior) = state.begin_body.as_ref() {
                    if !prior.same_request(body) {
                        return Err(native::Error::SourceChanged);
                    }
                }
                let Some(native::Response::Inspected(inspection)) = state.inspected.as_deref()
                else {
                    return Err(native::Error::Refused);
                };
                if inspection.source.as_ref() != Some(expected_source) {
                    return Err(native::Error::SourceChanged);
                }
                Ok(())
            }
            Request::SourcePage { upgrade, .. }
            | Request::Target { upgrade }
            | Request::CheckFence { upgrade }
            | Request::Finish { upgrade, .. } => {
                let Some(native::Response::Begun(begun)) = state.begun.as_deref() else {
                    return Err(native::Error::Refused);
                };
                if !sdk::bootstrap::same_upgrade(upgrade, &begun.reference) {
                    return Err(native::Error::SourceChanged);
                }
                if let Request::SourcePage { snapshot, .. } = request {
                    if *snapshot != begun.snapshot {
                        return Err(native::Error::SourceChanged);
                    }
                }
                if let Request::Finish {
                    activation_receipt, ..
                } = request
                {
                    if activation_receipt.attempt.dataset != begun.target.dataset {
                        return Err(native::Error::SourceChanged);
                    }
                    if activation_receipt.phase == native::CompletionPhase::Complete
                        && (state.backend.is_none() || state.recovery.is_none())
                    {
                        return Err(native::Error::Refused);
                    }
                }
                if matches!(
                    self.phase(),
                    Phase::Upgrading | Phase::RecoveryReady | Phase::Open
                ) {
                    Ok(())
                } else {
                    Err(native::Error::Refused)
                }
            }
            _ => Err(native::Error::Refused),
        }
    }
}
impl PreparedStore for LoadedPrepared {
    fn phase(&self) -> native::Phase {
        self.session.plugin.store_phase()
    }
    fn bootstrap(&self, request: Arc<native::Request>) -> native::BootstrapCall<'_> {
        Box::pin(async move {
            let mut bounds = self.bounds;
            if let native::Request::Inspect { bounds: requested }
            | native::Request::SourcePage {
                bounds: requested, ..
            } = request.as_ref()
            {
                bounds.items = bounds.items.min(requested.items);
                bounds.bytes = bounds.bytes.min(requested.bytes);
            }
            let candidate = Arc::new(sdk::bootstrap::Bootstrap::new(request, bounds)?);
            let future = {
                let mut state = self.state();
                if let Some(last) = state.last.as_ref() {
                    if last.future.peek().is_none() {
                        if !last.body.same_request(&candidate) {
                            return Err(native::Error::Busy);
                        }
                        Some(last.future.clone())
                    } else if matches!(
                        last.future.peek(),
                        Some(Err(native::Error::Unknown
                            | native::Error::Pending
                            | native::Error::Unavailable
                            | native::Error::Corrupt))
                    ) && !last.body.same_request(&candidate)
                    {
                        return Err(native::Error::Pending);
                    } else {
                        None
                    }
                } else {
                    None
                }
                .unwrap_or_else(|| {
                    let body = state
                        .last
                        .as_ref()
                        .filter(|last| last.body.same_request(&candidate))
                        .map_or_else(|| candidate.clone(), |last| last.body.clone());
                    let session = self.session.clone();
                    let dispatcher = self.dispatcher.clone();
                    let settings = self.settings.clone();
                    let weak = Arc::downgrade(&self.state);
                    let limits = self.limits;
                    let validation = self.validate_call(&body, &state);
                    let retained = body.clone();
                    let future = async move {
                        validation?;
                        let response = invoke(
                            session.clone(),
                            dispatcher,
                            settings,
                            retained.clone(),
                            limits,
                        )
                        .await?;
                        finish_response(&session, &weak, retained, response).await
                    }
                    .boxed()
                    .shared();
                    state.last = Some(Attempt {
                        body,
                        future: future.clone(),
                    });
                    future
                })
            };
            future.await
        })
    }
    fn target(&self, upgrade: native::UpgradeRef) -> native::TargetCall<'_> {
        Box::pin(async move {
            self.bootstrap(Arc::new(native::Request::Target { upgrade }))
                .await?;
            let mut state = self.state();
            if let Some(target) = state.target_backend.as_ref() {
                return Ok(target.clone());
            }
            let Some(native::Response::Target(binding)) = state.target.as_deref() else {
                return Err(native::Error::Corrupt);
            };
            let backend = LoadedPersistence {
                plugin: self.session.plugin.clone(),
                _session: self.session.clone(),
                dispatcher: self.dispatcher.clone(),
                info: binding.info,
                limits: self.limits,
                next_worker: AtomicU32::new(0),
            };
            let target: native::TargetBackend = Arc::new(Target {
                backend,
                upgrade: binding.upgrade,
                _binding: state.target.clone().unwrap(),
            });
            state.target_backend = Some(target.clone());
            Ok(target)
        })
    }
    fn open(&self, binding: native::OpenBinding) -> native::PreparedOpenCall<'_> {
        Box::pin(async move {
            let future = {
                let mut state = self.state();
                if let Some(prior) = state.open_binding.as_ref() {
                    if prior != &binding {
                        return Err(native::Error::Refused);
                    }
                }
                // A completed transient OPEN may be retried only once its native
                // crossing has retired and no actual OPEN succeeded. An opened
                // instance without validated metadata remains reconciliation work.
                if state.opening.as_ref().is_some_and(|attempt| {
                    matches!(
                        attempt.peek(),
                        Some(Err(native::Error::Unknown
                            | native::Error::Pending
                            | native::Error::Busy
                            | native::Error::Unavailable))
                    )
                }) && state.open_lent.upgrade().is_none()
                    && !self.session.plugin.is_open()
                {
                    state.opening = None;
                }
                if let Some(backend) = state.backend.as_ref() {
                    futures::future::ready(Ok(backend.clone())).boxed().shared()
                } else if let Some(attempt) = state.opening.as_ref() {
                    attempt.clone()
                } else {
                    if state.last.as_ref().is_some_and(|last| {
                        last.future.peek().is_none()
                            || matches!(
                                last.future.peek(),
                                Some(Err(native::Error::Unknown
                                    | native::Error::Pending
                                    | native::Error::Corrupt))
                            )
                    }) {
                        return Err(native::Error::Pending);
                    }
                    let recovery = matches!(binding, native::OpenBinding::Recovery(_));
                    match &binding {
                        native::OpenBinding::Recovery(expected)
                            if state.recovery.as_ref() == Some(expected)
                                && self.phase() == native::Phase::RecoveryReady => {}
                        native::OpenBinding::Empty | native::OpenBinding::Current { .. } => {
                            let Some(native::Response::Inspected(inspection)) =
                                state.inspected.as_deref()
                            else {
                                return Err(native::Error::Refused);
                            };
                            if self.phase() != native::Phase::Prepared
                                || !sdk::bootstrap::open_matches(inspection, &binding)
                            {
                                return Err(native::Error::SourceChanged);
                            }
                            if !inspection
                                .capabilities
                                .contains(&native::NativeCapability::CurrentOpen)
                            {
                                return Err(native::Error::MissingCapability);
                            }
                        }
                        _ => return Err(native::Error::Refused),
                    }
                    let encoded = Arc::new(sdk::bootstrap::OpenBindingBytes::new(
                        binding.clone(),
                        self.bounds,
                    )?);
                    state.open_lent = Arc::downgrade(&encoded);
                    let session = self.session.clone();
                    let dispatcher = self.dispatcher.clone();
                    let settings = self.settings.clone();
                    let limits = self.limits;
                    let weak = Arc::downgrade(&self.state);
                    let retained_binding = binding.clone();
                    let future = async move {
                        let backend = Arc::new(
                            LoadedPersistence::open_session(
                                session.plugin.clone(),
                                session,
                                dispatcher,
                                settings,
                                limits,
                                Some(encoded),
                                false,
                            )
                            .await
                            .map_err(|failure| failure.code)?,
                        );
                        if let Some(state) = weak.upgrade() {
                            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
                            let expected = match &retained_binding {
                                native::OpenBinding::Recovery(ready) => Some(ready.target),
                                native::OpenBinding::Current { source, .. } => Some(source.dataset),
                                native::OpenBinding::Empty => None,
                            };
                            if expected.is_some_and(|dataset| dataset != backend.info.dataset) {
                                return Err(native::Error::SourceChanged);
                            }
                            if recovery {
                                let Some(native::Response::Begun(begun)) = state.begun.as_deref()
                                else {
                                    return Err(native::Error::Corrupt);
                                };
                                if backend.info != begun.target {
                                    return Err(native::Error::SourceChanged);
                                }
                            }
                            state.backend = Some(backend.clone());
                        }
                        Ok(backend)
                    }
                    .boxed()
                    .shared();
                    state.open_binding = Some(binding.clone());
                    state.opening = Some(future.clone());
                    future
                }
            };
            let backend = future.await?;
            if !matches!(binding, native::OpenBinding::Recovery(_)) {
                let ready = {
                    let mut state = self.state();
                    retained_ready(&mut state, backend.clone())
                };
                ready.await?;
            }
            Ok(backend as owned::axis::OpenedBackend)
        })
    }
    fn serving(&self) -> Result<owned::axis::OpenedBackend, native::Error> {
        let state = self.state();
        if self.phase() != native::Phase::Open {
            return Err(native::Error::Pending);
        }
        if matches!(state.open_binding, Some(native::OpenBinding::Recovery(_)))
            && state.serving.is_none()
            || !matches!(
                state.readying.as_ref().and_then(|ready| ready.peek()),
                Some(Ok(()))
            )
        {
            return Err(native::Error::Pending);
        }
        state
            .backend
            .as_ref()
            .cloned()
            .map(|backend| backend as owned::axis::OpenedBackend)
            .ok_or(native::Error::Pending)
    }
}

fn retained_ready(state: &mut State, backend: Arc<LoadedPersistence>) -> ReadyFuture {
    if state.readying.as_ref().is_some_and(|future| {
        matches!(
            future.peek(),
            Some(Err(native::Error::Unknown
                | native::Error::Pending
                | native::Error::Unavailable
                | native::Error::Busy))
        )
    }) {
        state.readying = None;
    }
    state
        .readying
        .get_or_insert_with(|| {
            async move { backend.ready().await.map_err(|failure| failure.code) }
                .boxed()
                .shared()
        })
        .clone()
}

async fn finish_response(
    session: &Arc<Session>,
    weak: &Weak<Mutex<State>>,
    body: Arc<sdk::bootstrap::Bootstrap>,
    response: Arc<native::Response>,
) -> Result<Arc<native::Response>, native::Error> {
    use native::{Request, Response};
    let Some(state) = weak.upgrade() else {
        return Err(native::Error::Unavailable);
    };
    let ready = {
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        match (body.request().as_ref(), response.as_ref()) {
            (Request::Inspect { .. }, Response::Inspected(inspection)) => {
                if (inspection.state == native::InspectionState::Empty)
                    != inspection.source.is_none()
                {
                    return Err(native::Error::Corrupt);
                }
                state.inspected = Some(response.clone());
                None
            }
            (
                Request::BeginOrResume {
                    expected_source, ..
                },
                Response::Begun(begun),
            ) => {
                if begun.source != *expected_source || sdk::metadata::encode(begun.target).is_err()
                {
                    return Err(native::Error::SourceChanged);
                }
                // A post-fence catalogue may add immutable snapshot facts to
                // the original inspection. The native source identity remains exact.
                let Some(Response::Inspected(inspection)) = state.inspected.as_deref() else {
                    return Err(native::Error::Corrupt);
                };
                if inspection.catalogue.len() != begun.catalogue.len()
                    || !inspection
                        .catalogue
                        .iter()
                        .zip(&begun.catalogue)
                        .all(|(before, after)| {
                            before.name == after.name && before.columns == after.columns
                        })
                {
                    return Err(native::Error::SourceChanged);
                }
                if let Some(Response::Begun(prior)) = state.begun.as_deref() {
                    if !sdk::bootstrap::same_upgrade(&prior.reference, &begun.reference)
                        || prior.snapshot != begun.snapshot
                        || prior.target != begun.target
                        || prior.catalogue != begun.catalogue
                    {
                        return Err(native::Error::SourceChanged);
                    }
                }
                if session.plugin.store_phase() == native::Phase::Prepared
                    && !session.plugin.advance_store_phase(native::Phase::Upgrading)
                {
                    return Err(native::Error::Corrupt);
                }
                state.begun = Some(response.clone());
                state.begin_body = Some(body.clone());
                None
            }
            (
                Request::SourcePage {
                    snapshot, family, ..
                },
                Response::SourcePage(page),
            ) => {
                if page.snapshot != *snapshot
                    || page.family != *family
                    || state
                        .source_digest
                        .is_some_and(|digest| digest != page.source_digest)
                {
                    return Err(native::Error::SourceChanged);
                }
                state.source_digest = Some(page.source_digest);
                None
            }
            (Request::Target { upgrade }, Response::Target(target)) => {
                let Some(Response::Begun(begun)) = state.begun.as_deref() else {
                    return Err(native::Error::Corrupt);
                };
                if target.upgrade != upgrade.id || target.info != begun.target {
                    return Err(native::Error::SourceChanged);
                }
                if !session.plugin.admit_store_target() {
                    return Err(native::Error::Corrupt);
                }
                state.target = Some(response.clone());
                None
            }
            (Request::CheckFence { upgrade }, Response::Fence(fence)) => {
                let Some(Response::Begun(begun)) = state.begun.as_deref() else {
                    return Err(native::Error::Corrupt);
                };
                if fence.upgrade != upgrade.id
                    || fence.source != begun.source
                    || fence.snapshot != begun.snapshot
                {
                    return Err(native::Error::SourceChanged);
                }
                None
            }
            (
                Request::Finish {
                    upgrade,
                    activation_receipt,
                },
                Response::RecoveryReady(ready),
            ) if activation_receipt.phase == native::CompletionPhase::Activation => {
                let Some(Response::Begun(begun)) = state.begun.as_deref() else {
                    return Err(native::Error::Corrupt);
                };
                if ready.upgrade != upgrade.id || ready.target != begun.target.dataset {
                    return Err(native::Error::SourceChanged);
                }
                if !session
                    .plugin
                    .advance_store_phase(native::Phase::RecoveryReady)
                {
                    return Err(native::Error::Unavailable);
                }
                state.recovery = Some(ready.clone());
                None
            }
            (
                Request::Finish {
                    activation_receipt, ..
                },
                Response::ServingReady(ready),
            ) if activation_receipt.phase == native::CompletionPhase::Complete => {
                if state.recovery.as_ref() != Some(&ready.recovery)
                    || ready.completed_checkpoint_digest
                        != activation_receipt.checkpoint_value_digest
                {
                    return Err(native::Error::SourceChanged);
                }
                if let Some(confirmed) = state.serving.as_ref() {
                    if confirmed != ready {
                        return Err(native::Error::SourceChanged);
                    }
                    None
                } else {
                    Some((
                        state.backend.clone().ok_or(native::Error::Refused)?,
                        ready.clone(),
                    ))
                }
            }
            _ => return Err(native::Error::Corrupt),
        }
    };
    let ready = ready.map(|(backend, confirmation)| {
        let mut retained = state.lock().unwrap_or_else(|error| error.into_inner());
        let future = retained_ready(&mut retained, backend);
        (future, confirmation)
    });
    // The retained call is stored in State. Never retain State itself across an
    // await, which would keep a dropped prepared session in a reference cycle.
    drop(state);
    if let Some((future, confirmation)) = ready {
        if !session.plugin.advance_store_phase(native::Phase::Open) {
            return Err(native::Error::Corrupt);
        }
        future.await?;
        let state = weak.upgrade().ok_or(native::Error::Unavailable)?;
        state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .serving = Some(confirmation);
    }
    Ok(response)
}

struct Target {
    backend: LoadedPersistence,
    upgrade: native::Id,
    _binding: Arc<native::Response>,
}
impl native::MigrationTarget for Target {
    fn upgrade_id(&self) -> native::Id {
        self.upgrade
    }
}
impl PersistenceBackend for Target {
    fn info(&self) -> owned::BackendInfo {
        self.backend.info()
    }
    fn read(&self, request: Arc<owned::Read>) -> owned::Call<'_, owned::ReadResult> {
        self.backend.read(request)
    }
    fn scan(&self, request: Arc<owned::Scan>) -> owned::Call<'_, owned::Page> {
        self.backend.scan(request)
    }
    fn commit(&self, candidate: owned::PreparedCandidate) -> owned::Call<'_, owned::Decision> {
        self.backend.commit(candidate)
    }
    fn clock(&self, dataset: owned::DatasetId) -> owned::Call<'_, owned::ClockObservation> {
        self.backend.clock(dataset)
    }
}

struct BootstrapIo {
    session: Arc<Session>,
    settings: Arc<OpenLent>,
    body: Arc<sdk::bootstrap::Bootstrap>,
    output: UnsafeCell<zeroize::Zeroizing<Vec<u8>>>,
}
// SAFETY: only one retained dispatcher future owns each crossing. Output is read
// or resized only after that crossing retires; detached outcomes never resize it.
unsafe impl Send for BootstrapIo {}
// SAFETY: immutable inputs and the same exclusive output discipline apply to clones.
unsafe impl Sync for BootstrapIo {}
impl BootstrapIo {
    fn frame(&self) -> Frame<wire::BootstrapIn, wire::BootstrapOut> {
        // SAFETY: frame is constructed before submission or after native retirement.
        let output = unsafe { &mut *self.output.get() };
        Frame::new(
            wire::BootstrapIn {
                head: in_head(),
                host: std::ptr::null(),
                settings: octets(&self.settings.settings),
                secrets: self.settings.blobs.as_ptr(),
                secrets_len: self.settings.blobs.len(),
                generation: 1,
                request: self.body.blob(),
                result: HostBuf {
                    ptr: output.as_mut_ptr(),
                    cap: output.len(),
                },
            },
            wire::BootstrapOut {
                head: out_head(),
                instance: std::ptr::null_mut(),
                written: 0,
                needed: 0,
            },
        )
    }
}
async fn invoke(
    session: Arc<Session>,
    dispatcher: Arc<Dispatcher>,
    settings: Arc<OpenLent>,
    body: Arc<sdk::bootstrap::Bootstrap>,
    limits: Limits,
) -> Result<Arc<native::Response>, native::Error> {
    let ticket = dispatcher.mint(0).ok_or(native::Error::Busy)?;
    let _recycle = Recycle(&dispatcher, ticket);
    let bounds = body.bounds();
    let io = Arc::new(BootstrapIo {
        session,
        settings,
        body,
        output: UnsafeCell::new(zeroize::Zeroizing::new(vec![
            0;
            (bounds.bytes as usize)
                .min(1024)
        ])),
    });
    let until = deadline();
    for attempt in 0..2 {
        let done = dispatcher
            .submit_lent(
                &io.session.plugin,
                ticket,
                wire::slot::BOOTSTRAP,
                io.frame(),
                DeadlineClass::Call,
                until,
                io.clone() as Lent,
            )
            .await;
        let lease = AnswerLease::new(&io.session.plugin, done.lease);
        if done.detached || done.disposition.is_some() {
            return Err(native::Error::Unknown);
        }
        let frame = done.frame.as_ref().ok_or(native::Error::Unknown)?;
        if done.outcome == Outcome::Failed && frame.out.needed != 0 && attempt == 0 {
            let needed = usize::try_from(frame.out.needed).map_err(|_| native::Error::Unknown)?;
            if needed > limits.output_bytes || needed > bounds.bytes as usize {
                return Err(native::Error::Unknown);
            }
            drop(lease);
            // SAFETY: this native crossing retired, so the next frame may change only its output allocation.
            let output = unsafe { &mut *io.output.get() };
            *output = zeroize::Zeroizing::new(vec![0; needed]);
            continue;
        }
        if done.outcome != Outcome::Ready {
            return Err(if done.outcome == Outcome::Refused {
                native::Error::Refused
            } else {
                native::Error::Unknown
            });
        }
        let written = usize::try_from(frame.out.written).map_err(|_| native::Error::Corrupt)?;
        // SAFETY: native completion returned ownership of the checked output allocation.
        let output = unsafe { &*io.output.get() };
        if written > output.len() {
            return Err(native::Error::Corrupt);
        }
        return native::codec::decode_response(&output[..written], bounds).map(Arc::new);
    }
    Err(native::Error::Unknown)
}

#[cfg(test)]
#[path = "../tests/store_prepared_tests.rs"]
mod tests;
