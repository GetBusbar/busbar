// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The authenticated route on the port path (PROOF-056, PROOF-057; LEDGER S-C7). The old plane
//! driver's `ROUTE_AUTHENTICATED` continuation (`plane_driver/authenticated_route.rs`, deleted in
//! cut5) has one successor: the round-18 deferred FORWARD (IF plane.rs `piece`). The plane states a
//! caller-scoped LOOKUP (`LK_CALLER`) in its `request` answer; core resolves it as a prerequisite
//! before anything is admitted (`Task::resolve_before_hooks`, `port_intents::prerequisite`); the
//! plane answers the `P_LOOKUP` piece with FORWARD and the stored destination as its wants; and the
//! request's one admission then runs exactly as after a `request` FORWARD
//! (`port_serve::run_pending_session`): the walk is resolved and the key's grant of it judged
//! (`Pending::resolve_walk`), then the money is asked once (`Pending::admit_money`).
//!
//! Each test drives one whole session (`port_serve::run_session`) over a real pending admission
//! whose money records what it was asked for and refuses (402): the question is what is admitted,
//! and whether anything is, before any money. The plane is scripted as plane-llm's stored
//! interaction: the hit names the model, a miss is the plane's own 404.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use super::*;
use busbar_contract::records::{ScopeRef, VirtualKey};
use busbar_plugin_abi::plane::LK_CALLER;

use crate::host_services::{
    InvocationContext, KernelServices, NativeInvocationAdmission, Nest, NestDone, NestRoute,
    ServingGeneration,
};
use crate::plane_driver::port_admission::Pending;
use crate::plane_driver::port_intents::subject_scope;
use crate::plane_driver::port_serve::Ran;
use crate::plane_driver::request_admission::{RequestAllocation, RequestRoutes, RequestWalk};
use crate::refusal::ClientRefusal;

/// The caller's stored resource the plane looks up (a stored interaction's id).
const KEY: &[u8] = b"interaction/i-1";
/// The stored record: the model entry that created the resource.
const DEST: &[u8] = b"dest:m";
/// The model the record names, a direct model of the seat's catalog.
const MODEL: &str = "m";
/// The old continuation's own ceiling on its wait (`LOOKUP_CEILING`), which the port path's record
/// calls keep (`Namespace::caller`): the request's deadline in these tests.
const DEADLINE: Duration = Duration::from_secs(30);

struct NoChildren;
impl NestRoute for NoChildren {
    fn nest(&self, _: InvocationContext, _: Nest, _: NestDone) {
        panic!("nothing nests before admission")
    }
}

/// A plane session; its drop (by `end` or by cancellation) is counted.
struct Held(Arc<AtomicUsize>);
impl Drop for Held {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// plane-llm's authenticated route: `request` looks the caller's record up; the `P_LOOKUP` piece
/// that carries it is answered with the deferred FORWARD to the model it names, a miss with the
/// plane's own 404.
#[derive(Default)]
struct Interactions {
    /// Each `P_LOOKUP` the plane was handed: whether it carried the stored record.
    looked: Mutex<Vec<bool>>,
    dropped: Arc<AtomicUsize>,
    ended: AtomicUsize,
    upstreams: AtomicUsize,
}

impl Calls for Interactions {
    type Session = Held;

    fn request(
        &self,
        _: &PlaneIn<'_>,
        _: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<Held, PortError> {
        sink(PlaneOut::Lookup {
            flags: LK_CALLER,
            limit: 1,
            key: KEY,
        });
        Ok(Held(Arc::clone(&self.dropped)))
    }

    fn piece(
        &self,
        _: &mut Held,
        from: u32,
        _: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        if from != FROM_CORE || flags != P_LOOKUP {
            return Ok(());
        }
        let hit = bytes.windows(DEST.len()).any(|window| window == DEST);
        self.looked.lock().unwrap().push(hit);
        if hit {
            sink(PlaneOut::Forward { stream: false });
            sink(PlaneOut::Want(W_MODEL, FactRef::Text(MODEL)));
        } else {
            sink(PlaneOut::Respond { status: 404 });
            sink(PlaneOut::End);
        }
        Ok(())
    }

    fn rewrite(
        &self,
        _: &mut Held,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Ok(())
    }

    fn end(&self, _: Held, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        self.ended.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn probe(&self, _: &TargetIn<'_>, _: &mut dyn FnMut(PlaneOut<'_>)) -> Result<Held, PortError> {
        Err(nope())
    }

    fn render(
        &self,
        _: &PlaneIn<'_>,
        _: u32,
        _: &[u8],
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        Err(nope())
    }

    fn upstream(
        &self,
        _: &mut Held,
        _: &TargetIn<'_>,
        _: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        self.upstreams.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// One stored row: its scope's subject (`None`: the instance-wide scope), key and value.
type Row = (Option<[u8; 32]>, &'static [u8], &'static [u8]);

/// The plane instance's records. Each LOOKUP it is asked is kept with the scope it was asked in;
/// `during` runs while a LOOKUP is pending (the request stopped or reloaded under it); `hang`
/// never answers.
#[derive(Default)]
struct Records {
    rows: Vec<Row>,
    asked: Mutex<Vec<Option<[u8; 32]>>>,
    during: Option<Box<dyn Fn() + Send + Sync>>,
    hang: bool,
}

impl IntentHost for Records {
    fn lookup<'a>(
        &'a self,
        scope: Scope,
        _: u32,
        _: u32,
        key: &'a [u8],
        looked: &'a mut Looked,
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        self.asked.lock().unwrap().push(scope.subject);
        if self.hang {
            return Box::pin(std::future::pending());
        }
        if let Some(during) = &self.during {
            during();
        }
        for (subject, stored, value) in &self.rows {
            if *subject == scope.subject && *stored == key {
                looked.push(&[key], value);
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }
    fn store<'a>(
        &'a self,
        _: Scope,
        _: u32,
        _: u64,
        _: &'a [u8],
        _: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>> {
        panic!("an authenticated route writes nothing before its admission")
    }
    fn delete<'a>(&'a self, _: Scope, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        panic!("an authenticated route deletes nothing before its admission")
    }
    fn commit<'a>(
        &'a self,
        _: Scope,
        _: &'a [CommitOp<'a>],
    ) -> BoxFut<'a, Result<CommitOutcome, RecordsDenied>> {
        panic!("an authenticated route commits nothing before its admission")
    }
    fn work<'a>(
        &'a self,
        _: &'a crate::plane_driver::port_intents::WorkIntent<'a>,
    ) -> BoxFut<'a, WorkOutcome<'a>> {
        Box::pin(std::future::ready(WorkOutcome::unsupported()))
    }
    fn push<'a>(&'a self, _: u64, _: &'a [u8]) -> BoxFut<'a, Result<(), RecordsDenied>> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn signal(&self, _: &[u8], _: Option<[u8; 32]>) {}
}

/// alice's record, in alice's own scope.
fn alices_record() -> Records {
    Records {
        rows: vec![(Some(subject_scope("alice")), KEY, DEST)],
        ..Records::default()
    }
}

/// A carrier that counts its dials.
#[derive(Default)]
struct Dials(usize);
impl UpSend for Dials {
    type Rest<'a> = Whole;

    async fn open<'a>(
        &'a mut self,
        _: &'a Candidate,
        _: crate::plane_driver::port_session::UpExchange,
    ) -> Result<UpOpen<Whole>, SendFailed> {
        self.0 += 1;
        Err(SendFailed)
    }
}

/// The seat's catalog: a direct model `m`, and pool `p` over it; keys are scoped by pool.
fn routes() -> RequestRoutes {
    use crate::config::{self, providers, Grammar};
    use crate::plane_driver::provider_catalog::ProviderPlane;
    let grammar = Grammar::empty();
    let definitions = providers::catalog_from_str(
        "provider:\n  protocol: wire\n  base_url: https://upstream.example\n",
        &grammar,
    )
    .unwrap();
    let deployment = config::deploy_from_yaml_str(
        "providers:\n  provider: {api_key: none}\nmodels:\n  m:\n    provider: provider\n    upstream_model: wire-m\npools:\n  p: {members: [m]}\n",
        &grammar,
    )
    .unwrap();
    let mut resolved = config::resolve_with_provider_planes(
        &deployment,
        &definitions,
        &[ProviderPlane {
            instance: "seat".into(),
            image: "image".into(),
            dialects: ["wire".into()].into(),
            schema: r#"{"type":"object","additionalProperties":false}"#.into(),
        }],
    )
    .unwrap();
    RequestRoutes::new(
        "seat",
        Some(Arc::from("pool")),
        Some(Arc::new(resolved.catalogs.remove("seat").unwrap())),
        None,
    )
    .unwrap()
}

/// One request as its session finds it on the native path: registered under its verified key,
/// its walk not resolved, its money not asked. `asked` is what the money was asked for, by the
/// domain the walk resolved to; the money then refuses (402).
struct Request {
    pending: Pending,
    context: InvocationContext,
    walk: Walk,
    asked: Arc<Mutex<Vec<String>>>,
    _lease: NativeInvocationAdmission,
}

fn key(id: &str, allowed_scopes: Option<Vec<ScopeRef>>) -> VirtualKey {
    VirtualKey {
        id: id.into(),
        enabled: true,
        allowed_scopes,
        ..Default::default()
    }
}

fn request(unit: u64, key: VirtualKey) -> Request {
    let core = Arc::new(KernelServices::new());
    let caller = busbar_contract::services::Caller::for_test(
        Arc::from("seat"),
        busbar_contract::kinds::codes::KindCode::Plane,
    );
    let lease = core.admit_native_invocation(&caller).unwrap();
    assert!(core.units().pre_admitted_for(
        unit,
        &caller,
        crate::host_units::UnitRecord {
            principal: Some(Arc::new(key)),
            depth: 0,
        }
    ));
    let context = InvocationContext::new(
        Arc::new(ServingGeneration::new(core, Arc::new(NoChildren))),
        caller,
        unit,
    )
    .unwrap();
    let walk = Walk {
        queue: [candidate()].into(),
        request: Some(RequestWalk::new(&context).unwrap()),
        ..Walk::default()
    };
    let allocation = RequestAllocation::new(
        context.clone(),
        Arc::new(crate::cost::CostModel::resolve_parts(
            None,
            0,
            &Default::default(),
        )),
        100,
    )
    .unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let money = Arc::clone(&asked);
    let pending = Pending::new(allocation, Arc::new(routes()), None, move |receipt| {
        money
            .lock()
            .unwrap()
            .push(format!("money {:?}", receipt.domain()));
        Err(ClientRefusal {
            status: 402,
            code: busbar_plugin_abi::fail::refused::R_BUDGET,
            text: "budget exhausted".into(),
        })
    });
    Request {
        pending,
        context,
        walk,
        asked,
        _lease: lease,
    }
}

/// The session's effects on the native path: the pending admission and its invocation.
struct Admitting<'a>(&'a Pending);
impl Effects for Admitting<'_> {
    fn admission(&self) -> Option<&Pending> {
        Some(self.0)
    }
    fn invocation(&self) -> Option<&InvocationContext> {
        Some(self.0.context())
    }
    fn emit(&self, _: u64, _: &[u8]) {
        panic!("a request that was never paid for emits nothing")
    }
}

/// One session of `plane` for `request`, its intents resolved under `resolver` as
/// `port::drive_session` builds it: the verified principal the route's auth admitted, or none.
async fn serve(
    plane: &Interactions,
    request: &mut Request,
    resolver: &Resolver<'_>,
    far: &mut Dials,
) -> Result<Ran, SessionError> {
    let effects = Admitting(&request.pending);
    let refusals = CoreRefusals::new();
    let drive = Drive {
        resolver,
        members: Some(&mut request.walk),
        send: Some(far),
        dialect: "wire",
        refusals: &refusals,
        effects: &effects,
        books: &request.pending,
        carrier: None,
    };
    crate::plane_driver::port_serve::run_session(plane, &req(), b"{}", drive).await
}

fn asked(request: &Request) -> Vec<String> {
    request.asked.lock().unwrap().clone()
}

/// A verified caller's stored record routes the request to the model it names, and the request is
/// then admitted exactly as a `request` FORWARD is: the walk to that model is resolved and the key's
/// grant judged, and the money is asked once, for that destination. The LOOKUP was asked in the
/// caller's own scope, and the record reached the plane.
#[tokio::test]
async fn authenticated_route_preserves_request_and_runs_normal_verification() {
    let plane = Interactions::default();
    let host = alices_record();
    let resolver = Resolver::new(&host, None).with_principal("alice", &[]);
    let mut request = request(51, key("alice", None));
    let mut far = Dials::default();
    let result = serve(&plane, &mut request, &resolver, &mut far).await;
    assert!(
        matches!(&result, Err(SessionError::AdmissionRefused(refusal)) if refusal.status == 402),
        "{result:?}"
    );
    assert_eq!(*host.asked.lock().unwrap(), [Some(subject_scope("alice"))]);
    assert_eq!(*plane.looked.lock().unwrap(), [true]);
    assert_eq!(
        asked(&request),
        [format!("money DirectModel({MODEL:?})")],
        "the stored destination's walk was resolved and its money asked once"
    );
    assert_eq!(far.0, 0, "nothing is dialled before the money admits");
    assert_eq!(plane.upstreams.load(Ordering::SeqCst), 0);
}

/// The record is reached only through a caller reference. A route whose auth admitted no verified
/// principal (PUBLIC, or OPTIONAL with an anonymous caller) has none: core answers the caller-scoped
/// LOOKUP itself, the store is never asked, and the plane gets no record. Another verified caller's
/// reference is its own scope, where alice's record is not. Neither reaches the stored destination.
#[tokio::test]
async fn authenticated_route_requires_authentication_declaration_and_caller_reference() {
    let plane = Interactions::default();
    let host = alices_record();
    let unverified = Resolver::new(&host, None);
    let mut request_unverified = request(52, key("alice", None));
    let mut far = Dials::default();
    let result = serve(&plane, &mut request_unverified, &unverified, &mut far).await;
    assert!(result.is_err(), "{result:?}");
    assert!(
        host.asked.lock().unwrap().is_empty(),
        "no caller reference: the store is never asked"
    );
    assert_eq!(*plane.looked.lock().unwrap(), [false]);
    assert_eq!(
        asked(&request_unverified),
        ["money Local"],
        "no destination is resolved"
    );

    let plane = Interactions::default();
    let bob = Resolver::new(&host, None).with_principal("bob", &[]);
    let mut request_bob = request(53, key("bob", None));
    let result = serve(&plane, &mut request_bob, &bob, &mut far).await;
    assert!(result.is_err(), "{result:?}");
    assert_eq!(*host.asked.lock().unwrap(), [Some(subject_scope("bob"))]);
    assert_eq!(*plane.looked.lock().unwrap(), [false]);
    assert_eq!(asked(&request_bob), ["money Local"]);
    assert_eq!(far.0, 0);
    assert_eq!(plane.upstreams.load(Ordering::SeqCst), 0);
}

/// A stored destination is no grant. alice's record names model `m`, but her key's grants no longer
/// reach it (they were narrowed to pool `p`): the deferred FORWARD is judged against the key's grants
/// as they stand, and refused (403) before any money is asked and before anything is dialled.
#[tokio::test]
async fn authenticated_route_cannot_bypass_revoked_destination_grant() {
    let plane = Interactions::default();
    let host = alices_record();
    let resolver = Resolver::new(&host, None).with_principal("alice", &[]);
    let mut request = request(54, key("alice", Some(vec![ScopeRef::pool("p")])));
    let mut far = Dials::default();
    let result = serve(&plane, &mut request, &resolver, &mut far).await;
    assert!(
        matches!(&result, Err(SessionError::AdmissionRefused(refusal)) if refusal.status == 403),
        "{result:?}"
    );
    assert_eq!(
        *plane.looked.lock().unwrap(),
        [true],
        "the record was found"
    );
    assert!(asked(&request).is_empty(), "no money is asked");
    assert_eq!(far.0, 0);
    assert!(request.walk.served.is_empty());
    assert_eq!(plane.upstreams.load(Ordering::SeqCst), 0);
}

/// A caller with no record of her own is not served from a default scope: the same key stored
/// instance-wide is not hers, the LOOKUP is asked in her scope alone and misses, the plane answers
/// its own refusal, and no destination is resolved.
#[tokio::test]
async fn authenticated_route_missing_record_refuses_without_default_scope() {
    let plane = Interactions::default();
    let host = Records {
        rows: vec![(None, KEY, DEST)],
        ..Records::default()
    };
    let resolver = Resolver::new(&host, None).with_principal("alice", &[]);
    let mut request = request(55, key("alice", None));
    let mut far = Dials::default();
    let result = serve(&plane, &mut request, &resolver, &mut far).await;
    assert!(result.is_err(), "{result:?}");
    assert_eq!(*host.asked.lock().unwrap(), [Some(subject_scope("alice"))]);
    assert_eq!(*plane.looked.lock().unwrap(), [false]);
    assert_eq!(
        asked(&request),
        ["money Local"],
        "no destination is resolved"
    );
    assert_eq!(far.0, 0);
    assert_eq!(plane.upstreams.load(Ordering::SeqCst), 0);
}

/// A LOOKUP that never answers holds the request no longer than its deadline: the session bounded
/// by it ends there, its plane session is cancelled once (dropped, never ended), and nothing was
/// admitted: no money asked, nothing dialled, no effect allowed.
#[tokio::test(start_paused = true)]
async fn authenticated_route_pending_is_bounded_by_request_deadline_and_cleans_once() {
    let plane = Interactions::default();
    let host = Records {
        hang: true,
        ..alices_record()
    };
    let resolver = Resolver::new(&host, None).with_principal("alice", &[]);
    let mut request = request(56, key("alice", None));
    let mut far = Dials::default();
    let bounded =
        tokio::time::timeout(DEADLINE, serve(&plane, &mut request, &resolver, &mut far)).await;
    assert!(bounded.is_err(), "the deadline ended the wait");
    assert_eq!(host.asked.lock().unwrap().len(), 1);
    assert_eq!(plane.dropped.load(Ordering::SeqCst), 1, "cancelled once");
    assert_eq!(plane.ended.load(Ordering::SeqCst), 0);
    assert!(asked(&request).is_empty(), "no money is asked");
    assert_eq!(far.0, 0);
    assert!(!request.context.effects_allowed());
}

/// The caller's stop or a reload under a pending LOOKUP cancels the request before admission.
/// Dropped (the caller went away): the plane session is cancelled once, nothing is asked of the
/// money. Retired while the LOOKUP was pending (the unit's allocation released, as a reload or a
/// stop releases it): the record the LOOKUP then answers routes nothing, the walk is not resolved
/// for a unit that is no longer live, and no money is asked.
#[tokio::test]
async fn authenticated_route_caller_stop_reload_and_future_drop_cancel_before_admission() {
    let plane = Interactions::default();
    let host = Records {
        hang: true,
        ..alices_record()
    };
    let resolver = Resolver::new(&host, None).with_principal("alice", &[]);
    let mut request_dropped = request(57, key("alice", None));
    let mut far = Dials::default();
    let mut session = Box::pin(serve(&plane, &mut request_dropped, &resolver, &mut far));
    assert!(
        futures::FutureExt::now_or_never(session.as_mut()).is_none(),
        "the LOOKUP is pending"
    );
    drop(session);
    assert_eq!(host.asked.lock().unwrap().len(), 1);
    assert_eq!(plane.dropped.load(Ordering::SeqCst), 1, "cancelled once");
    assert_eq!(plane.ended.load(Ordering::SeqCst), 0);
    assert!(asked(&request_dropped).is_empty(), "no money is asked");
    assert!(!request_dropped.context.effects_allowed());

    let plane = Interactions::default();
    let mut request_retired = request(58, key("alice", None));
    let context = request_retired.context.clone();
    let host = Records {
        during: Some(Box::new(move || context.retire())),
        ..alices_record()
    };
    let resolver = Resolver::new(&host, None).with_principal("alice", &[]);
    let result = serve(&plane, &mut request_retired, &resolver, &mut far).await;
    assert!(matches!(result, Err(SessionError::NotDriven)), "{result:?}");
    assert_eq!(*plane.looked.lock().unwrap(), [true]);
    assert_eq!(plane.dropped.load(Ordering::SeqCst), 1, "cancelled once");
    assert!(asked(&request_retired).is_empty(), "no money is asked");
    assert!(!request_retired.context.effects_allowed());
    assert_eq!(far.0, 0);
    assert_eq!(plane.upstreams.load(Ordering::SeqCst), 0);
}
