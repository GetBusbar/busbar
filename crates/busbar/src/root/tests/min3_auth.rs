// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::secure::SecureVec;
use busbar_kernel::auth::verdicts::{VerdictPolicy, Verdicts};
use busbar_kernel::plugin_records::RecordsDenied;
use busbar_plugin_abi::host_side::caller::BoxFut;
use busbar_plugin_abi::records::{tag, Records, Reply, U64Rec, Writer};
use busbar_ports::auth::{
    decode_verify_ok, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut, UpstreamIn, Verify,
    VerifyAnswer, VerifyOk,
};
use busbar_ports::PortError;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct Owners(AtomicUsize, AtomicBool);
impl IssuedCredentials for Owners {
    fn lookup<'a>(&'a self, _: u64, _: &'a str, _: &'a str) -> BoxFut<'a, SecureVec> {
        panic!("an identity answer must not perform issued lookup");
    }
}
impl ReplayGuard for Owners {
    fn claim_until<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        let first = self.0.fetch_add(1, Ordering::SeqCst) == 0;
        let unknown = self.1.load(Ordering::SeqCst);
        Box::pin(async move {
            tokio::task::yield_now().await;
            if unknown {
                Err(RecordsDenied::Unavailable)
            } else {
                Ok(first)
            }
        })
    }
    fn claim<'a>(
        &'a self,
        _: &'a Caller<'_>,
        _: &'a [u8],
        _: u64,
    ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(true) })
    }
}

struct Port {
    calls: AtomicUsize,
    not_mine: bool,
    native: bool,
}
fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async {
        Err(PortError::Call(
            busbar_plugin_abi::fail::CallError::NotDeclared,
        ))
    })
}
impl AuthPort for Port {
    fn facts(&self) -> u64 {
        0
    }
    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }
    fn issued_kind(&self) -> Option<&str> {
        None
    }
    fn verify<'a>(&'a self, _: CallCx, req: &AuthIn<'_>, _: Option<&[u8]>) -> Verify<'a> {
        if self.native {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let accepted = req.body == b"admin-body";
            let mut records = Reply::new();
            records.put_text(tag::ID_SUBJECT, "client").unwrap();
            records.put_text(tag::ID_GROUP, "reader").unwrap();
            records
                .put_pod_tail(
                    busbar_plugin_abi::auth::tag::REPLAY,
                    &U64Rec { value: 60 },
                    b"nonce",
                )
                .unwrap();
            let VerifyOk::Identity(identity) =
                decode_verify_ok(Records::new(records.as_bytes())).unwrap()
            else {
                panic!("identity")
            };
            return Verify::Io(Box::pin(async move {
                tokio::task::yield_now().await;
                Ok(if accepted {
                    VerifyAnswer::Identity(identity)
                } else {
                    VerifyAnswer::Refused {
                        code: busbar_plugin_abi::auth::BAD_CREDENTIAL,
                        text: "body".into(),
                    }
                })
            }));
        }
        assert_eq!(req.path, "/resource");
        assert_eq!(req.body, b"body");
        assert_eq!(req.peer, "peer");
        assert_eq!(req.tls_peer_cert, b"certificate");
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.not_mine {
            return Verify::Done(Ok(VerifyAnswer::NotMine));
        }
        let mut records = Reply::new();
        records.put_text(tag::ID_SUBJECT, "client").unwrap();
        records
            .put_pod_tail(
                busbar_plugin_abi::auth::tag::REPLAY,
                &U64Rec { value: 60 },
                b"nonce",
            )
            .unwrap();
        let VerifyOk::Identity(identity) =
            decode_verify_ok(Records::new(records.as_bytes())).unwrap()
        else {
            panic!("identity");
        };
        Verify::Done(Ok(VerifyAnswer::Identity(identity)))
    }
    fn login<'a>(
        &'a self,
        _: CallCx,
        _: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        unsupported()
    }
    fn outbound<'a>(
        &'a self,
        _: CallCx,
        _: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        unsupported()
    }
    fn refresh<'a>(&'a self, _: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }
    fn serve<'a>(
        &'a self,
        _: CallCx,
        _: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

fn instance(id: u64, port: Arc<Port>) -> Arc<AuthInstance> {
    Arc::new(AuthInstance {
        opened: OpenedAuth {
            who: Namespace {
                plugin: "verified-image".into(),
                name: format!("provider-{id}").into(),
                instance: id,
                slot: 4,
            },
            port,
            methods: busbar_plugin_abi::auth::M_VERIFY,
            out_of_process: false,
            limits: InstanceLimits::default(),
        },
        keys: Arc::new(KeyRefresh::new(Duration::from_secs(30))),
        holds: Box::default(),
    })
}

#[tokio::test]
async fn retained_native_chain_snapshots_request_and_rejects_before_replay() {
    let first = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: true,
        native: false,
    });
    let second = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: false,
    });
    let owners = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    let chain = NativeChain::operator(
        vec![
            instance(41, Arc::clone(&first)),
            instance(42, Arc::clone(&second)),
        ],
        ChainPolicy::new(7, Vec::new()),
        Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners.clone(),
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    );
    let cx = CallCx {
        deadline: std::time::Instant::now() + Duration::from_secs(30),
        request_id: 1,
        stack: Default::default(),
        mono_ns: 0,
    };
    let future = {
        let body = b"body".to_vec();
        chain.verify(
            cx,
            &AuthIn {
                method: "POST",
                path: "/resource",
                query: "",
                authority: "node",
                headers: &[],
                peer: "peer",
                tls_peer_cert: b"certificate",
                body: &body,
                now_s: 1,
            },
        )
    };
    assert!(matches!(
        future.await,
        ChainEnd::PolicyRejected { instance: 42, .. }
    ));
    assert_eq!(first.calls.load(Ordering::SeqCst), 1);
    assert_eq!(second.calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn prepared_native_chain_retains_original_request_without_spending_replay() {
    let port = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: false,
    });
    let owners = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    let chain = Arc::new(NativeChain::operator(
        vec![instance(42, port.clone())],
        ChainPolicy::new(7, Vec::new()),
        Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners.clone(),
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    ));
    let request = charged_test_request(&AuthIn {
        method: "POST",
        path: "/resource",
        query: "a=b",
        authority: "node",
        headers: &[],
        peer: "peer",
        tls_peer_cert: b"certificate",
        body: b"body",
        now_s: 1,
    });
    let cx = CallCx {
        deadline: std::time::Instant::now() + Duration::from_secs(30),
        request_id: 9,
        stack: Default::default(),
        mono_ns: 0,
    };
    let busbar_kernel::auth::native_admin::PreparedAnswer::Identity(prepared) =
        chain.prepare(cx, request).await.unwrap()
    else {
        panic!("prepared identity")
    };
    assert_eq!(prepared.identity().subject(), "client");
    prepared
        .request()
        .with_auth_input(|req| {
            assert_eq!(req.body, b"body");
            assert_eq!(req.query, "a=b");
        })
        .unwrap();
    assert!(
        prepared.authorize(2).is_err(),
        "preparation has not granted route authority"
    );
    assert!(
        prepared.authorize(61).is_err(),
        "original replay window cannot be extended"
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
}

/// An App over the actual application Store (a MIN-3 image) with the keys chain and the operator
/// as its admin chain: the part of the deleted root inbound fixture these admin cases stood on.
async fn store_app() -> Arc<busbar_kernel::state::App> {
    use crate::root::test_plugins as plugins;
    crate::dist_root_install::install();
    let library_path = plugins::application_store_library();
    let manifest = plugins::native_manifest("store", &library_path, plugins::FIXTURE_PUBLISHER);
    let module = manifest.name.clone();
    let library = std::fs::read(&library_path).expect("the actual store library reads");
    let directory = plugins::scratch(&format!(
        "min3-auth-app-{}",
        busbar_kernel::door::op_id().counter()
    ));
    let archive = plugins::signed(&crate::dist_root_install::release_key(), manifest, &library);
    std::fs::write(directory.join("store.tar.gz"), archive)
        .expect("stage the actual store archive");
    let signing = directory.join("signing-key");
    std::fs::write(&signing, hex::encode([7u8; 32])).expect("write the configured signing key");
    let operator_token = directory.join("operator-token");
    std::fs::write(&operator_token, "actual-min3-auth-operator")
        .expect("write the operator credential");
    let operator = plugins::bind_operator();
    let mut document = serde_json::json!({
        "public_url": "https://gw.example",
        "providers": {},
        "models": {},
        "auth": { "chain": ["keys"], "admin_auth": [operator], "signing_key": {"file": signing} },
        "identity-providers": {},
        "store": { "module": module, "settings": plugins::application_store_settings(&directory) },
        "advanced": {},
    });
    document["identity-providers"][operator] = serde_json::json!({
        "module": operator, "settings": { "sha256": plugins::operator_sha256_of(&operator_token) },
    });
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        document,
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, _rotate, limits) = crate::root::real_store::build_app(
        config,
        plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual product builds the deployment");
    limits.stage_boot();
    Arc::new(app)
}

async fn admin_fixture() -> (
    Arc<busbar_kernel::state::AppHandle>,
    Arc<busbar_kernel::state::App>,
    Arc<Owners>,
    Arc<Port>,
) {
    let original = store_app().await;
    let mut app = (*original).clone();
    app.admin_chain = vec!["provider-42".into()];
    app.auth_scope_caps
        .insert("provider-42".into(), "full".into());
    app.role_bindings = busbar_kernel::config::RoleBindings::from([(
        "provider-42".into(),
        BTreeMap::from([(
            "reader".into(),
            busbar_kernel::config::RoleBindingCfg {
                allowed_pools: None,
                group: None,
                admin_scope: Some("full".into()),
                verbs: None,
                plane_grants: Default::default(),
            },
        )]),
    )]);
    let owners = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    let port = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: true,
    });
    let set = Arc::new(AuthSet {
        instances: BTreeMap::from([("provider-42".into(), instance(42, port.clone()))]),
        opened: vec!["provider-42".into()],
        owners: Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners.clone(),
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    });
    let epoch = app.config_generation.load(Ordering::Acquire);
    crate::root::min3_admin_auth::install(&mut app, set, epoch).unwrap();
    let app = Arc::new(app);
    (
        Arc::new(busbar_kernel::state::AppHandle::new(app.clone())),
        app,
        owners,
        port,
    )
}

pub(crate) async fn physical_app() -> Arc<busbar_kernel::state::App> {
    admin_fixture().await.1
}

fn admin_invocation(
    handle: &Arc<busbar_kernel::state::AppHandle>,
    app: &Arc<busbar_kernel::state::App>,
    at: u64,
) -> busbar_kernel::auth::native_admin::Invocation {
    use busbar_kernel::auth::{admin_call_context, native_admin::Invocation};
    let id = busbar_kernel::state::InvocationId::from_request_id(
        std::num::NonZeroU64::new(app.next_request_id()).unwrap(),
    );
    Invocation {
        handle: handle.clone(),
        selected: app.clone(),
        id,
        cx: admin_call_context(id),
        request: charged_test_request(&busbar_ports::auth::AuthIn {
            method: "GET",
            path: "/api/v1/admin/audit",
            query: "",
            authority: "",
            headers: &[],
            peer: "",
            tls_peer_cert: &[],
            body: b"admin-body",
            now_s: at,
        }),
    }
}

#[tokio::test]
async fn native_admin_probe_is_non_authoritative_and_final_claim_is_one_shot() {
    use busbar_kernel::auth::{admin_verdict, admin_verdict_for, AdminDoor};
    let (handle, app, owners, port) = admin_fixture().await;
    let headers = axum::http::HeaderMap::new();
    assert!(matches!(
        admin_verdict(&app, "GET", "/api/v1/admin/audit", &headers).door,
        AdminDoor::Unavailable(_)
    ));
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
    let invocation = admin_invocation(&handle, &app, busbar_kernel::store::now());
    let original_context = invocation.cx;
    let verdict = admin_verdict_for(invocation, &headers).await;
    assert!(busbar_kernel::auth::admin_door_admits(
        &verdict.door,
        "GET",
        "/api/v1/admin/audit"
    ));
    let pending = verdict.claim.unwrap();
    assert!(
        !pending.win().await,
        "bool-only callers cannot discard native lease custody"
    );
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
    let execution = pending.complete_admin().await.unwrap();
    let (origin, context) = execution.native_origin().unwrap();
    assert!(Arc::ptr_eq(origin, &handle));
    assert_eq!(context.request_id, original_context.request_id);
    assert_eq!(context.deadline, original_context.deadline);
    assert!(Arc::ptr_eq(
        execution.native().unwrap().0.generation(),
        &app
    ));
    assert!(pending.complete_admin().await.is_err());
    assert_eq!(owners.0.load(Ordering::SeqCst), 1);
    assert_eq!(
        port.calls.load(Ordering::SeqCst),
        1,
        "header-only probe and completion did not verify"
    );
}

#[tokio::test]
async fn native_admin_publication_before_lease_and_expired_window_claim_nothing() {
    use busbar_kernel::auth::admin_verdict_for;
    let (handle, app, owners, _) = admin_fixture().await;
    let headers = axum::http::HeaderMap::new();
    let expired = admin_verdict_for(
        admin_invocation(
            &handle,
            &app,
            busbar_kernel::store::now().saturating_sub(61),
        ),
        &headers,
    )
    .await
    .claim
    .unwrap();
    assert!(expired.complete_admin().await.is_err());
    let pending = admin_verdict_for(
        admin_invocation(&handle, &app, busbar_kernel::store::now()),
        &headers,
    )
    .await
    .claim
    .unwrap();
    handle.swap(Arc::new((*app).clone())).await;
    assert!(pending.complete_admin().await.is_err());
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn native_admin_lease_survives_publication_during_replay_and_pins_actual_effect() {
    use busbar_kernel::auth::{
        admin_verdict_for,
        effect::{Context, PinnedEffect},
    };
    let (handle, app, owners, port) = admin_fixture().await;
    let headers = axum::http::HeaderMap::new();
    let verdict = admin_verdict_for(
        admin_invocation(&handle, &app, busbar_kernel::store::now()),
        &headers,
    )
    .await;
    let mut context = Context::new("GET", "/api/v1/admin/audit", headers, &verdict.door);
    let pending = verdict.claim.unwrap();
    let mut completion = std::pin::pin!(pending.complete_admin());
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(completion.as_mut(), &mut cx).is_pending());
    assert_eq!(owners.0.load(Ordering::SeqCst), 1);
    handle.swap(Arc::new((*app).clone())).await;
    let execution = Arc::new(completion.await.unwrap());
    context.attach_execution(execution).unwrap();
    let effect = PinnedEffect::admit(&handle, Some(context)).await.unwrap();
    assert!(Arc::ptr_eq(effect.app(), &app));
    let _completion = effect.start(&handle).await.unwrap();
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn cancellation_before_verify_and_after_claim_cannot_create_execution() {
    use busbar_kernel::auth::admin_verdict_for;
    let (handle, app, owners, _) = admin_fixture().await;
    let headers = axum::http::HeaderMap::new();
    let invocation = admin_invocation(&handle, &app, busbar_kernel::store::now());
    let held = Arc::downgrade(&invocation.request);
    {
        let mut verify = std::pin::pin!(admin_verdict_for(invocation, &headers));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(verify.as_mut(), &mut cx).is_pending());
    }
    assert!(
        held.upgrade().is_none(),
        "cancelled preparation releases original request custody"
    );
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
    let pending = admin_verdict_for(
        admin_invocation(&handle, &app, busbar_kernel::store::now()),
        &headers,
    )
    .await
    .claim
    .unwrap();
    {
        let mut complete = std::pin::pin!(pending.complete_admin());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(std::future::Future::poll(complete.as_mut(), &mut cx).is_pending());
    }
    assert!(pending.complete_admin().await.is_err());
    assert_eq!(
        owners.0.load(Ordering::SeqCst),
        1,
        "cancellation cannot start a second claim"
    );
}

#[tokio::test]
async fn independent_native_admin_requests_compete_at_final_replay() {
    use busbar_kernel::auth::admin_verdict_for;
    let (handle, app, owners, _) = admin_fixture().await;
    let headers = axum::http::HeaderMap::new();
    let a = admin_verdict_for(
        admin_invocation(&handle, &app, busbar_kernel::store::now()),
        &headers,
    )
    .await
    .claim
    .unwrap();
    let b = admin_verdict_for(
        admin_invocation(&handle, &app, busbar_kernel::store::now()),
        &headers,
    )
    .await
    .claim
    .unwrap();
    let (a, b) = tokio::join!(a.complete_admin(), b.complete_admin());
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(owners.0.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn expired_invocation_deadline_refuses_before_replay_submission() {
    let (handle, app, owners, _) = admin_fixture().await;
    let mut invocation = admin_invocation(&handle, &app, busbar_kernel::store::now());
    invocation.cx.deadline = std::time::Instant::now();
    let verdict =
        busbar_kernel::auth::admin_verdict_for(invocation, &axum::http::HeaderMap::new()).await;
    assert!(verdict.claim.unwrap().complete_admin().await.is_err());
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn root_router_errand_reuses_completed_native_admission_without_second_verification() {
    use crate::root::units_admin::{AdminDispatch, AdminRequest, RouterDispatch};
    let mut f = admin_physical_fixture().await;
    let (handle, owners, port) = (&f.handle, &f.owners, &f.port);
    let headers = axum::http::HeaderMap::new();
    let invocation = physical_admin_invocation(&f);
    let verdict = busbar_kernel::auth::admin_verdict_for(invocation, &headers).await;
    let execution = Arc::new(verdict.claim.unwrap().complete_admin().await.unwrap());
    let physical = Arc::new(
        f.pending
            .take()
            .unwrap()
            .complete_admin(execution.clone())
            .unwrap(),
    );
    let inner = busbar_kernel::router::build_admin_router_on(handle, 1024, false);
    let dispatch = RouterDispatch::new(
        inner,
        &tokio::runtime::Handle::current(),
        Arc::new(busbar_core_admin::keys::KeyReplayCache::new()),
    );
    let snapshot = f.binding.snapshot().unwrap();
    let mut request = AdminRequest::from_binding(
        f.binding.clone(),
        Some(
            busbar_kernel::inbound::http_projection::HttpProjection::from_snapshot(snapshot)
                .unwrap(),
        ),
    )
    .unwrap();
    request.attach_physical(physical).unwrap();
    let resolved =
        busbar_core_admin::admin_codec::verbs::resolve(request.method(), request.path()).unwrap();
    let verb = crate::root::units_admin::kernel_verb(&resolved).unwrap();
    let answer = dispatch
        .execute_authorized(verb, &request, None, Some(&execution))
        .await;
    assert_eq!(answer.status, 200);
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.0.load(Ordering::SeqCst), 1);
    let mut foreign = request.clone();
    foreign.edit_for_test(|_| {});
    assert!(foreign
        .snapshot()
        .request()
        .same_request(request.snapshot().request()));
    assert_eq!(foreign.body(), request.body());
    assert_eq!(
        dispatch
            .execute_authorized(verb, &foreign, None, Some(&execution))
            .await
            .status,
        401
    );
    let mut changed = request.clone();
    changed.edit_for_test(|draft| draft.body = b"different body".to_vec());
    assert_eq!(
        dispatch
            .execute_authorized(verb, &changed, None, Some(&execution))
            .await
            .status,
        401
    );
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_admin_http_requires_original_snapshot_and_same_lease_before_verifying() {
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    use tower::ServiceExt;
    for (snapshot_present, foreign_lease, target, body, expected) in [
        (
            false,
            false,
            "/api/v1/admin/audit",
            b"admin-body".as_slice(),
            503,
        ),
        (
            true,
            true,
            "/api/v1/admin/audit",
            b"admin-body".as_slice(),
            401,
        ),
        (
            true,
            false,
            "/api/v1/admin/audit?",
            b"admin-body".as_slice(),
            401,
        ),
        (
            true,
            false,
            "/api/v1/admin/audit",
            b"changed-body".as_slice(),
            401,
        ),
    ] {
        let mut f = admin_physical_fixture().await;
        let router = busbar_kernel::router::build_admin_router_on(&f.handle, 1024, false);
        let snapshot = f.binding.snapshot().unwrap();
        let carrier = f.pending.take().unwrap().into_admin().unwrap();
        let mut request = axum::http::Request::builder()
            .method("GET")
            .uri(target)
            .body(axum::body::Body::from(body))
            .unwrap();
        request.extensions_mut().insert(carrier);
        if snapshot_present {
            request.extensions_mut().insert(snapshot.clone());
        }
        let lease = if foreign_lease {
            ProcessAdmission::new(2)
                .try_enter(AdmissionClass::Operator)
                .unwrap()
        } else {
            snapshot.request().clone()
        };
        request.extensions_mut().insert(lease);
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            expected
        );
        assert_eq!(f.port.calls.load(Ordering::SeqCst), 0);
        assert_eq!(f.owners.0.load(Ordering::SeqCst), 0);
    }
    let mut f = admin_physical_fixture().await;
    let router = busbar_kernel::router::build_admin_router_on(&f.handle, 1024, false);
    let snapshot = f.binding.snapshot().unwrap();
    let carrier = f.pending.take().unwrap().into_admin().unwrap();
    let request = axum::http::Request::builder()
        .method("GET")
        .uri(snapshot.target())
        .extension(carrier)
        .extension(snapshot.request().clone())
        .extension(snapshot.clone())
        .body(axum::body::Body::from(snapshot.body_bytes()))
        .unwrap();
    assert_eq!(router.oneshot(request).await.unwrap().status(), 200);
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn native_identity_without_grants_stays_identified_and_cannot_claim() {
    let (_, prior, owners, port) = admin_fixture().await;
    let mut app = (*prior).clone();
    app.role_bindings.clear();
    let set = Arc::new(AuthSet {
        instances: BTreeMap::from([("provider-42".into(), instance(42, port))]),
        opened: vec!["provider-42".into()],
        owners: Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners.clone(),
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    });
    let epoch = app.config_generation.load(Ordering::Acquire);
    crate::root::min3_admin_auth::install(&mut app, set, epoch).unwrap();
    let app = Arc::new(app);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app.clone()));
    let verdict = busbar_kernel::auth::admin_verdict_for(
        admin_invocation(&handle, &app, busbar_kernel::store::now()),
        &axum::http::HeaderMap::new(),
    )
    .await;
    assert!(matches!(
        verdict.door,
        busbar_kernel::auth::AdminDoor::Identified(_, _)
    ));
    assert!(!busbar_kernel::auth::admin_door_admits(
        &verdict.door,
        "GET",
        "/api/v1/admin/audit"
    ));
    assert!(verdict.claim.unwrap().complete_admin().await.is_err());
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_native_admin_coverage_refuses_candidate_construction() {
    let (_, prior, owners, _) = admin_fixture().await;
    let mut app = (*prior).clone();
    let empty = Arc::new(AuthSet {
        instances: BTreeMap::new(),
        opened: Vec::new(),
        owners: Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners,
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    });
    let epoch = app.config_generation.load(Ordering::Acquire);
    assert!(crate::root::min3_admin_auth::install(&mut app, empty, epoch).is_err());
}

/// E5: the admin chain never judges a request while a configured credential's instance is
/// unopened. The operator credential's position may be left unset ("not mine") only when its
/// definition carries nothing to judge; one that carries settings must have its native instance
/// opened, or the candidate is refused before any listener can serve it.
#[tokio::test]
async fn an_operator_credential_with_settings_and_no_opened_instance_refuses_the_admin_chain() {
    let (_, prior, owners, _) = admin_fixture().await;
    let operator = |settings: &str| {
        let mut app = (*prior).clone();
        app.admin_chain = vec!["admin-tokens".into()];
        app.identity_providers.insert(
            "admin-tokens".into(),
            busbar_contract::json::parse_str(&format!(
                r#"{{"module":"admin-tokens","settings":{settings}}}"#
            ))
            .unwrap(),
        );
        // The door-era operator credential the kernel built: answered, nothing opened on its axis.
        app.admin_modules = Arc::new(busbar_kernel::auth::AdminAuthChain {
            modules: Default::default(),
            operator: busbar_kernel::auth::Operator::open(
                "admin-tokens",
                std::iter::empty(),
                &|module: &str| module == "admin-tokens",
                true,
                Default::default(),
            ),
        });
        assert!(app.admin_modules.operator.unset("admin-tokens"));
        app
    };
    let empty = || {
        Arc::new(AuthSet {
            instances: BTreeMap::new(),
            opened: Vec::new(),
            owners: Arc::new(AuthOwners {
                issued: owners.clone(),
                replay: owners.clone(),
                cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
            }),
        })
    };

    let digest = busbar_contract::redacted::sha256_hex(b"e5-operator-token");
    let mut configured = operator(&format!(r#"{{"sha256":"{digest}"}}"#));
    let epoch = configured.config_generation.load(Ordering::Acquire);
    let refused = crate::root::min3_admin_auth::install(&mut configured, empty(), epoch)
        .expect_err("a configured operator credential with no opened instance is refused");
    assert_eq!(
        refused,
        "auth.admin_auth: 'admin-tokens' has no opened native auth instance"
    );
    assert!(
        !refused.contains(&digest),
        "the refusal never echoes the credential"
    );

    let mut bare = operator("{}");
    let epoch = bare.config_generation.load(Ordering::Acquire);
    crate::root::min3_admin_auth::install(&mut bare, empty(), epoch)
        .expect("a bare operator position has nothing to judge and stays unset");
    assert!(bare.native_admin.is_some());
}

/// A default configuration boots: the default `auth.admin_auth` is `[<operator>, keys]` with no
/// `identity-providers` definition, so the operator position has no credential and nothing to
/// open. It is left unset whatever the door-era operator says (here: no row answered it), and
/// the admin plane fails closed: a request presenting a token is denied, as 1.5.5 denied every
/// admin request when no admin token was configured.
#[tokio::test]
async fn the_default_admin_chain_with_no_operator_credential_installs_and_denies_every_request() {
    let (_, prior, owners, _) = admin_fixture().await;
    let mut app = (*prior).clone();
    app.admin_chain = vec![
        "admin-tokens".into(),
        busbar_kernel::config::KEYS_MODULE.into(),
    ];
    app.identity_providers.clear();
    app.admin_modules = Arc::new(busbar_kernel::auth::AdminAuthChain {
        modules: Default::default(),
        operator: busbar_kernel::auth::Operator::open(
            "admin-tokens",
            std::iter::empty(),
            &|module: &str| module == "admin-tokens",
            false,
            Default::default(),
        ),
    });
    assert!(!app.admin_modules.operator.unset("admin-tokens"));
    let empty = Arc::new(AuthSet {
        instances: BTreeMap::new(),
        opened: Vec::new(),
        owners: Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners,
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    });
    let epoch = app.config_generation.load(Ordering::Acquire);
    crate::root::min3_admin_auth::install(&mut app, empty, epoch)
        .expect("the default admin chain installs with no operator credential configured");
    let app = Arc::new(app);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app.clone()));
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_static("Bearer any-token-at-all"),
    );
    let verdict = busbar_kernel::auth::admin_verdict_for(
        admin_invocation(&handle, &app, busbar_kernel::store::now()),
        &headers,
    )
    .await;
    assert!(
        matches!(verdict.door, busbar_kernel::auth::AdminDoor::Denied),
        "no admin credential configured: every admin request is denied"
    );
}

#[tokio::test]
async fn shared_kernel_chain_preserves_admin_preparation_and_single_claim() {
    use busbar_kernel::auth::native_chain::NativeChain as KernelChain;
    let port = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: false,
    });
    let owners = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    let chain = Arc::new(KernelChain::operator(
        vec![instance(42, port.clone())],
        ChainPolicy::new(7, Vec::new()),
        Arc::new(AuthOwners {
            issued: owners.clone(),
            replay: owners.clone(),
            cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
        }),
    ));
    let request = charged_test_request(&AuthIn {
        method: "POST",
        path: "/resource",
        query: "a=b",
        authority: "node",
        headers: &[],
        peer: "peer",
        tls_peer_cert: b"certificate",
        body: b"body",
        now_s: 1,
    });
    let cx = CallCx {
        deadline: std::time::Instant::now() + Duration::from_secs(30),
        request_id: 11,
        stack: Default::default(),
        mono_ns: 0,
    };
    let PreparedAnswer::Identity(prepared) = chain.prepare(cx, request).await.unwrap() else {
        panic!("prepared identity")
    };
    assert_eq!(prepared.provider(), "provider-42");
    assert_eq!(prepared.identity().subject(), "client");
    assert_eq!(port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(owners.0.load(Ordering::SeqCst), 0);
    assert!(prepared.claim().await);
    assert_eq!(owners.0.load(Ordering::SeqCst), 1);
}

fn charged_test_request(
    view: &busbar_ports::auth::AuthIn<'_>,
) -> Arc<busbar_kernel::inbound::request_snapshot::ChargedRequestSnapshot> {
    use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let process = ProcessAdmission::new(2);
    let request = process.try_enter(AdmissionClass::Operator).unwrap();
    ChargedRequestSnapshot::capture(
        SnapshotInput {
            method: view.method,
            path: view.path,
            query: view.query,
            query_present: !view.query.is_empty(),
            authority: view.authority,
            headers: view.headers.iter().map(|p| (p.name.get(), p.value.get())),
            peer: view.peer,
            tls_peer_cert: view.tls_peer_cert,
            body: view.body,
            now_s: view.now_s,
        },
        &request,
    )
    .unwrap()
}

#[test]
fn native_data_chain_rejects_empty_and_repeated_real_reservations() {
    let port = Arc::new(Port {
        calls: AtomicUsize::new(0),
        not_mine: false,
        native: false,
    });
    let owners = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    let owners = Arc::new(AuthOwners {
        issued: owners.clone(),
        replay: owners,
        cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
    });
    assert!(NativeChain::data(7, Vec::new(), owners.clone()).is_err());
    let opened = instance(42, port);
    assert!(NativeChain::data(7, vec![opened.clone(), opened.clone()], owners.clone()).is_err());
    let data = NativeChain::data(7, vec![opened], owners).unwrap();
    assert!(data.is_data());
    assert_eq!(data.epoch(), 7);
    assert!(data.matches_names(&["provider-42".into()]));
    assert!(!data.matches_names(&["another-provider".into()]));
}

// Real Admin verification/replay joins the actual physical state machine. The reused transport
// port is an inert table fixture: this does not claim decoder or socket-path qualification.
struct AdminPhysicalFixture {
    budget: Arc<busbar_kernel::limits::process_admission::ProcessAdmission>,
    handle: Arc<busbar_kernel::state::AppHandle>,
    app: Arc<busbar_kernel::state::App>,
    owners: Arc<Owners>,
    port: Arc<Port>,
    connection: busbar_kernel::inbound::native::PhysicalConnection,
    stream: busbar_kernel::inbound::native::StreamOwner,
    pending: Option<busbar_kernel::inbound::native::CompletingPhysicalRequest>,
    binding: Arc<busbar_kernel::inbound::native::RequestBinding>,
}

async fn admin_physical_fixture() -> AdminPhysicalFixture {
    admin_physical_fixture_with_native(true).await
}

async fn admin_physical_fixture_with_native(native: bool) -> AdminPhysicalFixture {
    admin_physical_fixture_at(native, "/api/v1/admin/audit").await
}

async fn admin_physical_fixture_at(native: bool, path: &str) -> AdminPhysicalFixture {
    admin_physical_fixture_with_headers(native, path, Vec::new()).await
}

async fn admin_physical_fixture_with_headers(
    native: bool,
    path: &str,
    fields: Vec<(String, Vec<u8>)>,
) -> AdminPhysicalFixture {
    admin_physical_fixture_with_body(native, path, fields, b"admin-body").await
}

async fn admin_physical_fixture_with_body(
    native: bool,
    path: &str,
    fields: Vec<(String, Vec<u8>)>,
    input_body: &[u8],
) -> AdminPhysicalFixture {
    use busbar_contract::route::RouteAuth;
    use busbar_contract::route::{METHOD_GET, PATH_EXACT};
    use busbar_kernel::guest::{Claimant, GuestList, Line, LineAuth, Route};
    use busbar_kernel::inbound::native::{
        AcceptedConnection, PhysicalListener, PhysicalPlan, RouteBinding,
    };
    use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};
    let (handle, app, owners, port) = admin_fixture().await;
    let (handle, app) = if native {
        (handle, app)
    } else {
        let mut legacy = (*app).clone();
        legacy.native_admin = None;
        legacy.admin_chain.clear();
        let app = Arc::new(legacy);
        (
            Arc::new(busbar_kernel::state::AppHandle::new(app.clone())),
            app,
        )
    };
    let transport = crate::root::min3_boot::transports::tests::framer(&["http"]);
    let line = Line {
        route: Route {
            methods: METHOD_GET,
            path_form: PATH_EXACT,
            path: path.into(),
            fields: Vec::new(),
            rung: 0,
        },
        claimant: Claimant::Clean("core".into()),
        dialect: 0,
        auth: LineAuth::None,
        upgrade: None,
        offered: busbar_contract::route::AuthPoints::EMPTY,
    };
    let guests = GuestList::seal(vec![line.clone()]).unwrap();
    let plan = PhysicalPlan::new(
        "operator".into(),
        transport.clone(),
        guests,
        vec![RouteBinding::core(line, RouteAuth::Admin).unwrap()],
    )
    .unwrap();
    let prepared = Arc::new(
        busbar_kernel::router::PreparedListener::new(
            &app,
            &busbar_kernel::plugin_routes::PluginRouteTable::empty(),
            Vec::new(),
            Vec::new(),
            None,
            false,
        )
        .unwrap()
        .with_physical(plan)
        .unwrap(),
    );
    let listener = PhysicalListener::new(
        handle.clone(),
        "operator".into(),
        transport,
        AdmissionClass::Operator,
        Arc::new(move |_, slot| (slot == "operator").then(|| prepared.clone())),
    )
    .unwrap();
    let budget = ProcessAdmission::new(4);
    let connection = listener.connect(
        AcceptedConnection::capture(
            &budget.connection_storage(AdmissionClass::Operator),
            "192.0.2.1",
            "192.0.2.2",
            "http/1.1",
            &[],
        )
        .unwrap(),
    );
    let lease = budget.try_enter(AdmissionClass::Operator).unwrap();
    let credit = lease.try_reserve(input_body.len()).unwrap();
    let mut body = SecureVec::with_capacity(credit.len()).unwrap();
    body.extend(input_body).unwrap();
    let (request, stream) = connection
        .head(
            1,
            busbar_kernel::inbound::Head {
                method: "GET".into(),
                target: path.into(),
                fields,
                authority: String::new(),
                query: None,
            },
            lease,
            None,
        )
        .unwrap();
    let request = request.finish_input(body, credit).unwrap();
    let binding = request.binding().clone();
    let pending = Some(request.begin_completion().unwrap());
    AdminPhysicalFixture {
        budget,
        handle,
        app,
        owners,
        port,
        connection,
        stream,
        pending,
        binding,
    }
}

fn physical_admin_invocation(
    f: &AdminPhysicalFixture,
) -> busbar_kernel::auth::native_admin::Invocation {
    let id = f.binding.invocation();
    busbar_kernel::auth::native_admin::Invocation {
        handle: f.handle.clone(),
        selected: f.app.clone(),
        id,
        cx: busbar_kernel::auth::admin_call_context(id),
        request: f.binding.snapshot().unwrap(),
    }
}

async fn complete_physical_admin_auth(
    invocation: busbar_kernel::auth::native_admin::Invocation,
) -> Arc<busbar_kernel::auth::native_admin::ExecutionAdmission> {
    let verdict =
        busbar_kernel::auth::admin_verdict_for(invocation, &axum::http::HeaderMap::new()).await;
    Arc::new(verdict.claim.unwrap().complete_admin().await.unwrap())
}

#[tokio::test]
async fn physical_admin_join_rejects_foreign_origin_id_and_equal_content_snapshot() {
    use busbar_kernel::inbound::request_snapshot::{ChargedRequestSnapshot, SnapshotInput};
    for changed in ["handle", "id", "snapshot"] {
        let mut f = admin_physical_fixture().await;
        let mut invocation = physical_admin_invocation(&f);
        match changed {
            "handle" => {
                invocation.handle = Arc::new(busbar_kernel::state::AppHandle::new(f.app.clone()))
            }
            "id" => {
                invocation.id = busbar_kernel::state::InvocationId::from_request_id(
                    std::num::NonZeroU64::new(f.app.next_request_id()).unwrap(),
                );
                invocation.cx.request_id = invocation.id.request_id().get();
            }
            "snapshot" => {
                let s = &invocation.request;
                invocation.request = ChargedRequestSnapshot::capture(
                    SnapshotInput {
                        method: s.method(),
                        path: s.path(),
                        query: s.query(),
                        query_present: s.query_present(),
                        authority: s.authority(),
                        headers: s.headers(),
                        peer: s.peer(),
                        tls_peer_cert: s.tls_peer_cert(),
                        body: s.body(),
                        now_s: s.now_s(),
                    },
                    s.request(),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let proof = complete_physical_admin_auth(invocation).await;
        assert!(
            f.pending.take().unwrap().complete_admin(proof).is_err(),
            "{changed}"
        );
        assert!(f.binding.check_executing().is_err());
        assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.owners.0.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn physical_admin_join_consumes_carrier_once_and_retains_live_execution() {
    let mut f = admin_physical_fixture().await;
    let carrier = f.pending.take().unwrap().into_admin().unwrap();
    let clone = carrier.clone();
    let pending = carrier.take().unwrap();
    assert!(clone.take().is_err());
    let proof = complete_physical_admin_auth(physical_admin_invocation(&f)).await;
    let execution = pending.complete_admin(proof.clone()).unwrap();
    assert!(Arc::ptr_eq(execution.admission(), &proof));
    assert!(Arc::ptr_eq(execution.binding(), &f.binding));
    assert!(execution.check_executing().is_ok());
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 1);
    drop(execution);
    assert!(f.binding.check_executing().is_err());
    assert!(clone.take().is_err());
}

#[tokio::test]
async fn physical_admin_join_refuses_reset_or_expired_completed_proof() {
    for reset in [true, false] {
        let mut f = admin_physical_fixture().await;
        let mut invocation = physical_admin_invocation(&f);
        if !reset {
            invocation.cx.deadline = std::time::Instant::now() + Duration::from_secs(5);
        }
        let deadline = invocation.cx.deadline;
        let proof = complete_physical_admin_auth(invocation).await;
        if reset {
            assert!(f.connection.cancel(&f.stream));
        } else {
            tokio::time::sleep_until(deadline.into()).await;
        }
        assert!(f.pending.take().unwrap().complete_admin(proof).is_err());
        assert!(f.binding.check_executing().is_err());
        assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
        assert_eq!(f.owners.0.load(Ordering::SeqCst), 1);
    }
}

async fn physical_admin_router(f: &AdminPhysicalFixture) -> axum::Router {
    physical_admin_router_observing(f, None).await
}

async fn physical_admin_router_observing(
    f: &AdminPhysicalFixture,
    header_pointer: Option<Arc<AtomicUsize>>,
) -> axum::Router {
    physical_admin_router_on_book(f, header_pointer, None).await
}

async fn physical_admin_router_on_book(
    f: &AdminPhysicalFixture,
    header_pointer: Option<Arc<AtomicUsize>>,
    book: Option<&crate::root::durability::NodeBook>,
) -> axum::Router {
    use crate::root::units_admin::{AdminBinding, RefusingDispatch};
    let door = crate::root::units_admin::bound::live_admin_door(f.handle.clone());
    let mut units = match book {
        Some(book) => crate::root::kernel::ProductionUnits::admin_over_book(
            Arc::new(RefusingDispatch),
            door.clone(),
            book,
        ),
        None => {
            crate::root::kernel::ProductionUnits::admin_only(
                Arc::new(RefusingDispatch),
                door.clone(),
            )
            .await
        }
    };
    let mut inner = busbar_kernel::router::build_admin_router_on(&f.handle, 1024, false);
    if let Some(observed) = header_pointer {
        inner = inner.layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let observed = observed.clone();
                async move {
                    observed.store(
                        request.headers()["x-native-custody"].as_bytes().as_ptr() as usize,
                        Ordering::SeqCst,
                    );
                    next.run(request).await
                }
            },
        ));
    }
    crate::root::units_admin::mount(
        inner,
        crate::root::kernel::new_kernel(),
        1024,
        move |dispatch| {
            units.admin = AdminBinding::new(dispatch, door);
            units
        },
    )
}

fn physical_admin_http(
    f: &mut AdminPhysicalFixture,
) -> (
    axum::http::Request<axum::body::Body>,
    busbar_kernel::inbound::native::AdminPhysicalRequest,
) {
    let carrier = f.pending.take().unwrap().into_admin().unwrap();
    let snapshot = f.binding.snapshot().unwrap();
    let mut request =
        busbar_kernel::inbound::http_projection::HttpProjection::from_snapshot(snapshot.clone())
            .unwrap()
            .into_request(axum::body::Body::from(snapshot.body_bytes()));
    request.extensions_mut().insert(carrier.clone());
    (request, carrier)
}

#[tokio::test]
async fn physical_admin_denied_walk_returns_one_sealed_refusal_owner() {
    use busbar_kernel::inbound::native::{PhysicalAdminExecution, PhysicalRefusalCarrier};
    use futures::FutureExt;
    use tower::ServiceExt;
    let mut f = admin_physical_fixture_with_body(
        true,
        "/api/v1/admin/info",
        Vec::new(),
        b"wrong credential",
    )
    .await;
    let router = physical_admin_router(&f).await;
    let (request, pending_carrier) = physical_admin_http(&mut f);
    let mut response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 401);
    assert!(pending_carrier.take().is_err());
    assert!(response
        .extensions()
        .get::<Arc<PhysicalAdminExecution>>()
        .is_none());
    let carrier = response
        .extensions_mut()
        .remove::<PhysicalRefusalCarrier>()
        .expect("the actual denied walk must finish its original audit before output authority");
    let duplicate = carrier.clone();
    let refusal = carrier.take().expect("one original output right");
    assert!(duplicate.take().is_err());
    assert!(Arc::ptr_eq(refusal.binding(), &f.binding));
    assert!(f.binding.check_live().is_err());
    assert!(f.binding.check_executing().is_err());
    assert!(f.binding.cancelled().now_or_never().is_none());
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        f.owners.0.load(Ordering::SeqCst),
        0,
        "denied credentials never claim replay"
    );
    drop(refusal);
    assert!(f.binding.cancelled().now_or_never().is_some());
}

#[tokio::test]
async fn physical_admin_reset_during_denied_walk_cannot_mint_refusal_output() {
    use busbar_kernel::inbound::native::PhysicalRefusalCarrier;
    use tower::ServiceExt;
    let mut f = admin_physical_fixture_with_body(
        true,
        "/api/v1/admin/info",
        Vec::new(),
        b"wrong credential",
    )
    .await;
    let router = physical_admin_router(&f).await;
    let (request, _) = physical_admin_http(&mut f);
    let mut operation = Box::pin(router.oneshot(request));
    assert!(futures::poll!(operation.as_mut()).is_pending());
    assert!(f.connection.cancel(&f.stream));
    let response = operation.await.unwrap();
    assert!(response
        .extensions()
        .get::<PhysicalRefusalCarrier>()
        .is_none());
    assert!(f.binding.check_executing().is_err());
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn physical_admin_replay_duplicate_and_unknown_have_distinct_output_authority() {
    use busbar_kernel::inbound::native::PhysicalRefusalCarrier;
    use tower::ServiceExt;
    for unknown in [false, true] {
        let mut f = admin_physical_fixture_at(true, "/api/v1/admin/info").await;
        if unknown {
            f.owners.1.store(true, Ordering::SeqCst);
        } else {
            let first = admin_invocation(&f.handle, &f.app, busbar_kernel::store::now());
            let verdict =
                busbar_kernel::auth::admin_verdict_for(first, &axum::http::HeaderMap::new()).await;
            verdict.claim.unwrap().complete_admin().await.unwrap();
        }
        let before = f.owners.0.load(Ordering::SeqCst);
        let router = physical_admin_router(&f).await;
        let (request, _) = physical_admin_http(&mut f);
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(
            f.owners.0.load(Ordering::SeqCst),
            before + 1,
            "one original replay operation"
        );
        assert!(f.binding.check_executing().is_err());
        if unknown {
            assert_eq!(response.status(), 503);
            assert!(
                response
                    .extensions()
                    .get::<PhysicalRefusalCarrier>()
                    .is_none(),
                "unknown is not a duplicate refusal"
            );
        } else {
            assert_eq!(response.status(), 401);
            let refusal = response
                .extensions()
                .get::<PhysicalRefusalCarrier>()
                .unwrap()
                .take()
                .unwrap();
            assert!(Arc::ptr_eq(refusal.binding(), &f.binding));
        }
    }
}

#[tokio::test]
async fn physical_admin_lost_audit_ack_never_grants_refusal_output() {
    use busbar_kernel::inbound::native::PhysicalRefusalCarrier;
    use tower::ServiceExt;
    let journal = crate::root::durability::tests::NativeFixture::new(781).await;
    let book = crate::root::durability::node_book(
        journal.journal.clone(),
        crate::root::durability::tests::BUDGET,
    )
    .await
    .unwrap();
    let mut f = admin_physical_fixture_with_body(
        true,
        "/api/v1/admin/info",
        Vec::new(),
        b"wrong credential",
    )
    .await;
    let router = physical_admin_router_on_book(&f, None, Some(&book)).await;
    journal.faults.clear_observations();
    journal.faults.lose_acks.store(true, Ordering::Release);
    let (request, _) = physical_admin_http(&mut f);
    let response = router.oneshot(request).await.unwrap();
    assert!(response
        .extensions()
        .get::<PhysicalRefusalCarrier>()
        .is_none());
    assert!(f.binding.check_executing().is_err());
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 0);
    assert!(
        journal.journal.pending_records() > 0,
        "the unconfirmed original audit remains pending, not a refusal receipt"
    );
    let sent = journal.faults.requests.lock().unwrap();
    assert!(
        !sent.is_empty(),
        "the actual Store candidate must have been attempted"
    );
}

#[tokio::test]
async fn physical_admin_root_dispatch_moves_original_http_header_backing() {
    use tower::ServiceExt;
    let mut f = admin_physical_fixture_with_headers(
        true,
        "/api/v1/admin/info",
        vec![("x-native-custody".into(), vec![b'x'; 128])],
    )
    .await;
    let observed = Arc::new(AtomicUsize::new(0));
    let router = physical_admin_router_observing(&f, Some(observed.clone())).await;
    let (request, _) = physical_admin_http(&mut f);
    let original = request.headers()["x-native-custody"].as_bytes().as_ptr() as usize;
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        observed.load(Ordering::SeqCst),
        original,
        "root live door and dispatch must borrow/transfer the original HTTP projection"
    );
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn physical_admin_root_router_retains_exact_owner_through_response_body_drop() {
    use busbar_kernel::inbound::native::PhysicalAdminExecution;
    use tower::ServiceExt;
    let mut f = admin_physical_fixture_at(true, "/api/v1/admin/info").await;
    let router = physical_admin_router(&f).await;
    let (request, carrier) = physical_admin_http(&mut f);
    let response = router.oneshot(request).await.unwrap();
    assert_eq!(response.status(), 200);
    assert!(
        carrier.take().is_err(),
        "root consumed original completion right"
    );
    let physical = response
        .extensions()
        .get::<Arc<PhysicalAdminExecution>>()
        .unwrap()
        .clone();
    assert!(Arc::ptr_eq(physical.binding(), &f.binding));
    assert!(physical.check_executing().is_ok());
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 1);
    let weak = Arc::downgrade(&physical);
    let (parts, body) = response.into_parts();
    drop((parts, physical));
    assert!(
        weak.upgrade().is_some(),
        "body owns same physical execution after headers retire"
    );
    assert!(f.binding.check_executing().is_ok());
    drop(body);
    assert!(weak.upgrade().is_none());
    assert!(f.binding.check_executing().is_err());
}

#[tokio::test]
async fn physical_admin_root_consumes_carrier_before_await_and_reset_prevents_execution() {
    use tower::ServiceExt;
    let mut f = admin_physical_fixture_at(true, "/api/v1/admin/info").await;
    let router = physical_admin_router(&f).await;
    let (request, carrier) = physical_admin_http(&mut f);
    let mut response = std::pin::pin!(router.oneshot(request));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(std::future::Future::poll(response.as_mut(), &mut cx).is_pending());
    assert!(
        carrier.take().is_err(),
        "right taken before body/auth/task suspension"
    );
    assert!(f.connection.cancel(&f.stream));
    let answer = response.await.unwrap();
    assert_ne!(answer.status(), 200);
    assert!(answer
        .extensions()
        .get::<Arc<busbar_kernel::inbound::native::PhysicalAdminExecution>>()
        .is_none());
    assert!(f.binding.check_executing().is_err());
}

#[tokio::test]
async fn physical_admin_effect_keeps_owner_and_rechecks_reset_before_mutation() {
    use busbar_kernel::auth::effect::{Context, PinnedEffect};
    let mut f = admin_physical_fixture().await;
    let verdict = busbar_kernel::auth::admin_verdict_for(
        physical_admin_invocation(&f),
        &axum::http::HeaderMap::new(),
    )
    .await;
    let proof = Arc::new(verdict.claim.unwrap().complete_admin().await.unwrap());
    let physical = Arc::new(f.pending.take().unwrap().complete_admin(proof).unwrap());
    let weak = Arc::downgrade(&physical);
    let context = Context::from_physical(physical.clone()).unwrap();
    drop(physical);
    let effect = PinnedEffect::admit(&f.handle, Some(context)).await.unwrap();
    assert!(weak.upgrade().is_some());
    assert!(f.connection.cancel(&f.stream));
    assert!(effect.start(&f.handle).await.is_err());
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 1);
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 1);
    drop(effect);
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn native_effect_clones_share_original_snapshot_until_the_last_owner() {
    use busbar_kernel::auth::effect::Context;
    let mut f = admin_physical_fixture().await;
    let proof = complete_physical_admin_auth(physical_admin_invocation(&f)).await;
    let physical = Arc::new(f.pending.take().unwrap().complete_admin(proof).unwrap());
    let snapshot = f.binding.snapshot().unwrap();
    let weak = Arc::downgrade(&snapshot);
    let context = Context::from_physical(physical).unwrap();
    assert!(Arc::ptr_eq(context.request_snapshot().unwrap(), &snapshot));
    let budget = f.budget.clone();
    let before = budget.used();
    let clones: Vec<_> = (0..32).map(|_| context.clone()).collect();
    assert_eq!(
        budget.used(),
        before,
        "effect clones retain existing metadata credit"
    );
    for clone in &clones {
        assert!(Arc::ptr_eq(clone.request_snapshot().unwrap(), &snapshot));
    }
    drop(snapshot);
    drop(f);
    drop(context);
    assert!(
        weak.upgrade().is_some(),
        "detached effects retain the original snapshot"
    );
    assert!(budget.used().0 > 0);
    drop(clones);
    assert!(weak.upgrade().is_none());
    assert_eq!(budget.used(), (0, 0));
}

#[tokio::test]
async fn physical_admin_root_rejects_legacy_open_verdict_without_native_proof() {
    use tower::ServiceExt;
    let mut f = admin_physical_fixture_at(false, "/api/v1/admin/info").await;
    let router = physical_admin_router(&f).await;
    let (request, carrier) = physical_admin_http(&mut f);
    let response = router.oneshot(request).await.unwrap();
    assert_ne!(response.status(), 200);
    assert!(carrier.take().is_err());
    assert!(f.binding.check_executing().is_err());
    assert_eq!(f.port.calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.owners.0.load(Ordering::SeqCst), 0);
}
