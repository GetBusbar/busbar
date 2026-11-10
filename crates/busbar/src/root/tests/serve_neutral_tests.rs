// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::serve::{neutral, Stated};
use busbar_contract::abi::host::service::UnitRef;
use busbar_kernel::inbound::{HandIn, Head, Inbound, Listener, RequestAdmission, Seals};
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use std::sync::Mutex;

const OWNER: u64 = 7101;
const LISTENER: u64 = 7103;
const FRAMING: u64 = 7109;
const STREAM: u64 = 7111;

#[derive(Default)]
struct Output {
    head: Mutex<Option<(u32, HeadFields)>>,
    body: Mutex<Vec<u8>>,
    trailers: Mutex<Option<HeadFields>>,
}
impl CallerEnd for Output {
    fn head(&self, status: u32, fields: HeadFields) {
        assert!(self
            .head
            .lock()
            .unwrap()
            .replace((status, fields))
            .is_none());
    }
    async fn write(&self, bytes: &[u8]) -> bool {
        self.body.lock().unwrap().extend_from_slice(bytes);
        true
    }
}
impl SessionCaller for Output {
    async fn read(&self) -> Option<Vec<u8>> {
        None
    }
}
impl Stated for Output {
    fn stated(&self) -> Option<u32> {
        self.head.lock().unwrap().as_ref().map(|head| head.0)
    }
}
impl neutral::Output for Output {
    fn trailers(&self, fields: HeadFields) {
        *self.trailers.lock().unwrap() = Some(fields);
    }
}

fn admission(
    app: Arc<App>,
    guests: busbar_kernel::guest::GuestList,
    head: &Head,
) -> (Arc<Inbound>, RequestAdmission) {
    admission_with_scope(app, guests, head, None)
}

fn admission_with_scope(
    app: Arc<App>,
    guests: busbar_kernel::guest::GuestList,
    head: &Head,
    scope: Option<busbar_kernel::inbound::ListenerScope>,
) -> (Arc<Inbound>, RequestAdmission) {
    let next = Arc::new(std::sync::atomic::AtomicU64::new(8000));
    let host = Inbound::new(
        Seals {
            mint: Arc::new(move || next.fetch_add(1, std::sync::atomic::Ordering::SeqCst)),
            mac: Arc::new(|tag| {
                crate::root::loader::dispatch::auth_handle::mint_unit_ref(
                    tag.secret,
                    tag.generation,
                    tag.owner,
                    tag.line,
                    tag.unit,
                )
                .map(|unit| unit.mac)
            }),
        },
        Arc::new(|future| {
            tokio::spawn(future);
        }),
        Arc::new(|_| {}),
    );
    let index = guests
        .lines()
        .iter()
        .position(|line| line.route.rung == 2)
        .unwrap() as u32;
    let ids = (1..=guests.lines().len() as u64).collect();
    host.install_at(
        OWNER,
        LISTENER,
        1,
        Listener {
            guests,
            auths: Default::default(),
            body_limit: 4096,
            app,
            door_refusals: vec![],
            ids,
            signed_ingress: Arc::new(|_, _| false),
            scope,
        },
    )
    .unwrap();
    host.framing_started(OWNER, LISTENER, FRAMING, 1).unwrap();
    host.grant_stream(OWNER, FRAMING, STREAM, 1).unwrap();
    let (flow, _) = host
        .hand_in(HandIn {
            owner: OWNER,
            generation: 1,
            auth: index as u64 + 1,
            unit: UnitRef::NONE,
            line: index,
            conn: FRAMING,
            stream: STREAM,
            framing: Some(FRAMING),
            head: head.clone(),
        })
        .unwrap();
    assert_eq!(flow, busbar_contract::abi::host::service::FLOW_CONTINUE);
    let admission = host.claim_request(OWNER, FRAMING, STREAM, head).unwrap();
    (host, admission)
}

/// Replaces the old plane-through-axum fixture coverage: an actual dropped plane crosses the
/// common teller, money and audit path with a method/target/field head HTTP cannot represent.
#[tokio::test]
async fn a_third_claim_dispatches_opaque_heads_through_the_governed_plane_once() {
    let _one = PUBLISHING.lock().await;
    let g = governed("neutral-data-ingress", false).await;
    let mut served = g.served.clone();
    served.planes[0].snapshot.claims[2].verb = "*".into();
    served.planes[0].snapshot.claims[2].carrier = "quartz".into();
    served.planes[0].snapshot.claims[2].arrival_span = "neutral_arrival".into();
    use tracing_subscriber::layer::SubscriberExt as _;
    let log = SpanLog::default();
    let _subscribed =
        tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
    let mounts = crate::root::serve::door_mounts(served, || None, &[], &[], &[], &[]).unwrap();
    let routes = mounts.data;
    let head = Head {
        method: "READ OBJECT".into(),
        target: "/framed/object with spaces".into(),
        authority: "opaque authority".into(),
        query: Some("selection=[]".into()),
        fields: vec![
            ("field with spaces".into(), b"\0opaque".to_vec()),
            ("Authorization".into(), b"Bearer private-secret".to_vec()),
            ("Cookie".into(), b"private-secret".to_vec()),
            ("X-Api-Key".into(), b"private-secret".to_vec()),
            ("Connection".into(), b"private-secret".to_vec()),
            (
                busbar_contract::abi::host::service::CARRIER_SESSION_FIELD.into(),
                b"private-secret".to_vec(),
            ),
        ],
    };
    let (_host, admission) = admission(Arc::clone(&g.app), routes.guests.clone(), &head);
    let context = busbar_kernel::auth::admitted_context(&admission)
        .await
        .unwrap();
    assert!(Arc::ptr_eq(&context.app, &g.app));
    assert_eq!(context.head, head);
    let output = Arc::new(Output::default());
    let pipe = routes
        .serve_admitted(
            &admission,
            context,
            bytes::Bytes::from_static(b"opaque body"),
            busbar_contract::abi::host::service::SCHEME_SECURE,
            busbar_kernel::plane_routes::FramedSession::default(),
            Arc::clone(&output),
        )
        .await;
    assert!(pipe.is_none());
    let spans = log.0.lock().unwrap();
    assert_eq!(
        spans
            .iter()
            .filter(|span| span.0 == "neutral_arrival")
            .count(),
        1
    );
    assert!(
        spans
            .iter()
            .any(|span| span.0 == "forward" && span.1 == Some("neutral_arrival")),
        "the governed unit stays beneath the declared arrival span: {spans:?}"
    );
    drop(spans);
    assert_eq!(output.stated(), Some(200));
    assert_eq!(*output.body.lock().unwrap(), b"opaque body");
    assert_eq!(g.money.open_units(), 0, "money settled exactly once");
    assert_eq!(g.post.open_units(), 0, "the governed node completed");
    assert_eq!(
        g.book.lock().unwrap().audit_records.len(),
        1,
        "one fixed audit record"
    );
}

#[tokio::test]
async fn a_revoked_admission_cannot_enter_the_neutral_plane_dispatcher() {
    let _one = PUBLISHING.lock().await;
    let g = governed("neutral-data-revoked", false).await;
    let mounts =
        crate::root::serve::door_mounts(g.served.clone(), || None, &[], &[], &[], &[]).unwrap();
    let head = Head {
        method: "POST".into(),
        target: "/framed/ok".into(),
        authority: String::new(),
        query: None,
        fields: Vec::new(),
    };
    let (host, admission) = admission(Arc::clone(&g.app), mounts.data.guests.clone(), &head);
    host.stream_ended(OWNER, FRAMING, STREAM);
    assert!(busbar_kernel::auth::admitted_context(&admission)
        .await
        .is_err());
    assert_eq!(g.money.open_units(), 0);
    assert!(g.book.lock().unwrap().audit_records.is_empty());
}

#[tokio::test]
async fn a_neutral_auth_refusal_runs_the_selected_completion_tap_once_outside_host_locks() {
    neutral_auth_refusal("/framed/ok", 401).await;
}

#[tokio::test]
async fn an_opaque_preadmission_refusal_survives_the_exact_plane_callback_and_completion() {
    neutral_auth_refusal("/framed/opaque-refusal", 70_123).await;
}

async fn neutral_auth_refusal(target: &str, expected_status: u32) {
    use busbar_contract::abi::host::service::REFUSE_STOPPED;
    use busbar_kernel::inbound::{ListenerScope, Refuse};
    use std::time::Duration;

    let _one = PUBLISHING.lock().await;
    let g = governed("neutral-auth-refusal", false).await;
    let mounts =
        crate::root::serve::door_mounts(g.served.clone(), || None, &[], &[], &[], &[]).unwrap();
    let routes = mounts.data;
    let dialect = routes.served.planes[0].dialects[0];
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/completion", listener.local_addr().unwrap());
    let (send, mut received) = tokio::sync::mpsc::unbounded_channel();
    let router = axum::Router::new().route(
        "/completion",
        axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
            let send = send.clone();
            async move {
                send.send(body).unwrap();
                axum::http::StatusCode::NO_CONTENT
            }
        }),
    );
    struct Server(tokio::task::JoinHandle<()>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _server = Server(tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap()
    }));
    let mut hook =
        serde_json::to_value(g.screen_hook.authoring(&busbar_kernel::seal::acquire())).unwrap();
    hook["kind"] = serde_json::json!("tap");
    hook["phase"] = serde_json::json!(["response"]);
    hook["settings"]["url"] = serde_json::json!(endpoint);
    let registry = [(
        "completion".to_owned(),
        serde_json::from_value(hook).unwrap(),
    )]
    .into_iter()
    .collect();
    let mut app = (*g.app).clone();
    app.tap_hooks_response = busbar_kernel::hooks::resolve_tap_hooks(
        &registry,
        &["completion".into()],
        &app.hook_env,
        1,
        busbar_kernel::config::HookStage::Response,
    );
    assert_eq!(app.tap_hooks_response.len(), 1);
    let app = Arc::new(app);
    let weak = Arc::new(Mutex::new(std::sync::Weak::<Inbound>::new()));
    let callback_host = Arc::clone(&weak);
    let callback_routes = Arc::clone(&routes);
    let scope = ListenerScope {
        audit_kind: None,
        neutral_refuse: Some(Arc::new(move |app, refusal| {
            // Acquiring the units mutex inside the producer catches a held host lock.
            let host = callback_host.lock().unwrap().upgrade().unwrap();
            assert!(host.unit_secret(OWNER, 0).is_none());
            callback_routes.refuse_line(app, refusal)
        })),
        admission: Arc::new(|_, _| None),
        legacy_fallback: false,
        refuse: None,
    };
    let head = Head {
        method: "POST".into(),
        target: target.into(),
        authority: String::new(),
        query: None,
        fields: Vec::new(),
    };
    let (host, admission) = admission_with_scope(app, routes.guests.clone(), &head, Some(scope));
    *weak.lock().unwrap() = Arc::downgrade(&host);
    let index = routes
        .guests
        .lines()
        .iter()
        .position(|line| line == admission.selected_line())
        .unwrap() as u32;
    let reply = host
        .refuse(Refuse {
            owner: OWNER,
            generation: 1,
            unit: UnitRef::NONE,
            cause: REFUSE_STOPPED,
            line: index,
            conn: FRAMING,
            stream: STREAM,
            framing: Some(FRAMING),
            request: Some(head),
        })
        .unwrap();
    assert_eq!(reply.status, expected_status);
    assert_eq!(reply.body, b"refused:401:unauthenticated");
    let tap = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tap["stage"]["outcome"], "rejected_by_auth");
    assert_eq!(tap["stage"]["status"], 401);
    assert_eq!(tap["request"]["ingress_protocol"], dialect);
    assert!(
        received.try_recv().is_err(),
        "one completion tap per auth refusal"
    );
    assert_eq!(g.money.open_units(), 0);
    assert!(g.book.lock().unwrap().audit_records.is_empty());
}

#[path = "serve_inbound_audit.rs"]
mod inbound_audit;
