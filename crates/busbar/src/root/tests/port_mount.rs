// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE-BOOT-MOUNT: what the HTTP mount of a MIN-3 plane's data routes makes of a route table and of the
//! session's client items. The plane itself is an ffi handle, so the request path runs in the image suite
//! (W2-SW-PLANE e2e); these are the pure seams between axum and `PortDriver::serve`.

use axum::http::{HeaderMap, HeaderValue};
use busbar_contract::route::{RouteAuth, RouteMethod};
use busbar_contract::route::{
    METHOD_DELETE, METHOD_GET, METHOD_HEAD, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};
use busbar_kernel::plane_driver::port_session::ToClient;
use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET};

use super::*;

#[test]
fn the_method_mask_mounts_the_five_verbs_and_drops_the_rest() {
    let all = METHOD_GET | METHOD_HEAD | METHOD_POST | METHOD_PUT | METHOD_PATCH | METHOD_DELETE;
    assert_eq!(
        methods_of(all),
        [
            RouteMethod::Get,
            RouteMethod::Post,
            RouteMethod::Put,
            RouteMethod::Patch,
            RouteMethod::Delete
        ]
    );
    assert_eq!(methods_of(METHOD_HEAD), []);
    assert_eq!(methods_of(METHOD_POST), [RouteMethod::Post]);
}

#[test]
fn only_a_principal_only_route_is_behind_the_data_auth_chain() {
    assert_eq!(auth_of(AUTH_PRINCIPAL), RouteAuth::Key);
    // Core classifies these itself, per request (§12.11): the data chain must not refuse them first.
    for classes in [
        AUTH_OPTIONAL,
        AUTH_PUBLIC,
        AUTH_TICKET,
        AUTH_PRINCIPAL | AUTH_TICKET,
        AUTH_PRINCIPAL | AUTH_OPTIONAL,
    ] {
        assert_eq!(auth_of(classes), RouteAuth::None, "{classes:#x}");
    }
}

#[test]
fn the_route_credential_header_wins_over_authorization() {
    let mut h = HeaderMap::new();
    h.insert("authorization", HeaderValue::from_static("Bearer tok-a"));
    h.insert("x-api-key", HeaderValue::from_static("tok-b"));
    assert_eq!(bearer_of(&h, None).as_deref(), Some("tok-a"));
    assert_eq!(bearer_of(&h, Some("x-api-key")).as_deref(), Some("tok-b"));
    assert_eq!(bearer_of(&h, Some("x-missing")), None);
    h.insert("authorization", HeaderValue::from_static("Basic abc"));
    assert_eq!(bearer_of(&h, None), None);
}

#[test]
fn client_items_become_one_response_in_the_order_the_plane_wrote_them() {
    let items = vec![
        ToClient::Head {
            status: 201,
            fields: vec![(b"content-type".to_vec(), b"text/plain".to_vec())],
        },
        ToClient::Body(b"he".to_vec()),
        ToClient::Msg {
            flags: 0,
            bytes: b"llo".to_vec(),
        },
        ToClient::End,
    ];
    let (status, fields, body) = port_admin::joined(items);
    assert_eq!(status, 201);
    assert_eq!(fields, [(b"content-type".to_vec(), b"text/plain".to_vec())]);
    assert_eq!(body, b"hello");
}

#[test]
fn a_session_that_wrote_no_head_is_a_gateway_failure_not_a_200() {
    let (status, fields, body) =
        port_admin::joined(vec![ToClient::Body(b"x".to_vec()), ToClient::End]);
    assert_eq!((status, fields.len(), body), (502, 0, Vec::new()));
}

fn pipe() -> (
    Pipe,
    oneshot::Receiver<(u16, HeadFields)>,
    mpsc::UnboundedReceiver<Bytes>,
) {
    let (head_tx, head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::unbounded_channel();
    (
        Pipe {
            head: Mutex::new(Some(head_tx)),
            body: body_tx,
        },
        head_rx,
        body_rx,
    )
}

async fn frames(mut body: PipeBody) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(frame) =
        std::future::poll_fn(|cx| http_body::Body::poll_frame(std::pin::Pin::new(&mut body), cx))
            .await
    {
        out.push(frame.unwrap().into_data().unwrap().to_vec());
    }
    out
}

#[tokio::test]
async fn a_streamed_reply_decides_its_head_first_and_streams_the_body_in_the_order_written() {
    let (pipe, head, body) = pipe();
    assert!(pipe.items(vec![ToClient::Head {
        status: 201,
        fields: vec![(b"content-type".to_vec(), b"text/event-stream".to_vec())],
    }]));
    // The head is available before any body was written: the response can begin.
    let (status, fields) = head.await.unwrap();
    assert_eq!(status, 201);
    assert_eq!(fields.len(), 1);
    assert!(pipe.items(vec![
        ToClient::Body(b"one".to_vec()),
        ToClient::Msg {
            flags: 0,
            bytes: b"two".to_vec()
        },
        ToClient::Body(Vec::new()),
        ToClient::Trailers(Vec::new()),
        ToClient::End,
    ]));
    drop(pipe);
    assert_eq!(
        frames(PipeBody(body)).await,
        vec![b"one".to_vec(), b"two".to_vec()]
    );
}

#[tokio::test]
async fn a_second_head_changes_nothing_once_the_response_began() {
    let (pipe, head, _body) = pipe();
    let head_of = |status| ToClient::Head {
        status,
        fields: Vec::new(),
    };
    assert!(pipe.items(vec![head_of(200), head_of(500)]));
    assert_eq!(head.await.unwrap().0, 200);
}

#[test]
fn a_client_that_went_away_tells_the_session_to_stop() {
    let (gone_body, _head, body) = pipe();
    drop(body);
    assert!(!gone_body.items(vec![ToClient::Body(b"x".to_vec())]));
    let (gone_head, head, _body) = pipe();
    drop(head);
    assert!(
        !gone_head.items(vec![ToClient::Head {
            status: 200,
            fields: Vec::new()
        }]),
        "the response was dropped before its head: nothing more is wanted"
    );
}

mod optional_principal {
    use busbar_contract::auth::Principal;
    use busbar_kernel::auth::IdentityRefusal;
    use busbar_kernel::governance::GovCtx;

    use super::super::*;

    fn principal(id: &str) -> busbar_kernel::auth::AuthPrincipal {
        busbar_kernel::auth::AuthPrincipal(Some(Principal {
            id: id.into(),
            name: None,
            roles: Vec::new(),
            ttl_secs: None,
        }))
    }

    #[test]
    fn a_credential_the_chain_identifies_is_the_verified_principal() {
        assert_eq!(
            seen_of(Ok((principal("alice"), GovCtx::default()))),
            Seen::Verified(Principal {
                id: "alice".into(),
                name: None,
                roles: Vec::new(),
                ttl_secs: None,
            })
        );
    }

    #[test]
    fn an_open_chain_or_no_identity_is_anonymous_and_a_refused_credential_is_rejected() {
        assert_eq!(
            seen_of(Ok((
                busbar_kernel::auth::AuthPrincipal(None),
                GovCtx::default()
            ))),
            Seen::Anonymous
        );
        assert_eq!(seen_of(Err(IdentityRefusal::Denied)), Seen::Rejected);
        assert_eq!(seen_of(Err(IdentityRefusal::NoGrant)), Seen::Rejected);
    }

    #[test]
    fn a_route_the_data_chain_does_not_gate_resolves_the_credential_itself() {
        use busbar_plugin_abi::plane::{AUTH_OPTIONAL, AUTH_PRINCIPAL, AUTH_PUBLIC, AUTH_TICKET};
        // OPTIONAL takes the principal when a credential names one; PRINCIPAL beside another class is chosen per
        // request (a ticket or a key), so the key must be resolved here, as the chain does not gate the route.
        assert!(resolves_credential(AUTH_OPTIONAL));
        assert!(resolves_credential(AUTH_OPTIONAL | AUTH_PUBLIC));
        assert!(resolves_credential(AUTH_PRINCIPAL | AUTH_OPTIONAL));
        assert!(resolves_credential(AUTH_PRINCIPAL | AUTH_TICKET));
        // PRINCIPAL alone runs behind the data chain (`auth_of`); PUBLIC and TICKET never need a key.
        assert!(!resolves_credential(AUTH_PRINCIPAL));
        assert!(!resolves_credential(AUTH_PUBLIC));
        assert!(!resolves_credential(AUTH_TICKET));
        assert!(!resolves_credential(AUTH_PUBLIC | AUTH_TICKET));
    }
}

mod signed_ingress {
    use std::sync::atomic::{AtomicBool, Ordering};

    use busbar_contract::secret_ref::SecretRef;
    use busbar_kernel::plane_driver::port_routes::Mounted;
    use busbar_kernel::plane_grants::{IngressVerifier, ReplayGuard};
    use busbar_kernel::plugin_records::RecordsDenied;
    use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
    use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, AUTH_SIGNED_INGRESS};
    use busbar_plugin_abi::types::Pair;

    use super::super::*;

    struct Verifier(bool);
    impl IngressVerifier for Verifier {
        fn verify<'a>(
            &'a self,
            _: &'a SecretRef,
            _: &'a [Pair<'a>],
            _: &'a [u8],
            _: u64,
        ) -> BoxFut<'a, bool> {
            Box::pin(core::future::ready(self.0))
        }
    }

    struct Guard(AtomicBool);
    impl ReplayGuard for Guard {
        fn claim_until<'a>(
            &'a self,
            _: &'a Caller<'_>,
            _: &'a [u8],
            _: u64,
        ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
            panic!("mounted eager fixture must use its original relative replay policy")
        }
        fn claim<'a>(
            &'a self,
            _: &'a Caller<'_>,
            _: &'a [u8],
            _: u64,
        ) -> BoxFut<'a, Result<bool, RecordsDenied>> {
            Box::pin(core::future::ready(Ok(self
                .0
                .swap(false, Ordering::SeqCst))))
        }
    }

    fn route(effective: u32) -> Mounted {
        Mounted {
            record: busbar_kernel::auth::route_record::RouteRecord::stated(
                busbar_kernel::auth::route_record::RouteClass::Data,
                busbar_kernel::auth::route_record::Who::from_mask(effective).expect("a caller set"),
                busbar_kernel::auth::route_record::Scope::none(),
                busbar_kernel::auth::route_record::Money::None,
            ),
            route: 4,
            methods: 0,
            flags: 0,
            auth: effective,
            effective,
            pattern: "/hooks/in".into(),
            cred_header: None,
            resource_kinds: Default::default(),
            catalog: false,
        }
    }

    fn ingress(verified: bool, secret: bool) -> Ingress {
        Ingress {
            verifier: Arc::new(Verifier(verified)),
            replay: Arc::new(Guard(AtomicBool::new(true))),
            secrets: Arc::new(move |_: &str, _: u32| secret.then_some(SecretRef::None)),
        }
    }

    fn who() -> busbar_kernel::plane_driver::port_intents::Namespace {
        busbar_kernel::plane_driver::port_intents::Namespace {
            plugin: "plane-x".into(),
            name: "x".into(),
            instance: 1,
            slot: 0,
        }
    }

    async fn check(ingress: &Ingress, effective: u32) -> Option<bool> {
        // No header fields, a `{}` body.
        let http = HttpIn::new(
            HttpHead::Text {
                method: "POST".into(),
                path: "/".into(),
                query: String::new(),
                headers: Vec::new(),
            },
            Bytes::from_static(b"{}"),
            0,
        );
        signed_of(ingress, &who(), &route(effective), &http, 1_000).await
    }

    #[tokio::test]
    async fn a_route_that_is_not_signed_ingress_runs_no_check() {
        assert_eq!(check(&ingress(true, true), AUTH_PRINCIPAL).await, None);
    }

    #[tokio::test]
    async fn a_verified_first_sighting_is_admitted_and_its_replay_is_not() {
        let ingress = ingress(true, true);
        assert_eq!(check(&ingress, AUTH_SIGNED_INGRESS).await, Some(true));
        assert_eq!(
            check(&ingress, AUTH_SIGNED_INGRESS).await,
            Some(false),
            "the same signed request is replayed"
        );
    }

    #[tokio::test]
    async fn a_bad_signature_or_a_route_with_no_secret_is_not_admitted() {
        assert_eq!(
            check(&ingress(false, true), AUTH_SIGNED_INGRESS).await,
            Some(false)
        );
        assert_eq!(
            check(&ingress(true, false), AUTH_SIGNED_INGRESS).await,
            Some(false)
        );
    }
}

#[test]
fn a_blocked_admission_is_answered_with_its_status_and_the_wait_it_names() {
    use busbar_kernel::governance::LimitBlocked;
    let limit = |metric, retry_after| LimitBlocked::Limit {
        group: "g".into(),
        metric,
        window: None,
        pool: None,
        downgrade_to: None,
        retry_after,
    };
    let rate = blocked_response(&limit("concurrent", None));
    assert_eq!(rate.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(rate.headers().get(header::RETRY_AFTER).is_none());
    let waited = blocked_response(&limit("requests", Some(30)));
    assert_eq!(waited.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(waited.headers()[header::RETRY_AFTER], "30");
    let frozen = blocked_response(&LimitBlocked::Disabled("g".into()));
    assert_eq!(frozen.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn the_planes_end_closes_the_response_body_while_the_session_goes_on() {
    let (pipe, head, body) = pipe();
    let status = Arc::new(AtomicU16::new(0));
    let sink = Counted {
        inner: Mutex::new(Some(pipe)),
        status: Arc::clone(&status),
    };
    assert!(sink.items(vec![
        ToClient::Head {
            status: 201,
            fields: Vec::new(),
        },
        ToClient::Body(b"answer".to_vec()),
        ToClient::End,
    ]));
    assert_eq!(
        status.load(Ordering::Relaxed),
        201,
        "the unit settles by what the client was told"
    );
    assert_eq!(head.await.unwrap().0, 201);
    // The sink is still alive (a held channel or media bridge keeps the session going), yet the body is complete.
    assert_eq!(frames(PipeBody(body)).await, vec![b"answer".to_vec()]);
    assert!(
        sink.items(vec![ToClient::Body(b"late".to_vec())]),
        "a write after the end has no client to reach, and the client is not gone"
    );
}

/// E9a: the route-level rules of a ROUTE_UPGRADE route (§12.27). Its auth step and the custody of
/// core's answer are proved in the kernel (`auth/tests/native_upgrade_tests.rs`).
mod upgrade {
    use busbar_contract::kinds::codes::KindCode;
    use busbar_contract::route::{METHOD_GET, METHOD_POST, PATH_EXACT};
    use busbar_contract::services::Caller;
    use busbar_kernel::guest::{Claimant, Line, LineAuth, Route};
    use busbar_kernel::inbound::native::RouteBinding;
    use busbar_kernel::plane_driver::port_routes::Mounted;
    use busbar_kernel::plane_driver::port_session::ToClient;
    use busbar_plugin_abi::fail::refused::{R_INVALID, R_UNSUPPORTED};
    use busbar_plugin_abi::plane::{AUTH_PRINCIPAL, ROUTE_UPGRADE};

    use super::super::*;
    use crate::root::min3_boot::transports::tests::framer;
    use crate::root::min3_boot::transports::ServedTransport;

    fn asks(fields: &[(&str, &str)]) -> bool {
        asks_websocket(fields.iter().map(|(name, value)| (*name, value.as_bytes())))
    }

    #[test]
    fn only_a_request_that_asks_to_switch_to_websocket_is_an_upgrade_request() {
        assert!(asks(&[("connection", "Upgrade"), ("upgrade", "websocket")]));
        assert!(asks(&[
            ("Connection", "keep-alive, Upgrade"),
            ("Upgrade", "WebSocket")
        ]));
        assert!(!asks(&[]), "a plain GET on the route");
        assert!(!asks(&[("upgrade", "websocket")]), "no connection token");
        assert!(!asks(&[("connection", "upgrade")]), "no upgrade protocol");
        assert!(!asks(&[("connection", "upgrade"), ("upgrade", "h2c")]));
        assert!(!asks(&[
            ("connection", "upgraded"),
            ("upgrade", "websocket")
        ]));
    }

    #[test]
    fn with_no_websocket_instance_an_upgrade_request_is_answered_501_r_unsupported() {
        let UpgradeStep::Refuse(refusal) = upgrade_step(true, None) else {
            panic!("no instance can carry it")
        };
        assert_eq!(
            (refusal.status, refusal.code, refusal.text.as_ref()),
            (501, R_UNSUPPORTED, NO_WEBSOCKET)
        );
        // Core's fallback when the plane cannot render it: a plain status response with body.
        let items = port_auth::plain_refusal(&refusal);
        assert!(matches!(
            items.first(),
            Some(ToClient::Head { status: 501, .. })
        ));
        assert!(
            matches!(items.get(1), Some(ToClient::Body(body)) if body == NO_WEBSOCKET.as_bytes())
        );
    }

    #[test]
    fn a_request_that_does_not_ask_for_websocket_is_the_routes_400_even_with_an_instance() {
        let websocket = ServedTransport {
            instance: Arc::from("transport-ws"),
            port: framer(&["websocket"]),
        };
        for carrier in [None, Some(&websocket)] {
            let UpgradeStep::Refuse(refusal) = upgrade_step(false, carrier) else {
                panic!("not an upgrade request")
            };
            assert_eq!(
                (refusal.status, refusal.code, refusal.text.as_ref()),
                (400, R_INVALID, NOT_AN_UPGRADE)
            );
        }
    }

    #[test]
    fn with_an_admitted_websocket_instance_the_request_goes_to_that_exact_instance() {
        let websocket = ServedTransport {
            instance: Arc::from("transport-ws"),
            port: framer(&["websocket"]),
        };
        let UpgradeStep::HandOver(carrier) = upgrade_step(true, Some(&websocket)) else {
            panic!("an instance can carry it")
        };
        assert!(Arc::ptr_eq(&carrier.port, &websocket.port));
    }

    fn binding(route: u32, methods: u32, flags: u32, path: &str) -> RouteBinding {
        let caller = Caller::issue(
            &busbar_kernel::seal::acquire(),
            Arc::from("plane/test"),
            KindCode::Plane,
        );
        let line = Line {
            route: Route {
                methods,
                path_form: PATH_EXACT,
                path: path.into(),
                fields: Vec::new(),
                rung: route,
            },
            claimant: Claimant::Plane("plane/test".into()),
            dialect: 0,
            auth: LineAuth::Chain(
                vec!["provider".into()],
                busbar_contract::route::AuthPoints::EMPTY,
            ),
            upgrade: None,
            offered: busbar_contract::route::AuthPoints::EMPTY,
        };
        let mounted = Mounted {
            record: busbar_kernel::auth::route_record::RouteRecord::stated(
                busbar_kernel::auth::route_record::RouteClass::from_flags(flags)
                    .expect("one class"),
                busbar_kernel::auth::route_record::Who::PRINCIPAL,
                busbar_kernel::auth::route_record::Scope::none(),
                busbar_kernel::auth::route_record::Money::Unit,
            ),
            route,
            methods,
            flags,
            auth: AUTH_PRINCIPAL,
            effective: AUTH_PRINCIPAL,
            pattern: path.into(),
            cred_header: None,
            resource_kinds: Default::default(),
            catalog: false,
        };
        RouteBinding::plane(line, caller, mounted, vec!["provider".into()]).unwrap()
    }

    #[test]
    fn only_the_upgrade_route_takes_the_upgrade_path_and_the_planes_other_routes_stay_data() {
        use crate::root::min3_physical::is_upgrade;
        assert!(is_upgrade(&binding(
            6,
            METHOD_GET,
            ROUTE_UPGRADE,
            "/v1/realtime"
        )));
        assert!(!is_upgrade(&binding(
            2,
            METHOD_POST,
            0,
            "/v1/realtime/calls"
        )));
    }
}
