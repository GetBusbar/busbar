// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE-BOOT-MOUNT: what the HTTP mount of a MIN-3 plane's data routes makes of a route table and of the
//! session's client items. The plane itself is an ffi handle, so the request path runs in the image suite
//! (W2-SW-PLANE e2e); these are the pure seams between axum and `PortDriver::serve`.

use axum::http::{HeaderMap, HeaderValue};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::abi::transport::route::{
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
            Seen::Verified("alice".into())
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
            route: 4,
            methods: 0,
            flags: 0,
            auth: effective,
            effective,
            pattern: "/hooks/in".into(),
            cred_header: None,
            resource_kinds: Vec::new(),
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
        signed_of(ingress, &who(), &route(effective), &[], b"{}", 1_000).await
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
