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
    let (status, fields, body) = parts_of(items);
    assert_eq!(status, 201);
    assert_eq!(fields, [(b"content-type".to_vec(), b"text/plain".to_vec())]);
    assert_eq!(body, b"hello");
}

#[test]
fn a_session_that_wrote_no_head_is_a_gateway_failure_not_a_200() {
    let (status, fields, body) = parts_of(vec![ToClient::Body(b"x".to_vec()), ToClient::End]);
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
