// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A client credential presented to Busbar is never forwarded upstream (SEC-STRIP). The plane builds
//! every upstream request from the head fields core lends it (`HttpIn::each_header`, a selector's
//! `FrozenRequest::with_selection_input`), so a field it is never lent never reaches an upstream.
//! The upstream gets only what core seals for it; a caller's own credential reaches an upstream only
//! through core's configured passthrough (the lent `CallerCredential`), never through the plane.
//! Each test sends every carrier a client credential travels in, on each data path and chain, and
//! asserts the plane is lent none of them.

use super::*;
use crate::auth::native_chain::BuiltIn;
use crate::plane_driver::port::{HttpHead, HttpIn};

/// A request head carrying the client's credential in every carrier, beside one ordinary field.
fn presented() -> Vec<(String, Vec<u8>)> {
    vec![
        ("authorization".to_owned(), b"Bearer client-secret".to_vec()),
        ("X-Api-Key".to_owned(), b"client-secret".to_vec()),
        ("api-key".to_owned(), b"client-secret".to_vec()),
        ("x-goog-api-key".to_owned(), b"client-secret".to_vec()),
        ("cookie".to_owned(), b"session=client-secret".to_vec()),
        (
            "proxy-authorization".to_owned(),
            b"Basic Y2xpZW50OnNlY3JldA==".to_vec(),
        ),
        ("x-amz-security-token".to_owned(), b"client-secret".to_vec()),
        ("x-admin-token".to_owned(), b"client-secret".to_vec()),
        ("x-trace".to_owned(), b"1".to_vec()),
    ]
}

/// The names of the head fields the plane is lent, lowercase, in order.
fn lent_names(http: &HttpIn) -> Vec<String> {
    let mut names = Vec::new();
    http.each_header(|name, _| names.push(name.to_ascii_lowercase()));
    names
}

fn owners() -> Arc<AuthOwners> {
    let replay = Arc::new(Owners(AtomicUsize::new(0), AtomicBool::new(false)));
    Arc::new(AuthOwners {
        issued: replay.clone(),
        replay,
        cache: Arc::new(Verdicts::new(VerdictPolicy::DEFAULT)),
    })
}

/// What the plane is lent on a native data route of `chain`, as `PortDriver::serve_admitted`
/// lends it: the request's head with the route's carriers withheld.
fn lent_on_native_route(chain: &NativeChain) -> Vec<String> {
    let mut http = HttpIn::new(
        HttpHead::Text {
            method: "POST".into(),
            path: "/v1/messages".into(),
            query: String::new(),
            headers: presented(),
        },
        bytes::Bytes::new(),
        1,
    );
    http.withhold(withheld_carriers(chain, None));
    lent_names(&http)
}

/// The plane port path (`port_mount::http_in`): the request's parts move into the plane's input as
/// the router handed them, after the gate stripped what it consumed (nothing, since the plugin auth
/// axis is gone). Whatever the chain, the plane is lent no client credential.
#[test]
fn the_plane_port_path_lends_the_plane_no_client_credential() {
    let mut headers = http::HeaderMap::new();
    for (name, value) in presented() {
        headers.append(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::header::HeaderValue::from_bytes(&value).unwrap(),
        );
    }
    let http = HttpIn::new(
        HttpHead::Parts {
            method: "POST",
            uri: http::Uri::from_static("/v1/chat/completions"),
            headers,
        },
        bytes::Bytes::new(),
        1,
    );
    assert_eq!(lent_names(&http), ["x-trace"]);
}

/// An anonymous (open-relay) chain reads no credential, so it withholds nothing of its own: the
/// client's carriers are still never lent.
#[test]
fn a_native_route_on_an_anonymous_chain_lends_the_plane_no_client_credential() {
    let chain = NativeChain::data_admitting_anonymous(7, Vec::new(), owners()).unwrap();
    assert!(chain.is_open());
    assert_eq!(lent_on_native_route(&chain), ["x-trace"]);
}

/// A `keys` chain reads a core-issued key from `x-api-key` and `x-goog-api-key` as well as
/// `authorization` (`issued::KEY_CARRIERS`): none of them is lent.
#[test]
fn a_native_route_on_a_keys_chain_lends_the_plane_no_client_credential() {
    let chain = NativeChain::data_with(
        7,
        Vec::new(),
        owners(),
        BuiltIn {
            anonymous: false,
            keys: true,
        },
    )
    .unwrap();
    assert!(chain.admits_keys());
    assert_eq!(lent_on_native_route(&chain), ["x-trace"]);
}

/// A selecting route's selector is lent the frozen request before anything is forwarded: on an
/// anonymous chain it is lent no client credential either.
#[tokio::test]
async fn a_selector_on_an_anonymous_chain_is_lent_no_client_credential() {
    let f = fixture_of(true, true, Vec::new(), true);
    assert!(f.route.owners.chain.is_open());
    let (mut request, wire, cx, _owner) = arrival_with_fields(&f, 1, presented());
    let preparation = request.begin_data_preparation().unwrap();
    let pending = f.route.prepare(preparation, cx).await.unwrap();
    let lent = Mutex::new(Lent::default());
    let _pending = pending
        .select(|frozen, withheld| lend(&lent, frozen, withheld, wire))
        .unwrap();
    let lent = lent.into_inner().unwrap();
    assert_eq!(lent.calls, 1);
    assert_eq!(lent.headers, vec!["x-trace".to_owned()]);
}

/// Every field withheld as a client credential is one the specification already names: the
/// connector's caller-side strip (`NEVER_KEPT`) or the 1.5 admin carrier.
#[test]
fn every_client_credential_field_is_one_the_specification_names() {
    use busbar_contract::abi::host::conn::connector::NEVER_KEPT;
    for field in crate::plane_driver::port::CLIENT_CREDENTIAL_FIELDS {
        assert!(
            NEVER_KEPT.contains(&field) || field == "x-admin-token",
            "{field}"
        );
    }
}
