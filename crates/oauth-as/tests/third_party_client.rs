// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Independent-verifier harness: the widely used third-party `oauth2` CLIENT crate (pinned
//! =5.0.0) is driven against this AS as a black box. The client library, not this codebase,
//! decides whether our device authorization responses, token responses, and error bodies are
//! spec-legal: it parses them with its own strict types and runs its OWN RFC 8628 poll loop
//! (sleeping the advertised interval, backing off on `slow_down`).
//!
//! Hermetic by construction: the `oauth2` crate's pluggable `SyncHttpClient` seam is implemented
//! with an in-process adapter that hands the request straight to [`AuthorizationServer`], so no
//! network, no listener, and no timing flakiness (the client's sleeps advance a manual clock).
//!
//! The final tests are the harness's own red-proof: deliberately corrupted responses must make
//! the third-party client FAIL, demonstrating the verifier actually verifies.

use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use oauth2::basic::BasicClient;
use oauth2::{
    DeviceAuthorizationUrl, DeviceCodeErrorResponseType, RequestTokenError, Scope as OScope,
    StandardDeviceAuthorizationResponse, TokenResponse as _, TokenUrl,
};
use serde_json::Value;

use oauth_as::grant::DEVICE_CODE_GRANT_URN;
use oauth_as::{
    AuthorizationServer, Client, ClientAuth, ClientId, Clock, GrantType, MemoryStorage, ScopeSet,
    ServerConfig, TokenRequest,
};

#[derive(Clone)]
struct ManualClock(Arc<Mutex<SystemTime>>);
impl ManualClock {
    fn new() -> Self {
        ManualClock(Arc::new(Mutex::new(
            UNIX_EPOCH + Duration::from_secs(1_700_000_000),
        )))
    }
    fn advance(&self, d: Duration) {
        *self.0.lock().unwrap() += d;
    }
}
impl Clock for ManualClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

type Srv = AuthorizationServer<MemoryStorage, ManualClock>;

fn new_server(clock: ManualClock) -> Arc<Srv> {
    let srv = AuthorizationServer::with_clock(
        ServerConfig::new("https://as.example", "https://as.example/device"),
        MemoryStorage::new(),
        clock,
    );
    Arc::new(srv)
}

fn register(rt: &tokio::runtime::Runtime, srv: &Srv) {
    rt.block_on(srv.register_client(Client {
        client_id: ClientId::new("device-client"),
        auth: ClientAuth::Public,
        grant_types: vec![GrantType::DeviceCode, GrantType::RefreshToken],
        redirect_uris: vec![],
        allowed_scopes: ScopeSet::parse("read write").unwrap(),
        default_scopes: ScopeSet::parse("read").unwrap(),
        name: None,
    }))
    .unwrap();
}

/// Serve one of the third-party client's HTTP requests straight from the AS: parse the form body,
/// dispatch, serialize the crate's own response types with their `serde` shapes and HTTP statuses.
fn respond(rt: &tokio::runtime::Runtime, srv: &Srv, req: &oauth2::HttpRequest) -> (u16, Value) {
    let form: HashMap<String, String> = url::form_urlencoded::parse(req.body())
        .into_owned()
        .collect();
    let client_id = ClientId::new(form.get("client_id").cloned().unwrap_or_default());
    match req.uri().path() {
        "/device_authorization" => {
            let scope = form
                .get("scope")
                .map(|s| ScopeSet::parse(s).expect("client sent a grammatical scope"));
            match rt.block_on(srv.device_authorization(&client_id, None, scope.as_ref())) {
                Ok(resp) => (200, serde_json::to_value(resp).unwrap()),
                Err(err) => (err.http_status(), serde_json::to_value(err).unwrap()),
            }
        }
        "/token" => {
            let grant_type = form
                .get("grant_type")
                .map(String::as_str)
                .unwrap_or_default();
            let request = if grant_type == DEVICE_CODE_GRANT_URN {
                TokenRequest::DeviceCode {
                    client_id,
                    client_secret: None,
                    device_code: form.get("device_code").cloned().unwrap_or_default(),
                }
            } else {
                assert_eq!(
                    grant_type, "refresh_token",
                    "unexpected grant_type {grant_type:?}"
                );
                TokenRequest::RefreshToken {
                    client_id,
                    client_secret: None,
                    refresh_token: form.get("refresh_token").cloned().unwrap_or_default(),
                    scope: form.get("scope").map(|s| ScopeSet::parse(s).unwrap()),
                }
            };
            match rt.block_on(srv.token(request)) {
                Ok(resp) => (200, serde_json::to_value(resp).unwrap()),
                Err(err) => (err.http_status(), serde_json::to_value(err).unwrap()),
            }
        }
        other => panic!("third-party client hit an unexpected path {other:?}"),
    }
}

fn to_http(status: u16, body: &Value) -> oauth2::HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(body).unwrap())
        .unwrap()
}

fn oauth2_client() -> oauth2::Client<
    oauth2::basic::BasicErrorResponse,
    oauth2::basic::BasicTokenResponse,
    oauth2::basic::BasicTokenIntrospectionResponse,
    oauth2::StandardRevocableToken,
    oauth2::basic::BasicRevocationErrorResponse,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointNotSet,
    oauth2::EndpointSet,
> {
    BasicClient::new(oauth2::ClientId::new("device-client".into()))
        .set_device_authorization_url(
            DeviceAuthorizationUrl::new("https://as.example/device_authorization".into()).unwrap(),
        )
        .set_token_uri(TokenUrl::new("https://as.example/token".into()).unwrap())
}

#[test]
fn third_party_client_completes_the_device_flow_including_pending_polls() {
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    );
    let clock = ManualClock::new();
    let srv = new_server(clock.clone());
    register(&rt, &srv);

    let polls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let http_client = {
        let (rt, srv, polls) = (rt.clone(), srv.clone(), polls.clone());
        move |req: oauth2::HttpRequest| -> Result<oauth2::HttpResponse, Infallible> {
            let (status, body) = respond(&rt, &srv, &req);
            if req.uri().path() == "/token" {
                polls.lock().unwrap().push(body.clone());
            }
            Ok(to_http(status, &body))
        }
    };

    let client = oauth2_client();
    let details: StandardDeviceAuthorizationResponse = client
        .exchange_device_code()
        .add_scope(OScope::new("read".into()))
        .add_scope(OScope::new("write".into()))
        .request(&http_client)
        .expect("the third-party client accepted our device authorization response");
    assert_eq!(
        details.verification_uri().as_str(),
        "https://as.example/device"
    );
    assert_eq!(details.interval(), Duration::from_secs(5));

    // The user approves after the client has already polled once (so the client must handle a
    // real authorization_pending from us). The client's sleeps advance the manual clock, keeping
    // the client's pacing and the server's pacing in the same timeline with no real waiting.
    let user_code = details.user_code().secret().clone();
    let sleeps = Arc::new(Mutex::new(0u32));
    let sleep_fn = {
        let (rt, srv, clock, sleeps) = (rt.clone(), srv.clone(), clock.clone(), sleeps.clone());
        move |d: Duration| {
            clock.advance(d);
            let mut n = sleeps.lock().unwrap();
            *n += 1;
            if *n == 1 {
                rt.block_on(srv.approve_device(&user_code, "conformance-user"))
                    .unwrap();
            }
        }
    };

    let token = client
        .exchange_device_access_token(&details)
        .request(&http_client, sleep_fn, None)
        .expect("the third-party client accepted our token response");
    assert!(!token.access_token().secret().is_empty());
    assert_eq!(token.expires_in(), Some(Duration::from_secs(3600)));
    assert!(token.refresh_token().is_some());
    let scopes: Vec<String> = token
        .scopes()
        .unwrap()
        .iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(scopes, vec!["read".to_string(), "write".to_string()]);

    let polls = polls.lock().unwrap();
    assert!(
        polls.len() >= 2,
        "expected at least one pending poll then success, saw {polls:?}"
    );
    assert_eq!(polls[0]["error"], "authorization_pending");
    assert!(polls.last().unwrap().get("access_token").is_some());
}

#[test]
fn third_party_client_backs_off_on_slow_down_and_still_completes() {
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    );
    let clock = ManualClock::new();
    let srv = new_server(clock.clone());
    register(&rt, &srv);

    let polls = Arc::new(Mutex::new(Vec::<Value>::new()));
    let http_client = {
        let (rt, srv, polls) = (rt.clone(), srv.clone(), polls.clone());
        move |req: oauth2::HttpRequest| -> Result<oauth2::HttpResponse, Infallible> {
            let (status, body) = respond(&rt, &srv, &req);
            if req.uri().path() == "/token" {
                polls.lock().unwrap().push(body.clone());
            }
            Ok(to_http(status, &body))
        }
    };

    let client = oauth2_client();
    let details: StandardDeviceAuthorizationResponse =
        client.exchange_device_code().request(&http_client).unwrap();
    let user_code = details.user_code().secret().clone();

    // A skewed device clock: the first sleep advances only half the requested wait, so the second
    // poll arrives too early and the server answers slow_down. The third-party client must then
    // raise its interval by 5 seconds (RFC 8628 section 3.5) on its own; later sleeps are honest.
    let sleeps = Arc::new(Mutex::new(0u32));
    let sleep_fn = {
        let (rt, srv, clock, sleeps) = (rt.clone(), srv.clone(), clock.clone(), sleeps.clone());
        move |d: Duration| {
            let mut n = sleeps.lock().unwrap();
            *n += 1;
            if *n == 1 {
                clock.advance(d / 2);
            } else {
                clock.advance(d);
                if *n == 3 {
                    rt.block_on(srv.approve_device(&user_code, "u")).unwrap();
                }
            }
        }
    };

    let token = client
        .exchange_device_access_token(&details)
        .request(&http_client, sleep_fn, None)
        .expect("the client recovered from slow_down and completed");
    assert!(!token.access_token().secret().is_empty());

    let polls = polls.lock().unwrap();
    let errors: Vec<&str> = polls
        .iter()
        .filter_map(|p| p.get("error").and_then(Value::as_str))
        .collect();
    assert!(
        errors.contains(&"slow_down"),
        "the skewed pace must have produced slow_down: {errors:?}"
    );
    assert!(polls.last().unwrap().get("access_token").is_some());
}

#[test]
fn third_party_client_surfaces_access_denied() {
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    );
    let clock = ManualClock::new();
    let srv = new_server(clock.clone());
    register(&rt, &srv);

    let http_client = {
        let (rt, srv) = (rt.clone(), srv.clone());
        move |req: oauth2::HttpRequest| -> Result<oauth2::HttpResponse, Infallible> {
            let (status, body) = respond(&rt, &srv, &req);
            Ok(to_http(status, &body))
        }
    };

    let client = oauth2_client();
    let details: StandardDeviceAuthorizationResponse =
        client.exchange_device_code().request(&http_client).unwrap();
    rt.block_on(srv.deny_device(details.user_code().secret()))
        .unwrap();

    let clock_for_sleep = clock.clone();
    let result = client.exchange_device_access_token(&details).request(
        &http_client,
        move |d| clock_for_sleep.advance(d),
        None,
    );
    match result {
        Err(RequestTokenError::ServerResponse(err)) => {
            assert_eq!(*err.error(), DeviceCodeErrorResponseType::AccessDenied);
        }
        other => panic!("expected the client to surface access_denied, got {other:?}"),
    }
}

/// RED-PROOF 1: a device authorization response missing `user_code` (an RFC 8628 section 3.2
/// REQUIRED member) must be REJECTED by the third-party client. If this test ever passes with the
/// corruption accepted, the verifier has stopped verifying.
#[test]
fn harness_red_proof_client_rejects_a_corrupted_device_authorization_response() {
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    );
    let clock = ManualClock::new();
    let srv = new_server(clock);
    register(&rt, &srv);

    let http_client = {
        let (rt, srv) = (rt.clone(), srv.clone());
        move |req: oauth2::HttpRequest| -> Result<oauth2::HttpResponse, Infallible> {
            let (status, mut body) = respond(&rt, &srv, &req);
            body.as_object_mut().unwrap().remove("user_code");
            Ok(to_http(status, &body))
        }
    };

    let result: Result<StandardDeviceAuthorizationResponse, _> =
        oauth2_client().exchange_device_code().request(&http_client);
    assert!(
        matches!(result, Err(RequestTokenError::Parse(_, _))),
        "the client must reject the corrupted body, got {result:?}"
    );
}

/// RED-PROOF 2: a token success body stripped of `access_token` (RFC 6749 section 5.1 REQUIRED)
/// must be rejected by the third-party client.
#[test]
fn harness_red_proof_client_rejects_a_corrupted_token_response() {
    let rt = Arc::new(
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap(),
    );
    let clock = ManualClock::new();
    let srv = new_server(clock.clone());
    register(&rt, &srv);

    let http_client = {
        let (rt, srv) = (rt.clone(), srv.clone());
        move |req: oauth2::HttpRequest| -> Result<oauth2::HttpResponse, Infallible> {
            let (status, mut body) = respond(&rt, &srv, &req);
            if let Some(obj) = body.as_object_mut() {
                obj.remove("access_token");
            }
            Ok(to_http(status, &body))
        }
    };

    let client = oauth2_client();
    let details: StandardDeviceAuthorizationResponse =
        client.exchange_device_code().request(&http_client).unwrap();
    rt.block_on(srv.approve_device(details.user_code().secret(), "u"))
        .unwrap();

    let clock_for_sleep = clock.clone();
    let result = client.exchange_device_access_token(&details).request(
        &http_client,
        move |d| clock_for_sleep.advance(d),
        None,
    );
    assert!(
        matches!(result, Err(RequestTokenError::Parse(_, _))),
        "the client must reject the stripped success body, got {result:?}"
    );
}
