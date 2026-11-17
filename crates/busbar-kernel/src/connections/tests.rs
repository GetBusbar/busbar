// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! W1-K10: caller connections (IF §12.12): BEGIN with core-minted PKCE, the callback, STATUS, REVOKE, the grant
//! deletion on R_CONNECT_REQUIRED, restart/replica visibility and the callback route claims.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::auth::{FB_LOGIN_REDIRECT, SECURITY_CHECK};
use busbar_plugin_abi::fail::refused::{R_CONNECT_REQUIRED, R_UNSUPPORTED};
use busbar_plugin_abi::host_side::caller::{BoxFut, CallStack, Caller, InstanceLimits};
use busbar_plugin_abi::plane::{CONN_NONE, CONN_READY};
use busbar_plugin_abi::types::KindCode;
use busbar_ports::auth::{
    AuthIn, AuthPort, LoginAnswer, LoginIn, OutboundAnswer, ServeIn, ServeOut, UpstreamIn, Verify,
};
use busbar_ports::{CallCx, PortError};

use super::*;
use crate::plugin_records::{RecordsDenied, StoreRecords};
use crate::upstreams::{UpstreamAuth, UpstreamDef, UpstreamTls, Upstreams};

const AT_REST: [u8; 32] = [9u8; 32];
const PUBLIC: &str = "https://busbar.example";
const CALLBACK: &str = "/connect/cb";

/// What the fake authorization plugin saw.
#[derive(Default)]
struct Seen {
    challenge: Option<String>,
    begin_nonce: Option<String>,
    state_key: Option<String>,
    redirect_uri: Option<String>,
    connect: Option<String>,
    verifier: Option<String>,
    complete_nonce: Option<String>,
    complete_state: Option<Vec<u8>>,
}

/// An `oauth-connection`-style auth instance: BEGIN redirects, COMPLETE answers a GRANT, or SECURITY_CHECK when
/// the callback's `iss` is wrong.
struct FakeOauth {
    facts: u64,
    seen: Arc<Mutex<Seen>>,
}

fn refused(code: u32) -> PortError {
    PortError::Refused {
        code,
        text: "refused".into(),
        error: None,
    }
}

fn unsupported<'a, T: Send + 'a>() -> BoxFut<'a, Result<T, PortError>> {
    Box::pin(async { Err(refused(R_UNSUPPORTED)) })
}

impl AuthPort for FakeOauth {
    fn facts(&self) -> u64 {
        self.facts
    }

    fn cred_headers(&self) -> &[Box<str>] {
        &[]
    }

    fn issued_kind(&self) -> Option<&str> {
        None
    }

    fn verify<'a>(&'a self, _cx: CallCx, _req: &AuthIn<'_>, _issued: Option<&[u8]>) -> Verify<'a> {
        Verify::Done(Err(refused(R_UNSUPPORTED)))
    }

    fn login<'a>(
        &'a self,
        _cx: CallCx,
        step: LoginIn<'a>,
    ) -> BoxFut<'a, Result<LoginAnswer, PortError>> {
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let answer = match step {
            LoginIn::Begin {
                redirect_uri,
                state_key,
                code_challenge,
                nonce,
                connect,
                ..
            } => {
                seen.challenge = Some(code_challenge.to_owned());
                seen.begin_nonce = Some(nonce.to_owned());
                seen.state_key = Some(state_key.to_owned());
                seen.redirect_uri = Some(redirect_uri.to_owned());
                seen.connect = connect.map(str::to_owned);
                Ok(LoginAnswer::Redirect {
                    url: format!(
                        "https://as.example/authorize?code_challenge={code_challenge}&code_challenge_method=S256&state={state_key}"
                    )
                    .into(),
                    state: SecureVec::from(b"issuer=as.example".as_slice()),
                })
            }
            LoginIn::Complete {
                callback_query,
                state,
                code_verifier,
                nonce,
                ..
            } => {
                seen.verifier = Some(code_verifier.to_owned());
                seen.complete_nonce = Some(nonce.to_owned());
                seen.complete_state = Some(state.to_vec());
                if callback_query.contains("iss=evil") {
                    Err(refused(SECURITY_CHECK))
                } else {
                    Ok(LoginAnswer::Grant(SecureVec::from(
                        b"refresh-token-1".as_slice(),
                    )))
                }
            }
            LoginIn::Credential { .. } => Err(refused(R_UNSUPPORTED)),
        };
        Box::pin(async move { answer })
    }

    fn outbound<'a>(
        &'a self,
        _cx: CallCx,
        _req: &'a UpstreamIn<'a>,
    ) -> BoxFut<'a, Result<OutboundAnswer, PortError>> {
        unsupported()
    }

    fn refresh<'a>(&'a self, _cx: CallCx) -> BoxFut<'a, Result<Option<u32>, PortError>> {
        unsupported()
    }

    fn serve<'a>(
        &'a self,
        _cx: CallCx,
        _req: &'a ServeIn<'a>,
    ) -> BoxFut<'a, Result<ServeOut, PortError>> {
        unsupported()
    }
}

struct Logins(BTreeMap<&'static str, Arc<dyn AuthPort>>);

impl ConnectLogins for Logins {
    fn port(&self, instance: &str) -> Option<Arc<dyn AuthPort>> {
        self.0.get(instance).cloned()
    }
}

struct Table(BTreeMap<&'static str, Arc<UpstreamDef>>);

impl Upstreams for Table {
    fn get(&self, name: &str) -> Option<Arc<UpstreamDef>> {
        self.0.get(name).cloned()
    }
}

fn upstream(name: &str, auth: Option<UpstreamAuth>) -> Arc<UpstreamDef> {
    Arc::new(UpstreamDef {
        name: name.into(),
        url: Some(format!("https://{name}.example").into()),
        command: None,
        tls: UpstreamTls {
            pin_spki: Vec::new(),
            client_identity: None,
            trust: None,
        },
        auth,
    })
}

fn binding(instance: &str, callback: Option<&str>) -> UpstreamAuth {
    UpstreamAuth {
        instance: instance.into(),
        cache_max_s: None,
        connect_callback: callback.map(Into::into),
        caller: true,
        scoped: false,
        per_request: false,
    }
}

fn plane() -> Caller<'static> {
    Caller {
        plugin: "plane-mcp",
        kind: KindCode::Plane,
        name: "tools",
        instance: 3,
        slot: 0,
        chain: 1,
        deadline: std::time::Instant::now() + std::time::Duration::from_secs(30),
        stack: CallStack::default(),
        out_of_process: false,
        limits: InstanceLimits::default(),
    }
}

struct Rig {
    store: Arc<crate::persistence::facade::CoreStore>,
    upstreams: Arc<dyn Upstreams>,
    logins: Arc<dyn ConnectLogins>,
    seen: Arc<Mutex<Seen>>,
}

impl Rig {
    async fn new() -> Self {
        let seen = Arc::new(Mutex::new(Seen::default()));
        let oauth: Arc<dyn AuthPort> = Arc::new(FakeOauth {
            facts: FB_LOGIN_REDIRECT,
            seen: Arc::clone(&seen),
        });
        let header: Arc<dyn AuthPort> = Arc::new(FakeOauth {
            facts: 0,
            seen: Arc::new(Mutex::new(Seen::default())),
        });
        let mut ports = BTreeMap::new();
        ports.insert("oauth-conn", oauth);
        ports.insert("auth-header", header);
        let mut table = BTreeMap::new();
        table.insert(
            "github",
            upstream("github", Some(binding("oauth-conn", Some(CALLBACK)))),
        );
        table.insert(
            "plain",
            upstream("plain", Some(binding("auth-header", None))),
        );
        table.insert(
            "noredirect",
            upstream("noredirect", Some(binding("auth-header", Some("/x/cb")))),
        );
        table.insert("open", upstream("open", None));
        Self {
            store: crate::real_store::core().await,
            upstreams: Arc::new(Table(table)),
            logins: Arc::new(Logins(ports)),
            seen,
        }
    }

    /// One replica's connections over the shared store.
    fn replica(&self) -> StoreConnections<StoreRecords> {
        StoreConnections::new(
            StoreRecords::new(Arc::clone(&self.store)),
            &AT_REST,
            Arc::clone(&self.upstreams),
            Arc::clone(&self.logins),
            PUBLIC,
        )
        .expect("a 32-byte at-rest key")
    }

    fn state_key(&self) -> String {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state_key
            .clone()
            .expect("BEGIN ran")
    }
}

#[tokio::test]
async fn begin_mints_pkce_once_and_the_callback_stores_the_grant() {
    let rig = Rig::new().await;
    let conns = rig.replica();
    let who = plane();
    let url = conns
        .begin(&who, "alice", "github", Some("/done"))
        .await
        .expect("BEGIN answers the authorization URL");
    let state_key = rig.state_key();
    {
        let seen = rig.seen.lock().unwrap_or_else(|e| e.into_inner());
        let challenge = seen.challenge.clone().expect("L_CODE_CHALLENGE");
        assert!(url.contains(&format!("code_challenge={challenge}")));
        assert_eq!(
            seen.redirect_uri.as_deref(),
            Some("https://busbar.example/connect/cb")
        );
        assert_eq!(seen.connect.as_deref(), Some("github"));
        assert_eq!(challenge.len(), 43, "S256 of a 32-byte verifier, base64url");
    }
    assert_eq!(conns.status(&who, "alice", "github").await, CONN_NONE);

    let answer = conns
        .callback(CALLBACK, &format!("code=abc&state={state_key}"))
        .await;
    assert_eq!(
        answer,
        CallbackAnswer::Connected {
            location: "/done".into()
        }
    );
    {
        let seen = rig.seen.lock().unwrap_or_else(|e| e.into_inner());
        let verifier = seen.verifier.clone().expect("L_CODE_VERIFIER");
        assert_eq!(
            pkce::code_challenge_s256(&verifier),
            seen.challenge.clone().unwrap_or_default(),
            "COMPLETE's verifier is the one BEGIN's challenge was minted from"
        );
        assert_eq!(
            seen.complete_nonce, seen.begin_nonce,
            "one nonce, BEGIN to COMPLETE"
        );
        assert_eq!(
            seen.complete_state.as_deref(),
            Some(b"issuer=as.example".as_slice()),
            "COMPLETE gets the plugin's own STATE back"
        );
    }
    assert_eq!(conns.status(&who, "alice", "github").await, CONN_READY);
    assert_eq!(
        conns.grant(&who, "alice", "github").await.as_deref(),
        Some(b"refresh-token-1".as_slice())
    );
    assert_eq!(
        conns.status(&who, "bob", "github").await,
        CONN_NONE,
        "a grant is the caller's own"
    );
    assert_eq!(
        conns
            .callback(CALLBACK, &format!("code=abc&state={state_key}"))
            .await,
        CallbackAnswer::SecurityCheck,
        "a login state is redeemed once"
    );
}

#[tokio::test]
async fn a_foreign_path_an_unknown_state_and_an_iss_mismatch_store_nothing() {
    let rig = Rig::new().await;
    let conns = rig.replica();
    let who = plane();
    conns
        .begin(&who, "alice", "github", None)
        .await
        .expect("BEGIN");
    let state_key = rig.state_key();
    assert_eq!(
        conns
            .callback("/other/cb", &format!("state={state_key}"))
            .await,
        CallbackAnswer::SecurityCheck
    );
    assert_eq!(
        conns.callback(CALLBACK, "state=never-minted").await,
        CallbackAnswer::SecurityCheck
    );
    assert_eq!(
        conns.callback(CALLBACK, "code=abc").await,
        CallbackAnswer::SecurityCheck
    );

    conns
        .begin(&who, "alice", "github", None)
        .await
        .expect("BEGIN");
    let state_key = rig.state_key();
    assert_eq!(
        conns
            .callback(CALLBACK, &format!("code=abc&iss=evil&state={state_key}"))
            .await,
        CallbackAnswer::SecurityCheck,
        "the plugin's SECURITY_CHECK is the security-check page"
    );
    assert_eq!(conns.status(&who, "alice", "github").await, CONN_NONE);
}

#[tokio::test]
async fn an_upstream_without_a_redirect_connection_refuses_begin_and_answers_none() {
    let rig = Rig::new().await;
    let conns = rig.replica();
    let who = plane();
    for name in ["plain", "noredirect", "open", "unconfigured"] {
        assert_eq!(
            conns.begin(&who, "alice", name, None).await,
            Err(RecordsDenied::Invalid),
            "{name}"
        );
        assert_eq!(conns.status(&who, "alice", name).await, CONN_NONE, "{name}");
        assert_eq!(
            conns.revoke(&who, "alice", name).await,
            Err(RecordsDenied::Invalid),
            "{name}"
        );
    }
}

#[tokio::test]
async fn return_to_is_same_origin_only() {
    let rig = Rig::new().await;
    let conns = rig.replica();
    let who = plane();
    for evil in [
        "https://evil.example/",
        "//evil.example",
        "/\\evil",
        "javascript:x",
    ] {
        assert_eq!(
            conns.begin(&who, "alice", "github", Some(evil)).await,
            Err(RecordsDenied::Invalid),
            "{evil}"
        );
    }
    assert!(conns
        .begin(&who, "alice", "github", Some("https://busbar.example/ui"))
        .await
        .is_ok());
}

async fn connected(rig: &Rig, conns: &StoreConnections<StoreRecords>, subject: &str) {
    let who = plane();
    conns
        .begin(&who, subject, "github", None)
        .await
        .expect("BEGIN");
    let state_key = rig.state_key();
    assert_eq!(
        conns
            .callback(CALLBACK, &format!("code=abc&state={state_key}"))
            .await,
        CallbackAnswer::Connected {
            location: "/".into()
        }
    );
}

#[tokio::test]
async fn the_grant_survives_a_restart_and_is_read_by_a_second_replica() {
    let rig = Rig::new().await;
    connected(&rig, &rig.replica(), "alice").await;
    let restarted = rig.replica();
    let who = plane();
    assert_eq!(restarted.status(&who, "alice", "github").await, CONN_READY);
    assert_eq!(
        restarted.grant(&who, "alice", "github").await.as_deref(),
        Some(b"refresh-token-1".as_slice())
    );
    let other_instance = Caller {
        name: "other",
        ..plane()
    };
    assert_eq!(
        restarted.status(&other_instance, "alice", "github").await,
        CONN_NONE,
        "grants are keyed by the plane instance name"
    );
    let wrong_key = StoreConnections::new(
        StoreRecords::new(Arc::clone(&rig.store)),
        &[1u8; 32],
        Arc::clone(&rig.upstreams),
        Arc::clone(&rig.logins),
        PUBLIC,
    )
    .expect("a key");
    assert!(
        wrong_key.grant(&who, "alice", "github").await.is_none(),
        "a grant opens only under core's at-rest key"
    );
}

#[tokio::test]
async fn revoke_and_a_connect_required_refusal_delete_the_grant_and_an_update_replaces_it() {
    let rig = Rig::new().await;
    let conns = rig.replica();
    let who = plane();
    connected(&rig, &conns, "alice").await;

    let updated: Result<OutboundAnswer, PortError> = Ok(OutboundAnswer {
        headers: Vec::new(),
        query: Vec::new(),
        cache_s: 60,
        grant_update: Some(SecureVec::from(b"refresh-token-2".as_slice())),
    });
    settle_outbound(&conns, &who, "alice", "github", true, &updated)
        .await
        .expect("GRANT_UPDATE stored");
    assert_eq!(
        conns.grant(&who, "alice", "github").await.as_deref(),
        Some(b"refresh-token-2".as_slice())
    );

    let other: Result<OutboundAnswer, PortError> = Err(refused(R_UNSUPPORTED));
    settle_outbound(&conns, &who, "alice", "github", true, &other)
        .await
        .expect("nothing to do");
    assert_eq!(conns.status(&who, "alice", "github").await, CONN_READY);

    let revoked: Result<OutboundAnswer, PortError> = Err(refused(R_CONNECT_REQUIRED));
    settle_outbound(&conns, &who, "alice", "github", false, &revoked)
        .await
        .expect("no grant passed: nothing deleted");
    assert_eq!(conns.status(&who, "alice", "github").await, CONN_READY);
    settle_outbound(&conns, &who, "alice", "github", true, &revoked)
        .await
        .expect("the revoked grant is deleted");
    assert_eq!(conns.status(&who, "alice", "github").await, CONN_NONE);

    connected(&rig, &conns, "alice").await;
    conns.revoke(&who, "alice", "github").await.expect("REVOKE");
    assert_eq!(conns.status(&who, "alice", "github").await, CONN_NONE);
    assert!(conns.grant(&who, "alice", "github").await.is_none());
}

#[test]
fn the_callback_answer_is_cores_own_page() {
    use axum::http::{header, StatusCode};
    let r = CallbackAnswer::Connected {
        location: "/done".into(),
    }
    .into_response();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    assert_eq!(r.headers()[header::LOCATION], "/done");
    assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        CallbackAnswer::SecurityCheck.into_response().status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        CallbackAnswer::Failed.into_response().status(),
        StatusCode::BAD_GATEWAY
    );
}

#[test]
fn pkce_challenge_is_s256_of_the_verifier() {
    let verifier = pkce::random_b64url(pkce::VERIFIER_BYTES).expect("randomness");
    assert_eq!(verifier.len(), 43);
    let challenge = pkce::code_challenge_s256(&verifier);
    use base64::Engine as _;
    let expected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(busbar_contract::crypto::sha256(verifier.as_bytes()));
    assert_eq!(challenge, expected);
    // RFC 7636 appendix B.
    assert_eq!(
        pkce::code_challenge_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
}
