// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SESSION-SCOPE AUTHORIZATION GATE — the plane's declared `session` scope kind, enforced.
//!
//! The plane declares one scope kind (`PLANE_DECL.scope_kinds`), which is the vocabulary an
//! `allowed_scopes: [{ kind: session, value: … }]` entry validates against. Holding a key that is
//! valid for this plane's AUDIENCE is not the same as being GRANTED a session on it — the audience
//! check answers "is this token for this door", the grant answers "may this caller walk through it",
//! exactly as MCP double-gates a tool and A2A gates an agent.
//!
//! The refusal lands FIRST: before the operator's hook gate fires, before a metering lease is
//! reserved, before a durable session row exists, and before any provider is dialed. So a caller
//! without the grant costs zero bytes and zero charge.
//!
//! RED before the wiring: any key valid for the voice audience opened a session, and the declared
//! scope kind was vocabulary nothing consulted.

use crate::mount::{open_governed, session_scope_allowed, GovernedOpen, Ingress};
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::testkit::fixture_host::FixtureHost;
use std::sync::Arc;

/// The pool a voice session is served on — the value the `session` grant names.
const VOICE_POOL: &str = "voice-server";

/// A key carrying an EXPLICIT scope list. An explicit list is exhaustive across kinds: whatever is
/// not in it is not granted.
fn key_scoped(id: &str, scopes: Vec<busbar_api::ScopeRef>) -> busbar_api::VirtualKey {
    busbar_api::VirtualKey {
        id: id.to_string(),
        name: id.to_string(),
        allowed_scopes: Some(scopes),
        ..Default::default()
    }
}

fn session_scope(value: &str) -> busbar_api::ScopeRef {
    busbar_api::ScopeRef {
        kind: "session".to_string(),
        value: value.to_string(),
    }
}

fn runtime() -> VoiceRuntime {
    VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
}

async fn open_as(key: Option<busbar_api::VirtualKey>) -> axum::http::StatusCode {
    let rt = runtime();
    open_governed(GovernedOpen {
        rt: &rt,
        host: FixtureHost::new().into_host(),
        provider: None,
        ingress: Ingress::Mint,
        owner: "acct-scope".to_string(),
        call_id: "call-scope".to_string(),
        vkey: key,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 11,
    })
    .await
    .status()
}

#[test]
fn the_grant_is_read_off_the_keys_own_scope_list() {
    // A wildcard principal (no scope list at all) is granted every kind — the store's own semantic,
    // and the most common key shape in a small deployment.
    let wildcard = busbar_api::VirtualKey {
        id: "vk-wildcard".to_string(),
        ..Default::default()
    };
    assert!(
        session_scope_allowed(&wildcard),
        "a key with no scope list is granted every kind, voice included"
    );

    // An explicit list that names the session scope on the voice pool grants it.
    assert!(
        session_scope_allowed(&key_scoped("vk-granted", vec![session_scope(VOICE_POOL)])),
        "an explicit session grant on the voice pool admits"
    );

    // An explicit list WITHOUT it does not — including one that carries pool scopes (a model-plane
    // key) or a session scope for some other pool.
    assert!(
        !session_scope_allowed(&key_scoped(
            "vk-pool-only",
            vec![busbar_api::ScopeRef::pool("fast")]
        )),
        "a model-plane key is not thereby granted a voice session"
    );
    assert!(
        !session_scope_allowed(&key_scoped(
            "vk-other-pool",
            vec![session_scope("some-other-pool")]
        )),
        "a session grant for another pool does not reach the voice pool"
    );
    assert!(
        !session_scope_allowed(&key_scoped("vk-empty", Vec::new())),
        "an empty explicit list grants nothing"
    );
}

#[tokio::test]
async fn a_key_without_session_scope_is_refused_at_the_door() {
    let refused = open_as(Some(key_scoped(
        "vk-no-session",
        vec![busbar_api::ScopeRef::pool("fast")],
    )))
    .await;
    assert_eq!(
        refused,
        axum::http::StatusCode::FORBIDDEN,
        "a key holding no session scope is refused with the plane's own fail-closed answer"
    );
}

#[tokio::test]
async fn a_granted_key_and_an_ungoverned_caller_still_open() {
    // The granted key proceeds past the gate into the governed open (which, with no provider
    // composed here, reports that there is nothing to dial) — the point is that it got there.
    let granted = open_as(Some(key_scoped(
        "vk-granted",
        vec![session_scope(VOICE_POOL)],
    )))
    .await;
    assert_eq!(
        granted,
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "a granted key opens the governed session"
    );

    // An ungoverned deployment resolves no key and has no grant to consult, so it is unaffected —
    // this gate narrows governed callers only.
    assert_eq!(
        open_as(None).await,
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "an ungoverned caller is unchanged by the grant check"
    );
}
