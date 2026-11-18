// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-MCP-CONNECT (ABI-MIN3-INTERFACE §14): Caller connections: CONNECT BEGIN/COMPLETE, refresh, revoke (§12.12;
//! K10 core arms). The auth-oauth and plane-mcp image arms are on #217.
//!
//! W1-K10's core arms, over the kernel's `StoreConnections` and a fake authorization server behind an
//! `oauth-connection`-style auth instance: BEGIN's URL carries S256 of the verifier core kept; the callback on the
//! configured `redirect_uri` path runs COMPLETE with that verifier and stores the GRANT (STATUS CONN_READY); a
//! GRANT_UPDATE replaces it; `invalid_grant` (R_CONNECT_REQUIRED) deletes it (CONN_NONE); REVOKE deletes it; an
//! `iss` mismatch is the security-check page; the grant survives a restart and is read by a second replica.

use busbar_contract::secure::SecureVec;
use busbar_kernel::connections::{pkce, settle_outbound, CallbackAnswer};
use busbar_plugin_abi::fail::refused::R_CONNECT_REQUIRED;
use busbar_plugin_abi::plane::{CONN_NONE, CONN_READY};
use busbar_ports::auth::OutboundAnswer;
use busbar_ports::PortError;

use crate::k10_rig::{
    connect, plane, runtime, Deployment, CALLBACK, CONNECTED, GRANT, PUBLIC, SUBJECT,
};

#[test]
fn connect_core_arms() {
    let rt = runtime();
    let deployment = rt.block_on(Deployment::new());
    let conns = deployment.connections();
    let who = plane();

    // BEGIN / COMPLETE: one challenge, one verifier, one nonce, all core's.
    assert_eq!(
        connect(&rt, &deployment, &conns, "&iss=https://as.example"),
        CallbackAnswer::Connected {
            location: "/".into()
        }
    );
    let seen = deployment.seen();
    let challenge = seen.challenge.clone().expect("L_CODE_CHALLENGE");
    let verifier = seen.verifier.clone().expect("L_CODE_VERIFIER");
    assert_eq!(pkce::code_challenge_s256(&verifier), challenge);
    assert_eq!(seen.begin_nonce, seen.complete_nonce);
    assert_eq!(
        seen.redirect_uri.as_deref(),
        Some(format!("{PUBLIC}{CALLBACK}").as_str()),
        "the configured redirect_uri"
    );
    assert_eq!(
        rt.block_on(conns.status(&who, SUBJECT, CONNECTED)),
        CONN_READY
    );
    assert_eq!(
        rt.block_on(conns.grant(&who, SUBJECT, CONNECTED))
            .as_deref(),
        Some(GRANT),
        "the GRANT COMPLETE answered is what core keeps"
    );

    // Refresh: a GRANT_UPDATE is stored.
    let refreshed: Result<OutboundAnswer, PortError> = Ok(OutboundAnswer {
        headers: Vec::new(),
        query: Vec::new(),
        cache_s: 3_600,
        grant_update: Some(SecureVec::from(b"gho_refresh-token-2".as_slice())),
    });
    rt.block_on(settle_outbound(
        &conns, &who, SUBJECT, CONNECTED, true, &refreshed,
    ))
    .expect("GRANT_UPDATE stored");
    assert_eq!(
        rt.block_on(conns.grant(&who, SUBJECT, CONNECTED))
            .as_deref(),
        Some(b"gho_refresh-token-2".as_slice())
    );

    // A second replica, and a restart, read the same grant.
    let replica = deployment.connections();
    assert_eq!(
        rt.block_on(replica.status(&who, SUBJECT, CONNECTED)),
        CONN_READY
    );

    // `invalid_grant`: the refresh is refused R_CONNECT_REQUIRED and the grant is deleted.
    let revoked: Result<OutboundAnswer, PortError> = Err(PortError::Refused {
        code: R_CONNECT_REQUIRED,
        text: "invalid_grant".into(),
        error: None,
    });
    rt.block_on(settle_outbound(
        &replica, &who, SUBJECT, CONNECTED, true, &revoked,
    ))
    .expect("the grant is deleted");
    assert_eq!(
        rt.block_on(conns.status(&who, SUBJECT, CONNECTED)),
        CONN_NONE
    );

    // REVOKE deletes the grant.
    assert_eq!(
        connect(&rt, &deployment, &conns, "&iss=https://as.example"),
        CallbackAnswer::Connected {
            location: "/".into()
        }
    );
    rt.block_on(conns.revoke(&who, SUBJECT, CONNECTED))
        .expect("REVOKE");
    assert_eq!(
        rt.block_on(conns.status(&who, SUBJECT, CONNECTED)),
        CONN_NONE
    );

    // An `iss` mismatch on the callback is the security-check page and stores nothing.
    assert_eq!(
        connect(&rt, &deployment, &conns, "&iss=https://evil.example"),
        CallbackAnswer::SecurityCheck
    );
    assert_eq!(
        rt.block_on(conns.status(&who, SUBJECT, CONNECTED)),
        CONN_NONE
    );
    assert!(rt.block_on(conns.grant(&who, SUBJECT, CONNECTED)).is_none());
}
