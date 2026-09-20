// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! S6: AN UNRESOLVABLE UPSTREAM SUBJECT TOKEN must not hand the CALLER — who is not the operator —
//! the secret's SOURCE (the env var name / file path `resolve_builtin_string`'s own error names).
//! That detail belongs in the server log, where the operator who can fix it can see it; the caller
//! gets a generic refusal and a pointer to the log.
//!
//! Driven at the same front door every other battery in this directory drives
//! (`crate::mcp::method::dispatch` through `call_as`), because the claim is about what a REAL
//! `tools/call` hands back to a REAL caller — a unit test against `credential_mode` alone would
//! prove the string was built right and say nothing about whether `refuse_setup` renders it
//! verbatim onto the wire.

use super::upstream_support::{
    call_as, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer,
};
use crate::mcp::test_engine::*;
use crate::testkit::TestAppMcpExt;

const CANONICAL: &str = "https://gateway.example.com/mcp";

/// The env var name is distinctive enough that its presence in the response body is unambiguous
/// evidence of a leak, and unlikely enough to appear in unrelated JSON-RPC scaffolding that a false
/// negative from a coincidental substring match is not a real risk.
const UNSET_VAR: &str = "BUSBAR_S6_TEST_SUBJECT_TOKEN_DOES_NOT_EXIST";

#[tokio::test]
async fn an_unresolvable_subject_token_refuses_generically_and_names_no_secret_source() {
    metrics_init();
    std::env::remove_var(UNSET_VAR);
    let peer = Peer::start(Behaviour::Result, "unused-issued-token").await;
    let mut cfg = exchanging_server(&peer, "unused-subject-value");
    // Point the subject token at an env var that is guaranteed unset, so
    // `busbar_api::resolve_builtin_string` fails exactly the way S6 documents.
    cfg.token_exchange.as_mut().unwrap().subject_token = busbar_api::SecretRef::env(UNSET_VAR);
    let app = test_app()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", cfg)
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call_as(
        &app,
        &g,
        "s6-credential-leak-principal",
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;

    assert_eq!(
        status, 403,
        "a credential that cannot resolve is refused before any I/O: {body}"
    );
    let rendered = body.to_string();
    assert!(
        !rendered.contains(UNSET_VAR),
        "the caller-facing refusal must not name the secret's env-var SOURCE: {rendered}"
    );
    assert!(
        !rendered
            .to_ascii_lowercase()
            .contains("environment variable"),
        "nor describe the source class at all: {rendered}"
    );
    assert!(
        rendered.contains("see the server log"),
        "the caller is told where the real reason went: {rendered}"
    );
    assert!(
        peer.mcp_hits() == 0,
        "and the refusal costs no round trip: the credential is minted before any network I/O"
    );
}
