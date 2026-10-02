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
    // `busbar_plugin_loader::builtin_secret::resolve_builtin_string` fails exactly the way S6 documents.
    cfg.token_exchange.as_mut().unwrap().subject_token =
        busbar_contract::secret_ref::SecretRef::env(UNSET_VAR);
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

/// S6 (operator half): redacting the CALLER-facing text must not blind the OPERATOR too — a fix
/// that scrubs the secret's source from BOTH surfaces would just move the defect from "the caller
/// can target the secret" to "the operator can't find it either". Driven as a plain synchronous
/// unit test against `SetupRefusal` directly (no HTTP round trip, no `tokio::test` runtime): the
/// claim is about the split between two renderings of the SAME value, which needs no peer or
/// dispatch to observe.
///
/// `Display` is the rendering `refuse_setup` feeds to `diag_debug!`'s `detail = %denied` field —
/// the operator's own server log, never the wire — and must still carry the secret's source
/// exactly as `busbar_plugin_loader::builtin_secret::resolve_builtin_string` names it. `client_message()` is the ONLY
/// rendering that reaches the caller, and must not.
#[test]
fn client_message_redacts_the_source_but_display_still_carries_it_for_the_operator() {
    use crate::mcp::upstream::SetupRefusal;

    // The exact shape `credential_mode` produces (see `upstream.rs`'s `credential_mode`, which
    // wraps `busbar_plugin_loader::builtin_secret::resolve_builtin_string`'s error): a message that NAMES the source.
    let denied = SetupRefusal::Credential(format!(
        "busbar's own subject token for this upstream cannot resolve: secret env:{UNSET_VAR} \
         cannot resolve: environment variable '{UNSET_VAR}' is unset"
    ));

    // OPERATOR surface: `Display` (what `%denied` renders in the log) keeps the source.
    let operator_detail = denied.to_string();
    assert!(
        operator_detail.contains(UNSET_VAR),
        "the operator-facing rendering must keep the secret's source so the operator can act on \
         it: {operator_detail}"
    );

    // CALLER surface: `client_message()` (what reaches the wire) does not.
    let caller_text = denied.client_message();
    assert!(
        !caller_text.contains(UNSET_VAR),
        "the caller-facing rendering must not name the secret's source: {caller_text}"
    );
    assert!(
        caller_text.contains("see the server log"),
        "and must point the caller at where the real detail actually went: {caller_text}"
    );
}
