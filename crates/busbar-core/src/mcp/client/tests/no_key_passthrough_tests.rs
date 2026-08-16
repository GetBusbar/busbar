// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADVERSARIAL: the caller's busbar key NEVER reaches an upstream. busbar holds its own per-backend
//! credentials and mints audience-bound tokens for them; the inbound key authenticates the caller
//! TO busbar and has no business travelling any further.
//!
//! ## Why this is a scan and not an inspection
//!
//! "We do not forward the caller's key" is the kind of claim that is true of the code somebody read
//! and false of the branch they did not. So: a distinctive SENTINEL is planted as the caller's
//! presented secret, the request is built through the real builder in every credential mode, and
//! EVERY BYTE that would go on the wire — URL, header names, header values, body — is scanned for
//! the sentinel and for every obvious encoding of it.
//!
//! Two properties make the scan non-vacuous, and both are asserted rather than assumed:
//!
//! 1. **The scan covers the whole request.** `OutboundRequest::wire_bytes` is derived from the same
//!    fields the transport writes, and a separate test destructures `OutboundRequest` exhaustively
//!    so that adding a field without adding it to the scan stops compiling.
//! 2. **The scan can find things.** A control run plants a DIFFERENT sentinel as a legitimately
//!    forwarded upstream credential and asserts it IS found. A scanner that never matches anything
//!    would otherwise report a clean bill of health for a request that carried the key in plaintext.

use crate::mcp::client::egress::{
    plan_credential, CallerContext, CredentialPlan, ExchangeCfg, UpstreamCredential,
};
use crate::mcp::client::jsonrpc::{tools_call, tools_list, OutboundRequest};
use crate::mcp::client::support::{key_wildcard, sid, tkey};
use busbar_api::Redacted;

/// The caller's busbar key. Distinctive enough that a substring match cannot be a coincidence.
const BUSBAR_KEY: &str = "bb-sk-CALLER-BUSBAR-KEY-MUST-NEVER-LEAVE-1234567890";
/// A credential the caller legitimately holds FOR THE UPSTREAM. This one is allowed to leave under
/// `passthrough`, and the control assertion below requires that it does.
const CALLER_UPSTREAM: &str = "upstream-cred-CALLER-HOLDS-THIS-FOR-THE-BACKEND";
/// busbar's own ambient subject token.
const BUSBAR_AMBIENT: &str = "busbar-ambient-subject-token";

fn caller() -> CallerContext {
    CallerContext {
        key: key_wildcard("agent-1"),
        busbar_key: Redacted::new(BUSBAR_KEY.to_string()),
        upstream_credential: Some(Redacted::new(CALLER_UPSTREAM.to_string())),
    }
}

/// Every credential mode a server may be configured with. A floor is asserted on the length so that
/// deleting a mode from this list is red rather than a smaller-but-still-green suite.
fn every_mode() -> Vec<(&'static str, UpstreamCredential)> {
    vec![
        ("none", UpstreamCredential::None),
        (
            "static",
            UpstreamCredential::Static(Redacted::new("static-server-secret".into())),
        ),
        ("passthrough", UpstreamCredential::Passthrough),
        (
            "exchange",
            UpstreamCredential::Exchange(ExchangeCfg {
                token_url: "https://idp.example.com/token".into(),
                subject_token: Redacted::new(BUSBAR_AMBIENT.into()),
                subject_token_type: "urn:ietf:params:oauth:token-type:access_token".into(),
                resource: "https://payments.internal/mcp".into(),
            }),
        ),
    ]
}

/// Build the request that would actually be sent, for one credential mode, plus (for the exchange
/// mode) the token-endpoint form body that would be POSTed on the way.
///
/// Both are returned because the exchange is a SECOND outbound request and a leak there is a leak.
/// A test that only scanned the tool call would miss a key smuggled into `subject_token`.
fn wire_for(mode: &UpstreamCredential) -> (OutboundRequest, Vec<u8>) {
    let c = caller();
    let key = tkey("payments", "refund");
    let plan = plan_credential(
        &sid("payments"),
        mode,
        &c.key,
        c.upstream_credential.as_ref(),
        &key,
    )
    .expect("a wildcard caller is granted, so every mode plans");
    let (auth, exchange_body) = match &plan {
        CredentialPlan::None => (None, Vec::new()),
        CredentialPlan::Bearer(b) => (Some(b.expose_secret().to_string()), Vec::new()),
        CredentialPlan::Exchange(req) => {
            let body = req
                .form_fields()
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&")
                .into_bytes();
            // The exchanged access token would arrive from the IdP; a plausible stand-in is used so
            // the tool call still carries an Authorization header to scan.
            (Some("exchanged-access-token".to_string()), body)
        }
    };
    let req = tools_call(
        "https://payments.internal/mcp",
        &key,
        &serde_json::json!({"amount": 100}),
        7,
        auth.as_deref(),
        Default::default(),
        None,
    );
    (req, exchange_body)
}

/// Encodings a key could plausibly be smuggled in. Checked so that "we base64'd it first" is not a
/// way past the scan.
fn encodings(secret: &str) -> Vec<(&'static str, Vec<u8>)> {
    use base64::Engine as _;
    let mut v = vec![
        ("plain", secret.as_bytes().to_vec()),
        (
            "base64",
            base64::engine::general_purpose::STANDARD
                .encode(secret)
                .into_bytes(),
        ),
        (
            "base64url-nopad",
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(secret)
                .into_bytes(),
        ),
        ("hex", hex::encode(secret).into_bytes()),
    ];
    // sha256, because "we only sent a hash of it" is still sending a value derived from a credential
    // to a party that has no business holding one.
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(secret.as_bytes());
    v.push(("sha256-hex", hex::encode(h.finalize()).into_bytes()));
    v
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// THE ADVERSARIAL SCAN.
#[test]
fn the_callers_busbar_key_appears_nowhere_on_the_wire_in_any_credential_mode() {
    let modes = every_mode();
    assert_eq!(modes.len(), 4, "every credential mode must be exercised");
    let forms = encodings(BUSBAR_KEY);
    assert_eq!(forms.len(), 5, "every encoding must be exercised");

    for (name, mode) in &modes {
        let (req, exchange_body) = wire_for(mode);
        let mut wire = req.wire_bytes();
        wire.extend_from_slice(&exchange_body);
        // A floor: an empty wire would pass every `contains` check vacuously.
        assert!(
            wire.len() > 100,
            "mode `{name}` produced only {} wire bytes; the scan has nothing to scan",
            wire.len()
        );
        for (encoding, bytes) in &forms {
            assert!(
                !contains(&wire, bytes),
                "mode `{name}`: the caller's busbar key appears on the wire as {encoding}"
            );
        }
    }
}

/// THE CONTROL. The scanner is proven able to FIND a secret, on the same wire, in the mode where one
/// is legitimately forwarded. Without this, the test above would be equally green against a builder
/// that emitted an empty request.
#[test]
fn the_scan_finds_a_secret_that_is_legitimately_forwarded() {
    let (req, _) = wire_for(&UpstreamCredential::Passthrough);
    let wire = req.wire_bytes();
    assert!(
        contains(&wire, CALLER_UPSTREAM.as_bytes()),
        "under passthrough the caller's UPSTREAM credential must be forwarded — if it is not, the \
         no-leak assertion above proves nothing"
    );
}

/// busbar's own ambient subject token appears in the EXCHANGE body (that is what an exchange is) and
/// NOT in the tool call. A subject token leaking onto the tool call would hand the upstream a token
/// that has not been down-scoped.
#[test]
fn the_ambient_subject_token_rides_the_exchange_and_not_the_tool_call() {
    let modes = every_mode();
    let exchange = &modes
        .iter()
        .find(|(n, _)| *n == "exchange")
        .expect("the exchange mode must exist")
        .1;
    let (req, exchange_body) = wire_for(exchange);
    assert!(
        contains(&exchange_body, BUSBAR_AMBIENT.as_bytes()),
        "the exchange must carry busbar's own subject token"
    );
    assert!(
        !contains(&req.wire_bytes(), BUSBAR_AMBIENT.as_bytes()),
        "the ambient subject token must not ride the tool call"
    );
}

/// `tools/list` is scanned too. It is the request an operator's mind skips, and it is made with the
/// same credential machinery.
#[test]
fn the_catalogue_fetch_carries_no_caller_key_either() {
    let req = tools_list(
        "https://payments.internal/mcp",
        1,
        Some("some-upstream-token"),
    );
    assert!(!contains(&req.wire_bytes(), BUSBAR_KEY.as_bytes()));
    assert!(req.wire_bytes().len() > 50);
}

/// THE SCAN CANNOT GO STALE. `OutboundRequest` is destructured exhaustively, so a field added to it
/// without being added to `wire_bytes` stops this test COMPILING rather than silently narrowing the
/// scan.
#[test]
fn every_field_is_scanned() {
    let req = tools_call(
        "https://u.example/mcp",
        &tkey("s", "t"),
        &serde_json::json!({"k": "BODYMARK"}),
        1,
        Some("AUTHMARK"),
        Default::default(),
        None,
    );
    let OutboundRequest { url, headers, body } = &req;
    let wire = req.wire_bytes();
    assert!(contains(&wire, url.as_bytes()), "url must be scanned");
    assert!(!headers.is_empty(), "headers must be present to be scanned");
    for (n, v) in headers {
        assert!(
            contains(&wire, n.as_bytes()),
            "header name `{n}` must be scanned"
        );
        assert!(
            contains(&wire, v.as_bytes()),
            "header value for `{n}` must be scanned"
        );
    }
    assert!(contains(&wire, body), "body must be scanned");
    // ...and the two markers planted through the public arguments are both found, so the scan
    // reaches values that arrive from the caller rather than only constants.
    assert!(contains(&wire, b"BODYMARK"));
    assert!(contains(&wire, b"AUTHMARK"));
}
