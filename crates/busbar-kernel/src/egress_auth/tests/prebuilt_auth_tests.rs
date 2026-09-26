// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PREBUILT-AUTH DIFFERENTIAL PROOF. `Lane::prebuilt_auth` is a boot-time freeze of
//! `headers_for` under `Own` mode, taken only when the credential says `is_lane_constant()`. The
//! claim that makes the freeze sound is CONTEXT-INDEPENDENCE: for such a credential, `headers_for`
//! must return the same bytes no matter what body/timestamp/path the `SigningContext` carries.
//!
//! The suite walks EVERY protocol declaration the registry holds that declares its own egress
//! builder, and judges each one by what its builder DOES rather than by its name: a builder whose
//! headers stay the same under two deliberately different contexts must be lane-constant and
//! prebuild to exactly those bytes; a builder whose headers move with the context (a request
//! signer) must refuse the freeze. A declaration claiming `egress_auth_lane_constant` for a signer
//! would replay one signature on every request — the second arm catches exactly that lie.

use crate::egress_auth::{prebuild_auth, resolve};
use crate::proto::{convert_headers, SigningContext};
use busbar_substrate_values::proto::ProtocolDecl;

/// A credential every declared builder can use: a request signer reads `<id>:<secret>`, a static
/// scheme presents the whole string.
const KEY: &str = "test-id:test-secret";
const HOST: &str = "h.example.com";

fn ctx<'a>(body: &'a [u8], ts: u64, canonical: &'a str) -> SigningContext<'a> {
    SigningContext {
        host: HOST,
        canonical_uri: canonical,
        body,
        timestamp_epoch: ts,
        upstream_creds: busbar_api::UpstreamCreds::Own,
    }
}

/// Every declaration in the core-test registry that declares its own egress builder. `builtin_decls`
/// is the list `crate::proto::registry()` seeds the substrate registry with, and each name is
/// resolved back THROUGH `resolve` (and so through that registry) below — without the seed every
/// scheme would collapse to `NoCredential` and both arms would compare nothing against itself.
fn declared_builders() -> Vec<&'static ProtocolDecl> {
    let _ = crate::proto::registry();
    crate::proto::registry::builtin_decls()
        .iter()
        .copied()
        .filter(|d| d.egress_auth_headers.is_some())
        .collect()
}

/// Headers under an empty context and under a maximally different one.
fn live_pair(
    cred: &std::sync::Arc<dyn crate::egress_auth::CredentialProvider>,
) -> (http::header::HeaderMap, http::header::HeaderMap) {
    let a = convert_headers(cred.headers_for(KEY, &ctx(b"", 0, "")));
    let b = convert_headers(cred.headers_for(
        KEY,
        &ctx(
            br#"{"messages":[{"role":"user","content":"x"}]}"#,
            1_756_000_000,
            "/v1/x",
        ),
    ));
    (a, b)
}

/// Every lane-constant scheme: prebuilt == live under two maximally different contexts; every
/// context-reading scheme (a signer) is not lane-constant and never prebuilds.
#[test]
fn prebuilt_equals_live_for_every_lane_constant_scheme_and_signers_never_prebuild() {
    let decls = declared_builders();
    let (mut constant, mut signers) = (0usize, 0usize);
    for decl in &decls {
        let proto = decl.name;
        let cred = resolve(proto, None);
        let (live_a, live_b) = live_pair(&cred);
        assert!(
            !live_a.is_empty(),
            "{proto}: the declared builder emitted no header for a well-formed key — the proof \
             below would compare nothing"
        );
        if live_a == live_b {
            constant += 1;
            assert!(
                cred.is_lane_constant(),
                "{proto}: headers_for is context-independent, so the credential should be lane-constant"
            );
            let pre = prebuild_auth(&cred, KEY, HOST).expect("lane-constant credential prebuilds");
            assert_eq!(pre, live_a, "{proto}: prebuilt != live (empty ctx)");
            assert_eq!(
                pre, live_b,
                "{proto}: prebuilt != live (varied ctx) — headers_for read the \
                 context; this credential must NOT declare is_lane_constant"
            );
        } else {
            signers += 1;
            assert!(
                !cred.is_lane_constant(),
                "{proto}: headers_for reads the request (a signer); freezing it at boot would \
                 replay one signature on every request"
            );
            assert!(
                prebuild_auth(&cred, KEY, HOST).is_none(),
                "{proto}: a signer must never prebuild"
            );
        }
    }
    // Both arms must have run, or the suite proved one half of the claim over nothing.
    assert!(
        constant >= 1 && signers >= 1,
        "the registry's declared builders split {constant} lane-constant / {signers} signing — \
         both arms need at least one scheme ({} declared)",
        decls.len()
    );
}

/// The operator's `auth: api_key` override is a static header scheme for EVERY protocol: it
/// prebuilds to the live bytes whatever the protocol's own builder is.
#[test]
fn api_key_override_prebuilds_for_every_protocol() {
    let decls = declared_builders();
    assert!(
        !decls.is_empty(),
        "no declared egress builder in the registry"
    );
    for decl in decls {
        let proto = decl.name;
        let cred = resolve(proto, Some(crate::config::ProviderAuth::ApiKey));
        assert!(
            cred.is_lane_constant(),
            "{proto} (ApiKey) should be lane-constant"
        );
        let (live_a, live_b) = live_pair(&cred);
        let pre = prebuild_auth(&cred, KEY, HOST).expect("lane-constant credential prebuilds");
        assert_eq!(
            pre, live_a,
            "{proto} (ApiKey): prebuilt != live (empty ctx)"
        );
        assert_eq!(
            pre, live_b,
            "{proto} (ApiKey): prebuilt != live (varied ctx)"
        );
    }
}

/// The operator's `auth: api-key` override is a DECLARED static header scheme presented by the
/// egress-auth unit under the teller's `Grant<Sign>` (#83a SD-2b): for every key a config system can
/// hand it, in either credential mode, it writes exactly the bytes the shared header builder wrote,
/// and a key that is not a legal header value still sends no header at all.
#[test]
fn the_api_key_override_presents_the_shared_builders_bytes() {
    const KEYS: &[&str] = &[
        "sk-test-123",
        "",
        " leading",
        "sk\tkey",
        "klucz-\u{142}-\u{e9}",
        "sk\r\ninjected",
        "sk\u{0}key",
        "sk\u{7f}key",
    ];
    let cred = resolve("any-protocol", Some(crate::config::ProviderAuth::ApiKey));
    for &key in KEYS {
        for upstream_creds in [
            busbar_api::UpstreamCreds::Own,
            busbar_api::UpstreamCreds::Passthrough,
        ] {
            let c = SigningContext {
                upstream_creds,
                ..ctx(b"{}", 1_756_000_000, "/v1/x")
            };
            assert_eq!(
                cred.headers_for(key, &c),
                busbar_substrate_values::proto::api_key_auth_headers("api-key", key),
                "key {key:?}, mode {upstream_creds:?}"
            );
        }
    }
}
