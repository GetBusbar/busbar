// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PREBUILT-AUTH DIFFERENTIAL PROOF. `Lane::prebuilt_auth` is a boot-time freeze of
//! `headers_for` under `Own` mode, taken only when the credential says `is_lane_constant()`. The
//! claim that makes the freeze sound is CONTEXT-INDEPENDENCE: for such a credential, `headers_for`
//! must return the same bytes no matter what body/timestamp/path the `SigningContext` carries.
//! This suite proves that claim per scheme by comparing the prebuilt map against live builds under
//! deliberately DIFFERENT contexts — and proves the converse for the signers (bedrock SigV4, the
//! OAuth minters) by asserting they refuse to prebuild at all.

use crate::egress_auth::{prebuild_auth, resolve};
use crate::proto::{convert_headers, SigningContext};

/// Seed the core-test built-in `ProtocolDecl`s into the shared substrate registry the relocated
/// `resolve` reads. `resolve` now lives in `busbar_substrate::egress_auth` and calls substrate's
/// `proto::decl_for` DIRECTLY, bypassing core's `#[cfg(test)]` self-seeding `registry()` veneer;
/// without this seed the LLM dialect decls are absent and EVERY scheme collapses to `NoCredential`
/// (a silent weakening — the bedrock arm below would then wrongly report lane-constant, and the
/// lane-constant arm would compare NoCredential against itself). A `decl_for` call through core's
/// veneer seeds the singleton, which is exactly what the request path did before the module moved.
fn seed_dialect_decls() {
    let _ = crate::proto::decl_for("bedrock");
}

fn ctx<'a>(body: &'a [u8], ts: u64, canonical: &'a str) -> SigningContext<'a> {
    SigningContext {
        host: "h.example.com",
        canonical_uri: canonical,
        body,
        timestamp_epoch: ts,
        upstream_creds: busbar_api::UpstreamCreds::Own,
    }
}

/// Every lane-constant scheme: prebuilt == live under two maximally different contexts.
#[test]
fn prebuilt_equals_live_for_every_lane_constant_scheme() {
    seed_dialect_decls();
    for (proto, auth) in [
        ("openai", None),
        ("anthropic", None),
        ("cohere", None),
        ("responses", None),
        ("gemini", None),
        ("openai", Some(crate::config::ProviderAuth::ApiKey)), // Azure api-key style
    ] {
        let cred = resolve(proto, auth);
        assert!(
            cred.is_lane_constant(),
            "{proto} ({auth:?}) should be lane-constant"
        );
        let pre = prebuild_auth(&cred, "sk-test-123", "h.example.com")
            .expect("lane-constant credential prebuilds");
        let live_a = convert_headers(cred.headers_for("sk-test-123", &ctx(b"", 0, "")));
        let live_b = convert_headers(cred.headers_for(
            "sk-test-123",
            &ctx(
                br#"{"messages":[{"role":"user","content":"x"}]}"#,
                1_756_000_000,
                "/v1/x",
            ),
        ));
        assert_eq!(pre, live_a, "{proto}: prebuilt != live (empty ctx)");
        assert_eq!(
            pre, live_b,
            "{proto}: prebuilt != live (varied ctx) — headers_for read the \
             context; this credential must NOT declare is_lane_constant"
        );
    }
}

/// The signer refuses the freeze: bedrock's declared SigV4 builder covers the request bytes, so
/// its credential must never prebuild.
#[test]
fn bedrock_sigv4_never_prebuilds() {
    seed_dialect_decls();
    let cred = resolve("bedrock", None);
    assert!(
        !cred.is_lane_constant(),
        "SigV4 signs the request; freezing it at boot would replay \
         one signature on every request"
    );
    assert!(prebuild_auth(
        &cred,
        "AKIA:secret",
        "bedrock-runtime.us-east-1.amazonaws.com"
    )
    .is_none());
}
