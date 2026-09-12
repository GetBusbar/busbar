// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/egress_auth/oauth_client_credentials.rs`.

use super::*;

/// The default (no operator carve-out) SSRF posture used by most tests.
fn deny() -> super::super::MetadataSsrfPolicy<'static> {
    super::super::MetadataSsrfPolicy {
        allow_overrides: &[],
        allow_all: false,
        blocked_hosts: &[],
    }
}

/// THE SEATED JUDGES these tests hand in. The mechanism no longer holds a predicate about an
/// address: it is given a verdict and renders it, so what is proven here is the handing-over and
/// the wording, and the predicate itself is proven where it now lives (the egress-auth unit's
/// `token_endpoint` suite).
fn admit(
    _url: &str,
    _ssrf: &super::super::MetadataSsrfPolicy<'_>,
) -> super::super::TokenEndpointVerdict {
    super::super::TokenEndpointVerdict::Admitted
}

/// A seat that refuses on the scheme.
fn refuse_scheme(
    _url: &str,
    _ssrf: &super::super::MetadataSsrfPolicy<'_>,
) -> super::super::TokenEndpointVerdict {
    super::super::TokenEndpointVerdict::InsecureScheme
}

/// A seat that refuses a blocked cloud-metadata host, naming the host it blocked.
fn refuse_metadata(
    _url: &str,
    _ssrf: &super::super::MetadataSsrfPolicy<'_>,
) -> super::super::TokenEndpointVerdict {
    super::super::TokenEndpointVerdict::BlockedMetadataHost {
        host: "169.254.169.254".to_string(),
    }
}

/// A seat that ANSWERS WITH THE POSTURE IT WAS HANDED. The bug this seam closed was a mechanism
/// judging under a posture that was not the operator's (jwt-bearer ignored the deployment-global
/// stance entirely, so a token endpoint an operator had allow-listed passed `--validate` and died
/// at boot). The posture crossing the seam intact is therefore a property worth a case of its own,
/// and this is the only way to see it from this side.
fn echo_posture(
    _url: &str,
    ssrf: &super::super::MetadataSsrfPolicy<'_>,
) -> super::super::TokenEndpointVerdict {
    super::super::TokenEndpointVerdict::BlockedMetadataHost {
        host: format!(
            "allow={:?} all={} block={:?}",
            ssrf.allow_overrides, ssrf.allow_all, ssrf.blocked_hosts
        ),
    }
}

/// The resolved `client_secret` NEVER appears in this struct's `Debug` (it is held
/// `Redacted`). A `{:?}` of the exchange material must show `[REDACTED]`, not the secret.
#[test]
fn client_secret_is_redacted_in_debug() {
    let creds = ClientCreds {
        client_id: "id".to_string(),
        client_secret: busbar_api::Redacted::new("super-secret-value".to_string()),
        token_url: "https://t".to_string(),
        scope: "s".to_string(),
        http: super::super::minter_client().unwrap(),
    };
    let dbg = format!("{creds:?}");
    assert!(
        !dbg.contains("super-secret-value"),
        "client_secret must not appear in Debug: {dbg}"
    );
    assert!(
        dbg.contains("[REDACTED]"),
        "expected redaction marker: {dbg}"
    );
}

#[test]
fn build_rejects_a_credential_without_a_colon() {
    assert!(build("no-colon-here", "https://t", "s", &deny(), admit).is_err());
    assert!(build(":secret-only", "https://t", "s", &deny(), admit).is_err());
    assert!(build("id-only:", "https://t", "s", &deny(), admit).is_err());
}

// `validate_credential` is the standalone `--validate` dry-run entry point (unlike `build`, it
// never constructs a provider or touches the network) - it must apply the SAME parse checks as
// `build`'s `split_credential` call, not just always succeed.
#[test]
fn validate_credential_rejects_malformed_and_accepts_well_formed() {
    assert!(validate_credential("no-colon-here").is_err());
    assert!(validate_credential(":secret-only").is_err());
    assert!(validate_credential("id-only:").is_err());
    assert!(validate_credential("id:secret").is_ok());
}

// build() puts the token_url past the seated judge as defense-in-depth (parity with jwt-bearer)
// and REFUSES WITH THIS MECHANISM'S OWN WORDS: the field the operator wrote (`token_url`) and the
// material at risk (the client_id/client_secret). A well-formed credential does not save it; an
// admitted endpoint builds.
#[test]
fn build_refuses_the_token_url_the_seat_refuses_in_its_own_words() {
    let e = build(
        "id:secret",
        "http://login.example.com/token",
        "s",
        &deny(),
        refuse_scheme,
    )
    .err()
    .expect("an insecure-scheme verdict must refuse the build");
    assert_eq!(
        e,
        "oauth-client-credentials token_url must use https for a public host (got \
         'http://login.example.com/token'); it receives the client_id/client_secret, so plaintext \
         http is permitted only for a private/loopback endpoint"
    );
    let e = build(
        "id:secret",
        "https://169.254.169.254/token",
        "s",
        &deny(),
        refuse_metadata,
    )
    .err()
    .expect("a blocked-metadata verdict must refuse the build");
    assert!(
        e.starts_with(
            "oauth-client-credentials token_url 'https://169.254.169.254/token' targets a blocked \
             cloud-metadata host '169.254.169.254' (the client credentials would be POSTed there"
        ),
        "got: {e}"
    );
    assert!(build(
        "id:secret",
        "http://127.0.0.1:8080/token",
        "s",
        &deny(),
        admit
    )
    .is_ok());
}

// The boot-time token_url check MUST be made under the operator's REAL posture — the same one
// config_validate passes — else a config that allow-lists a metadata host as its token endpoint
// passes `--validate` and dies at boot (validate != apply). The posture is no longer read here, so
// what this proves is that all three fields cross the seam to the seat unaltered.
#[test]
fn build_hands_the_operators_real_posture_to_the_seat() {
    let allowed = ["169.254.169.254".to_string()];
    let extra_block = ["evil.example.com".to_string()];
    let posture = super::super::MetadataSsrfPolicy {
        allow_overrides: &allowed,
        allow_all: true,
        blocked_hosts: &extra_block,
    };
    let e = build(
        "id:secret",
        "https://169.254.169.254/token",
        "s",
        &posture,
        echo_posture,
    )
    .err()
    .expect("the echo seat always refuses, so the posture it saw is readable");
    assert!(
        e.contains(r#"allow=["169.254.169.254"] all=true block=["evil.example.com"]"#),
        "the seat did not receive the operator's posture; got: {e}"
    );
}

#[test]
fn build_accepts_a_secret_containing_a_colon() {
    // Only the FIRST colon splits id:secret, so a secret with colons is preserved. Constructed
    // outside a runtime, so no mint is spawned — this just checks the credential parse.
    assert!(build(
        "client-abc:secret:with:colons",
        "https://t",
        "s",
        &deny(),
        admit
    )
    .is_ok());
}

// `expires_in` must tolerate a JSON number, a numeric string (ADFS /
// Azure AD v1), and absence (defaulting to 1 h) — a strict u64 breaks minting for those IdPs.
#[test]
fn token_response_tolerates_expires_in_as_number_string_or_absent() {
    let num: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":3600}"#).unwrap();
    assert_eq!(num.expires_in, 3600);
    let s: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":"7200"}"#).unwrap();
    assert_eq!(s.expires_in, 7200);
    let absent: TokenResponse = serde_json::from_str(r#"{"access_token":"a"}"#).unwrap();
    assert_eq!(absent.expires_in, super::super::default_expires_in());
    // Also tolerate a JSON float and a decimal string (truncated toward zero).
    let float: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":3600.0}"#).unwrap();
    assert_eq!(float.expires_in, 3600);
    let decimal_str: TokenResponse =
        serde_json::from_str(r#"{"access_token":"a","expires_in":"3600.9"}"#).unwrap();
    assert_eq!(decimal_str.expires_in, 3600);
}

/// The token endpoint is an untrusted network peer (its `expires_in` is already treated as
/// attacker-influenced above), so `mint()` must read the response body under a size cap rather
/// than `resp.text()`'s unbounded read: a hijacked/misbehaving token endpoint returning a body
/// past the `upstream_error_body_max_bytes()` cap must surface a clear error, never silently
/// buffer the whole thing or attempt a partial JSON parse of a truncated fragment.
#[tokio::test]
async fn mint_rejects_a_response_body_over_the_cap() {
    // A single oversized field pushes the serialized body past the 256 KiB default cap; the
    // fixture only needs to be a legal JSON document once — truncated is irrelevant, since the
    // cap must trip and short-circuit BEFORE any JSON parsing happens. Served on a real loopback
    // socket through substrate's own egress fixture (busbar-core's `MockServer` is unreachable
    // from here).
    let oversized_token = "a".repeat(300 * 1024);
    let body =
        serde_json::json!({ "access_token": oversized_token, "expires_in": 3600 }).to_string();
    let server =
        crate::egress::fixtures::spawn_http(crate::egress::fixtures::CannedResponse::ok(&body), 1);

    let creds = ClientCreds {
        client_id: "id".to_string(),
        client_secret: busbar_api::Redacted::new("secret".to_string()),
        token_url: format!("http://{}", server.addr),
        scope: "s".to_string(),
        http: super::super::minter_client().unwrap(),
    };
    let result = creds.mint().await;

    let err = match result {
        Ok(_) => {
            panic!("an over-cap token response must be a clear error, not a buffered success")
        }
        Err(e) => e,
    };
    assert!(
        err.contains("cap") || err.contains("truncat"),
        "expected an error naming the size cap / truncation, got: {err}"
    );
}
