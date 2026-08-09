// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The discovery half of the resource server: the RFC 9728 metadata document, the `WWW-Authenticate`
//! challenge that names it, and the configuration validation that keeps the two from ever naming
//! different URLs.

use super::support::*;
use super::{
    ResourceServer, MCP_MOUNT_PATH, PROTECTED_RESOURCE_METADATA_PATH,
    PROTECTED_RESOURCE_METADATA_ROOT_PATH,
};

fn doc(rs: &ResourceServer) -> serde_json::Value {
    serde_json::from_str(rs.metadata()).expect("metadata document is JSON")
}

/// The document is what a client reads to learn where to go and get a token. It must name busbar's
/// own resource identifier and the authorization servers busbar will accept tokens from — those two
/// facts and the way to present the token are the whole contract.
#[test]
fn the_metadata_document_names_the_resource_and_its_authorization_servers() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let d = doc(&rs);
    assert_eq!(d["resource"], serde_json::json!(BUSBAR_RESOURCE));
    assert_eq!(d["authorization_servers"], serde_json::json!([ISSUER]));
    assert_eq!(d["bearer_methods_supported"], serde_json::json!(["header"]));
}

/// The advertised resource identifier must be EXACTLY the audience busbar enforces. If the document
/// advertised one string and the verifier compared another, every compliant client would ask its IdP
/// for a token busbar then refuses — and the operator's only visible symptom would be a 401 loop
/// that looks like a credential problem.
#[test]
fn the_advertised_resource_is_the_audience_that_is_enforced() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let advertised = doc(&rs)["resource"].as_str().expect("string").to_string();
    assert_eq!(advertised, rs.canonical_uri());

    // And a token minted for the advertised value is admitted, which is the property the equality
    // above is a proxy for. Asserting it directly means the two cannot agree on a value that does
    // not actually work.
    let mut claims = good_claims();
    claims["aud"] = serde_json::json!(advertised);
    assert!(rs.admit(&idp.mint(&claims), NOW).is_ok());
}

/// The 401 challenge is the entire discovery mechanism: a client that has never seen busbar learns
/// the metadata URL from it. It must be the RFC 9728 form and it must name the document that is
/// ACTUALLY mounted — the challenge URL's path is asserted against the route constant, not against a
/// second copy of the string.
#[test]
fn the_challenge_names_the_metadata_document_that_is_mounted() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    assert_eq!(
        rs.challenge(),
        format!(
            "Bearer resource_metadata=\"https://busbar.acme.com{PROTECTED_RESOURCE_METADATA_PATH}\""
        )
    );
    assert!(rs
        .metadata_url()
        .ends_with(PROTECTED_RESOURCE_METADATA_PATH));
    // The document path is the well-known prefix plus the resource's own path, which is what a
    // client derives independently. Both derivations must land on the same string.
    assert_eq!(
        rs.metadata_url(),
        format!("https://busbar.acme.com{PROTECTED_RESOURCE_METADATA_ROOT_PATH}{MCP_MOUNT_PATH}")
    );
}

/// The document is served to an entirely unauthenticated caller, so everything in it is public.
/// It therefore carries the three facts a client cannot proceed without and NOTHING else — no tool
/// names, no pool names, no scope inventory, no internal hostnames, no operator contact. This test
/// pins the key set exactly, so a later "helpful" addition has to be a deliberate decision rather
/// than a diff nobody read.
#[test]
fn the_metadata_document_leaks_nothing_beyond_the_facts_a_client_needs() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    let d = doc(&rs);
    let mut keys: Vec<&str> = d
        .as_object()
        .expect("object")
        .keys()
        .map(|k| k.as_str())
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec!["authorization_servers", "bearer_methods_supported", "resource"],
        "the protected-resource metadata document is public; every member added to it is published \
         to unauthenticated callers"
    );
    // And nothing key-shaped ever appears in it: the key set busbar verifies with is the IdP's
    // business to publish, not busbar's.
    let rendered = rs.metadata();
    for forbidden in ["\"keys\"", "kty", "\"n\"", "\"x\"", "private", "secret"] {
        assert!(
            !rendered.contains(forbidden),
            "metadata document must not contain {forbidden}: {rendered}"
        );
    }
}

/// `canonical_uri` is an identifier compared byte-for-byte against a token's audience AND the base
/// the metadata path is derived from. Each rule below closes a way those two uses could disagree, or
/// a way an operator could ship bearer tokens in clear text.
#[test]
fn canonical_uri_validation_refuses_what_would_break_the_derivation() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let jwks = idp.jwks();
    let build = |uri: &str| ResourceServer::build(uri, vec![(ISSUER.to_string(), jwks.clone())]);

    for (uri, why) in [
        ("busbar.acme.com/mcp", "no scheme"),
        ("ftp://busbar.acme.com/mcp", "not http(s)"),
        ("http://busbar.acme.com/mcp", "plain http, not loopback"),
        ("https:///mcp", "no host"),
        ("https://busbar.acme.com/", "path is not the MCP mount"),
        (
            "https://busbar.acme.com/tools/mcp",
            "path is not the MCP mount",
        ),
        ("https://busbar.acme.com/mcp?x=1", "carries a query"),
        ("https://busbar.acme.com/mcp#f", "carries a fragment"),
    ] {
        assert!(
            build(uri).is_err(),
            "mcp.canonical_uri {uri:?} must be refused at boot ({why})"
        );
    }

    // Loopback http IS accepted, so the whole flow can be run locally without a certificate.
    assert!(build("http://127.0.0.1:8080/mcp").is_ok());
    assert!(build("https://busbar.acme.com/mcp").is_ok());
}

/// A resource server that came up with an unusable configuration would answer 401 to every
/// legitimate caller, which looks exactly like an attack and is exactly not one. Each of these is a
/// BOOT failure with a named cause instead.
#[test]
fn an_unusable_authorization_server_configuration_refuses_to_build() {
    // No issuer at all: there is nowhere to send a caller for a token.
    assert!(ResourceServer::build(BUSBAR_RESOURCE, vec![]).is_err());

    // An empty or non-https issuer would be published verbatim in a public document.
    let idp = TestIdp::ec(ISSUER, "k1");
    assert!(ResourceServer::build(BUSBAR_RESOURCE, vec![(String::new(), idp.jwks())]).is_err());
    assert!(ResourceServer::build(
        BUSBAR_RESOURCE,
        vec![("http://evil.example.com/".to_string(), idp.jwks())]
    )
    .is_err());

    // A key set that parses but can verify nothing.
    assert!(ResourceServer::build(
        BUSBAR_RESOURCE,
        vec![(ISSUER.to_string(), r#"{"keys":[]}"#.to_string())]
    )
    .is_err());
    assert!(ResourceServer::build(
        BUSBAR_RESOURCE,
        vec![(ISSUER.to_string(), "not json".to_string())]
    )
    .is_err());

    // The same issuer twice: the issuer selects the key set, so a duplicate makes that ambiguous.
    assert!(ResourceServer::build(
        BUSBAR_RESOURCE,
        vec![
            (ISSUER.to_string(), idp.jwks()),
            (ISSUER.to_string(), idp.jwks())
        ]
    )
    .is_err());
}

/// The MCP plane is a SUBTREE, and its boundary is a path-segment boundary. `/mcpx` is a different
/// route that happens to share a prefix, and admitting it to the MCP plane — or, worse, letting an
/// MCP-plane path escape into the ordinary data-plane bar — is the same class of bug as the
/// `starts_with("/api")` near-miss the admin classifier already guards against.
#[test]
fn the_mcp_plane_boundary_is_a_path_segment_boundary() {
    let idp = TestIdp::ec(ISSUER, "k1");
    let rs = resource_server(&idp);
    for inside in ["/mcp", "/mcp/", "/mcp/messages", "/mcp/v1/anything"] {
        assert!(rs.owns_path(inside), "{inside} is on the MCP plane");
    }
    for outside in [
        "/mcpx",
        "/mcp-admin",
        "/",
        "/healthz",
        "/api/v1/admin/keys",
        "/v1/models",
        "/mc",
        "/xmcp",
        "/auth/token",
    ] {
        assert!(!rs.owns_path(outside), "{outside} is NOT on the MCP plane");
    }
}
