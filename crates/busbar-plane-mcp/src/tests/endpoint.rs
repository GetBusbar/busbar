// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `mcp:` validation and derivation, moved with the code from the retired host crate.
//!
//! Every refusal here is a BOOT refusal, and the reason they are all tested rather than sampled is
//! that each one prevents a deployment that would answer requests while being subtly wrong about its
//! own identity — advertising one audience in its metadata document and enforcing another in its
//! verifier. That failure is invisible from inside busbar and fatal for every client.

use super::{McpCfg, McpCfgError, McpResource};
use crate::tool_claims::DEFAULT_MOUNT;

fn cfg(uri: &str) -> McpCfg {
    McpCfg {
        canonical_uri: uri.to_string(),
        authorization_servers: vec!["https://login.example.com".to_string()],
        scopes_supported: Vec::new(),
        allowed_origins: Vec::new(),
    }
}

/// THE DERIVATION, which is the whole reason the mount path is not a separate config key: the path
/// a client posts to and the identifier its token is bound to come from ONE string, so they cannot
/// drift. And the RFC 9728 section 3.1 path-INSERTION rule — the resource's path goes AFTER the well-known
/// prefix, not before it. Getting that backwards 404s every compliant client's discovery.
#[test]
fn the_mount_and_the_metadata_path_are_derived_from_the_one_canonical_uri() {
    let r = McpResource::from_cfg(&cfg("https://gateway.example.com/mcp")).unwrap();
    assert_eq!(r.canonical_uri(), "https://gateway.example.com/mcp");
    assert_eq!(r.mount_path(), "/mcp");
    assert_eq!(
        r.metadata_path(),
        "/.well-known/oauth-protected-resource/mcp"
    );
    assert_eq!(
        r.metadata_url(),
        "https://gateway.example.com/.well-known/oauth-protected-resource/mcp"
    );
}

/// A multi-segment path is refused (below); a trailing slash does not create a second spelling of
/// one deployment, and the audience stays the string the operator wrote.
#[test]
fn a_trailing_slash_derives_the_same_mount() {
    let bare = format!("https://h.example{DEFAULT_MOUNT}");
    let slashed = format!("{bare}/");
    let r = McpResource::from_cfg(&cfg(&bare)).unwrap();
    let s = McpResource::from_cfg(&cfg(&slashed)).unwrap();
    assert_eq!(s.mount_path(), DEFAULT_MOUNT);
    assert_eq!(s.mount_path(), r.mount_path());
    assert_eq!(s.metadata_path(), r.metadata_path());
    assert_eq!(s.canonical_uri(), slashed);
}

/// CG-17: THE MOUNT IS FIXED, NOT OPERATOR-CONFIGURABLE. The design rules that inbound paths are
/// compile-time claims, and a configured address naming a path nothing claims refuses boot at
/// validation.
///
/// Such an address used to be accepted: the process advertised that path in its `401` challenge and
/// bound every token's audience to it, while the claim table served another — a deployment its
/// clients can never reach. It is a boot refusal now, and the refusal says what to type. Paths
/// differ by case, so an upper-cased mount is another path, and so is a nested one.
#[test]
fn a_canonical_uri_naming_any_other_path_is_refused_at_boot() {
    let upper = DEFAULT_MOUNT.to_uppercase();
    let cases = [
        format!("/api{DEFAULT_MOUNT}"),
        format!("{DEFAULT_MOUNT}/v2"),
        format!("{DEFAULT_MOUNT}-staging"),
        "/tools".to_string(),
        upper,
    ];
    for path in &cases {
        for uri in [
            format!("https://h.example{path}"),
            format!("https://h.example{path}/"),
        ] {
            let err = McpResource::from_cfg(&cfg(&uri))
                .expect_err(&format!("`{uri}` names `{path}`, which nothing claims"));
            assert_eq!(
                err.to_string(),
                format!(
                    "mcp.canonical_uri `{uri}` names the path `{path}`, but the MCP endpoint is \
                     served only at `{DEFAULT_MOUNT}`; the path is fixed, not configurable. Keep the \
                     scheme, host and port and end the URI in `{DEFAULT_MOUNT}`. Example: \
                     `https://gateway.example.com{DEFAULT_MOUNT}`"
                ),
                "`{uri}`"
            );
        }
    }
}

/// The canonical URI is NOT normalised, only recognised. It is compared byte-for-byte against the
/// `aud` an authorization server minted, and a parser that helpfully lower-cased the host or
/// stripped a default port would hand back a string that no longer equals what the IdP issued —
/// turning a correct client into a refused one, for a reason nothing logs.
#[test]
fn the_canonical_uri_is_preserved_verbatim_rather_than_normalised() {
    let uri = format!("https://Gateway.Example.COM:443{DEFAULT_MOUNT}");
    let r = McpResource::from_cfg(&cfg(&uri)).unwrap();
    assert_eq!(r.canonical_uri(), uri);
    assert_eq!(r.mount_path(), DEFAULT_MOUNT);
}

/// Every refusal arm, with the exact error, because a boot refusal that names the wrong field sends
/// an operator to edit the wrong line.
#[test]
fn every_malformed_canonical_uri_is_refused_with_its_own_diagnosis() {
    let cases: &[(&str, McpCfgError)] = &[
        ("", McpCfgError::MissingCanonicalUri),
        ("   ", McpCfgError::MissingCanonicalUri),
        (
            "gateway.example.com/mcp",
            McpCfgError::CanonicalUriNotAbsolute("gateway.example.com/mcp".into()),
        ),
        (
            "ftp://gateway.example.com/mcp",
            McpCfgError::CanonicalUriNotAbsolute("ftp://gateway.example.com/mcp".into()),
        ),
        (
            "https:///mcp",
            McpCfgError::CanonicalUriNotAbsolute("https:///mcp".into()),
        ),
        (
            "https://gateway.example.com/mcp?tenant=a",
            McpCfgError::CanonicalUriHasQueryOrFragment(
                "https://gateway.example.com/mcp?tenant=a".into(),
            ),
        ),
        (
            "https://gateway.example.com/mcp#frag",
            McpCfgError::CanonicalUriHasQueryOrFragment(
                "https://gateway.example.com/mcp#frag".into(),
            ),
        ),
        (
            "https://gateway.example.com",
            McpCfgError::CanonicalUriHasNoPath("https://gateway.example.com".into()),
        ),
        (
            "https://gateway.example.com/",
            McpCfgError::CanonicalUriHasNoPath("https://gateway.example.com/".into()),
        ),
    ];
    for (uri, expected) in cases {
        assert_eq!(
            McpResource::from_cfg(&cfg(uri)).unwrap_err(),
            *expected,
            "`{uri}`"
        );
    }
}

/// The MCP plane may not mount at the deployment root. The LLM plane is the RESIDUAL — its catch-all
/// claims every unclaimed path by construction — so an MCP mount at `/` would sit in front of every
/// protocol endpoint in the process and answer them all with JSON-RPC errors.
#[test]
fn the_plane_cannot_mount_at_the_deployment_root() {
    assert!(matches!(
        McpResource::from_cfg(&cfg("https://gateway.example.com/")),
        Err(McpCfgError::CanonicalUriHasNoPath(_))
    ));
}

/// An authorization-server list is the ENTIRE content of the answer a credential-less client came
/// for. With none, the `401` it receives names nowhere to go, and the discovery loop dead-ends at
/// step two with no error anyone can act on.
#[test]
fn a_resource_with_no_authorization_server_is_refused() {
    let mut c = cfg("https://gateway.example.com/mcp");
    c.authorization_servers.clear();
    assert_eq!(
        McpResource::from_cfg(&c).unwrap_err(),
        McpCfgError::NoAuthorizationServers
    );
    c.authorization_servers = vec!["login.example.com".to_string()];
    assert_eq!(
        McpResource::from_cfg(&c).unwrap_err(),
        McpCfgError::AuthorizationServerNotAbsolute("login.example.com".into())
    );
}

/// The allowlist is the operator's list verbatim: the default is empty, and what the operator wrote
/// is what the resource carries. The verdict on an `Origin` is not the plane's (one rule for every
/// plane, asserted beside that rule); this holds the data half it reads.
#[test]
fn the_origin_allowlist_is_carried_as_written_and_empty_by_default() {
    let mut c = cfg("https://gateway.example.com/mcp");
    let empty = McpResource::from_cfg(&c).unwrap();
    assert!(
        empty.allowed_origins().is_empty(),
        "the default allowlist is empty"
    );
    c.allowed_origins = vec!["https://app.example.com".to_string()];
    let r = McpResource::from_cfg(&c).unwrap();
    assert_eq!(r.allowed_origins(), ["https://app.example.com".to_string()]);
}

/// The `mcp:` block parses with the field names an operator actually writes, and an unknown key is
/// REFUSED rather than silently ignored — a typo'd `allowed_origin:` that parsed to an empty
/// allowlist would look like a working config and be a closed door. (The composition root reads
/// the block as a parsed value, so a JSON document carries the same shape here.)
#[test]
fn the_config_block_parses_and_refuses_an_unknown_key() {
    let parsed: McpCfg = serde_json::from_str(
        r#"{"canonical_uri": "https://gateway.example.com/mcp",
            "authorization_servers": ["https://login.example.com"],
            "scopes_supported": ["mcp:tools:list"],
            "allowed_origins": []}"#,
    )
    .expect("the documented shape must parse");
    assert_eq!(parsed.canonical_uri, "https://gateway.example.com/mcp");
    assert_eq!(parsed.scopes_supported, vec!["mcp:tools:list".to_string()]);

    let typo = serde_json::from_str::<McpCfg>(
        r#"{"canonical_uri": "https://gateway.example.com/mcp",
            "authorization_servers": ["https://login.example.com"],
            "allowed_origin": ["https://app.example.com"]}"#,
    );
    assert!(
        typo.is_err(),
        "an unknown key must be refused: silently ignoring `allowed_origin` leaves a config that \
         reads as permissive and behaves as closed"
    );
}
