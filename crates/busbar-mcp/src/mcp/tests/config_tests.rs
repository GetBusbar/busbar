// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `mcp:` validation and derivation.
//!
//! Every refusal here is a BOOT refusal, and the reason they are all tested rather than sampled is
//! that each one prevents a deployment that would answer requests while being subtly wrong about its
//! own identity — advertising one audience in its metadata document and enforcing another in its
//! verifier. That failure is invisible from inside busbar and fatal for every client.

use super::config::{
    SamplingCfg, DEFAULT_MAX_SAMPLING_MESSAGES, DEFAULT_MAX_SAMPLING_PROMPT_BYTES,
    DEFAULT_MAX_STOP_SEQUENCES, DEFAULT_MAX_STOP_SEQUENCE_BYTES, DEFAULT_TEMPERATURE_MAX_MILLI,
    DEFAULT_TEMPERATURE_MIN_MILLI,
};
use super::{McpCfg, McpCfgError, McpResource};

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
/// drift. And the RFC 9728 §3.1 path-INSERTION rule — the resource's path goes AFTER the well-known
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
    // The admission facts handed to the plane dispatch carry the SAME two strings. A second
    // spelling of either is a deployment whose challenge points somewhere its verifier does not.
    let adm = r.admission();
    assert_eq!(adm.audience, r.canonical_uri());
    assert_eq!(adm.resource_metadata, r.metadata_url());
}

/// A multi-segment path survives intact, and a trailing slash does not create a second spelling of
/// one deployment.
#[test]
fn a_nested_path_and_a_trailing_slash_derive_the_same_mount() {
    let r = McpResource::from_cfg(&cfg("https://h.example/api/mcp")).unwrap();
    assert_eq!(r.mount_path(), "/api/mcp");
    assert_eq!(
        r.metadata_path(),
        "/.well-known/oauth-protected-resource/api/mcp"
    );
    let slashed = McpResource::from_cfg(&cfg("https://h.example/api/mcp/")).unwrap();
    assert_eq!(slashed.mount_path(), r.mount_path());
}

/// The canonical URI is NOT normalised, only recognised. It is compared byte-for-byte against the
/// `aud` an authorization server minted, and a parser that helpfully lower-cased the host or
/// stripped a default port would hand back a string that no longer equals what the IdP issued —
/// turning a correct client into a refused one, for a reason nothing logs.
#[test]
fn the_canonical_uri_is_preserved_verbatim_rather_than_normalised() {
    let r = McpResource::from_cfg(&cfg("https://Gateway.Example.COM:443/MCP")).unwrap();
    assert_eq!(r.canonical_uri(), "https://Gateway.Example.COM:443/MCP");
    assert_eq!(r.mount_path(), "/MCP");
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

/// Origins are matched EXACTLY. Every entry below shares a prefix or a suffix with an allowed origin
/// and is a different origin; admitting one is how `https://app.example.com` starts admitting
/// `https://app.example.com.evil.test`, which is the DNS-rebinding attack the check exists for.
///
/// THE VERDICT IS NO LONGER THIS PLANE'S — it is `busbar_kernel::ingress::protocol::origin_admitted`, one
/// rule for every JSON-RPC plane, because A2A had no such check at all for as long as this one was
/// a method on `McpResource`. What this asserts is unchanged: the exact-match rule, applied to the
/// list THIS config parses. The loopback half of the same rule is asserted beside the rule itself,
/// in `ingress::protocol`'s own battery.
#[test]
fn origin_matching_is_exact_and_the_empty_allowlist_admits_nothing() {
    let mut c = cfg("https://gateway.example.com/mcp");
    let empty = McpResource::from_cfg(&c).unwrap();
    assert!(
        !busbar_kernel::ingress::protocol::origin_admitted(
            "https://app.example.com",
            empty.allowed_origins()
        ),
        "the default allowlist is empty and must admit no origin at all"
    );

    c.allowed_origins = vec!["https://app.example.com".to_string()];
    let r = McpResource::from_cfg(&c).unwrap();
    assert!(busbar_kernel::ingress::protocol::origin_admitted(
        "https://app.example.com",
        r.allowed_origins()
    ));
    for near in [
        "https://app.example.com.evil.test",
        "https://app.example.com/",
        "https://evil.test/?x=https://app.example.com",
        "http://app.example.com",
        "https://APP.EXAMPLE.COM",
        "https://sub.app.example.com",
        "null",
        "",
    ] {
        assert!(
            !busbar_kernel::ingress::protocol::origin_admitted(near, r.allowed_origins()),
            "`{near}` is not the allowed origin and must be refused"
        );
    }
}

/// The `mcp:` block round-trips through YAML with the field names an operator actually writes, and
/// an unknown key is REFUSED rather than silently ignored — a typo'd `allowed_origin:` that parsed
/// to an empty allowlist would look like a working config and be a closed door.
#[test]
fn the_config_block_parses_from_yaml_and_refuses_an_unknown_key() {
    let parsed: McpCfg = serde_yaml::from_str(
        "canonical_uri: https://gateway.example.com/mcp\n\
         authorization_servers:\n  - https://login.example.com\n\
         scopes_supported: [\"mcp:tools:list\"]\n\
         allowed_origins: []\n",
    )
    .expect("the documented shape must parse");
    assert_eq!(parsed.canonical_uri, "https://gateway.example.com/mcp");
    assert_eq!(parsed.scopes_supported, vec!["mcp:tools:list".to_string()]);

    let typo = serde_yaml::from_str::<McpCfg>(
        "canonical_uri: https://gateway.example.com/mcp\n\
         authorization_servers: [https://login.example.com]\n\
         allowed_origin: [https://app.example.com]\n",
    );
    assert!(
        typo.is_err(),
        "an unknown key must be refused: silently ignoring `allowed_origin` leaves a config that \
         reads as permissive and behaves as closed"
    );
}

/// `tools.<server>.sampling:` ROUND-TRIPS through YAML — owner ruling Q22c / Q35's input-side
/// bounds included. An operator who declares only the three original fields (`model`, `max_tokens`,
/// `max_requests_per_minute`) gets the shipped defaults on the four new ones; an operator who
/// spells all seven gets back exactly what they wrote; and an unknown key is still refused, because
/// `SamplingCfg` staying `deny_unknown_fields` while gaining optional fields is the whole point of
/// `#[serde(default = ...)]` over a blanket `#[serde(default)]` on the struct.
#[test]
fn the_sampling_block_round_trips_through_yaml_and_the_new_bounds_default_when_omitted() {
    let minimal: SamplingCfg = serde_yaml::from_str(
        "model: sampler-model\n\
         max_tokens: 512\n\
         max_requests_per_minute: 30\n",
    )
    .expect("the pre-existing three-field shape must still parse");
    assert_eq!(minimal.model, "sampler-model");
    assert_eq!(minimal.max_tokens, 512);
    assert_eq!(minimal.max_requests_per_minute, 30);
    assert_eq!(minimal.max_messages, DEFAULT_MAX_SAMPLING_MESSAGES);
    assert_eq!(minimal.max_prompt_bytes, DEFAULT_MAX_SAMPLING_PROMPT_BYTES);
    assert_eq!(minimal.max_stop_sequences, DEFAULT_MAX_STOP_SEQUENCES);
    assert_eq!(
        minimal.max_stop_sequence_bytes,
        DEFAULT_MAX_STOP_SEQUENCE_BYTES
    );
    assert_eq!(minimal.temperature_min_milli, DEFAULT_TEMPERATURE_MIN_MILLI);
    assert_eq!(minimal.temperature_max_milli, DEFAULT_TEMPERATURE_MAX_MILLI);

    let full: SamplingCfg = serde_yaml::from_str(
        "model: sampler-model\n\
         max_tokens: 512\n\
         max_requests_per_minute: 30\n\
         max_messages: 16\n\
         max_prompt_bytes: 4096\n\
         max_stop_sequences: 2\n\
         max_stop_sequence_bytes: 16\n\
         temperature_min_milli: 100\n\
         temperature_max_milli: 1200\n",
    )
    .expect("the full seven-field shape must parse");
    let expected = SamplingCfg {
        model: "sampler-model".to_string(),
        max_tokens: 512,
        max_requests_per_minute: 30,
        max_messages: 16,
        max_prompt_bytes: 4096,
        max_stop_sequences: 2,
        max_stop_sequence_bytes: 16,
        temperature_min_milli: 100,
        temperature_max_milli: 1200,
    };
    assert_eq!(full, expected);
    // ROUND-TRIP: serialising what was just parsed and re-parsing it must land on the same value,
    // so a config an operator saved back out (a UI, a formatter) is not a second spelling.
    let yaml = serde_yaml::to_string(&full).expect("a fully-populated policy must serialise");
    let reparsed: SamplingCfg =
        serde_yaml::from_str(&yaml).expect("what busbar serialises, busbar must parse back");
    assert_eq!(reparsed, expected);

    let typo = serde_yaml::from_str::<SamplingCfg>(
        "model: sampler-model\n\
         max_tokens: 512\n\
         max_requests_per_minute: 30\n\
         max_mesages: 16\n",
    );
    assert!(
        typo.is_err(),
        "an unknown key must be refused: silently ignoring `max_mesages` would leave the real \
         `max_messages` at its default, unbounded by what the operator thought they wrote"
    );
}

/// THE CADENCE RATCHET, OVER THIS PLANE'S OWN FILES. The `tools:` plane has a `verify_ttl:` and a
/// fetch of its own, and both drive the kernel's shared `due`. A knob that slowed detection or
/// delayed a quarantine would be exactly as dangerous here as on any other plane, so this plane's
/// config grammar and its connect path are held to the identical rule the kernel's shared trust gate
/// is held to. The plane tests itself: no sibling plane reads these files.
#[test]
fn the_cadence_grammar_has_no_knob_that_slows_detection_or_delays_demotion() {
    let read = |rel: &str| -> String {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
            .unwrap_or_else(|e| {
                panic!(
                    "the cadence ratchet cannot read `{rel}`: {e}. If the file \
                 moved, MOVE THE RATCHET — do not drop the path."
                )
            })
    };
    let code = |s: &str| -> String {
        s.lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    for rel in ["src/mcp/config.rs", "src/mcp/connect.rs"] {
        let src = code(&read(rel));
        for banned in [
            "detection_backoff",
            "detection_grace",
            "demotion_backoff",
            "demotion_grace",
            "demotion_delay",
            "quarantine_grace",
            "quarantine_delay",
            "drift_grace",
            "suppress_drift",
            "min_drift",
        ] {
            assert!(
                !src.contains(banned),
                "{rel} names `{banned}`. Detection is never rate-limited and demotion is never \
                 held; the only direction that may be held is RECOVERY. A window an upstream can \
                 open for itself by flapping is a window it will use."
            );
        }
    }
}
