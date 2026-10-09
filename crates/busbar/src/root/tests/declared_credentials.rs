// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LLM DIALECTS' DECLARED SCHEMES, PRESENTED THROUGH THE LINKED AUTH PLUGINS (P2 D1, the auth
//! split; #83a SD-2b, SD-3; O7, S2-a).
//!
//! The kernel holds no auth style: a lane's credential is bound on the auth plugin serving the
//! style its dialect's declared scheme maps to, and every request asks that plugin for its fields.
//! This suite holds the composition root's auth axis and the auth plugins this build links
//! (`auths`), bound under each dialect's recorded binding (the shared fixture
//! `testing/plane-copies/declared-credentials.json`, `bindings`), to the credential headers each
//! dialect's own 1.5.5 builder wrote, per credential, mode and request (`rows`). The plane's own
//! suite holds its mapping of each real declaration to the same `bindings`, so the halves together
//! are the byte-identity proof of the switch, and neither names the other. Ported from the
//! kernel's `egress_auth` differential, which it replaces.
//!
//! THE MAIN LOG'S LINES (ARCHITECT D1 2026-10-05, LOG LINES): a credential the plugin cannot present
//! is its declared diagnostic on the #85 envelope, which the root writes to the main log in the line
//! 1.5.5's builder wrote there ([`crate::root::door_steps::MainLogSink`]). The two tests that pinned
//! those lines are ported below, word for word.

use std::sync::{Arc, OnceLock};

use busbar_contract::config::UpstreamCreds;
use busbar_contract::protocol::{
    CredentialFamily, CredentialHeader, EgressScheme, ProtocolDecl, SigningContext,
};
use busbar_kernel::bound_credential::{bind, CredentialProvider, StyleBinding};

fn fixture() -> &'static serde_json::Value {
    static DOC: OnceLock<serde_json::Value> = OnceLock::new();
    DOC.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../testing/plane-copies/declared-credentials.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
            .expect("fixture is JSON")
    })
}

/// The build's auth axis, as the kernel's build is handed it: the composition root's, whose
/// outbound half is the process's auth instances over this build's linked `auths` rows.
fn axis() -> Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    crate::root::dispatch::auth_axis(Arc::new(crate::root::loader::PluginRegistry::empty()))
}

/// `binding`, bound with `credential` on the linked plugin serving its style.
fn bound(binding: &StyleBinding, credential: &str) -> Arc<dyn CredentialProvider> {
    bind(&*axis(), binding, credential.as_bytes()).unwrap_or_else(|e| {
        panic!(
            "the linked auth plugins serve the style '{}': {e}",
            binding.style
        )
    })
}

/// The binding the fixture records for `dialect` (`bindings`): the style its declared scheme is
/// bound under and its parameters, a signing style's region added from `host` as the plane adds it
/// (the plane's own suite holds its mapping to the same rows).
fn binding_of(
    dialect: &str,
    host: &str,
    statics: &'static [(&'static str, &'static str)],
) -> StyleBinding {
    let row = &fixture()["bindings"][dialect];
    let style = row["style"].as_str().expect("style").to_string();
    let mut params = row["params"].clone();
    if style == "sigv4" {
        let region = recorded_region(host).unwrap_or("us-east-1");
        params["region"] = serde_json::Value::String(region.to_string());
    }
    StyleBinding {
        style,
        params,
        uses_key: true,
        statics,
    }
}

/// The headers `dialect`'s declared scheme presents for `key` under `ctx`, with `statics` after
/// them: bound as a lane binds (the operator's key in `Own` mode; a passthrough lane binds its own,
/// here none, and presents the caller's per request), in order, as strings.
fn present_bound(binding: &StyleBinding, key: &str, ctx: &SigningContext) -> Vec<(String, String)> {
    let own = match ctx.upstream_creds {
        UpstreamCreds::Own => key,
        UpstreamCreds::Passthrough => "",
    };
    strings(&bound(binding, own).headers_for(key, ctx))
}

/// `decl`'s dialect (its twin name's tail), presented.
fn present(decl: &'static ProtocolDecl, key: &str, ctx: &SigningContext) -> Vec<(String, String)> {
    let dialect = decl
        .name
        .rsplit('-')
        .next()
        .expect("a twin name ends in its dialect");
    present_bound(
        &binding_of(dialect, ctx.host, decl.static_headers),
        key,
        ctx,
    )
}

fn strings(h: &[(axum::http::HeaderName, axum::http::HeaderValue)]) -> Vec<(String, String)> {
    h.iter()
        .map(|(k, v)| {
            (
                k.as_str().to_string(),
                String::from_utf8(v.as_bytes().to_vec()).expect("utf-8"),
            )
        })
        .collect()
}

/// The signing twin's region function: the fixture's recorded answer for the host.
fn recorded_region(host: &str) -> Option<&'static str> {
    fixture()["regions"]
        .as_array()
        .expect("regions")
        .iter()
        .find(|r| r["host"] == host)
        .and_then(|r| r["region"].as_str())
}

const ANTHROPIC_FAMILIES: &[CredentialFamily] = &[
    CredentialFamily {
        prefix: "sk-ant-api",
        presented_as: CredentialHeader::Raw {
            header: "x-api-key",
            trim_start: true,
        },
    },
    CredentialFamily {
        prefix: "sk-ant-oat",
        presented_as: CredentialHeader::Bearer,
    },
];

const GOOG: CredentialHeader = CredentialHeader::Raw {
    header: "x-goog-api-key",
    trim_start: false,
};

static TWINS: [ProtocolDecl; 6] = [
    ProtocolDecl {
        egress_scheme: Some(EgressScheme::bearer()),
        ..ProtocolDecl::named("declared-twin-openai")
    },
    ProtocolDecl {
        egress_scheme: Some(EgressScheme::bearer()),
        ..ProtocolDecl::named("declared-twin-responses")
    },
    ProtocolDecl {
        egress_scheme: Some(EgressScheme::bearer()),
        ..ProtocolDecl::named("declared-twin-cohere")
    },
    ProtocolDecl {
        egress_scheme: Some(EgressScheme::Static {
            families: &[],
            own: GOOG,
            passthrough: GOOG,
        }),
        ..ProtocolDecl::named("declared-twin-gemini")
    },
    ProtocolDecl {
        egress_scheme: Some(EgressScheme::Static {
            families: ANTHROPIC_FAMILIES,
            own: CredentialHeader::Raw {
                header: "x-api-key",
                trim_start: false,
            },
            passthrough: CredentialHeader::Bearer,
        }),
        ..ProtocolDecl::named("declared-twin-anthropic")
    },
    ProtocolDecl {
        egress_scheme: Some(EgressScheme::SigV4 {
            service: "bedrock",
            region_of_host: recorded_region,
            default_region: "us-east-1",
            content_type: "application/json",
        }),
        ..ProtocolDecl::named("declared-twin-bedrock")
    },
];

fn twin(dialect: &str) -> &'static ProtocolDecl {
    let name = format!("declared-twin-{dialect}");
    TWINS
        .iter()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("no twin for {dialect}"))
}

fn presentation(h: &CredentialHeader) -> serde_json::Value {
    match h {
        CredentialHeader::Bearer => serde_json::json!({"bearer": true}),
        CredentialHeader::Raw { header, trim_start } => {
            serde_json::json!({"header": header, "trim_start": trim_start})
        }
    }
}

fn describe(scheme: &EgressScheme) -> serde_json::Value {
    match scheme {
        EgressScheme::Static {
            families,
            own,
            passthrough,
        } => serde_json::json!({
            "kind": "static",
            "families": families
                .iter()
                .map(|f| serde_json::json!({"prefix": f.prefix, "presented_as": presentation(&f.presented_as)}))
                .collect::<Vec<_>>(),
            "own": presentation(own),
            "passthrough": presentation(passthrough),
        }),
        EgressScheme::SigV4 {
            service,
            default_region,
            content_type,
            ..
        } => serde_json::json!({
            "kind": "sigv4",
            "service": service,
            "default_region": default_region,
            "content_type": content_type,
        }),
    }
}

fn hex(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().expect("hex")).expect("hex")
}

/// Every twin carries exactly the scheme data the fixture records for its dialect — the data the
/// plane's own suite holds each real declaration to.
#[test]
fn each_twin_carries_the_fixture_scheme_of_its_dialect() {
    let schemes = fixture()["schemes"].as_object().expect("schemes");
    assert_eq!(schemes.len(), TWINS.len());
    for (dialect, data) in schemes {
        let scheme = twin(dialect).egress_scheme.expect("declared");
        assert_eq!(&describe(&scheme), data, "{dialect}");
    }
}

/// THE DIFFERENTIAL: presented under each dialect's declared scheme, through the linked auth
/// plugins, the request carries exactly the credential headers that dialect's own builder wrote,
/// for every credential, mode and request in the fixture.
#[test]
fn each_declared_scheme_presents_what_its_dialect_builder_wrote() {
    let mut compared = 0usize;
    for row in fixture()["rows"].as_array().expect("rows") {
        let dialect = row["dialect"].as_str().expect("dialect");
        let key = String::from_utf8(hex(&row["key_hex"])).expect("utf-8 key");
        // AN EMPTY KEY NEVER REACHES THE BUILDER ON THE WIRE: the lane's writer asks for no header
        // at all for a key that presents (1.5.5's `lane_auth_headers` and the passthrough rule;
        // `test_keyless_lane_sends_no_auth_header`), so the builder's raw answer for it was never
        // sent and is no byte-identity obligation of the plugin's.
        if key.is_empty() {
            continue;
        }
        let body = hex(&row["body_hex"]);
        let ctx = SigningContext {
            host: row["host"].as_str().expect("host"),
            canonical_uri: row["canonical_uri"].as_str().expect("uri"),
            body: &body,
            timestamp_epoch: row["timestamp_epoch"].as_u64().expect("ts"),
            upstream_creds: if row["mode"] == "own" {
                UpstreamCreds::Own
            } else {
                UpstreamCreds::Passthrough
            },
        };
        let presented: Vec<serde_json::Value> = present(twin(dialect), &key, &ctx)
            .into_iter()
            .map(|(k, v)| serde_json::json!([k, hex::encode(v.as_bytes())]))
            .collect();
        assert_eq!(
            serde_json::Value::Array(presented),
            row["headers"],
            "{dialect}: key {key:?}, host {}, mode {}, uri {}",
            ctx.host,
            row["mode"],
            ctx.canonical_uri
        );
        compared += 1;
    }
    assert!(compared > 0);
}

fn signed(key: &str, host: &str, uri: &str, body: &[u8]) -> Vec<(String, String)> {
    let ctx = SigningContext {
        host,
        canonical_uri: uri,
        body,
        timestamp_epoch: 1_440_938_160, // 20150830T123600Z
        upstream_creds: UpstreamCreds::Own,
    };
    present(twin("bedrock"), key, &ctx)
}

fn get(headers: &[(String, String)], name: &str) -> Option<String> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.clone())
}

#[test]
fn a_signing_dialect_request_carries_the_scope_the_host_names() {
    let h = signed(
        "AKIDEXAMPLE:SECRETKEY",
        "bedrock-runtime.us-east-1.amazonaws.com",
        "/model/anthropic.claude%3A0/converse",
        br#"{"messages":[]}"#,
    );
    let auth = get(&h, "authorization").expect("authorization header");
    assert!(
        auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, "
        ),
        "scope/region derived from host; got: {auth}"
    );
    assert!(auth.contains("SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date"));
    assert!(auth.contains("Signature="));
    assert_eq!(get(&h, "x-amz-date").as_deref(), Some("20150830T123600Z"));
    assert!(get(&h, "x-amz-content-sha256").is_some());
    assert!(get(&h, "x-amz-security-token").is_none());
}

#[test]
fn a_session_token_is_sent_and_signed_for_the_hosts_region() {
    let h = signed(
        "AKID:SECRET:SESSIONTOKEN",
        "bedrock-runtime.eu-west-1.amazonaws.com",
        "/model/m/converse",
        b"{}",
    );
    assert_eq!(
        get(&h, "x-amz-security-token").as_deref(),
        Some("SESSIONTOKEN")
    );
    let auth = get(&h, "authorization").expect("authorization");
    assert!(auth.contains("/eu-west-1/bedrock/aws4_request"));
    assert!(auth.contains("x-amz-security-token"));
}

#[test]
fn a_misconfigured_or_unsendable_signing_credential_signs_nothing() {
    let host = "bedrock-runtime.us-east-1.amazonaws.com";
    for key in [
        "not-a-valid-key",
        "AKID\r\nINJECT:SECRET",
        "AKID\u{0001}X:SECRET",
        "AKID:SECRET:TOK\r\nEN",
        "AKID:SECRET:TOK\u{0001}EN",
    ] {
        let h = signed(key, host, "/model/m/converse", b"{}");
        assert!(h.is_empty(), "{key:?} must yield no headers, got {h:?}");
    }
    let ok = signed("AKID:SECRET:CLEANTOKEN", host, "/model/m/converse", b"{}");
    let auth = get(&ok, "authorization").expect("a clean credential signs");
    assert!(auth.contains("x-amz-security-token"));
    assert_eq!(
        get(&ok, "x-amz-security-token").as_deref(),
        Some("CLEANTOKEN")
    );
}

#[test]
fn a_fips_host_signs_for_its_region_and_an_unnamed_one_for_the_default() {
    let fips = signed(
        "AKID:SECRET",
        "bedrock-runtime-fips.eu-west-1.amazonaws.com",
        "/model/m/converse",
        b"{}",
    );
    let auth = get(&fips, "authorization").expect("authorization");
    assert!(auth.contains("/eu-west-1/bedrock/aws4_request"), "{auth}");
    assert!(!auth.contains("/us-east-1/"), "{auth}");
    let cname = signed(
        "AKID:SECRET",
        "my-cname-front.example.com",
        "/model/m/converse",
        b"{}",
    );
    let auth = get(&cname, "authorization").expect("authorization");
    assert!(auth.contains("/us-east-1/bedrock/aws4_request"), "{auth}");
}

// ══ SIGV4 SIGNS THE WALKED REQUEST (auth audit fix b; BUSBAR-1.6.0 l.870-873) ═══════════════════
//
// The door-plane walk hands the style the request's real method and query (`far_end.rs`'s
// `FieldsRequest`), so the signature must cover those, not a fixed `POST` with no query. The
// expected signature is recomputed here from the request facts with plain AWS SigV4 steps; the
// plugin's signer is never called for it.

/// RED ARM (on `busbar-auth-sigv4` c22578a, which signs `POST`, an empty query and an unsent
/// `content-type`): a `GET` with a query, signed through the linked sigv4 style, verifies under the
/// secret over that method, the double-encoded path, the sorted query and the headers it names,
/// and names no `content-type`, since the request carries none.
#[cfg(feature = "auth-sigv4")]
#[test]
fn the_linked_sigv4_style_signs_the_walked_requests_method_and_query() {
    use busbar_contract::abi::auth::AuthPoint;
    use busbar_contract::auth_calls::{Fields, FieldsRequest};

    const SECRET: &str = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const AUTHORITY: &str = "runtime.example.com";
    let params = binding_of("bedrock", SIGNING_HOST, &[]).params;
    assert_eq!(
        params,
        serde_json::json!({
            "service": "bedrock",
            "region": "us-east-1",
            "content_type": "application/json"
        })
    );
    let serving = axis()
        .serving("sigv4", &params)
        .expect("the sigv4 plugin opens")
        .expect("a linked plugin serves sigv4");
    let handle = serving
        .auth
        .open_outbound("sigv4", format!("AKIDEXAMPLE:{SECRET}").as_bytes(), &params)
        .expect("the binding opens");
    // The shape the door-plane walk builds (`far_end.rs`): the real method, path and query.
    let request = FieldsRequest {
        point: AuthPoint::Head,
        method: b"GET".to_vec(),
        authority: AUTHORITY.into(),
        path: b"/model/a%3Ab/invoke".to_vec(),
        query: Some(b"b=2&a=1".to_vec()),
        timestamp: 1_440_938_160, // 20150830T123600Z
        headers: vec![],
        ..Default::default()
    };
    let fields = match serving.auth.fields_now(handle, &request) {
        Some(Fields::Ready(fields)) => fields,
        other => panic!("the style signs in place: {other:?}"),
    };
    let field = |name: &str| {
        fields
            .iter()
            .find(|f| f.name == name.as_bytes())
            .map(|f| String::from_utf8(f.value.expose_secret().clone()).expect("utf-8"))
    };
    let auth = field("authorization").expect("an authorization field");
    let amzdate = field("x-amz-date").expect("an x-amz-date field");
    assert_eq!(amzdate, "20150830T123600Z");
    let rest = auth
        .strip_prefix(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/bedrock/aws4_request, ",
        )
        .unwrap_or_else(|| panic!("the scope is the request's day, region and service: {auth}"));
    let (signed_headers, signature) = rest
        .strip_prefix("SignedHeaders=")
        .and_then(|r| r.split_once(", Signature="))
        .unwrap_or_else(|| panic!("SignedHeaders then Signature: {auth}"));

    // Each header the signature names, valued as the request sends it: the authority, the empty
    // payload's hash, and otherwise the field the style answered.
    let empty_hash = sigv4::sha256_hex(b"");
    let mut canonical_headers = String::new();
    for name in signed_headers.split(';') {
        let value = match name {
            "host" => AUTHORITY.to_string(),
            "x-amz-content-sha256" => empty_hash.clone(),
            other => {
                field(other).unwrap_or_else(|| panic!("no field carries the signed `{other}`"))
            }
        };
        canonical_headers.push_str(&format!("{name}:{value}\n"));
    }
    let canonical_request = format!(
        "GET\n{}\na=1&b=2\n{canonical_headers}\n{signed_headers}\n{empty_hash}",
        sigv4::uri_encode("/model/a%3Ab/invoke")
    );
    assert_eq!(
        signature,
        sigv4::signature(
            SECRET,
            &amzdate,
            "20150830",
            "us-east-1",
            "bedrock",
            &canonical_request
        ),
        "the signature verifies over the walked request:\n{canonical_request}"
    );
    assert!(
        signed_headers.split(';').all(|h| h != "content-type"),
        "a request without content-type signs none: {signed_headers}"
    );
}

/// The SigV4 steps the cell above recomputes with, ported from `tests/sigv4_both_ways.rs`.
#[cfg(feature = "auth-sigv4")]
mod sigv4 {
    use sha2::{Digest, Sha256};

    /// The SigV4 signature (hex) of `canonical_request` under `secret`'s derived signing key.
    pub(super) fn signature(
        secret: &str,
        amzdate: &str,
        datestamp: &str,
        region: &str,
        service: &str,
        canonical_request: &str,
    ) -> String {
        let scope = format!("{datestamp}/{region}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amzdate}\n{scope}\n{}",
            sha256_hex(canonical_request.as_bytes())
        );
        let k_date = hmac_sha256(format!("AWS4{secret}").as_bytes(), datestamp.as_bytes());
        let k_region = hmac_sha256(&k_date, region.as_bytes());
        let k_service = hmac_sha256(&k_region, service.as_bytes());
        let k_signing = hmac_sha256(&k_service, b"aws4_request");
        hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()))
    }

    /// HMAC-SHA256 (RFC 2104) over `sha2`.
    fn hmac_sha256(key: &[u8], msg: &[u8]) -> Vec<u8> {
        const BLOCK: usize = 64;
        let mut k = if key.len() > BLOCK {
            Sha256::digest(key).to_vec()
        } else {
            key.to_vec()
        };
        k.resize(BLOCK, 0);
        let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
        let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
        let inner = Sha256::new()
            .chain_update(&ipad)
            .chain_update(msg)
            .finalize();
        Sha256::new()
            .chain_update(&opad)
            .chain_update(inner)
            .finalize()
            .to_vec()
    }

    pub(super) fn sha256_hex(bytes: &[u8]) -> String {
        hex::encode(Sha256::digest(bytes))
    }

    /// SigV4 URI encoding of a path: unreserved bytes and `/` pass, every other byte is `%XX`.
    pub(super) fn uri_encode(path: &str) -> String {
        let mut out = String::with_capacity(path.len());
        for &b in path.as_bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}

#[test]
fn a_static_credential_is_presented_verbatim_or_omitted_never_emptied() {
    let ctx = SigningContext {
        host: "upstream.internal",
        canonical_uri: "/v1/chat/completions",
        body: b"{}",
        timestamp_epoch: 1_752_000_000,
        upstream_creds: UpstreamCreds::Own,
    };
    let p = |dialect: &str, key: &str| present(twin(dialect), key, &ctx);
    for dialect in ["openai", "responses", "cohere"] {
        assert_eq!(
            p(dialect, "sk-test"),
            vec![("authorization".to_string(), "Bearer sk-test".to_string())],
            "{dialect}"
        );
        for bad in ["bad\nkey", "key\u{0000}bad"] {
            assert!(p(dialect, bad).is_empty(), "{dialect}: {bad:?}");
        }
    }
    assert_eq!(
        p("gemini", "AIzaSyValidKey123"),
        vec![(
            "x-goog-api-key".to_string(),
            "AIzaSyValidKey123".to_string()
        )]
    );
    for bad in ["bad\nkey", "key\u{0000}bad"] {
        assert!(p("gemini", bad).is_empty(), "gemini: {bad:?}");
    }
}

// ══ DECLARED STATIC HEADERS (#83a S2-a; SD-3b) ═══════════════════════════════════════════════════
//
// A protocol's `static_headers` are written verbatim after its declared credential, on every request
// the credential is presented for — the one version header its builder used to write beside the
// credential, now declared data.

const FAMILY_TABLE: EgressScheme = EgressScheme::Static {
    families: ANTHROPIC_FAMILIES,
    own: CredentialHeader::Raw {
        header: "x-api-key",
        trim_start: false,
    },
    passthrough: CredentialHeader::Bearer,
};

static STATIC_TWINS: [ProtocolDecl; 3] = [
    ProtocolDecl {
        egress_scheme: Some(FAMILY_TABLE),
        static_headers: &[("anthropic-version", "2023-06-01")],
        ..ProtocolDecl::named("static-twin-versioned")
    },
    ProtocolDecl {
        egress_scheme: Some(FAMILY_TABLE),
        ..ProtocolDecl::named("static-twin-unversioned")
    },
    ProtocolDecl {
        egress_scheme: Some(EgressScheme::bearer()),
        static_headers: &[("x-static-one", "1"), ("x-static-two", "two")],
        ..ProtocolDecl::named("static-twin-two-statics")
    },
];

fn static_twin(name: &str) -> &'static ProtocolDecl {
    STATIC_TWINS
        .iter()
        .find(|d| d.name == name)
        .expect("a twin")
}

fn presented(name: &str, key: &str, mode: UpstreamCreds) -> Vec<(String, String)> {
    let ctx = SigningContext {
        host: "upstream.internal",
        canonical_uri: "/v1/messages",
        body: b"{}",
        timestamp_epoch: 1_752_000_000,
        upstream_creds: mode,
    };
    // The family-table twins carry the anthropic scheme, the two-statics twin the bearer one.
    let dialect = if name == "static-twin-two-statics" {
        "openai"
    } else {
        "anthropic"
    };
    present_bound(
        &binding_of(dialect, ctx.host, static_twin(name).static_headers),
        key,
        &ctx,
    )
}

fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
    v.iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// THE VERSIONED REQUEST: the declared credential, then EXACTLY the declared static header — for
/// each credential family and mode, and for a key no header value may carry (the credential is
/// omitted, the version stays).
#[test]
fn a_declared_static_header_follows_the_credential_verbatim() {
    let v = ("anthropic-version", "2023-06-01");
    let own = UpstreamCreds::Own;
    let pt = UpstreamCreds::Passthrough;
    for (key, mode, want) in [
        (
            "sk-ant-api03-k",
            own,
            vec![("x-api-key", "sk-ant-api03-k"), v],
        ),
        (
            "  sk-ant-api03-k",
            pt,
            vec![("x-api-key", "sk-ant-api03-k"), v],
        ),
        (
            "sk-ant-oat01-t",
            own,
            vec![("authorization", "Bearer sk-ant-oat01-t"), v],
        ),
        ("opaque", own, vec![("x-api-key", "opaque"), v]),
        ("opaque", pt, vec![("authorization", "Bearer opaque"), v]),
        ("sk-ant-api03-bad\nkey", own, vec![v]),
        ("sk-ant-oat01-bad\ntoken", own, vec![v]),
    ] {
        assert_eq!(
            presented("static-twin-versioned", key, mode),
            pairs(&want),
            "key {key:?}, mode {mode:?}"
        );
    }
    assert_eq!(
        presented("static-twin-two-statics", "k", own),
        pairs(&[
            ("authorization", "Bearer k"),
            ("x-static-one", "1"),
            ("x-static-two", "two")
        ]),
        "several static headers are written in their declared order"
    );
}

/// RED ARM: the same scheme with NO static header declared presents the credential alone — the
/// version header is absent, so it is the declaration that puts it on the wire, nothing else.
#[test]
fn with_no_static_header_declared_the_version_header_is_absent() {
    for (key, mode) in [
        ("sk-ant-api03-k", UpstreamCreds::Own),
        ("opaque", UpstreamCreds::Passthrough),
        ("sk-ant-api03-bad\nkey", UpstreamCreds::Own),
    ] {
        let h = presented("static-twin-unversioned", key, mode);
        assert!(
            h.iter().all(|(k, _)| k != "anthropic-version"),
            "{key:?}: {h:?}"
        );
    }
    assert_eq!(
        presented(
            "static-twin-unversioned",
            "sk-ant-api03-k",
            UpstreamCreds::Own
        ),
        pairs(&[("x-api-key", "sk-ant-api03-k")])
    );
}

/// The operator's `auth: api-key` override, bound on the linked plugin serving `api-key`: for every
/// key a config system can hand it, in either credential mode, the credential verbatim in `api-key`
/// (the shared header rule), and a key that is not a legal header value sends no header at all.
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
    let binding = binding_of("api-key-override", "h.example.com", &[]);
    for &key in KEYS {
        for upstream_creds in [UpstreamCreds::Own, UpstreamCreds::Passthrough] {
            let ctx = SigningContext {
                host: "h.example.com",
                canonical_uri: "/v1/x",
                body: b"{}",
                timestamp_epoch: 1_756_000_000,
                upstream_creds,
            };
            let own = match upstream_creds {
                UpstreamCreds::Own => key,
                UpstreamCreds::Passthrough => "",
            };
            // The lane's writer asks for no header at all for an empty key (the keyless rule);
            // every other key is the plugin's answer.
            let got = if key.is_empty() {
                Vec::new()
            } else {
                strings(&bound(&binding, own).headers_for(key, &ctx))
            };
            let want: Vec<(String, String)> =
                if busbar_contract::header::is_legal_header_value(key) && !key.is_empty() {
                    vec![("api-key".to_string(), key.to_string())]
                } else {
                    Vec::new()
                };
            assert_eq!(got, want, "key {key:?}, mode {upstream_creds:?}");
        }
    }
}

/// `dialect`'s recorded binding, its lines naming `protocol` (the name 1.5.5's twin carried).
fn named_binding(dialect: &str, protocol: &str) -> StyleBinding {
    let mut binding = binding_of(dialect, SIGNING_HOST, &[]);
    if binding.style == "api-key" {
        binding.params["protocol"] = serde_json::Value::String(protocol.to_string());
    }
    binding
}

const SIGNING_HOST: &str = "bedrock-runtime.us-east-1.amazonaws.com";

/// Every line the main log took, DEBUG and above, while `f` ran.
fn main_log(f: impl FnOnce()) -> Vec<String> {
    use tracing_subscriber::layer::SubscriberExt as _;
    let cap = busbar_kernel::test_support::warn_capture::WarnCapture::capturing_debug();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, f);
    cap.messages()
        .into_iter()
        .map(|m| m.trim_end().to_string())
        .collect()
}

/// The main log's lines while `binding` was bound with `key` and asked for one `mode` request
/// (`Passthrough`: `key` is the caller's, the lane binds none).
fn lines_in(binding: &StyleBinding, key: &str, mode: UpstreamCreds) -> Vec<String> {
    let own = match mode {
        UpstreamCreds::Own => key,
        UpstreamCreds::Passthrough => "",
    };
    main_log(|| {
        let ctx = SigningContext {
            host: SIGNING_HOST,
            canonical_uri: "/model/m/converse",
            body: b"{}",
            timestamp_epoch: 1_756_000_000,
            upstream_creds: mode,
        };
        bound(binding, own).headers_for(key, &ctx);
    })
}

/// [`lines_in`] for the lane's own credential.
fn lines(binding: &StyleBinding, key: &str) -> Vec<String> {
    lines_in(binding, key, UpstreamCreds::Own)
}

/// A signing credential whose session token no header value may carry logs, word for word, the
/// line the dialect's own signer logged in 1.5.5 — naming the declared service — and signs
/// nothing. A malformed credential without that token logged nothing then and logs nothing now.
#[test]
fn an_unsendable_session_token_logs_the_signers_own_line() {
    let signing = named_binding("bedrock", "static-twin-signing");
    assert_eq!(
        lines(&signing, "AKID:SECRET:TOK\r\nEN"),
        vec![
            "Bedrock lane session token contains a byte rejected by HeaderValue; skipping \
             signing to avoid a signed-but-absent x-amz-security-token header."
                .to_string()
        ]
    );
    for quiet in [
        "not-a-valid-key",
        "AKID\r\nINJECT:SECRET",
        "AKID:SECRET:CLEAN",
    ] {
        assert!(lines(&signing, quiet).is_empty(), "{quiet:?}");
    }
}

/// A bearer credential with a byte no header value may carry logs the bearer builder's 1.5.5
/// line, naming the protocol; a static custom header's and a credential-family table's keep
/// theirs, each naming the header it omitted.
#[test]
fn an_unpresentable_static_credential_logs_its_builders_own_line() {
    let bearer = named_binding("openai", "static-twin-bearer");
    assert_eq!(
        lines(&bearer, "bad\nkey"),
        vec![
            "authorization credential contains invalid header bytes (ASCII control \
             character); omitting auth header — upstream will reject with 401 \
             diag=BUSBAR-7087 protocol=static-twin-bearer"
                .to_string()
        ]
    );
    assert_eq!(
        lines(&named_binding("gemini", "static-twin-header"), "bad\nkey"),
        vec![
            "egress credential contains invalid header bytes (ASCII control character); \
             omitting auth header — upstream will reject with 401 diag=BUSBAR-4013 \
             header=x-goog-api-key"
                .to_string()
        ]
    );
    for (key, header) in [
        ("sk-ant-api03-bad\nkey", "x-api-key"),
        ("sk-ant-oat01-bad\ntoken", "authorization"),
    ] {
        assert_eq!(
            lines(&named_binding("anthropic", "static-twin-versioned"), key),
            vec![format!(
                "auth credential contains bytes invalid for an HTTP header value (e.g. a \
                 trailing newline); omitting the credential header — upstream will return \
                 401, check the key configuration protocol=static-twin-versioned \
                 header={header}"
            )]
        );
    }
    assert!(lines(&bearer, "good-key").is_empty());
}

/// A CALLER's credential no header value may carry logs its builder's line on the request that
/// presents it, as 1.5.5 built (and logged) a passthrough header per request; a signing
/// credential's unsendable token, likewise per request in either mode.
#[test]
fn a_callers_unpresentable_credential_logs_on_its_request() {
    assert_eq!(
        lines_in(
            &named_binding("openai", "static-twin-bearer"),
            "bad\nkey",
            UpstreamCreds::Passthrough
        ),
        vec![
            "authorization credential contains invalid header bytes (ASCII control \
             character); omitting auth header — upstream will reject with 401 \
             diag=BUSBAR-7087 protocol=static-twin-bearer"
                .to_string()
        ]
    );
    assert_eq!(
        lines_in(
            &named_binding("bedrock", "static-twin-signing"),
            "AKID:SECRET:TOK\r\nEN",
            UpstreamCreds::Passthrough
        )
        .len(),
        1
    );
}

/// A declared diagnostic outside the credential lines is written in 1.5.5's shape too: a mint that
/// failed, its catalog code as `diag` and the error as its trailing named value; a plugin's free
/// log record stays out of the main log.
#[test]
fn the_main_log_sink_writes_a_declared_diagnostic_in_its_one_five_five_shape() {
    use crate::root::loader::dispatch::{Diagnostic, EnvelopeSink, NoSink};
    let sink = crate::root::door_steps::MainLogSink(Arc::new(NoSink));
    let got = main_log(|| {
        sink.diag(Diagnostic {
            id: 2,
            name: b"BUSBAR-4016",
            severity: 1,
            text: b"OAuth token mint failed; will retry error=connect: refused (os error 111)",
        });
        sink.diag(Diagnostic {
            id: busbar_contract::abi::mechanism::call::DIAG_LOG,
            name: b"",
            severity: 1,
            text: b"the plugin's own record",
        });
    });
    assert_eq!(
        got,
        vec![
            "OAuth token mint failed; will retry diag=BUSBAR-4016 error=connect: refused (os \
             error 111)"
                .to_string()
        ]
    );
}
