// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARED-SCHEME DIFFERENTIAL (#83a SD-2b, SD-3; O7, S2-a): every dialect's egress credential,
//! stated as DECLARED DATA — a credential-family table, or a SigV4 signature whose region is a pure
//! function of the host — and presented by the kernel's egress-auth unit under a teller-minted
//! `Grant<Sign>`, writes byte-for-byte the credential headers the dialect's own builder wrote, in the
//! same order, for every key, credential mode and request the vectors below cover. Non-credential
//! static headers a builder also emits (a version header) are not auth and stay in the dialect
//! writer, so they are set aside before the comparison.
//!
//! Since SD-3 five of the six dialects DECLARE their scheme on their real declaration and carry no
//! builder, so each is presented exactly as its lanes are and compared against the builder it
//! replaced, kept here verbatim as the REFERENCE (the shared bearer and custom-header builders are
//! still live host-side; the dialect's own SigV4 signer is reproduced below). The sixth still
//! declares a builder, because its builder also writes a non-credential version header no
//! declaration field carries yet; its scheme is proven here on a declared twin against that builder.

use busbar_contract::config::UpstreamCreds;
use busbar_substrate_values::proto::{
    CredentialFamily, CredentialHeader, EgressAuthHeaders, EgressScheme, ProtocolDecl,
    SigningContext,
};

/// Hosts the signing dialect derives a region for, plus one it derives none for (the declaration's
/// default then applies).
const SIGNING_HOSTS: &[&str] = &[
    "bedrock-runtime.us-west-2.amazonaws.com",
    "bedrock-runtime-fips.eu-central-1.amazonaws.com",
    "upstream.internal",
];

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

static TWIN_ANTHROPIC: ProtocolDecl = ProtocolDecl {
    egress_scheme: Some(EgressScheme::Static {
        families: ANTHROPIC_FAMILIES,
        own: CredentialHeader::Raw {
            header: "x-api-key",
            trim_start: false,
        },
        passthrough: CredentialHeader::Bearer,
    }),
    ..ProtocolDecl::named("declared-twin-anthropic")
};

/// The builder each declared dialect used to carry, as the reference its presentation must match.
fn reference_openai(
    key: &str,
    _ctx: &SigningContext,
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    busbar_kernel::proto::bearer_auth_headers("openai", key)
}
fn reference_responses(
    key: &str,
    _ctx: &SigningContext,
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    busbar_kernel::proto::bearer_auth_headers("responses", key)
}
fn reference_cohere(
    key: &str,
    _ctx: &SigningContext,
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    busbar_kernel::proto::bearer_auth_headers("cohere", key)
}
fn reference_gemini(
    key: &str,
    _ctx: &SigningContext,
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    busbar_kernel::proto::api_key_auth_headers("x-goog-api-key", key)
}

/// The signing dialect's own SigV4 builder, as it stood when the dialect declared it (verbatim but
/// for paths): the `ACCESS:SECRET[:SESSION]` lane key, the region from the host (default
/// `us-east-1`), service `bedrock`, a `POST` over the JSON content type, the host and the body.
fn reference_bedrock_signer(
    key: &str,
    ctx: &SigningContext,
) -> Vec<(http::HeaderName, http::HeaderValue)> {
    let mut parts = key.splitn(3, ':');
    let (access, secret, token) = match (parts.next(), parts.next(), parts.next()) {
        (Some(a), Some(s), tok) if !a.is_empty() && !s.is_empty() => (a, s, tok),
        _ => return vec![],
    };
    let region = match crate::bedrock::derive_sigv4_region(ctx.host) {
        Some(r) => r,
        None => {
            tracing::warn!(host = %ctx.host, "could not derive AWS region from Bedrock endpoint host; defaulting SigV4 scope to us-east-1 (set a bedrock-runtime[-fips].<region>.amazonaws.com host)");
            "us-east-1"
        }
    };
    let service = "bedrock";
    let (amzdate, datestamp) = busbar_kernel::sigv4::format_amz_time(ctx.timestamp_epoch);
    let payload_hash = busbar_kernel::sigv4::sha256_hex(ctx.body);
    let token_header = match token {
        Some(t) => match http::HeaderValue::from_str(t) {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!("Bedrock lane session token contains a byte rejected by HeaderValue; skipping signing to avoid a signed-but-absent x-amz-security-token header.");
                return vec![];
            }
        },
        None => None,
    };
    let mut signed = vec![
        (
            "content-type".to_string(),
            busbar_kernel::proxy::APPLICATION_JSON.to_string(),
        ),
        ("host".to_string(), ctx.host.to_string()),
        (
            busbar_kernel::sigv4::X_AMZ_CONTENT_SHA256.to_string(),
            payload_hash.clone(),
        ),
        (
            busbar_kernel::sigv4::X_AMZ_DATE.to_string(),
            amzdate.clone(),
        ),
    ];
    if let Some(t) = token {
        signed.push((
            busbar_kernel::sigv4::X_AMZ_SECURITY_TOKEN.to_string(),
            t.to_string(),
        ));
    }
    let (signature, signed_headers) = busbar_kernel::sigv4::sign_v4(
        secret,
        region,
        service,
        "POST",
        ctx.canonical_uri,
        "",
        &signed,
        &payload_hash,
        &amzdate,
        &datestamp,
    );
    let authorization = {
        use busbar_kernel::sigv4::{SIGV4_ALGORITHM, SIGV4_TERMINATION};
        format!(
            "{SIGV4_ALGORITHM} Credential={access}/{datestamp}/{region}/{service}/{SIGV4_TERMINATION}, SignedHeaders={signed_headers}, Signature={signature}"
        )
    };
    let (Ok(authorization_val), Ok(amzdate_val), Ok(payload_hash_val)) = (
        http::HeaderValue::from_str(&authorization),
        http::HeaderValue::from_str(&amzdate),
        http::HeaderValue::from_str(&payload_hash),
    ) else {
        return vec![];
    };
    let mut out = vec![
        (
            http::HeaderName::from_static(busbar_kernel::proto::HDR_AUTHORIZATION),
            authorization_val,
        ),
        (
            http::HeaderName::from_static(busbar_kernel::sigv4::X_AMZ_DATE),
            amzdate_val,
        ),
        (
            http::HeaderName::from_static(busbar_kernel::sigv4::X_AMZ_CONTENT_SHA256),
            payload_hash_val,
        ),
    ];
    if let Some(v) = token_header {
        out.push((
            http::HeaderName::from_static(busbar_kernel::sigv4::X_AMZ_SECURITY_TOKEN),
            v,
        ));
    }
    out
}

/// One comparison: the declaration presented, the builder it must reproduce, whether that builder was
/// lane-constant, and the non-credential headers that builder also wrote.
struct Case {
    presented: &'static ProtocolDecl,
    reference: EgressAuthHeaders,
    lane_constant: bool,
    not_auth: &'static [&'static str],
}

fn cases() -> [Case; 6] {
    [
        Case {
            presented: &crate::openai_chat::DECL,
            reference: reference_openai,
            lane_constant: true,
            not_auth: &[],
        },
        Case {
            presented: &crate::openai_responses::DECL,
            reference: reference_responses,
            lane_constant: true,
            not_auth: &[],
        },
        Case {
            presented: &crate::cohere::DECL,
            reference: reference_cohere,
            lane_constant: true,
            not_auth: &[],
        },
        Case {
            presented: &crate::gemini::DECL,
            reference: reference_gemini,
            lane_constant: true,
            not_auth: &[],
        },
        Case {
            presented: &TWIN_ANTHROPIC,
            reference: crate::anthropic::DECL
                .egress_auth_headers
                .expect("the anthropic dialect still declares its builder"),
            lane_constant: crate::anthropic::DECL.egress_auth_lane_constant,
            not_auth: &["anthropic-version"],
        },
        Case {
            presented: &crate::bedrock::DECL,
            reference: reference_bedrock_signer,
            lane_constant: false,
            not_auth: &[],
        },
    ]
}

/// Static keys: every credential family, the leading-whitespace case the family table trims, and the
/// bytes a header value may and may not carry.
const STATIC_KEYS: &[&str] = &[
    "sk-test-123",
    "sk-ant-api03-abc",
    "  sk-ant-api03-abc",
    "sk-ant-oat01-abc",
    " sk-ant-oat01-abc",
    "opaque-caller-token",
    "",
    "sk\tkey",
    "klucz-\u{142}-\u{e9}",
    "sk\r\ninjected",
    "sk\u{0}key",
    "sk\u{7f}key",
];

/// Signing credentials: plain, with a session token (colons kept), and every refusal.
const SIGNING_KEYS: &[&str] = &[
    "AKIDEXAMPLE:wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
    "AKID:SECRET:TOKEN:with:colons",
    "AKID:SECRET:",
    "AKID:SECRET:bad\ntoken",
    "AKID",
    ":SECRET",
    "",
];

fn contexts(host: &'static str) -> Vec<SigningContext<'static>> {
    let mut out = Vec::new();
    for upstream_creds in [UpstreamCreds::Own, UpstreamCreds::Passthrough] {
        for (canonical_uri, body, timestamp_epoch) in [
            (
                "/model/m/converse",
                &br#"{"messages":[]}"#[..],
                1_756_000_000,
            ),
            ("/model/vendor.m%3A0/invoke", &b""[..], 0),
        ] {
            out.push(SigningContext {
                host,
                canonical_uri,
                body,
                timestamp_epoch,
                upstream_creds,
            });
        }
    }
    out
}

fn as_pairs(headers: Vec<(http::HeaderName, http::HeaderValue)>) -> Vec<(String, Vec<u8>)> {
    headers
        .into_iter()
        .map(|(k, v)| (k.as_str().to_string(), v.as_bytes().to_vec()))
        .collect()
}

/// Every dialect in this plane's declaration table states its egress credential — a declared scheme,
/// or (the one dialect whose builder also writes a version header) a builder with a declared twin —
/// and every one of them is compared below, so a dialect added without either fails this suite
/// instead of passing it by omission.
#[test]
fn every_dialect_declaring_a_credential_builder_has_a_declared_twin() {
    let compared: Vec<&str> = cases()
        .iter()
        .map(|c| c.presented.name)
        .chain(["anthropic"])
        .collect();
    for decl in crate::DECLS {
        assert!(
            decl.egress_scheme.is_some() || decl.egress_auth_headers.is_some(),
            "{} declares no egress credential",
            decl.name
        );
        assert!(
            compared.contains(&decl.name),
            "{} has no declared-scheme comparison",
            decl.name
        );
    }
}

/// #83a S2-a: the five dialects whose credential is auth and nothing else DECLARE their scheme and
/// carry no builder, so no credential ever passes through this plane on their lanes.
#[test]
fn the_declared_dialects_carry_a_scheme_and_no_builder() {
    for decl in [
        &crate::openai_chat::DECL,
        &crate::openai_responses::DECL,
        &crate::cohere::DECL,
        &crate::gemini::DECL,
        &crate::bedrock::DECL,
    ] {
        assert!(
            decl.egress_scheme.is_some(),
            "{} declares no scheme",
            decl.name
        );
        assert!(
            decl.egress_auth_headers.is_none(),
            "{} still carries a credential builder",
            decl.name
        );
    }
}

/// THE DIFFERENTIAL: the kernel presenting each declaration writes exactly the credential headers
/// the builder it replaced writes, and agrees with it on whether the credential is lane-constant.
#[test]
fn each_declared_scheme_presents_what_its_dialect_builder_writes() {
    crate::ensure_test_protocols_registered();
    busbar_substrate_values::proto::register_test_protocols(&[&TWIN_ANTHROPIC]);
    let mut compared = 0usize;
    for case in cases() {
        let presenter = busbar_kernel::egress_auth::resolve(case.presented.name, None);
        assert_eq!(
            presenter.is_lane_constant(),
            case.lane_constant,
            "{}: the declared scheme and the builder disagree on lane-constancy",
            case.presented.name
        );
        let signing = matches!(
            case.presented.egress_scheme,
            Some(EgressScheme::SigV4 { .. })
        );
        let (keys, hosts) = if signing {
            (SIGNING_KEYS, SIGNING_HOSTS)
        } else {
            (STATIC_KEYS, &["upstream.internal"][..])
        };
        for &host in hosts {
            for ctx in contexts(host) {
                for &key in keys {
                    let mut expected = as_pairs((case.reference)(key, &ctx));
                    expected.retain(|(k, _)| !case.not_auth.contains(&k.as_str()));
                    let presented = as_pairs(presenter.headers_for(key, &ctx));
                    assert_eq!(
                        presented, expected,
                        "{}: key {key:?}, host {host}, mode {:?}, uri {}",
                        case.presented.name, ctx.upstream_creds, ctx.canonical_uri
                    );
                    compared += 1;
                }
            }
        }
    }
    assert!(compared > 0);
}
