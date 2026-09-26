// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARED-SCHEME DIFFERENTIAL (#83a SD-2b; O7, S2-a): every dialect's egress credential,
//! stated as DECLARED DATA — a credential-family table, or a SigV4 signature whose region is a pure
//! function of the host — and presented by the kernel's egress-auth unit under a teller-minted
//! `Grant<Sign>`, writes byte-for-byte the credential headers the dialect's own builder writes
//! today, in the same order, for every key, credential mode and request the vectors below cover.
//! Non-credential static headers a builder also emits (a version header) are not auth and stay in
//! the dialect writer, so they are set aside before the comparison.
//!
//! Each declared twin is registered under its own name beside the real declaration, and resolved
//! through `busbar_kernel::egress_auth::resolve` exactly as a lane is — so the path proven is the
//! path a lane takes once a dialect declares its scheme.

use busbar_contract::config::UpstreamCreds;
use busbar_substrate_values::proto::{
    CredentialFamily, CredentialHeader, EgressScheme, ProtocolDecl, SigningContext,
};

/// The signing twin's region function: the dotted label after the endpoint's service label, the
/// same label the dialect writer derives for every host [`SIGNING_HOSTS`] lists.
fn region_after_service_label(host: &str) -> Option<&str> {
    let labels: Vec<&str> = host.split('.').collect();
    labels
        .iter()
        .position(|l| l.starts_with("bedrock"))
        .and_then(|i| labels.get(i + 1).copied())
        .filter(|l| l.ends_with(|c: char| c.is_ascii_digit()))
}

/// Hosts the signing dialect's writer derives a region for, plus one it derives none for (the
/// writer's and the declaration's default then apply).
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

/// The declared twins: each dialect's scheme as data, beside the declaration whose builder it must
/// reproduce, and the non-credential headers that builder also writes.
struct Twin {
    real: &'static ProtocolDecl,
    declared: &'static ProtocolDecl,
    not_auth: &'static [&'static str],
}

static TWIN_OPENAI: ProtocolDecl = ProtocolDecl {
    egress_scheme: Some(EgressScheme::bearer()),
    ..ProtocolDecl::named("declared-twin-openai")
};
static TWIN_RESPONSES: ProtocolDecl = ProtocolDecl {
    egress_scheme: Some(EgressScheme::bearer()),
    ..ProtocolDecl::named("declared-twin-responses")
};
static TWIN_COHERE: ProtocolDecl = ProtocolDecl {
    egress_scheme: Some(EgressScheme::bearer()),
    ..ProtocolDecl::named("declared-twin-cohere")
};
static TWIN_GEMINI: ProtocolDecl = ProtocolDecl {
    egress_scheme: Some(EgressScheme::header("x-goog-api-key")),
    ..ProtocolDecl::named("declared-twin-gemini")
};
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
static TWIN_BEDROCK: ProtocolDecl = ProtocolDecl {
    egress_scheme: Some(EgressScheme::SigV4 {
        service: "bedrock",
        region_of_host: region_after_service_label,
        default_region: "us-east-1",
        content_type: "application/json",
    }),
    ..ProtocolDecl::named("declared-twin-bedrock")
};

fn twins() -> [Twin; 6] {
    [
        Twin {
            real: &crate::openai_chat::DECL,
            declared: &TWIN_OPENAI,
            not_auth: &[],
        },
        Twin {
            real: &crate::openai_responses::DECL,
            declared: &TWIN_RESPONSES,
            not_auth: &[],
        },
        Twin {
            real: &crate::cohere::DECL,
            declared: &TWIN_COHERE,
            not_auth: &[],
        },
        Twin {
            real: &crate::gemini::DECL,
            declared: &TWIN_GEMINI,
            not_auth: &[],
        },
        Twin {
            real: &crate::anthropic::DECL,
            declared: &TWIN_ANTHROPIC,
            not_auth: &["anthropic-version"],
        },
        Twin {
            real: &crate::bedrock::DECL,
            declared: &TWIN_BEDROCK,
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

/// Every dialect in this plane's declaration table has a declared twin here, so a dialect added
/// without one fails this suite instead of passing it by omission.
#[test]
fn every_dialect_declaring_a_credential_builder_has_a_declared_twin() {
    let twinned: Vec<&str> = twins().iter().map(|t| t.real.name).collect();
    for decl in crate::DECLS {
        if decl.egress_auth_headers.is_some() {
            assert!(
                twinned.contains(&decl.name),
                "{} has no declared twin",
                decl.name
            );
        }
    }
}

/// THE DIFFERENTIAL: the kernel presenting each declared twin writes exactly the credential headers
/// the dialect's builder writes, and agrees with it on whether the credential is lane-constant.
#[test]
fn each_declared_scheme_presents_what_its_dialect_builder_writes() {
    let decls: Vec<&'static ProtocolDecl> = twins().iter().map(|t| t.declared).collect();
    busbar_substrate_values::proto::register_test_protocols(&decls);
    let mut compared = 0usize;
    for twin in twins() {
        let builder = twin
            .real
            .egress_auth_headers
            .expect("the real dialect declares a builder");
        let presenter = busbar_kernel::egress_auth::resolve(twin.declared.name, None);
        assert_eq!(
            presenter.is_lane_constant(),
            twin.real.egress_auth_lane_constant,
            "{}: the declared scheme and the builder disagree on lane-constancy",
            twin.real.name
        );
        let signing = matches!(
            twin.declared.egress_scheme,
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
                    let mut expected = as_pairs(builder(key, &ctx));
                    expected.retain(|(k, _)| !twin.not_auth.contains(&k.as_str()));
                    let presented = as_pairs(presenter.headers_for(key, &ctx));
                    assert_eq!(
                        presented, expected,
                        "{}: key {key:?}, host {host}, mode {:?}, uri {}",
                        twin.real.name, ctx.upstream_creds, ctx.canonical_uri
                    );
                    compared += 1;
                }
            }
        }
    }
    assert!(compared > 0);
}
