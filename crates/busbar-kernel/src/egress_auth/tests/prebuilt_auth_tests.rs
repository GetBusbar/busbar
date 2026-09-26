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
        upstream_creds: busbar_contract::config::UpstreamCreds::Own,
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
            busbar_contract::config::UpstreamCreds::Own,
            busbar_contract::config::UpstreamCreds::Passthrough,
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

// ══ THE LLM DIALECTS' DECLARED SCHEMES, PRESENTED (#83a SD-2b, SD-3; O7, S2-a) ═══════════════════
//
// Since SD-3 the LLM plane's dialects DECLARE their egress credential as data and carry no builder;
// the host presents it. The plane's own suite holds each declaration's scheme data, its signing
// dialect's host-to-region answers and its one remaining builder to the shared fixture
// `testing/plane-copies/declared-credentials.json` — the credential headers each dialect's own
// builder wrote, per credential, mode and request. This half holds the HOST to the same file:
// presented under schemes carrying exactly the fixture's data, this unit writes exactly those
// headers, in order. The two halves together are the byte-identity proof of the switch; neither
// suite reaches the other's crate.

mod declared_llm_schemes {
    use crate::egress_auth::resolve;
    use busbar_contract::config::UpstreamCreds;
    use busbar_contract::protocol::{
        CredentialFamily, CredentialHeader, EgressScheme, ProtocolDecl, SigningContext,
    };
    use std::sync::OnceLock;

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

    /// Every twin carries exactly the scheme data the fixture records for its dialect — the data
    /// the plane's own suite holds each real declaration to.
    #[test]
    fn each_twin_carries_the_fixture_scheme_of_its_dialect() {
        let schemes = fixture()["schemes"].as_object().expect("schemes");
        assert_eq!(schemes.len(), TWINS.len());
        for (dialect, data) in schemes {
            let scheme = twin(dialect).egress_scheme.expect("declared");
            assert_eq!(&describe(&scheme), data, "{dialect}");
        }
    }

    /// THE DIFFERENTIAL: presented under each dialect's declared scheme, this unit writes exactly the
    /// credential headers that dialect's own builder wrote, for every credential, mode and request in
    /// the fixture — and a static scheme is lane-constant, a signature never is.
    #[test]
    fn each_declared_scheme_presents_what_its_dialect_builder_wrote() {
        crate::proto::register_test_protocols(&TWINS.iter().collect::<Vec<_>>());
        let mut compared = 0usize;
        for row in fixture()["rows"].as_array().expect("rows") {
            let dialect = row["dialect"].as_str().expect("dialect");
            let decl = twin(dialect);
            let presenter = resolve(decl.name, None);
            assert_eq!(
                presenter.is_lane_constant(),
                matches!(decl.egress_scheme, Some(EgressScheme::Static { .. })),
                "{dialect}"
            );
            let key = String::from_utf8(hex(&row["key_hex"])).expect("utf-8 key");
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
            let presented: Vec<serde_json::Value> = presenter
                .headers_for(&key, &ctx)
                .into_iter()
                .map(|(k, v)| serde_json::json!([k.as_str(), hex::encode(v.as_bytes())]))
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

    fn signed(
        key: &str,
        host: &'static str,
        uri: &'static str,
        body: &'static [u8],
    ) -> Vec<(String, String)> {
        crate::proto::register_test_protocols(&TWINS.iter().collect::<Vec<_>>());
        let ctx = SigningContext {
            host,
            canonical_uri: uri,
            body,
            timestamp_epoch: 1_440_938_160, // 20150830T123600Z
            upstream_creds: UpstreamCreds::Own,
        };
        resolve(twin("bedrock").name, None)
            .headers_for(key, &ctx)
            .into_iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_string(),
                    v.to_str().expect("ascii").to_string(),
                )
            })
            .collect()
    }

    fn get(headers: &[(String, String)], name: &str) -> Option<String> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }

    // The signing dialect's SigV4 regressions, moved here from the plane's suite with the signer.

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

    // The static dialects' credential regressions, moved here from the plane's suites.

    #[test]
    fn a_static_credential_is_presented_verbatim_or_omitted_never_emptied() {
        crate::proto::register_test_protocols(&TWINS.iter().collect::<Vec<_>>());
        let ctx = SigningContext {
            host: "upstream.internal",
            canonical_uri: "/v1/chat/completions",
            body: b"{}",
            timestamp_epoch: 1_752_000_000,
            upstream_creds: UpstreamCreds::Own,
        };
        let present = |dialect: &str, key: &str| -> Vec<(String, String)> {
            resolve(twin(dialect).name, None)
                .headers_for(key, &ctx)
                .into_iter()
                .map(|(k, v)| {
                    (
                        k.as_str().to_string(),
                        v.to_str().expect("ascii").to_string(),
                    )
                })
                .collect()
        };
        for dialect in ["openai", "responses", "cohere"] {
            assert_eq!(
                present(dialect, "sk-test"),
                vec![("authorization".to_string(), "Bearer sk-test".to_string())],
                "{dialect}"
            );
            for bad in ["bad\nkey", "key\u{0000}bad"] {
                assert!(present(dialect, bad).is_empty(), "{dialect}: {bad:?}");
            }
        }
        assert_eq!(
            present("gemini", "AIzaSyValidKey123"),
            vec![(
                "x-goog-api-key".to_string(),
                "AIzaSyValidKey123".to_string()
            )]
        );
        for bad in ["bad\nkey", "key\u{0000}bad"] {
            assert!(present("gemini", bad).is_empty(), "gemini: {bad:?}");
        }
    }
}
