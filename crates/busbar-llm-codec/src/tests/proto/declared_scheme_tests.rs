// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DECLARED EGRESS SCHEMES, AS THIS PLANE DECLARES THEM (#83a SD-2b, SD-3; O7, S2-a). Five of
//! the six dialects state their egress credential as DECLARED DATA — a credential-family table, or a
//! SigV4 signature whose region is a pure function of the host — and carry no builder, so the lane
//! key is presented by the host's egress-auth unit and never passes through this plane. The sixth
//! still declares a builder, because that builder also writes a non-credential version header no
//! declaration field carries yet.
//!
//! The codec proves its own seam here and reaches no host: every declaration's scheme data, the
//! signing dialect's host-to-region answers and the remaining builder's credential headers are held
//! to the shared fixture `testing/plane-copies/declared-credentials.json` — the headers each
//! dialect's own builder wrote, per credential, mode and request. The host's suite holds its
//! egress-auth unit to the same file: presented under schemes carrying exactly this data, it writes
//! exactly those headers. Together the two suites are the byte-identity proof of the switch.

use busbar_contract::config::UpstreamCreds;
use busbar_contract::protocol::{CredentialHeader, EgressScheme, ProtocolDecl, SigningContext};

fn fixture() -> serde_json::Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../testing/plane-copies/declared-credentials.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture readable"))
        .expect("fixture is JSON")
}

fn presentation(h: &CredentialHeader) -> serde_json::Value {
    match h {
        CredentialHeader::Bearer => serde_json::json!({"bearer": true}),
        CredentialHeader::Raw { header, trim_start } => {
            serde_json::json!({"header": header, "trim_start": trim_start})
        }
    }
}

/// A declared scheme's DATA, in the fixture's spelling (the region function is compared by its
/// answers, below).
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

const DECLARED: [&ProtocolDecl; 5] = [
    &crate::openai_chat::DECL,
    &crate::openai_responses::DECL,
    &crate::cohere::DECL,
    &crate::gemini::DECL,
    &crate::bedrock::DECL,
];

/// Every dialect in this plane's declaration table states its egress credential — a declared
/// scheme, or (the one dialect whose builder also writes a version header) a builder — and the
/// fixture carries a scheme for every one of them, so a dialect added without either fails this
/// suite instead of passing it by omission.
#[test]
fn every_dialect_declaring_a_credential_builder_has_a_declared_twin() {
    let doc = fixture();
    for decl in crate::DECLS {
        assert!(
            decl.egress_scheme.is_some() || decl.egress_auth_headers.is_some(),
            "{} declares no egress credential",
            decl.name
        );
        assert!(
            doc["schemes"].get(decl.name).is_some(),
            "{} has no declared scheme in the shared fixture",
            decl.name
        );
    }
}

/// #83a S2-a: the five dialects whose credential is auth and nothing else DECLARE their scheme and
/// carry no builder, so no credential ever passes through this plane on their lanes — and the scheme
/// each declares is exactly the data the host's suite presents.
#[test]
fn the_declared_dialects_carry_a_scheme_and_no_builder() {
    let doc = fixture();
    for decl in DECLARED {
        let scheme = decl
            .egress_scheme
            .unwrap_or_else(|| panic!("{} declares no scheme", decl.name));
        assert!(
            decl.egress_auth_headers.is_none(),
            "{} still carries a credential builder",
            decl.name
        );
        assert!(!decl.egress_auth_lane_constant, "{}", decl.name);
        assert_eq!(
            describe(&scheme),
            doc["schemes"][decl.name],
            "{}: the declared scheme differs from the shared fixture",
            decl.name
        );
    }
}

/// The signing dialect's region is a declared pure function of the host: it answers every host in the
/// fixture as recorded, and a host that names no region leaves the declared `us-east-1` default.
#[test]
fn the_declared_region_answers_every_fixture_host() {
    let Some(EgressScheme::SigV4 { region_of_host, .. }) = crate::bedrock::DECL.egress_scheme
    else {
        panic!("the signing dialect declares a SigV4 scheme");
    };
    for r in fixture()["regions"].as_array().expect("regions") {
        let host = r["host"].as_str().expect("host");
        assert_eq!(
            region_of_host(host),
            r["region"].as_str(),
            "region of {host}"
        );
    }
}

/// THE REMAINING BUILDER: the dialect that still declares one writes, beside its version header,
/// exactly the credential headers the fixture records for it — the headers the host presents for its
/// declared twin.
#[test]
fn the_remaining_builder_writes_the_fixture_credential_headers() {
    let builder = crate::anthropic::DECL
        .egress_auth_headers
        .expect("the anthropic dialect still declares its builder");
    let hex = |v: &serde_json::Value| crate::hex::decode(v.as_str().expect("hex")).expect("hex");
    let mut compared = 0usize;
    for row in fixture()["rows"].as_array().expect("rows") {
        if row["dialect"] != "anthropic" {
            continue;
        }
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
        let written: Vec<serde_json::Value> = builder(&key, &ctx)
            .into_iter()
            .filter(|(k, _)| k.as_str() != "anthropic-version")
            .map(|(k, v)| serde_json::json!([k.as_str(), crate::hex::encode(v.as_bytes())]))
            .collect();
        assert_eq!(
            serde_json::Value::Array(written),
            row["headers"],
            "key {key:?}, mode {}",
            row["mode"]
        );
        compared += 1;
    }
    assert!(compared > 0);
}
