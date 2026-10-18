// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIST-MODELS CATALOG (ARCHITECT ruling 2026-10-16, 3b C): `GET /v1/models` and
//! `GET /v1beta/models` are the plane's CATALOG claims, answered with no unit, and the plane renders
//! the kernel's names in the envelope of the dialect the request names, byte for byte as the
//! previous release answered (the oracle's `neutrality|models-empty|surface` cell holds the same
//! bytes on the served binary).

use busbar_contract::abi::plane::{CLAIM_CATALOG, CLAIM_EXACT};
use busbar_plane_llm::exchange::catalog::{render_listing, BETA_PATH, PATH};
use busbar_plane_llm::plane_door::claims;

fn head(pairs: &[(&str, &str)]) -> Vec<(Vec<u8>, Vec<u8>)> {
    pairs
        .iter()
        .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
        .collect()
}

fn body(path: &str, pairs: &[(&str, &str)]) -> String {
    let rendered = render_listing(path, &head(pairs), &[]);
    assert_eq!(rendered.status, 200, "{path} {pairs:?}");
    assert_eq!(
        rendered.fields,
        vec![("content-type".to_string(), b"application/json".to_vec())],
        "{path} {pairs:?}"
    );
    String::from_utf8(rendered.body).expect("a JSON body")
}

/// THE 1.5.5 BYTES, PER DIALECT, FOR AN EMPTY LIST: a request naming no dialect is answered in the
/// residual default's envelope; the anthropic fingerprint header and the gemini key header steer
/// the envelope on `/v1/models`; the `/v1beta` path names the gemini envelope. RED arm: a renderer
/// that ignored the fingerprint, or the path, answers the wrong envelope's bytes.
#[test]
fn an_empty_listing_is_the_previous_releases_bytes_in_each_dialect() {
    let openai = r#"{"data":[],"object":"list"}"#;
    let anthropic = r#"{"data":[],"first_id":null,"has_more":false,"last_id":null}"#;
    let gemini = r#"{"models":[]}"#;
    assert_eq!(body(PATH, &[]), openai);
    assert_eq!(
        body(PATH, &[("anthropic-version", "2023-06-01")]),
        anthropic
    );
    assert_eq!(body(PATH, &[("x-goog-api-key", "k")]), gemini);
    assert_eq!(body(BETA_PATH, &[]), gemini);
    // An incidental header steers nothing.
    assert_eq!(body(PATH, &[("x-unrelated", "1")]), openai);
}

/// THE NAMES ARE THE KERNEL'S, IN ITS ORDER: the plane renders exactly what it is handed.
#[test]
fn the_names_are_rendered_in_the_order_the_kernel_hands_them() {
    let names = ["pool-b".to_string(), "pool-a".to_string(), "m".to_string()];
    let rendered = render_listing(BETA_PATH, &head(&[]), &names);
    let value: serde_json::Value = serde_json::from_slice(&rendered.body).expect("JSON");
    let got: Vec<&str> = value["models"]
        .as_array()
        .expect("a models array")
        .iter()
        .map(|m| m["name"].as_str().expect("a name"))
        .collect();
    assert_eq!(got, ["models/pool-b", "models/pool-a", "models/m"]);
}

/// THE CATALOG ROUTES ARE CLAIMED: `GET` on each listing path, exact, flagged `CLAIM_CATALOG` so
/// the kernel answers it with no unit. RED arm: without the flag the kernel would mint a unit and
/// audit a listing the previous release never audited.
#[test]
fn the_listing_paths_are_exact_catalog_claims_on_get() {
    let all = claims();
    for path in [PATH, BETA_PATH] {
        let claim = all
            .iter()
            .find(|c| c.verb == "GET" && c.target == path)
            .unwrap_or_else(|| panic!("no claim for GET {path}"));
        assert_eq!(
            claim.flags & (CLAIM_EXACT | CLAIM_CATALOG),
            CLAIM_EXACT | CLAIM_CATALOG,
            "GET {path}"
        );
    }
    assert_eq!(
        all.iter().filter(|c| c.flags & CLAIM_CATALOG != 0).count(),
        2,
        "only the two listing paths are catalogs"
    );
}
