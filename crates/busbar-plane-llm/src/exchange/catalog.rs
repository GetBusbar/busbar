// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LIST-MODELS CATALOG, rendered: `GET /v1/models` and `GET /v1beta/models` answer the names the
//! kernel lists for the caller in the envelope of the dialect the request names (ARCHITECT ruling
//! 2026-10-16, 3b C: a catalog route is answered with no unit; the plane renders, the kernel lists).
//!
//! Several dialects list their models on the same noun, each with its own envelope. Their primary
//! surfaces are disjoint by path, so this is the one place a dialect is told apart by its PROTOCOL
//! FINGERPRINT: each dialect declares its fingerprint headers
//! ([`ProtocolDecl::list_models_fingerprint_headers`]) or the `/v1beta` path convention names it,
//! the tightest claim over those wins, and a request that names none is answered in the residual
//! default dialect. The previous release's rule, byte for byte: only a declared fingerprint steers
//! the envelope, never an incidental header.

use busbar_contract::protocol::ProtocolDecl;

use crate::codec::DECLS;

/// The path the catalog's detection reads for a `/v1beta` listing: the dialect convention that
/// names the model-scoped surface.
const BETA_SNIFF_PATH: &str = "/v1beta/models/";
/// The path the catalog's detection reads for every other listing.
const SNIFF_PATH: &str = "/v1/models";
/// The listing route of the `/v1beta` convention.
pub const BETA_PATH: &str = "/v1beta/models";
/// The listing route every dialect shares.
pub const PATH: &str = "/v1/models";

/// What the caller reads: the status, the head fields and the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelsCatalogAnswer {
    /// The status.
    pub status: u16,
    /// The head fields, in order.
    pub fields: Vec<(String, Vec<u8>)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The dialect a listing at `path` answers in, read off the request's head `fields` (lower-case
/// names, every value in arrival order): the fingerprint headers the dialects declare, each with
/// its first value, then the tightest claim over the sniff path, then the residual default.
#[must_use]
pub fn dialect(path: &str, fields: &[(Vec<u8>, Vec<u8>)]) -> Option<&'static ProtocolDecl> {
    let mut sniff: Vec<(&[u8], &[u8])> = Vec::new();
    for decl in DECLS.iter().filter(|d| d.codec.is_some()) {
        for name in decl.list_models_fingerprint_headers {
            let first = fields
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()));
            if let Some((_, value)) = first {
                if !sniff
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
                {
                    sniff.push((name.as_bytes(), value.as_slice()));
                }
            }
        }
    }
    let sniff_path = if path == BETA_PATH {
        BETA_SNIFF_PATH
    } else {
        SNIFF_PATH
    };
    DECLS
        .iter()
        .filter_map(|d| d.claim_over(sniff_path, &sniff).map(|s| (s, *d)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, d)| d)
        .or_else(|| DECLS.iter().copied().find(|d| d.residual_default))
}

/// RENDER the listing of `names` for a request at `path` with head `fields`: `200`, a JSON body in
/// the dialect's list envelope, `content-type: application/json`. A dialect that declares no
/// envelope answers an empty JSON object, which names no protocol and leaks no shape.
#[must_use]
pub fn render_listing(
    path: &str,
    fields: &[(Vec<u8>, Vec<u8>)],
    names: &[String],
) -> ModelsCatalogAnswer {
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let value = dialect(path, fields)
        .and_then(|d| d.models_list_envelope)
        .map_or_else(|| serde_json::json!({}), |build| build(&names));
    ModelsCatalogAnswer {
        status: 200,
        fields: vec![(
            "content-type".to_string(),
            busbar_contract::protocol::APPLICATION_JSON
                .as_bytes()
                .to_vec(),
        )],
        body: serde_json::to_vec(&value).unwrap_or_default(),
    }
}
