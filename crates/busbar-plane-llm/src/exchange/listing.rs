// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MODEL LISTING, rendered by the plane (ARCHITECT RULING D, 2026-10-07; spec Part 2 #49, the
//! design's connections, where every refusal's bytes are its claimant's), sans I/O. The kernel keeps `GET /v1/models` and `GET /v1beta/models` and
//! computes the caller's visible names itself (its governance); it hands them to this plane's
//! `serve` as a listing render (`ServeIn::listing`), and the plane answers the reply in the dialect
//! its own rule picks, so the kernel names and picks no dialect.
//!
//! THE RULE is the previous release's, unchanged (v1.5.5 `list_models_dialect`): several dialects
//! put their list-models endpoint on one noun, each with its own envelope, so a caller is told
//! apart by PROTOCOL FINGERPRINT. Each dialect states its fingerprint fields
//! (`ProtocolDecl::list_models_fingerprint_headers`); the detection fold runs over those fields
//! alone (an incidental field on a list-models GET never steers the envelope) and the path
//! convention (a `/v1beta` path reads as the gemini discovery path); the first dialect whose
//! fingerprint holds renders, and anything unmatched falls to the residual default dialect.

use busbar_contract::protocol::HeadFields;

use crate::codec::DECLS;
use crate::exchange::arrive::detect;

/// The listing's content type, as the previous release's JSON answer carried it.
pub const CONTENT_TYPE: (&str, &str) = ("content-type", "application/json");

/// One rendered listing: the caller's whole reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listing {
    /// The status.
    pub status: u16,
    /// The head fields.
    pub fields: Vec<(&'static str, &'static str)>,
    /// The body.
    pub body: Vec<u8>,
}

/// The path the fingerprint fold reads for `target`: a `/v1beta` listing reads as the gemini
/// discovery path (`/v1beta/models/`), any other as `/v1/models` (the previous release's two
/// routes, each sniffed under its own path).
#[must_use]
pub fn sniff_path(target: &str) -> &'static str {
    let path = target.split_once('?').map_or(target, |(p, _)| p);
    if path == "/v1beta" || path.starts_with("/v1beta/") {
        "/v1beta/models/"
    } else {
        "/v1/models"
    }
}

/// The dialect a listing on `target` with the caller's head `fields` renders in: the detection
/// fold over every dialect's declared fingerprint fields alone and the sniff path, else the
/// residual default dialect; `None` when no dialect is either.
#[must_use]
pub fn dialect_of(target: &str, fields: HeadFields<'_>) -> Option<&'static str> {
    let mut sniff: Vec<(&[u8], &[u8])> = Vec::new();
    for decl in DECLS {
        for name in decl.list_models_fingerprint_headers {
            if let Some(&(_, value)) = fields
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
            {
                if !sniff
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
                {
                    sniff.push((name.as_bytes(), value));
                }
            }
        }
    }
    detect(sniff_path(target), &sniff)
        .or_else(|| DECLS.iter().find(|d| d.residual_default).map(|d| d.name))
}

/// THE LISTING for `names` (the kernel's, in its order): `200`, JSON, in the envelope of the
/// dialect [`dialect_of`] picks. A dialect that states no envelope answers an empty JSON object,
/// which names no dialect and leaks no shape (the previous release's arm for a build with none).
#[must_use]
pub fn render(target: &str, fields: HeadFields<'_>, names: &[&str]) -> Listing {
    let envelope = dialect_of(target, fields)
        .and_then(|name| DECLS.iter().find(|d| d.name == name))
        .and_then(|d| d.models_list_envelope);
    let value = match envelope {
        Some(build) => build(names),
        None => serde_json::Value::Object(serde_json::Map::new()),
    };
    Listing {
        status: 200,
        fields: vec![CONTENT_TYPE],
        body: serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec()),
    }
}
