// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::Arc;

use busbar_contract::abi::auth::{AuthPoint, AuthPoints, STYLE_NEEDS_HEADERS};
use busbar_contract::auth_calls::{AuthAxis, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::config::UpstreamCreds;
use busbar_contract::protocol::EgressAuthHeaders;
use busbar_contract::redacted::Secret;
use http::{HeaderName, HeaderValue};

use busbar_contract::protocol::SigningContext;

pub trait CredentialProvider: Send + Sync {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)>;

    fn is_ready(&self) -> bool {
        true
    }

    fn is_lane_constant(&self) -> bool {
        false
    }

    fn uses_key(&self) -> bool {
        true
    }
}

pub struct NoCredential;

impl CredentialProvider for NoCredential {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        Vec::new()
    }
    fn is_lane_constant(&self) -> bool {
        true
    }
}

pub struct DeclaredBuilder {
    pub headers_for: EgressAuthHeaders,

    pub lane_constant: bool,
}

impl CredentialProvider for DeclaredBuilder {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        (self.headers_for)(key, ctx)
            .into_iter()
            .filter_map(|(name, value)| {
                Some((
                    HeaderName::from_bytes(name.as_bytes()).ok()?,
                    HeaderValue::from_bytes(&value).ok()?,
                ))
            })
            .collect()
    }
    fn is_lane_constant(&self) -> bool {
        self.lane_constant
    }
}

/// WHAT A LANE'S CREDENTIAL IS BOUND UNDER: the style its provider resolves to, the style's
/// parameters, and what the lane's writer adds after the plugin's fields.
#[derive(Debug, Clone)]
pub struct StyleBinding {
    /// The style, an opaque word the serving plugin's tail states.
    pub style: String,
    /// Its parameters (one JSON object), as the plugin opens the binding with them.
    pub params: serde_json::Value,
    /// Whether the credential is the key the request presents (`false`: the plugin mints its own
    /// token from the credential, and ignores the per-request key in either mode).
    pub uses_key: bool,
    /// The dialect's own non-credential fields, written after the plugin's, in order.
    pub statics: &'static [(&'static str, &'static str)],
    /// The head fields the lane's writer sends that a style declaring `STYLE_NEEDS_HEADERS` reads
    /// (a signing dialect's `content-type`, which its signature covers), lent on every request.
    pub sent: Vec<(String, String)>,
}

pub struct BoundCredential {
    auth: Arc<dyn OutboundAuth>,
    handle: u64,
    points: AuthPoints,
    uses_key: bool,
    statics: &'static [(&'static str, &'static str)],

    headers: Vec<(Vec<u8>, Vec<u8>)>,
}

impl BoundCredential {
    fn lane_constant(&self) -> bool {
        self.uses_key && !self.points.has(AuthPoint::HeadBody)
    }
}

impl BoundCredential {
    fn request(&self, key: &str, ctx: &SigningContext) -> FieldsRequest {
        let point = if self.points.has(AuthPoint::HeadBody) {
            AuthPoint::HeadBody
        } else {
            AuthPoint::Head
        };
        let passthrough = matches!(ctx.upstream_creds, UpstreamCreds::Passthrough) && self.uses_key;
        FieldsRequest {
            point,
            body: (point == AuthPoint::HeadBody).then(|| ctx.body.to_vec()),
            method: b"POST".to_vec(),
            authority: ctx.host.to_string(),
            path: crate::observability::percent_decode(ctx.canonical_uri).into_bytes(),
            query: None,
            timestamp: ctx.timestamp_epoch,
            headers: self.headers.clone(),
            caller_credential: passthrough.then(|| Secret::new(key.as_bytes().to_vec())),
            extensions: Default::default(),
            ..FieldsRequest::default()
        }
    }
}

impl CredentialProvider for BoundCredential {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        let answered = self.auth.fields_now(self.handle, &self.request(key, ctx));

        let mut headers: Vec<(HeaderName, HeaderValue)> = match answered {
            Some(Fields::Ready(fields)) if !fields.iter().any(|f| f.require_secure) => fields
                .into_iter()
                .filter_map(|f| {
                    let mut value =
                        HeaderValue::from_bytes(f.value.expose(&crate::seal::lend())).ok()?;
                    value.set_sensitive(true);
                    Some((HeaderName::from_bytes(&f.name).ok()?, value))
                })
                .collect(),
            _ => Vec::new(),
        };
        headers.extend(
            self.statics
                .iter()
                .filter_map(|(k, v)| Some((k.parse().ok()?, v.parse().ok()?))),
        );
        headers
    }

    fn is_ready(&self) -> bool {
        self.auth.ready(self.handle)
    }

    fn is_lane_constant(&self) -> bool {
        self.lane_constant()
    }

    fn uses_key(&self) -> bool {
        self.uses_key
    }
}

pub fn bind(
    axis: &dyn AuthAxis,
    binding: &StyleBinding,
    credential: &[u8],
) -> Result<Arc<dyn CredentialProvider>, String> {
    let serving = axis
        .serving(&binding.style, &binding.params)?
        .ok_or_else(|| {
            format!(
                "no linked or dropped-in auth plugin serves the style '{}'",
                binding.style
            )
        })?;
    let handle = serving
        .auth
        .open_outbound(&binding.style, credential, &binding.params)?;
    let headers = if serving.flags & STYLE_NEEDS_HEADERS != 0 {
        binding
            .sent
            .iter()
            .map(|(n, v)| (n.as_bytes().to_vec(), v.as_bytes().to_vec()))
            .collect()
    } else {
        Vec::new()
    };
    Ok(Arc::new(BoundCredential {
        auth: serving.auth,
        handle,
        points: AuthPoints(serving.points),
        uses_key: binding.uses_key,
        statics: binding.statics,
        headers,
    }))
}

pub fn prebuild_auth(
    credential: &Arc<dyn CredentialProvider>,
    api_key: &str,
    signing_host: &str,
) -> Option<http::header::HeaderMap> {
    if !credential.is_lane_constant() {
        return None;
    }

    if api_key.is_empty() && credential.uses_key() {
        return Some(http::header::HeaderMap::new());
    }
    let ctx = SigningContext {
        host: signing_host,
        canonical_uri: "",
        body: &[],
        timestamp_epoch: 0,
        upstream_creds: UpstreamCreds::Own,
    };
    let mut headers = http::header::HeaderMap::new();
    for (name, value) in credential.headers_for(api_key, &ctx) {
        headers.insert(name, value);
    }
    Some(headers)
}

#[cfg(test)]
#[path = "tests/bound_credential_sensitive_tests.rs"]
mod sensitive_tests;
