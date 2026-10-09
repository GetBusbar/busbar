// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LANE'S CREDENTIAL, BOUND BY THE AUTH PLUGIN THAT SERVES ITS STYLE (BUSBAR-1.6.0.md THE DESIGN
//! §6 steps 2-5, "Auth points and guest lists" step 5; P2 D1, the auth split).
//!
//! The kernel holds no auth style. A lane's credential is opened as a binding on the auth plugin
//! whose tail states the lane's style ([`busbar_contract::auth_calls::AuthAxis::serving`], then
//! `open_outbound`), and the plugin keeps the binding and its cache (a header built once, a minted
//! token refreshed ahead of expiry on `tick`, a SigV4 day key); the kernel keeps only the handle.
//! For every request the lane's writer asks [`CredentialProvider::headers_for`], which is ONE
//! memory-ABI call (`fields`) to that plugin; a binding whose answer cannot vary per request (a
//! style that presents the key over the head alone) is asked once, at boot, as the lane froze a
//! static header before ([`prebuild_auth`]). The writer then adds the dialect's own static fields.
//!
//! [`CredentialProvider`] is the shape the request path asks; this module holds no credential
//! logic of its own: a binding no plugin serves is [`NoCredential`] (no auth header, so the
//! upstream answers 401, the fail-closed answer), and a protocol that declares its own builder
//! ([`busbar_contract::protocol::ProtocolDecl::egress_auth_headers`]) is that builder.

use std::sync::Arc;

use busbar_contract::abi::auth::{AuthPoint, AuthPoints, STYLE_NEEDS_HEADERS};
use busbar_contract::auth_calls::{AuthAxis, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::config::UpstreamCreds;
use busbar_contract::protocol::EgressAuthHeaders;
use busbar_contract::redacted::Redacted;
use http::{HeaderName, HeaderValue};

use crate::proto::SigningContext;

/// Produces the outbound auth headers for a single upstream request.
///
/// `key` is the per-request credential the caller resolved — the lane's configured key for
/// [`UpstreamCreds::Own`], or the forwarded caller token for `Passthrough`. A self-minting
/// credential ignores `key`. `ctx` carries the host / canonical-uri / body / timestamp a signer
/// needs, plus the `Own | Passthrough` mode.
pub trait CredentialProvider: Send + Sync {
    /// The headers, in order.
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)>;

    /// Whether this credential can currently produce a usable auth header. A self-minting
    /// credential is NOT ready before its first mint completes — `headers_for` returns no header
    /// then, so an active health probe would send an unauthenticated request and a guaranteed 401
    /// could HardDown-park a healthy lane. The prober consults this to skip a not-yet-minted lane
    /// until its token is live. Default: always ready.
    fn is_ready(&self) -> bool {
        true
    }

    /// Whether `headers_for` is LANE-CONSTANT: a pure function of the resolved credential string
    /// and the `Own`/`Passthrough` mode. `true` lets the boot path prebuild this lane's exact auth
    /// header set once ([`prebuild_auth`]). Default `false` — fail closed.
    fn is_lane_constant(&self) -> bool {
        false
    }

    /// Whether this credential builds its header FROM the `key` it is handed. True for every static
    /// and signing style; false for a self-minting credential, which ignores `key` entirely and
    /// presents its own minted token. Callers use this to decide that an EMPTY key means "there is
    /// no credential to present, so send no auth header". Default: true.
    fn uses_key(&self) -> bool {
        true
    }
}

/// Fail-closed credential: emits no auth header (the upstream answers 401).
pub struct NoCredential;

impl CredentialProvider for NoCredential {
    fn headers_for(&self, _key: &str, _ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        Vec::new()
    }
    fn is_lane_constant(&self) -> bool {
        true // constantly nothing
    }
}

/// A credential a PROTOCOL DECLARED its own builder for
/// ([`busbar_contract::protocol::ProtocolDecl::egress_auth_headers`]): the plane's builder, behind
/// the one shape the request path asks.
pub struct DeclaredBuilder {
    /// The plane's builder.
    pub headers_for: EgressAuthHeaders,
    /// Whether it reads only `(key, mode)` (`ProtocolDecl::egress_auth_lane_constant`).
    pub lane_constant: bool,
}

impl CredentialProvider for DeclaredBuilder {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        (self.headers_for)(key, ctx)
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

/// One lane's credential, bound on the auth plugin serving its style: the handle `open_outbound`
/// answered, the points the style is called at, and the sent head fields it reads.
pub struct BoundCredential {
    auth: Arc<dyn OutboundAuth>,
    handle: u64,
    points: AuthPoints,
    uses_key: bool,
    statics: &'static [(&'static str, &'static str)],
    /// The binding's `sent` fields when the style declares `STYLE_NEEDS_HEADERS`; empty otherwise.
    headers: Vec<(Vec<u8>, Vec<u8>)>,
}

impl BoundCredential {
    /// Whether the plugin's answer for this binding in `Own` mode is a pure function of the bound
    /// credential: a style that presents the key (it does not mint) and reads only the head (it
    /// does not sign the body). The lane's writer then asks once, at boot ([`prebuild_auth`]),
    /// exactly as it froze a static scheme's header before.
    fn lane_constant(&self) -> bool {
        self.uses_key && !self.points.has(AuthPoint::HeadBody)
    }
}

impl BoundCredential {
    /// The one `fields` request for `ctx`: a POST of the body to its canonical path (the request a
    /// lane's writer signs), at the style's request point, with the sent head fields a style that
    /// needs them reads, and the caller's credential for a passthrough request on a style that
    /// presents the key.
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
            path: ctx.canonical_uri.as_bytes().to_vec(),
            query: None,
            timestamp: ctx.timestamp_epoch,
            headers: self.headers.clone(),
            caller_credential: passthrough.then(|| Redacted::new(key.as_bytes().to_vec())),
            ..FieldsRequest::default()
        }
    }
}

impl CredentialProvider for BoundCredential {
    fn headers_for(&self, key: &str, ctx: &SigningContext) -> Vec<(HeaderName, HeaderValue)> {
        // ONE CALL, on the spot: a cached header, a fresh minted token or a signature answers in
        // place. A plugin that cannot answer now (a token refreshing after it expired) presents
        // nothing for this request, as 1.5.5's lane did while its refresh was failing.
        let answered = self.auth.fields_now(self.handle, &self.request(key, ctx));
        let mut headers: Vec<(HeaderName, HeaderValue)> = match answered {
            Some(Fields::Ready(fields)) => fields
                .into_iter()
                .filter_map(|f| {
                    Some((
                        HeaderName::from_bytes(&f.name).ok()?,
                        HeaderValue::from_bytes(f.value.expose_secret()).ok()?,
                    ))
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

/// BIND `credential` under `binding` on the auth plugin `axis` reaches for the style (THE DESIGN
/// §6 step 3).
///
/// # Errors
///
/// No linked or dropped-in auth plugin serves the style, or the serving plugin refused the
/// binding (its own words).
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

/// Prebuild a lane's `Own`-mode egress auth headers at boot, or `None` when the credential is not
/// lane-constant. THE SAME CALL the request path makes — `headers_for` with an `Own`-mode context —
/// so the map a request clones is byte-identical to what it would have built live.
pub fn prebuild_auth(
    credential: &Arc<dyn CredentialProvider>,
    api_key: &str,
    signing_host: &str,
) -> Option<http::header::HeaderMap> {
    if !credential.is_lane_constant() {
        return None;
    }
    // NO CREDENTIAL ⇒ NO AUTH HEADER: an empty key means there is nothing to present (a keyless
    // local upstream); the same rule is applied per request by the lane's writer.
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
    Some(crate::proto::convert_headers(
        credential.headers_for(api_key, &ctx),
    ))
}
