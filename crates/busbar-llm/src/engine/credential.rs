// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LANE'S CREDENTIAL, BOUND ON THE AUTH PLUGIN SERVING ITS STYLE (BUSBAR-1.6.0.md THE DESIGN §6
//! steps 2-3; P2 D1, the auth split): the provider's `auth:` override, else the lane dialect's
//! declared egress scheme, read as the style the binding is opened under and that style's
//! parameters. The plugin holds the credential, its cache and its bytes; this plane holds the
//! handle (`busbar_kernel::bound_credential`).

use std::sync::Arc;

use busbar_contract::protocol::{CredentialHeader, EgressScheme, ProtocolDecl};
use busbar_kernel::bound_credential::{
    bind, CredentialProvider, DeclaredBuilder, NoCredential, StyleBinding,
};
use busbar_kernel::plane_host::{AuthStyleInput, LaneInput, PlaneBuildInput};
use serde_json::{json, Map, Value};

/// A static presentation as the header style's parameters spell it.
fn presentation(p: CredentialHeader) -> Value {
    match p {
        CredentialHeader::Bearer => json!({}),
        CredentialHeader::Raw { header, trim_start } => {
            let mut m = Map::new();
            m.insert("header".to_string(), Value::String(header.to_string()));
            if trim_start {
                m.insert("trim_start".to_string(), Value::Bool(true));
            }
            Value::Object(m)
        }
    }
}

/// The binding a DECLARED egress scheme is opened under: a static scheme on the `api-key` style
/// with its whole presentation table as parameters and the dialect's name (the `protocol` an
/// unpresentable credential's line names, as 1.5.5's did), a per-request signature on the `sigv4` style
/// with its service, the region its host names (else its default) and its content type, which the
/// lane's writer sends and so is lent as the `content-type` the signature covers. The dialect's
/// static fields (`decl`'s) follow the plugin's.
///
/// The region is read here SILENTLY: a dialect's `region_of_host` gives the operator its warning
/// when a host names no region, and 1.5.5 gave it once per signature, at request time, never at
/// boot. [`PerSignatureRegionRead`] keeps that line where 1.5.5 wrote it.
#[must_use]
pub(crate) fn declared_binding(
    decl: &'static ProtocolDecl,
    scheme: EgressScheme,
    host: &str,
) -> StyleBinding {
    let (style, params, sent) = match scheme {
        EgressScheme::Static {
            families,
            own,
            passthrough,
        } => {
            let families: Vec<Value> = families
                .iter()
                .map(|f| {
                    let mut row = match presentation(f.presented_as) {
                        Value::Object(m) => m,
                        _ => Map::new(),
                    };
                    row.insert("prefix".to_string(), Value::String(f.prefix.to_string()));
                    Value::Object(row)
                })
                .collect();
            (
                "api-key",
                json!({
                    "families": families,
                    "own": presentation(own),
                    "passthrough": presentation(passthrough),
                    "protocol": decl.name,
                }),
                Vec::new(),
            )
        }
        EgressScheme::SigV4 {
            service,
            region_of_host,
            default_region,
            content_type,
        } => (
            "sigv4",
            json!({
                "service": service,
                "region": silently(|| region_of_host(host)).unwrap_or(default_region),
                "content_type": content_type,
            }),
            vec![("content-type".to_string(), content_type.to_string())],
        ),
    };
    StyleBinding {
        style: style.to_string(),
        params,
        uses_key: true,
        statics: decl.static_headers,
        sent,
    }
}

/// `read`, with no line written: the binding's parameters are read once, at bind, and a warning the
/// read gives belongs to the request it is about ([`PerSignatureRegionRead`]).
fn silently<T>(read: impl FnOnce() -> T) -> T {
    tracing::subscriber::with_default(Silent, read)
}

/// The dispatcher [`silently`] reads under: it enables nothing, and it tells tracing's global
/// callsite cache and level ceiling NOTHING (`sometimes`, no level hint), so a cache rebuilt while
/// it is installed never turns a callsite or a level off for another thread's dispatcher (a
/// `NoSubscriber` answers `never` and `OFF`, which a concurrent rebuild can leave behind).
struct Silent;

impl tracing::Subscriber for Silent {
    fn register_callsite(
        &self,
        _: &'static tracing::Metadata<'static>,
    ) -> tracing::subscriber::Interest {
        tracing::subscriber::Interest::sometimes()
    }
    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        None
    }
    fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
        false
    }
    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }
    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
    fn event(&self, _: &tracing::Event<'_>) {}
    fn enter(&self, _: &tracing::span::Id) {}
    fn exit(&self, _: &tracing::span::Id) {}
}

/// A signing lane's bound credential, reading its host's region once per signature as 1.5.5's
/// signer did, so the dialect's `region_of_host` writes its operator warning (a host that names no
/// region signs for the default) on the request that signs, in 1.5.5's place in the log: after the
/// request's own lines, before the signer's. 1.5.5 read it only for a credential that splits as
/// `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]` (a misconfigured key signs nothing and reads nothing).
/// The plugin's binding already carries the region; the read's answer is not used.
struct PerSignatureRegionRead {
    inner: Arc<dyn CredentialProvider>,
    region_of_host: fn(&str) -> Option<&str>,
}

impl CredentialProvider for PerSignatureRegionRead {
    fn headers_for(
        &self,
        key: &str,
        ctx: &busbar_contract::protocol::SigningContext,
    ) -> Vec<(axum::http::HeaderName, axum::http::HeaderValue)> {
        if splits_as_signing_key(key) {
            let _ = (self.region_of_host)(ctx.host);
        }
        self.inner.headers_for(key, ctx)
    }
    fn is_ready(&self) -> bool {
        self.inner.is_ready()
    }
    fn is_lane_constant(&self) -> bool {
        self.inner.is_lane_constant()
    }
    fn uses_key(&self) -> bool {
        self.inner.uses_key()
    }
}

/// Whether `key` names an access key id and a secret, both non-empty: the credential 1.5.5's signer
/// signed with (anything else signs nothing).
fn splits_as_signing_key(key: &str) -> bool {
    let mut parts = key.splitn(3, ':');
    let access = parts.next().unwrap_or_default();
    let secret = parts.next().unwrap_or_default();
    !access.is_empty() && !secret.is_empty()
}

/// THE `auth: api-key` OVERRIDE's binding: the credential verbatim in `api-key` whatever the
/// dialect, and none of the dialect's static fields.
#[must_use]
pub(crate) fn api_key_override_binding() -> StyleBinding {
    StyleBinding {
        style: "api-key".to_string(),
        params: json!({}),
        uses_key: true,
        statics: &[],
        sent: Vec::new(),
    }
}

/// The token endpoint `jwt-bearer` posts to: the service account's own `token_uri` (the need's
/// target, judged by the kernel, BUSBAR-1.6.0.md THE DESIGN §5).
fn token_uri(credential: &str) -> Option<String> {
    busbar_kernel::config_validate::service_account_token_uri(credential).ok()
}

/// The mint styles' shared parameters: the token response cap the kernel's limits set.
fn mint_params(mut params: Map<String, Value>) -> Value {
    params.insert(
        "max_response_bytes".to_string(),
        json!(busbar_kernel::proxy::max_upstream_buffered_bytes()),
    );
    Value::Object(params)
}

/// The style and parameters `lane`'s credential is bound under, or the dialect's own builder.
enum Binding {
    /// The style binding, and a signing scheme's per-signature region read.
    Style(StyleBinding, Option<fn(&str) -> Option<&str>>),
    Builder(Arc<dyn CredentialProvider>),
}

fn binding_for(protocol: &'static str, lane: &LaneInput, host: &str, api_key: &str) -> Binding {
    let text = |m: &mut Map<String, Value>, k: &str, v: &Option<String>| {
        if let Some(v) = v {
            m.insert(k.to_string(), Value::String(v.clone()));
        }
    };
    match lane.auth_style {
        AuthStyleInput::JwtBearer => {
            let mut m = Map::new();
            text(&mut m, "scope", &lane.scope);
            text(&mut m, "subject", &lane.subject);
            text(&mut m, "token_uri", &token_uri(api_key));
            Binding::Style(
                StyleBinding {
                    style: "jwt-bearer".to_string(),
                    params: mint_params(m),
                    uses_key: false,
                    statics: &[],
                    sent: Vec::new(),
                },
                None,
            )
        }
        AuthStyleInput::OAuthClientCredentials => {
            let mut m = Map::new();
            text(&mut m, "token_url", &lane.token_url);
            text(&mut m, "scope", &lane.scope);
            Binding::Style(
                StyleBinding {
                    style: "oauth-client-credentials".to_string(),
                    params: mint_params(m),
                    uses_key: false,
                    statics: &[],
                    sent: Vec::new(),
                },
                None,
            )
        }
        AuthStyleInput::ApiKey => Binding::Style(api_key_override_binding(), None),
        // No override, or `auth: bearer`: the dialect's own declared scheme.
        AuthStyleInput::Default | AuthStyleInput::Bearer => {
            match busbar_kernel::proto::decl_for(protocol) {
                Some(decl) => match (decl.egress_scheme, decl.egress_auth_headers) {
                    (Some(scheme), _) => {
                        let read = match scheme {
                            EgressScheme::SigV4 { region_of_host, .. } => Some(region_of_host),
                            EgressScheme::Static { .. } => None,
                        };
                        Binding::Style(declared_binding(decl, scheme, host), read)
                    }
                    (None, Some(headers_for)) => Binding::Builder(Arc::new(DeclaredBuilder {
                        headers_for,
                        lane_constant: decl.egress_auth_lane_constant,
                    })),
                    (None, None) => Binding::Builder(Arc::new(NoCredential)),
                },
                None => Binding::Builder(Arc::new(NoCredential)),
            }
        }
    }
}

/// `lane`'s credential, bound on the build's auth axis. A binding no plugin will open presents no
/// credential (the upstream answers 401), reported once here with the plugin's own words.
pub(crate) fn credential_for(
    input: &PlaneBuildInput,
    lane: &LaneInput,
    protocol: &'static str,
    host: &str,
    api_key: &str,
) -> Arc<dyn CredentialProvider> {
    match binding_for(protocol, lane, host, api_key) {
        Binding::Builder(built) => built,
        Binding::Style(binding, read) => {
            let Some(reach) = &input.auths else {
                return Arc::new(NoCredential);
            };
            match bind(&*reach.0, &binding, api_key.as_bytes()) {
                Ok(inner) => match read {
                    Some(region_of_host) => Arc::new(PerSignatureRegionRead {
                        inner,
                        region_of_host,
                    }),
                    None => inner,
                },
                Err(e) => {
                    tracing::error!(
                        lane = %lane.model,
                        style = %binding.style,
                        "the lane's credential is not bound, so its requests carry no credential: {e}"
                    );
                    Arc::new(NoCredential)
                }
            }
        }
    }
}
