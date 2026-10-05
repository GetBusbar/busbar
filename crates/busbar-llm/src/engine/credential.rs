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
/// with its whole presentation table as parameters, a per-request signature on the `sigv4` style
/// with its service, the region its host names (else its default) and its content type. The
/// dialect's static fields (`decl`'s) follow the plugin's.
#[must_use]
pub fn declared_binding(
    decl: &'static ProtocolDecl,
    scheme: EgressScheme,
    host: &str,
) -> StyleBinding {
    let (style, params) = match scheme {
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
                }),
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
                "region": region_of_host(host).unwrap_or(default_region),
                "content_type": content_type,
            }),
        ),
    };
    StyleBinding {
        style: style.to_string(),
        params,
        uses_key: true,
        statics: decl.static_headers,
    }
}

/// THE `auth: api-key` OVERRIDE's binding: the credential verbatim in `api-key` whatever the
/// dialect, and none of the dialect's static fields.
#[must_use]
pub fn api_key_override_binding() -> StyleBinding {
    StyleBinding {
        style: "api-key".to_string(),
        params: json!({}),
        uses_key: true,
        statics: &[],
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
    Style(StyleBinding),
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
            Binding::Style(StyleBinding {
                style: "jwt-bearer".to_string(),
                params: mint_params(m),
                uses_key: false,
                statics: &[],
            })
        }
        AuthStyleInput::OAuthClientCredentials => {
            let mut m = Map::new();
            text(&mut m, "token_url", &lane.token_url);
            text(&mut m, "scope", &lane.scope);
            Binding::Style(StyleBinding {
                style: "oauth-client-credentials".to_string(),
                params: mint_params(m),
                uses_key: false,
                statics: &[],
            })
        }
        AuthStyleInput::ApiKey => Binding::Style(api_key_override_binding()),
        // No override, or `auth: bearer`: the dialect's own declared scheme.
        AuthStyleInput::Default | AuthStyleInput::Bearer => {
            match busbar_kernel::proto::decl_for(protocol) {
                Some(decl) => match (decl.egress_scheme, decl.egress_auth_headers) {
                    (Some(scheme), _) => Binding::Style(declared_binding(decl, scheme, host)),
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
        Binding::Style(binding) => {
            let Some(reach) = &input.auths else {
                return Arc::new(NoCredential);
            };
            bind(&*reach.0, &binding, api_key.as_bytes()).unwrap_or_else(|e| {
                tracing::error!(
                    lane = %lane.model,
                    style = %binding.style,
                    "the lane's credential is not bound, so its requests carry no credential: {e}"
                );
                Arc::new(NoCredential)
            })
        }
    }
}
