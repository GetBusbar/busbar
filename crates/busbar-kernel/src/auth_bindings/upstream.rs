// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Upstream bindings (IF §12.18 rounds 21-22): `upstreams.<name>.auth` forms mapped by `CORE_UPSTREAM_STYLES`
//! into in-memory `auth.upstream-<name>-outbound` instances, the credential mode derived from the style flags and
//! the three `upstream_credentials` refusals. Pure over what K1 and K7 parsed; the binder opens the instances.

use busbar_contract::config::dialect_styles::{self as styles, Settings, UpstreamForm};
use busbar_contract::config::{outbound_owner, UpstreamCreds};
use busbar_plugin_abi::auth::{STYLE_CALLER, STYLE_PER_REQUEST, STYLE_SCOPE};

use super::{check_style, squat_text, CredentialFrom, ImplicitInstance, OperatorAuth};
use crate::config::min3::{UpstreamAuthCfg, UpstreamAuthForm};
use crate::upstreams::UpstreamAuth;

/// One upstream's auth, resolved: its instance, module and style, the implicit instance it adds (if
/// any), and its connect callback (if any).
type Resolved = (
    Box<str>,
    Box<str>,
    Box<str>,
    Option<ImplicitInstance>,
    Option<Box<str>>,
);

/// One configured upstream, as far as bindings read it. No `Debug`: the form carries URLs.
pub struct UpstreamView<'a> {
    pub name: &'a str,
    pub auth: Option<&'a UpstreamAuthCfg>,
    /// `upstreams.<name>.upstream_credentials`; None = derived from the binding.
    pub upstream_credentials: Option<UpstreamCreds>,
    /// `command` is set (CARRIER_STDIO): a form has no carrier there.
    pub stdio: bool,
}

/// What one upstream's binding answers.
pub struct UpstreamBinding {
    pub name: Box<str>,
    /// The in-memory instance a core-vocabulary form needs; None for the operator form and for no `auth`.
    pub implicit: Option<ImplicitInstance>,
    /// `UpstreamDef.auth`; None when the upstream has no `auth`.
    pub auth: Option<UpstreamAuth>,
}

/// The auth instance name core gives an upstream's implicit binding.
#[must_use]
pub(crate) fn implicit_name(upstream: &str) -> String {
    format!("upstream-{upstream}-outbound")
}

/// The path of an absolute URL (no query, no fragment); None when it has none.
fn url_path(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let at = rest.find('/')?;
    let path = &rest[at..];
    let end = path.find(['?', '#']).unwrap_or(path.len());
    Some(&path[..end])
}

fn form_parts(form: &UpstreamAuthForm) -> Option<(UpstreamForm, CredentialFrom, Settings)> {
    Some(match form {
        UpstreamAuthForm::Instance(_) => return None,
        UpstreamAuthForm::Bearer(_) => (
            UpstreamForm::Bearer,
            CredentialFrom::UpstreamForm("bearer".into()),
            Settings::Empty,
        ),
        UpstreamAuthForm::ApiKey { header, .. } => (
            UpstreamForm::ApiKey,
            CredentialFrom::UpstreamForm("api_key".into()),
            Settings::ApiKey {
                header: header.clone(),
            },
        ),
        UpstreamAuthForm::TokenExchange {
            token_url,
            resource,
            subject_token_type,
            ..
        } => (
            UpstreamForm::TokenExchange,
            CredentialFrom::UpstreamForm("token_exchange".into()),
            Settings::TokenExchange {
                token_url: token_url.clone(),
                resource: resource.clone(),
                subject_token_type: subject_token_type.clone(),
            },
        ),
        UpstreamAuthForm::Connection {
            issuer,
            resource,
            client_id,
            redirect_uri,
            authorization_endpoint,
            token_endpoint,
            scopes,
        } => (
            UpstreamForm::Connection,
            CredentialFrom::None,
            Settings::Connection {
                issuer: issuer.clone(),
                resource: resource.clone(),
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                authorization_endpoint: authorization_endpoint.clone(),
                token_endpoint: token_endpoint.clone(),
                scopes: scopes.clone(),
            },
        ),
    })
}

/// The three `upstream_credentials` refusals (IF §12.18 round 22), the hook K7's config load calls. `binding` =
/// `Some(caller)` when the upstream has an `auth` binding (caller = its style declared STYLE_CALLER), `form` =
/// whether that binding is a core-vocabulary form.
pub fn check_upstream_credentials(
    name: &str,
    creds: Option<UpstreamCreds>,
    binding: Option<bool>,
    form: bool,
) -> Result<(), String> {
    match (creds, binding) {
        (Some(UpstreamCreds::Connection), None | Some(false)) => Err(format!(
            "`upstreams.{name}.upstream_credentials` is `connection`, but its `auth` presents its own credential; \
             use the `connection` form or drop `upstream_credentials`"
        )),
        (Some(UpstreamCreds::Own | UpstreamCreds::Passthrough), Some(true)) => Err(format!(
            "`upstreams.{name}.auth` is a per-caller connection; set `upstream_credentials: connection` or drop it"
        )),
        (Some(UpstreamCreds::Passthrough), Some(false)) if form => Err(format!(
            "`upstreams.{name}.upstream_credentials` is `passthrough`, but `auth` is a core-vocabulary form that \
             presents its own credential; name an auth instance or drop `upstream_credentials`"
        )),
        _ => Ok(()),
    }
}

/// Resolve every upstream's binding. `flags(module, style)` = `Registry::style_flags`. Err = every refusal text.
pub fn bind_upstreams(
    upstreams: &[UpstreamView<'_>],
    styles_of: &[(&str, Vec<&str>)],
    operator: &[OperatorAuth<'_>],
    flags: &dyn Fn(&str, &str) -> u64,
) -> Result<Vec<UpstreamBinding>, Vec<String>> {
    let mut refused = Vec::new();
    let mut out = Vec::new();
    for u in upstreams {
        let Some(cfg) = u.auth else {
            if let Err(why) =
                check_upstream_credentials(u.name, u.upstream_credentials, None, false)
            {
                refused.push(why);
            }
            out.push(UpstreamBinding {
                name: u.name.into(),
                implicit: None,
                auth: None,
            });
            continue;
        };
        if u.stdio && !matches!(cfg.form, UpstreamAuthForm::Instance(_)) {
            refused.push(format!(
                "`upstreams.{}.auth` has no carrier on `transport: stdio`",
                u.name
            ));
            continue;
        }
        let (instance, module, style, implicit, connect_callback): Resolved = match &cfg.form {
            UpstreamAuthForm::Instance(named) => {
                let Some(op) = operator.iter().find(|o| o.name == &**named) else {
                    refused.push(format!(
                        "`upstreams.{}.auth` names `{named}`, which is not configured under `auth:`",
                        u.name
                    ));
                    continue;
                };
                if let Some(why) = check_style(op, styles_of) {
                    refused.push(why);
                    continue;
                }
                (
                    named.clone(),
                    op.module.into(),
                    op.style.unwrap_or_default().into(),
                    None,
                    None,
                )
            }
            form => {
                let Some((kind, credential, settings)) = form_parts(form) else {
                    continue;
                };
                let name = implicit_name(u.name);
                if operator.iter().any(|o| o.name == name) {
                    refused.push(squat_text(&name, &format!("upstreams.{}", u.name)));
                    continue;
                }
                let word = styles::upstream_style(kind);
                let owner = match outbound_owner(styles_of, word) {
                    Ok(owner) => owner,
                    Err(why) => {
                        refused.push(why.text(&format!("auth.{name}"), word));
                        continue;
                    }
                };
                let callback = match form {
                    UpstreamAuthForm::Connection { redirect_uri, .. } => {
                        url_path(redirect_uri).map(Box::from)
                    }
                    _ => None,
                };
                let implicit = ImplicitInstance {
                    name: name.clone().into(),
                    module: owner.into(),
                    style: word.into(),
                    credential,
                    settings,
                };
                (
                    name.into(),
                    owner.into(),
                    word.into(),
                    Some(implicit),
                    callback,
                )
            }
        };
        let mask = flags(&module, &style);
        let caller = mask & STYLE_CALLER != 0;
        let is_form = implicit.is_some();
        if let Err(why) =
            check_upstream_credentials(u.name, u.upstream_credentials, Some(caller), is_form)
        {
            refused.push(why);
            continue;
        }
        out.push(UpstreamBinding {
            name: u.name.into(),
            implicit,
            auth: Some(UpstreamAuth {
                instance,
                cache_max_s: cfg.cache_max_s,
                connect_callback,
                caller,
                scoped: mask & STYLE_SCOPE != 0,
                per_request: mask & STYLE_PER_REQUEST != 0,
            }),
        });
    }
    if refused.is_empty() {
        Ok(out)
    } else {
        Err(refused)
    }
}
