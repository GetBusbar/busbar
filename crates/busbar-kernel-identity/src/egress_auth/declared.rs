// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A protocol's DECLARED egress scheme, presented. A protocol declares HOW its upstream is
//! authenticated as data on its declaration ([`EgressScheme`]): a credential-family table for a
//! static credential, or a per-request signature whose region is a declared pure function of the
//! upstream host. This module reads that declaration, picks the one [`Scheme`] it names for this
//! credential and this lane's credential mode, and decorates through [`decorate`] and
//! [`substitute`] under the kernel's [`Grant<Sign>`] — so the credential is written onto the
//! request here, and never passes through the plane that declared the scheme.

use super::{decorate, sigv4, substitute, EgressBody, Scheme, SessionToken};
use busbar_contract::caps::{Grant, Sign};
use busbar_contract::config::UpstreamCreds;
use busbar_contract::diagnostic::Diagnostic;
use busbar_contract::protocol::{CredentialHeader, EgressScheme, ProtocolDecl, SigningContext};

/// How a static declared scheme presents `credential` in `mode`: the first credential-family row
/// whose prefix the credential (leading whitespace trimmed) starts with, else the scheme's
/// presentation for the mode. `None` for a signing scheme, which presents no static header.
pub fn presentation(
    scheme: &EgressScheme,
    credential: &str,
    mode: UpstreamCreds,
) -> Option<CredentialHeader> {
    let EgressScheme::Static {
        families,
        own,
        passthrough,
    } = scheme
    else {
        return None;
    };
    let trimmed = credential.trim_start();
    let by_family = families
        .iter()
        .find(|family| trimmed.starts_with(family.prefix))
        .map(|family| family.presented_as);
    Some(by_family.unwrap_or(match mode {
        UpstreamCreds::Own => *own,
        UpstreamCreds::Passthrough => *passthrough,
    }))
}

/// Present `credential` under the protocol's declared `scheme` for the request `ctx` describes:
/// the header pairs to attach, in the order they are set, or NONE when the credential cannot be
/// presented (a byte that is not a legal header value, a signing credential missing its key id or
/// secret, an unsendable session token). An empty result is the omission; reporting it is the
/// caller's, which owns the diagnostics catalog.
///
/// A static scheme decorates [`Scheme::Bearer`] or [`Scheme::ApiKeyHeader`] with the credential as
/// its secret slot. A signing scheme splits the lane credential with [`sigv4::split_credential`],
/// finds its region through the declared function of `ctx.host`, and signs a `POST` over the
/// declared content type, the host and the body.
pub fn present(
    token: &Grant<Sign>,
    scheme: &EgressScheme,
    credential: &str,
    ctx: &SigningContext<'_>,
) -> Vec<(String, String)> {
    match scheme {
        EgressScheme::Static { .. } => {
            let (scheme, secret) = match presentation(scheme, credential, ctx.upstream_creds) {
                Some(CredentialHeader::Raw { header, trim_start }) => (
                    Scheme::ApiKeyHeader { header },
                    if trim_start {
                        credential.trim_start()
                    } else {
                        credential
                    },
                ),
                _ => (Scheme::Bearer, credential),
            };
            let decoration = decorate(token, &scheme, secret, &request(ctx, &[]));
            substitute(&decoration, secret, Vec::new())
        }
        EgressScheme::SigV4 {
            service,
            region_of_host,
            default_region,
            content_type,
        } => {
            let Some((access_key_id, secret, session_token)) = sigv4::split_credential(credential)
            else {
                return Vec::new();
            };
            let scheme = Scheme::SigV4 {
                access_key_id,
                region: region_of_host(ctx.host).unwrap_or(default_region),
                service,
                session_token: session_token.map(SessionToken),
            };
            let signed = [
                ("content-type".to_string(), (*content_type).to_string()),
                ("host".to_string(), ctx.host.to_string()),
            ];
            let decoration = decorate(token, &scheme, secret, &request(ctx, &signed));
            substitute(&decoration, secret, Vec::new())
        }
    }
}

/// [`present`] for a lane of the protocol `decl` declared (`None`: the operator's override, which
/// declares nothing else): the credential headers, then — when none could be presented —
/// [`report_unpresented`] under the host catalog's `codes`, then the declaration's `static_headers`
/// verbatim, in their declared order. A static header is not auth: it rides whatever the credential.
pub fn present_declared(
    token: &Grant<Sign>,
    scheme: &EgressScheme,
    decl: Option<&ProtocolDecl>,
    credential: &str,
    ctx: &SigningContext<'_>,
    codes: [&Diagnostic; 2],
) -> Vec<(String, String)> {
    let mut headers = present(token, scheme, credential, ctx);
    let (protocol, statics) = decl.map_or(("", &[][..]), |d| (d.name, d.static_headers));
    if headers.is_empty() {
        report_unpresented(scheme, protocol, credential, ctx.upstream_creds, codes);
    }
    headers.extend(statics.iter().map(|(k, v)| (k.to_string(), v.to_string())));
    headers
}

/// Report a credential [`present`] could not present (an empty presentation), in the line its
/// scheme's builder always logged, the key never logged: a credential-family table's line naming the
/// header it omitted, a static header's (`codes[0]`) naming the header, a bearer's (`codes[1]`, at
/// debug) naming `protocol`, and — for a signing scheme — the signer's line for an unsendable
/// session token, naming the declared service. The codes are the host catalog's, handed in by the
/// caller that owns it. A signing credential that is merely malformed logged nothing and logs nothing.
pub fn report_unpresented(
    scheme: &EgressScheme,
    protocol: &str,
    credential: &str,
    mode: UpstreamCreds,
    codes: [&Diagnostic; 2],
) {
    let (header, raw) = match presentation(scheme, credential, mode) {
        Some(CredentialHeader::Raw { header, .. }) => (header, true),
        Some(CredentialHeader::Bearer) => ("authorization", false),
        None => {
            let token = sigv4::split_credential(credential).and_then(|(_, _, t)| t);
            let unsendable = token.is_some_and(|t| !super::is_legal_header_value(t));
            if let (EgressScheme::SigV4 { service, .. }, true) = (scheme, unsendable) {
                let (initial, rest) = service.split_at(service.len().min(1));
                tracing::warn!("{}{rest} lane session token contains a byte rejected by HeaderValue; skipping signing to avoid a signed-but-absent x-amz-security-token header.", initial.to_uppercase());
            }
            return;
        }
    };
    if matches!(scheme, EgressScheme::Static { families, .. } if !families.is_empty()) {
        tracing::warn!(protocol, header, "auth credential contains bytes invalid for an HTTP header value (e.g. a trailing newline); omitting the credential header — upstream will return 401, check the key configuration");
    } else if raw {
        busbar_contract::diag_warn!(
            codes[0],
            header,
            "egress credential contains invalid header bytes (ASCII control character); omitting \
             auth header — upstream will reject with 401"
        );
    } else {
        busbar_contract::diag_debug!(
            codes[1],
            protocol,
            "authorization credential contains invalid header bytes (ASCII control character); \
             omitting auth header — upstream will reject with 401"
        );
    }
}

/// The request a declared scheme decorates: a `POST` of `ctx`'s body to its path, with `envelope`
/// the fields a signer folds in.
fn request<'b>(ctx: &'b SigningContext<'_>, envelope: &'b [(String, String)]) -> EgressBody<'b> {
    EgressBody {
        method: "POST",
        canonical_uri: ctx.canonical_uri,
        canonical_querystring: "",
        envelope,
        body: ctx.body,
        timestamp_epoch: ctx.timestamp_epoch,
    }
}

#[cfg(test)]
#[path = "declared_tests.rs"]
mod tests;
