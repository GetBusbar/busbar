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
use busbar_contract::protocol::{CredentialHeader, EgressScheme, SigningContext};

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
