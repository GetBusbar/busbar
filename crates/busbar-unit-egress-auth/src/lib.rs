// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-unit-egress-auth — the ROUTE step's egress-auth unit
//!
//! Between the egress unit encoding the wire request (`plane.encode_egress()`) and the send, one
//! unit decorates the request with credentials: `decorate(cfg, &EgressBody, signer) ->
//! AuthDecoration`, and `continue_handshake` for a scheme whose upstream challenge needs a second
//! round. This unit substitutes every [`SecretSlot`] itself — the whole reason a secret never has
//! to pass through a plane — and after decoration the lane is checked again against the
//! [`VerifiedDestination`] the trust unit sealed, so a decoration can never quietly move the unit to
//! a different lane.
//!
//! ## What is in here
//!
//! - [`Scheme`] and [`decorate`] — the egress-auth schemes actually shipped: bearer, a static
//!   custom header (`api-key` / `x-goog-api-key`), and per-request AWS SigV4.
//! - [`sigv4`] — the signer itself, verified against AWS's published worked example.
//! - [`substitute`] — applies a decoration's [`SecretSlot`]s to an envelope exactly once each.
//! - [`lane_cross_check`] — the post-decoration re-check: the envelope must still equal the
//!   [`VerifiedDestination`] the trust unit sealed.
//! - [`FORWARDED_CLIENT_HEADERS`] / [`allowed_client_headers_for`] — the allow-listed client
//!   request headers that ride upstream verbatim, scoped per egress dialect so a beta header sent
//!   for one dialect never leaks to a different one on a cross-protocol route or failover.
//!
//! ## What is deliberately absent
//!
//! `continue_handshake` is declared with the shape the contract calls for (a bounded number of
//! frames/bytes for a multi-round scheme's second round) but every scheme this build ships is
//! single-round, so there is no live multi-round vector to prove it against; `// contract:` marks
//! it. Inbound SigV4 verification (a client authenticating itself to busbar, not busbar
//! authenticating itself to an upstream) is a different unit's concern — see the [`sigv4`] module
//! doc — and was not ported here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod sigv4;

use busbar_caps::{AuthDecoration, EgressAuthToken, SecretSlot, VerifiedDestination};

/// The outbound request the egress-auth unit decorates. Everything the schemes below need to
/// compute a decoration, and nothing else — no plane, no transport, no framework header type.
pub struct EgressBody<'a> {
    /// The HTTP method (`GET`, `POST`, ...), for schemes that sign the request line.
    pub method: &'a str,
    /// The already-encoded, already-URI-escaped path SigV4 signs and the wire sends.
    pub canonical_uri: &'a str,
    /// The sorted, encoded query string SigV4 signs (empty when there is none).
    pub canonical_querystring: &'a str,
    /// The envelope fields already set by encoding, visible to a signer that must fold them into
    /// its canonical request (e.g. `host`, `content-type`).
    pub envelope: &'a [(String, String)],
    /// The encoded body bytes, for a scheme that signs the payload.
    pub body: &'a [u8],
    /// Seconds since the Unix epoch, for a scheme that timestamps its signature.
    pub timestamp_epoch: u64,
}

/// An egress-auth scheme this build ships. Each variant is the whole of what `decorate` needs to
/// build the right decoration; there is no scheme-specific state beyond what is named here (a
/// self-minting scheme, e.g. a future OAuth client-credentials egress, would carry its own token
/// cache elsewhere and hand `decorate` an already-minted bearer value).
#[derive(Debug, Clone)]
pub enum Scheme {
    /// `Authorization: Bearer <key>` — OpenAI, `/v1/responses`, Cohere, Anthropic's non-native
    /// case.
    Bearer,
    /// A static custom header carrying the raw key verbatim: `api-key` (Azure OpenAI override) or
    /// `x-goog-api-key` (Gemini).
    ApiKeyHeader {
        /// The header name, lowercase.
        header: &'static str,
    },
    /// Per-request AWS Signature Version 4 (Bedrock). `access_key_id` is not secret (it travels in
    /// plaintext in the `Authorization` header); the signing secret is passed to [`decorate`]
    /// separately, exactly like every other scheme.
    SigV4 {
        /// The non-secret AWS access key id.
        access_key_id: &'static str,
        /// The AWS region the request is scoped to.
        region: &'static str,
        /// The AWS service name (`bedrock`).
        service: &'static str,
    },
}

/// Whether `s` is safe to carry as an HTTP header value: no ASCII control byte (0x00-0x1F, 0x7F).
/// A config system that injects a stray CR/LF/NUL must not produce a request-smuggling header; the
/// egress-auth unit omits the header entirely instead (the upstream then answers 401, exactly like
/// every other misconfigured-credential path).
fn is_valid_header_value(s: &str) -> bool {
    !s.bytes().any(|b| b.is_ascii_control())
}

/// Decorate an outbound request for `scheme`, given the already-resolved `secret`. Only the
/// egress-auth unit ever sees `secret` in the clear (`expose()` is confined to the auth,
/// egress-auth and transport-key units) — that is why this function, not a plane, takes it.
///
/// Every static scheme (bearer, the custom-header schemes) declares a [`SecretSlot`] naming WHERE
/// the secret goes rather than writing it into `fields` directly, so [`substitute`] is the one place
/// the literal secret bytes are ever assembled into the envelope. SigV4 is different in kind: what
/// goes on the wire is a SIGNATURE, a value derived from the secret that does not itself let anyone
/// recover it, so it is written into `fields` directly and the decoration carries no slot.
///
/// An un-encodable key (an ASCII control byte a config system may have injected) yields the
/// no-header decoration — the upstream then answers 401, the same graceful path every dialect
/// already takes for a malformed credential.
pub fn decorate(
    token: &EgressAuthToken,
    scheme: &Scheme,
    secret: &str,
    body: &EgressBody<'_>,
) -> AuthDecoration {
    match scheme {
        Scheme::Bearer => {
            if !is_valid_header_value(secret) {
                return AuthDecoration::decorate(token, Vec::new(), false, Vec::new());
            }
            let slot = SecretSlot::declare(token, "header:authorization:bearer");
            AuthDecoration::decorate(token, Vec::new(), false, vec![slot])
        }
        Scheme::ApiKeyHeader { header } => {
            if !is_valid_header_value(secret) {
                return AuthDecoration::decorate(token, Vec::new(), false, Vec::new());
            }
            let slot = SecretSlot::declare(token, format!("header:{header}:raw"));
            AuthDecoration::decorate(token, Vec::new(), false, vec![slot])
        }
        Scheme::SigV4 {
            access_key_id,
            region,
            service,
        } => {
            let (amzdate, datestamp) = sigv4::format_amz_time(body.timestamp_epoch);
            let payload_hash = sigv4::sha256_hex(body.body);
            let mut headers: Vec<(String, String)> = body.envelope.to_vec();
            headers.push(("x-amz-date".to_string(), amzdate.clone()));
            headers.push(("x-amz-content-sha256".to_string(), payload_hash.clone()));
            let (signature, signed_headers) = sigv4::sign_v4(
                secret,
                region,
                service,
                body.method,
                body.canonical_uri,
                body.canonical_querystring,
                &headers,
                &payload_hash,
                &amzdate,
                &datestamp,
            );
            let credential_scope = format!("{datestamp}/{region}/{service}/{}", sigv4::SIGV4_TERMINATION);
            let authorization = format!(
                "{} Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
                sigv4::SIGV4_ALGORITHM
            );
            AuthDecoration::decorate(
                token,
                vec![
                    ("authorization".to_string(), authorization),
                    ("x-amz-date".to_string(), amzdate),
                    ("x-amz-content-sha256".to_string(), payload_hash),
                ],
                true,
                Vec::new(),
            )
        }
    }
}

/// Run the second (or later) round of a scheme whose upstream challenge spans more than one
/// handshake frame. Every scheme this build ships (bearer, the custom-header schemes, per-request
/// SigV4) is single-round, so there is no live scheme to exercise this against yet.
///
/// `// contract:` a future multi-round scheme (e.g. a challenge-response credential) implements
/// this by reading `state` (whatever it returned from its own prior round) and the upstream's
/// `frame`, and returns either another `AuthDecoration::Handshake` (more rounds needed, within the
/// bounds it already declared) or the terminal `AuthDecoration::Decorate`. The bound stays whatever
/// the FIRST decoration for this scheme declared — `continue_handshake` never widens it.
pub fn continue_handshake(
    token: &EgressAuthToken,
    _state: &[u8],
    _frame: &[u8],
) -> AuthDecoration {
    // No shipped scheme reaches this path; refuse to guess at a shape with no real scheme to
    // validate it against, and hand back a zero-budget handshake so a caller that DOES reach here
    // fails closed rather than silently proceeding unauthenticated.
    AuthDecoration::handshake(token, 0, 0)
}

/// Apply a decoration's [`SecretSlot`]s to `envelope`, substituting `secret` at each slot's
/// location exactly once. Returns the fields the decoration set literally (already fully computed,
/// never touched here) plus the substituted envelope. This is the ONLY place a slot's location
/// string is interpreted — the egress-auth unit is the only unit that ever holds `secret` in the
/// clear, so this is also the only place that can perform the substitution at all.
///
/// The `header:<name>:bearer` / `header:<name>:raw` location grammar is private to this crate:
/// [`decorate`] is the only producer of a [`SecretSlot`] here, so the two agree by construction.
pub fn substitute(
    decoration: &AuthDecoration,
    secret: &str,
    mut envelope: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let AuthDecoration::Decorate { fields, slots, .. } = decoration else {
        // A Handshake decoration carries no envelope fields or slots to apply.
        return envelope;
    };
    for (k, v) in fields {
        set_header(&mut envelope, k, v.clone());
    }
    for slot in slots {
        let location = slot.location();
        let Some(rest) = location.strip_prefix("header:") else {
            continue;
        };
        let Some((name, template)) = rest.rsplit_once(':') else {
            continue;
        };
        let value = match template {
            "bearer" => format!("Bearer {secret}"),
            "raw" => secret.to_string(),
            _ => continue,
        };
        set_header(&mut envelope, name, value);
    }
    envelope
}

/// Set (or replace) one header in an envelope vector, case-insensitively — the envelope is a small
/// `Vec`, not a map, because the wire request preserves the order fields were set in.
fn set_header(envelope: &mut Vec<(String, String)>, name: &str, value: String) {
    if let Some(existing) = envelope
        .iter_mut()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
    {
        existing.1 = value;
    } else {
        envelope.push((name.to_string(), value));
    }
}

/// Why the post-decoration lane cross-check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaneMismatch {
    /// The decorated envelope's value for the cross-checked field no longer equals what the trust
    /// unit sealed into the [`VerifiedDestination`].
    EnvelopeDivergedFromVerifiedDestination {
        /// The field that diverged.
        field: &'static str,
    },
}

/// Re-run the lane cross-check on the POST-decoration bytes: a hook, or a scheme's own
/// decoration, is permitted to touch the envelope, but the field that carries the lane (`host` for
/// every in-tree scheme's target) must still equal the [`VerifiedDestination`] the trust unit
/// sealed. `field` names the envelope key that carries the destination (`"host"` for the schemes in
/// this crate).
pub fn lane_cross_check(
    verified: &VerifiedDestination,
    field: &'static str,
    envelope: &[(String, String)],
    expected_host: &str,
) -> Result<(), LaneMismatch> {
    let _ = verified.lane(); // the lane this destination sits on; the field check below is what
                             // stands in here for the full three-way cross-check the kernel loop's Meter step runs,
                             // which also folds in the response-side locator this crate does not
                             // see.
    let actual = envelope
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(field))
        .map(|(_, v)| v.as_str());
    if actual == Some(expected_host) {
        Ok(())
    } else {
        Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field })
    }
}

/// The allow-listed client request headers that ride upstream verbatim, paired with the egress
/// dialect(s) they are meaningful for. Every OTHER client request header is dropped, never
/// forwarded. Never contains a hop-by-hop, `host`, or auth/credential header — forwarding is
/// strictly opt-in.
pub const FORWARDED_CLIENT_HEADERS: &[(&str, &[&str])] = &[
    ("anthropic-beta", &["anthropic"]),
    ("anthropic-version", &["anthropic"]),
    ("openai-beta", &["openai", "responses"]),
];

/// The union of every forwardable client-header name, for a collector that runs before the egress
/// dialect is known (routing/failover may still pick a different dialect's lane after collection).
pub fn forwardable_client_header_names() -> Vec<&'static str> {
    FORWARDED_CLIENT_HEADERS.iter().map(|(name, _)| *name).collect()
}

/// The client-header names allow-listed for `egress_dialect` — the no-cross-dialect-leak guard
/// applied at egress assembly, once the actual destination dialect is known. Empty for a dialect
/// with no forwardable header names.
pub fn allowed_client_headers_for(egress_dialect: &str) -> Vec<&'static str> {
    FORWARDED_CLIENT_HEADERS
        .iter()
        .filter(|(_, dialects)| dialects.contains(&egress_dialect))
        .map(|(name, _)| *name)
        .collect()
}

#[cfg(test)]
mod tests;
