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
//!   custom header (`api-key` / `x-goog-api-key`), and per-request AWS SigV4 (with a temporary
//!   credential's session token).
//! - [`bearer_auth_headers`] and [`api_key_auth_headers`] — the two static credential header
//!   builders, whose one legality rule ([`is_legal_header_value`]) `decorate` applies too, so a slot
//!   substituted here and a header built here are the same bytes.
//! - [`present`] and [`presentation`] — a protocol's DECLARED egress scheme (a credential-family
//!   table, or a signature whose region is a declared function of the host), read and decorated
//!   here under the kernel's `Grant<Sign>`; [`present_declared`] adds the declaration's static
//!   headers and, through [`report_unpresented`], logs a credential it could not present in the
//!   line that scheme's builder always logged.
//! - [`sigv4`] — the signer itself, verified against AWS's published worked example.
//! - [`substitute`] — applies a decoration's [`SecretSlot`]s to an envelope exactly once each.
//! - [`lane_cross_check`] — the post-decoration re-check: the envelope must still equal the
//!   [`VerifiedDestination`] the trust unit sealed.
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

mod declared;
pub mod sigv4;
mod token_response;

pub use declared::{present, present_declared, presentation, report_unpresented};
pub use token_response::{default_expires_in, deserialize_expires_in};

use busbar_contract::caps::{AuthDecoration, Grant, SecretSlot, Sign, VerifiedDestination};

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
///
/// The lifetime is the lane's: the kernel builds a `Scheme` from the protocol's DECLARED scheme
/// plus the lane's resolved, non-secret configuration (the access key id, the region, a session
/// token), so none of it has to be `'static`.
#[derive(Debug, Clone)]
pub enum Scheme<'a> {
    /// `Authorization: Bearer <key>` — a plain bearer credential in the standard header.
    Bearer,
    /// A static custom header carrying the raw key verbatim: e.g. `api-key` or
    /// `x-goog-api-key`, per the header name the scheme is configured with.
    ApiKeyHeader {
        /// The header name, lowercase.
        header: &'static str,
    },
    /// Per-request AWS Signature Version 4. `access_key_id` is not secret (it travels in
    /// plaintext in the `Authorization` header); the signing secret is passed to [`decorate`]
    /// separately, exactly like every other scheme.
    SigV4 {
        /// The non-secret AWS access key id.
        access_key_id: &'a str,
        /// The AWS region the request is scoped to.
        region: &'a str,
        /// The AWS service name this scheme is configured to sign for.
        service: &'a str,
        /// A temporary credential's session token, when the lane has one. It is sent as its own
        /// header AND folded into the signed set, so the two can never disagree; a token that is
        /// not a legal header value decorates nothing (see [`decorate`]).
        session_token: Option<SessionToken<'a>>,
    },
}

/// A temporary credential's session token. A newtype only so that it prints redacted: a
/// [`Scheme`] logged with `{:?}` shows that a token is present, never the token.
#[derive(Clone, Copy)]
pub struct SessionToken<'a>(pub &'a str);

impl std::fmt::Debug for SessionToken<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// Whether `s` is a legal HTTP header value — byte for byte the rule the `http` crate's
/// `HeaderValue::from_str` applies (every byte `>= 0x20` except DEL `0x7F`, plus horizontal tab),
/// which is the rule every egress credential header builder has always been judged by. A config
/// system that injects a stray CR/LF/NUL must not produce a request-smuggling header; the
/// egress-auth unit omits the header entirely instead (the upstream then answers 401, exactly like
/// every other misconfigured-credential path). Spelled here rather than borrowed so this crate takes
/// no HTTP-stack dependency; `tests::header_value_rule_is_the_http_crate_rule` pins the table.
pub fn is_legal_header_value(s: &str) -> bool {
    s.bytes().all(|b| (b >= 0x20 && b != 0x7F) || b == b'\t')
}

/// The `Authorization` value for a bearer credential: the one place the scheme word and the
/// credential are joined, shared by [`bearer_auth_headers`] and [`substitute`].
fn token_value(key: &str) -> String {
    format!("Bearer {key}")
}

/// The static bearer egress credential: `authorization: Bearer <key>`, or NO header when the key
/// carries a byte that is not a legal header value (the upstream then answers 401). Header name and
/// value, as the envelope pairs this unit speaks.
///
/// This is the body of the header builder the dialects shared (`proto::bearer_auth_headers`),
/// moved to the unit that owns egress credentials so the kernel can present the credential and no
/// plane ever holds the key. The omission is the whole policy; REPORTING it is the caller's — the
/// kernel owns the diagnostics catalog and this crate takes no logging dependency, so an empty
/// result for a non-empty key is the signal the caller turns into its coded diagnostic. The key
/// itself is never logged, here or there.
pub fn bearer_auth_headers(key: &str) -> Vec<(String, String)> {
    if !is_legal_header_value(key) {
        return Vec::new();
    }
    vec![("authorization".to_string(), token_value(key))]
}

/// The static custom-header egress credential (`api-key`, `x-goog-api-key`, …) carrying the raw key
/// verbatim, or NO header when the key carries a byte that is not a legal header value. `header` is
/// the lowercase header name the scheme declares.
///
/// The body of the shared builder `proto::api_key_auth_headers`, moved here beside
/// [`bearer_auth_headers`]; the same omission and reporting rule applies.
pub fn api_key_auth_headers(header: &'static str, key: &str) -> Vec<(String, String)> {
    if !is_legal_header_value(key) {
        return Vec::new();
    }
    vec![(header.to_string(), key.to_string())]
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
/// An un-encodable key (a byte [`is_legal_header_value`] refuses) yields the no-header decoration —
/// the upstream then answers 401, the same graceful path every dialect already takes for a
/// malformed credential. For SigV4 the same holds for an empty access key id or secret, a session
/// token that is not a legal header value, and an access key id that would make the
/// `Authorization` value illegal: each decorates nothing rather than signing over a header that
/// cannot be sent.
pub fn decorate(
    token: &Grant<Sign>,
    scheme: &Scheme<'_>,
    secret: &str,
    body: &EgressBody<'_>,
) -> AuthDecoration {
    let nothing = || AuthDecoration::decorate(token, Vec::new(), false, Vec::new());
    match scheme {
        Scheme::Bearer => {
            if !is_legal_header_value(secret) {
                return nothing();
            }
            let slot = SecretSlot::declare(token, "header:authorization:token");
            AuthDecoration::decorate(token, Vec::new(), false, vec![slot])
        }
        Scheme::ApiKeyHeader { header } => {
            if !is_legal_header_value(secret) {
                return nothing();
            }
            let slot = SecretSlot::declare(token, format!("header:{header}:raw"));
            AuthDecoration::decorate(token, Vec::new(), false, vec![slot])
        }
        Scheme::SigV4 {
            access_key_id,
            region,
            service,
            session_token,
        } => {
            // Validated BEFORE signing, so the signed set and the sent set are gated by the same
            // check: a token the wire cannot carry must not be signed over and then dropped.
            if access_key_id.is_empty()
                || secret.is_empty()
                || session_token.is_some_and(|t| !is_legal_header_value(t.0))
            {
                return nothing();
            }
            let (amzdate, datestamp) = sigv4::format_amz_time(body.timestamp_epoch);
            let payload_hash = sigv4::sha256_hex(body.body);
            // SET, never append. Signing is re-run per attempt over whatever envelope encoding
            // handed this call, and that envelope may already carry the two fields a previous
            // decoration wrote — a retried leg, a plane that timestamps its own request. Appending
            // signs the field twice while `substitute` writes it once, so the bytes that went out
            // are not the bytes that were signed and the upstream refuses every one of them.
            let mut headers: Vec<(String, String)> = body.envelope.to_vec();
            set_header(&mut headers, "x-amz-date", amzdate.clone());
            set_header(&mut headers, "x-amz-content-sha256", payload_hash.clone());
            if let Some(SessionToken(t)) = session_token {
                set_header(&mut headers, "x-amz-security-token", t.to_string());
            }
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
            let credential_scope = format!(
                "{datestamp}/{region}/{service}/{}",
                sigv4::SIGNATURE_TERMINATION
            );
            let authorization = format!(
                "{} Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
                sigv4::SIGV4_ALGORITHM
            );
            // The access key id rides in this value verbatim, so it is the one input that can make
            // it unsendable; the date and the hash are always legal.
            if !is_legal_header_value(&authorization) {
                return nothing();
            }
            let mut fields = vec![
                ("authorization".to_string(), authorization),
                ("x-amz-date".to_string(), amzdate),
                ("x-amz-content-sha256".to_string(), payload_hash),
            ];
            if let Some(SessionToken(t)) = session_token {
                fields.push(("x-amz-security-token".to_string(), t.to_string()));
            }
            AuthDecoration::decorate(token, fields, true, Vec::new())
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
pub fn continue_handshake(token: &Grant<Sign>, _state: &[u8], _frame: &[u8]) -> AuthDecoration {
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
/// The `header:<name>:token` / `header:<name>:raw` location grammar is private to this crate:
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
            "token" => token_value(secret),
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
///
/// The value compared against is the sealed lane itself, read off the [`VerifiedDestination`] — not
/// anything the caller passes alongside it. A caller-supplied expectation would only prove that the
/// envelope still agrees with whatever the caller believed, which is exactly the belief a hook or a
/// scheme's decoration could have moved; the seal is the authority, so it is the only thing this
/// compares to. This field check stands in for the full three-way cross-check the kernel loop's
/// Meter step runs, which also folds in the response-side locator this crate does not see.
///
/// The field name is matched case-insensitively (field names are case-insensitive on the wire), and
/// a field carried twice is a refusal rather than a first-match: two spellings is not a request
/// whose destination can be read at all.
pub fn lane_cross_check(
    verified: &VerifiedDestination,
    field: &'static str,
    envelope: &[(String, String)],
) -> Result<(), LaneMismatch> {
    let sealed = verified.lane().as_str();
    let mut carrying = envelope
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(field));
    let diverged = Err(LaneMismatch::EnvelopeDivergedFromVerifiedDestination { field });
    let Some((_, actual)) = carrying.next() else {
        return diverged;
    };
    if carrying.next().is_some() {
        return diverged;
    }
    if actual == sealed {
        Ok(())
    } else {
        diverged
    }
}

#[cfg(test)]
mod tests;
