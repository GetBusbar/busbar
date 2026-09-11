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
//! - [`decorate`] — one presentation KIND per declaration, never a scheme per vendor: a credential
//!   behind a scheme word in a header, a credential written into a header verbatim, and a
//!   per-request signature over the canonical request. Which one a request takes is read off the
//!   [`CredentialPresentation`] the dialect declared, and this unit holds no list of dialects at
//!   all.
//! - [`sigv4`] — the signer itself, verified against AWS's published worked example.
//! - [`substitute`] — applies a decoration's [`SecretSlot`]s to an envelope exactly once each.
//! - [`lane_cross_check`] — the post-decoration re-check: the envelope must still equal the
//!   [`VerifiedDestination`] the trust unit sealed.
//!
//! ## What is deliberately absent
//!
//! `continue_handshake` is declared with the shape the contract calls for (a bounded number of
//! frames/bytes for a multi-round scheme's second round) but every presentation this build ships
//! is single-round, so there is no live multi-round vector to prove it against; `// contract:`
//! marks it. The query-parameter presentation is likewise declared in the contract's grammar and
//! refused here rather than guessed at: writing the request target is the egress unit's job, not
//! this one's, and no declaration in the tree carries that kind yet. Inbound signature
//! verification (a client authenticating itself to busbar, not busbar authenticating itself to an
//! upstream) is a different unit's concern — see the [`sigv4`] module doc — and was not ported
//! here.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod sigv4;

use busbar_caps::{AuthDecoration, EgressAuthToken, SecretSlot, VerifiedDestination};
use busbar_contract::kinds::{CredentialPresentation, CredentialSignature};

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

/// The non-secret parameters a request-signature presentation needs.
///
/// They are CONFIG, not a wire fact, which is why they are not on the dialect's declaration: two
/// upstreams speaking one dialect sign in different regions under different key ids, and a
/// declaration that carried them would be a declaration per upstream rather than per dialect. The
/// signing secret is not here for the reason it is not on any other presentation — it reaches
/// [`decorate`] separately, and only this unit ever holds one in the clear.
#[derive(Debug, Clone, Copy, Default)]
pub struct SigningParams<'a> {
    /// The non-secret access key id. It travels in plaintext in the signature's own header.
    pub access_key_id: &'a str,
    /// The region the request is scoped to.
    pub region: &'a str,
    /// The service name the request is scoped to.
    pub service: &'a str,
}

/// Whether `s` is safe to carry as an HTTP header value: no ASCII control byte (0x00-0x1F, 0x7F).
/// A config system that injects a stray CR/LF/NUL must not produce a request-smuggling header; the
/// egress-auth unit omits the header entirely instead (the upstream then answers 401, exactly like
/// every other misconfigured-credential path).
fn is_valid_header_value(s: &str) -> bool {
    !s.bytes().any(|b| b.is_ascii_control())
}

/// Decorate an outbound request the way `presentation` declares, given the already-resolved
/// `secret`. Only the egress-auth unit ever sees `secret` in the clear (`expose()` is confined to
/// the auth, egress-auth and transport-key units) — that is why this function, not a plane, takes
/// it.
///
/// `presentation` is the dialect's own declaration, handed in by whoever composed this unit with
/// that dialect. The unit reads the KIND and nothing else: two dialects that present the same way
/// take the same path here and are indistinguishable to it, and a dialect nobody mounted hands in
/// no declaration and therefore reaches no path at all.
///
/// Every presentation that carries the credential itself declares a [`SecretSlot`] naming WHERE
/// the secret goes rather than writing it into `fields` directly, so [`substitute`] is the one
/// place the literal secret bytes are ever assembled into the envelope. A request signature is
/// different in kind: what goes on the wire is a value DERIVED from the secret that does not let
/// anyone recover it, so it is written into `fields` directly and the decoration carries no slot.
///
/// An un-encodable key (an ASCII control byte a config system may have injected) yields the
/// no-header decoration — the upstream then answers 401, the same graceful path a malformed
/// credential already takes.
///
/// `signing` is consulted only by the request-signature kind; every other kind ignores it.
pub fn decorate(
    token: &EgressAuthToken,
    presentation: &CredentialPresentation,
    signing: &SigningParams<'_>,
    secret: &str,
    body: &EgressBody<'_>,
) -> AuthDecoration {
    let nothing = || AuthDecoration::decorate(token, Vec::new(), false, Vec::new());
    match presentation {
        CredentialPresentation::Header { name, prefix } => {
            if !is_valid_header_value(secret) {
                return nothing();
            }
            let slot = SecretSlot::declare(
                token,
                match prefix {
                    Some(word) => format!("header:{name}:word {word}"),
                    None => format!("header:{name}:verbatim"),
                },
            );
            AuthDecoration::decorate(token, Vec::new(), false, vec![slot])
        }
        // `// contract:` the query presentation writes the request TARGET, and the target is
        // written by the egress unit before this one is called. No declaration in the tree carries
        // this kind, so there is no live shape to prove a substitution against; refuse closed and
        // let the upstream answer 401 rather than invent a grammar nothing exercises.
        CredentialPresentation::Query { .. } => nothing(),
        CredentialPresentation::RequestSignature => {
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
            let (signature, signed_headers) = sigv4::sign_v4(
                secret,
                signing.region,
                signing.service,
                body.method,
                body.canonical_uri,
                body.canonical_querystring,
                &headers,
                &payload_hash,
                &amzdate,
                &datestamp,
            );
            let credential_scope = format!(
                "{datestamp}/{}/{}/{}",
                signing.region,
                signing.service,
                sigv4::SIGV4_TERMINATION
            );
            let authorization = format!(
                "{} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
                sigv4::SIGV4_ALGORITHM,
                signing.access_key_id
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

/// The presentations this unit can serve for the set of declarations it was composed with, in
/// declared order.
///
/// This is the ONLY way in. A dialect the root did not mount contributes no signature, so its
/// presentation never appears here and the unit cannot produce it — refused by the declaration's
/// absence, not by a name this unit checked against a list it was born knowing.
pub fn presentations(set: &[CredentialSignature]) -> impl Iterator<Item = &CredentialPresentation> {
    set.iter().map(|sig| &sig.presentation)
}

/// Run the second (or later) round of a presentation whose upstream challenge spans more than one
/// handshake frame. Every presentation kind the contract declares is single-round, so there is no
/// live shape to exercise this against yet.
///
/// `// contract:` a future multi-round presentation (e.g. a challenge-response credential) implements
/// this by reading `state` (whatever it returned from its own prior round) and the upstream's
/// `frame`, and returns either another `AuthDecoration::Handshake` (more rounds needed, within the
/// bounds it already declared) or the terminal `AuthDecoration::Decorate`. The bound stays whatever
/// the FIRST decoration for this presentation declared — `continue_handshake` never widens it.
pub fn continue_handshake(token: &EgressAuthToken, _state: &[u8], _frame: &[u8]) -> AuthDecoration {
    // No shipped presentation reaches this path; refuse to guess at a shape with no real scheme to
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
/// The `header:<name>:word <Word>` / `header:<name>:verbatim` location grammar is private to this
/// crate: [`decorate`] is the only producer of a [`SecretSlot`] here, so the two agree by
/// construction. The word is written exactly as the declaration spells it, which is the spelling
/// the wire expects, so the ingress ladder's case-insensitive read and this verbatim write are one
/// declared fact used twice.
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
        let value = match template.strip_prefix("word ") {
            Some(word) => format!("{word} {secret}"),
            None if template == "verbatim" => secret.to_string(),
            None => continue,
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

/// Re-run the lane cross-check on the POST-decoration bytes: a hook, or a presentation's own
/// decoration, is permitted to touch the envelope, but the field that carries the lane (`host` for
/// every in-tree scheme's target) must still equal the [`VerifiedDestination`] the trust unit
/// sealed. `field` names the envelope key that carries the destination (`"host"` for the schemes in
/// this crate).
///
/// The value compared against is the sealed lane itself, read off the [`VerifiedDestination`] — not
/// anything the caller passes alongside it. A caller-supplied expectation would only prove that the
/// envelope still agrees with whatever the caller believed, which is exactly the belief a hook or a
/// presentation's decoration could have moved; the seal is the authority, so it is the only thing this
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
