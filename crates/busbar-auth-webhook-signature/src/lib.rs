// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! # busbar-auth-webhook-signature — an inbound request signed by its sender, one auth-kind plugin
//!
//! THE MECHANISM: a webhook sender that holds no busbar credential signs each request with a secret
//! it shares with the receiver — an HMAC over what it sent — and presents the signature in a header.
//! This plugin checks that signature on the auth kind's inbound `verify` (webhook
//! signature verification belongs to the auth kind; the request's handler never sees the secret).
//! It is named by the mechanism, not by a sender; a sender's exact algorithm is a VARIANT
//! ([`Variant`], the algorithms in [`signature`]):
//!
//! * `twilio` — HMAC-SHA1 over the full URL plus the sorted POST form parameters, in
//!   `X-Twilio-Signature`. It authenticates a Twilio Media Streams WebSocket upgrade (a GET: the URL
//!   alone), which a claim names under the `webhook-signature` scheme alternative
//!   (Twilio cannot present a busbar bearer or API key), and Twilio's signed POSTs.
//! * `standard-webhooks` — the Standard Webhooks specification: HMAC-SHA256 over
//!   `id.timestamp.body`, in `webhook-id` / `webhook-timestamp` / `webhook-signature`, with a
//!   timestamp tolerance against replay.
//!
//! It runs on the SDK's safe layer ([`busbar_contract::auth_verify_door!`]): the crate holds no
//! `unsafe`. Its settings are one JSON document ([`Settings`]); its one secret, the shared signing
//! secret, arrives through the secret kind as the Statement's `signing-secret` reference and is
//! never logged or echoed. Its inbound point is `HeadBody` (THE DESIGN, "Auth points and guest
//! lists"): the host lends the whole body, bounded by the size gate, so a signature over the body is
//! checked over the bytes received; a request the host lent no body is refused (fail-closed).
//! Whatever its verdict, it names its signature header lines for the transport to strip, so the
//! request's handler never sees them.
//!
//! THE VERDICTS:
//! * none of the variant's headers present — PASS: not this plugin's credential. A claim whose only
//!   alternative is this one is then refused, because nothing identified the request.
//! * a signature that verifies (and, for `standard-webhooks`, a timestamp within the tolerance) —
//!   IDENTITY ([`Settings::subject`]).
//! * anything else, including a partial header set — REJECT, fail-closed.
//!
//! REPLAY: a verified `standard-webhooks` identity carries a replay key
//! (`standard-webhooks/<webhook-id>`) and the rest of its tolerance window as TTL; the kernel claims
//! it in its record store and refuses the same message id again inside the window. A `twilio` identity carries none: its signature has
//! no nonce or timestamp to key on, and v1.5.5 had no Twilio surface whose behaviour to keep
//! (`git grep -i twilio v1.5.5`: 0 hits). A signature replayed on ANOTHER URL, or over another body,
//! does not verify.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod signature;

use busbar_contract::abi::auth::{AuthPoints, AuthTail};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::abi::mechanism::door::{MarkWord, Statement};
use busbar_contract::abi::sdk::auth_door::{
    carrier, verify_tail, with_tail, Answer, Strip, Verdict, VerifiedIdentity, VerifyPlugin,
    VerifyView,
};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::auth_calls::Replay;
use serde::Deserialize;

/// The scheme alternative a claim names to be authenticated by this plugin.
pub const SCHEME_ALTERNATIVE: &str = "webhook-signature";

/// The Statement's one secret reference: the shared signing secret (for `twilio`, the account's
/// auth token; for `standard-webhooks`, the `whsec_` secret), resolved by the secret kind.
pub const SECRET_REF: &str = "signing-secret";

/// The header a `twilio` signature is presented in (matched ASCII case-insensitively).
pub const TWILIO_SIGNATURE_HEADER: &str = "x-twilio-signature";
/// The Standard Webhooks message id header.
pub const WEBHOOK_ID_HEADER: &str = "webhook-id";
/// The Standard Webhooks timestamp header (seconds since the epoch).
pub const WEBHOOK_TIMESTAMP_HEADER: &str = "webhook-timestamp";
/// The Standard Webhooks signature-list header.
pub const WEBHOOK_SIGNATURE_HEADER: &str = "webhook-signature";

/// The Standard Webhooks default tolerance, either direction: five minutes.
pub const DEFAULT_TOLERANCE_SECS: u64 = 300;

/// Which sender's algorithm a configured instance checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Variant {
    /// Twilio: HMAC-SHA1 over the full URL plus the sorted POST form parameters, base64, in
    /// `X-Twilio-Signature`.
    Twilio,
    /// Standard Webhooks: HMAC-SHA256 over `id.timestamp.body`, in `webhook-signature`.
    StandardWebhooks,
}

impl Variant {
    fn name(self) -> &'static str {
        match self {
            Variant::Twilio => "twilio",
            Variant::StandardWebhooks => "standard-webhooks",
        }
    }
}

/// The settings document, one JSON object.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// The sender's algorithm.
    pub variant: Variant,
    /// `twilio` only, and required there: the scheme and authority the SENDER requested — exactly
    /// as configured at the sender (for a Twilio Media Stream, the scheme and host of the
    /// `<Stream url>`, e.g. `wss://edge.example.com`). The signed URL is this, then the received
    /// path and query, byte for byte. Configuration rather than read off the request, because the
    /// sender signs the URL it was given, not whatever authority a front proxy forwards.
    #[serde(default)]
    pub origin: Option<String>,
    /// `standard-webhooks` only: the allowed distance, in seconds, between `webhook-timestamp` and
    /// now, either direction. Default [`DEFAULT_TOLERANCE_SECS`].
    #[serde(default)]
    pub tolerance_secs: Option<u64>,
    /// The identity a verified request is attributed to. Default `webhook-signature:<variant>`.
    #[serde(default)]
    pub subject: Option<String>,
}

impl Settings {
    /// Parse and check a settings document.
    ///
    /// # Errors
    /// Not a settings object of this plugin, or a field the variant does not take or lacks.
    pub fn parse(settings: &[u8]) -> Result<Self, &'static str> {
        let s: Settings = serde_json::from_slice(settings)
            .map_err(|_| "settings: not a webhook-signature settings object")?;
        match s.variant {
            Variant::Twilio => {
                let Some(origin) = &s.origin else {
                    return Err("settings: `twilio` requires `origin`");
                };
                if !origin_is_scheme_and_authority(origin) {
                    return Err(
                        "settings: `origin` must be scheme://authority, with no path, query or fragment",
                    );
                }
                if s.tolerance_secs.is_some() {
                    return Err("settings: `tolerance_secs` is a `standard-webhooks` setting");
                }
            }
            Variant::StandardWebhooks => {
                if s.origin.is_some() {
                    return Err("settings: `origin` is a `twilio` setting");
                }
            }
        }
        if s.subject.as_deref() == Some("") {
            return Err("settings: `subject` must not be empty");
        }
        Ok(s)
    }

    fn subject(&self) -> String {
        self.subject
            .clone()
            .unwrap_or_else(|| format!("webhook-signature:{}", self.variant.name()))
    }
}

/// `scheme://authority`, nothing after the authority.
fn origin_is_scheme_and_authority(origin: &str) -> bool {
    let Some((scheme, authority)) = origin.split_once("://") else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        && !authority.is_empty()
        && !authority.contains(['/', '?', '#'])
        && !authority
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
}

/// One request, as much of it as a signature reads.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    /// The method.
    pub method: &'a [u8],
    /// The path, raw as received.
    pub path: &'a [u8],
    /// The query without `?`, raw as received; `None` = none.
    pub query: Option<&'a [u8]>,
    /// The body; `None` = the host lent none.
    pub body: Option<&'a [u8]>,
    /// Wall-clock seconds, read once by the host for this call.
    pub now: u64,
    /// The header `name` (ASCII case-insensitive), as presented; `None` = absent.
    pub headers: &'a dyn Fn(&str) -> Option<&'a [u8]>,
}

impl std::fmt::Debug for Request<'_> {
    // Never a header value or the body: they carry the signature and the payload.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &String::from_utf8_lossy(self.method))
            .field("path", &String::from_utf8_lossy(self.path))
            .finish_non_exhaustive()
    }
}

impl<'a> Request<'a> {
    fn get(&self, name: &str) -> Option<&'a [u8]> {
        (self.headers)(name)
    }
}

/// One configured instance: its settings and its signing key.
pub struct WebhookSignature {
    settings: Settings,
    /// The HMAC key: the token as given (`twilio`), or the decoded secret (`standard-webhooks`).
    key: Vec<u8>,
}

impl std::fmt::Debug for WebhookSignature {
    // The key is never formatted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookSignature")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

impl WebhookSignature {
    /// Build an instance from its settings document and its resolved secrets (the Statement's
    /// `secret_refs`, in order: exactly the signing secret).
    ///
    /// # Errors
    /// The settings are not this plugin's, or the signing secret is missing, empty, or (for
    /// `standard-webhooks`) not base64.
    pub fn new(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str> {
        let settings = Settings::parse(settings)?;
        let [secret] = secrets else {
            return Err("secrets: exactly one, the signing secret");
        };
        if secret.is_empty() {
            return Err("secrets: the signing secret is empty");
        }
        let key = match settings.variant {
            Variant::Twilio => secret.to_vec(),
            Variant::StandardWebhooks => signature::standard_webhooks_key(secret).ok_or(
                "secrets: a standard-webhooks secret is base64, optionally `whsec_`-prefixed",
            )?,
        };
        Ok(WebhookSignature { settings, key })
    }

    /// Judge one request.
    #[must_use]
    pub fn judge(&self, r: &Request<'_>) -> Verdict {
        // `Some(replay)` = verified; the replay claim the kernel makes after it, if any.
        let verified: Option<Option<Box<Replay>>> = match self.settings.variant {
            Variant::Twilio => {
                let Some(presented) = r.get(TWILIO_SIGNATURE_HEADER) else {
                    return Verdict::Pass;
                };
                // No replay claim: a Twilio signature carries no nonce or timestamp to key one on,
                // and there is no earlier behaviour to keep (v1.5.5 has no Twilio surface at all:
                // `git grep -i twilio v1.5.5` has 0 hits).
                self.twilio(r, presented).then_some(None)
            }
            Variant::StandardWebhooks => {
                let (id, ts, sig) = (
                    r.get(WEBHOOK_ID_HEADER),
                    r.get(WEBHOOK_TIMESTAMP_HEADER),
                    r.get(WEBHOOK_SIGNATURE_HEADER),
                );
                match (id, ts, sig) {
                    (None, None, None) => return Verdict::Pass,
                    (Some(id), Some(ts), Some(sig)) => self.standard_webhooks(r, id, ts, sig),
                    _ => None,
                }
            }
        };
        match verified {
            Some(replay) => Verdict::Identity(VerifiedIdentity {
                subject: self.settings.subject(),
                provider: Some(SCHEME_ALTERNATIVE.to_string()),
                replay,
                ..VerifiedIdentity::default()
            }),
            None => Verdict::Reject,
        }
    }

    /// Standard Webhooks: the signature over `id.timestamp.body` within the tolerance. A verified
    /// message asks the kernel to admit its `webhook-id` ONCE for the rest of the window in which its
    /// timestamp is acceptable (`timestamp + tolerance - now`, plus a second), so a replay of the
    /// same signed message inside the window is refused, and one after it is stale anyway.
    fn standard_webhooks(
        &self,
        r: &Request<'_>,
        id: &[u8],
        ts: &[u8],
        sig: &[u8],
    ) -> Option<Option<Box<Replay>>> {
        // No body lent is a body the signature cannot be checked over.
        let body = r.body?;
        let tolerance = self
            .settings
            .tolerance_secs
            .unwrap_or(DEFAULT_TOLERANCE_SECS);
        signature::standard_webhooks_verify(&self.key, id, ts, body, sig, r.now, tolerance).ok()?;
        let ts: u64 = std::str::from_utf8(ts.trim_ascii()).ok()?.parse().ok()?;
        let ttl = ts.saturating_add(tolerance).saturating_sub(r.now) + 1;
        let key = format!("standard-webhooks/{}", String::from_utf8_lossy(id));
        Some(Some(Box::new(Replay { key, ttl_secs: ttl })))
    }

    /// Twilio: a GET signs the URL; a POST whose URL carries `bodySHA256` signs the URL and binds
    /// the body by that digest; any other POST signs the URL plus its form parameters.
    fn twilio(&self, r: &Request<'_>, presented: &[u8]) -> bool {
        let url = self.twilio_url(r.path, r.query);
        if r.method.eq_ignore_ascii_case(b"GET") {
            return signature::twilio_verify(&self.key, &url, &[], presented);
        }
        // A signed request with a body the host did not lend cannot be judged: fail closed.
        let Some(body) = r.body else {
            return false;
        };
        match r
            .query
            .and_then(|q| signature::query_param(q, b"bodySHA256"))
        {
            Some(digest) => {
                signature::body_sha256_matches(body, digest)
                    && signature::twilio_verify(&self.key, &url, &[], presented)
            }
            None => signature::form_params(body).is_some_and(|params| {
                signature::twilio_verify(&self.key, &url, &params, presented)
            }),
        }
    }

    /// The URL the sender requested: the configured origin, the received path, and `?query` when
    /// the request had one.
    fn twilio_url(&self, path: &[u8], query: Option<&[u8]>) -> Vec<u8> {
        let mut url = self
            .settings
            .origin
            .as_deref()
            .unwrap_or_default()
            .as_bytes()
            .to_vec();
        url.extend_from_slice(path);
        if let Some(q) = query {
            url.push(b'?');
            url.extend_from_slice(q);
        }
        url
    }
}

impl VerifyPlugin for WebhookSignature {
    fn open(settings: &[u8], secrets: &[&[u8]]) -> Result<Self, &'static str> {
        WebhookSignature::new(settings, secrets)
    }

    fn verify(&self, request: &VerifyView<'_>) -> Answer {
        let headers = |name: &str| request.line(name);
        let verdict = self.judge(&Request {
            method: request.method(),
            path: request.path(),
            query: request.query(),
            // Lent at `HeadBody` only; none lent is a body the signature cannot be checked over.
            body: request.body(),
            now: request.timestamp(),
            headers: &headers,
        });
        Answer {
            strips: SIGNATURE_LINES.iter().map(|n| Strip::field(*n)).collect(),
            ..verdict.into()
        }
    }
}

/// The signature header lines, named for the transport to strip whatever the verdict.
const SIGNATURE_LINES: [&str; 4] = [
    TWILIO_SIGNATURE_HEADER,
    WEBHOOK_ID_HEADER,
    WEBHOOK_TIMESTAMP_HEADER,
    WEBHOOK_SIGNATURE_HEADER,
];

/// The carriers `verify` reads: the Statement's carrier word marks.
const CARRIERS: &[MarkWord] = &[
    carrier(TWILIO_SIGNATURE_HEADER),
    carrier(WEBHOOK_ID_HEADER),
    carrier(WEBHOOK_TIMESTAMP_HEADER),
    carrier(WEBHOOK_SIGNATURE_HEADER),
];

/// Verify-only and NOT cacheable: a signature is a verdict about one request, not a reusable
/// credential. Called at `HeadBody`: the signatures cover the body.
const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD_BODY);

const SECRET_REFS: &[AbiStr] = &[abi_str(SECRET_REF)];

/// THE STATEMENT: the plugin's name, version, one secret reference, its carriers and its auth tail.
pub const STATEMENT: Statement = with_tail(
    Statement {
        secret_refs: SECRET_REFS.as_ptr(),
        secret_refs_len: SECRET_REFS.len(),
        mark_words: CARRIERS.as_ptr(),
        mark_words_len: CARRIERS.len(),
        ..statement(
            "busbar-auth-webhook-signature",
            env!("CARGO_PKG_VERSION"),
            1024,
        )
    },
    TAIL,
);

busbar_contract::auth_verify_door!(WebhookSignature, STATEMENT);

#[cfg(test)]
#[path = "tests/instance_tests.rs"]
mod tests;
