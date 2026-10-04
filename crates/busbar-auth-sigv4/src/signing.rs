// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE `sigv4` STYLE: per-request AWS Signature Version 4 over the request, the credential being
//! `ACCESS_KEY_ID:SECRET[:SESSION_TOKEN]`. MOVED VERBATIM from the `Scheme::SigV4` arm of
//! the identity unit's `egress_auth/mod.rs::decorate` in the kernel and the `EgressScheme::SigV4` arm of
//! `.../declared.rs::present`, staged `busbar-auth-outbound::signing` (KERNEL<>PLUGINS step 22),
//! then here (AUTH-SPLIT): the same checks before signing, the same SET-never-append over the
//! signed set, the same `Authorization` value and the same field order.
//!
//! THE DAILY KEY (BUSBAR-1.6.0.md THE DESIGN, §6.5). The HMAC chain over date, region and service is derived once per
//! UTC day and held here, wiped on drop; `tick` derives the next day's key ahead of midnight
//! ([`SigV4Binding::prederive`]), so a request signs with a key already in hand. A binding built for
//! the CALLER's credential (`STYLE_CALLER_CREDENTIAL` passthrough mode, ARCHITECT ruling
//! 2026-09-29) is instead constructed fresh per request in [`crate::Fields`] and never enters this
//! cache — the caller's key varies request to request, so there is nothing to hold ahead of time.

use std::sync::RwLock;

use busbar_contract::header::is_legal_header_value;
use busbar_contract::redacted::Redacted;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::sigv4;

/// The seconds in a day.
const DAY_SECS: u64 = 86_400;
/// How long before UTC midnight `tick` derives the next day's key.
const PREDERIVE_AHEAD_SECS: u64 = 3_600;

/// A `sigv4` binding's settings: the service and region the signature is scoped to, and the request
/// content type the signature covers beside the host. The kernel resolves them at seal (the region
/// from the provider's host through the plane's declared function) — see the seam in the crate doc.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigV4Params {
    /// The AWS service name.
    pub service: String,
    /// The AWS region.
    pub region: String,
    /// The request content type.
    pub content_type: String,
}

/// The request facts a signature covers.
#[derive(Debug, Clone, Copy)]
pub struct SignFacts<'a> {
    /// The host the request is sent to (the `host` field the signature covers).
    pub host: &'a str,
    /// The encoded path, which is also the canonical URI.
    pub canonical_uri: &'a str,
    /// Lowercase hex SHA-256 of the body.
    pub payload_hash: &'a str,
    /// Seconds since the epoch (1970-01-01 UTC).
    pub timestamp_epoch: u64,
}

/// A credential split for signing, the secret held redacted.
pub struct SigningCredential {
    access_key_id: String,
    secret: Redacted<String>,
    session_token: Option<Redacted<String>>,
}

impl std::fmt::Debug for SigningCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl SigningCredential {
    /// Split `raw` ([`sigv4::split_credential`]); `None` when either of the first two parts is
    /// missing or empty — the credential then signs nothing.
    pub fn split(raw: &str) -> Option<Self> {
        let (access, secret, token) = sigv4::split_credential(raw)?;
        Some(Self {
            access_key_id: access.to_string(),
            secret: Redacted::new(secret.to_string()),
            session_token: token.map(|t| Redacted::new(t.to_string())),
        })
    }

    /// Whether the session token is present and not a legal header value: the credential then
    /// signs nothing (signing over a token the wire cannot carry is a guaranteed mismatch).
    pub fn session_token_unsendable(&self) -> bool {
        self.session_token
            .as_ref()
            .is_some_and(|t| !is_legal_header_value(t.expose_secret()))
    }
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

/// One day's derived key.
struct DayKey {
    datestamp: String,
    key: Zeroizing<Vec<u8>>,
}

/// A `sigv4` binding: the params, the credential, and the day keys derived for it.
pub struct SigV4Binding {
    params: SigV4Params,
    credential: Option<SigningCredential>,
    /// Today's key and, ahead of midnight, tomorrow's.
    keys: RwLock<Vec<DayKey>>,
}

impl std::fmt::Debug for SigV4Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigV4Binding")
            .field("params", &self.params)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

impl SigV4Binding {
    /// A binding of `params` to `credential` (`None`: a credential that signs nothing).
    pub fn new(params: SigV4Params, credential: Option<SigningCredential>) -> Self {
        Self {
            params,
            credential,
            keys: RwLock::new(Vec::new()),
        }
    }

    /// The params this binding signs under — read back to build a fresh per-request binding for
    /// the caller's credential in passthrough mode ([`crate::Fields`]).
    pub fn params(&self) -> &SigV4Params {
        &self.params
    }

    /// Derive (and keep) the key for `datestamp` unless held; at most two days are kept.
    fn derive(&self, datestamp: &str) {
        let Some(cred) = &self.credential else {
            return;
        };
        let held = self
            .keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .any(|k| k.datestamp == datestamp);
        if held {
            return;
        }
        let key = sigv4::signing_key(
            cred.secret.expose_secret(),
            datestamp,
            &self.params.region,
            &self.params.service,
        );
        let mut keys = self
            .keys
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if keys.iter().any(|k| k.datestamp == datestamp) {
            return;
        }
        keys.push(DayKey {
            datestamp: datestamp.to_string(),
            key,
        });
        keys.sort_by(|a, b| a.datestamp.cmp(&b.datestamp));
        while keys.len() > 2 {
            keys.remove(0);
        }
    }

    /// The datestamps whose keys are held, oldest first.
    #[cfg(test)]
    pub fn held(&self) -> Vec<String> {
        self.keys
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|k| k.datestamp.clone())
            .collect()
    }

    /// `tick`: hold today's key, and tomorrow's once within [`PREDERIVE_AHEAD_SECS`] of midnight.
    pub fn prederive(&self, now_epoch: u64) {
        let (_, today) = sigv4::format_amz_time(now_epoch);
        self.derive(&today);
        if DAY_SECS - now_epoch % DAY_SECS <= PREDERIVE_AHEAD_SECS {
            let (_, tomorrow) = sigv4::format_amz_time(now_epoch + DAY_SECS);
            self.derive(&tomorrow);
        }
    }

    /// Sign one request: the fields to set, in order, or NONE when the credential cannot sign
    /// (missing, an empty access key id or secret, an unsendable session token, or an access key id
    /// that makes the `Authorization` value illegal).
    pub fn sign(&self, facts: &SignFacts<'_>) -> Vec<(String, String)> {
        let Some(cred) = &self.credential else {
            return Vec::new();
        };
        // Validated BEFORE signing, so the signed set and the sent set are gated by the same
        // check: a token the wire cannot carry must not be signed over and then dropped.
        if cred.access_key_id.is_empty()
            || cred.secret.expose_secret().is_empty()
            || cred.session_token_unsendable()
        {
            return Vec::new();
        }
        let region = self.params.region.as_str();
        let service = self.params.service.as_str();
        let (amzdate, datestamp) = sigv4::format_amz_time(facts.timestamp_epoch);
        let payload_hash = facts.payload_hash.to_string();
        // The declared scheme signs the content type and the host (`declared.rs::present`), then
        // SETS, never appends, the fields it writes.
        let mut headers: Vec<(String, String)> = vec![
            ("content-type".to_string(), self.params.content_type.clone()),
            ("host".to_string(), facts.host.to_string()),
        ];
        set_header(&mut headers, "x-amz-date", amzdate.clone());
        set_header(&mut headers, "x-amz-content-sha256", payload_hash.clone());
        if let Some(t) = &cred.session_token {
            set_header(
                &mut headers,
                "x-amz-security-token",
                t.expose_secret().clone(),
            );
        }
        self.derive(&datestamp);
        let sign_with = |key: &[u8]| {
            // A POST of the body to its path, with no query: the request 1.5.5's signing dialect writer
            // signed (`declared.rs::request`).
            sigv4::sign_v4_with_key(
                key,
                region,
                service,
                "POST",
                facts.canonical_uri,
                "",
                &headers,
                &payload_hash,
                &amzdate,
                &datestamp,
            )
        };
        let held = {
            let keys = self
                .keys
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            keys.iter()
                .find(|k| k.datestamp == datestamp)
                .map(|k| sign_with(&k.key))
        };
        // A date older than both held keys (a skewed request clock) is derived for this request
        // alone rather than evicting a day key.
        let (signature, signed_headers) = held.unwrap_or_else(|| {
            sign_with(&sigv4::signing_key(
                cred.secret.expose_secret(),
                &datestamp,
                region,
                service,
            ))
        });
        let credential_scope = format!(
            "{datestamp}/{region}/{service}/{}",
            sigv4::SIGNATURE_TERMINATION
        );
        let authorization = format!(
            "{} Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
            sigv4::SIGV4_ALGORITHM,
            cred.access_key_id,
        );
        // The access key id rides in this value verbatim, so it is the one input that can make
        // it unsendable; the date and the hash are always legal.
        if !is_legal_header_value(&authorization) {
            return Vec::new();
        }
        let mut fields = vec![
            ("authorization".to_string(), authorization),
            ("x-amz-date".to_string(), amzdate),
            ("x-amz-content-sha256".to_string(), payload_hash),
        ];
        if let Some(t) = &cred.session_token {
            fields.push((
                "x-amz-security-token".to_string(),
                t.expose_secret().clone(),
            ));
        }
        fields
    }
}

#[cfg(test)]
#[path = "tests/signing_tests.rs"]
mod tests;
