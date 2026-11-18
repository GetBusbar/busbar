// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AUTH_SIGNED_INGRESS: the Standard Webhooks verifier (IF §12.11). HMAC-SHA256 over `{id}.{timestamp}.{body}`
//! with the route's configured secret, 5-minute tolerance, through the crypto facade. [`admit`] adds the replay
//! claim `standard-webhooks/<ts>/<id>` (ttl 300 s): a verified request is admitted only when it wins.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use busbar_contract::crypto;
use busbar_contract::secret_ref::SecretRef;
use busbar_contract::secure::SecureVec;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::types::Pair;

use crate::plane_grants::{IngressVerifier, ReplayGuard};

/// Clock tolerance either side of now, seconds.
pub(crate) const TOLERANCE_S: u64 = 300;
/// Replay-claim lifetime, seconds.
pub const REPLAY_TTL_S: u64 = 300;
const SECRET_PREFIX: &str = "whsec_";

/// Custody's answer for a route's webhook secret: its bytes, or None when it does not resolve.
pub trait RouteSecrets: Send + Sync + 'static {
    fn resolve<'a>(&'a self, reference: &'a SecretRef) -> BoxFut<'a, Option<SecureVec>>;
}

/// The Standard Webhooks verifier over `S`.
pub struct StandardWebhooks<S> {
    secrets: S,
}

impl<S: RouteSecrets> StandardWebhooks<S> {
    pub fn new(secrets: S) -> Self {
        Self { secrets }
    }
}

fn header<'a>(headers: &[Pair<'a>], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|p| p.name.get().eq_ignore_ascii_case(name))
        .and_then(|p| core::str::from_utf8(p.value.get()).ok())
}

/// The key bytes: `whsec_<base64>` decodes, anything else is used as written.
fn key_bytes(secret: &[u8]) -> Option<SecureVec> {
    match core::str::from_utf8(secret)
        .ok()?
        .strip_prefix(SECRET_PREFIX)
    {
        Some(b64) => STANDARD.decode(b64).ok().map(SecureVec::from),
        None => Some(SecureVec::from(secret)),
    }
}

/// The (webhook-id, webhook-timestamp) of a request that verified.
pub struct Verified<'a> {
    pub id: &'a str,
    pub timestamp: u64,
}

/// The pure check: headers present, timestamp inside the tolerance, one `v1,` signature matching.
pub fn check<'a>(
    secret: &[u8],
    headers: &[Pair<'a>],
    body: &[u8],
    now_s: u64,
) -> Option<Verified<'a>> {
    let id = header(headers, "webhook-id")?;
    let ts = header(headers, "webhook-timestamp")?;
    let sigs = header(headers, "webhook-signature")?;
    let timestamp: u64 = ts.parse().ok()?;
    if now_s.abs_diff(timestamp) > TOLERANCE_S {
        return None;
    }
    let key = key_bytes(secret)?;
    // A key the backend refuses verifies nothing, as before.
    let mac_key = crypto::HmacSha256Key::new(&key).ok()?;
    // The signed message is `<id>.<timestamp>.<body>`. It is MACed in its parts, where they lie:
    // the body is never copied to be joined to its prefix. The MAC is made once, on the first
    // candidate that decodes, and every candidate is compared with the whole of it in constant
    // time (a tag of another length never matches).
    let mut expected: Option<[u8; 32]> = None;
    let mut matched = false;
    for candidate in sigs.split(' ') {
        let Some(b64) = candidate.strip_prefix("v1,") else {
            continue;
        };
        if let Ok(tag) = STANDARD.decode(b64) {
            let mac = expected.get_or_insert_with(|| {
                mac_key.sign_parts(&[id.as_bytes(), b".", ts.as_bytes(), b".", body])
            });
            // Every candidate is checked: the answer does not depend on which one matched.
            matched |= crypto::ct_eq(mac.as_slice(), &tag);
        }
    }
    if let Some(mac) = expected.as_mut() {
        zeroize::Zeroize::zeroize(mac);
    }
    matched.then_some(Verified { id, timestamp })
}

impl<S: RouteSecrets> IngressVerifier for StandardWebhooks<S> {
    fn verify<'a>(
        &'a self,
        route_secret: &'a SecretRef,
        headers: &'a [Pair<'a>],
        body: &'a [u8],
        now_s: u64,
    ) -> BoxFut<'a, bool> {
        Box::pin(async move {
            match self.secrets.resolve(route_secret).await {
                Some(secret) => check(&secret, headers, body, now_s).is_some(),
                None => false,
            }
        })
    }
}

/// Why a signed request was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// Signature, timestamp or headers do not verify (R_BAD_CREDENTIAL).
    BadCredential,
    /// The request was seen before (R_REPLAYED, audit `auth_replay`).
    Replayed,
    /// The replay store could not be reached: refuse (fail closed).
    Unavailable,
}

/// Verify, then claim the replay key; admitted only when both succeed.
pub async fn admit<V: IngressVerifier + ?Sized, G: ReplayGuard + ?Sized>(
    verifier: &V,
    guard: &G,
    plane: &Caller<'_>,
    route_secret: &SecretRef,
    headers: &[Pair<'_>],
    body: &[u8],
    now_s: u64,
) -> Result<(), Refused> {
    if !verifier.verify(route_secret, headers, body, now_s).await {
        return Err(Refused::BadCredential);
    }
    // `verify` passed, so both headers are present and the timestamp parses.
    let (Some(id), Some(ts)) = (
        header(headers, "webhook-id"),
        header(headers, "webhook-timestamp"),
    ) else {
        return Err(Refused::BadCredential);
    };
    // `standard-webhooks/<ts>/<id>`, built on the stack (a heap block only for an unusually long id).
    let mut key: smallvec::SmallVec<[u8; 256]> = smallvec::SmallVec::new();
    key.extend_from_slice(b"standard-webhooks/");
    key.extend_from_slice(ts.as_bytes());
    key.push(b'/');
    key.extend_from_slice(id.as_bytes());
    match guard.claim(plane, &key, REPLAY_TTL_S).await {
        Ok(true) => Ok(()),
        Ok(false) => Err(Refused::Replayed),
        Err(_) => Err(Refused::Unavailable),
    }
}
