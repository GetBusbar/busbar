// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN OPERATOR URL'S USERINFO AS A BASIC CREDENTIAL OF THE AUTH KIND (row 74, F25; ARCHITECT ruling
//! on #913: "the kernel never sees the key", `BUSBAR-1.6.0.md` l.650-660, 828-834, 872-873).
//!
//! 1.5.5 sent every provider request, and every token POST, with reqwest over the URL as the
//! operator wrote it (v1.5.5 `crates/busbar/src/proxy/engine/mod.rs:1669-1670`,
//! `proxy/engine/walk.rs:583-584`, `health.rs:313-314`,
//! `egress_auth/oauth_client_credentials.rs:119-126`, `egress_auth/jwt_bearer.rs:175-181`).
//! reqwest 0.12.28's `RequestBuilder::new` (`src/async_impl/request.rs:169-182`) took a
//! `user:pass@` out of the URL (`extract_authority`, `:581-605`: percent-decoded; nothing when the
//! user is empty and there is no password) and put it FIRST as a sensitive
//! `authorization: Basic base64(user:pass)` (`src/util.rs:4-25`); the request's own credential then
//! went in through `.headers(auth)`, whose `replace_headers` (`src/util.rs:50-77`) replaced that
//! field only when the credential named `authorization`.
//!
//! The composition root reads that userinfo AT CONFIGURATION TIME into a [`UserinfoBasic`], and it is
//! presented through the auth kind's outbound call alone: a member's binding is wrapped
//! ([`lead_with`]) so its fields lead with the Basic value unless they name `authorization`, and a
//! minting plugin's token POST is led by it from the root's own connection table. The kernel holds
//! the binding's handle (`Arc<dyn OutboundAuth>`) and never the bytes.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::redacted::Secret;

/// The field a URL's userinfo rides under, and the one name that displaces it.
const AUTHORIZATION: &str = "authorization";

/// THE BASIC VALUE AN OPERATOR'S URL SPELLED (`Basic base64(user:pass)`), root-owned. `Debug` prints
/// a marker; the bytes are zeroised when the last copy drops.
#[derive(Clone)]
pub struct UserinfoBasic(Arc<Secret<Vec<u8>>>);

impl UserinfoBasic {
    /// The Basic value `url`'s authority spells, or `None` when it spells no user and no password.
    /// The authority ends at the first `/`, `?`, `#` or `\`, and the userinfo is everything before
    /// its LAST `@`; the user is what precedes the first `:`, the pass what follows it (an empty pass
    /// is none). Both are percent-decoded as reqwest decoded them: a user that does not decode to
    /// UTF-8 presents nothing, a pass that does not is no pass (`extract_authority`'s two arms).
    #[must_use]
    pub fn of(url: &str) -> Option<Self> {
        // The authority the one split reads ([`busbar_contract::net::url_authority`]).
        let parts = busbar_contract::net::url_authority(url);
        parts.scheme?;
        let spelled = parts.userinfo?;
        let (user, pass) = match spelled.split_once(':') {
            Some((user, pass)) => (user, Some(pass).filter(|p| !p.is_empty())),
            None => (spelled, None),
        };
        let user = Secret::new(percent_decoded(user)?);
        let pass = pass.and_then(percent_decoded).map(Secret::new);
        // Read under the kernel's seal (Part 2 #54): the root spells the Basic value once, here.
        let seal = busbar_kernel::seal::lend();
        if user.expose(&seal).is_empty() && pass.is_none() {
            return None;
        }
        let mut plain = user.expose(&seal).as_bytes().to_vec();
        plain.push(b':');
        if let Some(pass) = &pass {
            plain.extend_from_slice(pass.expose(&seal).as_bytes());
        }
        let plain = Secret::new(plain);
        Some(Self(Arc::new(Secret::new(basic_value(
            plain.expose(&seal),
        )))))
    }

    /// The value a legacy hop handed across the auth axis (`AuthAxis::serving_presenting`), as
    /// the root holds it. TRANSITIONAL: deleted with the legacy lane plane (row 155 C).
    #[must_use]
    pub fn from_value(bytes: &[u8]) -> Option<Self> {
        (!bytes.is_empty()).then(|| Self(Arc::new(Secret::new(bytes.to_vec()))))
    }

    /// The value's bytes, for the root's own field writers, read under the kernel's seal (Part 2
    /// #54).
    fn bytes(&self) -> &[u8] {
        self.0.expose(&busbar_kernel::seal::lend())
    }

    /// A connection open's head `fields` with this value LEADING them under `authorization`, or
    /// `None` when they already name `authorization` (the value then rides nowhere): 1.5.5's
    /// order and condition, for a minting plugin's token POST.
    #[must_use]
    pub fn leading<'a>(
        &'a self,
        fields: &[(&'a str, &'a [u8])],
    ) -> Option<Vec<(&'a str, &'a [u8])>> {
        if fields
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(AUTHORIZATION))
        {
            return None;
        }
        Some(
            std::iter::once((AUTHORIZATION, self.bytes()))
                .chain(fields.iter().copied())
                .collect(),
        )
    }

    /// An auth answer led by this value, under the same condition: a ready answer that names no
    /// `authorization` gets it first; one that does, and any other answer, is left as it is.
    #[must_use]
    pub fn lead(&self, answer: Fields) -> Fields {
        match answer {
            Fields::Ready(mut fields)
                if !fields
                    .iter()
                    .any(|f| f.name.eq_ignore_ascii_case(AUTHORIZATION.as_bytes())) =>
            {
                fields.insert(
                    0,
                    AuthField {
                        name: AUTHORIZATION.as_bytes().to_vec(),
                        value: Secret::new(self.bytes().to_vec()),
                        sensitive: true,
                    },
                );
                Fields::Ready(fields)
            }
            other => other,
        }
    }
}

impl std::fmt::Debug for UserinfoBasic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserinfoBasic(<redacted>)")
    }
}

/// `Basic ` and the standard base64 (padded) of `plain`: what reqwest's `util::basic_auth` wrote.
fn basic_value(plain: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = b"Basic ".to_vec();
    for chunk in plain.chunks(3) {
        let at = |i: usize| u32::from(chunk.get(i).copied().unwrap_or(0));
        let n = (at(0) << 16) | (at(1) << 8) | at(2);
        let sextet = |shift: u32| TABLE[((n >> shift) & 63) as usize];
        out.push(sextet(18));
        out.push(sextet(12));
        out.push(if chunk.len() > 1 { sextet(6) } else { b'=' });
        out.push(if chunk.len() > 2 { sextet(0) } else { b'=' });
    }
    out
}

/// `%XX` sequences decoded to bytes, the result read as UTF-8 (`None` when it is not). A `%` that
/// opens no two-digit hex escape is kept as written, as the percent-decoder reqwest used kept it.
fn percent_decoded(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (bytes[i], bytes.get(i + 1), bytes.get(i + 2)) {
            (b'%', Some(&h), Some(&l)) if hex(h).is_some() && hex(l).is_some() => {
                let (h, l) = (hex(h).unwrap_or(0), hex(l).unwrap_or(0));
                out.push((h * 16 + l) as u8);
                i += 3;
            }
            (b, _, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// A member's binding as the kernel is handed it: `auth` itself when its provider's URL spelled no
/// userinfo, else `auth` with every answer led by the Basic value ([`UserinfoBasic::lead`]).
#[must_use]
pub fn lead_with(
    auth: Arc<dyn OutboundAuth>,
    basic: Option<UserinfoBasic>,
) -> Arc<dyn OutboundAuth> {
    match basic {
        Some(basic) => Arc::new(BasicLed { inner: auth, basic }),
        None => auth,
    }
}

/// See [`lead_with`]: every call is the inner binding's own, its answers led by the Basic value.
struct BasicLed {
    inner: Arc<dyn OutboundAuth>,
    basic: UserinfoBasic,
}

impl OutboundAuth for BasicLed {
    fn open_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<u64, String> {
        self.inner.open_outbound(style, credential, settings)
    }

    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields> {
        self.inner
            .fields_now(handle, request)
            .map(|answer| self.basic.lead(answer))
    }

    fn fields(&self, handle: u64, request: FieldsRequest, deadline_ns: u64) -> Box<dyn Fielding> {
        Box::new(LedFielding {
            inner: self.inner.fields(handle, request, deadline_ns),
            basic: self.basic.clone(),
        })
    }

    fn ready(&self, handle: u64) -> bool {
        self.inner.ready(handle)
    }
}

/// An inner `fields` in flight, its answer led by the Basic value once it arrives.
struct LedFielding {
    inner: Box<dyn Fielding>,
    basic: UserinfoBasic,
}

impl std::future::Future for LedFielding {
    type Output = Fields;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Fields> {
        let this = &mut *self;
        Pin::new(&mut this.inner)
            .poll(cx)
            .map(|answer| this.basic.lead(answer))
    }
}

impl Fielding for LedFielding {
    fn settled(&mut self) -> Option<Fields> {
        self.inner.settled().map(|answer| self.basic.lead(answer))
    }
}

#[cfg(test)]
#[path = "tests/userinfo.rs"]
mod tests;
