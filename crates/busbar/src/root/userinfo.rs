// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::redacted::Secret;

const AUTHORIZATION: &str = "authorization";

/// THE BASIC VALUE AN OPERATOR'S URL SPELLED (`Basic base64(user:pass)`), root-owned. `Debug` prints
/// a marker; the bytes are zeroised when the last copy drops.
#[derive(Clone)]
pub struct UserinfoBasic(Arc<Secret<Vec<u8>>>);

impl UserinfoBasic {
    #[must_use]
    pub fn of(url: &str) -> Option<Self> {
        let parts = busbar_contract::net::url_authority(url);
        parts.scheme?;
        let spelled = parts.userinfo?;
        let (user, pass) = match spelled.split_once(':') {
            Some((user, pass)) => (user, Some(pass).filter(|p| !p.is_empty())),
            None => (spelled, None),
        };
        let user = Secret::new(percent_decoded(user)?);
        let pass = pass.and_then(percent_decoded).map(Secret::new);

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

    fn bytes(&self) -> &[u8] {
        self.0.expose(&busbar_kernel::seal::lend())
    }

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

    #[must_use]
    pub fn lead(&self, answer: Fields) -> Fields {
        match answer {
            Fields::Ready(mut fields)
                if !fields
                    .iter()
                    .any(|f| !f.query && f.name.eq_ignore_ascii_case(AUTHORIZATION.as_bytes())) =>
            {
                fields.insert(
                    0,
                    AuthField {
                        name: AUTHORIZATION.as_bytes().to_vec(),
                        value: Secret::new(self.bytes().to_vec()),
                        sensitive: true,
                        query: false,
                        require_secure: false,
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
