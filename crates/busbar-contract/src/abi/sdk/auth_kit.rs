// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S SHARED PLUGIN PIECES (`abi::auth`): what the auth plugins wrote alike, stated

use std::borrow::Cow;

use crate::abi::auth::{
    retry_after_extensions, IdentifyOut, IdentityBuf, IDENTITY_HAS_TTL, LOGIN_IDENTITY,
    LOGIN_OUTAGE, SPAN_ABSENT,
};
use crate::abi::mechanism::call::{Blob, Outcome, Span, BLOB_ABSENT, BLOB_OCTETS};
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::out::Out;
use crate::auth::Principal;

/// The `map_err` for a decode of `what` whose input may carry a secret: `<what>: <serde's words>`

pub fn json_error(what: &'static str) -> impl FnOnce(serde_json::Error) -> String {
    move |e: serde_json::Error| {
        let text = e.to_string();
        if e.is_data()
            && (text.starts_with("missing field `") || text.starts_with("unknown field `"))
        {
            return format!("{what}: {text}");
        }
        let class = match e.classify() {
            serde_json::error::Category::Io => "the input could not be read",
            serde_json::error::Category::Syntax => "it is not well-formed JSON",
            serde_json::error::Category::Data => "a field is missing or has the wrong type",
            serde_json::error::Category::Eof => "it ends before the JSON does",
        };
        let (line, column) = (e.line(), e.column());
        format!("{what}: {class} (line {line}, column {column}; the decoder's text is withheld)")
    }
}

/// `complete_login`'s answer that is not an identity: `verdict`

pub fn login_declined(
    verdict: u32,
    why: impl Into<Cow<'static, str>>,
    out: &mut Out<'_, IdentifyOut>,
) -> Outcome {
    out.set(|o| &o.verdict, verdict);
    out.reason(why);
    Outcome::Ready
}

/// No span: the field is absent.
const ABSENT: Span = Span {
    offset: SPAN_ABSENT,
    len: 0,
};

/// `complete_login`'s identity answer for `p`, written into the host's `buf`: its id as the

pub fn login_identity(
    p: &Principal,
    buf: Lent<'_, IdentityBuf>,
    out: &mut Out<'_, IdentifyOut>,
) -> Outcome {
    let (mut bytes, mut groups) = (buf.buf(), buf.groups());
    let need_bytes = p.id.len()
        + p.name.as_ref().map_or(0, String::len)
        + p.roles.iter().map(String::len).sum::<usize>();
    if need_bytes > bytes.cap() || p.roles.len() > groups.cap() {
        out.set(|o| &o.needed_bytes, need_bytes as u64);
        out.set(
            |o| &o.needed_groups,
            u32::try_from(p.roles.len()).unwrap_or(u32::MAX),
        );
        return Outcome::Failed;
    }
    let subject = bytes.span(p.id.as_bytes());
    let name = p.name.as_ref().map_or(ABSENT, |n| bytes.span(n.as_bytes()));
    for role in &p.roles {
        let s = bytes.span(role.as_bytes());
        groups.push(s);
    }
    let (flags, ttl) = p.ttl_secs.map_or((0, 0), |t| (IDENTITY_HAS_TTL, t));
    out.set(|o| &o.identity.subject, subject);
    out.set(|o| &o.identity.key_id, ABSENT);
    out.set(|o| &o.identity.key_name, ABSENT);
    out.set(|o| &o.identity.user, ABSENT);
    out.set(|o| &o.identity.provider, ABSENT);
    out.set(|o| &o.identity.name, name);
    out.set(|o| &o.identity.claims, ABSENT);
    out.set(|o| &o.identity.claims_fmt, BLOB_ABSENT);
    out.set(|o| &o.identity.flags, flags);
    out.set(|o| &o.identity.ttl_secs, ttl);
    out.set(
        |o| &o.identity.groups_len,
        u32::try_from(groups.written()).unwrap_or(u32::MAX),
    );
    out.set(|o| &o.verdict, LOGIN_IDENTITY);
    Outcome::Ready
}

/// `complete_login`'s answer for an IdP that could not answer (connect, TLS, a timeout, a 5xx or

pub fn login_outage(
    retry_after_secs: Option<u64>,
    buf: Lent<'_, IdentityBuf>,
    out: &mut Out<'_, IdentifyOut>,
) -> Outcome {
    out.set(|o| &o.verdict, LOGIN_OUTAGE);
    if let Some(secs) = retry_after_secs {
        let entry = retry_after_extensions(secs);
        let mut bytes = buf.buf();
        if entry.len() <= bytes.cap() {
            let at = bytes.span(&entry);
            out.raw().head.extensions = Blob {
                ptr: bytes.as_ptr().wrapping_add(at.offset as usize).cast_const(),
                len: entry.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        }
    }
    Outcome::Ready
}

#[cfg(test)]
#[path = "tests/auth_kit_tests.rs"]
mod tests;
