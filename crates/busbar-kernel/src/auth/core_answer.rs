// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Core's own answer to a refusal: one shape, written by core, for every row of the refusal table
//! whose body core writes and for any row a plane could not render. The 401 is the one answer an
//! unverified caller receives on every route and on none: the same status, the same body bytes,
//! and a `WWW-Authenticate` header (HTTP requires one on a 401). Only that header's text can
//! differ, and only where a route's record declares the challenge its protocol's specification
//! requires.

use busbar_contract::route::{
    METHOD_DELETE, METHOD_GET, METHOD_HEAD, METHOD_PATCH, METHOD_POST, METHOD_PUT,
};

use super::admission_table::{Refusal, Row, TEXT_UNVERIFIED};
use crate::plane_driver::port_session::ToClient;
use crate::plane_driver::HeadFields;

/// The challenge of a 401 on a route that declares none, and on no route.
pub const GENERIC_CHALLENGE: &str = "Bearer";

const CONTENT_TYPE: &[u8] = b"content-type";
const JSON: &[u8] = b"application/json";
const WWW_AUTHENTICATE: &[u8] = b"www-authenticate";
const RETRY_AFTER: &[u8] = b"retry-after";
const ALLOW: &[u8] = b"allow";

/// A status, its head fields and its body, ready to be written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreAnswer {
    pub status: u16,
    pub fields: HeadFields,
    pub body: Vec<u8>,
}

impl CoreAnswer {
    /// The client items of this answer: its head, its body, the end.
    pub fn into_items(self) -> Vec<ToClient> {
        vec![
            ToClient::Head {
                status: self.status,
                fields: self.fields,
            },
            ToClient::Body(self.body),
            ToClient::End,
        ]
    }
}

/// The word a refusal carries in the body's `error.code`. It names the row's meaning, never which
/// check found it: a missing and a wrong credential share one word, as they share every byte.
pub const fn word(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::GatewayFull
        | Refusal::Draining
        | Refusal::VerifierUnavailable
        | Refusal::MoneyUnavailable => "unavailable",
        Refusal::Unverified { .. } | Refusal::DigestMismatch => "authentication_required",
        Refusal::KeyDisabled => "key_disabled",
        Refusal::NoRoute => "not_found",
        Refusal::WrongMethod { .. } => "method_not_allowed",
        Refusal::BodyTooLarge => "request_too_large",
        Refusal::Trailers | Refusal::NotAnUpgrade | Refusal::Unpriced => "invalid_request",
        Refusal::ScopeDenied => "permission_denied",
        Refusal::GroupFrozen | Refusal::GroupUnknown => "policy",
        Refusal::InFlight | Refusal::Window { .. } => "rate_limited",
        Refusal::BudgetSpent { .. } => "budget_exhausted",
        Refusal::Replayed => "replayed",
        Refusal::NoUpgradeTransport => "unsupported",
    }
}

/// `text` as the inside of a JSON string.
fn escape_into(out: &mut Vec<u8>, text: &str) {
    for byte in text.bytes() {
        match byte {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x00..=0x1f => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.extend_from_slice(b"\\u00");
                out.push(HEX[usize::from(byte >> 4)]);
                out.push(HEX[usize::from(byte & 0x0f)]);
            }
            _ => out.push(byte),
        }
    }
}

/// `{"error":{"code":"<word>","message":"<text>"}}`: the envelope the admin API already answers
/// in, so core has one error shape.
pub fn body(word: &str, text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(40 + word.len() + text.len());
    out.extend_from_slice(b"{\"error\":{\"code\":\"");
    escape_into(&mut out, word);
    out.extend_from_slice(b"\",\"message\":\"");
    escape_into(&mut out, text);
    out.extend_from_slice(b"\"}}");
    out
}

/// The `Allow` value of a methods mask: the methods it holds, in the vocabulary's order.
pub fn allow_value(methods: u32) -> Vec<u8> {
    let mut out = Vec::new();
    for (bit, name) in [
        (METHOD_GET, "GET"),
        (METHOD_HEAD, "HEAD"),
        (METHOD_POST, "POST"),
        (METHOD_PUT, "PUT"),
        (METHOD_PATCH, "PATCH"),
        (METHOD_DELETE, "DELETE"),
    ] {
        if methods & bit != 0 {
            if !out.is_empty() {
                out.extend_from_slice(b", ");
            }
            out.extend_from_slice(name.as_bytes());
        }
    }
    out
}

/// Core's answer to `refusal`. `text`: the row's own text when it has one, else the text built
/// where the row was decided (the group and window of a limit). `challenge`: the route's declared
/// challenge; used only by a row that sends one.
pub fn answer(refusal: Refusal, row: &Row, text: &str, challenge: Option<&str>) -> CoreAnswer {
    let mut fields: HeadFields = Vec::with_capacity(3);
    fields.push((CONTENT_TYPE.to_vec(), JSON.to_vec()));
    if row.challenge {
        fields.push((
            WWW_AUTHENTICATE.to_vec(),
            challenge.unwrap_or(GENERIC_CHALLENGE).as_bytes().to_vec(),
        ));
    }
    if let Some(seconds) = row.retry_after_s {
        fields.push((RETRY_AFTER.to_vec(), seconds.to_string().into_bytes()));
    }
    if let Some(methods) = row.allow {
        fields.push((ALLOW.to_vec(), allow_value(methods)));
    }
    CoreAnswer {
        status: row.status,
        fields,
        body: body(word(refusal), row.text.unwrap_or(text)),
    }
}

/// The one answer to a caller that is not verified. `presented` changes what core records, never
/// a byte of the answer.
pub fn unverified(presented: bool, challenge: Option<&str>) -> CoreAnswer {
    let refusal = Refusal::Unverified { presented };
    answer(refusal, &refusal.row(false), TEXT_UNVERIFIED, challenge)
}

/// The `ClientRefusal` a row records and hands a plane to render.
pub fn client_refusal(row: &Row, text: &str) -> crate::refusal::ClientRefusal {
    crate::refusal::ClientRefusal {
        status: row.status,
        code: row.code,
        text: match row.text {
            Some(fixed) => fixed.into(),
            None => text.to_owned().into(),
        },
    }
}
