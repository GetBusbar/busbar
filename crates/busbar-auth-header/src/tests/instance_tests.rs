// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HANDLE BOOKKEEPING AND `fields` SLOT, both credential modes, over the trampoline the door
//! macro builds — no mint, no wire, no waiting ticket: a header binding is synchronous end to end.

use super::*;
use crate::style;
use crate::Fields;
use busbar_contract::abi::auth::{FieldSpan, FieldsIn, FieldsOut, MODE_OWN, MODE_PASSTHROUGH};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::sdk::door::Slot;
use std::ffi::c_void;

fn auth_span() -> busbar_contract::abi::mechanism::call::Span {
    busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 }
}

/// One `fields` call through the slot body, as the trampoline makes it.
fn fields(h: &Header, handle: u64, mode: u32, caller: &str) -> (Outcome, String) {
    let mut buf = [0_u8; 512];
    let mut spans = [FieldSpan {
        name: auth_span(),
        value: auth_span(),
        flags: 0,
        _reserved: 0,
    }; 4];
    let mut i: FieldsIn = crate::abi::zeroed_in();
    i.handle = handle;
    i.mode = mode;
    i.caller_credential = if caller.is_empty() {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: 0,
            flags: 0,
        }
    } else {
        Blob {
            ptr: caller.as_ptr(),
            len: caller.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        }
    };
    (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 4);
    let mut out: FieldsOut = crate::abi::zeroed_out();
    let inst = std::ptr::from_ref(h).cast_mut().cast::<c_void>();
    let outcome = Fields::call(inst, &i, &mut out);
    let written = (0..out.fields_len as usize)
        .map(|k| {
            let at = |sp: busbar_contract::abi::mechanism::call::Span| {
                String::from_utf8_lossy(&buf[sp.offset as usize..(sp.offset + sp.len) as usize])
                    .into_owned()
            };
            format!("{}: {}", at(spans[k].name), at(spans[k].value))
        })
        .collect::<Vec<_>>()
        .join(" ; ");
    (outcome, written)
}

fn open(h: &Header, style: &str, cred: Option<&str>, settings: &str) -> u64 {
    let binding = style::open_binding(
        style,
        cred.map(str::as_bytes),
        Some(settings.as_bytes()),
        &mut Vec::new(),
    )
    .expect("the binding opens");
    h.keep(binding)
}

#[test]
fn a_handle_presents_its_own_credential_then_the_callers() {
    let h = Header::new(1);
    let handle = open(&h, style::BEARER, Some("sk-1"), "{}");
    assert_eq!(
        fields(&h, handle, MODE_OWN, ""),
        (Outcome::Ready, "authorization: Bearer sk-1".to_string())
    );
    assert_eq!(
        fields(&h, handle, MODE_PASSTHROUGH, "caller-tok"),
        (
            Outcome::Ready,
            "authorization: Bearer caller-tok".to_string()
        )
    );
    assert_eq!(
        fields(&h, handle, MODE_PASSTHROUGH, ""),
        (Outcome::Ready, String::new()),
        "no caller credential presented: no header"
    );
}

#[test]
fn retire_drops_the_generations_handles() {
    let h = Header::new(1);
    let handle = open(&h, style::BEARER, Some("sk-1"), "{}");
    h.retire(1);
    assert_eq!(
        fields(&h, handle, MODE_OWN, ""),
        (Outcome::Refused, String::new())
    );
}

#[test]
fn note_open_reports_each_note_in_its_own_line() {
    let mut env = EnvStore::default();
    Header::note_open(
        &mut env,
        &[
            style::OpenNote::Header("api-key".to_string()),
            style::OpenNote::Bearer(None),
            style::OpenNote::Family(None, "x-api-key".to_string()),
        ],
    );
    assert_eq!(env.diags().len(), 3);
    assert_eq!(env.diags()[0].id_idx, diag::APIKEY_INVALID_BYTES);
    assert_eq!(env.diags()[1].id_idx, diag::AUTH_INVALID_HEADER_BYTES);
    assert_eq!(env.diags()[2].id_idx, diag::CREDENTIAL_INVALID_BYTES);
}

/// THE UNPRESENTABLE-CREDENTIAL LINES, BYTE FOR BYTE (ported from the kernel's deleted
/// `egress_auth/tests/prebuilt_auth_tests.rs`, `an_unpresentable_static_credential_logs_its_builders_own_line`,
/// ARCHITECT F25 ruling 2026-10-07; the `protocol` field and the bearer's severity restored by the
/// coordinator's B21 ruling 2026-10-07: log lines are customer-visible). A credential no header
/// value may carry is reported at WARNING in the line its 1.5.5 builder logged, its fields as the
/// log formatter wrote them after the message. 1.5.5's sites, at `v1.5.5`:
/// `egress_auth/mod.rs` `api_key_headers` — `warn!(header, "...")`;
/// `proto/mod.rs` `bearer_auth_headers` — `warn!(protocol = proto, "...")`;
/// `proto/anthropic/mod.rs` `anthropic_auth_headers` — `warn!(protocol = "anthropic", header = name, "...")`.
/// tracing's formatter renders each as `<message> protocol="openai"` / `header="x-goog-api-key"` /
/// `protocol="anthropic" header="x-api-key"` (measured with tracing-subscriber's default `fmt`).
#[test]
fn an_unpresentable_credential_is_reported_in_its_builders_own_words() {
    let mut env = EnvStore::default();
    Header::note_open(
        &mut env,
        &[
            style::OpenNote::Header("x-goog-api-key".to_string()),
            style::OpenNote::Bearer(Some("openai".to_string())),
            style::OpenNote::Bearer(Some("responses".to_string())),
            style::OpenNote::Bearer(Some("cohere".to_string())),
            style::OpenNote::Family(Some("anthropic".to_string()), "x-api-key".to_string()),
            style::OpenNote::Family(Some("anthropic".to_string()), "authorization".to_string()),
        ],
    );
    assert_eq!(
        env.texts,
        [
            "egress credential contains invalid header bytes (ASCII control character); omitting \
             auth header — upstream will reject with 401 header=\"x-goog-api-key\"",
            "authorization credential contains invalid header bytes (ASCII control character); \
             omitting auth header — upstream will reject with 401 protocol=\"openai\"",
            "authorization credential contains invalid header bytes (ASCII control character); \
             omitting auth header — upstream will reject with 401 protocol=\"responses\"",
            "authorization credential contains invalid header bytes (ASCII control character); \
             omitting auth header — upstream will reject with 401 protocol=\"cohere\"",
            "auth credential contains bytes invalid for an HTTP header value (e.g. a trailing \
             newline); omitting the credential header — upstream will return 401, check the key \
             configuration protocol=\"anthropic\" header=\"x-api-key\"",
            "auth credential contains bytes invalid for an HTTP header value (e.g. a trailing \
             newline); omitting the credential header — upstream will return 401, check the key \
             configuration protocol=\"anthropic\" header=\"authorization\"",
        ]
    );
    let severities: Vec<u8> = env.diags().iter().map(|d| d.severity).collect();
    assert_eq!(
        severities, [1; 6],
        "every line at warning, as 1.5.5's `warn!`"
    );
    let ids: Vec<u32> = env.diags().iter().map(|d| d.id_idx).collect();
    assert_eq!(
        ids,
        [
            diag::APIKEY_INVALID_BYTES,
            diag::AUTH_INVALID_HEADER_BYTES,
            diag::AUTH_INVALID_HEADER_BYTES,
            diag::AUTH_INVALID_HEADER_BYTES,
            diag::CREDENTIAL_INVALID_BYTES,
            diag::CREDENTIAL_INVALID_BYTES
        ]
    );
}
