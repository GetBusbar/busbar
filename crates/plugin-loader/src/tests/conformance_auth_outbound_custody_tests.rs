// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::conformance::{dispatcher, load, release};
use busbar_contract::abi::auth::{AuthPoints, FIELD_SENSITIVE};
use busbar_contract::abi::sdk::auth_door::with_tail;
use busbar_contract::abi::sdk::auth_outbound::{
    outbound_tail, style, Diags, FieldsAnswer, FieldsView, FieldsWriter, OpenRefusal,
    OutboundPlugin, SEALED_FIELDS_UNSUPPORTED,
};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::cred::{Cred, Parts};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::exchange::Op;
use busbar_contract::abi::sdk::life::Refusal;
use std::task::Poll;

pub struct Secure;

impl OutboundPlugin for Secure {
    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self)
    }

    fn open_outbound(
        &self,
        _: &str,
        _: Option<&[u8]>,
        _: Option<&[u8]>,
        _: Option<&Host>,
        _: &mut Diags,
    ) -> Result<u64, OpenRefusal> {
        Ok(1)
    }

    fn fields(
        &self,
        r: &FieldsView<'_>,
        out: &mut FieldsWriter<'_>,
        _: &Op<'_>,
    ) -> Poll<FieldsAnswer> {
        let text = |bytes: &[u8]| String::from_utf8_lossy(bytes).into_owned();
        let facts = serde_json::json!({
            "method": text(r.method()), "authority": text(r.authority()),
            "path": text(r.path()), "query": r.query().map(text),
            "timestamp": r.timestamp(), "scope": r.scope().map(text),
            "headers": r.headers().map(|(k, v)| (text(k), text(v))).collect::<Vec<_>>(),
            "body": r.body().map(text),
        });
        out.push(b"x-facts", facts.to_string().as_bytes(), 0);
        let credential = Cred::take(&mut serde_json::json!("opaque-token"))
            .expect("the fixture credential is a string")
            .require_secure();
        out.push_sealed(
            b"authorization",
            Parts::new().public(b"Bearer ").sealed(credential.field()),
            0,
        );
        Poll::Ready(FieldsAnswer::Ready)
    }

    fn outbound_ready(&self, _: u64) -> bool {
        true
    }
}

mod real {
    use super::*;
    busbar_contract::auth_outbound_door!(
        Secure,
        with_tail(
            statement("outbound-custody", "1.0.0", 8),
            &outbound_tail(
                0,
                &[style("secure", STYLE_NEEDS_HEADERS, AuthPoints::HEAD_BODY)]
            )
        )
    );
}

fn fixture() -> (Arc<Dispatcher>, Plugin<Auth>, Style, u64) {
    let subject = Subject::new(real::door, "unused", "{}");
    let dispatcher = dispatcher();
    let plugin = load::<Auth>(&subject, Leg::Linked, subject.bind(&dispatcher, "custody"))
        .expect("the genuine SDK auth door loads");
    assert_eq!(open(&plugin, b"{}").outcome, Outcome::Ready);
    let style = Style::parse(&serde_json::json!({
        "style": "secure", "settings": {},
        "head": {
            "method": "POST", "authority": "api.test:443", "target": "/signed?q=one",
            "timestamp": 1900000000, "fields": [["x-one", "first"], ["x-two", "second"]],
            "body": "the complete signed body", "extensions": {"scope": "scope-one", "unrelated": "keep-me"}
        },
        "expect_fields": [["authorization", "Bearer opaque-token", FIELD_SENSITIVE]]
    }));
    let (answer, handle) = open_outbound(&plugin, &style);
    assert!(answer.starts_with("Ready"), "{answer}");
    (dispatcher, plugin, style, handle)
}

fn reply_extensions(out: &FieldsOut) -> &[u8] {
    if out.head.extensions.len == 0 {
        return &[];
    }
    // SAFETY: this exact SDK writer supplies a complete live reply extension range. Callers
    // read it before releasing the answer lease or closing the still-live plugin instance.
    unsafe { std::slice::from_raw_parts(out.head.extensions.ptr, out.head.extensions.len) }
}

#[test]
fn outbound_lend_keeps_secure_requirement_and_all_request_facts() {
    let (_dispatcher, plugin, style, handle) = fixture();
    let mut lend = Lend::new(&style.head);
    let mut expected_extensions = extensions::encode(&[(EXT_SEALED_FIELDS, SEALED_FIELDS_V1)]);
    expected_extensions.extend_from_slice(&style.head.extensions_blob());
    assert_eq!(lend.ext, expected_extensions);
    let input = lend.input(handle, &style.head, STYLE_NEEDS_HEADERS, POINT_HEAD_BODY);
    drop(style);
    let mut frame = Frame::new(input, output::<FieldsOut>());
    let called = plugin.call(slot::FIELDS, &mut frame);
    assert_eq!(called.outcome, Outcome::Ready);
    assert_eq!(
        extensions::get(reply_extensions(&frame.out), EXT_SEALED_FIELDS),
        Some(SEALED_FIELDS_V1),
        "the actual secure-connection requirement must survive the SDK crossing"
    );
    assert_eq!(frame.out.fields_len, 2);
    let facts: serde_json::Value =
        serde_json::from_slice(at(&lend.buf, lend.spans[0].value)).unwrap();
    assert_eq!(
        facts,
        serde_json::json!({
            "method": "POST", "authority": "api.test:443", "path": "/signed", "query": "q=one",
            "timestamp": 1900000000_u64, "scope": "scope-one",
            "headers": [["x-one", "first"], ["x-two", "second"]],
            "body": "the complete signed body"
        })
    );
    let wanted = expected(
        &serde_json::json!([
            ["x-facts", facts.to_string(), 0],
            ["authorization", "Bearer opaque-token", FIELD_SENSITIVE]
        ]),
        "secure fields",
    );
    assert_eq!(lend.answer(called.outcome, None, false, &frame.out), wanted);
    if called.lease != 0 {
        assert_eq!(release(&plugin, called.lease).outcome, Outcome::Ready);
    }
    assert_eq!(close(&plugin).outcome, Outcome::Ready);
}

#[test]
fn outbound_lend_without_valid_custody_refuses_before_any_credential_write() {
    let (_dispatcher, plugin, style, handle) = fixture();
    for version in [None, Some(&b"1"[..]), Some(&[0][..]), Some(&[1, 0][..])] {
        let mut lend = Lend::new(&style.head);

        lend.ext = version.map_or_else(Vec::new, |v| extensions::encode(&[(EXT_SEALED_FIELDS, v)]));
        lend.ext.extend_from_slice(&style.head.extensions_blob());
        lend.buf.fill(0xa5);
        let input = lend.input(handle, &style.head, STYLE_NEEDS_HEADERS, POINT_HEAD_BODY);
        let mut frame = Frame::new(input, output::<FieldsOut>());
        let called = plugin.call(slot::FIELDS, &mut frame);
        assert_eq!(called.outcome, Outcome::Refused);
        assert_eq!(
            called.error.as_deref(),
            Some(SEALED_FIELDS_UNSUPPORTED.as_bytes())
        );
        assert_eq!(frame.out.fields_len, 0);
        assert!(reply_extensions(&frame.out).is_empty());
        assert!(lend.buf.iter().all(|byte| *byte == 0xa5));
        assert!(lend
            .spans
            .iter()
            .all(|s| s.name.len == 0 && s.value.len == 0 && s.flags == 0));
        if called.lease != 0 {
            assert_eq!(release(&plugin, called.lease).outcome, Outcome::Ready);
        }
    }
    assert_eq!(close(&plugin).outcome, Outcome::Ready);
}

#[test]
fn outbound_double_fetch_scope_keeps_custody_and_unrelated_extensions() {
    let (_dispatcher, plugin, style, _) = fixture();
    let lend = Lend::new(&style.head);
    let second = longer_scope(&lend.ext);
    assert_eq!(
        extensions::get(&second, auth::EXT_SCOPE),
        Some(&b"scope-one "[..])
    );
    let unrelated = |blob: &[u8]| {
        extensions::entries(blob)
            .filter(|(key, _)| *key != auth::EXT_SCOPE.as_bytes())
            .map(|(key, value)| (key.to_vec(), value.to_vec()))
            .collect::<Vec<_>>()
    };
    assert_eq!(unrelated(&second), unrelated(&lend.ext));
    assert_eq!(
        extensions::get(&second, EXT_SEALED_FIELDS),
        Some(SEALED_FIELDS_V1)
    );
    assert_eq!(close(&plugin).outcome, Outcome::Ready);
}
