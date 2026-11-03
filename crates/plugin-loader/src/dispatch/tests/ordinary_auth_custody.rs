// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::dispatch::{load_linked, Bind, ConnTable, DispatchConfig, LinkedRow, NoSink};
use busbar_contract::abi::auth::AuthPoints;
use busbar_contract::abi::auth::{AuthPoint, EXT_SCOPE, STYLE_NEEDS_HEADERS};
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

fn fixture() -> (OutboundInstance, FieldsRequest, u64) {
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let row = LinkedRow::of(real::door).expect("the existing SDK custody witness states itself");
    let plugin = load_linked::<Auth>(
        &row,
        Bind {
            instance: Arc::from("custody"),
            max_inflight_cap: 16,
            sink: Arc::new(NoSink),
            dispatcher: dispatcher.adopter(),
            conns: ConnTable::NoNeeds,
        },
    )
    .unwrap();
    let auth = OutboundInstance::open_with(plugin, dispatcher, 0, b"{}")
        .expect("SDK outbound instance opens");
    let request = FieldsRequest {
        point: AuthPoint::HeadBody,
        conn: 0,
        unit: 0,
        method: b"POST".to_vec(),
        authority: "api.test:443".into(),
        path: b"/signed".to_vec(),
        query: Some(b"q=one".to_vec()),
        timestamp: 1900000000,
        headers: vec![
            (b"x-one".to_vec(), b"first".to_vec()),
            (b"x-two".to_vec(), b"second".to_vec()),
        ],
        body: Some(b"the complete signed body".to_vec()),
        caller_credential: None,
        extensions: extensions::encode(&[(EXT_SCOPE, b"scope-one"), ("unrelated", b"keep-me")]),
    };
    let handle = auth
        .open_outbound("secure", b"", &serde_json::json!({}))
        .expect("secure style opens");
    (auth, request, handle)
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
    let (auth, request, handle) = fixture();
    let plugin = &*auth.plugin;
    let mut lend = Lend::new(super::copy(&request), 4096, 16);
    let mut expected_extensions = extensions::encode(&[(EXT_SEALED_FIELDS, SEALED_FIELDS_V1)]);
    expected_extensions.extend_from_slice(&request.extensions.clone());
    assert_eq!(lend.request.extensions, expected_extensions);
    let input = lend.input(handle, None);
    drop(request);
    let mut frame = Frame::new(input, fields_out());
    let called = plugin.call(slot::FIELDS, &mut frame);
    assert_eq!(called.outcome, Outcome::Ready);
    assert_eq!(
        extensions::get(reply_extensions(&frame.out), EXT_SEALED_FIELDS),
        Some(SEALED_FIELDS_V1),
        "the actual secure-connection requirement must survive the SDK crossing"
    );
    assert_eq!(frame.out.fields_len, 2);
    let facts: serde_json::Value = serde_json::from_slice(
        &lend.field_buf[lend.fields[0].value.offset as usize
            ..(lend.fields[0].value.offset as usize + lend.fields[0].value.len as usize)],
    )
    .unwrap();
    assert_eq!(
        facts,
        serde_json::json!({
            "method": "POST", "authority": "api.test:443", "path": "/signed", "query": "q=one",
            "timestamp": 1900000000_u64, "scope": "scope-one",
            "headers": [["x-one", "first"], ["x-two", "second"]],
            "body": "the complete signed body"
        })
    );
    let Fields::Ready(fields) = lend.answer(&frame.out) else {
        panic!("the secure fields copy succeeds");
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[1].name, b"authorization");
    assert!(fields[1].require_secure);
    assert_eq!(
        fields[1].value,
        Secret::new(b"Bearer opaque-token".to_vec())
    );
    if called.lease != 0 {
        release(plugin, called.lease);
    }
    crate::dispatch::lifecycle::close(plugin);
}

#[test]
fn outbound_lend_without_valid_custody_refuses_before_any_credential_write() {
    let (auth, request, handle) = fixture();
    let plugin = &*auth.plugin;
    for version in [None, Some(&b"1"[..]), Some(&[0][..]), Some(&[1, 0][..])] {
        let mut lend = Lend::new(super::copy(&request), 4096, 16);

        lend.request.extensions =
            version.map_or_else(Vec::new, |v| extensions::encode(&[(EXT_SEALED_FIELDS, v)]));
        lend.request
            .extensions
            .extend_from_slice(&request.extensions.clone());
        lend.field_buf.fill(0xa5);
        let input = lend.input(handle, None);
        let mut frame = Frame::new(input, fields_out());
        let called = plugin.call(slot::FIELDS, &mut frame);
        assert_eq!(called.outcome, Outcome::Refused);
        assert_eq!(
            called.error.as_deref(),
            Some(SEALED_FIELDS_UNSUPPORTED.as_bytes())
        );
        assert_eq!(frame.out.fields_len, 0);
        assert!(reply_extensions(&frame.out).is_empty());
        assert!(lend.field_buf.iter().all(|byte| *byte == 0xa5));
        assert!(lend
            .fields
            .iter()
            .all(|s| s.name.len == 0 && s.value.len == 0 && s.flags == 0));
        if called.lease != 0 {
            release(plugin, called.lease);
        }
    }
    crate::dispatch::lifecycle::close(plugin);
}
