// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth kind's shared plugin pieces: a decode error withholds the decoder's text but keeps a
//! missing or unknown field's name; a completed login's principal crosses the door as the identity
//! answer the kind's own check accepts, or as the short-buffer answer with nothing written.

use super::*;
use crate::abi::auth::{check_complete_login, slot, CompleteLoginIn, Ops};
use crate::abi::mechanism::lifecycle::{slot as life, OpenIn, OpenOut};
use crate::abi::sdk::door::statement;
use crate::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use crate::abi::sdk::test_support::reply;
use crate::abi::sdk::test_support::test_in::TestIn;
use crate::abi::sdk::test_support::{zeroed, DoorView};
use crate::abi::sdk::{Instance, Safe, SafeSlot};

#[derive(serde::Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct Settings {
    url: String,
    password: String,
}

fn refused(json: &str) -> String {
    serde_json::from_str::<Settings>(json)
        .map_err(json_error("invalid probe config"))
        .expect_err("refused")
}

/// A missing or unknown field is named as serde names it; any other failure is its class and
/// position, never the value it quoted.
#[test]
fn a_decode_error_withholds_the_decoders_text() {
    let raw = |json: &str| serde_json::from_str::<Settings>(json).expect_err("refused");
    for json in [
        r#"{"url":"u"}"#,
        r#"{"url":"u","password":"p","pasword":"x"}"#,
    ] {
        assert_eq!(
            refused(json),
            format!("invalid probe config: {}", raw(json))
        );
    }
    assert!(refused(r#"{"url":"u"}"#).starts_with("invalid probe config: missing field `password`"));
    for (json, class) in [
        (
            r#"{"url":"u","password":12345678}"#,
            "a field is missing or has the wrong type",
        ),
        ("{\"url\":\"hunter2", "it ends before the JSON does"),
        ("x", "it is not well-formed JSON"),
    ] {
        let e = raw(json);
        let text = refused(json);
        assert_eq!(
            text,
            format!(
                "invalid probe config: {class} (line {}, column {}; the decoder's text is withheld)",
                e.line(),
                e.column()
            )
        );
        assert!(
            !text.contains("12345678") && !text.contains("hunter2"),
            "{text}"
        );
    }
}

/// The probe: it logs everyone in as the one principal.
struct Probe;

impl Life for Probe {
    const CANCEL: u32 = 0;

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Probe)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

fn principal() -> Principal {
    Principal {
        id: "probe:alice".to_string(),
        name: Some("Alice".to_string()),
        roles: vec!["ops".to_string(), "dev".to_string()],
        ttl_secs: Some(60),
    }
}

/// `complete_login`: [`login_identity`] over the one principal.
struct Complete;

impl SafeSlot for Complete {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    type State = Held<Probe>;
    fn call(
        _: Instance<'_, Held<Probe>>,
        input: Lent<'_, CompleteLoginIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        login_identity(&principal(), input.out_buf(), &mut out)
    }
}

mod plugin {
    crate::plugin_door! {
        ops: super::Ops,
        statement: super::statement("probe-login", "0.0.1", 4),
        lifecycle: life(super::Probe),
        kind_ops: { complete_login: super::Safe<super::Complete> },
    }
}

thread_local! {
    /// The IdP's delay [`Outage`] answers with, per test thread.
    static RETRY_AFTER: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// `complete_login`: [`login_outage`], with the delay [`RETRY_AFTER`] holds.
struct Outage;

impl SafeSlot for Outage {
    type In = CompleteLoginIn;
    type Out = IdentifyOut;
    type State = Held<Probe>;
    fn call(
        _: Instance<'_, Held<Probe>>,
        input: Lent<'_, CompleteLoginIn>,
        mut out: Out<'_, IdentifyOut>,
    ) -> Outcome {
        login_outage(
            RETRY_AFTER.with(std::cell::Cell::get),
            input.out_buf(),
            &mut out,
        )
    }
}

mod outage_plugin {
    crate::plugin_door! {
        ops: super::Ops,
        statement: super::statement("probe-outage", "0.0.1", 4),
        lifecycle: life(super::Probe),
        kind_ops: { complete_login: super::Safe<super::Outage> },
    }
}

/// One `complete_login` with host buffers of `cap` bytes and `groups` spans: the answer, and the
/// bytes and group spans as the host holds them after it.
fn login(cap: usize, groups: usize) -> (Outcome, IdentifyOut, Vec<u8>, Vec<Span>) {
    login_on(plugin::MACRO_DOOR, cap, groups)
}

/// [`login`] on `door`.
fn login_on(
    door: crate::abi::sdk::door::MacroDoor,
    cap: usize,
    groups: usize,
) -> (Outcome, IdentifyOut, Vec<u8>, Vec<Span>) {
    let view = DoorView::of(door);
    let open = view.op::<Ops>(|t| &t.head.open).expect("open");
    let complete = view
        .op::<Ops>(|t| &t.complete_login)
        .expect("complete_login");
    let mut opened = reply::call_in(
        open,
        None,
        &TestIn::<OpenIn>::new().set(|i| &i.head.op, life::OPEN),
        zeroed::<OpenOut>(),
    );
    let instance = opened.take_instance().expect("an instance");
    let mut bytes = vec![0u8; cap];
    let mut spans = vec![Span { offset: 0, len: 0 }; groups];
    let c = {
        let input = TestIn::<CompleteLoginIn>::new()
            .set(|i| &i.head.op, slot::COMPLETE_LOGIN)
            .buffer(|i| &i.out_buf.buf, |i| &i.out_buf.buf_cap, &mut bytes)
            .buffer(|i| &i.out_buf.groups, |i| &i.out_buf.groups_cap, &mut spans);
        reply::call_in(complete, Some(&instance), &input, zeroed::<IdentifyOut>())
    };
    (c.outcome, c.out, bytes, spans)
}

/// The principal crosses as the identity: subject, name, its roles as groups and its TTL, every
/// other field absent, verdict LOGIN_IDENTITY; the kind's own check accepts the answer.
#[test]
fn a_completed_login_crosses_as_the_identity_answer() {
    let (outcome, out, mut bytes, mut spans) = login(64, 4);
    assert_eq!(outcome, Outcome::Ready);
    assert_eq!(out.verdict, LOGIN_IDENTITY);
    let text = |s: Span| -> Option<&str> {
        (s.offset != SPAN_ABSENT).then(|| {
            std::str::from_utf8(&bytes[s.offset as usize..(s.offset + s.len) as usize])
                .expect("UTF-8")
        })
    };
    let id = out.identity;
    assert_eq!(text(id.subject), Some("probe:alice"));
    assert_eq!(text(id.name), Some("Alice"));
    for absent in [id.key_id, id.key_name, id.user, id.provider, id.claims] {
        assert_eq!(text(absent), None);
    }
    assert_eq!(id.claims_fmt, BLOB_ABSENT);
    assert_eq!((id.flags, id.ttl_secs), (IDENTITY_HAS_TTL, 60));
    assert_eq!(id.groups_len, 2);
    assert_eq!(text(spans[0]), Some("ops"));
    assert_eq!(text(spans[1]), Some("dev"));
    let host = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: spans.as_mut_ptr(),
        groups_cap: 4,
        _reserved: 0,
    };
    check_complete_login(outcome, &out, &host, &spans[..2]).expect("the kind's check passes");
}

/// A buffer too small for the bytes, or for the groups, writes nothing and answers FAILED with
/// both sizes needed.
#[test]
fn a_short_buffer_writes_nothing_and_names_what_it_needs() {
    let need = "probe:alice".len() + "Alice".len() + "ops".len() + "dev".len();
    for (cap, groups) in [(need - 1, 4), (64, 1)] {
        let (outcome, out, bytes, spans) = login(cap, groups);
        assert_eq!(outcome, Outcome::Failed);
        assert_eq!(out.needed_bytes, need as u64);
        assert_eq!(out.needed_groups, 2);
        assert_eq!(out.identity.groups_len, 0);
        assert!(bytes.iter().all(|b| *b == 0));
        assert!(spans.iter().all(|s| s.len == 0));
    }
}

/// An IdP that could not answer (owner-signed 2026-10-30, OWNER-QUEUE.md item "IdP errors"):
/// [`login_outage`] answers LOGIN_OUTAGE, READY, and carries the IdP's delay as the reply-extensions
/// entry `retry_after`, ASCII decimal, written into the HOST's identity buffer (the one memory the
/// host reads back after the call); with no delay nothing is written. The kind's own check accepts
/// both.
#[test]
fn a_login_outage_carries_the_idps_retry_after_in_the_hosts_buffer() {
    use crate::abi::auth::{retry_after_of, EXT_RETRY_AFTER, LOGIN_OUTAGE};
    for stated in [Some(120), Some(0), Some(u64::MAX), None] {
        RETRY_AFTER.with(|r| r.set(stated));
        let (outcome, out, mut bytes, mut spans) = login_on(outage_plugin::MACRO_DOOR, 64, 4);
        assert_eq!(outcome, Outcome::Ready, "{stated:?}");
        assert_eq!(out.verdict, LOGIN_OUTAGE, "{stated:?}");
        // The harness clears the reply's head pointers before handing it back, so the entry is
        // read where the host reads it: the host's own identity buffer, written from its start.
        match stated {
            Some(n) => {
                let entry = crate::abi::auth::retry_after_extensions(n);
                assert_eq!(&bytes[..entry.len()], &entry[..], "{stated:?}");
                assert!(bytes[entry.len()..].iter().all(|b| *b == 0));
                let blob = &bytes[..entry.len()];
                assert_eq!(
                    crate::abi::mechanism::extensions::get(blob, EXT_RETRY_AFTER),
                    Some(n.to_string().as_bytes())
                );
                assert_eq!(retry_after_of(blob), Some(n));
            }
            None => assert!(bytes.iter().all(|b| *b == 0), "nothing written"),
        }
        let host = IdentityBuf {
            buf: bytes.as_mut_ptr(),
            buf_cap: bytes.len(),
            groups: spans.as_mut_ptr(),
            groups_cap: 4,
            _reserved: 0,
        };
        check_complete_login(outcome, &out, &host, &[]).expect("the kind's check passes");
    }
    // A host buffer too small for the entry: still the outage, its delay left absent.
    RETRY_AFTER.with(|r| r.set(Some(120)));
    let (outcome, out, bytes, _) = login_on(outage_plugin::MACRO_DOOR, 4, 1);
    assert_eq!((outcome, out.verdict), (Outcome::Ready, LOGIN_OUTAGE));
    assert!(bytes.iter().all(|b| *b == 0));
}
