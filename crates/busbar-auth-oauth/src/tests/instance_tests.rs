// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE MINT THROUGH THE INSTANCE AND THE `fields` SLOT (BUSBAR-1.6.0.md THE DESIGN, §6.5: jwt-bearer and
//! oauth-client-credentials "mint through the plugin's own `open-web` need and refresh ahead of
//! expiry in the background on `tick`"), over a scripted need: the request the plugin sends, the
//! first mint on the first tick, the per-request call presenting the minted bearer, and THE
//! EXPIRED-TOKEN RULE end to end — an expired token whose refresh failed answers PENDING on a
//! ticket bounded by the attempt's deadline, the next landed mint WAKES that ticket, and the resumed
//! call presents the new token.
//!
//! The need is a [`Wire`] double, not the host's connector table: how a plugin makes a framed request/response
//! exchange through the connector is the step 20-21 seam ([`crate::abi::waker`]). With
//! `AUTH_OUT_CAPTURE_DIR` set, each request the plugin sent is written out for the 1.5.5 wire-bytes
//! comparison through the framer door (whose defaults, `accept: */*` included, are the framer's —
//! never this plugin's or the kernel's).

use super::*;
use crate::mint;
use crate::mint::tests::{Scripted, Step};
use crate::mint::TokenRequest;
use crate::style;
use crate::Fields;
use busbar_contract::abi::auth::{FieldSpan, FieldsIn, FieldsOut, MODE_OWN};
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::HostCtx;
use busbar_contract::abi::sdk::door::Slot;
use busbar_contract::conn::{ConnError, ConnId};
use std::ffi::c_void;

/// The scripted need, shared so the test reads what was sent.
struct Shared(Arc<Scripted>);

impl Wire for Shared {
    fn open(&self, req: &TokenRequest, timeout_ms: u64) -> Result<ConnId, ConnError> {
        self.0.open(req, timeout_ms)
    }
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<mint::Got, ConnError> {
        self.0.read(conn, buf)
    }
    fn close(&self, conn: ConnId) {
        self.0.close(conn);
    }
}

static WOKEN: Mutex<Vec<Ticket>> = Mutex::new(Vec::new());

extern "C" fn wake(_: HostCtx, t: Ticket) {
    WOKEN.lock().unwrap().push(t);
}

fn instance(wire: &Arc<Scripted>) -> Oauth {
    Oauth::with_wire(
        1,
        Some(Waker::test(wake)),
        Some(Box::new(Shared(wire.clone()))),
    )
}

fn open(o: &Oauth, style: &str, cred: &str, settings: &str) -> u64 {
    let cell = style::open_binding(style, Some(cred.as_bytes()), Some(settings.as_bytes()), o)
        .expect("the binding opens");
    o.keep(cell)
}

/// One `fields` call through the slot body, as the trampoline makes it.
fn fields(o: &Oauth, handle: u64, ticket: Ticket) -> (Outcome, String, u64) {
    let mut buf = [0_u8; 512];
    let mut spans = [FieldSpan {
        name: auth_span(),
        value: auth_span(),
        flags: 0,
        _reserved: 0,
    }; 4];
    let mut i: FieldsIn = crate::abi::zeroed_in();
    i.head.ticket = ticket;
    i.head.deadline_ns = 99;
    i.handle = handle;
    i.mode = MODE_OWN;
    (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 4);
    let mut out: FieldsOut = crate::abi::zeroed_out();
    let inst = std::ptr::from_ref(o).cast_mut().cast::<c_void>();
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
    (outcome, written, out.head.wake_at_ns)
}

fn auth_span() -> busbar_contract::abi::mechanism::call::Span {
    busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 }
}

fn capture(name: &str, w: &Scripted) {
    let Some(dir) = std::env::var_os("AUTH_OUT_CAPTURE_DIR") else {
        return;
    };
    let sent = w.sent.lock().unwrap();
    let (target, head, body) = &sent[0];
    let v = serde_json::json!({ "target": target, "fields": head, "body": body });
    std::fs::write(std::path::Path::new(&dir).join(name), v.to_string()).expect("capture");
}

const NS: u64 = 1_000_000_000;

#[test]
fn oauth_client_credentials_mints_on_tick_and_honours_the_expired_token_rule() {
    WOKEN.lock().unwrap().clear();
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(
        &o,
        style::OAUTH_CLIENT_CREDENTIALS,
        "client-abc:s3cr&t",
        r#"{"token_url":"https://login.example.com/tenant/oauth2/v2.0/token","scope":"https://cognitiveservices.azure.com/.default"}"#,
    );
    assert_eq!(
        fields(&o, h, Ticket::NONE).0,
        Outcome::Ready,
        "before the first mint: READY, no header"
    );
    assert_eq!(fields(&o, h, Ticket::NONE).1, "");

    // THE FIRST MINT, on the first tick: a token that expires at once, so the rule can run on the
    // wall clock.
    w.ok(r#"{"access_token":"tok-1","expires_in":0}"#);
    let mut env = EnvStore::default();
    let due = o.tick(1_000, &mut env);
    {
        let sent = w.sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].0,
            "https://login.example.com/tenant/oauth2/v2.0/token"
        );
        assert_eq!(
            sent[0].1,
            [(
                "content-type".to_string(),
                "application/x-www-form-urlencoded".to_string()
            )]
        );
        assert_eq!(
            sent[0].2,
            "grant_type=client_credentials&client_id=client-abc&client_secret=s3cr%26t&scope=https%3A%2F%2Fcognitiveservices.azure.com%2F.default"
        );
    }
    capture("oauth-client-credentials.json", &w);
    assert_eq!(fields(&o, h, Ticket::NONE).1, "authorization: Bearer tok-1");
    assert_eq!(
        due,
        1_000 + 30 * NS,
        "an expired-at-once token re-mints after MIN_SLEEP"
    );

    // THE REFRESH FAILS: the expired token answers PENDING on a ticket, bounded by the deadline;
    // a call that may not pend fails closed (no header).
    w.push(vec![Step::Head(503), Step::Body(b"down".to_vec(), true)]);
    o.tick(due, &mut env);
    let ticket = Ticket {
        slot: 3,
        generation: 1,
    };
    let (outcome, _, wake_at) = fields(&o, h, ticket);
    assert_eq!(outcome, Outcome::Pending);
    assert_eq!(wake_at, 99, "bounded by the attempt's deadline");
    assert_eq!(
        fields(&o, h, Ticket::NONE),
        (Outcome::Ready, String::new(), 0)
    );

    // THE NEXT MINT LANDS: the waiting ticket is woken; the resumed call presents the new token.
    w.ok(r#"{"access_token":"tok-2","expires_in":3600}"#);
    o.tick(due + 30 * NS, &mut env);
    assert_eq!(*WOKEN.lock().unwrap(), vec![ticket]);
    assert_eq!(fields(&o, h, ticket).1, "authorization: Bearer tok-2");
    assert_eq!(
        *w.closed.lock().unwrap(),
        3,
        "every exchange closed its connection"
    );
}

#[test]
fn jwt_bearer_mints_on_tick() {
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let sa = serde_json::json!({
        "client_email": "svc@proj.iam.gserviceaccount.com",
        "private_key": include_str!("fixtures/test_sa_key.pem"),
        "token_uri": "https://oauth2.googleapis.com/token",
    })
    .to_string();
    let h = open(&o, style::JWT_BEARER, &sa, "{}");
    w.ok(r#"{"access_token":"ya29.tok","expires_in":3599}"#);
    o.tick(1, &mut EnvStore::default());
    {
        let sent = w.sent.lock().unwrap();
        assert_eq!(sent[0].0, "https://oauth2.googleapis.com/token");
        assert!(
            sent[0].2.starts_with(
                "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9."
            ),
            "{}",
            sent[0].2
        );
    }
    capture("jwt-bearer.json", &w);
    assert_eq!(
        fields(&o, h, Ticket::NONE).1,
        "authorization: Bearer ya29.tok"
    );
}
