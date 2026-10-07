// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `oauth-token-exchange` (RFC 8693; ARCHITECT round 5 Q-L3B-EXCHANGE (B)) over a scripted need,
//! through the instance and the `fields` slot as the trampoline calls it: the exact token request
//! (the previous release's form, field for field), the per-call scope the call's extensions blob
//! states reaching that request, a cached token per scope (two scopes never share one), a failed
//! exchange failing exactly the calls that waited on it, and the binding's refusals.

use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::auth::{FieldSpan, FieldsIn, FieldsOut, EXT_SCOPE, MODE_OWN};
use busbar_contract::abi::mechanism::call::{Blob, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::extensions;
use busbar_contract::abi::mechanism::ticket::{HostCtx, Ticket};
use busbar_contract::abi::sdk::door::Slot;
use busbar_contract::conn::{ConnError, ConnId};

use super::*;
use crate::abi::Waker;
use crate::instance::{EnvStore, Oauth};
use crate::mint::tests::{Scripted, Step};
use crate::mint::{Got, Wire};
use crate::style;

/// The scripted need, shared so the test reads what was sent.
struct Shared(Arc<Scripted>);

impl Wire for Shared {
    fn open(&self, req: &TokenRequest, timeout_ms: u64) -> Result<ConnId, ConnError> {
        self.0.open(req, timeout_ms)
    }
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError> {
        self.0.read(conn, buf)
    }
    fn close(&self, conn: ConnId) {
        self.0.close(conn);
    }
}

/// The tickets this module's instances woke (this module's own: the tests in it share no ticket).
static WOKEN: Mutex<Vec<Ticket>> = Mutex::new(Vec::new());

extern "C" fn wake(_: HostCtx, t: Ticket) {
    WOKEN.lock().unwrap().push(t);
}

fn woken(of: &[Ticket]) -> Vec<Ticket> {
    let mut all = WOKEN.lock().unwrap();
    let mine: Vec<Ticket> = all.iter().copied().filter(|t| of.contains(t)).collect();
    all.retain(|t| !of.contains(t));
    mine
}

const SETTINGS: &str =
    r#"{"token_url":"https://as.example/token","resource":"https://tools.example/rpc"}"#;
const SUBJECT: &str = "busbar-own-subject-token";

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

fn instance(wire: &Arc<Scripted>) -> Oauth {
    Oauth::with_wire(
        1,
        Some(Waker::test(wake)),
        Some(Box::new(Shared(wire.clone()))),
    )
}

fn open(o: &Oauth) -> u64 {
    let b = style::open(
        style::OAUTH_TOKEN_EXCHANGE,
        Some(SUBJECT.as_bytes()),
        Some(SETTINGS.as_bytes()),
        o,
    )
    .unwrap_or_else(|_| panic!("the binding opens"));
    o.keep_binding(b)
}

/// One `fields` call through the slot body, its extensions blob stating `scope` (none: absent).
fn fields(o: &Oauth, handle: u64, ticket: Ticket, scope: Option<&str>) -> (Outcome, String) {
    let ext = scope.map(|s| extensions::encode(&[(EXT_SCOPE, s.as_bytes())]));
    let mut buf = [0_u8; 512];
    let span = busbar_contract::abi::mechanism::call::Span { offset: 0, len: 0 };
    let mut spans = [FieldSpan {
        name: span,
        value: span,
        flags: 0,
        _reserved: 0,
    }; 4];
    let mut i: FieldsIn = crate::abi::zeroed_in();
    i.head.ticket = ticket;
    i.head.deadline_ns = 99;
    if let Some(e) = &ext {
        i.head.extensions = Blob {
            ptr: e.as_ptr(),
            len: e.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        };
    }
    i.handle = handle;
    i.mode = MODE_OWN;
    (i.field_buf, i.field_buf_cap) = (buf.as_mut_ptr(), buf.len());
    (i.fields, i.fields_cap) = (spans.as_mut_ptr(), 4);
    let mut out: FieldsOut = crate::abi::zeroed_out();
    let inst = std::ptr::from_ref(o).cast_mut().cast::<c_void>();
    let outcome = crate::Fields::call(inst, &i, &mut out);
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

/// The form a sent body decodes to, in order.
fn form(body: &str) -> Vec<(String, String)> {
    serde_urlencoded::from_str(body).expect("a form")
}

/// THE REQUEST, FIELD FOR FIELD: the previous release's RFC 8693 form in RFC order — the grant,
/// busbar's own subject token and its type, an access token requested back, the RFC 8707 resource,
/// and the scope (present and empty when the call states none) — POSTed as a form to `token_url`
/// over the need that names it.
#[test]
fn the_exchange_request_is_the_previous_releases_form_with_the_stated_scope() {
    let x = Arc::new(build(
        SUBJECT,
        "https://as.example/token",
        ACCESS_TOKEN_TYPE,
        "https://tools.example/rpc",
    ));
    let req = Scoped::new(Arc::clone(&x), "fs_read_file fs_write_file")
        .request()
        .expect("a request");
    assert_eq!(req.need, crate::mint::need::TOKEN_URL);
    assert_eq!(req.target, "https://as.example/token");
    assert_eq!(
        req.fields,
        [
            ("content-type", "application/x-www-form-urlencoded"),
            ("accept", "*/*"),
        ]
    );
    let expected = |scope: &str| {
        vec![
            ("grant_type".to_string(), GRANT_TYPE.to_string()),
            ("subject_token".to_string(), SUBJECT.to_string()),
            (
                "subject_token_type".to_string(),
                ACCESS_TOKEN_TYPE.to_string(),
            ),
            (
                "requested_token_type".to_string(),
                ACCESS_TOKEN_TYPE.to_string(),
            ),
            (
                "resource".to_string(),
                "https://tools.example/rpc".to_string(),
            ),
            ("scope".to_string(), scope.to_string()),
        ]
    };
    assert_eq!(
        form(req.body.expose_secret()),
        expected("fs_read_file fs_write_file")
    );
    let unscoped = Scoped::new(x, "").request().expect("a request");
    assert_eq!(form(unscoped.body.expose_secret()), expected(""));
    assert!(
        format!("{req:?}").find(SUBJECT).is_none(),
        "the subject token never prints"
    );
}

/// THE PER-CALL SCOPE, CACHED PER SCOPE: a call stating a scope waits (PENDING on its ticket, a
/// ticket-less call REFUSED) while the exchange it arms asks for exactly that scope; the landed token
/// wakes it and is presented; a second scope is its own exchange and its own token; the first
/// scope's next call is answered from its cache with no exchange at all.
#[test]
fn each_scope_is_its_own_exchange_and_its_own_cached_token() {
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    let (a, b) = (ticket(101), ticket(102));
    assert_eq!(
        fields(&o, h, Ticket::NONE, Some("fs_read_file")).0,
        Outcome::Refused,
        "ticket-less, nothing usable: REFUSED (the host submits it on a ticket)"
    );
    assert_eq!(fields(&o, h, a, Some("fs_read_file")).0, Outcome::Pending);
    w.ok(r#"{"access_token":"tok-read","token_type":"Bearer","expires_in":3600}"#);
    let mut env = EnvStore::default();
    o.tick(1_000, Ticket::NONE, &mut env);
    assert_eq!(
        woken(&[a, b]),
        vec![a],
        "the landed exchange wakes its call"
    );
    assert_eq!(
        fields(&o, h, a, Some("fs_read_file")),
        (Outcome::Ready, "authorization: Bearer tok-read".to_string())
    );

    assert_eq!(
        fields(&o, h, b, Some("fs_read_file fs_write_file")).0,
        Outcome::Pending,
        "another scope never shares the first's token"
    );
    w.ok(r#"{"access_token":"tok-both","expires_in":3600}"#);
    o.tick(2_000, Ticket::NONE, &mut env);
    assert_eq!(woken(&[a, b]), vec![b]);
    assert_eq!(
        fields(&o, h, b, Some("fs_read_file fs_write_file")).1,
        "authorization: Bearer tok-both"
    );
    // The first scope again, on the spot: its cached token, no exchange.
    assert_eq!(
        fields(&o, h, Ticket::NONE, Some("fs_read_file")).1,
        "authorization: Bearer tok-read"
    );
    o.tick(3_000, Ticket::NONE, &mut env);
    let sent = w.sent.lock().unwrap();
    let scopes: Vec<String> = sent
        .iter()
        .map(|(_, _, body)| {
            form(body)
                .into_iter()
                .find(|(k, _)| k == "scope")
                .map(|(_, v)| v)
                .unwrap_or_default()
        })
        .collect();
    assert_eq!(scopes, ["fs_read_file", "fs_read_file fs_write_file"]);
}

/// A FAILED EXCHANGE FAILS ITS CALLS: the authorization server's refusal wakes every call that
/// waited on it, and each answers FAILED (the attempt fails; nothing unauthenticated is sent), the
/// instance's log naming why; the scope's next call arms a fresh exchange rather than inheriting
/// the failure.
#[test]
fn a_refused_exchange_fails_the_calls_that_waited_and_the_next_call_asks_again() {
    let w = Arc::new(Scripted::default());
    let o = instance(&w);
    let h = open(&o);
    let (first, second, later) = (ticket(201), ticket(202), ticket(203));
    assert_eq!(fields(&o, h, first, Some("s")).0, Outcome::Pending);
    assert_eq!(fields(&o, h, second, Some("s")).0, Outcome::Pending);
    w.push(vec![
        Step::Head(401),
        Step::Body(b"{\"error\":\"invalid_grant\"}".to_vec(), true),
    ]);
    let mut env = EnvStore::default();
    o.tick(1_000, Ticket::NONE, &mut env);
    let mut both = woken(&[first, second, later]);
    both.sort_by_key(|t| t.slot);
    assert_eq!(both, vec![first, second]);
    assert_eq!(fields(&o, h, first, Some("s")).0, Outcome::Failed);
    assert_eq!(fields(&o, h, second, Some("s")).0, Outcome::Failed);
    assert!(
        env.diags()
            .iter()
            .any(|d| d.id_idx == crate::instance::diag::OAUTH_MINT_FAILED),
        "the failure is logged"
    );
    // The next call is not failed by the last one: it arms a fresh exchange.
    assert_eq!(fields(&o, h, later, Some("s")).0, Outcome::Pending);
    w.ok(r#"{"access_token":"tok-s","expires_in":3600}"#);
    o.tick(2_000, Ticket::NONE, &mut env);
    assert_eq!(woken(&[first, second, later]), vec![later]);
    assert_eq!(
        fields(&o, h, later, Some("s")).1,
        "authorization: Bearer tok-s"
    );
    assert_eq!(w.sent.lock().unwrap().len(), 2);
}

/// THE REFUSALS: busbar's own subject token is the credential (none, or a blank one, refuses),
/// `token_url` and the RFC 8707 `resource` are required; every finding is one `settings:` line.
#[test]
fn the_binding_refuses_without_its_subject_token_token_url_or_resource() {
    let o = Oauth::with_wire(1, None, None);
    let lines = |cred: Option<&str>, settings: &str| -> Vec<String> {
        match style::open(
            style::OAUTH_TOKEN_EXCHANGE,
            cred.map(str::as_bytes),
            Some(settings.as_bytes()),
            &o,
        ) {
            Ok(_) => panic!("the binding is refused"),
            Err(r) => r.iter().map(style::Refusal::line).collect(),
        }
    };
    assert_eq!(
        lines(None, "{}"),
        [
            "settings: uses auth: oauth-token-exchange but declares no credential; that grant \
             exchanges busbar's own subject token (the credential) for the upstream's, so there \
             is nothing to exchange",
            "settings: uses auth: oauth-token-exchange but has no `token_url` (the authorization \
             server's token endpoint busbar's subject token is exchanged at)",
            "settings: uses auth: oauth-token-exchange but has no `resource` — the RFC 8707 \
             resource indicator the exchanged token is audience-bound to. A token minted for one \
             upstream must not be spendable at another.",
        ]
    );
    assert_eq!(
        lines(Some("  "), SETTINGS).len(),
        1,
        "a blank subject token is none"
    );
    assert_eq!(
        lines(Some(SUBJECT), r#"{"token_url":"https://as.example/token"}"#).len(),
        1,
        "no resource"
    );
}
