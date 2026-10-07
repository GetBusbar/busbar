// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S SCRIPTS (`abi/auth/`, v3): the INBOUND and LOGIN script, this file, and the
//! OUTBOUND script ([`outbound`]). A door is driven by the script of every family its tail declares:
//! one declaring `CAP_INBOUND` or `CAP_LOGIN` by this one, one declaring `CAP_OUTBOUND` by the
//! outbound one, one declaring both by both (each then skips the other family's "undeclared" steps).
//!
//! THE INBOUND AND LOGIN SCRIPT. Ported from the auth both-ways proofs (#439's
//! `auth_door_conformance_tests`, the predev `auth_verify_conformance_tests`, and the token cases of
//! `busbar-auth-admin-tokens`' own conformance test), over the one loader and the one dispatcher.
//!
//! The script drives the INBOUND family, `verify`, the way the host's identity chain calls it
//! (`busbar_contract::auth_calls::AuthCalls`): ON THE SPOT (ticket-less, on the caller's thread),
//! and SUBMITTED on a ticket; a short answer is re-called ONCE with the buffers it named. Every
//! case is presented as the host presents a request: the kernel's extracted candidate credential
//! (`VerifyIn::credential`, a secret blob) and the carrier lines (`VerifyIn::carrier`), each a
//! carrier the Statement states (its `MARK_WORD_CARRIER` word marks), unless the tail states
//! `FACT_INBOUND_ALL_HEADERS`. A tail declaring the LOGIN family (`CAP_LOGIN`) has it driven too:
//! `begin_login` (its authorize URL, leased, then released) and `complete_login` SUBMITTED on a
//! ticket (the plugin's own token exchange over its declared need). A login-only tail (no
//! `CAP_INBOUND`) is driven through the login family alone. The op families the tail does NOT
//! declare are each called once and must answer REFUSED; the outbound family's are the outbound
//! script's when the tail declares it.
//!
//! A plugin whose needs reach a far end (an IdP's JWKS, its token endpoint) names those far ends
//! in `far_ends` (see the suite's module docs): each instance is bound to a connection table that
//! serves them, as the host's connector would, and the plugin holds no socket.
//!
//! Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings it opens over>,
//!   "auth": {
//!     "bad_settings": [<settings `open` must refuse, FAILED with a reason>, ...],
//!     "rotated_settings": <settings for ANOTHER credential: no identity case identifies there>,
//!     "cases": [
//!       { "credential": "<the extracted candidate>" | null,
//!         "carriers": { "<carrier line>": "<its value>", ... },
//!         "verdict": "identity:<subject>" | "reject" | "pass" }, ... ],
//!     "never_echoed": ["<text no answer may carry: the token, the raw settings>", ...],
//!     "login": {                                   // required when the tail states CAP_LOGIN
//!       "begin": { "redirect_uri": "..", "state": "..", "code_challenge": "..", "nonce": ".." },
//!       "authorize_prefix": "<the authorize URL starts with this>",   // a redirect login
//!       "form": ["<name>:text|password[:required]", ...],             // a credential login
//!       "begin_crossings": <crossings of begin_login, default 2 (the call, the release)>,
//!       "complete": { "code": "..", "state": "..", "nonce": "..", "redirect_uri": "..",
//!                     "code_verifier": ".." }      // a redirect login's callback
//!                 | { "submitted": { "<field>": "<value>", ... } },  // a credential login's form
//!       "complete_verdict": "identity:<subject>" | "reject" | "outage" | "security",
//!       "complete_rejected": <a `complete` the far end refuses: verdict reject; optional>,
//!       "complete_crossings": <crossings of each submitted complete_login, default 1> } } }
//! ```
//!
//! The cases must reach every verdict (an identity, a reject, a pass), so the two legs' equality
//! covers all three; but a door that judges no bearer credential (every case PASS, its identity
//! is its login's) is compared over its login, which must then reach an identity and a refused
//! credential (`complete_rejected`). The verdict semantics are the kind's (`abi/auth/mod.rs`): VERDICTS ARE ALWAYS
//! READY, never leased; an identity names its subject in the host's buffer.
//!
//! Every step is one ticket-less crossing of the auth table (or one ticketed crossing, for the
//! submitted `verify`), but: `verify` on an UNOPENED instance and after `close` (the host refuses
//! an op on an instance that is not open before any crossing: 0); the short-buffer `verify` (the
//! ONE re-call is +1: 2); and `ready` ([`super::ready_step`]).

use std::time::Duration;

use busbar_contract::abi::auth::{
    self, slot, AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, LoginField, NamedValue, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, StripName, VerifyIn, BEGIN_AUTHORIZE, BEGIN_FORM,
    FORM_PASSWORD, FORM_TEXT, LOGIN_BAD_CREDENTIAL, LOGIN_IDENTITY, LOGIN_KIND_CREDENTIAL,
    LOGIN_OUTAGE, LOGIN_SECURITY_CHECK_FAILED, SPAN_ABSENT, VERDICT_IDENTITY, VERDICT_PASS,
    VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, Span, BLOB_ABSENT, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_CARRIER};

mod outbound;

pub use outbound::{red_outbound_double_fetch, red_outbound_wrong_byte};

use super::{
    bind_far, called, close, crossings, dispatcher, input, load, open, output, ready_step, refresh,
    release, tick, validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{now_ns, Dispatcher, Frame, Plugin};

/// How long a submitted `verify` is awaited: the host's call budget, generously.
const SUBMIT_WAIT: Duration = Duration::from_secs(10);

fn text(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: an auth input is missing"),
        other => other.to_string().into_bytes(),
    }
}

/// What the tail and the Statement state, read off the linked door (the dropped-in library states
/// the same Statement: the both-ways arm asserts it first).
struct Stated {
    caps: u32,
    facts: u32,
    login_kind: u32,
    carriers: Vec<String>,
    /// The outbound styles the tail declares: name, flags, points.
    styles: Vec<(String, u32, u32)>,
}

/// `s`'s door's auth tail and carrier word marks.
///
/// # Panics
/// When the door states no auth tail.
fn stated(s: &Subject) -> Stated {
    let door = (s.door)();
    assert!(!door.is_null(), "the door function answered NULL");
    // SAFETY: a door function answers a `'static` door whose Statement, kind tail and word marks
    // are `'static` plain data (`abi/mechanism/door.rs`); an auth door's kind tail is an
    // `AuthTail` leading with its `KindTailHead` (`abi/auth/mod.rs`). Each is read unaligned.
    unsafe {
        let st: *const Statement = std::ptr::addr_of!((*door).statement).read_unaligned();
        assert!(!st.is_null(), "the door states no Statement");
        let st = st.read_unaligned();
        assert!(!st.kind_tail.is_null(), "an auth door states its auth tail");
        let tail = st.kind_tail.cast::<AuthTail>().read_unaligned();
        let words: &[MarkWord] = if st.mark_words.is_null() {
            &[]
        } else {
            std::slice::from_raw_parts(st.mark_words, st.mark_words_len)
        };
        let carriers = words
            .iter()
            .filter(|w| w.class == MARK_WORD_CARRIER)
            .map(|w| {
                String::from_utf8_lossy(std::slice::from_raw_parts(w.word.ptr, w.word.len))
                    .into_owned()
            })
            .collect();
        let styles = if tail.styles.is_null() {
            Vec::new()
        } else {
            std::slice::from_raw_parts(tail.styles, tail.styles_len)
                .iter()
                .map(|d| {
                    (
                        String::from_utf8_lossy(std::slice::from_raw_parts(d.name.ptr, d.name.len))
                            .into_owned(),
                        d.flags,
                        d.points,
                    )
                })
                .collect()
        };
        Stated {
            caps: tail.caps,
            facts: tail.facts,
            login_kind: tail.login_kind,
            carriers,
            styles,
        }
    }
}

/// One case, as the host presents it: the candidate credential and the carrier lines, owned for
/// as long as a `verify` over them may run, with the host's identity buffer.
struct Presented {
    credential: Option<Vec<u8>>,
    names: Vec<String>,
    _values: Vec<Vec<u8>>,
    carriers: Vec<NamedValue>,
    bytes: Vec<u8>,
    groups: Vec<Span>,
    /// The host's strip array (the credential lines the plugin names, whatever its verdict).
    strips: Vec<StripName>,
}

/// A secret octet blob over `bytes`.
fn secret(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

impl Presented {
    fn new(case: &serde_json::Value) -> Self {
        let credential = match &case["credential"] {
            serde_json::Value::Null => None,
            v => Some(text(v)),
        };
        let lines = case["carriers"].as_object().cloned().unwrap_or_default();
        let names: Vec<String> = lines.keys().cloned().collect();
        let values: Vec<Vec<u8>> = lines.values().map(text).collect();
        let carriers = names
            .iter()
            .zip(&values)
            .map(|(n, v)| NamedValue {
                name: AbiStr::over(n.as_bytes()),
                value: secret(v),
            })
            .collect();
        Self {
            credential,
            names,
            _values: values,
            carriers,
            bytes: vec![0; auth::IDENTITY_BUF_BYTES],
            groups: vec![Span { offset: 0, len: 0 }; auth::IDENTITY_GROUPS as usize],
            strips: vec![
                StripName {
                    name: Span {
                        offset: SPAN_ABSENT,
                        len: 0
                    },
                    place: 0,
                    _reserved: 0,
                };
                auth::FIELDS_MAX as usize
            ],
        }
    }

    /// The host's identity buffer: the full one, or one of no capacity (the short-buffer step).
    fn buf(&mut self, full: bool) -> IdentityBuf {
        IdentityBuf {
            buf: self.bytes.as_mut_ptr(),
            buf_cap: if full { self.bytes.len() } else { 0 },
            groups: self.groups.as_mut_ptr(),
            groups_cap: if full { self.groups.len() as u32 } else { 0 },
            _reserved: 0,
        }
    }

    /// `verify`'s frame over this case.
    fn frame(&mut self, full: bool) -> Frame<VerifyIn, IdentifyOut> {
        let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(input(), output());
        f.input.credential = self.credential.as_deref().map_or(Blob::ABSENT, secret);
        f.input.lines = self.carriers.as_ptr();
        f.input.lines_len = self.carriers.len();
        f.input.point = busbar_contract::abi::auth::AuthPoint::Head.bit();
        f.input.strip = self.strips.as_mut_ptr();
        f.input.strip_cap = self.strips.len() as u32;
        f.input.request.method = AbiStr::over(b"GET");
        f.input.request.authority = AbiStr::over(b"conformance.invalid");
        f.input.request.canonical_path = AbiStr::over(b"/");
        f.input.out_buf = self.buf(full);
        f
    }

    /// The verdict an answer's `out` names, as the transcript spells it.
    fn verdict(&self, outcome: Outcome, out: &IdentifyOut) -> String {
        let needed = format!("needed={}/{}", out.needed_bytes, out.needed_groups);
        if outcome != Outcome::Ready {
            return format!("verdict=none {needed}");
        }
        match out.verdict {
            VERDICT_IDENTITY => {
                let s = out.identity.subject;
                let subject = if s.offset == SPAN_ABSENT {
                    "<absent>".to_string()
                } else {
                    let at = s.offset as usize;
                    String::from_utf8_lossy(&self.bytes[at..at + s.len as usize]).into_owned()
                };
                format!(
                    "{needed} groups={} verdict=Identity({subject})",
                    out.identity.groups_len
                )
            }
            VERDICT_REJECT => format!("{needed} verdict=Reject"),
            VERDICT_PASS => format!("{needed} verdict=Pass"),
            other => format!("{needed} verdict={other}"),
        }
    }

    /// The carrier names this case presents.
    fn carrier_names(&self) -> &[String] {
        &self.names
    }
}

/// `verify` ON THE SPOT, ticket-less, at the host's starting buffers.
fn verify_now(p: &Plugin<Auth>, case: &mut Presented) -> String {
    let mut f = case.frame(true);
    let c = p.call(slot::VERIFY, &mut f);
    format!("{} {}", called(&c), case.verdict(c.outcome, &f.out))
}

/// `verify` SUBMITTED on a ticket, awaited, the ticket recycled.
fn verify_submitted(p: &Plugin<Auth>, d: &Dispatcher, case: &mut Presented) -> String {
    let ticket = d.mint(0).expect("a ticket is free");
    let deadline = now_ns().saturating_add(SUBMIT_WAIT.as_nanos() as u64);
    let reply = d.submit(
        p,
        ticket,
        slot::VERIFY,
        case.frame(true),
        DeadlineClass::Call,
        deadline,
    );
    let done = reply.wait(SUBMIT_WAIT);
    drop(reply);
    d.recycle(ticket);
    let Some(done) = done else {
        return "no answer".to_string();
    };
    let text = done
        .error
        .as_deref()
        .map(String::from_utf8_lossy)
        .unwrap_or_default();
    let verdict = match &done.frame {
        Some(f) => case.verdict(done.outcome, &f.out),
        None => "frame=none".to_string(),
    };
    format!(
        "{:?} lease={} {text} {verdict}",
        done.outcome,
        done.lease != 0
    )
}

/// `verify` with NO buffer: the identity does not fit, the answer is short, and the host re-calls
/// ONCE, as a fresh call, with the buffers it named.
fn verify_short(p: &Plugin<Auth>, case: &mut Presented) -> String {
    let mut f = case.frame(false);
    let first = p.call(slot::VERIFY, &mut f);
    let short = format!("short={}", first.recall.is_some());
    let Some(token) = first.recall else {
        return format!(
            "{short} {} {}",
            called(&first),
            case.verdict(first.outcome, &f.out)
        );
    };
    f.input.out_buf = case.buf(true);
    let c = p.recall(token, slot::VERIFY, &mut f);
    format!("{short} {} {}", called(&c), case.verdict(c.outcome, &f.out))
}

/// An auth op over all-zero frames: the families the tail does not declare answer REFUSED.
fn undeclared<I: crate::dispatch::InFrame, O: crate::dispatch::OutFrame>(
    p: &Plugin<Auth>,
    s: u32,
) -> String {
    let mut f: Frame<I, O> = Frame::new(input(), output());
    called(&p.call(s, &mut f))
}

/// A login input's text (`""` when absent).
fn word(v: &serde_json::Value, key: &str) -> Vec<u8> {
    v[key].as_str().unwrap_or_default().as_bytes().to_vec()
}

/// Plugin text named by a READY answer, copied (`""` when absent).
///
/// # Safety
/// `s` names plugin memory valid until the answer's lease is released (the caller copies first).
unsafe fn copied(s: AbiStr) -> String {
    if s.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the caller's contract.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

/// A credential form as the transcript spells it: `name:kind[:required]` a field, in order.
fn spelled_form(out: &BeginLoginOut) -> String {
    if out.form.is_null() || out.form_len == 0 {
        return "[]".to_string();
    }
    // SAFETY: a READY `begin_login` names `form_len` fields of plugin memory held under the
    // answer's lease (or `'static`), valid until that lease is released (after this copy).
    let fields = unsafe { std::slice::from_raw_parts(out.form, out.form_len) };
    let fields: Vec<String> = fields
        .iter()
        .map(|f: &LoginField| {
            let kind = match f.kind {
                FORM_TEXT => "text".to_string(),
                FORM_PASSWORD => "password".to_string(),
                other => other.to_string(),
            };
            // SAFETY: as above.
            let name = unsafe { copied(f.name) };
            if f.required == 1 {
                format!("{name}:{kind}:required")
            } else {
                format!("{name}:{kind}")
            }
        })
        .collect();
    format!("[{}]", fields.join(","))
}

/// `begin_login` over `begin`'s inputs, then the release of the lease its answer is held under
/// (none for a `'static` answer): the answer, the shape, and the URL or the credential form as the
/// plugin answered it.
fn begin_login(p: &Plugin<Auth>, begin: &serde_json::Value) -> String {
    let (redirect, state, challenge, nonce) = (
        word(begin, "redirect_uri"),
        word(begin, "state"),
        word(begin, "code_challenge"),
        word(begin, "nonce"),
    );
    let mut f: Frame<BeginLoginIn, BeginLoginOut> = Frame::new(input(), output());
    f.input.redirect_uri = AbiStr::over(&redirect);
    f.input.state = AbiStr::over(&state);
    f.input.code_challenge = AbiStr::over(&challenge);
    f.input.nonce = AbiStr::over(&nonce);
    let c = p.call(slot::BEGIN_LOGIN, &mut f);
    let shape = if f.out.shape == BEGIN_FORM {
        format!("form={}", spelled_form(&f.out))
    } else {
        // SAFETY: a READY `begin_login` names its URL in plugin memory held under the answer's
        // lease, valid until that lease is released (below, after this copy).
        let url = unsafe { copied(f.out.authorize_url) };
        format!("authorize={} url={url}", f.out.shape == BEGIN_AUTHORIZE)
    };
    let released = if c.lease == 0 {
        "none".to_string()
    } else {
        called(&release(p, c.lease))
    };
    format!("{} {shape} released={released}", called(&c))
}

/// A secret blob over `bytes`, or the absent blob when the login input names none.
fn secret_or_absent(v: &serde_json::Value, key: &str, bytes: &[u8]) -> Blob {
    if v.get(key).is_some() {
        secret(bytes)
    } else {
        Blob {
            ptr: std::ptr::null(),
            len: 0,
            fmt: BLOB_ABSENT,
            flags: 0,
        }
    }
}

/// `complete_login` over `complete`'s inputs, SUBMITTED on a ticket and awaited (the plugin makes
/// its own token exchange, or its directory bind, over its need): the answer and the verdict it
/// names. The redirect flow's callback (`code`, `state`, `nonce`, `redirect_uri`,
/// `code_verifier`), or the credential flow's `submitted` form fields (`{ "<name>": "<value>" }`),
/// each value a secret blob as the host lends every submitted field.
fn complete_submitted(p: &Plugin<Auth>, d: &Dispatcher, complete: &serde_json::Value) -> String {
    let (code, state, nonce, redirect, verifier) = (
        word(complete, "code"),
        word(complete, "state"),
        word(complete, "nonce"),
        word(complete, "redirect_uri"),
        word(complete, "code_verifier"),
    );
    let mut bytes = vec![0_u8; auth::IDENTITY_BUF_BYTES];
    let mut groups = vec![Span { offset: 0, len: 0 }; auth::IDENTITY_GROUPS as usize];
    let submitted: Vec<(String, Vec<u8>)> = complete["submitted"]
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        v.as_str().unwrap_or_default().as_bytes().to_vec(),
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let named: Vec<NamedValue> = submitted
        .iter()
        .map(|(name, value)| NamedValue {
            name: AbiStr::over(name.as_bytes()),
            value: secret(value),
        })
        .collect();
    let mut f: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(input(), output());
    f.input.code = secret_or_absent(complete, "code", &code);
    f.input.state = AbiStr::over(&state);
    f.input.nonce = AbiStr::over(&nonce);
    f.input.redirect_uri = AbiStr::over(&redirect);
    f.input.code_verifier = secret_or_absent(complete, "code_verifier", &verifier);
    if !named.is_empty() {
        f.input.submitted = named.as_ptr();
        f.input.submitted_len = named.len();
    }
    f.input.out_buf = IdentityBuf {
        buf: bytes.as_mut_ptr(),
        buf_cap: bytes.len(),
        groups: groups.as_mut_ptr(),
        groups_cap: groups.len() as u32,
        _reserved: 0,
    };
    let ticket = d.mint(0).expect("a ticket is free");
    let deadline = now_ns().saturating_add(SUBMIT_WAIT.as_nanos() as u64);
    let reply = d.submit(
        p,
        ticket,
        slot::COMPLETE_LOGIN,
        f,
        DeadlineClass::Call,
        deadline,
    );
    let done = reply.wait(SUBMIT_WAIT);
    drop(reply);
    d.recycle(ticket);
    let Some(done) = done else {
        return "no answer".to_string();
    };
    let verdict = match &done.frame {
        Some(f) if done.outcome == Outcome::Ready => match f.out.verdict {
            LOGIN_IDENTITY => {
                let s = f.out.identity.subject;
                let subject = if s.offset == SPAN_ABSENT {
                    "<absent>".to_string()
                } else {
                    let at = s.offset as usize;
                    String::from_utf8_lossy(&bytes[at..at + s.len as usize]).into_owned()
                };
                format!("verdict=Identity({subject})")
            }
            LOGIN_BAD_CREDENTIAL => "verdict=Reject".to_string(),
            LOGIN_OUTAGE => "verdict=Outage".to_string(),
            LOGIN_SECURITY_CHECK_FAILED => "verdict=Security".to_string(),
            other => format!("verdict={other}"),
        },
        _ => "verdict=none".to_string(),
    };
    format!("{:?} lease={} {verdict}", done.outcome, done.lease != 0)
}

/// A login's expected verdict, as the transcript spells it.
fn expected_login(v: &serde_json::Value) -> String {
    let v = v
        .as_str()
        .expect("conformance.json: auth.login.complete_verdict names the verdict");
    match v.split_once(':') {
        Some(("identity", subject)) => format!("verdict=Identity({subject})"),
        None if v == "reject" => "verdict=Reject".to_string(),
        None if v == "outage" => "verdict=Outage".to_string(),
        None if v == "security" => "verdict=Security".to_string(),
        _ => panic!(
            "conformance.json: login verdict '{v}' is not identity:<subject>, reject, outage or \
             security"
        ),
    }
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("auth");
    assert!(k.is_object(), "conformance.json has no `auth` inputs");
    let st = stated(s);
    let inbound = st.caps & auth::CAP_INBOUND != 0;
    let login = st.caps & auth::CAP_LOGIN != 0;
    let outbound = st.caps & auth::CAP_OUTBOUND != 0;
    assert!(
        inbound || login || outbound,
        "an auth door declares the inbound, the login or the outbound family; this one states \
         caps={}",
        st.caps
    );
    let mut fold = Fold::new();
    if inbound || login {
        fold.extend(inbound_and_login(s, leg, k, &st));
    }
    if outbound {
        fold.extend(outbound::fold(s, leg, s.door, &st));
    }
    fold
}

/// THE INBOUND AND LOGIN SCRIPT, over a door whose tail declares `CAP_INBOUND` or `CAP_LOGIN`.
fn inbound_and_login(s: &Subject, leg: Leg, k: &serde_json::Value, st: &Stated) -> Fold {
    let inbound = st.caps & auth::CAP_INBOUND != 0;
    let login = st.caps & auth::CAP_LOGIN != 0;
    let settings = leg.settings(s);
    let bad: Vec<Vec<u8>> = k["bad_settings"]
        .as_array()
        .expect("conformance.json: auth.bad_settings must be an array")
        .iter()
        .map(text)
        .collect();
    assert!(
        !bad.is_empty(),
        "conformance.json: auth.bad_settings is empty"
    );
    let specs: Vec<serde_json::Value> = if inbound {
        k["cases"]
            .as_array()
            .expect("conformance.json: auth.cases must be an array")
            .clone()
    } else {
        Vec::new()
    };
    let expected: Vec<String> = specs.iter().map(expected_verdict).collect();
    let lg = &k["login"];
    // A door that judges no bearer credential (every case PASS: its identity is its login's) is
    // compared over its login instead: the login must reach an identity AND a refused credential.
    let pass_only = !expected.is_empty() && expected.iter().all(|v| v.ends_with("Pass"));
    if inbound && pass_only {
        assert!(
            login
                && expected_login(&lg["complete_verdict"]).contains("Identity(")
                && lg["complete_rejected"].is_object(),
            "conformance.json: auth.cases reach only PASS, so the door's login is what the two \
             legs compare: the tail must state CAP_LOGIN, auth.login.complete_verdict an identity, \
             and auth.login.complete_rejected a credential the far end refuses"
        );
    } else if inbound {
        for want in ["Identity(", "Reject", "Pass"] {
            assert!(
                expected.iter().any(|v| v.contains(want)),
                "conformance.json: auth.cases must reach a {want} verdict"
            );
        }
    }
    let mut cases: Vec<Presented> = specs.iter().map(Presented::new).collect();
    if st.facts & auth::FACT_INBOUND_ALL_HEADERS == 0 {
        for c in &cases {
            for n in c.carrier_names() {
                assert!(
                    st.carriers.iter().any(|w| w.eq_ignore_ascii_case(n)),
                    "conformance.json: carrier '{n}' is not a carrier the Statement states \
                     ({:?}); the host lends no other",
                    st.carriers
                );
            }
        }
    }
    let identity_at = expected.iter().position(|v| v.contains("Identity("));
    if login {
        assert!(
            lg.is_object(),
            "conformance.json: the tail states CAP_LOGIN, so auth.login drives it"
        );
    }

    let d = dispatcher();
    let p = load::<Auth>(s, leg, bind_far(&d, "auth", s)).expect("the auth door loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("facts", 0, || {
        format!(
            "{:?} {} max_inflight={} caps={} facts={} login_kind={} carriers={:?}",
            p.kind(),
            p.name(),
            p.max_inflight(),
            st.caps,
            st.facts,
            st.login_kind,
            st.carriers
        )
    });
    for (i, b) in bad.iter().enumerate() {
        r.line(&format!("validate bad #{i}"), 1, || {
            called(&validate(&p, b))
        });
    }
    r.line("validate", 1, || called(&validate(&p, &settings)));
    if let Some(at) = identity_at {
        // 0: the host refuses a kind op on an instance that is not open, before any crossing.
        r.line("verify unopened", 0, || verify_now(&p, &mut cases[at]));
    }
    for (i, b) in bad.iter().enumerate() {
        r.line(&format!("open bad #{i}"), 1, || called(&open(&p, b)));
    }
    r.line("open", 1, || called(&open(&p, &settings)));
    ready_step(&mut r, s, &p, &d);
    if inbound {
        for (i, c) in cases.iter_mut().enumerate() {
            r.line(&format!("verify #{i}"), 1, || verify_now(&p, c));
        }
        for (i, c) in cases.iter_mut().enumerate() {
            r.line(&format!("verify #{i} submitted"), 1, || {
                verify_submitted(&p, &d, c)
            });
        }
        if let Some(at) = identity_at {
            // 2: the short answer, then the ONE re-call with the buffers it named.
            r.line("verify short, re-called", 2, || {
                verify_short(&p, &mut cases[at])
            });
        }
    } else {
        r.line("verify undeclared", 1, || {
            undeclared::<VerifyIn, IdentifyOut>(&p, slot::VERIFY)
        });
    }
    if login {
        // 2: the call, then the release of the lease its answer is held under (a `'static`
        // answer holds none: `begin_crossings` 1).
        let begun = lg["begin_crossings"].as_u64().unwrap_or(2);
        r.line("begin_login", begun, || begin_login(&p, &lg["begin"]));
        let pinned = lg["complete_crossings"].as_u64().unwrap_or(1);
        r.line("complete_login submitted", pinned, || {
            complete_submitted(&p, &d, &lg["complete"])
        });
        if lg["complete_rejected"].is_object() {
            r.line("complete_login rejected submitted", pinned, || {
                complete_submitted(&p, &d, &lg["complete_rejected"])
            });
        }
    } else {
        r.line("begin_login undeclared", 1, || {
            undeclared::<BeginLoginIn, BeginLoginOut>(&p, slot::BEGIN_LOGIN)
        });
        r.line("complete_login undeclared", 1, || {
            undeclared::<CompleteLoginIn, IdentifyOut>(&p, slot::COMPLETE_LOGIN)
        });
    }
    // The outbound family's steps are the outbound script's when the tail declares it.
    if st.caps & auth::CAP_OUTBOUND == 0 {
        r.line("open_outbound undeclared", 1, || {
            undeclared::<OpenOutboundIn, OpenOutboundOut>(&p, slot::OPEN_OUTBOUND)
        });
        r.line("outbound_ready undeclared", 1, || {
            undeclared::<OutboundReadyIn, OutboundReadyOut>(&p, slot::OUTBOUND_READY)
        });
        r.line("fields undeclared", 1, || {
            undeclared::<FieldsIn, FieldsOut>(&p, slot::FIELDS)
        });
    }
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        format!("{} next={next}", called(&c))
    });
    // The admin cache flush: `refresh` with a new generation and unchanged settings.
    r.line("refresh", 1, || called(&refresh(&p, &settings)));
    if let Some(at) = identity_at {
        r.line("verify after refresh", 1, || verify_now(&p, &mut cases[at]));
    }
    r.line("close", 1, || called(&close(&p)));
    if let Some(at) = identity_at {
        // 0: a closed instance answers FAULT without a crossing.
        r.line("verify after close", 0, || verify_now(&p, &mut cases[at]));
    }

    if inbound {
        // THE ROTATED CREDENTIAL, on an instance of its own (opened and made ready as the host
        // opens every instance): no identity case identifies there.
        let rotated = text(&k["rotated_settings"]);
        let q = load::<Auth>(s, leg, bind_far(&d, "auth-rotated", s)).expect("the auth door loads");
        let mut rq = Recorder::new(crossings(&q));
        rq.line("open rotated", 1, || called(&open(&q, &rotated)));
        ready_step(&mut rq, s, &q, &d);
        for (i, c) in cases.iter_mut().enumerate() {
            if expected[i].contains("Identity(") {
                rq.line(&format!("verify #{i} rotated"), 1, || verify_now(&q, c));
            }
        }
        rq.line("close rotated", 1, || called(&close(&q)));
        r.absorb(rq);
    }

    let fold = r.fold();
    contract(&fold, &expected, identity_at, &never_echoed(k));
    if login {
        login_contract(&fold, lg, st.login_kind);
    }
    fold
}

/// THE LOGIN FAMILY'S CONTRACT: `begin_login` answers READY with an authorize URL that starts as
/// the inputs say, leased and then released (a redirect login), or with the credential form the
/// inputs state, field by field, its lease (if any) released (a credential login); the submitted
/// `complete_login` answers READY with the login's verdict, unleased, and a credential the far end
/// refuses (`complete_rejected`) answers READY with a refused credential.
fn login_contract(fold: &Fold, lg: &serde_json::Value, login_kind: u32) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    let begin = at("begin_login");
    if login_kind == LOGIN_KIND_CREDENTIAL {
        let form: Vec<&str> = lg["form"]
            .as_array()
            .expect("conformance.json: a credential login states auth.login.form")
            .iter()
            .map(|f| {
                f.as_str()
                    .expect("conformance.json: auth.login.form is `name:kind[:required]` lines")
            })
            .collect();
        let released = if begin.starts_with("Ready lease=true ") {
            "released=Ready lease=false "
        } else {
            "released=none"
        };
        assert!(
            begin.starts_with("Ready ")
                && begin.contains(&format!("form=[{}]", form.join(",")))
                && begin.ends_with(released),
            "begin_login answers its credential form (want {form:?}), any lease released: {begin}"
        );
    } else {
        let prefix = lg["authorize_prefix"]
            .as_str()
            .expect("conformance.json: auth.login.authorize_prefix");
        assert!(
            begin.starts_with("Ready lease=true ")
                && begin.contains(&format!("authorize=true url={prefix}"))
                && begin.ends_with("released=Ready lease=false "),
            "begin_login answers its authorize URL under a lease it then releases: {begin}"
        );
    }
    let complete = at("complete_login submitted");
    let want = expected_login(&lg["complete_verdict"]);
    assert!(
        complete.starts_with("Ready lease=false ") && complete.ends_with(&want),
        "complete_login: {complete} (want {want})"
    );
    if lg["complete_rejected"].is_object() {
        let refused = at("complete_login rejected submitted");
        assert!(
            refused.starts_with("Ready lease=false ") && refused.ends_with("verdict=Reject"),
            "complete_login over a refused credential: {refused} (want verdict=Reject)"
        );
    }
}

/// A case's verdict as the transcript spells it.
fn expected_verdict(case: &serde_json::Value) -> String {
    let v = case["verdict"]
        .as_str()
        .expect("conformance.json: every auth case names its verdict");
    match v.split_once(':') {
        Some(("identity", subject)) => format!("verdict=Identity({subject})"),
        None if v == "reject" => "verdict=Reject".to_string(),
        None if v == "pass" => "verdict=Pass".to_string(),
        _ => {
            panic!("conformance.json: auth verdict '{v}' is not identity:<subject>, reject or pass")
        }
    }
}

fn never_echoed(k: &serde_json::Value) -> Vec<String> {
    k["never_echoed"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures cannot pass: every verdict is
/// READY and unleased, and is the case's own; the submitted answer is the on-the-spot one; the
/// short answer is re-called once into the case's verdict; settings `open` refuses are FAILED with
/// a reason; undeclared families are REFUSED; the flush keeps serving; a closed instance serves
/// nothing; a rotated credential identifies no one; no answer carries what must never be echoed.
fn contract(fold: &Fold, expected: &[String], identity_at: Option<usize>, never: &[String]) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    let rotated: &[&str] = if identity_at.is_some() {
        &["open rotated", "close rotated"]
    } else {
        &[]
    };
    for label in ["validate", "open", "refresh", "close"]
        .iter()
        .chain(rotated)
    {
        assert!(at(label).starts_with("Ready "), "{label}: {}", at(label));
    }
    let verdict_ok = |answer: &str, want: &str| {
        answer.starts_with("Ready lease=false ") && answer.ends_with(want)
    };
    for (i, want) in expected.iter().enumerate() {
        let now = at(&format!("verify #{i}"));
        assert!(verdict_ok(now, want), "verify #{i}: {now} (want {want})");
        let sub = at(&format!("verify #{i} submitted"));
        assert_eq!(
            sub, now,
            "verify #{i}: submitted and on the spot answer alike"
        );
        if want.contains("Identity(") {
            let rot = at(&format!("verify #{i} rotated"));
            assert!(
                rot.starts_with("Ready lease=false ") && !rot.contains("Identity("),
                "verify #{i} under a rotated credential identifies no one: {rot}"
            );
        }
    }
    if let Some(identity_at) = identity_at {
        let short = at("verify short, re-called");
        assert!(
            short.starts_with("short=true Ready lease=false ")
                && short.ends_with(&expected[identity_at]),
            "a short identity is re-called once into its verdict: {short}"
        );
        assert!(
            verdict_ok(at("verify after refresh"), &expected[identity_at]),
            "the flush keeps serving: {}",
            at("verify after refresh")
        );
        for label in ["verify unopened", "verify after close"] {
            assert!(!at(label).starts_with("Ready"), "{label}: {}", at(label));
        }
    }
    for st in fold.iter().filter(|s| s.label.starts_with("open bad #")) {
        assert!(
            st.answer.starts_with("Failed lease=false ")
                && st.answer.len() > "Failed lease=false ".len(),
            "{}: a refused open names why: {}",
            st.label,
            st.answer
        );
    }
    for st in fold.iter().filter(|s| s.label.ends_with(" undeclared")) {
        assert!(
            st.answer.starts_with("Refused "),
            "{}: {}",
            st.label,
            st.answer
        );
    }
    for word in never {
        for st in fold {
            assert!(
                !st.answer.contains(word.as_str()),
                "{}: an answer echoes what it must never carry",
                st.label
            );
        }
    }
}
