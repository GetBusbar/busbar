// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S SCRIPTS (`abi/auth/`, v3): the INBOUND and LOGIN script, this file, and the
//! OUTBOUND script ([`outbound`]). A door is driven by the script of every family its tail declares:
//! one declaring `CAP_INBOUND` or `CAP_LOGIN` by this one, one declaring `CAP_OUTBOUND` by the
//! outbound one, one declaring both by both (each then skips the other family's "undeclared" steps).
//!
//! The inbound and login conformance script runs over the loader and dispatcher.
//!
//!
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
//!                         (required unless the tail states FACT_READS_CREDENTIALS; there optional,
//!                          the rotated instance then opens over it, else over "settings")
//!     "host_credentials": [                         (required with FACT_READS_CREDENTIALS)
//!       { "kind": "<credential kind>", "id": "<credential id>", "secret": "<its secret>",
//!         "live": true | false }, ... ],
//!     "rotated_host_credentials": [ <the same ids, other secrets> ],   (likewise)
//!     "cases": [
//!       { "credential": "<the extracted candidate>" | null,
//!         "carriers" | "lines": { "<field line>": "<its value>", ... },
//!         "method": "<method>",            (optional, default "GET")
//!         "path": "<raw received path>",   (optional, default "/")
//!         "query": "<raw query, no ?>",    (optional, default none)
//!         "timestamp": <unix seconds>,     (optional, default 0)
//!         "body": "<the body, as text>",   (optional, HeadBody doors only, default none)
//!         "verdict": "identity:<subject>" | "reject" | "pass" }, ... ],
//!     "never_echoed": ["<text no answer may carry: the token, the raw settings>", ...],
//!     "short_reply": "retained" | "static",         (optional, default retained; static holds no lease)
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
//! The field lines are each a carrier the Statement states, unless the tail states
//! `FACT_INBOUND_ALL_HEADERS` (then any line); `"carriers"` and `"lines"` are one input under two
//! names. A door whose tail's `inbound_points` hold `POINT_HEAD_BODY` is presented each case at
//! `HeadBody`, with the case's body (none when it names none); every other door at `Head`. The
//! request facts (method, `conformance.invalid`, path, query, timestamp) are the case's, at either.
//!
//! Every leg's dispatcher serves the host's clock (`clock.now`, the kernel's one clock): a door
//! reading no host credential runs on a host holding none, which answers the wall clock a login's
//! token expiry is judged at and refuses every other service.
//!
//! A door whose tail states `FACT_READS_CREDENTIALS` reads its secret from the host: its leg's
//! dispatcher serves the host services, `records.secret` from `host_credentials` (the entry's
//! secret, `SECRET_LIVE` or `SECRET_NOT_LIVE`; for an id it does not hold, a fixed dummy secret,
//! not live, as busbar's root answers) and every other service unserved. Its credential is not in
//! its settings, so the ROTATED instance runs on a dispatcher of its own serving
//! `rotated_host_credentials`. And since a service that may pend needs a ticket, its ON-THE-SPOT
//! (ticket-less) `verify` may answer REFUSED for a case that needs the host read: the SUBMITTED one
//! must answer the case's verdict, having read the host (`host_reads=` on its line), and every step
//! the script reads a verdict from (`verify short, re-called`, `verify after refresh`,
//! `verify #i rotated`) is submitted on a ticket, the short re-call ONCE on the same ticket. A door
//! that does not read host credentials runs every step as before.
//!
//! The cases must reach every verdict (an identity, a reject, a pass), so the two legs' equality
//! covers all three; but a door that judges no bearer credential (every case PASS, its identity
//! is its login's) is compared over its login, which must then reach an identity and a refused
//! credential (`complete_rejected`). The verdict semantics are the kind's (`abi/auth/mod.rs`): VERDICTS ARE ALWAYS
//! READY, never leased; an identity names its subject in the host's buffer. A retained SHORT
//! negotiation holds the SDK's immutable decision under a private lease until recall cleanup.
//!
//! Every step is one ticket-less crossing of the auth table (or one ticketed crossing, for the
//! submitted `verify`), but: `verify` on an UNOPENED instance and after `close` (the host refuses
//! an op on an instance that is not open before any crossing: 0); the short-buffer `verify` (the
//! ONE re-call is +1, and retained-reply RELEASE is +1: 3). An explicitly declared static SHORT
//! reply holds no lease and crosses twice. `ready` is counted by [`super::ready_step`].

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{
    self, slot, AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, NamedValue, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
    OutboundReadyOut, StripName, VerifyIn, BEGIN_AUTHORIZE, BEGIN_FORM, LOGIN_BAD_CREDENTIAL,
    LOGIN_IDENTITY, LOGIN_KIND_CREDENTIAL, LOGIN_OUTAGE, LOGIN_SECURITY_CHECK_FAILED,
    POINT_HEAD_BODY, SPAN_ABSENT, VERDICT_IDENTITY, VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::host::service::{ItemSpan, SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, Span, BLOB_ABSENT, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_CARRIER};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::auth::{FieldKind, LoginOutcome};
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Snapshot,
    Stored, UNSERVED,
};

mod outbound;

pub use outbound::{
    red_outbound_double_fetch, red_outbound_writes_nothing, red_outbound_wrong_byte,
};

pub fn outbound_plant(s: &Subject, arm: fn(&Subject)) {
    s.apply_env();
    let states = s.kind() == busbar_contract::abi::mechanism::KindCode::Auth
        && stated(s).caps & auth::CAP_OUTBOUND != 0;
    let drives = !s.kind_inputs("auth")["outbound"].is_null();
    assert_eq!(
        states, drives,
        "the door states the outbound family: {states}; conformance.json drives `auth.outbound`: \
         {drives}. The outbound RED arms plant over a door that states the family and is driven \
         through it, and never pass unrun"
    );
    if states {
        arm(s);
    }
}

use super::{
    bind_far, called, close, crossings, dispatcher_serving, input, load, open, output, ready_step,
    refresh, release, tick, validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{now_ns, DispatchConfig, Dispatcher, Done, Frame, Lent, Plugin};

const SUBMIT_WAIT: Duration = Duration::from_secs(10);

fn text(v: &serde_json::Value) -> Vec<u8> {
    match v {
        serde_json::Value::String(s) => s.as_bytes().to_vec(),
        serde_json::Value::Null => panic!("conformance.json: an auth input is missing"),
        other => other.to_string().into_bytes(),
    }
}

struct Stated {
    caps: u32,
    facts: u32,
    login_kind: u32,

    points: u32,
    carriers: Vec<String>,

    styles: Vec<(String, u32, u32)>,
}

impl Stated {
    fn reads_credentials(&self) -> bool {
        self.facts & auth::FACT_READS_CREDENTIALS != 0
    }

    fn at_head_body(&self) -> bool {
        self.points & POINT_HEAD_BODY != 0
    }
}

fn stated(s: &Subject) -> Stated {
    let door = crate::dispatch::load::enter_door(s.door);
    assert!(!door.is_null(), "the door function answered NULL");
    // SAFETY: a door function answers a `'static` door whose Statement, kind tail and word marks
    // are `'static` plain data (`abi/mechanism/door.rs`); an auth door's kind tail is an
    // `AuthTail` leading with its `KindTailHead` (`abi/auth/mod.rs`). Each is read unaligned.
    unsafe {
        let st: *const Statement =
            busbar_contract::abi::mechanism::door::Door::read_parts(door).statement;
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
            points: tail.inbound_points,
            carriers,
            styles,
        }
    }
}

struct Presented {
    credential: Option<Vec<u8>>,
    names: Vec<String>,
    _values: Vec<Vec<u8>>,
    carriers: Vec<NamedValue>,
    bytes: Vec<u8>,
    groups: Vec<Span>,

    strips: Vec<StripName>,

    at_body: bool,
    method: Vec<u8>,
    path: Vec<u8>,
    query: Option<Vec<u8>>,
    timestamp: u64,

    body: Option<Vec<u8>>,
}

fn case_text(case: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    match case.get(key) {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(text(v)),
    }
}

fn secret(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: BLOB_SECRET,
    }
}

// SAFETY: the raw pointers in `carriers` point into `names` and `_values`, owned by the same
// `Presented` (their heap buffers never move); nothing mutates a `Presented` lent to a submitted
// op but the plugin's writes into `bytes`, `groups` and `strips`, which the host reads only after
// the op completes.
unsafe impl Send for Presented {}
// SAFETY: as above.
unsafe impl Sync for Presented {}

impl Presented {
    fn new(case: &serde_json::Value, at_body: bool) -> Self {
        let credential = match &case["credential"] {
            serde_json::Value::Null => None,
            v => Some(text(v)),
        };
        assert!(
            case.get("lines").is_none() || case.get("carriers").is_none(),
            "conformance.json: an auth case names its field lines once, as `carriers` or `lines`"
        );
        let lines = match case.get("lines").or_else(|| case.get("carriers")) {
            None => serde_json::Map::new(),
            Some(v) => v
                .as_object()
                .expect("conformance.json: auth lines/carriers must be an object")
                .clone(),
        };
        let body = case_text(case, "body");
        assert!(
            at_body || body.is_none(),
            "conformance.json: an auth case names a body, but the door is not called at HeadBody"
        );
        let timestamp = match case.get("timestamp") {
            None | Some(serde_json::Value::Null) => 0,
            Some(v) => v
                .as_u64()
                .expect("conformance.json: an auth case's timestamp is unix seconds (u64)"),
        };
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
            at_body,
            method: case_text(case, "method").unwrap_or_else(|| b"GET".to_vec()),
            path: case_text(case, "path").unwrap_or_else(|| b"/".to_vec()),
            query: case_text(case, "query"),
            timestamp,
            body,
        }
    }

    fn again(&self) -> Box<Self> {
        let names = self.names.clone();
        let values = self._values.clone();
        let carriers = names
            .iter()
            .zip(&values)
            .map(|(n, v)| NamedValue {
                name: AbiStr::over(n.as_bytes()),
                value: secret(v),
            })
            .collect();
        Box::new(Self {
            credential: self.credential.clone(),
            names,
            _values: values,
            carriers,
            bytes: vec![0; self.bytes.len()],
            groups: vec![Span { offset: 0, len: 0 }; self.groups.len()],
            strips: vec![
                StripName {
                    name: Span {
                        offset: SPAN_ABSENT,
                        len: 0
                    },
                    place: 0,
                    _reserved: 0,
                };
                self.strips.len()
            ],
            at_body: self.at_body,
            method: self.method.clone(),
            path: self.path.clone(),
            query: self.query.clone(),
            timestamp: self.timestamp,
            body: self.body.clone(),
        })
    }

    fn buf(&mut self, full: bool) -> IdentityBuf {
        IdentityBuf {
            buf: self.bytes.as_mut_ptr(),
            buf_cap: if full { self.bytes.len() } else { 0 },
            groups: self.groups.as_mut_ptr(),
            groups_cap: if full { self.groups.len() as u32 } else { 0 },
            _reserved: 0,
        }
    }

    fn frame(&mut self, full: bool) -> Frame<VerifyIn, IdentifyOut> {
        let mut f: Frame<VerifyIn, IdentifyOut> = Frame::new(input(), output());
        f.input.credential = self.credential.as_deref().map_or(Blob::ABSENT, secret);
        f.input.lines = self.carriers.as_ptr();
        f.input.lines_len = self.carriers.len();
        f.input.point = if self.at_body {
            POINT_HEAD_BODY
        } else {
            busbar_contract::abi::auth::AuthPoint::Head.bit()
        };
        f.input.strip = self.strips.as_mut_ptr();
        f.input.strip_cap = self.strips.len() as u32;
        f.input.request.method = AbiStr::over(&self.method);
        f.input.request.authority = AbiStr::over(b"conformance.invalid");
        f.input.request.canonical_path = AbiStr::over(&self.path);
        if let Some(q) = &self.query {
            f.input.request.query = AbiStr::over(q);
        }
        f.input.request.timestamp = self.timestamp;
        if let Some(b) = &self.body {
            f.input.body = Blob {
                ptr: b.as_ptr(),
                len: b.len(),
                fmt: BLOB_OCTETS,
                flags: 0,
            };
        }
        f.input.out_buf = self.buf(full);
        f
    }

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

    fn carrier_names(&self) -> &[String] {
        &self.names
    }
}

fn verify_now(p: &Plugin<Auth>, case: &mut Presented) -> String {
    let mut f = case.frame(true);
    let c = p.call(slot::VERIFY, &mut f);
    format!("{} {}", called(&c), case.verdict(c.outcome, &f.out))
}

fn submit_verify(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    ticket: Ticket,
    frame: Frame<VerifyIn, IdentifyOut>,
    lend: &Arc<Presented>,
) -> Done<VerifyIn, IdentifyOut> {
    let deadline = now_ns().saturating_add(SUBMIT_WAIT.as_nanos() as u64);
    super::submit_on(
        p,
        d,
        ticket,
        slot::VERIFY,
        frame,
        (DeadlineClass::Call, deadline),
        Arc::clone(lend) as Lent,
        Duration::ZERO,
    )
}

fn submitted_answer(case: &Presented, done: &Done<VerifyIn, IdentifyOut>) -> String {
    let verdict = match &done.frame {
        Some(f) => case.verdict(done.outcome, &f.out),
        None => "frame=none".to_string(),
    };
    format!("{} {verdict}", called(&super::answered(done)))
}

fn verify_submitted(p: &Plugin<Auth>, d: &Dispatcher, case: &Presented) -> String {
    let mut lend = case.again();
    let f = lend.frame(true);
    let lend: Arc<Presented> = Arc::from(lend);
    let ticket = d.mint(0).expect("a ticket is free");
    let done = submit_verify(p, d, ticket, f, &lend);
    d.recycle(ticket);
    submitted_answer(&lend, &done)
}

/// The SHORT storage contract is declared before the call; it never follows observed counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShortReply {
    Retained,
    Static,
}

impl ShortReply {
    fn of(inputs: &serde_json::Value) -> Self {
        match inputs.get("short_reply") {
            None => Self::Retained,
            Some(serde_json::Value::String(value)) if value == "retained" => Self::Retained,
            Some(serde_json::Value::String(value)) if value == "static" => Self::Static,
            _ => panic!("conformance.json: auth.short_reply must be retained (default) or static"),
        }
    }

    const fn crossings(self) -> u64 {
        match self {
            Self::Retained => 3,
            Self::Static => 2,
        }
    }

    fn check_lease(self, short: bool, lease: u64) {
        if short {
            assert_eq!(
                lease != 0,
                self == Self::Retained,
                "auth.short_reply={self:?} must match the SHORT answer's lease ownership"
            );
        }
    }
}

fn verify_short_submitted(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    case: &Presented,
    storage: ShortReply,
) -> String {
    let mut lend = case.again();
    let f = lend.frame(false);
    let full = lend.buf(true);
    let lend: Arc<Presented> = Arc::from(lend);
    let ticket = d.mint(0).expect("a ticket is free");
    let first = submit_verify(p, d, ticket, f, &lend);
    let short = first.short;
    if short {
        storage.check_lease(
            true,
            first
                .frame
                .as_ref()
                .expect("SHORT returned its frame")
                .out
                .head
                .lease,
        );
    }
    let answer = match first {
        Done {
            frame: Some(mut f),
            short: true,
            ..
        } => {
            f.input.out_buf = full;
            let again = submit_verify(p, d, ticket, f, &lend);
            submitted_answer(&lend, &again)
        }
        other => submitted_answer(&lend, &other),
    };
    d.recycle(ticket);
    assert!(
        d.retirement_barrier(ticket, SUBMIT_WAIT),
        "the submitted SHORT decision's cleanup must retire before its step is measured"
    );
    format!("short={short} {answer}")
}

fn verify_short(p: &Plugin<Auth>, case: &mut Presented, storage: ShortReply) -> String {
    let mut f = case.frame(false);
    let first = p.call(slot::VERIFY, &mut f);
    storage.check_lease(first.recall.is_some(), f.out.head.lease);
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

fn undeclared<I: crate::dispatch::InFrame, O: crate::dispatch::OutFrame>(
    p: &Plugin<Auth>,
    s: u32,
) -> String {
    let mut f: Frame<I, O> = Frame::new(input(), output());
    called(&p.call(s, &mut f))
}

const NOT_HELD: &str = "";

type HeldCredential = (String, String, String, bool);

fn held_credentials(k: &serde_json::Value, section: &str) -> Vec<HeldCredential> {
    let list = k[section].as_array().unwrap_or_else(|| {
        panic!(
            "conformance.json: the door reads host credentials (FACT_READS_CREDENTIALS): auth.{section} \
             must be an array of {{\"kind\",\"id\",\"secret\",\"live\"}}"
        )
    });
    assert!(
        !list.is_empty(),
        "conformance.json: auth.{section} is empty"
    );
    list.iter()
        .map(|c| {
            let field = |f: &str| {
                c[f].as_str()
                    .unwrap_or_else(|| panic!("conformance.json: auth.{section}[].{f} is a string"))
                    .to_string()
            };
            let live = c["live"]
                .as_bool()
                .unwrap_or_else(|| panic!("conformance.json: auth.{section}[].live is a boolean"));
            (field("kind"), field("id"), field("secret"), live)
        })
        .collect()
}

struct CredentialHost {
    held: Vec<HeldCredential>,
    reads: AtomicU64,
    clock: Option<Arc<outbound::Clock>>,
}

impl CredentialHost {
    fn new(held: Vec<HeldCredential>) -> Arc<Self> {
        Arc::new(Self {
            held,
            reads: AtomicU64::new(0),
            clock: None,
        })
    }

    fn clocked(clock: Arc<outbound::Clock>) -> Arc<Self> {
        Arc::new(Self {
            held: Vec::new(),
            reads: AtomicU64::new(0),
            clock: Some(clock),
        })
    }

    fn reads(&self) -> u64 {
        self.reads.load(Ordering::SeqCst)
    }
}

fn unserved() -> Ran {
    Ran::Now(Stored::refused(UNSERVED))
}

impl HostServices for CredentialHost {
    fn now(&self) -> Reading {
        if let Some(clock) = &self.clock {
            return clock.reading();
        }
        let wall = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Reading {
            wall_ns: wall,
            mono_ns: now_ns(),
        }
    }
    fn dest_judge(&self, _: &str, _: u32, _: u32, _: Option<Later>) -> Ran {
        unserved()
    }
    fn records_get(&self, _: &Caller, _: &str, _: &[u8], _: Later) -> Ran {
        unserved()
    }
    fn records_list(&self, _: &Caller, _: RecordsList, _: Later) -> Ran {
        unserved()
    }
    fn records_claim(&self, _: &Caller, _: &str, _: &[u8], _: u64, _: Later) -> Ran {
        unserved()
    }
    fn sign(&self, _: &Caller, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight(&self, _: &Caller, _: &str, _: &str, _: Later) -> Ran {
        unserved()
    }
    fn trust_due(&self, _: &Caller) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_verify(&self, _: &Caller, _: &str, _: &[u8], _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_unreached(&self, _: &Caller, _: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_sight_item(&self, _: &Caller, _: &str, _: &str, _: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_decide(
        &self,
        _: &Caller,
        _: busbar_contract::services::TrustKeyRef<'_>,
        _: Option<&str>,
        _: bool,
    ) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_state(&self, _: &Caller, _: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn session_emit(&self, _: &Caller, _: u64, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn ticket_mint(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8]) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn ticket_take(&self, _: &Caller, _: Option<u64>) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn trust_serves(&self, _: &Caller, _: &str, _: Option<&str>, _: Option<&str>) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn entitlement_check(&self, _: &Caller, _: Option<u64>, _: &str) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn random_fill(&self, _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn unit_nest(&self, _: &Caller, _: Option<u64>, _: NestAsk, _: Later) -> Ran {
        unserved()
    }
    fn work_open(&self, _: &Caller, _: Option<u64>, _: &str, _: &[u8], _: Later) -> Ran {
        unserved()
    }
    fn work_find(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        unserved()
    }
    fn work_settle(&self, _: &Caller, _: Option<u64>, _: u64, _: &[u8], _: Later) -> Ran {
        unserved()
    }
    fn work_resume(&self, _: &Caller, _: Option<u64>, _: u64, _: Later) -> Ran {
        unserved()
    }
    fn verify_lookup(&self, _: &Caller, _: &[u8], _: Later) -> Ran {
        unserved()
    }
    fn verify_store(&self, _: &Caller, _: &[u8], _: &[u8], _: u64) -> Stored {
        Stored::refused(UNSERVED)
    }
    fn content_scan(&self, _: &Caller, _: Option<u64>, _: &[u8], _: Later) -> Ran {
        unserved()
    }
    fn hook_call(&self, _: &Caller, _: Option<u64>, _: HookAsk, _: Later) -> Ran {
        unserved()
    }
    fn disk_append(&self, _: &DiskDest, _: Vec<u8>, _: Later) -> Ran {
        unserved()
    }
    fn snapshot_read(&self, _: &Caller, _: u32) -> Snapshot {
        Snapshot::Refused(UNSERVED)
    }
    fn records_secret(&self, kind: &str, id: &str, _: Later) -> Ran {
        if self.clock.is_some() {
            return unserved();
        }
        self.reads.fetch_add(1, Ordering::SeqCst);
        let (secret, live) = self
            .held
            .iter()
            .find(|(k, i, _, _)| k == kind && i == id)
            .map_or((NOT_HELD, false), |(_, _, s, live)| (s.as_str(), *live));
        Ran::Now(Stored {
            bytes: secret.as_bytes().to_vec(),
            spans: vec![ItemSpan {
                key: Span {
                    offset: SPAN_ABSENT,
                    len: 0,
                },
                value: Span {
                    offset: 0,
                    len: secret.len() as u32,
                },
            }],
            ..Stored::ready(if live { SECRET_LIVE } else { SECRET_NOT_LIVE })
        })
    }
}

fn served_by(host: &Arc<CredentialHost>) -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        host.clone(),
    ))
}

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

    String::from_utf8_lossy(crate::dispatch::plugin::str_bytes(s).unwrap_or_default()).into_owned()
}

fn spelled_form(out: &BeginLoginOut) -> String {
    let Some(LoginOutcome::Prompt(form)) = crate::auth_door::login::begun(out) else {
        return "malformed".to_string();
    };
    let fields: Vec<String> = form
        .fields
        .iter()
        .map(|f| {
            let kind = match f.kind {
                FieldKind::Password => "password",
                FieldKind::Text => "text",
            };
            if f.required {
                format!("{}:{kind}:required", f.name)
            } else {
                format!("{}:{kind}", f.name)
            }
        })
        .collect();
    format!("[{}]", fields.join(","))
}

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

    if c.outcome != busbar_contract::abi::mechanism::call::Outcome::Ready {
        return format!("{} UNREAD", called(&c));
    }
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

struct LoginLend {
    words: [Vec<u8>; 5],
    _submitted: Vec<(String, Vec<u8>)>,
    named: Vec<NamedValue>,
    bytes: Vec<u8>,
    groups: Vec<Span>,
}

// SAFETY: the raw pointers in `named` point into `_submitted`, owned by the same `LoginLend`;
// nothing mutates it once its frame is built but the plugin's writes into `bytes` and `groups`,
// which the host reads only after the op completes.
unsafe impl Send for LoginLend {}
// SAFETY: as above.
unsafe impl Sync for LoginLend {}

fn complete_submitted(p: &Plugin<Auth>, d: &Dispatcher, complete: &serde_json::Value) -> String {
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
    let mut lend = Box::new(LoginLend {
        words: [
            word(complete, "code"),
            word(complete, "state"),
            word(complete, "nonce"),
            word(complete, "redirect_uri"),
            word(complete, "code_verifier"),
        ],
        _submitted: submitted,
        named,
        bytes: vec![0_u8; auth::IDENTITY_BUF_BYTES],
        groups: vec![Span { offset: 0, len: 0 }; auth::IDENTITY_GROUPS as usize],
    });
    let [code, state, nonce, redirect, verifier] = &lend.words;
    let mut f: Frame<CompleteLoginIn, IdentifyOut> = Frame::new(input(), output());
    f.input.code = secret_or_absent(complete, "code", code);
    f.input.state = AbiStr::over(state);
    f.input.nonce = AbiStr::over(nonce);
    f.input.redirect_uri = AbiStr::over(redirect);
    f.input.code_verifier = secret_or_absent(complete, "code_verifier", verifier);
    if !lend.named.is_empty() {
        f.input.submitted = lend.named.as_ptr();
        f.input.submitted_len = lend.named.len();
    }
    f.input.out_buf = IdentityBuf {
        buf: lend.bytes.as_mut_ptr(),
        buf_cap: lend.bytes.len(),
        groups: lend.groups.as_mut_ptr(),
        groups_cap: lend.groups.len() as u32,
        _reserved: 0,
    };
    let lend: Arc<LoginLend> = Arc::from(lend);
    let deadline = now_ns().saturating_add(SUBMIT_WAIT.as_nanos() as u64);
    let (c, f) = super::on_ticket_frame(
        p,
        d,
        slot::COMPLETE_LOGIN,
        f,
        DeadlineClass::Call,
        deadline,
        Arc::clone(&lend) as Lent,
    );
    let verdict = match &f {
        Some(f) if c.outcome == Outcome::Ready => match f.out.verdict {
            LOGIN_IDENTITY => {
                let s = f.out.identity.subject;
                let subject = if s.offset == SPAN_ABSENT {
                    "<absent>".to_string()
                } else {
                    let at = s.offset as usize;
                    lend.bytes.get(at..at + s.len as usize).map_or_else(
                        || "<OUTSIDE>".to_string(),
                        |b| String::from_utf8_lossy(b).into_owned(),
                    )
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
    format!("{:?} lease={} {verdict}", c.outcome, c.lease != 0)
}

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

    let reads = st.reads_credentials();
    let hosts = reads.then(|| {
        let held = held_credentials(k, "host_credentials");
        let rotated = held_credentials(k, "rotated_host_credentials");
        for (kind, id, secret, _) in &rotated {
            assert!(
                held.iter()
                    .any(|(k, i, s, _)| k == kind && i == id && s != secret),
                "conformance.json: auth.rotated_host_credentials holds the ids of \
                 host_credentials under other secrets; {kind}:{id} is not one"
            );
        }
        (CredentialHost::new(held), CredentialHost::new(rotated))
    });
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
    let at_body = st.at_head_body();
    let mut cases: Vec<Presented> = specs.iter().map(|c| Presented::new(c, at_body)).collect();
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

    let d = match &hosts {
        Some((host, _)) => served_by(host),
        None => dispatcher_serving(CredentialHost::new(Vec::new())),
    };
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
            r.line(&format!("verify #{i} submitted"), 1, || match &hosts {
                Some((host, _)) => {
                    let before = host.reads();
                    let answer = verify_submitted(&p, &d, c);
                    format!("{answer} host_reads={}", host.reads() - before)
                }
                None => verify_submitted(&p, &d, c),
            });
        }
        if let Some(at) = identity_at {
            let storage = ShortReply::of(k);
            r.line("verify short, re-called", storage.crossings(), || {
                if reads {
                    verify_short_submitted(&p, &d, &cases[at], storage)
                } else {
                    verify_short(&p, &mut cases[at], storage)
                }
            });
        }
    } else {
        r.line("verify undeclared", 1, || {
            undeclared::<VerifyIn, IdentifyOut>(&p, slot::VERIFY)
        });
    }
    if login {
        let crossings = |key: &str, default| match lg.get(key) {
            None => default,
            Some(v) => v
                .as_u64()
                .expect("conformance.json: login crossings must be a u64"),
        };
        let begun = crossings("begin_crossings", 2);
        r.line("begin_login", begun, || begin_login(&p, &lg["begin"]));
        let pinned = crossings("complete_crossings", 1);
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

    r.line("refresh", 1, || called(&refresh(&p, &settings)));
    if let Some(at) = identity_at {
        r.line("verify after refresh", 1, || {
            if reads {
                verify_submitted(&p, &d, &cases[at])
            } else {
                verify_now(&p, &mut cases[at])
            }
        });
    }
    r.line("close", 1, || called(&close(&p)));
    if let Some(at) = identity_at {
        r.line("verify after close", 0, || verify_now(&p, &mut cases[at]));
    }

    if inbound {
        let rotated = if reads && k.get("rotated_settings").is_none_or(|v| v.is_null()) {
            settings.to_vec()
        } else {
            text(&k["rotated_settings"])
        };
        let dq = match &hosts {
            Some((_, rotated_host)) => served_by(rotated_host),
            None => d.clone(),
        };
        let q =
            load::<Auth>(s, leg, bind_far(&dq, "auth-rotated", s)).expect("the auth door loads");
        let mut rq = Recorder::new(crossings(&q));
        rq.line("open rotated", 1, || called(&open(&q, &rotated)));
        ready_step(&mut rq, s, &q, &dq);
        for (i, c) in cases.iter_mut().enumerate() {
            if expected[i].contains("Identity(") {
                rq.line(&format!("verify #{i} rotated"), 1, || {
                    if reads {
                        verify_submitted(&q, &dq, c)
                    } else {
                        verify_now(&q, c)
                    }
                });
            }
        }
        rq.line("close rotated", 1, || called(&close(&q)));
        r.absorb(rq);
    }

    let fold = r.fold();
    contract(&fold, &expected, identity_at, &never_echoed(k), reads);
    if login {
        login_contract(&fold, lg, st.login_kind);
    }
    fold
}

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
    match k.get("never_echoed") {
        None => Vec::new(),
        Some(v) => v
            .as_array()
            .expect("conformance.json: never_echoed must be an array")
            .iter()
            .map(|v| {
                v.as_str()
                    .expect("conformance.json: never_echoed entries must be strings")
                    .to_string()
            })
            .collect(),
    }
}

fn contract(
    fold: &Fold,
    expected: &[String],
    identity_at: Option<usize>,
    never: &[String],
    reads: bool,
) {
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
        let sub = at(&format!("verify #{i} submitted"));
        if reads {
            let (sub, host_reads) = sub
                .rsplit_once(" host_reads=")
                .unwrap_or_else(|| panic!("verify #{i} submitted names no host_reads: {sub}"));
            assert!(
                verdict_ok(sub, want),
                "verify #{i} submitted: {sub} (want {want})"
            );
            if now.starts_with("Refused ") {
                assert_ne!(
                    host_reads, "0",
                    "verify #{i}: REFUSED on the spot, yet its submitted twin read nothing: {now}"
                );
            } else {
                assert_eq!(
                    sub, now,
                    "verify #{i}: submitted and on the spot answer alike"
                );
            }
        } else {
            assert!(verdict_ok(now, want), "verify #{i}: {now} (want {want})");
            assert_eq!(
                sub, now,
                "verify #{i}: submitted and on the spot answer alike"
            );
        }
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

#[cfg(all(test, loader_self_tests))]
#[path = "../../tests/conformance_auth_form_tests.rs"]
mod form_tests;

#[cfg(all(test, loader_self_tests))]
#[path = "../../tests/conformance_auth_unjudged_tests.rs"]
mod unjudged_tests;

#[cfg(all(test, loader_self_tests))]
#[path = "../../tests/conformance_auth_short_tests.rs"]
mod short_tests;
