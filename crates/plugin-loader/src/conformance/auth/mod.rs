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
//! READY, never leased; an identity names its subject in the host's buffer.
//!
//! Every step is one ticket-less crossing of the auth table (or one ticketed crossing, for the
//! submitted `verify`), but: `verify` on an UNOPENED instance and after `close` (the host refuses
//! an op on an instance that is not open before any crossing: 0); the short-buffer `verify` (the
//! ONE re-call is +1: 2); and `ready` ([`super::ready_step`]).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::auth::{
    self, slot, AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, LoginField, NamedValue, OpenOutboundIn, OpenOutboundOut,
    OutboundReadyIn, OutboundReadyOut, StripName, VerifyIn, BEGIN_AUTHORIZE, BEGIN_FORM,
    FORM_PASSWORD, FORM_TEXT, LOGIN_BAD_CREDENTIAL, LOGIN_IDENTITY, LOGIN_KIND_CREDENTIAL,
    LOGIN_OUTAGE, LOGIN_SECURITY_CHECK_FAILED, POINT_HEAD_BODY, SPAN_ABSENT, VERDICT_IDENTITY,
    VERDICT_PASS, VERDICT_REJECT,
};
use busbar_contract::abi::host::service::{ItemSpan, SECRET_LIVE, SECRET_NOT_LIVE};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, Span, BLOB_ABSENT, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_CARRIER};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, Ran, Reading, RecordsList, Snapshot,
    Stored, UNSERVED,
};

mod outbound;

pub use outbound::{
    red_outbound_double_fetch, red_outbound_writes_nothing, red_outbound_wrong_byte,
};

use super::{
    bind_far, called, close, crossings, dispatcher, input, load, open, output, ready_step, refresh,
    release, tick, validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::auth::Auth;
use crate::dispatch::{now_ns, DispatchConfig, Dispatcher, Done, Frame, Plugin};

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
    /// The points `verify` is called at (`AuthTail::inbound_points`).
    points: u32,
    carriers: Vec<String>,
    /// The outbound styles the tail declares: name, flags, points.
    styles: Vec<(String, u32, u32)>,
}

impl Stated {
    /// The tail states `FACT_READS_CREDENTIALS`: `verify` reads its secret from the host.
    fn reads_credentials(&self) -> bool {
        self.facts & auth::FACT_READS_CREDENTIALS != 0
    }

    /// The tail's points hold `HeadBody`: each case is presented there, with its body.
    fn at_head_body(&self) -> bool {
        self.points & POINT_HEAD_BODY != 0
    }
}

/// `s`'s door's auth tail and carrier word marks.
///
/// # Panics
/// When the door states no auth tail.
fn stated(s: &Subject) -> Stated {
    let door = crate::dispatch::load::enter_door(s.door);
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
            points: tail.inbound_points,
            carriers,
            styles,
        }
    }
}

/// One case, as the host presents it: the candidate credential, the field lines, the request facts
/// and (at `HeadBody`) the body, owned for as long as a `verify` over them may run, with the
/// host's identity buffer.
struct Presented {
    credential: Option<Vec<u8>>,
    names: Vec<String>,
    _values: Vec<Vec<u8>>,
    carriers: Vec<NamedValue>,
    bytes: Vec<u8>,
    groups: Vec<Span>,
    /// The host's strip array (the credential lines the plugin names, whatever its verdict).
    strips: Vec<StripName>,
    /// Presented at `HeadBody` (else at `Head`).
    at_body: bool,
    method: Vec<u8>,
    path: Vec<u8>,
    query: Option<Vec<u8>>,
    timestamp: u64,
    /// The body lent at `HeadBody`; none = absent.
    body: Option<Vec<u8>>,
}

/// A case's optional text input `key`, as bytes.
fn case_text(case: &serde_json::Value, key: &str) -> Option<Vec<u8>> {
    match case.get(key) {
        None | Some(serde_json::Value::Null) => None,
        Some(v) => Some(text(v)),
    }
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
    fn new(case: &serde_json::Value, at_body: bool) -> Self {
        let credential = match &case["credential"] {
            serde_json::Value::Null => None,
            v => Some(text(v)),
        };
        assert!(
            case.get("lines").is_none() || case.get("carriers").is_none(),
            "conformance.json: an auth case names its field lines once, as `carriers` or `lines`"
        );
        let lines = case
            .get("lines")
            .unwrap_or(&case["carriers"])
            .as_object()
            .cloned()
            .unwrap_or_default();
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

/// `frame` submitted as `verify` on `ticket`, awaited.
fn submit_verify(
    p: &Plugin<Auth>,
    d: &Dispatcher,
    ticket: Ticket,
    frame: Frame<VerifyIn, IdentifyOut>,
) -> Option<Done<VerifyIn, IdentifyOut>> {
    let deadline = now_ns().saturating_add(SUBMIT_WAIT.as_nanos() as u64);
    let reply = d.submit(
        p,
        ticket,
        slot::VERIFY,
        frame,
        DeadlineClass::Call,
        deadline,
    );
    let done = reply.wait(SUBMIT_WAIT);
    drop(reply);
    done
}

/// A submitted `verify`'s answer as the transcript spells it.
fn submitted_answer(case: &Presented, done: Option<&Done<VerifyIn, IdentifyOut>>) -> String {
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

/// `verify` SUBMITTED on a ticket, awaited, the ticket recycled.
fn verify_submitted(p: &Plugin<Auth>, d: &Dispatcher, case: &mut Presented) -> String {
    let ticket = d.mint(0).expect("a ticket is free");
    let done = submit_verify(p, d, ticket, case.frame(true));
    d.recycle(ticket);
    submitted_answer(case, done.as_ref())
}

/// [`verify_short`] SUBMITTED, for a door that reads host credentials (its ticket-less `verify`
/// may not read them): the short answer, then the ONE re-call on the SAME ticket with the buffers
/// it named.
fn verify_short_submitted(p: &Plugin<Auth>, d: &Dispatcher, case: &mut Presented) -> String {
    let ticket = d.mint(0).expect("a ticket is free");
    let first = submit_verify(p, d, ticket, case.frame(false));
    let short = first.as_ref().is_some_and(|f| f.short);
    let answer = match first {
        Some(Done {
            frame: Some(mut f),
            short: true,
            ..
        }) => {
            f.input.out_buf = case.buf(true);
            let again = submit_verify(p, d, ticket, *f);
            submitted_answer(case, again.as_ref())
        }
        other => submitted_answer(case, other.as_ref()),
    };
    d.recycle(ticket);
    format!("short={short} {answer}")
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

/// The secret `records.secret` answers, not live, for an id the host does not hold: busbar's root
/// answers the kernel's `auth::DUMMY_SECRET`, these bytes.
const DUMMY_SECRET: &str = "AWS4-DUMMY-SECRET-FOR-CONSTANT-TIME-REJECT-PATH";

/// One host-held credential: kind, id, secret, live.
type HeldCredential = (String, String, String, bool);

/// `k[section]`, the host-held credentials (`[{"kind","id","secret","live"}]`).
///
/// # Panics
/// When it is missing, empty or malformed.
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

/// THE HOST a credential-reading door's leg is served by: `records.secret` over its credentials
/// (and the dummy, not live, for any other id), answered at once and counted; every other service
/// unserved; the wall clock.
struct CredentialHost {
    held: Vec<HeldCredential>,
    reads: AtomicU64,
}

impl CredentialHost {
    fn new(held: Vec<HeldCredential>) -> Arc<Self> {
        Arc::new(Self {
            held,
            reads: AtomicU64::new(0),
        })
    }

    /// The `records.secret` reads served so far.
    fn reads(&self) -> u64 {
        self.reads.load(Ordering::SeqCst)
    }
}

fn unserved() -> Ran {
    Ran::Now(Stored::refused(UNSERVED))
}

impl HostServices for CredentialHost {
    fn now(&self) -> Reading {
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
    fn work_settle(&self, _: &Caller, _: u64, _: &[u8], _: Later) -> Ran {
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
        self.reads.fetch_add(1, Ordering::SeqCst);
        let (secret, live) = self
            .held
            .iter()
            .find(|(k, i, _, _)| k == kind && i == id)
            .map_or((DUMMY_SECRET, false), |(_, _, s, live)| (s.as_str(), *live));
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

/// A dispatcher serving `host`'s services.
fn served_by(host: &Arc<CredentialHost>) -> Arc<Dispatcher> {
    Arc::new(Dispatcher::with_services(
        DispatchConfig::default(),
        host.clone(),
    ))
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
    // A door reading host credentials is served by a host holding them, and rotates through the
    // host: a second host serves other secrets for the same ids.
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
        None => dispatcher(),
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
            r.line(&format!("verify #{i} submitted"), 1, || match &hosts {
                // The host reads the call made, so a REFUSED on the spot is told from a read it
                // needed.
                Some((host, _)) => {
                    let before = host.reads();
                    let answer = verify_submitted(&p, &d, c);
                    format!("{answer} host_reads={}", host.reads() - before)
                }
                None => verify_submitted(&p, &d, c),
            });
        }
        if let Some(at) = identity_at {
            // 2: the short answer, then the ONE re-call with the buffers it named.
            r.line("verify short, re-called", 2, || {
                if reads {
                    verify_short_submitted(&p, &d, &mut cases[at])
                } else {
                    verify_short(&p, &mut cases[at])
                }
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
        r.line("verify after refresh", 1, || {
            if reads {
                verify_submitted(&p, &d, &mut cases[at])
            } else {
                verify_now(&p, &mut cases[at])
            }
        });
    }
    r.line("close", 1, || called(&close(&p)));
    if let Some(at) = identity_at {
        // 0: a closed instance answers FAULT without a crossing.
        r.line("verify after close", 0, || verify_now(&p, &mut cases[at]));
    }

    if inbound {
        // THE ROTATED CREDENTIAL, on an instance of its own (opened and made ready as the host
        // opens every instance): no identity case identifies there. A door reading host
        // credentials rotates through the host: a dispatcher of its own serves the rotated ones,
        // and its instance opens over `rotated_settings` when named, else over its own settings.
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
/// For a door that `reads` host credentials, an on-the-spot answer may instead be REFUSED when
/// its submitted twin read the host, and the submitted one carries the case's verdict.
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
                // The ABI requires a ticket for a service that may pend: only a case that needs
                // the host's read may be refused on the spot.
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
