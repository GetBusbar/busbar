// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE AUTH KIND'S SCRIPT (`abi/auth/`, v3). Ported from the auth both-ways proofs (#439's
//! `auth_door_conformance_tests`, the predev `auth_verify_conformance_tests`, and the token cases of
//! `busbar-auth-admin-tokens`' own conformance test), over the one loader and the one dispatcher.
//!
//! The script drives the INBOUND family, `verify`, the way the host's identity chain calls it
//! (`busbar_contract::auth_calls::AuthCalls`): ON THE SPOT (ticket-less, on the caller's thread),
//! and SUBMITTED on a ticket; a short answer is re-called ONCE with the buffers it named. Every
//! case is presented as the host presents a request: the kernel's extracted candidate credential
//! (`VerifyIn::credential`, a secret blob) and the carrier lines (`VerifyIn::carrier`), each a
//! carrier the Statement states (its `MARK_WORD_CARRIER` word marks), unless the tail states
//! `FACT_INBOUND_ALL_HEADERS`. The op families the tail does NOT declare (`CAP_LOGIN`,
//! `CAP_OUTBOUND`) are each called once and must answer REFUSED. A tail declaring the login or the
//! outbound family is not driven by this script yet and FAILS the suite, never passes it unseen.
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
//!     "never_echoed": ["<text no answer may carry: the token, the raw settings>", ...] } }
//! ```
//!
//! The cases must reach every verdict (an identity, a reject, a pass), so the two legs' equality
//! covers all three. The verdict semantics are the kind's (`abi/auth/mod.rs`): VERDICTS ARE ALWAYS
//! READY, never leased; an identity names its subject in the host's buffer.
//!
//! Every step is one ticket-less crossing of the auth table (or one ticketed crossing, for the
//! submitted `verify`), but: `verify` on an UNOPENED instance and after `close` (the host refuses
//! an op on an instance that is not open before any crossing: 0); the short-buffer `verify` (the
//! ONE re-call is +1: 2); and `ready` ([`super::ready_step`]).

use std::time::Duration;

use busbar_contract::abi::auth::{
    self, slot, AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut,
    IdentifyOut, IdentityBuf, NamedValue, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn,
    OutboundReadyOut, StripName, VerifyIn, SPAN_ABSENT, VERDICT_IDENTITY, VERDICT_PASS,
    VERDICT_REJECT,
};
use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, Outcome, Span, BLOB_OCTETS, BLOB_SECRET,
};
use busbar_contract::abi::mechanism::door::{MarkWord, Statement, MARK_WORD_CARRIER};

use super::{
    bind, called, close, crossings, dispatcher, input, load, open, output, ready_step, refresh,
    tick, validate, Fold, Leg, Recorder, Subject,
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
        Stated {
            caps: tail.caps,
            facts: tail.facts,
            login_kind: tail.login_kind,
            carriers,
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

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("auth");
    assert!(k.is_object(), "conformance.json has no `auth` inputs");
    let st = stated(s);
    assert!(
        st.caps & auth::CAP_INBOUND != 0,
        "the auth script drives the inbound family (`verify`); this door states caps={}",
        st.caps
    );
    assert!(
        st.caps & (auth::CAP_LOGIN | auth::CAP_OUTBOUND) == 0,
        "the auth script does not drive the login or the outbound family yet (caps={}): this \
         suite fails rather than pass a family it did not run",
        st.caps
    );
    let settings = s.settings();
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
    let rotated = text(&k["rotated_settings"]);
    let specs = k["cases"]
        .as_array()
        .expect("conformance.json: auth.cases must be an array");
    let expected: Vec<String> = specs.iter().map(expected_verdict).collect();
    for want in ["Identity(", "Reject", "Pass"] {
        assert!(
            expected.iter().any(|v| v.contains(want)),
            "conformance.json: auth.cases must reach a {want} verdict"
        );
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
    let identity_at = expected
        .iter()
        .position(|v| v.contains("Identity("))
        .expect("an identity case");

    let d = dispatcher();
    let p = load::<Auth>(s, leg, bind(&d, "auth")).expect("the auth door loads");
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
    // 0: the host refuses a kind op on an instance that is not open, before any crossing.
    r.line("verify unopened", 0, || {
        verify_now(&p, &mut cases[identity_at])
    });
    for (i, b) in bad.iter().enumerate() {
        r.line(&format!("open bad #{i}"), 1, || called(&open(&p, b)));
    }
    r.line("open", 1, || called(&open(&p, &settings)));
    ready_step(&mut r, s, &p, &d);
    for (i, c) in cases.iter_mut().enumerate() {
        r.line(&format!("verify #{i}"), 1, || verify_now(&p, c));
    }
    for (i, c) in cases.iter_mut().enumerate() {
        r.line(&format!("verify #{i} submitted"), 1, || {
            verify_submitted(&p, &d, c)
        });
    }
    // 2: the short answer, then the ONE re-call with the buffers it named.
    r.line("verify short, re-called", 2, || {
        verify_short(&p, &mut cases[identity_at])
    });
    r.line("begin_login undeclared", 1, || {
        undeclared::<BeginLoginIn, BeginLoginOut>(&p, slot::BEGIN_LOGIN)
    });
    r.line("complete_login undeclared", 1, || {
        undeclared::<CompleteLoginIn, IdentifyOut>(&p, slot::COMPLETE_LOGIN)
    });
    r.line("open_outbound undeclared", 1, || {
        undeclared::<OpenOutboundIn, OpenOutboundOut>(&p, slot::OPEN_OUTBOUND)
    });
    r.line("outbound_ready undeclared", 1, || {
        undeclared::<OutboundReadyIn, OutboundReadyOut>(&p, slot::OUTBOUND_READY)
    });
    r.line("fields undeclared", 1, || {
        undeclared::<FieldsIn, FieldsOut>(&p, slot::FIELDS)
    });
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        format!("{} next={next}", called(&c))
    });
    // The admin cache flush: `refresh` with a new generation and unchanged settings.
    r.line("refresh", 1, || called(&refresh(&p, &settings)));
    r.line("verify after refresh", 1, || {
        verify_now(&p, &mut cases[identity_at])
    });
    r.line("close", 1, || called(&close(&p)));
    // 0: a closed instance answers FAULT without a crossing.
    r.line("verify after close", 0, || {
        verify_now(&p, &mut cases[identity_at])
    });

    // THE ROTATED CREDENTIAL, on an instance of its own: no identity case identifies there.
    let q = load::<Auth>(s, leg, bind(&d, "auth-rotated")).expect("the auth door loads");
    let mut rq = Recorder::new(crossings(&q));
    rq.line("open rotated", 1, || called(&open(&q, &rotated)));
    for (i, c) in cases.iter_mut().enumerate() {
        if expected[i].contains("Identity(") {
            rq.line(&format!("verify #{i} rotated"), 1, || verify_now(&q, c));
        }
    }
    rq.line("close rotated", 1, || called(&close(&q)));
    r.absorb(rq);

    let fold = r.fold();
    contract(&fold, &expected, identity_at, &never_echoed(k));
    fold
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
fn contract(fold: &Fold, expected: &[String], identity_at: usize, never: &[String]) {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .unwrap_or_else(|| panic!("the script ran no step '{label}'"))
    };
    for label in [
        "validate",
        "open",
        "refresh",
        "close",
        "open rotated",
        "close rotated",
    ] {
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
