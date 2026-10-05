// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S SCRIPT. Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings the gate opens over>,
//!   "hook": {
//!     "bad_settings": ["<settings it must refuse: validate, open and refresh FAIL>", ...],
//!     "order_cap": <the order slots the host's FIRST `decide` buffer holds>,
//!     "requests": [<request>, ...],
//!     "refresh": { "settings": <what it refreshes to>, "request": <request> } } }
//! ```
//!
//! A `<request>` is one `decide` or `transform` over the host's view, and what it must answer:
//!
//! ```json
//! { "label": "<step label>", "op": "decide" | "transform",
//!   "candidates": [{ "idx": 3, "model": "m", "provider": "p", "weight": 1,
//!                    "cost_per_mtok": 5.0, "latency_ms": 200.0, "available_concurrency": 2,
//!                    "budget_remaining": 10, "rate_headroom": 0.2 }, ...],
//!   "expect": { "verb": "prefer", "order": [9, 3, 7] }
//!           | { "verb": "abstain" }
//!           | { "verb": "reject", "status": 429, "message": "..." }
//!           | { "verb": "restrict", "tags": "..." }
//!           | { "verb": "rewrite", "rewrite": "..." } }
//! ```
//!
//! Every candidate member but `idx` may be left out (a signal the host does not have).
//!
//! THE KIND'S CONTRACT the script holds the answers to: a READY `decide`/`transform` names exactly
//! the verb its request expects, with exactly the order, status, message, tags or rewrite expected;
//! an answer too big for the host's first buffer is FAILED naming what it needs, and the host makes
//! THE ONE RE-CALL with bigger buffers, which answers READY; a re-call that answers short again is
//! FAULT; a re-call token spent on another op is REFUSED without a crossing. At least one `decide`
//! must expect an order longer than `order_cap`, so the set walks the re-call.
//!
//! Every step is one ticket-less crossing of the hook table, but: a request whose expected answer
//! overflows the host's first buffer is 2 (the ONE short-buffer re-call is +1); `decide` before
//! `open` and after `close` is 0 (the dispatcher refuses an unopened instance, and a closed one
//! answers FAULT, without a crossing); the token-on-another-op step is 1 (its short `decide`; the
//! misdirected re-call does not cross); and `ready` ([`super::ready_step`]).
//!
//! THE RED ARM, in the script: the honest fold with every PREFER order reversed (a door that ranks
//! the other way) must be refused by the same contract.
//!
//! No `timeout` step: the dispatcher's ticket-less `decide` budget is the watchdog's, and a step
//! needs a plugin-controlled slow answer, which the script's inputs do not name.

use busbar_contract::abi::hook::{
    slot, CandidateDynamic, CandidateStatic, DecideIn, DecideOut, TransformOut,
    CANDIDATE_HAS_BUDGET_REMAINING, CANDIDATE_HAS_COST_PER_MTOK, CANDIDATE_HAS_LATENCY_MS,
    CANDIDATE_HAS_RATE_HEADROOM, VERB_ABSTAIN, VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT,
    VERB_RESTRICT, VERB_REWRITE,
};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::sdk::door::abi_str;
use serde_json::Value;

use super::{
    called, close, crossings, dispatcher, input, load, open, output, ready_step, refresh, tick,
    validate, Fold, Leg, Recorder, Subject,
};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{Called, Frame, Plugin, Recall};

/// The host's first reject-message buffer, in bytes.
const MESSAGE_CAP: usize = 4096;
/// The host's first restrict-tags buffer, in bytes.
const TAGS_CAP: usize = 4096;
/// The host's first rewrite buffer, in bytes.
const REWRITE_CAP: usize = 64 * 1024;

/// The pool and dialect every request names.
const POOL: &str = "conformance";

fn text(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => s.as_bytes().to_vec(),
        Value::Null => panic!("conformance.json: a hook input is missing"),
        other => other.to_string().into_bytes(),
    }
}

/// One request of the set: the host's view, the op, and the line its answer must read.
struct Request {
    label: String,
    op: u32,
    /// The candidates' model and provider names, which `statics` point into.
    _names: Vec<String>,
    statics: Vec<CandidateStatic>,
    dynamics: Vec<CandidateDynamic>,
    /// The verdict the request must answer ([`verdict`]'s form).
    expect: String,
    /// Whether the expected answer overflows the host's first buffer (the ONE re-call).
    short: bool,
}

fn str_of(s: &str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

impl Request {
    fn of(v: &Value, order_cap: usize) -> Self {
        let label = v["label"]
            .as_str()
            .expect("conformance.json: a hook request has no `label`")
            .to_string();
        let op = match v["op"].as_str() {
            Some("decide") => slot::DECIDE,
            Some("transform") => slot::TRANSFORM,
            other => panic!("conformance.json: request '{label}': op {other:?}"),
        };
        let cands = v["candidates"]
            .as_array()
            .unwrap_or_else(|| panic!("conformance.json: request '{label}' has no `candidates`"));
        let names: Vec<String> = cands
            .iter()
            .flat_map(|c| {
                [
                    c["model"].as_str().unwrap_or("model").to_string(),
                    c["provider"].as_str().unwrap_or("provider").to_string(),
                ]
            })
            .collect();
        let mut statics = Vec::with_capacity(cands.len());
        let mut dynamics = Vec::with_capacity(cands.len());
        for (i, c) in cands.iter().enumerate() {
            let f = |k: &str| c[k].as_f64();
            let mut present = 0;
            let cost = f("cost_per_mtok").inspect(|_| present |= CANDIDATE_HAS_COST_PER_MTOK);
            statics.push(CandidateStatic {
                idx: c["idx"]
                    .as_u64()
                    .and_then(|x| u32::try_from(x).ok())
                    .unwrap_or_else(|| {
                        panic!("conformance.json: request '{label}': a candidate's idx")
                    }),
                _reserved: 0,
                model: str_of(&names[2 * i]),
                provider: str_of(&names[2 * i + 1]),
                weight: c["weight"]
                    .as_u64()
                    .and_then(|x| u32::try_from(x).ok())
                    .unwrap_or(1),
                _reserved3: 0,
                context_max: 0,
                tier: AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                },
                cost_per_mtok: cost.unwrap_or(0.0),
                tags: std::ptr::null(),
                tags_len: 0,
                present,
                _reserved2: 0,
            });
            let mut present = 0;
            let latency = f("latency_ms").inspect(|_| present |= CANDIDATE_HAS_LATENCY_MS);
            let budget = c["budget_remaining"]
                .as_i64()
                .inspect(|_| present |= CANDIDATE_HAS_BUDGET_REMAINING);
            let rate = f("rate_headroom").inspect(|_| present |= CANDIDATE_HAS_RATE_HEADROOM);
            dynamics.push(CandidateDynamic {
                latency_ms: latency.unwrap_or(0.0),
                // Absent is no concurrency; present and not a u64 is a broken script, refused.
                available_concurrency: c.get("available_concurrency").map_or(0, |n| {
                    n.as_u64().unwrap_or_else(|| {
                        panic!("conformance.json: request '{label}': available_concurrency {n}")
                    })
                }),
                budget_remaining: budget.unwrap_or(0),
                rate_headroom: rate.unwrap_or(0.0),
                signals: std::ptr::null(),
                signals_len: 0,
                present,
                _reserved: 0,
            });
        }
        let (expect, short) = expected(&label, op, &v["expect"], order_cap);
        Self {
            label,
            op,
            _names: names,
            statics,
            dynamics,
            expect,
            short,
        }
    }

    /// The step's pinned crossings: one, and the ONE re-call when the answer overflows.
    fn pinned(&self) -> u64 {
        1 + u64::from(self.short)
    }

    /// The line an honest answer reads.
    fn line(&self) -> String {
        format!(
            "Ready lease=false | {} recalled={}",
            self.expect, self.short
        )
    }
}

/// The expected verdict, in [`verdict`]'s form, and whether it overflows the first buffers.
fn expected(label: &str, op: u32, e: &Value, order_cap: usize) -> (String, bool) {
    let s = |k: &str| e[k].as_str().unwrap_or("").to_string();
    match (op, e["verb"].as_str()) {
        (slot::DECIDE, Some("prefer")) => {
            let order: Vec<u32> = e["order"]
                .as_array()
                .unwrap_or_else(|| panic!("conformance.json: request '{label}': expect.order"))
                .iter()
                .map(|x| {
                    x.as_u64()
                        .and_then(|x| u32::try_from(x).ok())
                        .expect("an order index")
                })
                .collect();
            let short = order.len() > order_cap;
            (format!("verb=prefer order={order:?}"), short)
        }
        (slot::DECIDE, Some("restrict")) => {
            let tags = s("tags");
            let short = tags.len() > TAGS_CAP;
            (format!("verb=restrict tags={tags:?}"), short)
        }
        (slot::TRANSFORM, Some("rewrite")) => {
            let rewrite = s("rewrite");
            let short = rewrite.len() > REWRITE_CAP;
            (format!("verb=rewrite rewrite={rewrite:?}"), short)
        }
        (_, Some("abstain")) => ("verb=abstain".to_string(), false),
        (_, Some("reject")) => {
            let status = e["status"]
                .as_u64()
                .map_or_else(|| "none".to_string(), |n| n.to_string());
            let message = s("message");
            let short = message.len() > MESSAGE_CAP;
            (
                format!("verb=reject status={status} message={message:?}"),
                short,
            )
        }
        (_, other) => panic!("conformance.json: request '{label}': expect.verb {other:?}"),
    }
}

/// The host's buffers for one crossing.
struct Bufs {
    order: Vec<u32>,
    message: Vec<u8>,
    tags: Vec<u8>,
    rewrite: Vec<u8>,
}

impl Bufs {
    fn of(order: usize, message: usize, tags: usize, rewrite: usize) -> Self {
        Self {
            order: vec![0; order],
            message: vec![0; message],
            tags: vec![0; tags],
            rewrite: vec![0; rewrite],
        }
    }

    fn first(order_cap: usize) -> Self {
        Self::of(order_cap, MESSAGE_CAP, TAGS_CAP, REWRITE_CAP)
    }

    /// The `in` of `r` over these buffers.
    fn input(&mut self, r: &Request) -> DecideIn {
        let mut i: DecideIn = input();
        i.request.request_id = 1;
        i.request.pool = abi_str(POOL);
        i.request.ingress_dialect = abi_str(POOL);
        i.request.message_count = 1;
        i.candidates = r.statics.as_ptr();
        i.candidate_dynamics = r.dynamics.as_ptr();
        i.candidates_len = r.statics.len();
        i.order_buf = self.order.as_mut_ptr();
        i.order_cap = self.order.len();
        i.reject_message_buf = self.message.as_mut_ptr();
        i.reject_message_cap = self.message.len();
        i.restrict_tags_buf = self.tags.as_mut_ptr();
        i.restrict_tags_cap = self.tags.len();
        i.rewrite_buf = self.rewrite.as_mut_ptr();
        i.rewrite_cap = self.rewrite.len();
        i
    }
}

/// What one `decide`/`transform` said, copied out of the host's buffers.
#[derive(Default)]
struct Said {
    verbs: u32,
    status: u16,
    order: Vec<u32>,
    message: Vec<u8>,
    tags: Vec<u8>,
    rewrite: Vec<u8>,
    /// `(order, message, tags, rewrite)` needed, for the re-call's buffers.
    needed: [usize; 4],
}

fn head<T: Copy>(buf: &[T], n: usize) -> Vec<T> {
    buf[..n.min(buf.len())].to_vec()
}

/// One crossing of `r`'s op over `b`: a call, or THE re-call when `token` is given (spent on
/// `op`, which may be another op than the one that answered short).
fn cross(
    p: &Plugin<Hook>,
    op: u32,
    r: &Request,
    b: &mut Bufs,
    token: Option<Recall>,
) -> (Called, Said) {
    let i = b.input(r);
    if op == slot::DECIDE {
        let mut f: Frame<DecideIn, DecideOut> = Frame::new(i, output());
        let c = match token {
            Some(t) => p.recall(t, op, &mut f),
            None => p.call(op, &mut f),
        };
        let o = f.out;
        let said = Said {
            verbs: o.verbs,
            status: o.reject_status,
            order: head(&b.order, o.order_written),
            message: head(&b.message, o.reject_message_written),
            tags: head(&b.tags, o.restrict_tags_written),
            rewrite: Vec::new(),
            needed: [
                o.order_needed,
                o.reject_message_needed,
                o.restrict_tags_needed,
                0,
            ],
        };
        (c, said)
    } else {
        let mut f: Frame<DecideIn, TransformOut> = Frame::new(i, output());
        let c = match token {
            Some(t) => p.recall(t, op, &mut f),
            None => p.call(op, &mut f),
        };
        let o = f.out;
        let said = Said {
            verbs: o.verbs,
            status: o.reject_status,
            message: head(&b.message, o.reject_message_written),
            rewrite: head(&b.rewrite, o.rewrite_written),
            needed: [0, o.reject_message_needed, 0, o.rewrite_needed],
            ..Said::default()
        };
        (c, said)
    }
}

/// The verdict a READY answer of `op` names; `verb=none` for any other outcome.
fn verdict(op: u32, c: &Called, s: &Said) -> String {
    if c.outcome != Outcome::Ready {
        return "verb=none".to_string();
    }
    let lossy = |b: &[u8]| String::from_utf8_lossy(b).into_owned();
    let verb = s.verbs & !VERB_HAS_REJECT_STATUS;
    match (op, verb) {
        (slot::DECIDE, VERB_PREFER) => format!("verb=prefer order={:?}", s.order),
        (slot::DECIDE, VERB_RESTRICT) => format!("verb=restrict tags={:?}", lossy(&s.tags)),
        (slot::TRANSFORM, VERB_REWRITE) => {
            format!("verb=rewrite rewrite={:?}", lossy(&s.rewrite))
        }
        (_, VERB_ABSTAIN) => "verb=abstain".to_string(),
        (_, VERB_REJECT) => {
            let status = if s.verbs & VERB_HAS_REJECT_STATUS == 0 {
                "none".to_string()
            } else {
                s.status.to_string()
            };
            format!(
                "verb=reject status={status} message={:?}",
                lossy(&s.message)
            )
        }
        (_, v) => format!("verbs={v:#x}"),
    }
}

/// THE HOST'S WAY WITH ONE REQUEST: the call over the first buffers, and on a short answer THE
/// ONE re-call over buffers of the size it named. Its line: the outcome the host acts on, the
/// verdict, and whether it took the re-call.
fn ask(p: &Plugin<Hook>, r: &Request, order_cap: usize) -> String {
    let (mut c, said) = cross(p, r.op, r, &mut Bufs::first(order_cap), None);
    let (c, said, recalled) = match c.recall.take() {
        Some(token) => {
            let [order, message, tags, rewrite] = said.needed;
            let mut big = Bufs::of(
                order.max(order_cap),
                message.max(MESSAGE_CAP),
                tags.max(TAGS_CAP),
                rewrite.max(REWRITE_CAP),
            );
            let (c, said) = cross(p, r.op, r, &mut big, Some(token));
            (c, said, true)
        }
        None => (c, said, false),
    };
    format!(
        "{} | {} recalled={recalled}",
        called(&c).trim_end(),
        verdict(r.op, &c, &said)
    )
}

/// The first answer of `r`, short, then its token spent over `op` with the SAME short buffers.
fn recall_again(p: &Plugin<Hook>, r: &Request, op: u32, order_cap: usize) -> String {
    let mut b = Bufs::first(order_cap);
    let (mut first, _) = cross(p, r.op, r, &mut b, None);
    let Some(token) = first.recall.take() else {
        return format!("{} (no re-call token)", called(&first).trim_end());
    };
    let (again, _) = cross(p, op, r, &mut b, Some(token));
    format!(
        "{} then {}",
        called(&first).trim_end(),
        called(&again).trim_end()
    )
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("hook");
    assert!(k.is_object(), "conformance.json has no `hook` inputs");
    let settings = s.settings();
    let bad: Vec<Vec<u8>> = k["bad_settings"]
        .as_array()
        .expect("conformance.json: hook.bad_settings must be an array")
        .iter()
        .map(text)
        .collect();
    assert!(
        !bad.is_empty(),
        "conformance.json: hook.bad_settings is empty"
    );
    let order_cap = k["order_cap"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .expect("conformance.json: hook.order_cap must be a number");
    let requests: Vec<Request> = k["requests"]
        .as_array()
        .expect("conformance.json: hook.requests must be an array")
        .iter()
        .map(|r| Request::of(r, order_cap))
        .collect();
    assert!(
        !requests.is_empty(),
        "conformance.json: hook.requests is empty"
    );
    let short = requests
        .iter()
        .find(|r| r.op == slot::DECIDE && r.short)
        .expect(
        "conformance.json: no `decide` expects an order longer than hook.order_cap (the re-call)",
    );
    let refreshed = text(&k["refresh"]["settings"]);
    let after = Request::of(&k["refresh"]["request"], order_cap);

    let d = dispatcher();
    let p = load::<Hook>(s, leg, s.bind(&d, "hook")).expect("the hook door loads");
    let mut r = Recorder::new(crossings(&p));
    r.line("facts", 0, || {
        format!(
            "{:?} {} max_inflight={}",
            p.kind(),
            p.name(),
            p.max_inflight()
        )
    });
    for (i, b) in bad.iter().enumerate() {
        r.line(&format!("validate bad #{i}"), 1, || {
            called(&validate(&p, b))
        });
    }
    r.line("validate", 1, || called(&validate(&p, &settings)));
    r.line("decide unopened", 0, || ask(&p, &requests[0], order_cap));
    r.line("open bad", 1, || called(&open(&p, &bad[0])));
    r.line("open", 1, || called(&open(&p, &settings)));
    ready_step(&mut r, s, &p, &d);
    for q in &requests {
        r.line(&q.label, q.pinned(), || ask(&p, q, order_cap));
    }
    // The short answer re-called over the same short buffers: one crossing each, then FAULT.
    r.line("re-call short again", 2, || {
        recall_again(&p, short, short.op, order_cap)
    });
    // The token spent on another op: the short answer's crossing; the re-call is refused.
    r.line("re-call as another op", 1, || {
        recall_again(&p, short, slot::TRANSFORM, order_cap)
    });
    r.line("tick", 1, || {
        let (c, next) = tick(&p, 1);
        format!("{} next={next}", called(&c))
    });
    r.line("refresh bad", 1, || called(&refresh(&p, &bad[0])));
    r.line("refresh", 1, || called(&refresh(&p, &refreshed)));
    let after_label = format!("after refresh: {}", after.label);
    r.line(&after_label, after.pinned(), || ask(&p, &after, order_cap));
    r.line("close", 1, || called(&close(&p)));
    r.line("decide after close", 0, || ask(&p, &requests[0], order_cap));
    let fold = r.fold();

    let mut expect: Vec<(String, String)> = requests
        .iter()
        .map(|q| (q.label.clone(), q.line()))
        .collect();
    expect.push((after_label, after.line()));
    contract(&fold, &expect).unwrap_or_else(|e| panic!("{leg:?}: the hook contract: {e}"));
    // THE RED ARM: a door that ranks the other way answers otherwise, and is refused.
    let reversed = reversed(&fold);
    if reversed != fold {
        assert!(
            contract(&reversed, &expect).is_err(),
            "{leg:?}: a fold with every order reversed passed the hook contract"
        );
    }
    fold
}

/// `fold` with every PREFER order reversed: what a door that ranks the other way answers.
fn reversed(fold: &Fold) -> Fold {
    fold.iter()
        .cloned()
        .map(|mut st| {
            if let Some((before, rest)) = st.answer.split_once("order=[") {
                if let Some((list, after)) = rest.split_once(']') {
                    let mut items: Vec<&str> = list.split(", ").collect();
                    items.reverse();
                    st.answer = format!("{before}order=[{}]{after}", items.join(", "));
                }
            }
            st
        })
        .collect()
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: the lifecycle
/// answers READY where it must and FAILED with its reason where it must; every request answers
/// exactly its expected line (verb, order, status, message, the re-call taken or not); a re-call
/// that is short again is FAULT and a token spent on another op REFUSED; an unopened or closed
/// instance serves nothing.
fn contract(fold: &Fold, expect: &[(String, String)]) -> Result<(), String> {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .ok_or_else(|| format!("the script ran no step '{label}'"))
    };
    let need = |ok: bool, label: &str, line: &str| {
        if ok {
            Ok(())
        } else {
            Err(format!("{label}: {line}"))
        }
    };
    for label in ["validate", "open", "tick", "refresh", "close"] {
        let line = at(label)?;
        need(line.starts_with("Ready "), label, line)?;
    }
    for (label, want) in expect {
        let line = at(label)?;
        need(line == want, label, &format!("{line} (want: {want})"))?;
    }
    let refused = at("validate bad #0")?;
    need(
        refused.starts_with("Failed lease=false ") && refused.len() > "Failed lease=false ".len(),
        "a refused validate names why",
        refused,
    )?;
    for label in ["open bad", "refresh bad"] {
        let line = at(label)?;
        need(line.starts_with("Failed "), label, line)?;
    }
    let again = at("re-call short again")?;
    need(
        again.starts_with("Failed ") && again.ends_with(" then Fault lease=false"),
        "a re-call answering short again is FAULT",
        again,
    )?;
    let other = at("re-call as another op")?;
    need(
        other.starts_with("Failed ") && other.ends_with(" then Refused lease=false"),
        "a re-call token spent on another op is REFUSED",
        other,
    )?;
    for label in ["decide unopened", "decide after close"] {
        let line = at(label)?;
        need(!line.starts_with("Ready"), label, line)?;
    }
    Ok(())
}
