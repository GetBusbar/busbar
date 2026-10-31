// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK KIND'S SCRIPT. Inputs (`conformance.json`):
//!
//! ```json
//! { "settings": <the settings the gate opens over>,
//!   "hook": {
//!     "bad_settings": ["<settings it must refuse: validate and open FAIL each; refresh the first>", ...],
//!     "order_cap": <the order slots the host's FIRST `decide` buffer holds>,
//!     "requests": [<request>, ...],
//!     "refresh": { "settings": <what it refreshes to>, "request": <request> },
//!     "configure": { "settings": <settings pushed>, "acks": true | false },   (optional)
//!     "notify": "ready",                                                     (optional)
//!     "status": <the JSON `status` answers>,                                 (optional)
//!     "describe": <the JSON `describe` answers> } }                          (optional)
//! ```
//!
//! THE MANAGEMENT OPS, walked on every hook once it is open: `configure` pushes the settings it
//! opened over at version 2 (READY acknowledges exactly that version; a refusal names why;
//! REFUSED is a hook that takes no pushed settings); `notify` taps one request-stage view; `status`
//! and `describe` answer READY with a JSON blob under a lease (released, one crossing each) or are
//! REFUSED. None may FAULT. The optional keys pin more: `configure` pushes its settings at version 3
//! and the hook must acknowledge them (`acks: true`) or refuse them naming why (`acks: false`);
//! `notify` READY; `status` and `describe` the JSON each answers.
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
//! FAULT. At least one `decide` must expect an order longer than `order_cap`, so the set walks the
//! re-call, UNLESS the hook declared `{"hook": {"orders": false}}` in its `declares.json` (it never
//! answers an order, ARCHITECT ruling, status row 194): it is judged on ABSTAIN-ONLY, no request
//! expects an order, there is no re-call to walk, and it FAILS if it ever orders. A hook that
//! states nothing may order, and still must produce the long one. (The ticket-less re-call TOKEN, and its refusal when spent on another op, is
//! `Plugin::recall`'s: no hook call is ticket-less, so the dispatcher's own tests prove it.)
//!
//! THE CROSSINGS ARE THE KERNEL'S (THE DESIGN §11.4: one table, as production drives it): every
//! `decide` and `transform` is SUBMITTED WATCHED on a ticket of its own, as the host's hook door
//! submits it (`hook_door`: `submit_watched`, the watch budget the hook's `timeout_ms`, here
//! [`BUDGET`]), its view and buffers lent to the op through the dispatcher's lending submit (§2).
//! So a gate that waits on a may-pend host service answers PENDING and is RESUMED on its wake
//! (a may-pend service on a ticket-less op is REFUSED, §11.12). A short answer is re-submitted
//! ONCE on the same ticket with the buffers it named. The lifecycle is ticket-less, as the host
//! makes it.
//!
//! Every step is one crossing of the hook table (its resumes reported, never pinned), but: a
//! request whose expected answer overflows the host's first buffer is 2 (the ONE short-buffer
//! re-call is +1); `decide` before `open` and after `close` is 0 (the dispatcher refuses an
//! unopened instance, and a closed one answers FAULT, without a crossing); and `ready`
//! ([`super::ready_step`]).
//!
//! THE RED ARM, in the script: the honest fold with every PREFER order reversed (a door that ranks
//! the other way) must be refused by the same contract.
//!
//! No `timeout` step: a step needs a plugin-controlled slow answer, which the script's inputs do
//! not name.

use busbar_contract::abi::hook::{
    slot, CandidateDynamic, CandidateStatic, ConfigureIn, ConfigureOut, DecideIn, DecideOut,
    DescribeOut, NotifyIn, StatusOut, TransformOut, CANDIDATE_HAS_BUDGET_REMAINING,
    CANDIDATE_HAS_COST_PER_MTOK, CANDIDATE_HAS_LATENCY_MS, CANDIDATE_HAS_RATE_HEADROOM,
    VERB_ABSTAIN, VERB_HAS_REJECT_STATUS, VERB_PREFER, VERB_REJECT, VERB_RESTRICT, VERB_REWRITE,
};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, DeadlineClass, InHead, OutHead, Outcome,
};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::abi_str;
use serde_json::Value;

use super::{
    abi_bytes as str_of, answered, asis, bind_far, called, closed, crossings, dispatcher, facts,
    input, input_text, json, listed, load, open, opened, output, refreshed, refused_settings,
    release, submit_on, Fold, Leg, Script, Subject,
};
use crate::dispatch::kinds::hook::Hook;
use crate::dispatch::{now_ns, Called, Dispatcher, Frame, Lent, Plugin};

/// THE WATCH BUDGET every `decide`/`transform` is submitted under, and its deadline: the hook's
/// `timeout_ms` as the host's hook door rides it on the op (THE DESIGN §11.7), generously.
const BUDGET: Duration = Duration::from_secs(10);

/// The host's first reject-message buffer, in bytes.
const MESSAGE_CAP: usize = 4096;
/// The host's first restrict-tags buffer, in bytes.
const TAGS_CAP: usize = 4096;
/// The host's first rewrite buffer, in bytes.
const REWRITE_CAP: usize = 64 * 1024;

/// The pool and dialect every request names.
const POOL: &str = "conformance";

/// One request of the set: the host's view, the op, and the line its answer must read.
pub(super) struct Request {
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

// SAFETY: the raw pointers in `statics` point into `_names`, owned by the same `Request` (their heap
// buffers never move); a `Request` lent to an op is never mutated.
unsafe impl Send for Request {}
// SAFETY: as above.
unsafe impl Sync for Request {}

impl Request {
    pub(super) fn of(v: &Value, order_cap: usize) -> Self {
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

/// The host's buffers for one op.
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
}

/// THE MEMORY ONE `decide`/`transform` LENDS THE HOOK: the request's view and the host's buffers,
/// built in place in the `Arc` lent to the op (THE DESIGN §2).
struct Lend {
    request: Arc<Request>,
    bufs: Bufs,
}

impl Lend {
    /// `r` over `bufs`: the memory lent, and the `in` over it.
    fn of(r: &Arc<Request>, bufs: Bufs) -> (Arc<Self>, DecideIn) {
        let mut lend = Arc::new(Self {
            request: Arc::clone(r),
            bufs,
        });
        let me = Arc::get_mut(&mut lend).expect("a lend not yet lent is unshared");
        let r = &me.request;
        let b = &mut me.bufs;
        let mut i: DecideIn = input();
        i.request.request_id = 1;
        i.request.pool = abi_str(POOL);
        i.request.ingress_dialect = abi_str(POOL);
        i.request.message_count = 1;
        i.candidates = r.statics.as_ptr();
        i.candidate_dynamics = r.dynamics.as_ptr();
        i.candidates_len = r.statics.len();
        i.order_buf = b.order.as_mut_ptr();
        i.order_cap = b.order.len();
        i.reject_message_buf = b.message.as_mut_ptr();
        i.reject_message_cap = b.message.len();
        i.restrict_tags_buf = b.tags.as_mut_ptr();
        i.restrict_tags_cap = b.tags.len();
        i.rewrite_buf = b.rewrite.as_mut_ptr();
        i.rewrite_cap = b.rewrite.len();
        (lend, i)
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

/// One op's answer: as the host reads it, whether it was SHORT, and what it said.
struct Crossed {
    called: Called,
    short: bool,
    said: Said,
}

/// ONE SUBMISSION of `r`'s op `op` on `ticket`, WATCHED (the hook door's way: the watch budget and
/// the deadline the hook's `timeout_ms`), over `bufs`, lent to the op.
fn cross(
    p: &Plugin<Hook>,
    d: &Dispatcher,
    ticket: Ticket,
    op: u32,
    r: &Arc<Request>,
    bufs: Bufs,
) -> Crossed {
    let (lend, i) = Lend::of(r, bufs);
    let when = (
        DeadlineClass::Call,
        now_ns().saturating_add(u64::try_from(BUDGET.as_nanos()).unwrap_or(u64::MAX)),
    );
    let lent = Arc::clone(&lend) as Lent;
    let b = &lend.bufs;
    let (called, short, said) = if op == slot::DECIDE {
        let f: Frame<DecideIn, DecideOut> = Frame::new(i, output());
        let done = submit_on(p, d, ticket, op, f, when, lent, BUDGET);
        let said = done.frame.as_ref().map_or_else(Said::default, |f| {
            let o = f.out;
            Said {
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
            }
        });
        (answered(&done), done.short, said)
    } else {
        let f: Frame<DecideIn, TransformOut> = Frame::new(i, output());
        let done = submit_on(p, d, ticket, op, f, when, lent, BUDGET);
        let said = done.frame.as_ref().map_or_else(Said::default, |f| {
            let o = f.out;
            Said {
                verbs: o.verbs,
                status: o.reject_status,
                message: head(&b.message, o.reject_message_written),
                rewrite: head(&b.rewrite, o.rewrite_written),
                needed: [0, o.reject_message_needed, 0, o.rewrite_needed],
                ..Said::default()
            }
        });
        (answered(&done), done.short, said)
    };
    Crossed {
        called,
        short,
        said,
    }
}

/// A ticket of `d`'s for one request (`None` when none is free: the step answers REFUSED).
fn ticket(d: &Dispatcher) -> Option<Ticket> {
    d.mint(0)
}

const NO_TICKET: &str = "Refused lease=false no ticket";

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

/// THE HOST'S WAY WITH ONE REQUEST (`hook_door`'s): the op submitted watched on a ticket of its
/// own over the first buffers, and on a short answer THE ONE re-call, re-submitted on that ticket
/// over buffers of the size it named. Its line: the outcome the host acts on, the verdict, and
/// whether it took the re-call.
pub(super) fn ask(p: &Plugin<Hook>, d: &Dispatcher, r: &Arc<Request>, order_cap: usize) -> String {
    let Some(t) = ticket(d) else {
        return NO_TICKET.to_string();
    };
    let first = cross(p, d, t, r.op, r, Bufs::first(order_cap));
    let (c, recalled) = if first.short {
        let [order, message, tags, rewrite] = first.said.needed;
        let big = Bufs::of(
            order.max(order_cap),
            message.max(MESSAGE_CAP),
            tags.max(TAGS_CAP),
            rewrite.max(REWRITE_CAP),
        );
        (cross(p, d, t, r.op, r, big), true)
    } else {
        (first, false)
    };
    d.recycle(t);
    format!(
        "{} | {} recalled={recalled}",
        called(&c.called).trim_end(),
        verdict(r.op, &c.called, &c.said)
    )
}

/// The first answer of `r`, short, then re-submitted on its ticket over the SAME short buffers.
fn recall_again(p: &Plugin<Hook>, d: &Dispatcher, r: &Arc<Request>, order_cap: usize) -> String {
    let Some(t) = ticket(d) else {
        return NO_TICKET.to_string();
    };
    let first = cross(p, d, t, r.op, r, Bufs::first(order_cap));
    let line = if first.short {
        let again = cross(p, d, t, r.op, r, Bufs::first(order_cap));
        format!(
            "{} then {}",
            called(&first.called).trim_end(),
            called(&again.called).trim_end()
        )
    } else {
        format!("{} (not short)", called(&first.called).trim_end())
    };
    d.recycle(t);
    line
}

/// THE BIND THE HOOK SCRIPT LOADS ITS DOOR WITH, on each leg: as every kind whose needs reach a
/// far end is bound ([`super::bind_far`], the auth and plane scripts'), over a table serving the far
/// ends its inputs name (`far_ends`), else the leg's own table ([`Subject::bind`]).
pub(super) fn bind_for(d: &Dispatcher, s: &Subject) -> crate::dispatch::Bind {
    bind_far(d, "hook", s)
}

pub(super) fn fold(s: &Subject, leg: Leg) -> Fold {
    let k = s.kind_inputs("hook");
    assert!(k.is_object(), "conformance.json has no `hook` inputs");
    let settings = leg.settings(s);
    let text = |v: &Value| input_text(v, "a hook");
    let bad: Vec<Vec<u8>> = listed(k, "hook", "bad_settings").iter().map(text).collect();
    let order_cap = k["order_cap"]
        .as_u64()
        .and_then(|n| usize::try_from(n).ok())
        .expect("conformance.json: hook.order_cap must be a number");
    let requests: Vec<Arc<Request>> = listed(k, "hook", "requests")
        .iter()
        .map(|r| Arc::new(Request::of(r, order_cap)))
        .collect();
    let orders = s.hook_orders();
    let short = recall_request(orders, &requests)
        .unwrap_or_else(|e| panic!("conformance.json: {e}"))
        .cloned();
    let refreshed_to = text(&k["refresh"]["settings"]);
    let after = Arc::new(Request::of(&k["refresh"]["request"], order_cap));
    if !orders {
        if let Err(e) = abstain_only(std::slice::from_ref(&after)) {
            panic!("conformance.json: the refresh request: {e}");
        }
    }

    let d = dispatcher();
    let p = load::<Hook>(s, leg, bind_for(&d, s)).expect("the hook door loads");
    let mut r = Script::new(crossings(&p));
    r.line("facts", 0, || facts(&p));
    refused_settings(&mut r, &p, &bad, &asis);
    r.line("decide unopened", 0, || {
        ask(&p, &d, &requests[0], order_cap)
    });
    for (i, b) in bad.iter().enumerate() {
        r.line(&format!("open bad #{i}"), 1, || called(&open(&p, b)));
    }
    opened(&mut r, (s, &p, &d), &settings, &asis);
    for q in &requests {
        r.line(&q.label, q.pinned(), || ask(&p, &d, q, order_cap));
    }
    let mut expect: Vec<(String, String)> = requests
        .iter()
        .map(|q| (q.label.clone(), q.line()))
        .collect();
    managed(&mut r, (k, &p, &d), &settings, &mut expect);
    // The short answer re-submitted on its ticket over the same short buffers: one crossing
    // each, then FAULT.
    if let Some(short) = &short {
        r.line("re-call short again", 2, || {
            recall_again(&p, &d, short, order_cap)
        });
    }
    refreshed(&mut r, &p, Some(&bad[0]), &refreshed_to, &asis);
    let after_label = format!("after refresh: {}", after.label);
    r.line(&after_label, after.pinned(), || {
        ask(&p, &d, &after, order_cap)
    });
    closed(&mut r, &p, &asis);
    r.line("decide after close", 0, || {
        ask(&p, &d, &requests[0], order_cap)
    });
    let fold = r.fold();

    expect.push((after_label, after.line()));
    contract(&fold, &expect, orders).unwrap_or_else(|e| panic!("{leg:?}: the hook contract: {e}"));
    // THE RED ARM: a door that ranks the other way answers otherwise, and is refused.
    let reversed = reversed(&fold);
    if reversed != fold {
        assert!(
            contract(&reversed, &expect, orders).is_err(),
            "{leg:?}: a fold with every order reversed passed the hook contract"
        );
    }
    fold
}

/// The settings version the script's `configure` pushes (`open` is 1), and the scripted one's.
const PUSHED: u64 = 2;
const SCRIPTED: u64 = 3;

/// `configure` with `settings` at `version`: the host's line and the version it acknowledged.
fn configure(p: &Plugin<Hook>, settings: &[u8], version: u64) -> String {
    let mut f: Frame<ConfigureIn, ConfigureOut> = Frame::new(input(), output());
    f.input.version = version;
    f.input.settings = json(settings);
    f.input.name = abi_str(POOL);
    let c = p.call(slot::CONFIGURE, &mut f);
    format!("{} | acked={}", called(&c).trim_end(), f.out.acked_version)
}

/// One request-stage `notify`, submitted on a ticket of its own (a tap that asks the far end
/// pends and is resumed on its wake): the host's line.
fn notify(p: &Plugin<Hook>, d: &Dispatcher) -> String {
    let Some(t) = ticket(d) else {
        return NO_TICKET.to_string();
    };
    let mut i: NotifyIn = input();
    i.stage.request_id = 1;
    i.stage.pool = abi_str(POOL);
    i.stage.ingress_dialect = abi_str(POOL);
    i.stage.message_count = 1;
    let when = (
        DeadlineClass::Call,
        now_ns().saturating_add(u64::try_from(BUDGET.as_nanos()).unwrap_or(u64::MAX)),
    );
    let f: Frame<NotifyIn, OutHead> = Frame::new(i, output());
    let done = submit_on(p, d, t, slot::NOTIFY, f, when, Arc::new(()) as Lent, BUDGET);
    d.recycle(t);
    called(&answered(&done)).trim_end().to_string()
}

/// The JSON blob a READY answer leased, as one token: `json=<compact JSON>`, `json=invalid` when
/// the bytes are not JSON, `json=none` for any other outcome.
fn blob_json(c: &Called, b: Blob) -> String {
    if c.outcome != Outcome::Ready {
        return "json=none".to_string();
    }
    let bytes: &[u8] = if b.ptr.is_null() || b.len == 0 {
        &[]
    } else {
        // SAFETY: the plugin's blob, judged by the kind's check, live under the answer's lease,
        // which has not been released.
        unsafe { std::slice::from_raw_parts(b.ptr, b.len) }
    };
    match serde_json::from_slice::<Value>(bytes) {
        Ok(v) => format!("json={v}"),
        Err(_) => "json=invalid".to_string(),
    }
}

/// `status` (or `describe`, `op`): the host's line and the lease it holds.
fn leased(p: &Plugin<Hook>, op: u32) -> (String, u64) {
    let (c, token) = if op == slot::STATUS {
        let mut f: Frame<InHead, StatusOut> = Frame::new(input(), output());
        let c = p.call(op, &mut f);
        let token = blob_json(&c, f.out.status);
        (c, token)
    } else {
        let mut f: Frame<InHead, DescribeOut> = Frame::new(input(), output());
        let c = p.call(op, &mut f);
        let token = blob_json(&c, f.out.describe);
        (c, token)
    };
    (format!("{} | {token}", called(&c).trim_end()), c.lease)
}

/// THE MANAGEMENT OPS on the open instance (H9): `configure` (and the inputs' scripted one),
/// `notify`, `status` and `describe`, each lease released. What the inputs pin is pushed onto
/// `expect`.
fn managed(
    r: &mut Script<'_>,
    (k, p, d): (&Value, &Plugin<Hook>, &Dispatcher),
    settings: &[u8],
    expect: &mut Vec<(String, String)>,
) {
    r.line("configure", 1, || configure(p, settings, PUSHED));
    if let Some(c) = k.get("configure").filter(|c| !c.is_null()) {
        let pushed = input_text(&c["settings"], "a hook");
        let acks = c["acks"]
            .as_bool()
            .expect("conformance.json: hook.configure.acks must be true or false");
        let label = if acks {
            expect.push((
                "configure scripted".to_string(),
                format!("Ready lease=false | acked={SCRIPTED}"),
            ));
            "configure scripted"
        } else {
            "configure refused"
        };
        r.line(label, 1, || configure(p, &pushed, SCRIPTED));
    }
    r.line("notify", 1, || notify(p, d));
    match k.get("notify").and_then(Value::as_str) {
        None => {}
        Some("ready") => expect.push(("notify".to_string(), "Ready lease=false".to_string())),
        Some(o) => panic!("conformance.json: hook.notify is `ready`, not `{o}`"),
    }
    let mut leases = Vec::new();
    for (label, op) in [("status", slot::STATUS), ("describe", slot::DESCRIBE)] {
        let lease = r.step(label, 1, || leased(p, op));
        if let Some(want) = k.get(label).filter(|w| !w.is_null()) {
            expect.push((label.to_string(), format!("Ready lease=true | json={want}")));
        }
        if lease != 0 {
            leases.push((format!("release {label}"), lease));
        }
    }
    for (label, lease) in leases {
        r.line(&label, 1, || called(&release(p, lease)));
    }
}

/// The request whose short answer the script re-calls, and the order proof it rests on. A hook that
/// may order (`orders`) must have one `decide` expecting an order longer than the first buffer; a
/// hook that declared `orders: false` has none ([`abstain_only`]).
///
/// # Errors
/// The hook may order and no `decide` expects an order longer than `order_cap`; or it declared
/// `orders: false` and a request expects an order.
pub(super) fn recall_request(
    orders: bool,
    requests: &[Arc<Request>],
) -> Result<Option<&Arc<Request>>, String> {
    if !orders {
        return abstain_only(requests).map(|()| None);
    }
    requests
        .iter()
        .find(|r| r.op == slot::DECIDE && r.short)
        .map(Some)
        .ok_or_else(|| {
            "no `decide` expects an order longer than hook.order_cap (the re-call)".to_string()
        })
}

/// A hook that declared `orders: false` is judged on abstain-only: no `decide` of the set expects
/// an order.
///
/// # Errors
/// The first request that expects an order.
pub(super) fn abstain_only(requests: &[Arc<Request>]) -> Result<(), String> {
    match requests
        .iter()
        .find(|r| r.op == slot::DECIDE && r.expect.starts_with("verb=prefer"))
    {
        None => Ok(()),
        Some(r) => Err(format!(
            "the plugin declared `hook.orders: false` in its declares.json, but request '{}' \
             expects an order: a hook that never orders is judged on abstain-only",
            r.label
        )),
    }
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

/// THE MANAGEMENT OPS' CONTRACT (H9): none FAULTs; `configure` READY acknowledges the version it
/// was pushed, and FAILED names why; a scripted `configure` the hook must refuse is FAILED naming
/// why; `status` and `describe` READY carry JSON.
fn management(fold: &Fold) -> Result<(), String> {
    let at = |label: &str| {
        fold.iter()
            .find(|s| s.label == label)
            .map(|s| s.answer.as_str())
            .ok_or_else(|| format!("the script ran no step '{label}'"))
    };
    let fail = |label: &str, line: &str, why: &str| Err(format!("{label}: {why}: {line}"));
    for label in ["configure", "notify", "status", "describe"] {
        let line = at(label)?;
        if line.starts_with("Fault") {
            return fail(label, line, "a management op FAULTed");
        }
    }
    let names_why = |line: &str| {
        line.split(" | ")
            .next()
            .is_some_and(|head| head.len() > "Failed lease=false".len())
    };
    let configure = at("configure")?;
    if configure.starts_with("Ready") && !configure.ends_with(&format!(" | acked={PUSHED}")) {
        return fail(
            "configure",
            configure,
            "READY must acknowledge the pushed version",
        );
    }
    if configure.starts_with("Failed") && !names_why(configure) {
        return fail("configure", configure, "a refused configure names why");
    }
    if let Ok(refused) = at("configure refused") {
        if !refused.starts_with("Failed") || !names_why(refused) {
            return fail(
                "configure refused",
                refused,
                "the inputs' configure must be refused, naming why",
            );
        }
    }
    for label in ["status", "describe"] {
        let line = at(label)?;
        if line.starts_with("Ready") && line.ends_with("json=invalid") {
            return fail(label, line, "a READY blob is not JSON");
        }
        if line.starts_with("Ready") && line.ends_with("json=none") {
            return fail(label, line, "a READY answer carries its blob");
        }
    }
    Ok(())
}

/// THE KIND'S CONTRACT over the fold, so two equal folds of failures prove nothing: the lifecycle
/// answers READY where it must and FAILED with its reason where it must; every request answers
/// exactly its expected line (verb, order, status, message, the re-call taken or not); a re-call
/// that is short again is FAULT; an unopened or closed instance serves nothing.
///
/// A hook that declared `orders: false` FAILS the contract if any step answered an order (RED ARM).
pub(super) fn contract(
    fold: &Fold,
    expect: &[(String, String)],
    orders: bool,
) -> Result<(), String> {
    if !orders {
        if let Some(s) = fold.iter().find(|s| s.answer.contains("verb=prefer")) {
            return Err(format!(
                "{}: the plugin declared `hook.orders: false` and ordered: {}",
                s.label, s.answer
            ));
        }
    }
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
    // EVERY bad setting: each validate FAILED naming why, each open FAILED (H1).
    fn bad<'f>(fold: &'f Fold, prefix: &'static str) -> impl Iterator<Item = &'f super::Step> {
        fold.iter().filter(move |s| s.label.starts_with(prefix))
    }
    let bad = |prefix: &'static str| bad(fold, prefix);
    need(
        bad("validate bad #").next().is_some(),
        "the inputs name no bad settings",
        "",
    )?;
    for s in bad("validate bad #") {
        need(
            s.answer.starts_with("Failed lease=false ")
                && s.answer.len() > "Failed lease=false ".len(),
            &format!("{}: a refused validate names why", s.label),
            &s.answer,
        )?;
    }
    need(
        bad("open bad #").count() == bad("validate bad #").count(),
        "an open over every bad setting",
        "",
    )?;
    for s in bad("open bad #").chain(bad("refresh bad")) {
        need(s.answer.starts_with("Failed "), &s.label, &s.answer)?;
    }
    management(fold)?;
    if orders {
        let again = at("re-call short again")?;
        need(
            again.starts_with("Failed ") && again.ends_with(" then Fault lease=false"),
            "a re-call answering short again is FAULT",
            again,
        )?;
    }
    for label in ["decide unopened", "decide after close"] {
        let line = at(label)?;
        need(!line.starts_with("Ready"), label, line)?;
    }
    Ok(())
}
