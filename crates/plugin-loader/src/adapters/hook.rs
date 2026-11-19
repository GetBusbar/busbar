// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The hook adapter: `HookPort` over the hook kind's `Proxy` (IF §11.3, §8.4).
//!
//! A hook is sync (`on`) or async (`on_io`), as its describe declared (`M_ON` / `M_ON_IO`). Core's view is
//! encoded once per call with the §8.8 `encode_view` into a pooled buffer; the answer is decoded straight into
//! `HookAnswer`. A REFUSED or FAILED answer becomes a `PortError` whose text went through `scrub::fail_text`
//! (scrub, then cut: I14, C-SCRUB-CUT); a hook `MESSAGE` is operator text and takes the same path.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use busbar_plugin_abi::fail::fact::{FACT_BACKEND_STATUS, FACT_RETRY_AFTER_S};
use busbar_plugin_abi::fail::{failed, CallError, FaultReason};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::{sync_bufs, Pool};
use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
use busbar_plugin_abi::kinds::hook::hook::{
    tag, Verdict as VerdictRec, M_ON_IO, VERB_REJECT, VERB_REWRITE,
};
use busbar_plugin_abi::records::{tag as gtag, RecErr, Records};
use busbar_plugin_abi::types::Status;

use crate::call::kinds::hook::Proxy;
use crate::instance::ErrorBook;
use busbar_ports::codec::hook::encode_view;
use busbar_ports::hook::{HookAnswer, HookCall, HookPort, HookView};
use busbar_ports::PluginCode;
use busbar_ports::{CallCx, PortError};

/// The hook port over one instance's proxy.
pub struct HookAdapter<N: Needs> {
    proxy: Proxy,
    needs: Arc<N>,
    /// D_POINTS, decoded at describe.
    points: u32,
    /// The image's `ErrorBook` (§11.2), for the ERROR number of a REFUSED or FAILED answer.
    errors: &'static ErrorBook,
    /// The undeclared-number WARN latch (once per instance, Relaxed, no RMW).
    latch: AtomicBool,
    /// The image declared `M_ON_IO` (exactly one of `on` / `on_io` is declared).
    io: bool,
}

impl<N: Needs> HookAdapter<N> {
    /// Built by `Registry::open_hook` after INSTANCE: `points` is the describe's D_POINTS mask and `errors` the
    /// owning image's book.
    pub fn new(proxy: Proxy, needs: Arc<N>, points: u32, errors: &'static ErrorBook) -> Self {
        let io = proxy.instance().methods & M_ON_IO != 0;
        Self {
            proxy,
            needs,
            points,
            errors,
            latch: AtomicBool::new(false),
            io,
        }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    /// The call's `Caller`, borrowed from the instance (no refcount RMW). `chain` is 0: `Driver::new` mints it.
    fn caller<'a>(&'a self, cx: &CallCx) -> Caller<'a> {
        let inst = self.proxy.instance();
        Caller {
            plugin: &inst.identity,
            kind: inst.kind,
            name: &inst.name,
            instance: inst.id,
            slot: inst.slot,
            chain: 0,
            deadline: cx.deadline,
            stack: cx.stack,
            out_of_process: false,
            limits: inst.limits,
        }
    }

    /// An answer as the port's value. REFUSED and FAILED are `PortError`s; any other status is a contract break.
    fn finish(&self, answer: &Answer<'_>) -> Result<HookAnswer, PortError> {
        let inst = self.proxy.instance();
        let status = answer.status;
        if status == Status::OK {
            return decode_answer(answer.records(), &inst.scrub)
                .map_err(|e| PortError::Call(CallError::Fault(fault(e))));
        }
        let refused = status == Status::REFUSED;
        if !refused && status != Status::FAILED {
            return Err(PortError::Call(CallError::Fault(FaultReason::BadStatus(
                status.0,
            ))));
        }
        let Some((code, text)) = answer.fail() else {
            return Err(PortError::Call(CallError::Fault(FaultReason::MissingFail)));
        };
        let error = self.errors.resolve(answer.fail_error(), &self.latch);
        let (retry, backend) = if refused {
            (None, None)
        } else {
            (
                answer.fail_fact(FACT_RETRY_AFTER_S),
                answer.fail_fact(FACT_BACKEND_STATUS),
            )
        };
        Err(port_error(
            &inst.scrub,
            !refused,
            code,
            text,
            retry,
            backend,
            error,
        ))
    }
}

impl<N: Needs> HookPort for HookAdapter<N> {
    fn points(&self) -> u32 {
        self.points
    }

    fn facts(&self) -> u64 {
        self.proxy.instance().facts
    }

    fn on<'a>(&'a self, cx: CallCx, point: u32, view: &'a HookView<'a>) -> HookCall<'a> {
        let inst = self.proxy.instance();
        if !inst.is_live() {
            return HookCall::Done(Err(PortError::Call(CallError::Quarantined)));
        }
        if !self.io {
            // Sync: no box, no hop. The view goes into the thread's args buffer, the answer is decoded before
            // the buffers are reset.
            let r = sync_bufs(inst.max_out, |args, out| {
                encode_view(args, view).map_err(|_| view_too_big())?;
                let answer = self
                    .proxy
                    .on(out, crate::call::at(&cx), point, args.bytes())
                    .map_err(PortError::Call)?;
                self.finish(&answer)
            });
            return HookCall::Done(r);
        }
        let mut req = Pool::global().acquire(inst.max_out);
        if encode_view(&mut req, view).is_err() {
            return HookCall::Done(Err(view_too_big()));
        }
        HookCall::Io(Box::pin(async move {
            let mut drv = Driver::new(&*self.needs, self.caller(&cx));
            let owned = self
                .proxy
                .on_io(&mut drv, crate::call::at(&cx), req, point)
                .await
                .map_err(PortError::Call)?;
            self.finish(&owned.answer())
        }))
    }
}

/// Core built a view the request buffer cannot hold: core's own limit, not the plugin's text.
fn view_too_big() -> PortError {
    PortError::Failed {
        code: failed::F_LIMIT,
        text: "the hook view does not fit the request buffer".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }
}

/// A malformed answer is a plugin contract break (FAULT), reported with the record error's reason.
fn fault(e: RecErr) -> FaultReason {
    match e {
        RecErr::Unknown(t) => FaultReason::UnknownTag(t),
        e => FaultReason::BadRecords(e),
    }
}

/// The VERDICT then the answer's data records (IF §8.4); METRIC records are skipped (core keeps the series from
/// the answer, §12.17, not from this port). Anything else is `RecErr`.
fn decode_answer(recs: Records<'_>, scrub: &Scrub) -> Result<HookAnswer, RecErr> {
    let mut recs = recs;
    let first = recs.next().ok_or(RecErr::Truncated)??;
    if first.tag != tag::VERDICT {
        return Err(RecErr::Unknown(first.tag));
    }
    let v: VerdictRec = first.pod()?;
    if v.verb > VERB_REWRITE {
        return Err(RecErr::Size);
    }
    let mut out = HookAnswer {
        verb: v.verb,
        // Core clamps to 400..=499 (else 403); 0 or an out-of-range number states no status.
        reject_status: (v.verb == VERB_REJECT)
            .then(|| u16::try_from(v.reject_status).ok().filter(|s| *s != 0))
            .flatten(),
        order: Vec::new(),
        restrict: Vec::new(),
        message: None,
        rewrite: None,
    };
    let (mut order, mut message, mut rewrite) = (false, false, false);
    for rec in recs {
        let rec = rec?;
        match rec.tag {
            tag::ORDER => {
                if core::mem::replace(&mut order, true) || rec.body.len() % 4 != 0 {
                    return Err(RecErr::Size);
                }
                out.order = rec
                    .body
                    .as_chunks::<4>()
                    .0
                    .iter()
                    .map(|c| u32::from_le_bytes(*c))
                    .collect();
            }
            tag::RESTRICT => out.restrict.push(rec.text()?.into()),
            tag::MESSAGE => {
                if core::mem::replace(&mut message, true) {
                    return Err(RecErr::Size);
                }
                // Operator text from the plugin: scrub first, cut after (I14).
                out.message = Some(fail_text(scrub, rec.text()?).as_ref().into());
            }
            tag::REWRITE => {
                if core::mem::replace(&mut rewrite, true) {
                    return Err(RecErr::Size);
                }
                out.rewrite = Some(rec.body.to_vec());
            }
            gtag::METRIC => {}
            t => return Err(RecErr::Unknown(t)),
        }
    }
    Ok(out)
}

/// A REFUSED or FAILED answer as a `PortError`. The text is scrubbed whole, then cut (I14). The facts are the
/// FAILED answer's own; a REFUSED answer never carries any.
pub fn port_error(
    scrub: &Scrub,
    failed_answer: bool,
    code: u32,
    text: &str,
    retry_after_s: Option<u64>,
    backend_status: Option<u64>,
    error: Option<PluginCode>,
) -> PortError {
    let text: Box<str> = fail_text(scrub, text).as_ref().into();
    if failed_answer {
        PortError::Failed {
            code,
            text,
            retry_after_s,
            backend_status,
            error,
        }
    } else {
        PortError::Refused { code, text, error }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::fail::failed;
    use busbar_plugin_abi::fail::refused::R_POLICY;
    use busbar_plugin_abi::kinds::hook::hook::{
        tag, VERB_ABSTAIN, VERB_PREFER, VERB_REJECT, VERB_RESTRICT,
    };
    use busbar_plugin_abi::records::{Reply, Writer};

    fn scrub_with(secret: &[u8]) -> Scrub {
        Scrub::from_needles([secret])
    }

    fn verdict(r: &mut Reply, verb: u32, status: u32) {
        r.put_pod(
            tag::VERDICT,
            &VerdictRec {
                verb,
                reject_status: status,
            },
        )
        .unwrap();
    }

    #[test]
    fn an_abstain_is_an_empty_answer() {
        let mut r = Reply::new();
        verdict(&mut r, VERB_ABSTAIN, 0);
        let a = decode_answer(Records::new(r.as_bytes()), &Scrub::new()).unwrap();
        assert_eq!(a.verb, VERB_ABSTAIN);
        assert!(
            a.order.is_empty()
                && a.restrict.is_empty()
                && a.message.is_none()
                && a.rewrite.is_none()
        );
        assert_eq!(a.reject_status, None);
    }

    #[test]
    fn order_restrict_message_and_rewrite_come_through() {
        let mut r = Reply::new();
        verdict(&mut r, VERB_PREFER, 0);
        let order: Vec<u8> = [2u32, 0, 1].iter().flat_map(|n| n.to_le_bytes()).collect();
        r.put(tag::ORDER, &order).unwrap();
        r.put_text(tag::RESTRICT, "a").unwrap();
        r.put_text(tag::RESTRICT, "b").unwrap();
        r.put_text(tag::MESSAGE, "over budget").unwrap();
        r.put(tag::REWRITE, b"{\"messages\":[]}").unwrap();
        r.put_metric(1, 1, 1.0, &[]).unwrap();
        let a = decode_answer(Records::new(r.as_bytes()), &Scrub::new()).unwrap();
        assert_eq!(a.order, [2, 0, 1]);
        assert_eq!(
            a.restrict.iter().map(|s| &**s).collect::<Vec<_>>(),
            ["a", "b"]
        );
        assert_eq!(a.message.as_deref(), Some("over budget"));
        assert_eq!(a.rewrite.as_deref(), Some(&b"{\"messages\":[]}"[..]));
    }

    #[test]
    fn only_a_reject_carries_a_status_and_zero_is_none() {
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 429);
        assert_eq!(
            decode_answer(Records::new(r.as_bytes()), &Scrub::new())
                .unwrap()
                .reject_status,
            Some(429)
        );
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 0);
        assert_eq!(
            decode_answer(Records::new(r.as_bytes()), &Scrub::new())
                .unwrap()
                .reject_status,
            None
        );
        let mut r = Reply::new();
        verdict(&mut r, VERB_RESTRICT, 429);
        assert_eq!(
            decode_answer(Records::new(r.as_bytes()), &Scrub::new())
                .unwrap()
                .reject_status,
            None
        );
    }

    #[test]
    fn a_malformed_answer_is_a_record_error() {
        let empty = Reply::new();
        assert!(decode_answer(Records::new(empty.as_bytes()), &Scrub::new()).is_err());
        let mut r = Reply::new();
        verdict(&mut r, 99, 0);
        assert!(decode_answer(Records::new(r.as_bytes()), &Scrub::new()).is_err());
        let mut r = Reply::new();
        verdict(&mut r, VERB_PREFER, 0);
        r.put(tag::ORDER, &[1, 2, 3]).unwrap();
        assert!(decode_answer(Records::new(r.as_bytes()), &Scrub::new()).is_err());
        let mut r = Reply::new();
        verdict(&mut r, VERB_PREFER, 0);
        r.put_text(tag::MESSAGE, "x").unwrap();
        r.put_text(tag::MESSAGE, "y").unwrap();
        assert!(decode_answer(Records::new(r.as_bytes()), &Scrub::new()).is_err());
    }

    #[test]
    fn a_message_is_scrubbed_before_it_is_cut() {
        let secret = b"s3cr3t-value-xyz";
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 403);
        r.put_text(tag::MESSAGE, "denied for s3cr3t-value-xyz today")
            .unwrap();
        let a = decode_answer(Records::new(r.as_bytes()), &scrub_with(secret)).unwrap();
        let m = a.message.unwrap();
        assert!(!m.contains("s3cr3t"), "{m}");
        let long = format!("{}{}", "x".repeat(600), "tail");
        let mut r = Reply::new();
        verdict(&mut r, VERB_REJECT, 403);
        r.put_text(tag::MESSAGE, &long).unwrap();
        let a = decode_answer(Records::new(r.as_bytes()), &Scrub::new()).unwrap();
        assert_eq!(a.message.unwrap().len(), 512);
    }

    #[test]
    fn refused_has_no_facts_and_failed_maps_them() {
        let s = Scrub::new();
        let e = port_error(&s, false, R_POLICY, "no", Some(7), Some(503), None);
        assert_eq!(
            e,
            PortError::Refused {
                code: R_POLICY,
                text: "no".into(),
                error: None
            }
        );
        let e = port_error(
            &s,
            true,
            failed::F_UPSTREAM,
            "down",
            Some(30),
            Some(503),
            None,
        );
        assert_eq!(
            e,
            PortError::Failed {
                code: failed::F_UPSTREAM,
                text: "down".into(),
                retry_after_s: Some(30),
                backend_status: Some(503),
                error: None,
            }
        );
        let e = port_error(&s, true, failed::F_UPSTREAM, "down", None, None, None);
        assert!(matches!(
            e,
            PortError::Failed {
                retry_after_s: None,
                backend_status: None,
                ..
            }
        ));
    }

    #[test]
    fn a_port_error_text_never_carries_a_secret_or_exceeds_the_cut() {
        let s = scrub_with(b"hunter2-hunter2");
        let e = port_error(
            &s,
            true,
            failed::F_UNAVAILABLE,
            "bad hunter2-hunter2 here",
            None,
            None,
            None,
        );
        match e {
            PortError::Failed { text, .. } => assert!(!text.contains("hunter2")),
            other => panic!("{other:?}"),
        }
        let long = "y".repeat(2000);
        match port_error(&s, false, R_POLICY, &long, None, None, None) {
            PortError::Refused { text, .. } => assert_eq!(text.len(), 512),
            other => panic!("{other:?}"),
        }
    }
}
