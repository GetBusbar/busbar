// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export kind's shared sink pieces through a real door: a push sink built from them answers
//! `scrape` and `serve` REFUSED in the kind's words, `status` READY, its `one_instance` check
//! names every instance after the first, and its settings are refused in serde's words.

use std::mem::size_of;

use serde::Deserialize;

use super::*;
use crate::abi::export::{
    CheckInstance, CheckOut, DeliverIn, ExportStream, Ops, CHECK_PHASE_LIMITS,
};
use crate::abi::mechanism::call::{Blob, OutHead, BLOB_JSON};
use crate::abi::mechanism::door::{Statement, REWRITE_ALIAS};
use crate::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut};
use crate::abi::sdk::door::{abi_str, alias, statement};
use crate::abi::sdk::life::{
    settings_as, settings_value, HeldSlot, Opened, NOT_REFRESHED, NO_INSTANCE,
};
use crate::abi::sdk::test_support::reply::{self, Instance as TestInstance};
use crate::abi::sdk::test_support::test_in::TestIn;
use crate::abi::sdk::test_support::{zeroed, DoorView};
use crate::abi::sdk::Safe;

const STREAMS: &[u8] = &[ExportStream::Logs as u8];
const TAIL: Tail = tail(STREAMS, &[]);
const REWRITES: &[crate::abi::mechanism::door::Rewrite] = &[alias("probe-sink")];
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    ..statement("probe-sink", "0.0.1", 4)
};

/// The probe's settings.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ProbeSettings {
    path: String,
}

/// The probe sink: it holds nothing.
struct Probe;

impl Life for Probe {
    const CANCEL: u32 = 0;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        settings_as::<ProbeSettings>(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Self::validate(settings).map(|()| Probe)
    }
}

/// `deliver`: READY, nothing kept.
struct Deliver;

impl SafeSlot for Deliver {
    type In = DeliverIn;
    type Out = crate::abi::mechanism::call::OutHead;
    type State = Held<Probe>;
    fn call(_: Instance<'_, Held<Probe>>, _: Lent<'_, DeliverIn>, _: Out<'_, OutHead>) -> Outcome {
        Outcome::Ready
    }
}

/// The probe's one-instance refusal.
const WHY: &str = "The probe holds one file, so a second instance could only be ignored.";

/// `check`: at the limits phase, with more than one instance, why a second cannot run.
struct Check;

impl HeldSlot for Check {
    type In = CheckIn;
    type Out = CheckOut;
    type Life = Probe;
    fn call(
        held: &Held<Probe>,
        _: &Instance<'_, Held<Probe>>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        let lines = one_instance_reason(&instance_names(input), WHY);
        if !lines.is_empty() {
            let json = serde_json::to_vec(&lines).unwrap_or_default();
            out.lease(|o| &o.findings, held.leases(), json, BLOB_JSON);
        }
        Outcome::Ready
    }
}

mod plugin {
    use super::{Check, Deliver, NoScrape, NoServe, Opened, Probe, Quiet, Safe};

    crate::plugin_door! {
        ops: super::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Probe),
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<NoScrape<Probe>>, status: Safe<Quiet<Probe>>,
            check: Safe<Opened<Check>>, serve: Safe<NoServe<Probe>>,
        },
    }
}

fn view() -> DoorView {
    DoorView::of(plugin::MACRO_DOOR)
}

fn opened(view: &DoorView) -> TestInstance<'static> {
    let open = view.op::<Ops>(|t| &t.head.open).expect("open");
    let mut c = reply::call_in(
        open,
        None,
        &TestIn::<OpenIn>::new()
            .set(|i| &i.head.op, slot::OPEN)
            .settings(br#"{"path":"/x"}"#),
        zeroed::<OpenOut>(),
    );
    assert_eq!(c.outcome, Outcome::Ready);
    c.take_instance().expect("an instance")
}

fn close(view: &DoorView, instance: TestInstance<'static>) {
    let close = view.op::<Ops>(|t| &t.head.close).expect("close");
    let mut h: OutHead = zeroed();
    h.size = size_of::<OutHead>() as u32;
    let c = reply::close_in(
        close,
        instance,
        &TestIn::<InHead>::new().set(|i| &i.op, slot::CLOSE),
        h,
    );
    assert_eq!(c.outcome, Outcome::Ready);
}

/// A push sink's `scrape` and `serve` are REFUSED saying why, and its `status` is READY.
#[test]
fn a_push_sink_refuses_scrape_and_serve_in_the_kinds_words() {
    let view = view();
    let instance = opened(&view);

    let scrape = view.op::<Ops>(|t| &t.scrape).expect("scrape");
    let c = reply::call_in(
        scrape,
        Some(&instance),
        &TestIn::<ScrapeIn>::new().set(|i| &i.head.op, crate::abi::export::slot::SCRAPE),
        zeroed::<ScrapeOut>(),
    );
    assert_eq!(c.outcome, Outcome::Refused);
    assert_eq!(c.error.as_deref(), Some(NO_EXPOSITION));
    assert_eq!(c.out.written, 0);

    let serve = view.op::<Ops>(|t| &t.serve).expect("serve");
    let c = reply::call_in(
        serve,
        Some(&instance),
        &TestIn::<ServeIn>::new().set(|i| &i.head.op, crate::abi::export::slot::SERVE),
        zeroed::<ServeOut>(),
    );
    assert_eq!(c.outcome, Outcome::Refused);
    assert_eq!(c.error.as_deref(), Some(NO_ROUTE));

    let status = view.op::<Ops>(|t| &t.status).expect("status");
    let c = reply::call_in(
        status,
        Some(&instance),
        &TestIn::<InHead>::new().set(|i| &i.op, crate::abi::export::slot::STATUS),
        zeroed::<StatusOut>(),
    );
    assert_eq!(c.outcome, Outcome::Ready);
    assert_eq!(c.error, None);
    assert!(c.owned.is_empty());

    close(&view, instance);
}

/// The `one_instance` check through the door: with more than one instance, the sink's one finding
/// is why a second cannot run (the host words the refusal); one instance (or none) is none.
#[test]
fn a_second_instance_is_answered_with_the_sinks_reason() {
    let view = view();
    let instance = opened(&view);
    let check = view.op::<Ops>(|t| &t.check).expect("check");
    let named = |names: &[&'static str]| -> Vec<u8> {
        let list: Vec<CheckInstance> = names
            .iter()
            .map(|&n| CheckInstance {
                name: abi_str(n),
                settings: Blob::ABSENT,
            })
            .collect();
        let c = reply::call_in(
            check,
            Some(&instance),
            &TestIn::<CheckIn>::new()
                .set(|i| &i.head.op, crate::abi::export::slot::CHECK)
                .set(|i| &i.phase, CHECK_PHASE_LIMITS)
                .list(|i| &i.instances, |i| &i.instances_len, &list),
            zeroed::<CheckOut>(),
        );
        assert_eq!(c.outcome, Outcome::Ready);
        c.owned
    };
    assert!(named(&[]).is_empty());
    assert!(named(&["a"]).is_empty());
    let lines: Vec<String> =
        serde_json::from_slice(&named(&["a", "b", "c"])).expect("findings are a JSON list");
    assert_eq!(
        lines,
        [WHY],
        "the sink says why; the host words the refusal"
    );
    close(&view, instance);
}

/// Settings are read as their JSON value, empty as `{}`, and refused FAILED in serde's words.
#[test]
fn settings_are_refused_in_serdes_words_empty_reading_as_an_object() {
    let refused = |bytes: &[u8]| {
        let r = settings_as::<ProbeSettings>(bytes).err().expect("refused");
        assert_eq!(r.outcome(), Outcome::Failed);
        r.text().expect("a refusal says why").to_string()
    };
    assert_eq!(refused(b""), "settings: missing field `path`");
    assert_eq!(refused(b"{}"), "settings: missing field `path`");
    assert_eq!(
        refused(br#"{"path":"/x","rotate":1}"#),
        "settings: unknown field `rotate`, expected `path`"
    );
    assert_eq!(
        refused(br#"{"path":1}"#),
        "settings: invalid type: integer `1`, expected a string"
    );
    let eof = serde_json::from_slice::<serde_json::Value>(b"{").expect_err("not JSON");
    assert_eq!(refused(b"{"), format!("settings: {eof}"));
    assert!(settings_as::<ProbeSettings>(br#"{"path":"/x"}"#).is_ok());
    assert_eq!(settings_value(b"").expect("empty"), serde_json::json!({}));
}

/// The tail states the streams and routes it is given, an empty list NULL; the alias rewrite is
/// the module name, `to` absent.
#[test]
fn the_tail_and_the_alias_state_what_they_are_given() {
    assert_eq!(TAIL.head.size as usize, size_of::<Tail>());
    assert!(!TAIL.streams.is_null());
    assert_eq!(TAIL.streams_len, 1);
    assert!(TAIL.routes.is_null());
    assert_eq!(TAIL.routes_len, 0);
    const ROUTES: &[Route] = &[Route {
        path: abi_str("/metrics"),
        method: abi_str("GET"),
        auth: 0,
        _reserved: 0,
    }];
    const WITH: Tail = tail(&[], ROUTES);
    assert!(WITH.streams.is_null());
    assert!(!WITH.routes.is_null());
    assert_eq!(WITH.routes_len, 1);

    let a = alias("probe-sink");
    assert_eq!(a.class, REWRITE_ALIAS);
    assert!(!a.from.ptr.is_null());
    assert_eq!(a.from.len, "probe-sink".len());
    assert!(a.to.ptr.is_null() && a.to.len == 0);
    assert_eq!(view().name(), "probe-sink");
}

/// RED (export ABI defect 17): an op over the open instance answers a call with NO instance in the
/// SDK's own words, before the plugin's body runs. Before, each sink hand-wrote that branch.
#[test]
fn a_held_op_with_no_instance_answers_in_the_sdks_words() {
    let view = view();
    let check = view.op::<Ops>(|t| &t.check).expect("check");
    let c = reply::call_in(
        check,
        None,
        &TestIn::<CheckIn>::new()
            .set(|i| &i.head.op, crate::abi::export::slot::CHECK)
            .set(|i| &i.phase, CHECK_PHASE_LIMITS),
        zeroed::<CheckOut>(),
    );
    assert_eq!(c.outcome, Outcome::Refused);
    assert_eq!(c.error.as_deref(), Some(NO_INSTANCE));
}

/// RED (export ABI defect 5): a sink states no `refresh` — the host never refreshes an export
/// instance (restart to apply) — and the SDK's default answers it REFUSED, saying so.
#[test]
fn a_sink_that_states_no_refresh_is_answered_by_the_sdk() {
    let Err(refused) = Probe.refresh(b"{}", &[], 2) else {
        panic!("the default refresh is refused");
    };
    assert_eq!(refused.outcome(), Outcome::Refused);
    assert_eq!(refused.text(), Some(NOT_REFRESHED));
}
