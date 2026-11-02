// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The export kind's shared sink pieces through a real door: a push sink built from them answers

use std::mem::{size_of, size_of_val};

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
use crate::abi::sdk::test_support::zeroed;
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

/// What [`Deliver`] notes in its reply's envelope.
const DELIVERED: &str = "delivered one batch";

/// `deliver`: READY, nothing kept; it notes [`DELIVERED`] and counts one in its envelope.
struct Deliver;

impl SafeSlot for Deliver {
    type In = DeliverIn;
    type Out = crate::abi::mechanism::call::OutHead;
    type State = Held<Probe>;
    fn call(
        _: Instance<'_, Held<Probe>>,
        _: Lent<'_, DeliverIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        out.diag(
            crate::abi::mechanism::call::DIAG_LOG,
            crate::abi::mechanism::call::SEVERITY_INFO,
            DELIVERED,
        );
        out.metric(0, crate::abi::mechanism::call::METRIC_ADD, 1.0);
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

fn ops() -> &'static Ops {
    // SAFETY: the actual SDK-generated export door declares this complete static table.
    unsafe { &*plugin::door().ops().cast::<Ops>() }
}

fn opened(table: &Ops) -> *mut core::ffi::c_void {
    let mut input: OpenIn = zeroed();
    input.head.size = size_of::<OpenIn>() as u32;
    input.head.op = slot::OPEN;
    input.settings = Blob {
        fmt: BLOB_JSON,
        ..Blob::of(br#"{"path":"/x"}"#)
    };
    let mut output: OpenOut = zeroed();
    output.head.size = size_of::<OpenOut>() as u32;
    // SAFETY: exact initialized frames and static settings; this door creates the sole instance.
    assert_eq!(
        unsafe {
            table.head.open.unwrap()(
                core::ptr::null_mut(),
                core::ptr::from_ref(&input).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
    assert!(!output.instance.is_null(), "an instance");
    output.instance
}

fn close(table: &Ops, instance: *mut core::ffi::c_void) {
    let mut input: InHead = zeroed();
    input.size = size_of::<InHead>() as u32;
    input.op = slot::CLOSE;
    let mut output: OutHead = zeroed();
    output.size = size_of::<OutHead>() as u32;
    // SAFETY: each test consumes exactly the instance its OPEN created, after its final crossing.
    assert_eq!(
        unsafe {
            table.head.close.unwrap()(
                instance,
                core::ptr::from_ref(&input).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
}

fn release(table: &Ops, instance: *mut core::ffi::c_void, lease: u64) {
    if lease == 0 {
        return;
    }
    let mut input: crate::abi::mechanism::lifecycle::ReleaseIn = zeroed();
    input.head.size = size_of_val(&input) as u32;
    input.head.op = slot::RELEASE;
    input.lease = lease;
    let mut output: OutHead = zeroed();
    output.size = size_of::<OutHead>() as u32;
    // SAFETY: return only the actual lease from this live instance's immediately preceding answer.
    assert_eq!(
        unsafe {
            table.head.release.unwrap()(
                instance,
                core::ptr::from_ref(&input).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
}

fn error_text(head: &OutHead) -> Option<String> {
    if head.error.len == 0 {
        return None;
    }
    // SAFETY: called while the actual SDK answer still owns its initialized diagnostic bytes.
    Some(
        std::str::from_utf8(unsafe { std::slice::from_raw_parts(head.error.ptr, head.error.len) })
            .unwrap()
            .to_owned(),
    )
}

/// A push sink's `scrape` and `serve` are REFUSED saying why, and its `status` is READY.
#[test]
fn a_push_sink_refuses_scrape_and_serve_in_the_kinds_words() {
    let table = ops();
    let instance = opened(table);
    let mut scrape: ScrapeIn = zeroed();
    scrape.head.size = size_of::<ScrapeIn>() as u32;
    scrape.head.op = crate::abi::export::slot::SCRAPE;
    let mut output: ScrapeOut = zeroed();
    output.head.size = size_of::<ScrapeOut>() as u32;
    // SAFETY: the live export instance and exact initialized SCRAPE frames are held through this call.
    assert_eq!(
        unsafe {
            table.scrape.unwrap()(
                instance,
                core::ptr::from_ref(&scrape).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Refused
    );
    assert_eq!(error_text(&output.head).as_deref(), Some(NO_EXPOSITION));
    assert_eq!(output.written, 0);
    release(table, instance, output.head.lease);

    let mut serve: ServeIn = zeroed();
    serve.head.size = size_of::<ServeIn>() as u32;
    serve.head.op = crate::abi::export::slot::SERVE;
    let mut output: ServeOut = zeroed();
    output.head.size = size_of::<ServeOut>() as u32;
    // SAFETY: the same live instance and exact initialized SERVE frames.
    assert_eq!(
        unsafe {
            table.serve.unwrap()(
                instance,
                core::ptr::from_ref(&serve).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Refused
    );
    assert_eq!(error_text(&output.head).as_deref(), Some(NO_ROUTE));
    release(table, instance, output.head.lease);

    let mut status: InHead = zeroed();
    status.size = size_of::<InHead>() as u32;
    status.op = crate::abi::export::slot::STATUS;
    let mut output: StatusOut = zeroed();
    output.head.size = size_of::<StatusOut>() as u32;
    // SAFETY: the actual STATUS slot accepts this exact head and writes a complete StatusOut.
    assert_eq!(
        unsafe {
            table.status.unwrap()(
                instance,
                core::ptr::from_ref(&status).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
    assert_eq!(error_text(&output.head), None);
    assert_eq!(output.status.len, 0);
    release(table, instance, output.head.lease);
    close(table, instance);
}

/// The `one_instance` check through the door: with more than one instance, the sink's one finding
#[test]
fn a_second_instance_is_answered_with_the_sinks_reason() {
    let table = ops();
    let instance = opened(table);
    let named = |names: &[&'static str]| -> Vec<u8> {
        let list: Vec<CheckInstance> = names
            .iter()
            .map(|&name| CheckInstance {
                name: abi_str(name),
                settings: Blob::ABSENT,
            })
            .collect();
        let mut input: CheckIn = zeroed();
        input.head.size = size_of::<CheckIn>() as u32;
        input.head.op = crate::abi::export::slot::CHECK;
        input.phase = CHECK_PHASE_LIMITS;
        input.instances = list.as_ptr();
        input.instances_len = list.len();
        let mut output: CheckOut = zeroed();
        output.head.size = size_of::<CheckOut>() as u32;
        // SAFETY: the owned initialized instance list remains live through the actual CHECK call.
        assert_eq!(
            unsafe {
                table.check.unwrap()(
                    instance,
                    core::ptr::from_ref(&input).cast(),
                    core::ptr::from_mut(&mut output).cast(),
                )
            }
            .outcome(),
            Outcome::Ready
        );
        let findings = if output.findings.len == 0 {
            Vec::new()
        } else {
            // SAFETY: the actual answer's live lease owns exactly the stated findings bytes.
            unsafe { std::slice::from_raw_parts(output.findings.ptr, output.findings.len) }.to_vec()
        };
        release(table, instance, output.head.lease);
        findings
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
    close(table, instance);
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
    // SAFETY: the actual exported static Statement and its static name bytes stay live.
    let descriptor = unsafe { &*plugin::door().statement() };
    let name = unsafe { std::slice::from_raw_parts(descriptor.name.ptr, descriptor.name.len) };
    assert_eq!(std::str::from_utf8(name).unwrap(), "probe-sink");
}

/// A called op keeps a copy of its envelope.
#[test]
fn a_called_op_keeps_a_copy_of_its_envelope() {
    let table = ops();
    let instance = opened(table);
    let mut input: DeliverIn = zeroed();
    input.head.size = size_of::<DeliverIn>() as u32;
    input.head.op = crate::abi::export::slot::DELIVER;
    let mut output: OutHead = zeroed();
    output.size = size_of::<OutHead>() as u32;
    // SAFETY: exact initialized DELIVER/OutHead frames on the instance this door opened.
    assert_eq!(
        unsafe {
            table.deliver.unwrap()(
                instance,
                core::ptr::from_ref(&input).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Ready
    );
    assert_eq!(output.envelope.diags_len, 1);
    assert!(!output.envelope.diags.is_null());
    assert_eq!(output.envelope.metrics_len, 1);
    assert!(!output.envelope.metrics.is_null());
    // SAFETY: the actual answer's live envelope owns both counted initialized arrays and texts.
    let diags =
        unsafe { std::slice::from_raw_parts(output.envelope.diags, output.envelope.diags_len) }
            .iter()
            .map(|diag| {
                let text = unsafe { std::slice::from_raw_parts(diag.text.ptr, diag.text.len) };
                (
                    diag.id_idx,
                    diag.severity,
                    std::str::from_utf8(text).unwrap().to_owned(),
                )
            })
            .collect::<Vec<_>>();
    let metrics =
        unsafe { std::slice::from_raw_parts(output.envelope.metrics, output.envelope.metrics_len) }
            .iter()
            .map(|metric| {
                assert_eq!(metric.label_vals_len, 0);
                (
                    metric.family_idx,
                    metric.kind,
                    metric.value,
                    Vec::<String>::new(),
                )
            })
            .collect::<Vec<_>>();
    release(table, instance, output.lease);
    // The SDK keeps this envelope until the next crossing or instance destruction, separately
    // from leased payloads. Retire its actual owner before checking our concrete owned copies.
    close(table, instance);
    assert_eq!(
        diags,
        vec![(
            crate::abi::mechanism::call::DIAG_LOG,
            crate::abi::mechanism::call::SEVERITY_INFO,
            DELIVERED.to_owned()
        )]
    );
    assert_eq!(
        metrics,
        vec![(0, crate::abi::mechanism::call::METRIC_ADD, 1.0, Vec::new())]
    );
}

/// A held operation with no instance returns the SDK's refusal.
#[test]
fn a_held_op_with_no_instance_answers_in_the_sdks_words() {
    let table = ops();
    let mut input: CheckIn = zeroed();
    input.head.size = size_of::<CheckIn>() as u32;
    input.head.op = crate::abi::export::slot::CHECK;
    input.phase = CHECK_PHASE_LIMITS;
    let mut output: CheckOut = zeroed();
    output.head.size = size_of::<CheckOut>() as u32;
    // SAFETY: the real SDK CHECK slot accepts NULL to produce its missing-instance refusal.
    assert_eq!(
        unsafe {
            table.check.unwrap()(
                core::ptr::null_mut(),
                core::ptr::from_ref(&input).cast(),
                core::ptr::from_mut(&mut output).cast(),
            )
        }
        .outcome(),
        Outcome::Refused
    );
    assert_eq!(error_text(&output.head).as_deref(), Some(NO_INSTANCE));
}

/// The SDK handles a sink that declares no refresh operation.
#[test]
fn a_sink_that_states_no_refresh_is_answered_by_the_sdk() {
    let Err(refused) = Probe.refresh(b"{}", &[], 2) else {
        panic!("the default refresh is refused");
    };
    assert_eq!(refused.outcome(), Outcome::Refused);
    assert_eq!(refused.text(), Some(NOT_REFRESHED));
}
