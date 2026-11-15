// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EXPORT: `deliver` of `traces` batches, each carried to an in-memory far end.
//!
//! The instance is opened with the loader's own lifecycle (`ExportInstance::open`: validate, OPEN
//! with the settings, recorder check; then `start`, the instance's READY). Its bind carries a host
//! connection table ([`SinkConns`]), so the need its Statement declares is admitted against the
//! settings' target exactly as the host admits it. The far end is in memory: it takes each framed
//! request whole and answers `200` with an empty body, so a delivery completes inside its one
//! crossing (no PENDING, no socket).
//!
//! On the real path the kernel's traces producer queues ONE line per closed span and the export
//! flusher hands batches to `deliver` on a dispatcher worker ticket. Per openai→openai request the
//! kernel closes three spans (`forward`, `request_attempts`, one `forward_once` per attempt), each a
//! span record (projected fields plus the full `span` object), so the measured batches are:
//!
//! - `1 span`: the flusher's batch when it keeps up (it takes `ceil(queued / room)` lines);
//! - `1 req (3 spans)`: one request's worth;
//! - `256 spans`: `MAX_BATCH_LINES`, the flusher's batch under load.
//!
//! `deliver` is TICKET-BOUND: the SDK's `exchange()` may pend on the host, so on a ticketless
//! `Plugin::answer` the connector refuses it ("the call runs on no ticket and cannot pend") and the
//! batch is dropped. Every delivery therefore crosses inline on the loader's inline-ticket path
//! (`Plugin::answer_inline` under a fresh ticket, standing in for the worker ticket the flusher's
//! `Ticketed` call carries; no worker hop): `deliver` is that one crossing. Retiring the ticket
//! (the connector forgets what it kept under it) and minting the next delivery's is its own op,
//! `ticket`, outside `deliver`. The answer's lease is released inside `deliver`'s crossing.

use std::sync::Arc;

use busbar_contract::abi::export::{slot, DeliverIn};
use busbar_contract::export_stream::ExportStream;
use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_JSONL};
use busbar_contract::conn::admissions::AdmissionAuthority;
use busbar_contract::export_calls::ExportCalls;
use busbar_plugin_loader::dispatch::kinds::export::Export;
use busbar_plugin_loader::dispatch::{ConnTable, Dispatcher, Frame, InlineTicket, Plugin};
use busbar_plugin_loader::export_door::ExportInstance;
use serde_json::{json, Value};

use crate::frames::{input, output};
use crate::host::SinkConns;
use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

/// The flusher's largest batch (`export_door::MAX_BATCH_LINES`).
const MAX_BATCH: usize = busbar_plugin_loader::export_door::MAX_BATCH_LINES;

struct Opened {
    instance: ExportInstance,
    conns: Arc<SinkConns>,
    d: Arc<Dispatcher>,
}

// SAFETY: one opened export instance is shared by the bench threads as the export flusher shares
// it between its in-flight deliveries; every measured op is a `Plugin::answer_inline` on it.
unsafe impl Sync for Opened {}
unsafe impl Send for Opened {}

impl Opened {
    fn plugin(&self) -> &Plugin<Export> {
        self.instance.plugin()
    }
}

fn default_settings() -> Value {
    json!({ "url": "https://collector.bench.invalid:4318/v1/traces" })
}

fn open(cfg: &Config, target: &Target) -> Result<Arc<Opened>, String> {
    let d = crate::dispatcher();
    let conns = Arc::new(SinkConns::default());
    let authority = AdmissionAuthority::issue(
        &busbar_contract::caps::KernelSeal::acquire_for_kernel(),
        conns.clone(),
        Default::default(),
    );
    let plugin = crate::load::<Export>(
        target,
        crate::bind(&d, "bench-export", ConnTable::Host(authority)),
    )?;
    let settings = match &cfg.settings {
        Some(s) => s.clone(),
        None => serde_json::to_vec(&default_settings()).map_err(|e| e.to_string())?,
    };
    let instance = ExportInstance::open(plugin, d.clone(), &settings)
        .map_err(|e| format!("export open: {e}"))?;
    instance.start().map_err(|e| format!("export ready: {e}"))?;
    if !instance.streams().contains(&(ExportStream::Traces as u8)) {
        return Err(format!(
            "the export plugin carries streams {:?}, not traces (the only workload here)",
            instance.streams()
        ));
    }
    if !instance.takes_span_records() && crate::report::verbose() {
        eprintln!("[export] the plugin takes projected records only; span records sent anyway");
    }
    Ok(Arc::new(Opened { instance, conns, d }))
}

/// One closed span as the kernel's traces producer writes it: the projected default fields, plus
/// the full `span` record (ids, times, attributes, events, status) for a span-record sink.
fn span_line(
    name: &str,
    ids: (u64, u64, Option<u64>),
    projected: &[(&str, Value)],
    attributes: &[(&str, Value)],
) -> Vec<u8> {
    let hex = |id: u64| Value::from(format!("{id:016x}"));
    let (trace, own, parent) = ids;
    let start_us: u64 = 1_700_000_000_123_456 + own * 10;
    let mut line = serde_json::Map::new();
    line.insert("trace_id".into(), hex(trace));
    line.insert("span_id".into(), hex(own));
    if let Some(p) = parent {
        line.insert("parent_span_id".into(), hex(p));
    }
    line.insert("name".into(), Value::from(name));
    line.insert("start".into(), Value::from(start_us));
    line.insert("duration_us".into(), Value::from(1_843u64));
    for (k, v) in projected {
        line.insert((*k).into(), v.clone());
    }
    let mut attrs: Vec<Value> = vec![
        json!({"key": "code.file.path", "value": "crates/busbar-kernel/src/plane_driver/route.rs"}),
        json!({"key": "code.module.name", "value": "busbar_kernel::plane_driver::route"}),
        json!({"key": "code.line.number", "value": 1099}),
        json!({"key": "thread.id", "value": 14}),
        json!({"key": "thread.name", "value": "tokio-runtime-worker"}),
        json!({"key": "target", "value": "busbar::proxy::engine::walk"}),
    ];
    attrs.extend(
        attributes
            .iter()
            .map(|(k, v)| json!({"key": k, "value": v})),
    );
    attrs.push(json!({"key": "busy_ns", "value": 412_337}));
    attrs.push(json!({"key": "idle_ns", "value": 1_430_118}));
    let mut span = serde_json::Map::new();
    span.insert("trace_id".into(), hex(trace));
    span.insert("span_id".into(), hex(own));
    if let Some(p) = parent {
        span.insert("parent_span_id".into(), hex(p));
    }
    span.insert("name".into(), Value::from(name));
    span.insert("start_ns".into(), Value::from(start_us * 1000));
    span.insert("end_ns".into(), Value::from(start_us * 1000 + 1_843_000));
    span.insert("attributes".into(), Value::Array(attrs));
    span.insert("events".into(), Value::Array(Vec::new()));
    span.insert("status".into(), json!({"code": "unset", "message": ""}));
    line.insert("span".into(), Value::Object(span));
    serde_json::to_vec(&Value::Object(line)).expect("json")
}

/// One openai→openai request's three span records (closing order: innermost first).
fn request_lines(n: u64) -> [Vec<u8>; 3] {
    let trace = 0x5eed_0000_0000_0000 | (n * 3 + 1);
    let (forward, attempts, once) = (trace, trace + 1, trace + 2);
    [
        span_line(
            "forward_once",
            (trace, once, Some(attempts)),
            &[("lane", json!("lane-a"))],
            &[
                ("lane", json!("lane-a")),
                ("degraded", json!(false)),
                ("unit_id", json!(1_099_511_627_777u64)),
                ("attempt", json!(1)),
                ("route_wait_us", json!(3)),
                ("response_ready_us", json!(1_204)),
                ("first_body_us", json!(1_207)),
                ("far_end_last_us", json!(1_788)),
                ("producer_complete_us", json!(1_801)),
                ("attempt_end_us", json!(1_839)),
                ("outcome", json!("ok")),
                ("timing_profile", json!("observed-pump-v1")),
                ("first_token", json!("unavailable")),
                ("content_policy", json!("identity-and-timing-only")),
                ("sampling", json!("all-enabled-attempts")),
                ("delivery", json!("bounded-best-effort")),
            ],
        ),
        span_line(
            "request_attempts",
            (trace, attempts, Some(forward)),
            &[],
            &[
                ("unit_id", json!(1_099_511_627_777u64)),
                ("request_id", json!(48_211)),
            ],
        ),
        span_line(
            "forward",
            (trace, forward, None),
            &[
                ("pool", json!("bench")),
                ("ingress", json!("openai")),
                ("op", json!("chat")),
            ],
            &[
                ("pool", json!("bench")),
                ("ingress", json!("openai")),
                ("op", json!("chat")),
                ("request_id", json!(48_211)),
            ],
        ),
    ]
}

/// `spans` span records as one JSON-lines batch (requests' worth of lines, cut to `spans`).
fn batch(spans: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut n = 0u64;
    'fill: loop {
        for line in request_lines(n) {
            if out.iter().filter(|b| **b == b'\n').count() == spans {
                break 'fill;
            }
            out.extend_from_slice(&line);
            out.push(b'\n');
        }
        n += 1;
    }
    out
}

pub(crate) fn specs(cfg: &Config, target: &Target) -> Result<Vec<Spec>, String> {
    let opened = open(cfg, target)?;
    let mut specs = Vec::new();
    for (label, spans) in [
        ("1 span", 1),
        ("1 req (3 spans)", 3),
        ("256 spans", MAX_BATCH),
    ] {
        let o = opened.clone();
        let bytes = batch(spans).len();
        specs.push(Spec {
            name: format!("export.deliver({label}, {bytes}B)"),
            ops: vec!["deliver", "ticket"],
            primary: 0,
            make: Box::new(move |t| {
                Ok(Box::new(Deliver::new(o.clone(), t, spans)?) as Box<dyn Scenario>)
            }),
        });
    }
    Ok(specs)
}

/// One thread's deliveries: the batch built once, the frame rebuilt in place per call.
struct Deliver {
    opened: Arc<Opened>,
    batch: Box<[u8]>,
    op: u64,
    /// The next delivery's ticket, minted when the previous one retired.
    ticket: Option<InlineTicket>,
}

impl Deliver {
    fn new(opened: Arc<Opened>, thread: usize, spans: usize) -> Result<Self, String> {
        let mut d = Self {
            opened,
            batch: batch(spans).into_boxed_slice(),
            op: (thread as u64 + 1) << 40,
            ticket: None,
        };
        d.ticket = Some(
            d.opened
                .d
                .inline_ticket()
                .ok_or("no inline ticket could be minted")?,
        );
        // One delivery, unmeasured: proves the run is admitted (the far end's first answer
        // settles it) and the batch encodes to a request that reaches the far end.
        let mut probe = Recorder::new(2, 0, u64::MAX, std::time::Instant::now(), 1, false);
        d.unit(&mut probe)
            .map_err(|e| format!("first delivery (unmeasured): {e}"))?;
        if crate::report::verbose() {
            eprintln!(
                "[export] thread {thread}: {} spans = {} B per batch; far end has taken {} requests, {} B",
                spans,
                d.batch.len(),
                d.opened.conns.opened.load(std::sync::atomic::Ordering::Relaxed),
                d.opened.conns.bytes.load(std::sync::atomic::Ordering::Relaxed),
            );
        }
        Ok(d)
    }

    fn frame(&mut self) -> Frame<DeliverIn, OutHead> {
        self.op += 1;
        let mut i: DeliverIn = input();
        i.op_id[..8].copy_from_slice(&self.op.to_le_bytes());
        i.op_id[8..].copy_from_slice(b"benchexp");
        i.stream = ExportStream::Traces as u8;
        i.batch = Blob {
            ptr: self.batch.as_ptr(),
            len: self.batch.len(),
            fmt: BLOB_JSONL,
            flags: 0,
        };
        Frame::new(i, output())
    }
}

impl Scenario for Deliver {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let mut f = self.frame();
        let opened = self.opened.clone();
        let plugin = opened.plugin();
        let ticket = self.ticket.take().ok_or("no ticket held")?;
        let t = ticket.ticket();
        let before = SinkConns::opened_here();
        let called = rec.time(0, || plugin.answer_inline(t, false, slot::DELIVER, &mut f));
        if called.outcome != Outcome::Ready {
            return Err(format!(
                "deliver answered {:?} (faulted={}): {}",
                called.outcome,
                plugin.is_faulted(),
                String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
            ));
        }
        // Retire this delivery's ticket (the connector forgets what it kept under it) and mint
        // the next delivery's: each batch the flusher hands on takes a fresh ticket.
        self.ticket = rec.time(1, || {
            drop(ticket);
            opened.d.inline_ticket()
        });
        if self.ticket.is_none() {
            return Err("no inline ticket could be minted".into());
        }
        let carried = SinkConns::opened_here() - before;
        if carried != 1 {
            return Err(format!(
                "deliver answered READY but carried {carried} requests to the far end (1 expected: \
                 a run the far end refused, or a batch that encoded to nothing)"
            ));
        }
        Ok(())
    }
}
