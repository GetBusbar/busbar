// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE: whole exchanges and streamed answers through `arrive` and `on_piece`.
//!
//! One unit is driven as the kernel's plane driver drives it: `arrive` (the caller's head and
//! body), the ATTEMPT piece (the plane writes the far-end request), the caller's body piece, then
//! the far end's answer: one whole piece, or a status piece and one piece per SSE event. Every unit
//! runs to its end (`EMIT_DONE`), so the plane's unit book is left empty, as on the real path.
//! Each crossing is timed as its own op; the bodies are 1 KiB / 8 KiB / 100 KiB OpenAI or
//! Anthropic requests and the answers are provider-shaped JSON and SSE events.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::OutHead;
use busbar_contract::abi::mechanism::call::{Field, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{GenIn, OpenIn};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    RecordWrite, UnitCount, EMIT_DONE, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS,
    PIECE_LAST,
};
use busbar_contract::json::{self, json, JsonContainerTrait, Value};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{ConnTable, Dispatcher, Frame, Plugin};

use crate::frames::{abi, fields, input, json as json_blob, octets, output, pairs};
use crate::stats::Recorder;
use crate::{Config, Scenario, Spec, Target};

const CAP: usize = 64;

struct Opened {
    plugin: Plugin<Plane>,
    _d: Arc<Dispatcher>,
}

// SAFETY: one opened plane instance is shared by the bench threads as core shares it between
// its connection tasks; every measured op is a `Plugin::answer` on it.
unsafe impl Sync for Opened {}
unsafe impl Send for Opened {}

fn default_settings() -> Value {
    json!({
        "providers": {
            "oai": {"protocol": "openai", "base_url": "https://openai.example"},
            "ant": {"protocol": "anthropic", "base_url": "https://anthropic.example"}
        },
        "models": {
            "gpt": {"provider": "oai"},
            "claude": {"provider": "ant"}
        },
        "pools": {
            "bench": {"members": ["gpt", "claude"]}
        }
    })
}

/// The settings blob keyed as the kernel hands it: `{section: settings}` when the plane declares a
/// keyed section (or consumes others), the settings themselves otherwise.
fn handed(plugin: &Plugin<Plane>, settings: &[u8]) -> Result<Vec<u8>, String> {
    let facts = plugin.served();
    let value: Value = json::parse_value(settings).map_err(|e| format!("plane settings: {e}"))?;
    let keyed =
        facts.section == busbar_contract::section::RESERVED_POOLS_KEY || !facts.consumed.is_empty();
    let already = value.as_object().is_some_and(|o| {
        o.contains_key(facts.section)
            && o.keys()
                .all(|k| k == facts.section || facts.consumed.contains(&k))
    });
    if !keyed || already {
        return Ok(settings.to_vec());
    }
    json::to_vec(&json!({ facts.section: value })).map_err(|e| e.to_string())
}

fn open(cfg: &Config, target: &Target) -> Result<Arc<Opened>, String> {
    let d = crate::dispatcher();
    let plugin = crate::load::<Plane>(target, crate::bind(&d, "bench-plane", ConnTable::Probe))?;
    let settings = match &cfg.settings {
        Some(s) => s.clone(),
        None => json::to_vec(&default_settings()).map_err(|e| e.to_string())?,
    };
    let settings = handed(&plugin, &settings)?;
    let mut f: Frame<PlaneOpenIn, PlaneOpenOut> = Frame::new(input(), output());
    let mut o: OpenIn = f.input.open;
    (o.generation, o.settings) = (1, json_blob(&settings));
    f.input.open = o;
    let (called, _snapshot) = plugin.answer_open(&mut f);
    if called.outcome != Outcome::Ready {
        return Err(format!(
            "plane open answered {:?}: {}",
            called.outcome,
            String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
        ));
    }
    plugin
        .ready(&d, std::time::Duration::from_secs(30))
        .map_err(|e| format!("plane ready: {e}"))?;
    for s in [slot::HYDRATE, slot::START] {
        let mut g: Frame<GenIn, OutHead> = Frame::new(input(), output());
        g.input.generation = 1;
        let _ = plugin.answer(s, &mut g);
    }
    Ok(Arc::new(Opened { plugin, _d: d }))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dialect {
    OpenAi,
    Anthropic,
}

impl Dialect {
    fn name(self) -> &'static str {
        match self {
            Dialect::OpenAi => "openai",
            Dialect::Anthropic => "anthropic",
        }
    }
    fn target(self) -> &'static str {
        match self {
            Dialect::OpenAi => "/v1/chat/completions",
            Dialect::Anthropic => "/v1/messages",
        }
    }
    fn caller_fields(self) -> Vec<(Vec<u8>, Vec<u8>)> {
        match self {
            Dialect::OpenAi => pairs(&[("content-type", "application/json")]),
            Dialect::Anthropic => pairs(&[
                ("content-type", "application/json"),
                ("anthropic-version", "2023-06-01"),
            ]),
        }
    }
}

/// A caller request of about `size` bytes, in the caller's dialect, naming the far end's model.
fn request(caller: Dialect, model: &str, size: usize, stream: bool) -> Vec<u8> {
    let mut v = json!({
        "model": model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": ""}],
    });
    match caller {
        Dialect::OpenAi => {
            v["messages"] = json!([
                {"role": "system", "content": "You are a concise assistant."},
                {"role": "user", "content": ""}
            ]);
            if stream {
                v["stream"] = json!(true);
                v["stream_options"] = json!({"include_usage": true});
            }
        }
        Dialect::Anthropic => {
            v["system"] = json!("You are a concise assistant.");
            if stream {
                v["stream"] = json!(true);
            }
        }
    }
    let base = json::to_vec(&v).expect("json").len();
    let words = "the quick brown fox jumps over the lazy dog ";
    let pad: String = words
        .chars()
        .cycle()
        .take(size.saturating_sub(base))
        .collect();
    let last = v["messages"].as_array().map_or(0, |a| a.len() - 1);
    v["messages"][last]["content"] = json!(pad);
    json::to_vec(&v).expect("json")
}

/// The far end's whole answer.
fn whole_answer(far: Dialect, model: &str) -> Vec<u8> {
    let text = "Here is a short answer with a handful of sentences. ".repeat(8);
    let v = match far {
        Dialect::OpenAi => json!({
            "id": "chatcmpl-bench", "object": "chat.completion", "created": 1_700_000_000,
            "model": model, "system_fingerprint": "fp_bench",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                         "logprobs": null, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 312, "completion_tokens": 96, "total_tokens": 408}
        }),
        Dialect::Anthropic => json!({
            "id": "msg_bench", "type": "message", "role": "assistant", "model": model,
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn", "stop_sequence": null,
            "usage": {"input_tokens": 312, "output_tokens": 96}
        }),
    };
    json::to_vec(&v).expect("json")
}

/// The far end's streamed answer: one SSE event per piece.
fn sse_events(far: Dialect, model: &str, deltas: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    match far {
        Dialect::OpenAi => {
            let chunk = |delta: Value, finish: Value| {
                let v = json!({
                    "id": "chatcmpl-bench", "object": "chat.completion.chunk",
                    "created": 1_700_000_000, "model": model, "system_fingerprint": "fp_bench",
                    "choices": [{"index": 0, "delta": delta, "logprobs": null, "finish_reason": finish}]
                });
                format!("data: {v}\n\n").into_bytes()
            };
            out.push(chunk(
                json!({"role": "assistant", "content": ""}),
                Value::new(),
            ));
            for i in 0..deltas {
                out.push(chunk(json!({"content": format!(" tok{i}")}), Value::new()));
            }
            out.push(chunk(json!({}), json!("stop")));
            let usage = json!({
                "id": "chatcmpl-bench", "object": "chat.completion.chunk",
                "created": 1_700_000_000, "model": model, "choices": [],
                "usage": {"prompt_tokens": 312, "completion_tokens": deltas, "total_tokens": 312 + deltas}
            });
            out.push(format!("data: {usage}\n\n").into_bytes());
            out.push(b"data: [DONE]\n\n".to_vec());
        }
        Dialect::Anthropic => {
            let ev = |name: &str, v: Value| format!("event: {name}\ndata: {v}\n\n").into_bytes();
            out.push(ev(
                "message_start",
                json!({"type": "message_start", "message": {
                "id": "msg_bench", "type": "message", "role": "assistant", "model": model,
                "content": [], "stop_reason": null, "stop_sequence": null,
                "usage": {"input_tokens": 312, "output_tokens": 1}}}),
            ));
            out.push(ev(
                "content_block_start",
                json!({"type": "content_block_start", "index": 0,
                "content_block": {"type": "text", "text": ""}}),
            ));
            for i in 0..deltas {
                out.push(ev(
                    "content_block_delta",
                    json!({"type": "content_block_delta", "index": 0,
                    "delta": {"type": "text_delta", "text": format!(" tok{i}")}}),
                ));
            }
            out.push(ev(
                "content_block_stop",
                json!({"type": "content_block_stop", "index": 0}),
            ));
            out.push(ev(
                "message_delta",
                json!({"type": "message_delta",
                "delta": {"stop_reason": "end_turn", "stop_sequence": null},
                "usage": {"output_tokens": deltas}}),
            ));
            out.push(ev("message_stop", json!({"type": "message_stop"})));
        }
    }
    out
}

pub(crate) fn specs(cfg: &Config, target: &Target) -> Result<Vec<Spec>, String> {
    let opened = open(cfg, target)?;
    let mut specs = Vec::new();
    let whole_ops = vec!["arrive", "attempt", "body", "far_whole"];
    let mut add_whole = |caller: Dialect, far: Dialect, size: usize| {
        let o = opened.clone();
        specs.push(Spec {
            name: format!(
                "plane.{}>{} whole {}",
                caller.name(),
                far.name(),
                size_label(size)
            ),
            ops: whole_ops.clone(),
            primary: 0,
            make: Box::new(move |t| {
                Ok(
                    Box::new(Exchange::new(o.clone(), t, caller, far, size, None)?)
                        as Box<dyn Scenario>,
                )
            }),
        });
    };
    for &size in &cfg.body_sizes {
        add_whole(Dialect::OpenAi, Dialect::OpenAi, size);
    }
    add_whole(Dialect::Anthropic, Dialect::Anthropic, 8 * 1024);
    add_whole(Dialect::OpenAi, Dialect::Anthropic, 8 * 1024);
    let deltas = cfg.deltas;
    for (caller, far) in [
        (Dialect::OpenAi, Dialect::OpenAi),
        (Dialect::Anthropic, Dialect::Anthropic),
        (Dialect::OpenAi, Dialect::Anthropic),
        (Dialect::Anthropic, Dialect::OpenAi),
    ] {
        let o = opened.clone();
        specs.push(Spec {
            name: format!("plane.{}>{} sse x{deltas}", caller.name(), far.name()),
            ops: vec!["arrive", "attempt", "body", "far_head", "sse_piece"],
            primary: 4,
            make: Box::new(move |t| {
                Ok(Box::new(Exchange::new(
                    o.clone(),
                    t,
                    caller,
                    far,
                    1024,
                    Some(deltas),
                )?) as Box<dyn Scenario>)
            }),
        });
    }
    Ok(specs)
}

fn size_label(n: usize) -> String {
    if n.is_multiple_of(1024) {
        format!("{}KiB", n / 1024)
    } else {
        format!("{n}B")
    }
}

/// One thread's exchange: every lent buffer allocated once, reused by every unit.
struct Exchange {
    opened: Arc<Opened>,
    next_unit: u64,
    member: Vec<u8>,
    method: Vec<u8>,
    target: Vec<u8>,
    _caller_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    caller_fields: Vec<Field>,
    body: Vec<u8>,
    _far_pairs: Vec<(Vec<u8>, Vec<u8>)>,
    far_fields: Vec<Field>,
    /// The whole answer, or the SSE events.
    answer: Vec<Vec<u8>>,
    streamed: bool,
    units: Box<[UnitCount; CAP]>,
    records: Box<[RecordWrite; CAP]>,
    out_fields: Box<[OutField; CAP]>,
    reply: Box<[u8]>,
    arena: Box<[u8]>,
}

fn zeroed<T>() -> T {
    // SAFETY: only used for the plain C output descriptors of this ABI, valid all-zero.
    unsafe { std::mem::zeroed() }
}

impl Exchange {
    fn new(
        opened: Arc<Opened>,
        thread: usize,
        caller: Dialect,
        far: Dialect,
        size: usize,
        deltas: Option<usize>,
    ) -> Result<Self, String> {
        let model = match far {
            Dialect::OpenAi => "gpt",
            Dialect::Anthropic => "claude",
        };
        let caller_pairs = caller.caller_fields();
        let far_pairs = if deltas.is_some() {
            pairs(&[("content-type", "text/event-stream")])
        } else {
            pairs(&[("content-type", "application/json")])
        };
        let mut x = Self {
            opened,
            next_unit: ((thread as u64 + 1) << 40) + 1,
            member: model.as_bytes().to_vec(),
            method: b"POST".to_vec(),
            target: caller.target().as_bytes().to_vec(),
            caller_fields: fields(&caller_pairs),
            _caller_pairs: caller_pairs,
            body: request(caller, model, size, deltas.is_some()),
            far_fields: fields(&far_pairs),
            _far_pairs: far_pairs,
            answer: match deltas {
                Some(n) => sse_events(far, model, n),
                None => vec![whole_answer(far, model)],
            },
            streamed: deltas.is_some(),
            units: Box::new([zeroed(); CAP]),
            records: Box::new([zeroed(); CAP]),
            out_fields: Box::new([zeroed(); CAP]),
            reply: vec![0; size * 2 + 256 * 1024].into_boxed_slice(),
            arena: vec![0; 64 * 1024].into_boxed_slice(),
        };
        // One unwarmed unit, unmeasured, proves the plugin serves this shape.
        let mut probe = Recorder::new(5, 0, u64::MAX, std::time::Instant::now(), 1, false);
        x.unit(&mut probe)
            .map_err(|e| format!("first unit (unmeasured): {e}"))?;
        Ok(x)
    }

    fn arrive_frame(&mut self, unit: u64) -> Frame<ArriveIn, ArriveOut> {
        let mut i: ArriveIn = input();
        (i.unit, i.claim) = (unit, 0);
        (i.method, i.target) = (abi(&self.method), abi(&self.target));
        (i.fields, i.fields_len) = (self.caller_fields.as_ptr(), self.caller_fields.len());
        i.body = octets(&self.body);
        (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), 4);
        Frame::new(i, output())
    }

    /// A piece frame over this thread's lent buffers.
    fn piece(
        &mut self,
        unit: u64,
        from: u32,
        flags: u32,
        bytes: &[u8],
        status: u32,
    ) -> Frame<OnPieceIn, OnPieceOut> {
        let mut i: OnPieceIn = input();
        (i.unit, i.from, i.flags, i.bytes) = (unit, from, flags, octets(bytes));
        i.member = abi(&self.member);
        i.attempt_no = u32::from(from == FROM_KERNEL);
        if flags & PIECE_HAS_STATUS != 0 {
            i.status_code = status;
            (i.head_fields, i.head_fields_len) = (self.far_fields.as_ptr(), self.far_fields.len());
        }
        (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
        (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), CAP);
        (i.records_buf, i.records_cap) = (self.records.as_mut_ptr(), CAP);
        (i.fields_buf, i.fields_cap) = (self.out_fields.as_mut_ptr(), CAP);
        (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
        Frame::new(i, output())
    }

    /// Cross one piece as op `op` (re-calling on backpressure, `more = 1`, as the kernel does):
    /// the answer's flags.
    fn cross(
        &mut self,
        rec: &mut Recorder,
        op: usize,
        unit: u64,
        from: u32,
        flags: u32,
        index: Option<usize>,
    ) -> Result<u32, String> {
        let status = if flags & PIECE_HAS_STATUS != 0 {
            200
        } else {
            0
        };
        let bytes: *const [u8] = match index {
            Some(k) => &self.answer[k][..],
            None if from == FROM_CALLER => &self.body[..],
            None => &[],
        };
        // SAFETY: `answer` and `body` are never written while a unit runs.
        let mut f = self.piece(unit, from, flags, unsafe { &*bytes }, status);
        let opened = self.opened.clone();
        let plugin = &opened.plugin;
        let mut seen = 0;
        loop {
            let called = rec.time(op, || plugin.answer(slot::ON_PIECE, &mut f));
            if called.outcome != Outcome::Ready {
                return Err(format!(
                    "on_piece ({}) answered {:?} fault={} faulted={}: {}",
                    ["arrive", "attempt", "body", "far", "sse"][op.min(4)],
                    called.outcome,
                    f.out.fault,
                    plugin.is_faulted(),
                    String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
                ));
            }
            seen |= f.out.flags;
            if crate::report::verbose() {
                eprintln!("[piece op={op} from={from} flags={flags:#x}] emitted={} more={} out.flags={:#x} status={} fields={} units={} reply={}", f.out.emitted, f.out.more, f.out.flags, f.out.reply_status, f.out.fields_written, f.out.units_written, String::from_utf8_lossy(&self.reply[..(f.out.emitted as usize).min(400)]));
            }
            if f.out.more == 0 {
                return Ok(seen);
            }
            // The backpressure re-call: the same `from`, no bytes, no flags.
            f = self.piece(unit, from, 0, &[], 0);
        }
    }
}

impl Scenario for Exchange {
    fn unit(&mut self, rec: &mut Recorder) -> Result<(), String> {
        let unit = self.next_unit;
        self.next_unit += 1;
        let mut f = self.arrive_frame(unit);
        let plugin = &self.opened.plugin;
        let called = rec.time(0, || plugin.answer(slot::ARRIVE, &mut f));
        if called.outcome != Outcome::Ready {
            return Err(format!(
                "arrive answered {:?} refusal={} status={}: {}",
                called.outcome,
                f.out.refusal,
                f.out.refusal_status,
                String::from_utf8_lossy(called.error.as_deref().unwrap_or_default())
            ));
        }
        self.cross(rec, 1, unit, FROM_KERNEL, 0, None)?;
        self.cross(rec, 2, unit, FROM_CALLER, PIECE_LAST, None)?;
        let done = if self.streamed {
            let last = self.answer.len() - 1;
            let mut seen = self.cross(rec, 3, unit, FROM_FAR_END, PIECE_HAS_STATUS, Some(0))?;
            for k in 1..=last {
                let flags = if k == last { PIECE_LAST } else { 0 };
                seen |= self.cross(rec, 4, unit, FROM_FAR_END, flags, Some(k))?;
            }
            seen
        } else {
            self.cross(
                rec,
                3,
                unit,
                FROM_FAR_END,
                PIECE_HAS_STATUS | PIECE_LAST,
                Some(0),
            )?
        };
        if done & EMIT_DONE == 0 {
            return Err(format!(
                "the unit never ended: its last piece answered flags={done:#x} without EMIT_DONE"
            ));
        }
        Ok(())
    }
}
