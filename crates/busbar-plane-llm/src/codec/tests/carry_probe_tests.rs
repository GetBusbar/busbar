// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CARRY PROBE (DF-MAP per-dialect audit, design F3/F4): which wire paths a dialect actually maps
//! through the IR, MEASURED rather than read off the code.
//!
//! For every scalar path of the dialect's wire lock (`testing/llm-conformance/wire/<lock>.wire.json`),
//! request and buffered response: plant a unique marker at that path in a minimal valid body, read it,
//! clear the request's `extra` (exactly what the cross-dialect seam does), write it back in the SAME
//! dialect, and look for the marker at the same path. A survivor is a path the dialect maps into and
//! out of the IR, so its map file must declare it; a loss is either a field with no IR home (a
//! no-equivalent mark, or a slot) or a miss. One line per path on stdout:
//! `PROBE\t<lock>\t<direction>\t<path>\t<carried|lost|refused>`.
//!
//! A measurement, not a gate: `#[ignore]`d, run on demand with
//! `cargo test -p busbar-plane-llm --lib carry_probe -- --ignored --nocapture`.

use serde_json::{json, Map, Value};

use crate::codec::proto_codec::protocol_for;

/// One segment of a wire path in notation A.
#[derive(Debug, Clone)]
enum Seg {
    Key(String),
    Each(String, bool),
    Arm(String, String),
}

fn segments(path: &str) -> Vec<Seg> {
    path.split('.')
        .map(|s| {
            if let Some((t, a)) = s.split_once('=') {
                Seg::Arm(t.to_string(), a.to_string())
            } else if let Some(n) = s.strip_suffix("{}[]") {
                Seg::Each(n.to_string(), true)
            } else if let Some(n) = s.strip_suffix("[]") {
                Seg::Each(n.to_string(), false)
            } else if let Some(n) = s.strip_suffix("{}") {
                Seg::Each(n.to_string(), true)
            } else {
                Seg::Key(s.to_string())
            }
        })
        .collect()
}

/// The first scalar type of a lock entry's `type` (`null|string` is `string`), or `None` for a
/// container.
fn scalar(entry: &Value) -> Option<&'static str> {
    let ty = entry.get("type")?.as_str()?;
    ["string", "integer", "number", "boolean"]
        .into_iter()
        .find(|t| ty.split('|').any(|p| p == *t))
}

/// The marker planted at path number `n`.
fn marker(entry: &Value, n: usize) -> Option<Value> {
    if let Some(first) = entry
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|e| e.first())
    {
        return Some(first.clone());
    }
    Some(match scalar(entry)? {
        "string" => json!(format!("mk{n}x")),
        "integer" => json!(7000 + n),
        "number" => json!(n as f64 + 0.25),
        _ => json!(true),
    })
}

/// A sample value for a sibling the probe fills so the planted object is well-formed.
fn sample(entry: &Value) -> Option<Value> {
    if let Some(first) = entry
        .get("enum")
        .and_then(Value::as_array)
        .and_then(|e| e.first())
    {
        return Some(first.clone());
    }
    Some(match scalar(entry)? {
        "string" => json!("s"),
        "integer" => json!(1),
        "number" => json!(0.5),
        _ => json!(false),
    })
}

/// Fill every scalar child of `prefix` the lock lists into `obj`, where `obj` lacks it.
fn fill_siblings(obj: &mut Map<String, Value>, prefix: &str, lock: &Map<String, Value>) {
    for (p, e) in lock {
        let Some(rest) = p.strip_prefix(prefix).and_then(|r| r.strip_prefix('.')) else {
            continue;
        };
        if rest.contains(['.', '[', '{', '=']) || obj.contains_key(rest) {
            continue;
        }
        if let Some(v) = sample(e) {
            obj.insert(rest.to_string(), v);
        }
    }
}

/// Plant `value` at `path` into `root`, building the structure it names (a NEW array element at
/// every `[]`), with each built object's scalar siblings filled from the lock.
fn plant(root: &mut Value, path: &str, value: Value, lock: &Map<String, Value>) {
    let segs = segments(path);
    let mut cur = root;
    let mut prefix = String::new();
    for (i, seg) in segs.iter().enumerate() {
        let last = i + 1 == segs.len();
        let text = match seg {
            Seg::Key(k) => k.clone(),
            Seg::Each(k, true) => format!("{k}{{}}"),
            Seg::Each(k, false) => format!("{k}[]"),
            Seg::Arm(t, a) => format!("{t}={a}"),
        };
        prefix = if prefix.is_empty() {
            text
        } else {
            format!("{prefix}.{text}")
        };
        match seg {
            Seg::Key(k) => {
                let Some(obj) = cur.as_object_mut() else {
                    return;
                };
                if last {
                    obj.insert(k.clone(), value);
                    return;
                }
                let child = obj.entry(k.clone()).or_insert_with(|| json!({}));
                if !child.is_object() {
                    *child = json!({});
                }
                if let Some(o) = child.as_object_mut() {
                    fill_siblings(o, &prefix, lock);
                }
                cur = child;
            }
            Seg::Each(k, map) => {
                let Some(obj) = cur.as_object_mut() else {
                    return;
                };
                let elem = if last { value.clone() } else { json!({}) };
                let slot =
                    obj.entry(k.clone()).or_insert_with(
                        || {
                            if *map {
                                json!({})
                            } else {
                                json!([])
                            }
                        },
                    );
                let next = if *map {
                    if !slot.is_object() {
                        *slot = json!({});
                    }
                    let m = slot.as_object_mut().expect("object");
                    m.insert("k0".to_string(), elem);
                    m.get_mut("k0").expect("k0")
                } else {
                    if !slot.is_array() {
                        *slot = json!([]);
                    }
                    let a = slot.as_array_mut().expect("array");
                    a.push(elem);
                    a.last_mut().expect("pushed")
                };
                if last {
                    return;
                }
                if let Some(o) = next.as_object_mut() {
                    fill_siblings(o, &prefix, lock);
                }
                cur = next;
            }
            Seg::Arm(t, a) => {
                let Some(obj) = cur.as_object_mut() else {
                    return;
                };
                obj.insert(t.clone(), json!(a));
                fill_siblings(obj, &prefix, lock);
                if last {
                    return;
                }
            }
        }
    }
}

/// Every value found at `path` in `v`.
fn at<'a>(v: &'a Value, segs: &[Seg], out: &mut Vec<&'a Value>) {
    let Some((seg, rest)) = segs.split_first() else {
        out.push(v);
        return;
    };
    match seg {
        Seg::Key(k) => {
            if let Some(c) = v.get(k) {
                at(c, rest, out);
            }
        }
        Seg::Each(k, _) => match v.get(k) {
            Some(Value::Array(a)) => a.iter().for_each(|e| at(e, rest, out)),
            Some(Value::Object(m)) => m.values().for_each(|e| at(e, rest, out)),
            _ => {}
        },
        Seg::Arm(t, a) => {
            if v.get(t).and_then(Value::as_str) == Some(a.as_str()) {
                at(v, rest, out);
            }
        }
    }
}

fn same(a: &Value, b: &Value) -> bool {
    a == b || matches!((a.as_f64(), b.as_f64()), (Some(x), Some(y)) if x == y)
}

/// The probe's minimal valid request and answer for each lock.
fn bases(lock: &str) -> (Value, Value) {
    match lock {
        "anthropic" => (
            json!({"model": "m", "max_tokens": 64, "messages": [{"role": "user", "content": "hi"}]}),
            json!({"id": "msg_1", "type": "message", "role": "assistant", "model": "m",
                   "content": [{"type": "text", "text": "hi"}], "stop_reason": "end_turn",
                   "stop_sequence": null, "usage": {"input_tokens": 1, "output_tokens": 1}}),
        ),
        "openai" => (
            json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
            json!({"id": "c1", "object": "chat.completion", "created": 1, "model": "m",
                   "choices": [{"index": 0, "message": {"role": "assistant", "content": "hi"},
                                "finish_reason": "stop"}],
                   "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}}),
        ),
        "responses" => (
            json!({"model": "m", "input": "hi"}),
            json!({"id": "r1", "object": "response", "created_at": 1, "model": "m",
                   "status": "completed",
                   "output": [{"type": "message", "id": "m1", "status": "completed",
                               "role": "assistant",
                               "content": [{"type": "output_text", "text": "hi",
                                            "annotations": []}]}],
                   "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}),
        ),
        "gemini" => (
            json!({"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}),
            json!({"candidates": [{"content": {"role": "model", "parts": [{"text": "hi"}]},
                                   "finishReason": "STOP", "index": 0}],
                   "usageMetadata": {"promptTokenCount": 1, "candidatesTokenCount": 1,
                                     "totalTokenCount": 2}}),
        ),
        "bedrock" => (
            json!({"messages": [{"role": "user", "content": [{"text": "hi"}]}]}),
            json!({"output": {"message": {"role": "assistant", "content": [{"text": "hi"}]}},
                   "stopReason": "end_turn",
                   "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                   "metrics": {"latencyMs": 1}}),
        ),
        _ => (
            json!({"model": "m", "messages": [{"role": "user", "content": "hi"}]}),
            json!({"id": "c1", "finish_reason": "COMPLETE",
                   "message": {"role": "assistant", "content": [{"type": "text", "text": "hi"}]},
                   "usage": {"billed_units": {"input_tokens": 1, "output_tokens": 1},
                             "tokens": {"input_tokens": 1, "output_tokens": 1}}}),
        ),
    }
}

fn probe(lock_name: &str) {
    let path = format!(
        "{}/../../testing/llm-conformance/wire/{lock_name}.wire.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let lock: Value =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("lock")).expect("lock json");
    let proto = protocol_for(lock_name).expect("registered dialect");
    let (req_base, resp_base) = bases(lock_name);
    for dir in ["request", "response"] {
        let Some(paths) = lock.get(dir).and_then(Value::as_object) else {
            continue;
        };
        for (n, (p, entry)) in paths.iter().enumerate() {
            let Some(mark) = marker(entry, n) else {
                continue;
            };
            let mut body = if dir == "request" {
                req_base.clone()
            } else {
                resp_base.clone()
            };
            plant(&mut body, p, mark.clone(), paths);
            let reader = proto.reader();
            let writer = proto.writer();
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if dir == "request" {
                    reader.read_request(&body).map(|mut req| {
                        req.extra.clear();
                        writer.write_request(&req)
                    })
                } else {
                    reader
                        .read_response(&body)
                        .map(|resp| writer.write_response(&resp))
                }
            }));
            let verdict = match out {
                Ok(Ok(written)) => {
                    let mut found = Vec::new();
                    at(&written, &segments(p), &mut found);
                    if found.iter().any(|v| same(v, &mark)) {
                        "carried"
                    } else {
                        "lost"
                    }
                }
                Ok(Err(_)) => "refused",
                Err(_) => "panicked",
            };
            println!("PROBE\t{lock_name}\t{dir}\t{p}\t{verdict}");
        }
    }
}

#[test]
#[ignore = "a measurement: run with --ignored --nocapture"]
fn carry_probe_every_dialect() {
    for lock in [
        "anthropic",
        "openai",
        "responses",
        "gemini",
        "bedrock",
        "cohere",
    ] {
        probe(lock);
    }
}
