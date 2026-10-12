// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ANSWER'S FRAMING: one JSON-RPC answer re-framed as an event stream, with the log records
//! busbar writes about its own handling of the request riding ahead of it. Pure: the caller's
//! `Accept` value, its `_meta` and the finished answer in; the event-stream bytes out.
//!
//! A caller that did not ask for a stream is answered in JSON, unchanged: [`prefers_event_stream`]
//! is false for every `Accept` that puts `application/json` first, which is every MCP client that
//! has not deliberately asked otherwise. A caller that supplied a `progressToken` has asked for
//! progress, and a stream is the only shape progress can arrive in, so the token is itself a request
//! for one. Only a `200` whose body is one JSON document is re-framed; every other answer goes out as
//! it was written.
//!
//! The log records describe BUSBAR, never an upstream: an upstream's own records would arrive at
//! busbar's caller under busbar's name. Their `logger` is prefixed `busbar.` so that stays visible.

use serde_json::{json, Value};

/// The `_meta` key a caller names the least severe log level it wants with. An extension key under
/// busbar's own prefix: this revision has no `logging/setLevel` (no session to remember it in), so
/// the level rides the request it applies to.
pub const META_LOGGING_LEVEL: &str = "io.busbar/loggingLevel";

/// The level a caller that names none is given.
pub const DEFAULT_LEVEL: &str = "info";

/// The protocol's eight severities, least severe first.
const SEVERITIES: &[&str] = &[
    "debug",
    "info",
    "notice",
    "warning",
    "error",
    "critical",
    "alert",
    "emergency",
];

/// The head field that names an answer's media type.
pub const CONTENT_TYPE: &str = "content-type";

/// The head field a whole answer states its length in.
pub const CONTENT_LENGTH: &str = "content-length";

/// The head field that carries an event-stream answer's cache directive.
pub const CACHE_CONTROL: &str = "cache-control";

/// The media type of an event-stream answer.
pub const EVENT_STREAM: &str = "text/event-stream";

/// The media type of a JSON answer.
pub const JSON: &str = "application/json";

/// The cache directive an event-stream answer carries.
pub const NO_STORE: &str = "no-cache, no-store";

fn severity_of(name: &str) -> Option<usize> {
    SEVERITIES.iter().position(|s| *s == name)
}

/// One `notifications/message` record busbar writes about its own handling of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogRecord {
    /// Its severity.
    pub level: &'static str,
    /// Its logger, always under `busbar.`.
    pub logger: &'static str,
    /// What it says.
    pub data: Value,
}

impl LogRecord {
    fn envelope(&self) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/message",
            "params": {
                "level": self.level,
                "logger": self.logger,
                "data": self.data,
            },
        })
    }
}

/// The least severe level the caller asked for in `_meta`, or [`DEFAULT_LEVEL`]. A level the
/// protocol does not name is the default, never a refusal: the caller asked for a stream, and an
/// unknown filter is not a reason to deny it one.
#[must_use]
pub fn requested_level(meta: Option<&Value>) -> &'static str {
    let named = meta
        .and_then(|m| m.get(META_LOGGING_LEVEL))
        .and_then(|v| v.as_str());
    match named.and_then(severity_of) {
        Some(i) => SEVERITIES[i],
        None => DEFAULT_LEVEL,
    }
}

/// Whether a record at `level` passes a caller that asked for `requested`. An unknown name on
/// either side passes: the filter only ever removes what it can place.
#[must_use]
pub fn level_allows(requested: &str, level: &str) -> bool {
    match (severity_of(requested), severity_of(level)) {
        (Some(min), Some(at)) => at >= min,
        _ => true,
    }
}

/// Whether the caller's `Accept` value prefers an event stream to JSON: by quality, then by
/// position, and never when the stream is listed at `q=0` or not at all.
#[must_use]
pub fn prefers_event_stream(accept: Option<&str>) -> bool {
    let Some(accept) = accept else {
        return false;
    };
    let mut sse: Option<(f32, usize)> = None;
    let mut json: Option<(f32, usize)> = None;
    for (position, entry) in accept.split(',').enumerate() {
        let mut parts = entry.split(';');
        let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let q = parts
            .filter_map(|p| p.trim().strip_prefix("q=").map(str::trim))
            .find_map(|v| v.parse::<f32>().ok())
            .unwrap_or(1.0);
        match media.as_str() {
            EVENT_STREAM => sse = sse.or(Some((q, position))),
            JSON => json = json.or(Some((q, position))),
            _ => {}
        }
    }
    let Some((sse_q, sse_pos)) = sse else {
        return false;
    };
    if sse_q <= 0.0 {
        return false;
    }
    match json {
        None => true,
        Some((json_q, json_pos)) => {
            if (sse_q - json_q).abs() > f32::EPSILON {
                sse_q > json_q
            } else {
                sse_pos < json_pos
            }
        }
    }
}

/// The two records busbar writes about one request: what was dispatched (`debug`) and how it ended
/// (`info` on a `200`, else `warning`). `target` is the request's `Mcp-Name` member, where its
/// method has one.
#[must_use]
pub fn request_log(method: &str, target: Option<Value>, status: u32) -> Vec<LogRecord> {
    let ok = status == 200;
    vec![
        LogRecord {
            level: "debug",
            logger: "busbar.mcp.dispatch",
            data: json!({
                "message": "dispatching MCP method",
                "method": method,
                "target": target,
            }),
        },
        LogRecord {
            level: if ok { "info" } else { "warning" },
            logger: "busbar.mcp.dispatch",
            data: json!({
                "message": if ok { "MCP method completed" } else { "MCP method refused" },
                "method": method,
                "httpStatus": status,
            }),
        },
    ]
}

/// One answer as an event stream: each progress frame, then each log record, then the answer, one
/// `message` event each. `None` when `body` is not one JSON document (it goes out as it was).
#[must_use]
pub fn event_stream(body: &[u8], logs: &[LogRecord], progress: &[Value]) -> Option<Vec<u8>> {
    let result = serde_json::from_slice::<Value>(body).ok()?;
    let mut out = String::new();
    for frame in progress {
        push_event(&mut out, frame);
    }
    for log in logs {
        push_event(&mut out, &log.envelope());
    }
    push_event(&mut out, &result);
    Some(out.into_bytes())
}

/// Messages as an event stream: one `message` event each, in order.
#[must_use]
pub fn events(frames: &[Value]) -> Vec<u8> {
    let mut out = String::new();
    for frame in frames {
        push_event(&mut out, frame);
    }
    out.into_bytes()
}

fn push_event(out: &mut String, value: &Value) {
    use std::fmt::Write as _;
    let _ = write!(
        out,
        "event: message\ndata: {}\n\n",
        serde_json::to_string(value).unwrap_or_else(|_| "null".to_string())
    );
}

/// How one request's answer is framed, decided at its arrival.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Framing {
    /// The method, for the log records.
    pub method: String,
    /// The `Mcp-Name` member's value, for the log records.
    pub target: Option<Value>,
    /// The least severe level the caller asked for.
    pub level: &'static str,
    /// Whether the caller asked for the frames only a stream carries (its log records and progress).
    pub stream: bool,
}

impl Framing {
    /// The framing a request arriving with `accept` and `body` asks for; `None` = JSON.
    #[must_use]
    pub fn of(accept: Option<&str>, method: &str, body: &Value) -> Option<Self> {
        let meta = body.get("params").and_then(|p| p.get("_meta"));
        let asked_for_progress = meta
            .and_then(|m| m.get("progressToken"))
            .is_some_and(|v| !v.is_null());
        if !prefers_event_stream(accept) && !asked_for_progress {
            return None;
        }
        let target = crate::codec::name_source_of(method)
            .and_then(|source| body.get("params").and_then(|p| p.get(source)).cloned());
        Some(Framing {
            method: method.to_string(),
            target,
            level: requested_level(meta),
            stream: true,
        })
    }

    /// The answer `(status, body)` framed: a `200` with a JSON body as an event stream with its log
    /// records and `progress`, and `true`; anything else as it was, and `false`.
    #[must_use]
    pub fn frame(&self, status: u32, body: Vec<u8>, progress: &[Value]) -> (Vec<u8>, bool) {
        if status != 200 {
            return (body, false);
        }
        let logs: Vec<LogRecord> = request_log(&self.method, self.target.clone(), status)
            .into_iter()
            .filter(|r| level_allows(self.level, r.level))
            .collect();
        match event_stream(&body, &logs, progress) {
            Some(stream) => (stream, true),
            None => (body, false),
        }
    }
}

#[cfg(test)]
#[path = "tests/framing.rs"]
mod tests;
