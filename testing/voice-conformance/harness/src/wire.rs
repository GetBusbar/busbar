// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HARNESS'S OWN WIRE READER (ARCHITECT ruling R-18). The harness is a black-box rig: it reads
//! the two duplex dialects' frames itself and never calls the plane's codec or splice, because
//! computing what the door owes with the plane's own code would be circular. Everything here is
//! written from the dialects' published wire shapes and from the session rules the plane states
//! (`streams:`'s locked session and its token ceilings), never from the plane's source.
//!
//! * [`read_up`] / [`read_down`]: a frame's concepts ([`Norm`]), from its `type` (OpenAI Realtime)
//!   or its one top-level key (Gemini Live).
//! * [`usage`]: the token classes a far end's usage report bills.
//! * [`owed`] / [`relayed_as_owed`]: what the door owes the far end for a caller frame. A frame that
//!   configures the session or asks for a response is GOVERNED and is judged at the JSON level (cut
//!   members absent, locked members equal, caps applied, every other member unchanged and in the
//!   same order); every other frame is owed byte for byte. The byte-level splice proof is the
//!   plane's own (`splice_tests`).
//! * [`Node`]: a JSON value whose objects keep their members in document order (this workspace's
//!   `serde_json` sorts a map's keys), so "in the same order" can be judged at all.

use busbar_contract::media::base64_decode;
use serde_json::{Map, Value};

use crate::codec_legs::Dialect;

// ── the shared normal form ──────────────────────────────────────────────────────────────────────

/// Both directions' concepts on one list, so they compare uniformly.
#[derive(Clone, Debug, PartialEq)]
pub enum Norm {
    /// Config essentials only: instructions|voice|tools|max (the survivable fields).
    Config(String),
    /// The configured modalities.
    ConfigModalities(Vec<String>),
    /// The session's acknowledgement.
    Connect,
    /// Uplink audio.
    AudioUp(Vec<u8>),
    /// Downlink audio.
    AudioDown(Vec<u8>),
    /// An item's audio is done.
    AudioDone,
    /// A conversation item.
    Item(Value),
    /// Speech began.
    SpeechStart,
    /// Speech stopped.
    SpeechStop,
    /// A truncate, at the ms heard.
    Truncate(u64),
    /// Commit the uplink.
    Commit,
    /// Clear the uplink.
    Clear,
    /// Ask for a response.
    ResponseCreate,
    /// Cancel the response.
    ResponseCancel,
    /// Delete an item.
    ItemDelete,
    /// Usage: audio in, audio out, text in, text out.
    Usage(u64, u64, u64, u64),
    /// A rate-limit report.
    RateLimits,
    /// An error: code, message.
    Error(String, String),
    /// A call opened: id, name.
    ToolOpen(String, String),
    /// A call's arguments: id, parsed.
    ToolArgs(String, Value),
    /// A call closed: id.
    ToolClose(String),
    /// A call's result: id, parsed output.
    ToolResult(String, Value),
}

/// A concept's tag, for a transcript's skeleton.
pub fn tag(n: &Norm) -> &'static str {
    match n {
        Norm::Config(_) => "config",
        Norm::ConfigModalities(_) => "config-modalities",
        Norm::Connect => "connect",
        Norm::AudioUp(_) => "audio-in",
        Norm::AudioDown(_) => "audio-out",
        Norm::AudioDone => "audio-done",
        Norm::Item(_) => "item",
        Norm::SpeechStart => "speech-start",
        Norm::SpeechStop => "speech-stop",
        Norm::Truncate(_) => "truncate",
        Norm::Commit => "commit",
        Norm::Clear => "clear",
        Norm::ResponseCreate => "response-create",
        Norm::ResponseCancel => "cancel",
        Norm::ItemDelete => "item-delete",
        Norm::Usage(..) => "usage",
        Norm::RateLimits => "rate-limits",
        Norm::Error(..) => "error",
        Norm::ToolOpen(..) => "tool-open",
        Norm::ToolArgs(..) => "tool-args",
        Norm::ToolClose(..) => "tool-close",
        Norm::ToolResult(..) => "tool-result",
    }
}

/// The error code a far end's unreadable usage report reads as.
pub const USAGE_UNREADABLE: &str = "usage_unreadable";

fn text_at<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn audio(b64: &str) -> Option<Vec<u8>> {
    base64_decode(b64).map(|b| b.to_vec())
}

/// A JSON text as a value, or `Null` when it is not one.
fn parsed(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or(Value::Null)
}

/// The config essentials and modalities of an OpenAI Realtime `session` object (GA or legacy
/// spelling).
fn realtime_config(s: &Value) -> [Norm; 2] {
    let voice = s
        .pointer("/audio/output/voice")
        .or_else(|| s.get("voice"))
        .and_then(Value::as_str);
    let max = s
        .get("max_output_tokens")
        .or_else(|| s.get("max_response_output_tokens"))
        .filter(|v| !v.is_null());
    let modalities = s
        .get("output_modalities")
        .or_else(|| s.get("modalities"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    [
        Norm::Config(format!(
            "{:?}|{voice:?}|{}|{max:?}",
            s.get("instructions").and_then(Value::as_str),
            s.get("tools").and_then(Value::as_array).map_or(0, Vec::len),
        )),
        Norm::ConfigModalities(modalities),
    ]
}

/// The config essentials and modalities of a Gemini Live `setup` object.
fn live_config(s: &Value) -> [Norm; 2] {
    let instructions: Option<String> = s
        .pointer("/systemInstruction/parts")
        .and_then(Value::as_array)
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| p.get("text").and_then(Value::as_str))
                .collect::<String>()
        })
        .filter(|t| !t.is_empty());
    let voice = s
        .pointer("/generationConfig/speechConfig/voiceConfig/prebuiltVoiceConfig/voiceName")
        .and_then(Value::as_str);
    let max = s
        .pointer("/generationConfig/maxOutputTokens")
        .filter(|v| !v.is_null());
    let modalities = s
        .pointer("/generationConfig/responseModalities")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    [
        Norm::Config(format!(
            "{instructions:?}|{voice:?}|{}|{max:?}",
            s.get("tools").and_then(Value::as_array).map_or(0, Vec::len),
        )),
        Norm::ConfigModalities(modalities),
    ]
}

/// Whether a Gemini Live blob's mime is audio this dialect's caller or far end speaks.
fn live_audio_mime(mime: &str, up: bool) -> bool {
    let m = mime.to_ascii_lowercase();
    if !m.starts_with("audio/pcm") {
        return false;
    }
    let rates: Vec<&str> = m
        .split(';')
        .map(str::trim)
        .filter_map(|p| p.strip_prefix("rate="))
        .collect();
    let known = |r: &&str| *r == "16000" || *r == "24000";
    if rates.is_empty() {
        return true;
    }
    if up {
        rates.iter().any(known)
    } else {
        rates.contains(&"24000")
    }
}

/// The concepts a caller frame carries.
pub fn read_up(dialect: Dialect, frame: &[u8]) -> Vec<Norm> {
    let Ok(v) = serde_json::from_slice::<Value>(frame) else {
        return Vec::new();
    };
    match dialect {
        Dialect::OpenAi => realtime_up(&v),
        Dialect::Gemini => live_up(&v),
    }
}

fn realtime_up(v: &Value) -> Vec<Norm> {
    match text_at(v, "type") {
        "session.update" => realtime_config(v.get("session").unwrap_or(&Value::Null)).to_vec(),
        "input_audio_buffer.append" => audio(text_at(v, "audio"))
            .map(Norm::AudioUp)
            .into_iter()
            .collect(),
        "input_audio_buffer.commit" => vec![Norm::Commit],
        "input_audio_buffer.clear" => vec![Norm::Clear],
        "conversation.item.create" => {
            let item = v.get("item").cloned().unwrap_or(Value::Null);
            if text_at(&item, "type") == "function_call_output" {
                vec![Norm::ToolResult(
                    text_at(&item, "call_id").to_string(),
                    parsed(text_at(&item, "output")),
                )]
            } else {
                vec![Norm::Item(item)]
            }
        }
        "conversation.item.truncate" => vec![Norm::Truncate(
            v.get("audio_end_ms").and_then(Value::as_u64).unwrap_or(0),
        )],
        "conversation.item.delete" => vec![Norm::ItemDelete],
        "response.create" => vec![Norm::ResponseCreate],
        "response.cancel" => vec![Norm::ResponseCancel],
        _ => Vec::new(),
    }
}

fn live_up(v: &Value) -> Vec<Norm> {
    if let Some(setup) = v.get("setup") {
        return live_config(setup).to_vec();
    }
    if let Some(content) = v.get("clientContent") {
        return vec![Norm::Item(content.clone())];
    }
    if let Some(input) = v.get("realtimeInput") {
        let mut out = Vec::new();
        let mut blob = |b: &Value| {
            if live_audio_mime(text_at(b, "mimeType"), true) {
                if let Some(a) = audio(text_at(b, "data")) {
                    out.push(Norm::AudioUp(a));
                }
            }
        };
        if let Some(a) = input.get("audio") {
            blob(a);
        } else if let Some(chunks) = input.get("mediaChunks").and_then(Value::as_array) {
            chunks.iter().for_each(&mut blob);
        }
        if input.get("audioStreamEnd").is_some() {
            out.push(Norm::Commit);
        }
        return out;
    }
    if let Some(response) = v.get("toolResponse") {
        return response
            .get("functionResponses")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|r| {
                Norm::ToolResult(
                    text_at(r, "id").to_string(),
                    r.get("response").cloned().unwrap_or(Value::Null),
                )
            })
            .collect();
    }
    Vec::new()
}

/// The concepts a far-end frame carries.
pub fn read_down(dialect: Dialect, frame: &[u8]) -> Vec<Norm> {
    let Ok(v) = serde_json::from_slice::<Value>(frame) else {
        return Vec::new();
    };
    let mut out = match dialect {
        Dialect::OpenAi => realtime_down(&v),
        Dialect::Gemini => live_down(&v),
    };
    match usage(dialect, frame) {
        Ok(Some(u)) => out.push(Norm::Usage(u[0], u[1], u[2], u[3])),
        Ok(None) => {}
        Err(e) => out.push(Norm::Error(USAGE_UNREADABLE.to_string(), e)),
    }
    out
}

fn realtime_down(v: &Value) -> Vec<Norm> {
    match text_at(v, "type") {
        "session.created" => vec![Norm::Connect],
        "input_audio_buffer.speech_started" => vec![Norm::SpeechStart],
        "input_audio_buffer.speech_stopped" => vec![Norm::SpeechStop],
        "response.output_audio.delta" | "response.audio.delta" => audio(text_at(v, "delta"))
            .map(Norm::AudioDown)
            .into_iter()
            .collect(),
        "response.output_audio.done" | "response.audio.done" => vec![Norm::AudioDone],
        "response.output_item.added" => {
            let item = v.get("item").unwrap_or(&Value::Null);
            if text_at(item, "type") == "function_call" {
                vec![Norm::ToolOpen(
                    text_at(item, "call_id").to_string(),
                    text_at(item, "name").to_string(),
                )]
            } else {
                Vec::new()
            }
        }
        "response.function_call_arguments.delta" => vec![Norm::ToolArgs(
            text_at(v, "call_id").to_string(),
            parsed(text_at(v, "delta")),
        )],
        "response.function_call_arguments.done" => {
            let id = text_at(v, "call_id").to_string();
            let args = text_at(v, "arguments");
            let mut out = Vec::new();
            if !args.is_empty() {
                out.push(Norm::ToolArgs(id.clone(), parsed(args)));
            }
            out.push(Norm::ToolClose(id));
            out
        }
        "rate_limits.updated" => vec![Norm::RateLimits],
        "error" => {
            let e = v.get("error").unwrap_or(&Value::Null);
            vec![Norm::Error(
                text_at(e, "code").to_string(),
                text_at(e, "message").to_string(),
            )]
        }
        // `response.done` is read by [`usage`].
        _ => Vec::new(),
    }
}

fn live_down(v: &Value) -> Vec<Norm> {
    if v.get("setupComplete").is_some() {
        return vec![Norm::Connect];
    }
    let mut out = Vec::new();
    if let Some(content) = v.get("serverContent") {
        for part in content
            .pointer("/modelTurn/parts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(inline) = part.get("inlineData") {
                if live_audio_mime(text_at(inline, "mimeType"), false) {
                    if let Some(a) = audio(text_at(inline, "data")) {
                        out.push(Norm::AudioDown(a));
                    }
                }
            }
        }
        if content.get("interrupted").and_then(Value::as_bool) == Some(true) {
            out.push(Norm::SpeechStart);
        }
        if content.get("turnComplete").and_then(Value::as_bool) == Some(true) {
            out.push(Norm::AudioDone);
        }
    } else if let Some(call) = v.get("toolCall") {
        for c in call
            .get("functionCalls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let id = text_at(c, "id").to_string();
            out.push(Norm::ToolOpen(id.clone(), text_at(c, "name").to_string()));
            out.push(Norm::ToolArgs(
                id.clone(),
                c.get("args").cloned().unwrap_or(Value::Null),
            ));
            out.push(Norm::ToolClose(id));
        }
    }
    out
}

// ── usage ───────────────────────────────────────────────────────────────────────────────────────

/// One billed count: absent or `null` is 0; a whole number (an integral float below 2^53 too) is
/// itself; anything else is unreadable.
fn count(o: Option<&Value>, key: &str) -> Result<u64, String> {
    match o.and_then(|x| x.get(key)) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v
            .as_u64()
            .or_else(|| {
                v.as_f64()
                    .filter(|f| (0.0..9_007_199_254_740_992.0).contains(f) && f.fract() == 0.0)
                    .map(|f| f as u64)
            })
            .ok_or_else(|| format!("usage field `{key}` is not a count: {v}")),
    }
}

/// The token classes a far end's usage report bills, `[audio in, audio out, text in, text out]`:
/// `Ok(None)` for a frame that reports none, `Err` for a report with an unreadable count.
///
/// OpenAI Realtime (`response.done`'s `response.usage`): each side bills the larger of its stated
/// total and the sum of its breakdown; audio bills as audio, image input as image (not here), and
/// the rest of the side as text. Gemini Live (`usageMetadata`, on any frame): the prompt bills
/// the larger of `promptTokenCount` and its breakdown, plus the tool-use prompt likewise; the
/// response bills the larger of `responseTokenCount` and its breakdown, plus `thoughtsTokenCount`;
/// the input is at least the total less the output; audio, image and video entries are their own
/// classes and the rest is text.
pub fn usage(dialect: Dialect, frame: &[u8]) -> Result<Option<[u64; 4]>, String> {
    let Ok(v) = serde_json::from_slice::<Value>(frame) else {
        return Ok(None);
    };
    match dialect {
        Dialect::OpenAi => {
            if text_at(&v, "type") != "response.done" {
                return Ok(None);
            }
            let Some(u) = v.pointer("/response/usage") else {
                return Ok(Some([0; 4]));
            };
            let (ind, outd) = (u.get("input_token_details"), u.get("output_token_details"));
            let audio_in = count(ind, "audio_tokens")?;
            let image_in = count(ind, "image_tokens")?;
            let input = count(Some(u), "input_tokens")?.max(
                audio_in
                    .saturating_add(count(ind, "text_tokens")?)
                    .saturating_add(image_in),
            );
            let audio_out = count(outd, "audio_tokens")?;
            let output = count(Some(u), "output_tokens")?
                .max(audio_out.saturating_add(count(outd, "text_tokens")?));
            Ok(Some([
                audio_in,
                audio_out,
                input.saturating_sub(audio_in).saturating_sub(image_in),
                output.saturating_sub(audio_out),
            ]))
        }
        Dialect::Gemini => {
            let Some(u) = v.get("usageMetadata") else {
                return Ok(None);
            };
            // (audio, image, video, every entry)
            let split = |key: &str| -> Result<[u64; 4], String> {
                let mut s = [0_u64; 4];
                for d in u.get(key).and_then(Value::as_array).into_iter().flatten() {
                    let n = count(Some(d), "tokenCount")?;
                    s[3] = s[3].saturating_add(n);
                    let m = text_at(d, "modality").to_ascii_uppercase();
                    let at = match m.as_str() {
                        "AUDIO" => 0,
                        "IMAGE" => 1,
                        "VIDEO" => 2,
                        _ => continue,
                    };
                    s[at] = s[at].saturating_add(n);
                }
                Ok(s)
            };
            let prompt = split("promptTokensDetails")?;
            let tool = split("toolUsePromptTokensDetails")?;
            let response = split("responseTokensDetails")?;
            let audio_in = prompt[0].saturating_add(tool[0]);
            let other_in = prompt[1]
                .saturating_add(tool[1])
                .saturating_add(prompt[2])
                .saturating_add(tool[2]);
            let input = count(Some(u), "promptTokenCount")?
                .max(prompt[3])
                .saturating_add(count(Some(u), "toolUsePromptTokenCount")?.max(tool[3]));
            let output = count(Some(u), "responseTokenCount")?
                .max(response[3])
                .saturating_add(count(Some(u), "thoughtsTokenCount")?);
            let input = input.max(count(Some(u), "totalTokenCount")?.saturating_sub(output));
            Ok(Some([
                audio_in,
                response[0],
                input.saturating_sub(audio_in).saturating_sub(other_in),
                output.saturating_sub(response[0]),
            ]))
        }
    }
}

// ── JSON with its members in order ──────────────────────────────────────────────────────────────

/// A JSON value whose objects keep their members in document order (duplicates included).
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    /// An object, its members as written.
    Object(Vec<(String, Node)>),
    /// Any other value.
    Other(Value),
}

impl Node {
    /// The value, as `serde_json` reads it (a repeated key: the last one).
    pub fn value(&self) -> Value {
        match self {
            Node::Object(members) => Value::Object(
                members
                    .iter()
                    .map(|(k, n)| (k.clone(), n.value()))
                    .collect::<Map<String, Value>>(),
            ),
            Node::Other(v) => v.clone(),
        }
    }
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while matches!(b.get(i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
        i += 1;
    }
    i
}

/// Past the string that opens at `b[i]`.
fn past_string(b: &[u8], i: usize) -> Option<usize> {
    let mut j = i + 1;
    while let Some(c) = b.get(j) {
        match c {
            b'\\' => j += 2,
            b'"' => return Some(j + 1),
            _ => j += 1,
        }
    }
    None
}

/// Past the value that starts at `b[i]` (any kind).
fn past_value(b: &[u8], i: usize) -> Option<usize> {
    match b.get(i)? {
        b'"' => past_string(b, i),
        b'{' | b'[' => {
            let mut depth = 0_usize;
            let mut j = i;
            while let Some(c) = b.get(j) {
                match c {
                    b'"' => {
                        j = past_string(b, j)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(j + 1);
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
            None
        }
        _ => {
            let mut j = i;
            while b
                .get(j)
                .is_some_and(|c| !matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r'))
            {
                j += 1;
            }
            (j > i).then_some(j)
        }
    }
}

/// The node at `b[i]`, and where it ends.
fn node_at(b: &[u8], i: usize) -> Option<(Node, usize)> {
    if b.get(i) != Some(&b'{') {
        let end = past_value(b, i)?;
        return Some((Node::Other(serde_json::from_slice(&b[i..end]).ok()?), end));
    }
    let mut members = Vec::new();
    let mut j = skip_ws(b, i + 1);
    if b.get(j) == Some(&b'}') {
        return Some((Node::Object(members), j + 1));
    }
    loop {
        let key_end = past_string(b, j).filter(|_| b.get(j) == Some(&b'"'))?;
        let key: String = serde_json::from_slice(&b[j..key_end]).ok()?;
        let colon = skip_ws(b, key_end);
        if b.get(colon) != Some(&b':') {
            return None;
        }
        let (value, end) = node_at(b, skip_ws(b, colon + 1))?;
        members.push((key, value));
        let next = skip_ws(b, end);
        match b.get(next)? {
            b',' => j = skip_ws(b, next + 1),
            b'}' => return Some((Node::Object(members), next + 1)),
            _ => return None,
        }
    }
}

/// The frame as one JSON object, its members in order; `None` for a frame that is not JSON, or
/// is JSON but not one object.
pub fn object_members(frame: &[u8]) -> Option<Vec<(String, Node)>> {
    serde_json::from_slice::<Value>(frame).ok()?;
    let (node, end) = node_at(frame, skip_ws(frame, 0))?;
    match node {
        Node::Object(members) if skip_ws(frame, end) == frame.len() => Some(members),
        _ => None,
    }
}

// ── what the door owes the far end for a caller frame ───────────────────────────────────────────

/// The section every relay leg opens under ([`crate::door::SESSION`]) states only the session's
/// model, so the lock is that model under the section's token ceilings, at their defaults
/// (`docs/voice.md`: `max_output_tokens` 4096, `context_window_tokens` 32768).
pub const LOCKED_MODEL: &str = crate::door::MODEL;
/// See [`LOCKED_MODEL`].
pub const OUTPUT_CEILING: u64 = 4096;
/// See [`LOCKED_MODEL`].
pub const CONTEXT_WINDOW: u64 = 32_768;

/// A token ceiling a governed object is held to: at `path` below the object, `key` is the lower of
/// what the caller asked and `ceiling`; written at `ceiling` where the caller asked nothing when
/// `when_absent`.
#[derive(Clone, Copy, Debug)]
struct Cap {
    path: &'static [&'static str],
    key: &'static str,
    ceiling: u64,
    when_absent: bool,
}

/// What a governed object takes: the members cut, the members locked (set over the caller's,
/// merged into the caller's object where both are objects) and the ceilings.
#[derive(Clone, Debug)]
struct Lock {
    cut: &'static [&'static str],
    set: Map<String, Value>,
    caps: Vec<Cap>,
    /// A Gemini Live `setup` is read by a protobuf JSON reader: `system_instruction` is
    /// `systemInstruction`.
    proto: bool,
}

/// The top-level members of a caller frame a dialect governs, and the lock each takes.
fn locks(dialect: Dialect) -> Vec<(&'static str, Lock)> {
    match dialect {
        Dialect::OpenAi => {
            let set = serde_json::json!({
                "type": "realtime",
                "model": LOCKED_MODEL,
                "truncation": {
                    "type": "retention_ratio",
                    "retention_ratio": 1.0,
                    "token_limits": {"post_instructions": CONTEXT_WINDOW - OUTPUT_CEILING},
                },
            });
            let cut: &'static [&'static str] = &["instructions", "tools", "prompt"];
            vec![
                (
                    "session",
                    Lock {
                        cut,
                        set: set.as_object().cloned().unwrap_or_default(),
                        caps: vec![
                            Cap {
                                path: &[],
                                key: "max_output_tokens",
                                ceiling: OUTPUT_CEILING,
                                when_absent: true,
                            },
                            Cap {
                                path: &[],
                                key: "max_response_output_tokens",
                                ceiling: OUTPUT_CEILING,
                                when_absent: false,
                            },
                        ],
                        proto: false,
                    },
                ),
                (
                    "response",
                    Lock {
                        cut,
                        set: Map::new(),
                        caps: vec![Cap {
                            path: &[],
                            key: "max_output_tokens",
                            ceiling: OUTPUT_CEILING,
                            when_absent: true,
                        }],
                        proto: false,
                    },
                ),
            ]
        }
        Dialect::Gemini => {
            let set = serde_json::json!({
                "model": LOCKED_MODEL,
                "contextWindowCompression": {"triggerTokens": CONTEXT_WINDOW, "slidingWindow": {}},
            });
            vec![(
                "setup",
                Lock {
                    cut: &["systemInstruction", "tools"],
                    set: set.as_object().cloned().unwrap_or_default(),
                    caps: vec![Cap {
                        path: &["generationConfig"],
                        key: "maxOutputTokens",
                        ceiling: OUTPUT_CEILING,
                        when_absent: true,
                    }],
                    proto: true,
                },
            )]
        }
    }
}

/// `key` as a protobuf JSON reader resolves it when `proto` (`a_b` is `aB`).
fn field_name(key: &str, proto: bool) -> String {
    if !proto {
        return key.to_string();
    }
    let mut out = String::with_capacity(key.len());
    let mut raise = false;
    for c in key.chars() {
        if c == '_' {
            raise = true;
        } else if raise {
            out.extend(c.to_uppercase());
            raise = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// The audio format a realtime `session` object names for the caller's uplink, if any: `Err` for
/// one the plane cannot meter (not pcm16 at 24 kHz, not µ-law) or two that differ.
fn uplink_format(session: &Value) -> Result<Option<&'static str>, ()> {
    fn legacy(v: &Value) -> Result<Option<&'static str>, ()> {
        match v {
            Value::Null => Ok(None),
            Value::String(s) if s == "pcm16" => Ok(Some("pcm16")),
            Value::String(s) if s == "g711_ulaw" => Ok(Some("g711_ulaw")),
            _ => Err(()),
        }
    }
    fn ga(v: &Value) -> Result<Option<&'static str>, ()> {
        let Some(o) = v.as_object() else {
            return legacy(v);
        };
        match o.get("type").and_then(Value::as_str) {
            Some("audio/pcm") => match o.get("rate") {
                None => Ok(Some("pcm16")),
                Some(r) if r.as_u64() == Some(24_000) => Ok(Some("pcm16")),
                Some(_) => Err(()),
            },
            Some("audio/pcmu") => Ok(Some("g711_ulaw")),
            _ => Err(()),
        }
    }
    let mut named: Option<&'static str> = None;
    let mut add = |f: Option<&'static str>| -> Result<(), ()> {
        match (named, f) {
            (_, None) => Ok(()),
            (None, Some(f)) => {
                named = Some(f);
                Ok(())
            }
            (Some(a), Some(b)) if a == b => Ok(()),
            _ => Err(()),
        }
    };
    if let Some(v) = session.get("input_audio_format") {
        add(legacy(v)?)?;
    }
    if let Some(f) = session.pointer("/audio/input/format") {
        add(ga(f)?)?;
    }
    Ok(named)
}

/// Whether an item is in an instructing role (`system`, `developer`).
fn instructs(item: &Value) -> bool {
    item.get("role").and_then(Value::as_str).is_some_and(|r| {
        ["system", "developer"]
            .iter()
            .any(|i| r.trim().eq_ignore_ascii_case(i))
    })
}

/// What the door owes the far end for one caller frame.
#[derive(Clone, Debug, PartialEq)]
pub enum Owed {
    /// Nothing: the frame is not one JSON object, authors an instructing item, or names an uplink
    /// format the plane cannot meter.
    Nothing,
    /// The frame, byte for byte.
    Exact(Vec<u8>),
    /// The frame under the session's lock (it configures the session or asks for a response):
    /// judged at the JSON level against the frame as the caller sent it.
    Governed(Vec<u8>),
}

/// What the door owes the far end for the caller frame `frame` under the leg's lock.
pub fn owed(dialect: Dialect, frame: &[u8]) -> Owed {
    let Some(top) = object_members(frame) else {
        return Owed::Nothing;
    };
    if dialect == Dialect::OpenAi {
        let v = Node::Object(top.clone()).value();
        let mut formats = top
            .iter()
            .filter(|(k, n)| k == "session" && matches!(n, Node::Object(_)))
            .map(|(_, n)| uplink_format(&n.value()));
        let mut named: Option<&'static str> = None;
        let unmeterable = formats.any(|f| match f {
            Err(()) => true,
            Ok(None) => false,
            Ok(Some(f)) => named.replace(f).is_some_and(|was| was != f),
        });
        let authors = instructs(v.get("item").unwrap_or(&Value::Null))
            || v.pointer("/response/input")
                .and_then(Value::as_array)
                .is_some_and(|items| items.iter().any(instructs));
        if unmeterable || authors {
            return Owed::Nothing;
        }
    }
    let governed = locks(dialect).into_iter().any(|(at, _)| {
        top.iter()
            .any(|(k, n)| k == at && matches!(n, Node::Object(_)))
    });
    if governed {
        Owed::Governed(frame.to_vec())
    } else {
        Owed::Exact(frame.to_vec())
    }
}

/// The members a governed object must hold: the caller's kept members, in order, then every member
/// the lock adds or rewrites (`(key, value)`, order free).
struct Expected {
    kept: Vec<(String, Value)>,
    added: Vec<(String, Value)>,
}

/// `locked` as a new object, each cap written in the caller's absence at its ceiling.
fn fresh(locked: &Map<String, Value>, caps: &[Cap]) -> Value {
    /// Write `ceiling` at `key` below `path` in `m`, making each object on the way; a path through
    /// a value that is not an object writes nothing.
    fn put(m: &mut Map<String, Value>, path: &[&str], key: &str, ceiling: u64) {
        match path.split_first() {
            None => {
                m.insert(key.to_string(), Value::from(ceiling));
            }
            Some((first, rest)) => {
                let next = m
                    .entry((*first).to_string())
                    .or_insert_with(|| Value::Object(Map::new()));
                if let Value::Object(o) = next {
                    put(o, rest, key, ceiling);
                }
            }
        }
    }
    let mut m = locked.clone();
    for c in caps.iter().filter(|c| c.when_absent) {
        put(&mut m, c.path, c.key, c.ceiling);
    }
    Value::Object(m)
}

/// The caps one level below `parent`.
fn below(caps: &[Cap], parent: &str) -> Vec<Cap> {
    caps.iter()
        .filter(|c| c.path.first() == Some(&parent))
        .map(|c| {
            let path: &'static [&'static str] = c.path;
            Cap {
                path: &path[1..],
                ..*c
            }
        })
        .collect()
}

/// The members the caller's object `theirs` must become under `cut`, `set` and `caps`.
fn expect_object(
    theirs: &[(String, Node)],
    cut: &[&str],
    set: &Map<String, Value>,
    proto: bool,
    caps: &[Cap],
) -> Expected {
    let here: Vec<&Cap> = caps.iter().filter(|c| c.path.is_empty()).collect();
    let mut parents: Vec<&'static str> = caps
        .iter()
        .filter_map(|c| c.path.first().copied())
        .collect();
    parents.sort_unstable();
    parents.dedup();
    let name = |k: &str| field_name(k, proto);
    let kept = theirs
        .iter()
        .filter(|(k, _)| {
            let n = name(k);
            !cut.contains(&n.as_str())
                && !set.contains_key(&n)
                && !here.iter().any(|c| c.key == n)
                && !parents.contains(&n.as_str())
        })
        .map(|(k, n)| (k.clone(), n.value()))
        .collect();
    let last_object = |key: &str| {
        theirs.iter().rev().find_map(|(k, n)| match n {
            Node::Object(m) if name(k) == key => Some(m.as_slice()),
            _ => None,
        })
    };
    let rebuilt =
        |e: Expected| -> Value { Value::Object(e.kept.into_iter().chain(e.added).collect()) };
    let mut added = Vec::new();
    for (key, value) in set {
        let sub = below(caps, key);
        let v = match (value, last_object(key.as_str())) {
            (Value::Object(locked), Some(m)) => rebuilt(expect_object(m, &[], locked, proto, &sub)),
            (Value::Object(locked), None) => fresh(locked, &sub),
            _ => value.clone(),
        };
        added.push((key.clone(), v));
    }
    for parent in parents.iter().copied().filter(|p| !set.contains_key(*p)) {
        let sub = below(caps, parent);
        let v = match last_object(parent) {
            Some(m) => rebuilt(expect_object(m, &[], &Map::new(), proto, &sub)),
            None if sub.iter().any(|c| c.when_absent)
                || theirs.iter().any(|(k, _)| name(k) == parent) =>
            {
                fresh(&Map::new(), &sub)
            }
            None => continue,
        };
        added.push((parent.to_string(), v));
    }
    for c in here {
        let asked: Vec<u64> = theirs
            .iter()
            .filter(|(k, _)| name(k) == c.key)
            .map(|(_, n)| n.value().as_u64().unwrap_or(c.ceiling))
            .collect();
        if c.when_absent || !asked.is_empty() {
            let v = asked.into_iter().fold(c.ceiling, u64::min);
            added.push((c.key.to_string(), Value::from(v)));
        }
    }
    Expected { kept, added }
}

/// Whether the object the door relayed (`got`) holds exactly what `want` says: the kept members in
/// the caller's order and unchanged, every added member with its value, and nothing else.
fn object_is(got: &[(String, Node)], want: &Expected) -> Result<(), String> {
    let mut rest: Vec<(String, Value)> = Vec::new();
    let mut kept = want.kept.iter();
    let mut next = kept.next();
    for (k, n) in got {
        let v = n.value();
        match next {
            Some((wk, wv)) if wk == k && *wv == v => next = kept.next(),
            _ => rest.push((k.clone(), v)),
        }
    }
    if let Some((k, v)) = next {
        return Err(format!(
            "the caller's `{k}` ({v}) is not kept unchanged and in its order"
        ));
    }
    let mut added = want.added.clone();
    for (k, v) in rest {
        match added.iter().position(|(ak, av)| *ak == k && *av == v) {
            Some(i) => {
                added.remove(i);
            }
            None => {
                return Err(match want.added.iter().find(|(ak, _)| *ak == k) {
                    Some((_, av)) => format!("`{k}` is {v}; the lock owes {av}"),
                    None => format!("`{k}` ({v}) is neither the caller's nor the lock's"),
                })
            }
        }
    }
    match added.first() {
        Some((k, v)) => Err(format!("the lock's `{k}` ({v}) is missing")),
        None => Ok(()),
    }
}

/// Whether `relayed` is the governed caller frame `sent` as the lock leaves it: at the top level
/// the caller's members in their order, each unchanged except the governed objects, which hold
/// the lock ([`expect_object`]).
pub fn relayed_as_owed(dialect: Dialect, sent: &[u8], relayed: &[u8]) -> Result<(), String> {
    let (Some(theirs), Some(got)) = (object_members(sent), object_members(relayed)) else {
        return Err("the relayed frame is not one JSON object".to_string());
    };
    let keys = |m: &[(String, Node)]| m.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>();
    if keys(theirs.as_slice()) != keys(got.as_slice()) {
        return Err(format!(
            "the frame's members are {:?}; the caller sent {:?}",
            keys(got.as_slice()),
            keys(theirs.as_slice())
        ));
    }
    let locks = locks(dialect);
    for ((k, sent_node), (_, got_node)) in theirs.iter().zip(&got) {
        let lock = locks.iter().find(|(at, _)| at == k).map(|(_, l)| l);
        match (lock, sent_node, got_node) {
            (Some(lock), Node::Object(s), Node::Object(g)) => {
                let want = expect_object(s, lock.cut, &lock.set, lock.proto, &lock.caps);
                object_is(g, &want).map_err(|e| format!("in `{k}`: {e}"))?;
            }
            (Some(_), Node::Object(_), _) => {
                return Err(format!("the governed `{k}` is no longer an object"));
            }
            _ if sent_node.value() != got_node.value() => {
                return Err(format!("`{k}` changed: {}", got_node.value()));
            }
            _ => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPDATE: &[u8] = br#"{"event_id":"e1","type":"session.update","session":{"voice":"marin","instructions":"x","max_output_tokens":1024,"tools":[]}}"#;

    /// The update as the lock leaves it: the caller's `voice` kept in place, `instructions` and
    /// `tools` cut, the lock's members set and the output cap held to the caller's lower ask.
    const LOCKED: &[u8] = br#"{"event_id":"e1","type":"session.update","session":{"voice":"marin","model":"m-cap","truncation":{"retention_ratio":1.0,"token_limits":{"post_instructions":28672},"type":"retention_ratio"},"type":"realtime","max_output_tokens":1024}}"#;

    #[test]
    fn a_session_update_is_governed_and_its_lock_is_judged() {
        assert_eq!(
            owed(Dialect::OpenAi, UPDATE),
            Owed::Governed(UPDATE.to_vec())
        );
        assert_eq!(relayed_as_owed(Dialect::OpenAi, UPDATE, LOCKED), Ok(()));
    }

    #[test]
    fn red_a_relay_that_breaks_the_lock_is_refused() {
        let text = String::from_utf8_lossy(LOCKED).into_owned();
        for (what, planted) in [
            (
                "the caller's instructions kept",
                text.replace(
                    r#""voice":"marin","#,
                    r#""voice":"marin","instructions":"x","#,
                ),
            ),
            (
                "the cap widened",
                text.replace(r#""max_output_tokens":1024"#, r#""max_output_tokens":4096"#),
            ),
            (
                "another model",
                text.replace(r#""model":"m-cap""#, r#""model":"other""#),
            ),
            (
                "a member gained",
                text.replace(r#""event_id":"e1","#, r#""event_id":"e1","x":1,"#),
            ),
            (
                "the top level reordered",
                text.replace(
                    r#""event_id":"e1","type":"session.update","#,
                    r#""type":"session.update","event_id":"e1","#,
                ),
            ),
            (
                "the caller's voice changed",
                text.replace(r#""voice":"marin""#, r#""voice":"alloy""#),
            ),
        ] {
            assert!(
                relayed_as_owed(Dialect::OpenAi, UPDATE, planted.as_bytes()).is_err(),
                "{what} was accepted"
            );
        }
    }

    #[test]
    fn a_gemini_setup_takes_the_lock_under_its_protobuf_names() {
        let setup = br#"{"setup":{"model":"models/x","system_instruction":{"parts":[{"text":"y"}]},"generationConfig":{"responseModalities":["AUDIO"]}}}"#;
        let locked = br#"{"setup":{"contextWindowCompression":{"slidingWindow":{},"triggerTokens":32768},"model":"m-cap","generationConfig":{"responseModalities":["AUDIO"],"maxOutputTokens":4096}}}"#;
        assert_eq!(relayed_as_owed(Dialect::Gemini, setup, locked), Ok(()));
        let kept = br#"{"setup":{"system_instruction":{"parts":[{"text":"y"}]},"contextWindowCompression":{"slidingWindow":{},"triggerTokens":32768},"model":"m-cap","generationConfig":{"responseModalities":["AUDIO"],"maxOutputTokens":4096}}}"#;
        assert!(relayed_as_owed(Dialect::Gemini, setup, kept).is_err());
    }

    #[test]
    fn an_ungoverned_frame_is_owed_byte_for_byte_and_a_non_object_nothing() {
        let append = br#"{"type":"input_audio_buffer.append","audio":"AAAA"}"#;
        assert_eq!(owed(Dialect::OpenAi, append), Owed::Exact(append.to_vec()));
        assert_eq!(owed(Dialect::OpenAi, b"[1]"), Owed::Nothing);
        assert_eq!(owed(Dialect::OpenAi, b"not json"), Owed::Nothing);
        let system =
            br#"{"type":"conversation.item.create","item":{"type":"message","role":"system"}}"#;
        assert_eq!(owed(Dialect::OpenAi, system), Owed::Nothing);
    }

    #[test]
    fn usage_bills_each_side_by_its_stated_rules() {
        let realtime = br#"{"type":"response.done","response":{"usage":{"input_token_details":{"audio_tokens":10,"text_tokens":3},"output_token_details":{"audio_tokens":20,"text_tokens":4}}}}"#;
        assert_eq!(usage(Dialect::OpenAi, realtime), Ok(Some([10, 20, 3, 4])));
        let live = br#"{"usageMetadata":{"promptTokenCount":140,"responseTokenCount":80,"totalTokenCount":220,"promptTokensDetails":[{"modality":"TEXT","tokenCount":40},{"modality":"AUDIO","tokenCount":100}],"responseTokensDetails":[{"modality":"AUDIO","tokenCount":80}]}}"#;
        assert_eq!(usage(Dialect::Gemini, live), Ok(Some([100, 80, 40, 0])));
        let unreadable =
            br#"{"type":"response.done","response":{"usage":{"input_tokens":"many"}}}"#;
        assert!(usage(Dialect::OpenAi, unreadable).is_err());
    }
}
