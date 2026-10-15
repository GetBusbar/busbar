// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWILIO LEGS, AT THE DOOR: the Twilio Media Streams dialect, judged to the spec and to
//! Twilio's published message formats, never to what the reader happens to do today.
//!
//! Twilio is a dialect over the `ws` transport (`BUSBAR-1.6.0.md` l.418-419: no transport crate of
//! its own, claimed on a one-level `/twilio` path prefix). Its inbound auth is
//! `busbar-auth-webhook-signature`, variant twilio (l.847-852). Every Twilio frame is `event`-tagged
//! JSON (<https://www.twilio.com/docs/voice/media-streams/websocket-messages>): Twilio sends
//! `connected`, `start`, `media`, `mark`, `dtmf` and `stop`; busbar sends `media`, `mark` and
//! `clear`.
//!
//! The session behind the Twilio door is the telephony session: the caller speaks Twilio, the far
//! end is the realtime dialect locked to `g711_ulaw` both ways. Caller frames are pushed as caller
//! pieces on the Twilio door's claim, the far end's as far-end pieces, on the linked AND the dropped
//! door, and the answer is read back off the wire: what reached the far end as caller audio, what
//! reached Twilio as a frame. The expectation is computed from the fixtures (Twilio's own formats),
//! never from the door.
//!
//! Slices: `twilio` (the spec-per-dialect slice: every fixture and the transcript), `twilio-route`,
//! `twilio-media`, `twilio-metering`.

use std::fs;
use std::path::Path;

use busbar_contract::abi::host::conn::connector::DIRECTION_INBOUND;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PRINCIPAL_REQUIRED, ROUTE_DIRECT,
};
use busbar_contract::grammar::Selector;
use busbar_contract::media::{base64_decode, base64_encode};
use busbar_plane_streaming::claims::{dialect_for, Dialect, DIALECT_CLAIMS, WS_TRANSPORT};
use busbar_plane_streaming::codec::topology::twilio::{
    assert_g711_ulaw, TwilioEnvelope, TwilioEvent,
};
use busbar_plane_streaming::door::{ROUTES, SIGNATURE_AUTH};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::Plugin;
use serde_json::{json, Value};

use crate::composition::{units_of, usage_units, USAGE_DONE};
use crate::door::{
    arrive, judge, open, piece, result, session, Answer, Arrived, Emission, Opened, Piece, Rig,
    Session, MODEL, PUBLIC, SESSION,
};

/// The door claim that opens a Twilio session: the fifth line of the snapshot (the telephony
/// socket), after the mint, the SDP offer, the sideband and the Gemini socket.
const CLAIM: u32 = 4;

/// The `streamSid` of the second call the media leg opens, to show the outbound frames carry
/// their own call's identity and not the first call's.
const OTHER_SID: &str = "MZYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY";

// ── the frames the legs push ────────────────────────────────────────────────────────────────────

/// One frame pushed to a session, and the lines the door must answer it with.
#[derive(Clone, Debug)]
struct Step {
    label: String,
    from: u32,
    bytes: Vec<u8>,
    expect: Vec<String>,
}

/// What a run of steps showed.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Run {
    lines: Vec<String>,
    done: u32,
    anomalies: Vec<String>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unb64(s: &str) -> Vec<u8> {
    base64_decode(s).map(|b| b.to_vec()).unwrap_or_default()
}

fn bytes_of(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_default()
}

/// What one emitted frame is, in the words the legs compare: the audio a frame hands the far end
/// (any other far-bound frame is the session's own business and is not described), and the Twilio
/// frame a caller-bound one is.
fn describe(e: &Emission) -> Option<String> {
    let v: Value = serde_json::from_slice(&e.frame).unwrap_or(Value::Null);
    if e.to_far {
        return (v["type"] == "input_audio_buffer.append").then(|| {
            format!(
                "far-audio:{}",
                hex(&unb64(v["audio"].as_str().unwrap_or_default()))
            )
        });
    }
    let sid = v["streamSid"].as_str().unwrap_or_default();
    Some(match v["event"].as_str() {
        Some("media") => format!(
            "caller-media:{sid}:{}",
            v["media"]["payload"].as_str().unwrap_or_default()
        ),
        Some("mark") => format!(
            "caller-mark:{sid}:{}",
            if v["mark"]["name"].as_str().is_some_and(|n| !n.is_empty()) {
                "named"
            } else {
                "unnamed"
            }
        ),
        Some("clear") => format!("caller-clear:{sid}"),
        _ => format!("caller-other:{}", String::from_utf8_lossy(&e.frame)),
    })
}

/// Push `steps` through the session on `stream` (the door is open), step by step.
fn run_steps(p: &Plugin<Plane>, stream: u64, steps: &[Step]) -> Run {
    let mut s = Session::open(p, stream, CLAIM);
    let mut lines = Vec::new();
    for st in steps {
        let from = s.emitted();
        s.push(st.from, 0, &st.bytes);
        let seen: Vec<String> = s.log.emissions[from..]
            .iter()
            .filter_map(describe)
            .collect();
        lines.push(format!("{} -> [{}]", st.label, seen.join(", ")));
    }
    Run {
        lines,
        done: s.log.done,
        anomalies: s.log.anomalies,
    }
}

/// A fresh door's session over `steps`: the door opened, then the steps.
fn fresh(p: &Plugin<Plane>, stream: u64, steps: &[Step]) -> Run {
    let opened = open(p, SESSION, Some(PUBLIC));
    let mut run = run_steps(p, stream, steps);
    if opened.outcome != Outcome::Ready {
        run.anomalies
            .insert(0, format!("open {:?}", opened.outcome));
    }
    run
}

fn wanted(steps: &[Step]) -> Vec<String> {
    steps
        .iter()
        .map(|s| format!("{} -> [{}]", s.label, s.expect.join(", ")))
        .collect()
}

/// A frame from Twilio, expecting `expect` back.
fn twilio(label: &str, v: &Value, expect: &[String]) -> Step {
    Step {
        label: label.to_string(),
        from: FROM_CALLER,
        bytes: bytes_of(v),
        expect: expect.to_vec(),
    }
}

/// A frame from the far end, expecting `expect` back.
fn far(label: &str, v: &Value, expect: &[String]) -> Step {
    Step {
        label: label.to_string(),
        from: FROM_FAR_END,
        bytes: bytes_of(v),
        expect: expect.to_vec(),
    }
}

/// The far end's audio delta carrying `b64`.
fn far_delta(b64: &str) -> Value {
    json!({"event_id": "evt_far_01", "type": "response.output_audio.delta",
        "response_id": "resp_001", "item_id": "item_asst_001", "output_index": 0,
        "content_index": 0, "delta": b64})
}

/// The far end's audio is done.
fn far_done() -> Value {
    json!({"event_id": "evt_far_02", "type": "response.output_audio.done",
        "response_id": "resp_001", "item_id": "item_asst_001", "output_index": 0,
        "content_index": 0})
}

/// The far end heard the user speak over its audio.
fn far_speech_started() -> Value {
    json!({"event_id": "evt_far_03", "type": "input_audio_buffer.speech_started",
        "audio_start_ms": 210, "item_id": "item_user_002"})
}

/// A Twilio `media` frame (Twilio's published shape) on call `sid` carrying `bytes`.
fn media_frame(sid: &str, n: usize, bytes: &[u8]) -> Value {
    json!({"event": "media", "sequenceNumber": (n + 2).to_string(),
        "media": {"track": "inbound", "chunk": (n + 1).to_string(),
            "timestamp": (n * 20).to_string(), "payload": base64_encode(bytes)},
        "streamSid": sid})
}

/// The fixtures the legs are built from.
#[derive(Clone)]
struct Fixtures {
    dir: std::path::PathBuf,
}

impl Fixtures {
    fn get(&self, name: &str) -> Result<Value, String> {
        let path = self.dir.join(name);
        fs::read(&path)
            .map_err(|e| format!("{}: {e}", path.display()))
            .and_then(|b| {
                serde_json::from_slice(&b).map_err(|e| format!("{}: {e}", path.display()))
            })
    }

    /// The call's `streamSid`, as the `start` fixture declares it.
    fn sid(&self) -> Result<String, String> {
        let start = self.get("from-twilio.start.json")?;
        start["start"]["streamSid"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| "from-twilio.start.json names no start.streamSid".to_string())
    }
}

/// The base64 payload of a `media` fixture, inbound or outbound.
fn payload_of(v: &Value) -> String {
    v["media"]["payload"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

/// `twilio <slice> <fixtures_dir>`.
pub fn run(rig: &Rig, slice: &str, dir: &Path) -> i32 {
    let fx = Fixtures {
        dir: dir.to_path_buf(),
    };
    let pass = match slice {
        "twilio-route" => route(rig, slice, &fx),
        "twilio-media" => media(rig, slice, &fx),
        "twilio-metering" => metering(rig, slice, &fx),
        other => {
            result(other, false, "slice", "unknown twilio slice");
            false
        }
    };
    i32::from(!pass)
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// spec-per-dialect, the twilio slice
// ══════════════════════════════════════════════════════════════════════════════════════════════

/// The CODEC half of one fixture: the plane's Twilio envelope reads it as Twilio's format says,
/// and what it writes back reads the same.
fn codec_half(name: &str, v: &Value) -> Result<String, String> {
    let frame = bytes_of(v);
    let event = name
        .strip_prefix("from-twilio.")
        .or_else(|| name.strip_prefix("to-twilio."))
        .and_then(|n| n.strip_suffix(".json"))
        .ok_or_else(|| "a fixture is named from-twilio.<event> or to-twilio.<event>".to_string())?;
    if v["event"] != event {
        return Err(format!(
            "the frame is not tagged `event: {event}`: {}",
            v["event"]
        ));
    }
    if v.get("type").is_some() {
        return Err("a Twilio frame carries no OpenAI `type` tag".to_string());
    }
    if event != "connected" && v["streamSid"].as_str().is_none_or(str::is_empty) {
        return Err("the frame names no streamSid".to_string());
    }
    match (name.starts_with("to-twilio."), event) {
        (_, "connected") => match TwilioEnvelope::decode(&frame) {
            Ok(TwilioEvent::Connected) => Ok("connected read as Connected".to_string()),
            other => Err(format!("connected read as {other:?}")),
        },
        (false, "start") => match TwilioEnvelope::decode(&frame) {
            Ok(TwilioEvent::Start(s)) => {
                if s.stream_sid != v["start"]["streamSid"] || s.call_sid != v["start"]["callSid"] {
                    return Err(format!("start read its identity as {s:?}"));
                }
                assert_g711_ulaw(&s.media_format).map_err(|e| e.to_string())?;
                Ok(
                    "start read with its identity and the audio/x-mulaw 8000 Hz mono format"
                        .to_string(),
                )
            }
            other => Err(format!("start read as {other:?}")),
        },
        (dir_out, "media") => {
            let sid = v["streamSid"].as_str().unwrap_or_default();
            let want = unb64(&payload_of(v));
            let Ok(TwilioEvent::Media {
                stream_sid,
                payload,
            }) = TwilioEnvelope::decode(&frame)
            else {
                return Err("media was not read as Media".to_string());
            };
            if stream_sid != sid || payload != want || want.is_empty() {
                return Err(format!("media read as {stream_sid} {payload:?}"));
            }
            let again = TwilioEnvelope::encode_media(sid, &payload);
            match TwilioEnvelope::decode(&again) {
                Ok(TwilioEvent::Media {
                    stream_sid: s2,
                    payload: p2,
                }) if s2 == sid && p2 == payload => {}
                other => return Err(format!("media did not round-trip: {other:?}")),
            }
            if dir_out && serde_json::from_slice::<Value>(&again).ok().as_ref() != Some(v) {
                return Err("the outbound media envelope is not Twilio's published shape".into());
            }
            Ok(format!(
                "media round trip stable ({} µ-law bytes)",
                payload.len()
            ))
        }
        (_, "mark") => match TwilioEnvelope::decode(&frame) {
            Ok(TwilioEvent::Mark {
                stream_sid,
                name: mark,
            }) if !mark.is_empty() => Ok(format!("mark `{mark}` read on {stream_sid}")),
            other => Err(format!("mark read as {other:?}")),
        },
        (false, "dtmf") => match TwilioEnvelope::decode(&frame) {
            Ok(TwilioEvent::Dtmf { digit, .. }) if !digit.is_empty() => {
                Ok(format!("dtmf digit {digit} read"))
            }
            other => Err(format!("dtmf read as {other:?}")),
        },
        (false, "stop") => match TwilioEnvelope::decode(&frame) {
            Ok(TwilioEvent::Stop) => Ok("stop read as Stop".to_string()),
            other => Err(format!("stop read as {other:?}")),
        },
        (true, "clear") => {
            let keys = v.as_object().map_or(0, serde_json::Map::len);
            if keys == 2 {
                Ok("clear is exactly {event, streamSid}".to_string())
            } else {
                Err(format!("clear carries {keys} members, Twilio's has two"))
            }
        }
        (_, other) => Err(format!(
            "`{other}` is not a Twilio Media Streams message here"
        )),
    }
}

/// The steps that push one fixture through a session, with what the door must answer each.
fn fixture_steps(fx: &Fixtures, name: &str, v: &Value) -> Result<Vec<Step>, String> {
    let start = fx.get("from-twilio.start.json")?;
    let sid = fx.sid()?;
    let nothing: &[String] = &[];
    let opening = || twilio("start", &start, nothing);
    let delta_b64 = payload_of(&fx.get("to-twilio.media.json")?);
    let heard = format!("caller-media:{sid}:{delta_b64}");
    let delta = || {
        far(
            "far audio",
            &far_delta(&delta_b64),
            std::slice::from_ref(&heard),
        )
    };
    Ok(match name {
        "from-twilio.connected.json" | "from-twilio.start.json" => {
            vec![twilio(name, v, nothing)]
        }
        "from-twilio.media.json" => {
            let audio = format!("far-audio:{}", hex(&unb64(&payload_of(v))));
            vec![opening(), twilio(name, v, &[audio])]
        }
        "from-twilio.stop.json" => vec![opening(), twilio(name, v, nothing)],
        "from-twilio.dtmf.json" | "from-twilio.mark.json" => {
            vec![opening(), twilio(name, v, nothing)]
        }
        "to-twilio.media.json" => vec![
            opening(),
            far(
                name,
                &far_delta(&payload_of(v)),
                &[format!("caller-media:{sid}:{}", payload_of(v))],
            ),
        ],
        "to-twilio.mark.json" => vec![
            opening(),
            delta(),
            far(name, &far_done(), &[format!("caller-mark:{sid}:named")]),
        ],
        "to-twilio.clear.json" => vec![
            opening(),
            delta(),
            far(
                name,
                &far_speech_started(),
                &[format!("caller-clear:{sid}")],
            ),
        ],
        other => return Err(format!("{other}: no steps for this fixture")),
    })
}

/// One finished assertion over `steps`: both doors, the codec half folded in, the planted door
/// (one that hands the far end audio nobody sent) refused by the same check.
fn judge_steps(
    rig: &Rig,
    slice: &str,
    what: &str,
    steps: &[Step],
    ends: u32,
    codec: &Result<String, String>,
) -> bool {
    let want = wanted(steps);
    let seen = rig.both(|p| fresh(p, 77, steps));
    judge(
        slice,
        what,
        &seen,
        &|run: &Run| {
            let codec = codec.clone()?;
            if !run.anomalies.is_empty() {
                return Err(format!("not answered READY: {:?}", run.anomalies));
            }
            if run.lines != want {
                return Err(format!("the door answered {:?}; want {want:?}", run.lines));
            }
            if run.done != ends {
                return Err(format!("{} end(s); want {ends}", run.done));
            }
            Ok(format!(
                "codec: {codec}; door: {}",
                run.lines.last().cloned().unwrap_or_default()
            ))
        },
        &|run: &Run| {
            let mut planted = run.clone();
            if let Some(last) = planted.lines.last_mut() {
                last.push_str(" +far-audio:dead");
            }
            planted
        },
    )
}

/// `spec twilio <dir>`: every fixture (codec round trip, and the door's relay of it by the session
/// rules), then the transcript.
pub fn spec(rig: &Rig, dir: &Path) -> i32 {
    let slice = "twilio";
    let fx = Fixtures {
        dir: dir.to_path_buf(),
    };
    let mut names: Vec<String> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".json"))
            .collect(),
        Err(e) => {
            result(slice, false, "fixtures", &format!("{}: {e}", dir.display()));
            return 1;
        }
    };
    names.sort();
    if names.is_empty() {
        result(slice, false, "fixtures", "no .json fixtures");
        return 1;
    }
    let mut fails = 0;
    for name in &names {
        let v = match fx.get(name) {
            Ok(v) => v,
            Err(e) => {
                result(slice, false, name, &format!("unreadable fixture: {e}"));
                fails += 1;
                continue;
            }
        };
        let steps = match fixture_steps(&fx, name, &v) {
            Ok(s) => s,
            Err(e) => {
                result(slice, false, name, &e);
                fails += 1;
                continue;
            }
        };
        let ends = u32::from(name == "from-twilio.stop.json");
        if !judge_steps(rig, slice, name, &steps, ends, &codec_half(name, &v)) {
            fails += 1;
        }
    }
    if !transcript(rig, slice, &fx) {
        fails += 1;
    }
    i32::from(fails > 0)
}

/// The transcript: one call, Twilio's frames (`client`) pushed as caller pieces in order, and for
/// each frame busbar sent Twilio (`server`) the far-end event that makes the door write it.
fn transcript_steps(fx: &Fixtures) -> Result<(Vec<Step>, u32, String), String> {
    let path = fx.dir.join("transcript.jsonl");
    let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (mut steps, mut read, mut ends) = (Vec::new(), Vec::new(), 0_u32);
    let mut sid = String::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let l: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let ev = &l["event"];
        let event = ev["event"].as_str().unwrap_or_default().to_string();
        let label = format!("{} {event}", steps.len());
        match l["dir"].as_str() {
            Some("client") => {
                if event == "start" {
                    sid = ev["start"]["streamSid"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                }
                TwilioEnvelope::decode(&bytes_of(ev)).map_err(|e| format!("{event}: {e}"))?;
                read.push(event.clone());
                ends += u32::from(event == "stop");
                let audio: Vec<String> = (event == "media")
                    .then(|| format!("far-audio:{}", hex(&unb64(&payload_of(ev)))))
                    .into_iter()
                    .collect();
                steps.push(twilio(&label, ev, &audio));
            }
            Some("server") => {
                let step = match event.as_str() {
                    "media" => far(
                        &label,
                        &far_delta(&payload_of(ev)),
                        &[format!("caller-media:{sid}:{}", payload_of(ev))],
                    ),
                    "mark" => far(&label, &far_done(), &[format!("caller-mark:{sid}:named")]),
                    "clear" => far(
                        &label,
                        &far_speech_started(),
                        &[format!("caller-clear:{sid}")],
                    ),
                    other => return Err(format!("the server sent `{other}`")),
                };
                steps.push(step);
            }
            _ => {}
        }
    }
    Ok((
        steps,
        ends,
        format!("Twilio's frames read in order: {}", read.join(" ")),
    ))
}

fn transcript(rig: &Rig, slice: &str, fx: &Fixtures) -> bool {
    let what = "transcript.jsonl";
    match transcript_steps(fx) {
        Ok((steps, ends, codec)) => judge_steps(rig, slice, what, &steps, ends, &Ok(codec)),
        Err(e) => {
            result(slice, false, what, &e);
            false
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// twilio-route
// ══════════════════════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteObs {
    opened: Opened,
    arrived: Arrived,
    dialect: String,
    route: String,
    signature_doors: Vec<String>,
    inbound_ws_auths: Vec<String>,
    claim: String,
    selectors: Vec<String>,
    handshake: Run,
    before_start: Run,
    after_start: Run,
    typed: Run,
}

fn route_script(p: &Plugin<Plane>, fx: &Fixtures) -> RouteObs {
    let opened = open(p, SESSION, Some(PUBLIC));
    let arrived = arrive(p, CLAIM);
    let served = p.served();
    let dialect = served
        .dialects
        .get(arrived.dialect as usize)
        .copied()
        .unwrap_or("?")
        .to_string();
    let inbound_ws_auths = served
        .need_auths
        .iter()
        .zip(&served.need_transports)
        .filter(|((direction, _), _)| *direction == DIRECTION_INBOUND)
        .map(|((_, auth), transport)| format!("{transport} {auth}"))
        .collect();
    let route = ROUTES
        .iter()
        .find(|r| r.target.starts_with("/twilio"))
        .map_or_else(
            || "no /twilio door".to_string(),
            |r| {
                format!(
                    "{} {} {} upgrade={} auth={}",
                    r.verb, r.target, r.carrier, r.upgrade, r.auth
                )
            },
        );
    let signature_doors = ROUTES
        .iter()
        .filter(|r| r.auth == SIGNATURE_AUTH)
        .map(|r| r.target.to_string())
        .collect();
    let claim = DIALECT_CLAIMS
        .iter()
        .find(|c| c.dialect == Dialect::TwilioMediaStreams)
        .map_or_else(
            || "no Twilio claim".to_string(),
            |c| {
                format!(
                    "{} {:?} alts={:?}",
                    c.claim.transport, c.claim.selector, c.claim.scheme_alternatives
                )
            },
        );
    let selectors = ["/twilio/call_0001", "/twilio", "/twilio/a/b", "/twiliofoo"]
        .iter()
        .map(|path| format!("{path}={:?}", dialect_for(path)))
        .collect();
    let nothing: &[String] = &[];
    let (start, sid) = (fx.get("from-twilio.start.json"), fx.sid());
    let (start, sid) = (start.unwrap_or(Value::Null), sid.unwrap_or_default());
    let audio = vec![7_u8; 160];
    let heard = [format!("far-audio:{}", hex(&audio))];
    let media = media_frame(&sid, 1, &audio);
    let connected = json!({"event": "connected", "protocol": "Call", "version": "1.0.0"});
    let handshake = run_steps(
        p,
        40,
        &[
            twilio("connected", &connected, nothing),
            twilio("start", &start, nothing),
        ],
    );
    let before_start = run_steps(p, 41, &[twilio("media", &media, nothing)]);
    let after_start = run_steps(
        p,
        42,
        &[
            twilio("start", &start, nothing),
            twilio("media", &media, &heard),
            twilio(
                "media on another call",
                &media_frame(OTHER_SID, 2, &audio),
                nothing,
            ),
        ],
    );
    let typed = run_steps(
        p,
        43,
        &[
            twilio("start", &start, nothing),
            twilio(
                "type-tagged append",
                &json!({"type": "input_audio_buffer.append", "audio": base64_encode(&audio)}),
                nothing,
            ),
        ],
    );
    RouteObs {
        opened,
        arrived,
        dialect,
        route,
        signature_doors,
        inbound_ws_auths,
        claim,
        selectors,
        handshake,
        before_start,
        after_start,
        typed,
    }
}

fn quiet(run: &Run, lines: usize) -> Result<(), String> {
    if !run.anomalies.is_empty() || run.done != 0 || run.lines.len() != lines {
        return Err(format!("{run:?}"));
    }
    Ok(())
}

fn route_check(o: &RouteObs) -> Result<String, String> {
    let claimed = |line: &str, dialect: u16| {
        o.opened
            .claims
            .iter()
            .any(|c| c.line == line && c.refusal_dialect == dialect)
    };
    if o.opened.outcome != Outcome::Ready || !claimed("GET /twilio/{call_id} ws", 2) {
        return Err(format!(
            "the snapshot does not claim the Twilio socket, refused in Twilio's dialect: {:?}",
            o.opened
        ));
    }
    let want_claim = format!(
        "{WS_TRANSPORT} {:?} alts={:?}",
        Selector::PrefixOneLevel("/twilio"),
        ["webhook-signature"]
    );
    if o.claim != want_claim {
        return Err(format!(
            "the Twilio claim is `{}`; want `{want_claim}` (the ws transport, the one-level \
             /twilio prefix, the webhook-signature alternative alone)",
            o.claim
        ));
    }
    let want_selectors = [
        "/twilio/call_0001=Some(TwilioMediaStreams)",
        "/twilio=None",
        "/twilio/a/b=None",
        "/twiliofoo=None",
    ];
    if o.selectors != want_selectors {
        return Err(format!(
            "the prefix is not one level deep: {:?}",
            o.selectors
        ));
    }
    if o.route != "GET /twilio/{call_id} ws upgrade=true auth=webhook-signature"
        || o.signature_doors != ["/twilio/{call_id}"]
        || !o
            .inbound_ws_auths
            .iter()
            .any(|a| a == "ws webhook-signature")
    {
        return Err(format!(
            "the Twilio door is `{}` (signature doors {:?}, inbound needs {:?}): an upgrade on \
             the ws transport under the webhook-signature auth, which no other door shares",
            o.route, o.signature_doors, o.inbound_ws_auths
        ));
    }
    let a = &o.arrived;
    if a.outcome != Outcome::Ready
        || a.principal != PRINCIPAL_REQUIRED
        || a.route != (ROUTE_DIRECT, MODEL.to_string())
        || o.dialect != Dialect::TwilioMediaStreams.name()
    {
        return Err(format!(
            "the Twilio door arrived as {a:?} in dialect {}: it must ask for a principal",
            o.dialect
        ));
    }
    quiet(&o.handshake, 2).map_err(|e| format!("connected then start was not quiet: {e}"))?;
    quiet(&o.before_start, 1).map_err(|e| format!("media before start: {e}"))?;
    if o.before_start.lines != ["media -> []"] {
        return Err(format!(
            "audio reached the far end before a start bound the call: {:?}",
            o.before_start
        ));
    }
    let want_after = [
        "start -> []".to_string(),
        format!("media -> [far-audio:{}]", hex(&[7_u8; 160])),
        "media on another call -> []".to_string(),
    ];
    quiet(&o.after_start, 3).map_err(|e| format!("start then media: {e}"))?;
    if o.after_start.lines != want_after {
        return Err(format!(
            "the session did not open on the start frame: {:?}",
            o.after_start.lines
        ));
    }
    quiet(&o.typed, 2).map_err(|e| format!("a type-tagged frame: {e}"))?;
    if o.typed.lines != ["start -> []", "type-tagged append -> []"] {
        return Err(format!(
            "an OpenAI type-tagged frame was taken for Twilio audio: {:?}",
            o.typed.lines
        ));
    }
    Ok(
        "the Twilio claim is on the ws transport at the one-level /twilio prefix with the \
         webhook-signature alternative alone (an upgrade line no other door shares), arrives for \
         a principal on the session model's DIRECT route, and the session opens on the \
         event-tagged start frame: no audio before it, audio after it, none for another call's \
         streamSid, none from a type-tagged frame. Refusing a missing signature 401, the \
         HMAC-SHA1 X-Twilio-Signature verify and the boot admitting the claim are the kernel's \
         and the auth plugin's"
            .to_string(),
    )
}

fn route(rig: &Rig, slice: &str, fx: &Fixtures) -> bool {
    judge(
        slice,
        "the Twilio door: claim, auth alternative, arrival and the start frame",
        &rig.both(|p| route_script(p, fx)),
        &route_check,
        &|o: &RouteObs| {
            let mut planted = o.clone();
            planted.claim = planted.claim.replace("webhook-signature", "bearer");
            planted
        },
    )
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// twilio-media
// ══════════════════════════════════════════════════════════════════════════════════════════════

#[derive(Clone, Debug, PartialEq, Eq)]
struct MediaObs {
    call: Run,
    other: Run,
    after_end: Vec<String>,
}

/// `v`, as the call `sid` sent it.
fn with_sid(mut v: Value, sid: &str) -> Value {
    v["streamSid"] = json!(sid);
    v
}

fn media_steps(fx: &Fixtures, sid: &str) -> Result<Vec<Step>, String> {
    let nothing: &[String] = &[];
    let start = fx.get("from-twilio.start.json")?;
    let mut start_here = start;
    start_here["start"]["streamSid"] = json!(sid);
    start_here["streamSid"] = json!(sid);
    let connected = fx.get("from-twilio.connected.json")?;
    let dtmf = with_sid(fx.get("from-twilio.dtmf.json")?, sid);
    let mark = with_sid(fx.get("from-twilio.mark.json")?, sid);
    let stop = with_sid(fx.get("from-twilio.stop.json")?, sid);
    let out_media = fx.get("to-twilio.media.json")?;
    let reply = payload_of(&out_media);
    let mut steps = vec![
        twilio("connected", &connected, nothing),
        twilio("start", &start_here, nothing),
    ];
    for n in 1..=3_u8 {
        let audio: Vec<u8> = (0..160)
            .map(|i| n.wrapping_mul(31).wrapping_add(i))
            .collect();
        steps.push(twilio(
            &format!("media {n}"),
            &media_frame(sid, usize::from(n), &audio),
            &[format!("far-audio:{}", hex(&audio))],
        ));
    }
    steps.push(twilio("dtmf", &dtmf, nothing));
    steps.push(far(
        "far audio",
        &far_delta(&reply),
        &[format!("caller-media:{sid}:{reply}")],
    ));
    steps.push(far(
        "far audio done",
        &far_done(),
        &[format!("caller-mark:{sid}:named")],
    ));
    steps.push(twilio("mark echo", &mark, nothing));
    steps.push(far(
        "far audio again",
        &far_delta(&reply),
        &[format!("caller-media:{sid}:{reply}")],
    ));
    steps.push(far(
        "barge-in",
        &far_speech_started(),
        &[format!("caller-clear:{sid}")],
    ));
    steps.push(twilio("stop", &stop, nothing));
    Ok(steps)
}

fn media_script(p: &Plugin<Plane>, first: &[Step], second: &[Step]) -> MediaObs {
    let opened = open(p, SESSION, Some(PUBLIC));
    let mut call = run_steps(p, 50, first);
    if opened.outcome != Outcome::Ready {
        call.anomalies
            .insert(0, format!("open {:?}", opened.outcome));
    }
    let other = run_steps(p, 51, second);
    let mut after_end = Vec::new();
    for (what, bytes) in [
        ("media", first[2].bytes.clone()),
        ("second stop", first[first.len() - 1].bytes.clone()),
        ("collect", Vec::new()),
    ] {
        let from = if what == "collect" {
            FROM_KERNEL
        } else {
            FROM_CALLER
        };
        let a = piece(p, &session(50, CLAIM, from, 0, &bytes));
        after_end.push(format!(
            "{what} {:?} emitted={}",
            a.outcome,
            a.emitted.len()
        ));
    }
    MediaObs {
        call,
        other,
        after_end,
    }
}

fn media_check(o: &MediaObs, first: &[Step], second: &[Step]) -> Result<String, String> {
    for (run, steps, what) in [
        (&o.call, first, "the call"),
        (&o.other, second, "another call"),
    ] {
        if !run.anomalies.is_empty() {
            return Err(format!(
                "{what} was not answered READY: {:?}",
                run.anomalies
            ));
        }
        let want = wanted(steps);
        if run.lines != want {
            return Err(format!(
                "{what} was answered {:?}; want {want:?}",
                run.lines
            ));
        }
        if run.done != 1 {
            return Err(format!("{what} ended {} time(s); want once", run.done));
        }
    }
    if o.after_end
        != [
            "media Refused emitted=0",
            "second stop Refused emitted=0",
            "collect Refused emitted=0",
        ]
    {
        return Err(format!("an ended call still answered: {:?}", o.after_end));
    }
    Ok(
        "inbound media reaches the far end as the caller's audio, byte for byte (start and \
         connected, dtmf and the mark echo reach it as nothing); the far end's audio is written \
         back as media frames on the call's own streamSid (a second call carries its own), the \
         end of its audio as a named mark, a barge-in as clear; stop ends the call once and the \
         ended call is refused on every side"
            .to_string(),
    )
}

fn media(rig: &Rig, slice: &str, fx: &Fixtures) -> bool {
    let first = fx.sid().and_then(|sid| media_steps(fx, &sid));
    let second = media_steps(fx, OTHER_SID);
    let (Ok(first), Ok(second)) = (first, second) else {
        result(
            slice,
            false,
            "fixtures",
            "the twilio fixtures are unreadable",
        );
        return false;
    };
    judge(
        slice,
        "Twilio media in and out, mark, clear, and the one end",
        &rig.both(|p| media_script(p, &first, &second)),
        &|o: &MediaObs| media_check(o, &first, &second),
        &|o: &MediaObs| {
            let mut planted = o.clone();
            for line in &mut planted.call.lines {
                if line.starts_with("far audio ->") {
                    *line = line.replace("caller-media:", "caller-media:MZwrong");
                }
            }
            planted
        },
    )
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// twilio-metering
// ══════════════════════════════════════════════════════════════════════════════════════════════

/// 20 ms of µ-law: 160 bytes.
fn chunk(n: usize) -> Vec<u8> {
    vec![u8::try_from(n % 251).unwrap_or(0); 160]
}

/// `frames` frames of Twilio media on stream `stream`, as caller pieces; the last answer, and how
/// many were not answered READY.
fn caller_media(p: &Plugin<Plane>, stream: u64, sid: &str, frames: usize) -> (Answer, usize) {
    let mut last = None;
    let mut bad = 0;
    for n in 0..frames {
        let bytes = bytes_of(&media_frame(sid, n, &chunk(n)));
        let a = piece(p, &session(stream, CLAIM, FROM_CALLER, 0, &bytes));
        bad += usize::from(a.outcome != Outcome::Ready);
        last = Some(a);
    }
    (
        last.unwrap_or_else(|| piece(p, &session(stream, CLAIM, FROM_KERNEL, 0, &[]))),
        bad,
    )
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TwilioMeterObs {
    lines: Vec<String>,
}

fn meter_script(p: &Plugin<Plane>, fx: &Fixtures) -> TwilioMeterObs {
    let _ = open(p, SESSION, Some(PUBLIC));
    let sid = fx.sid().unwrap_or_default();
    let start = bytes_of(&fx.get("from-twilio.start.json").unwrap_or(Value::Null));
    let stop = bytes_of(&fx.get("from-twilio.stop.json").unwrap_or(Value::Null));
    let mut lines = Vec::new();
    // Call A: two seconds of caller audio, the far end answers the turn, a second turn is open
    // (a short answer's re-call does not count its audio twice) when Twilio sends stop.
    lines.push(units_of(
        "start",
        &piece(p, &session(60, CLAIM, FROM_CALLER, 0, &start)),
    ));
    let (a, bad) = caller_media(p, 60, &sid, 100);
    lines.push(units_of("caller audio 2s", &a));
    lines.push(format!("frames not READY {bad}"));
    let turn = Piece {
        attempt_no: 1,
        ..session(60, CLAIM, FROM_KERNEL, 0, &[])
    };
    lines.push(units_of("turn attempt", &piece(p, &turn)));
    let far = Piece {
        status: 101,
        ..session(60, CLAIM, FROM_FAR_END, PIECE_HAS_STATUS, USAGE_DONE)
    };
    lines.push(units_of("far usage", &piece(p, &far)));
    lines.push(units_of(
        "collect",
        &piece(p, &session(60, CLAIM, FROM_KERNEL, 0, &[])),
    ));
    let (a, _) = caller_media(p, 60, &sid, 49);
    lines.push(units_of("second turn 0.98s", &a));
    let short = bytes_of(&media_frame(&sid, 49, &chunk(49)));
    let x = Piece {
        units_cap: 2,
        ..session(60, CLAIM, FROM_CALLER, 0, &short)
    };
    lines.push(units_of("short", &piece(p, &x)));
    lines.push(units_of(
        "short re-call",
        &piece(p, &session(60, CLAIM, FROM_CALLER, 0, &short)),
    ));
    let end = piece(p, &session(60, CLAIM, FROM_CALLER, 0, &stop));
    lines.push(format!(
        "{} done={}",
        units_of("stop mid-turn", &end),
        end.done
    ));
    let again = piece(p, &session(60, CLAIM, FROM_CALLER, 0, &stop));
    lines.push(format!(
        "{} done={}",
        units_of("second stop", &again),
        again.done
    ));
    // Call B: the far end never answered; one second of audio, then stop.
    lines.push(units_of(
        "unanswered start",
        &piece(p, &session(61, CLAIM, FROM_CALLER, 0, &start)),
    ));
    let (a, _) = caller_media(p, 61, &sid, 50);
    lines.push(units_of("unanswered audio 1s", &a));
    let end = piece(p, &session(61, CLAIM, FROM_CALLER, 0, &stop));
    lines.push(format!(
        "{} done={}",
        units_of("unanswered stop", &end),
        end.done
    ));
    // Call C: the turn is closed when stop arrives: nothing is counted twice.
    lines.push(units_of(
        "settled start",
        &piece(p, &session(62, CLAIM, FROM_CALLER, 0, &start)),
    ));
    let _ = caller_media(p, 62, &sid, 100);
    let turn = Piece {
        attempt_no: 1,
        ..session(62, CLAIM, FROM_KERNEL, 0, &[])
    };
    let _ = piece(p, &turn);
    let far = Piece {
        status: 101,
        ..session(62, CLAIM, FROM_FAR_END, PIECE_HAS_STATUS, USAGE_DONE)
    };
    let _ = piece(p, &far);
    let end = piece(p, &session(62, CLAIM, FROM_CALLER, 0, &stop));
    lines.push(format!(
        "{} done={}",
        units_of("settled stop", &end),
        end.done
    ));
    TwilioMeterObs { lines }
}

fn meter_expected() -> Vec<String> {
    vec![
        "start Ready units=[]".to_string(),
        "caller audio 2s Ready units=[]".to_string(),
        "frames not READY 0".to_string(),
        "turn attempt Ready units=[]".to_string(),
        format!("far usage Ready units=[{}]", usage_units(2)),
        format!("collect Ready units=[{}]", usage_units(2)),
        format!("second turn 0.98s Ready units=[{}]", usage_units(2)),
        "short Failed units=[needed 6]".to_string(),
        format!("short re-call Ready units=[{}]", usage_units(2)),
        format!("stop mid-turn Ready units=[{}] done=true", usage_units(3)),
        "second stop Refused units=[] done=false".to_string(),
        "unanswered start Ready units=[]".to_string(),
        "unanswered audio 1s Ready units=[]".to_string(),
        "unanswered stop Ready units=[4:1=1] done=true".to_string(),
        format!("settled stop Ready units=[{}] done=true", usage_units(2)),
    ]
}

fn meter_check(o: &TwilioMeterObs) -> Result<String, String> {
    let want = meter_expected();
    if o.lines != want {
        return Err(format!("the session reported {:?}; want {want:?}", o.lines));
    }
    Ok(
        "a Twilio session reports its units per declared class once per turn: the far end's \
         tokens and the audio seconds of the closed turn when the far end reports it, a short \
         answer's re-call does not count its audio twice, a call ending mid-turn (stop) settles \
         that open turn's audio once instead of discarding it, an unanswered call reports its \
         audio and no fee, a closed turn is not counted again at stop, and a second stop reports \
         nothing. Reserving, capping and ledgering the units are the kernel's session account"
            .to_string(),
    )
}

fn metering(rig: &Rig, slice: &str, fx: &Fixtures) -> bool {
    judge(
        slice,
        "a Twilio session's units, reported per declared class, the open turn settled at stop",
        &rig.both(|p| meter_script(p, fx)),
        &meter_check,
        &|o: &TwilioMeterObs| {
            let mut planted = o.clone();
            planted.lines[9] = planted.lines[9].replace("4:1=3", "4:1=2");
            planted
        },
    )
}
