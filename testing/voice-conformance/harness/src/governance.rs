// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIVE VISION CHECKPOINTS, AT THE DOOR — observations, never a conformance result (the runner
//! keeps governance out of the conformance tally). Each is probed on both doors and judged like
//! any leg; the process always exits 0.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{FROM_CALLER, FROM_FAR_END, PIECE_LAST};
use busbar_plane_streaming::session_door::CEILING_TICK_NS;
use busbar_plane_streaming::session_pump::SESSION_CEILING_REASON;
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::Plugin;
use serde_json::json;

use crate::codec_legs::{caller_norms, downscope_bridge, far_norms, frame, Dialect, Norm};
use crate::composition::{downlink, uplink, usage_units, USAGE_DONE};
use crate::door::{
    drive, judge, open, piece, refusal, result, session, tick, Emission, Log, Piece, Rendered, Rig,
    Session, PUBLIC, SESSION,
};

/// `governance <checkpoint>`: one observation; always exit 0.
pub fn run(rig: &Rig, checkpoint: &str) -> i32 {
    match checkpoint {
        "V1-barge-in-preemption" => barge_in(rig, checkpoint),
        "V2-turn-budget-enforcement" => ceiling(rig, checkpoint),
        "V3-metering-lease-settled" => settled_once(rig, checkpoint),
        "V4-dialect-downscope" => downscope(rig, checkpoint),
        "D2-hard-close-on-exhaustion" => hard_close(rig, checkpoint),
        other => result(other, false, "checkpoint", "unknown checkpoint"),
    }
    0
}

// ── V1: a barge-in preempts the turn ────────────────────────────────────────────────────────────

fn barge_script(p: &Plugin<Plane>) -> Log {
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 100, 2);
    // 96 bytes of 24 kHz PCM16: the caller has heard 2 ms of the far end's answer.
    s.push(FROM_FAR_END, 0, &downlink(96));
    s.push(
        FROM_FAR_END,
        0,
        &frame(&json!({"type": "input_audio_buffer.speech_started",
            "audio_start_ms": 0, "item_id": "it1"})),
    );
    s.log
}

fn barge_check(log: &Log) -> Result<String, String> {
    let far = far_norms(Dialect::OpenAi, log);
    let near = caller_norms(Dialect::OpenAi, log);
    if !log.anomalies.is_empty() {
        return Err(format!("not every piece READY: {:?}", log.anomalies));
    }
    if far != [Norm::ResponseCancel, Norm::Truncate(2)] {
        return Err(format!("the barge-in sent the far end {far:?}"));
    }
    if near != [Norm::AudioDown(vec![0; 96]), Norm::SpeechStart] {
        return Err(format!("the caller was sent {near:?}"));
    }
    Ok(
        "the far end's speech_started preempts the turn: the door cancels the response and \
         truncates the item at the 2 ms the caller heard, and tells the caller"
            .to_string(),
    )
}

fn barge_in(rig: &Rig, checkpoint: &str) {
    judge(
        checkpoint,
        "barge-in",
        &rig.both(barge_script),
        &barge_check,
        &|l: &Log| {
            let mut planted = l.clone();
            if let Some(i) = planted.emissions.iter().rposition(|e| e.to_far) {
                planted.emissions.remove(i);
            }
            planted
        },
    );
}

// ── V2: a session is bounded ────────────────────────────────────────────────────────────────────

const CEILING: &[u8] = br#"{"session":{"model":"m-cap"},"session_max_secs":1}"#;

#[derive(Clone, Debug, PartialEq, Eq)]
struct CeilingObs {
    next: u64,
    owed: Vec<u64>,
    log: Log,
}

fn ceiling_script(p: &Plugin<Plane>) -> CeilingObs {
    let _ = open(p, CEILING, Some(PUBLIC));
    let mut s = Session::open(p, 110, 2);
    let (_, next) = tick(p, 1_000);
    let _ = tick(p, 1_000 + 1_000_000_000);
    let (_, owed) = drive(p);
    s.collect();
    CeilingObs {
        next,
        owed,
        log: s.log,
    }
}

fn ceiling_check(o: &CeilingObs) -> Result<String, String> {
    if o.next != 1_000 + CEILING_TICK_NS {
        return Err(format!(
            "a ceilinged generation asked for its next tick at {}",
            o.next
        ));
    }
    if o.owed != [110] {
        return Err(format!("drive named {:?} once the ceiling passed", o.owed));
    }
    let told = caller_norms(Dialect::OpenAi, &o.log);
    let said = matches!(told.as_slice(), [Norm::Error(code, _)] if code == SESSION_CEILING_REASON);
    if !o.log.anomalies.is_empty() || !said || o.log.done != 1 {
        return Err(format!(
            "past its ceiling the session told the caller {told:?} and ended {} time(s)",
            o.log.done
        ));
    }
    Ok(format!(
        "a session past `streams.session_max_secs` is told why ({SESSION_CEILING_REASON}) and \
         ended once, on the kernel's tick clock; a money cut is the kernel's, rendered through \
         `refusal`"
    ))
}

fn ceiling(rig: &Rig, checkpoint: &str) {
    judge(
        checkpoint,
        "the wall-clock ceiling",
        &rig.both(ceiling_script),
        &ceiling_check,
        &|o: &CeilingObs| {
            let mut planted = o.clone();
            planted.log.done = 0;
            planted
        },
    );
}

// ── V3: a turn's units settle once ──────────────────────────────────────────────────────────────

/// The three answers of a turn whose report is re-called once, as lines.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Settled {
    lines: Vec<String>,
}

fn settle_script(p: &Plugin<Plane>) -> Settled {
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 120, 2);
    s.push(FROM_CALLER, 0, &uplink(1000));
    let narrow = Piece {
        units_cap: 2,
        ..session(120, 2, FROM_FAR_END, 0, USAGE_DONE)
    };
    let a = piece(p, &narrow);
    let b = piece(p, &session(120, 2, FROM_FAR_END, 0, USAGE_DONE));
    let c = piece(p, &session(120, 2, FROM_CALLER, PIECE_LAST, &[]));
    Settled {
        lines: vec![
            format!("narrow {:?} units=[{}]", a.outcome, a.units_line()),
            format!("re-call {:?} units=[{}]", b.outcome, b.units_line()),
            format!(
                "end {:?} done={} units=[{}]",
                c.outcome,
                c.done,
                c.units_line()
            ),
        ],
    }
}

fn settle_check(o: &Settled) -> Result<String, String> {
    let lines = &o.lines;
    let want = [
        "narrow Failed units=[needed 6]".to_string(),
        format!("re-call Ready units=[{}]", usage_units(1)),
        format!("end Ready done=true units=[{}]", usage_units(1)),
    ];
    if *lines != want {
        return Err(format!("the turn settled as {lines:?}; want {want:?}"));
    }
    Ok(
        "a turn's usage settles exactly once: the re-call of a short answer reports the same \
         cumulative units, and the end adds nothing already settled"
            .to_string(),
    )
}

fn settled_once(rig: &Rig, checkpoint: &str) {
    judge(
        checkpoint,
        "units settle once",
        &rig.both(settle_script),
        &settle_check,
        &|o: &Settled| {
            let mut planted = o.clone();
            planted.lines[1] = planted.lines[1].replace("0:1=10", "0:1=20");
            planted
        },
    );
}

// ── V4: crossing a dialect down-scopes ──────────────────────────────────────────────────────────

fn widened(text: &str) -> bool {
    text.contains("semantic") || text.contains("g711")
}

fn downscope_script(p: &Plugin<Plane>) -> Log {
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 140, 2);
    s.push(FROM_CALLER, 0, &frame(&downscope_update()));
    s.log
}

fn downscope_update() -> serde_json::Value {
    json!({"type": "session.update", "session": {"instructions": "x",
        "turn_detection": {"type": "semantic_vad", "eagerness": "high"},
        "input_audio_format": "g711_ulaw", "output_audio_format": "g711_ulaw"}})
}

fn downscope_check(log: &Log) -> Result<String, String> {
    let bridged = downscope_bridge(&downscope_update());
    if !bridged.contains("Config") || widened(&bridged) {
        return Err(format!("the bridge toward Gemini widened: {bridged}"));
    }
    let far: Vec<&Emission> = log.emissions.iter().filter(|e| e.to_far).collect();
    if !log.anomalies.is_empty()
        || far.len() != 1
        || far
            .iter()
            .any(|e| widened(&String::from_utf8_lossy(&e.frame)))
        || !far_norms(Dialect::OpenAi, log)
            .iter()
            .any(|n| matches!(n, Norm::Config(_)))
    {
        return Err(format!(
            "the caller's session.update reached the far end as {far:?}"
        ));
    }
    Ok(
        "an OpenAI-only semantic_vad/g711 concept is down-scoped, never widened, toward Gemini; \
         and at the door the caller's session.update never reaches the far end: the locked \
         session params do"
            .to_string(),
    )
}

fn downscope(rig: &Rig, checkpoint: &str) {
    judge(
        checkpoint,
        "down-scope",
        &rig.both(downscope_script),
        &downscope_check,
        &|l: &Log| {
            let mut planted = l.clone();
            for e in &mut planted.emissions {
                if e.to_far {
                    e.frame = frame(&downscope_update());
                }
            }
            planted
        },
    );
}

// ── D2: an ended session is closed hard ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct CloseObs {
    log: Log,
    late: (Outcome, usize),
    cut: Rendered,
}

fn close_script(p: &Plugin<Plane>) -> CloseObs {
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 130, 2);
    s.push(FROM_FAR_END, 0, &downlink(96));
    s.push(FROM_CALLER, PIECE_LAST, &[]);
    let late = piece(p, &session(130, 2, FROM_FAR_END, 0, &downlink(96)));
    CloseObs {
        log: s.log,
        late: (late.outcome, late.emitted.len()),
        cut: refusal(p, 130, 0, 429, "the caller's budget is exhausted"),
    }
}

fn close_check(o: &CloseObs) -> Result<String, String> {
    if o.log.done != 1 || !o.log.anomalies.is_empty() {
        return Err(format!("the session did not end once: {:?}", o.log));
    }
    if o.late != (Outcome::Refused, 0) {
        return Err(format!(
            "far-end audio after the end was answered {:?}",
            o.late
        ));
    }
    let v: serde_json::Value = serde_json::from_str(&o.cut.body).unwrap_or_default();
    if o.cut.outcome != Outcome::Ready || v["error"]["type"] != "rate_limit_error" {
        return Err(format!("the cut rendered as {:?}", o.cut));
    }
    Ok(
        "once a session has ended no far-end audio reaches the caller (the stream is refused) \
         and the cut renders in the dialect's error shape; reading the chain dry and cutting \
         are the kernel's"
            .to_string(),
    )
}

fn hard_close(rig: &Rig, checkpoint: &str) {
    judge(
        checkpoint,
        "hard close",
        &rig.both(close_script),
        &close_check,
        &|o: &CloseObs| CloseObs {
            late: (Outcome::Ready, 128),
            ..o.clone()
        },
    );
}
