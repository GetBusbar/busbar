// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIXTURE LEGS — `spec-per-dialect`, `replay`, `cross-parity` — through the door's session
//! pieces.
//!
//! Each fixture's wire bytes are pushed through a live session on the door that speaks the
//! dialect — the caller's frames as caller pieces, the far end's as far-end pieces — on the linked
//! and the dropped door, and what the door relays is held to the SESSION RULES the plane states
//! (Law 5's relay): a caller frame reaches the far end as it arrived, except that a frame
//! configuring the session or asking for a response takes the session's locked keys; a far-end
//! frame reaches the caller as it arrived, every one of them (a usage report also becomes reported
//! units), and nothing goes to the far end on the caller's behalf (Law 11). Every frame the lock
//! does not govern is compared BYTE FOR BYTE, frame by frame, per side and in order (Law 5,
//! `BUSBAR-1.6.0.md` l.1903: a relay "sends the client's bytes with governed byte-level splices");
//! a governed frame is held to the lock at the JSON level ([`crate::wire::relayed_as_owed`]).
//!
//! What the door owes is computed by the harness's own reader of the wire ([`crate::wire`],
//! ARCHITECT ruling R-18), never by the plane's codec or splice: the harness is a black-box rig.
//! The codec halves these legs once carried — the IR round trip, the cross-dialect bridge and its
//! asymmetry rows — are the plane's own tests (`voice_corpus_tests`), where its codecs are visible;
//! the byte-level splice proof is its `splice_tests`.

use std::fs;
use std::path::Path;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{FROM_CALLER, FROM_FAR_END, UNITS_REPORTED};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::Plugin;
use serde_json::Value;

pub use crate::wire::Norm;

use crate::door::{
    judge_planted, open, result, Emission, Log, Plant, Rig, Session, PUBLIC, REALTIME_CLAIM,
    SESSION,
};
use crate::stated::{
    GEMINI_SOCKET_PATH, PER_SESSION_CLASS, RIDES_LIVE_SOCKET, RIDES_REALTIME_SOCKET,
};
use crate::wire::{self, Owed};

// ── the two dialects ────────────────────────────────────────────────────────────────────────────

/// What a plain OpenAI Realtime session dials under the member's base URL: the realtime socket
/// naming the session's model ([`crate::door::MODEL`], the model [`SESSION`] locks), as OpenAI's
/// own WS surface takes it (ARCHITECT ruling 2026-10-23 on Part 2 #45).
pub const REALTIME_DIAL: &str = "/v1/realtime?model=m-cap";

/// A duplex dialect the plane dials, and the session door that speaks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// OpenAI Realtime: the plain realtime socket (`GET /v1/realtime`, [`REALTIME_CLAIM`]).
    OpenAi,
    /// Gemini Live: the Gemini socket (claim 3).
    Gemini,
}

impl Dialect {
    /// The dialect a leg names.
    pub fn of(name: &str) -> Option<Self> {
        match name {
            "openai" => Some(Dialect::OpenAi),
            "gemini" => Some(Dialect::Gemini),
            _ => None,
        }
    }

    /// Its name in the legs.
    pub const fn name(self) -> &'static str {
        match self {
            Dialect::OpenAi => "openai",
            Dialect::Gemini => "gemini",
        }
    }

    /// The door claim that opens a session in it.
    pub const fn claim(self) -> u32 {
        match self {
            Dialect::OpenAi => REALTIME_CLAIM,
            Dialect::Gemini => 3,
        }
    }

    /// The declared need its far frames ride.
    pub const fn ride(self) -> u32 {
        match self {
            Dialect::OpenAi => RIDES_REALTIME_SOCKET,
            Dialect::Gemini => RIDES_LIVE_SOCKET,
        }
    }

    /// The far end's socket, under the member's base URL, as a session on the dialect's door dials
    /// it: OpenAI Realtime's names the session's model ([`REALTIME_DIAL`]).
    pub const fn socket(self) -> &'static str {
        match self {
            Dialect::OpenAi => REALTIME_DIAL,
            Dialect::Gemini => GEMINI_SOCKET_PATH,
        }
    }
}

fn bytes_of(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("serialize wire value")
}

/// `expected` appears, in order, as a subsequence of `tags`.
fn ordered_subsequence(tags: &[&str], expected: &[&str]) -> Result<(), String> {
    let mut i = 0;
    for want in expected {
        match tags[i..].iter().position(|t| t == want) {
            Some(off) => i += off + 1,
            None => {
                return Err(format!(
                    "expected concept '{want}' not found after position {i} in {tags:?}"
                ))
            }
        }
    }
    Ok(())
}

// ── wires, and what a session does with them ────────────────────────────────────────────────────

/// Which side of the session a frame comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// The caller.
    Up,
    /// The far end.
    Down,
}

/// One frame pushed to a session.
#[derive(Clone, Debug)]
pub struct Wire {
    /// Its side.
    pub dir: Dir,
    /// Its bytes.
    pub bytes: Vec<u8>,
}

/// The side a frame of `dialect` comes from, as the harness reads it: the caller's when it reads
/// as a caller frame, else the far end's. `None` for a frame it reads as neither.
fn side_of(dialect: Dialect, frame: &[u8]) -> Option<Dir> {
    if !wire::read_up(dialect, frame).is_empty() {
        Some(Dir::Up)
    } else if !wire::read_down(dialect, frame).is_empty() {
        Some(Dir::Down)
    } else {
        None
    }
}

/// Drive `wires` through ONE session on `p`'s door for `dialect`.
pub fn relay(p: &Plugin<Plane>, dialect: Dialect, wires: &[Wire]) -> Log {
    let opened = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 77, dialect.claim());
    if opened.outcome != Outcome::Ready {
        s.log.anomalies.push(format!("open {:?}", opened.outcome));
    }
    for w in wires {
        let from = match w.dir {
            Dir::Up => FROM_CALLER,
            Dir::Down => FROM_FAR_END,
        };
        s.push(from, 0, &w.bytes);
    }
    s.log
}

/// What the session rules say the door must relay for a sequence of wires: what each side is owed,
/// in order, and the token units the far end's reports add up to.
pub struct Expected {
    far: Vec<Owed>,
    caller: Vec<Vec<u8>>,
    tokens: Vec<(u32, u64)>,
    answered: bool,
}

/// The session rules over `wires`, computed from the wire by the harness's reader (never by the
/// door, never by the plane's code).
pub fn expect(dialect: Dialect, wires: &[Wire]) -> Expected {
    let mut x = Expected {
        far: Vec::new(),
        caller: Vec::new(),
        tokens: Vec::new(),
        answered: false,
    };
    let mut sums = [0_u64; 4];
    for w in wires {
        match w.dir {
            Dir::Up => match wire::owed(dialect, &w.bytes) {
                Owed::Nothing => {}
                owed => x.far.push(owed),
            },
            Dir::Down => {
                x.answered = true;
                if let Ok(Some(u)) = wire::usage(dialect, &w.bytes) {
                    for (sum, n) in sums.iter_mut().zip(u) {
                        *sum = sum.saturating_add(n);
                    }
                }
                x.caller.push(w.bytes.clone());
            }
        }
    }
    x.tokens = (0_u32..).zip(sums).filter(|(_, n)| *n != 0).collect();
    x
}

/// What the door relayed, read back by the harness: the far end's frames, the caller's, and every
/// concept's tag in the order the door emitted it.
pub struct Relayed {
    far: Vec<Norm>,
    caller: Vec<Norm>,
    tags: Vec<&'static str>,
}

/// Read `log`'s frames back under `dialect`.
pub fn decode_relay(dialect: Dialect, log: &Log) -> Relayed {
    let mut r = Relayed {
        far: Vec::new(),
        caller: Vec::new(),
        tags: Vec::new(),
    };
    for e in &log.emissions {
        let n = if e.to_far {
            wire::read_up(dialect, &e.frame)
        } else {
            wire::read_down(dialect, &e.frame)
        };
        r.tags.extend(n.iter().map(wire::tag));
        if e.to_far {
            r.far.extend(n);
        } else {
            r.caller.extend(n);
        }
    }
    r
}

/// The door's relay of a session against the session rules: every answer READY, no record row,
/// every far frame on the dialect's socket need, both sides' frames the frames the session rules
/// owe them (byte for byte, or under the lock), the far end's token reports as reported units
/// (and the session fee once the far end answered).
pub fn relay_check(dialect: Dialect, log: &Log, x: &Expected) -> Result<String, String> {
    if !log.anomalies.is_empty() {
        return Err(format!(
            "the door did not answer every piece READY: {:?}",
            log.anomalies
        ));
    }
    if log.records != 0 {
        return Err(format!(
            "the door wrote {} record row(s) on a session",
            log.records
        ));
    }
    for e in log.emissions.iter().filter(|e| e.to_far) {
        if e.need != dialect.ride() || e.verb != "GET" || e.target != dialect.socket() {
            return Err(format!(
                "a far frame rode need {} to {} {}, not the {} socket (need {})",
                e.need,
                e.verb,
                e.target,
                dialect.name(),
                dialect.ride()
            ));
        }
    }
    if let Some(e) = far_differs(dialect, &frames_to(log, true), &x.far) {
        return Err(format!("the far end {e}"));
    }
    if let Some(e) = frames_differ(&frames_to(log, false), &x.caller) {
        return Err(format!("the caller {e}"));
    }
    if let Some(u) = log.units.iter().find(|u| u.1 != UNITS_REPORTED) {
        return Err(format!("a unit was not reported by the far end: {u:?}"));
    }
    let tokens: Vec<(u32, u64)> = log
        .units
        .iter()
        .filter(|u| u.0 < 4)
        .map(|u| (u.0, u.2))
        .collect();
    if tokens != x.tokens {
        return Err(format!(
            "the token units reported {tokens:?}; the far end's reports add up to {:?}",
            x.tokens
        ));
    }
    let fee = log
        .units
        .iter()
        .any(|u| u.0 == PER_SESSION_CLASS && u.2 == 1);
    if fee != x.answered {
        return Err(format!(
            "the session fee unit reported {fee}, the far end answered {}",
            x.answered
        ));
    }
    let governed = x
        .far
        .iter()
        .filter(|o| matches!(o, Owed::Governed(_)))
        .count();
    Ok(format!(
        "the {} door relayed {} far ({governed} under the lock) / {} caller frame(s) by the \
         session rules, {} token unit(s)",
        dialect.name(),
        x.far.len(),
        x.caller.len(),
        tokens.len()
    ))
}

/// The frames `log` emitted toward one side, in order.
fn frames_to(log: &Log, to_far: bool) -> Vec<&[u8]> {
    log.emissions
        .iter()
        .filter(|e| e.to_far == to_far)
        .map(|e| e.frame.as_slice())
        .collect()
}

fn text(b: Option<&[u8]>) -> String {
    b.map_or_else(
        || "<none>".to_string(),
        |b| String::from_utf8_lossy(b).into_owned(),
    )
}

/// How the frames a side was `sent` differ from the frames it is owed byte for byte, if they do:
/// the first frame that differs, both ways, as text.
fn frames_differ(sent: &[&[u8]], want: &[Vec<u8>]) -> Option<String> {
    let n = sent.len().max(want.len());
    let i = (0..n).find(|&i| sent.get(i).copied() != want.get(i).map(Vec::as_slice))?;
    Some(format!(
        "was sent {} frame(s), owed {}; frame {i} was {} where the session rules owe {}",
        sent.len(),
        want.len(),
        text(sent.get(i).copied()),
        text(want.get(i).map(Vec::as_slice))
    ))
}

/// How the far end's frames differ from what it is owed, if they do: a frame owed byte for byte
/// must be those bytes; a governed frame must be the caller's under the lock.
fn far_differs(dialect: Dialect, sent: &[&[u8]], want: &[Owed]) -> Option<String> {
    if sent.len() != want.len() {
        return Some(format!(
            "was sent {} frame(s), owed {}: {}",
            sent.len(),
            want.len(),
            sent.iter()
                .map(|f| text(Some(*f)))
                .collect::<Vec<_>>()
                .join(" | ")
        ));
    }
    sent.iter()
        .zip(want)
        .enumerate()
        .find_map(|(i, (got, owed))| match owed {
            Owed::Exact(bytes) if *got != bytes.as_slice() => Some(format!(
                "frame {i} was {} where the session rules owe {}",
                text(Some(*got)),
                text(Some(bytes.as_slice()))
            )),
            Owed::Governed(caller) => wire::relayed_as_owed(dialect, caller, got)
                .err()
                .map(|e| format!("frame {i} was {} under the lock: {e}", text(Some(*got)))),
            _ => None,
        })
}

/// THE PLANTED WRONG DOOR for a relay: one that reports a token the far end never sent.
pub fn plant_units(log: &Log) -> Log {
    let mut planted = log.clone();
    planted.units.push((1, UNITS_REPORTED, 7));
    planted
}

/// THE PLANTED WRONG DOOR that RE-ENCODES instead of relaying bytes (Law 5, `BUSBAR-1.6.0.md`
/// l.1903: a relay "sends the client's bytes"): the first frame it emits loses a member no reader
/// models (`event_id`), or gains one, and is re-serialized. Every concept the reader reads is
/// unchanged, so only the frame-level comparison refuses it. A log with no frame gains one the
/// session never owed.
pub fn plant_rewrite(log: &Log) -> Log {
    let mut planted = log.clone();
    let first = planted.emissions.iter().enumerate().find_map(|(i, e)| {
        let v = serde_json::from_slice::<Value>(&e.frame).ok()?;
        v.as_object().cloned().map(|o| (i, o))
    });
    match first {
        Some((i, mut o)) => {
            if o.remove("event_id").is_none() {
                o.insert("event_id".to_string(), Value::from("evt_planted"));
            }
            planted.emissions[i].frame = bytes_of(&Value::Object(o));
        }
        None => planted.emissions.push(Emission {
            to_far: false,
            frame: b"{}".to_vec(),
            need: 0,
            verb: String::new(),
            target: String::new(),
        }),
    }
    planted
}

/// THE PLANTED WRONG DOOR that DROPS a frame: the last frame it owed is never emitted (a far-end
/// transcript, `goAway` or `response.output_item.done` the reader reads to nothing is dropped as
/// silently as a read one). A log with no frame gains one the session never owed.
pub fn plant_drop(log: &Log) -> Log {
    let mut planted = log.clone();
    if planted.emissions.pop().is_none() {
        planted.emissions.push(Emission {
            to_far: true,
            frame: b"{}".to_vec(),
            need: 0,
            verb: String::new(),
            target: String::new(),
        });
    }
    planted
}

/// The relay legs' planted wrong doors: a phantom unit, a re-encoded frame, a dropped frame.
pub fn relay_plants() -> [Plant<'static, Log>; 3] {
    const UNITS: &dyn Fn(&Log) -> Log = &plant_units;
    const REWRITE: &dyn Fn(&Log) -> Log = &plant_rewrite;
    const DROP: &dyn Fn(&Log) -> Log = &plant_drop;
    [
        ("a token the far end never sent", UNITS),
        ("a frame re-encoded, not relayed", REWRITE),
        ("a frame dropped", DROP),
    ]
}

/// Judge one relay of `wires` on both doors, with `read` (the harness's reading of the wires)
/// folded in.
fn judge_relay(
    rig: &Rig,
    slice: &str,
    what: &str,
    dialect: Dialect,
    wires: &[Wire],
    read: &Result<String, String>,
) -> bool {
    let x = expect(dialect, wires);
    let seen = rig.both(|p| relay(p, dialect, wires));
    judge_planted(
        slice,
        what,
        &seen,
        &|log: &Log| {
            let read = read.clone()?;
            let door = relay_check(dialect, log, &x)?;
            Ok(format!("read: {read}; door: {door}"))
        },
        &relay_plants(),
    )
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// spec-per-dialect
// ══════════════════════════════════════════════════════════════════════════════════════════════

/// Fixtures that legitimately carry NO shared concept, with the reason (far-end frames a relay
/// passes on and no session rule reads).
fn drop_reason(dialect: Dialect, fixture: &str) -> Option<&'static str> {
    match (dialect, fixture) {
        (Dialect::Gemini, "goAway.json") => {
            Some("gemini_go_away: no OpenAI advance-disconnect twin (drop+warn)")
        }
        (Dialect::Gemini, "toolCallCancellation.json") => {
            Some("gemini_tool_call_cancellation: no OpenAI server-driven cancel (drop+warn)")
        }
        (Dialect::Gemini, "serverContent.inputTranscription.json") => {
            Some("input transcription side-channel: no shared concept (drop+warn)")
        }
        (Dialect::Gemini, "serverContent.outputTranscription.json") => {
            Some("output transcription side-channel: no shared concept (drop+warn)")
        }
        _ => None,
    }
}

/// The harness's reading of one fixture, and the side its frame is pushed from.
fn spec_read(dialect: Dialect, fixture: &str, frame: &[u8]) -> (Result<String, String>, Dir) {
    match side_of(dialect, frame) {
        Some(Dir::Up) => {
            let n = wire::read_up(dialect, frame);
            (Ok(format!("a caller frame ({:?})", tags(&n))), Dir::Up)
        }
        Some(Dir::Down) => {
            let n = wire::read_down(dialect, frame);
            (Ok(format!("a far-end frame ({:?})", tags(&n))), Dir::Down)
        }
        // A documented drop is a far-end frame with no shared concept: pushed from the far end,
        // the door relays its bytes to the caller unchanged (a relay is byte-level, Law 5).
        None => match drop_reason(dialect, fixture) {
            Some(reason) => (Ok(format!("documented drop — {reason}")), Dir::Down),
            None => (
                Err("reads as no frame of the dialect and is not a documented drop".to_string()),
                Dir::Down,
            ),
        },
    }
}

fn tags(n: &[Norm]) -> Vec<&'static str> {
    n.iter().map(wire::tag).collect()
}

/// `spec <dialect> <dir>`: every fixture through the dialect's door.
pub fn spec(rig: &Rig, dialect_name: &str, dir: &Path) -> i32 {
    let Some(dialect) = Dialect::of(dialect_name) else {
        result(dialect_name, false, "dialect", "unknown dialect");
        return 1;
    };
    let mut fixtures: Vec<String> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.ends_with(".json"))
            .collect(),
        Err(e) => {
            result(
                dialect.name(),
                false,
                "fixtures",
                &format!("{}: {e}", dir.display()),
            );
            return 1;
        }
    };
    fixtures.sort();
    if fixtures.is_empty() {
        result(dialect.name(), false, "fixtures", "no .json fixtures");
        return 1;
    }
    let mut fails = 0;
    for f in &fixtures {
        let Some(frame) = read_fixture(&dir.join(f)) else {
            result(dialect.name(), false, f, "unreadable fixture");
            fails += 1;
            continue;
        };
        let (read, side) = spec_read(dialect, f, &frame);
        let wires = [Wire {
            dir: side,
            bytes: frame,
        }];
        if !judge_relay(rig, dialect.name(), f, dialect, &wires, &read) {
            fails += 1;
        }
    }
    i32::from(fails > 0)
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// replay
// ══════════════════════════════════════════════════════════════════════════════════════════════

fn read_jsonl(path: &Path) -> Result<Vec<Value>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).map_err(|e| format!("{}: {e}", path.display())))
        .collect()
}

/// A transcript's frames, as the session saw them (client → caller, server → far end).
fn transcript_wires(lines: &[Value]) -> Vec<Wire> {
    lines
        .iter()
        .filter_map(|line| {
            let ev = line.get("event")?;
            let dir = match line.get("dir").and_then(Value::as_str) {
                Some("client") => Dir::Up,
                Some("server") => Dir::Down,
                _ => return None,
            };
            Some(Wire {
                dir,
                bytes: bytes_of(ev),
            })
        })
        .collect()
}

/// The harness's reading of a transcript: every frame read in order, and the skeleton in order.
fn replay_read(dialect: Dialect, wires: &[Wire], skeleton: &[&str]) -> Result<String, String> {
    let mut all = Vec::new();
    for w in wires {
        all.extend(match w.dir {
            Dir::Up => wire::read_up(dialect, &w.bytes),
            Dir::Down => wire::read_down(dialect, &w.bytes),
        });
    }
    ordered_subsequence(&tags(&all), skeleton)?;
    Ok(format!(
        "{} concept(s) over {} frame(s), skeleton {skeleton:?} in order",
        all.len(),
        wires.len()
    ))
}

/// `replay <root>`: each dialect's captured transcript through one session on its door.
pub fn replay(rig: &Rig, root: &Path) -> i32 {
    // The skeletons the transcripts carry; the door's relay must show the same concepts in the
    // order it emitted them: it relays every frame, the far end's usage reports included.
    let cases: [(Dialect, &[&str]); 2] = [
        (
            Dialect::OpenAi,
            &[
                "config",
                "connect",
                "audio-in",
                "speech-start",
                "tool-args",
                "tool-close",
                "tool-result",
                "audio-out",
                "speech-start",
                "cancel",
            ],
        ),
        (
            Dialect::Gemini,
            &[
                "config",
                "connect",
                "audio-in",
                "tool-open",
                "tool-args",
                "tool-close",
                "tool-result",
                "audio-out",
                "speech-start",
                "audio-done",
                "usage",
            ],
        ),
    ];
    let mut fails = 0;
    for (dialect, skeleton) in cases {
        let what = format!("{}-transcript", dialect.name());
        let lines = match read_jsonl(&root.join(dialect.name()).join("transcript.jsonl")) {
            Ok(lines) => lines,
            Err(e) => {
                result("default", false, &what, &e);
                fails += 1;
                continue;
            }
        };
        let wires = transcript_wires(&lines);
        let read = replay_read(dialect, &wires, skeleton);
        let x = expect(dialect, &wires);
        let seen = rig.both(|p| relay(p, dialect, &wires));
        let pass = judge_planted(
            "default",
            &what,
            &seen,
            &|log: &Log| {
                let read = read.clone()?;
                let door = relay_check(dialect, log, &x)?;
                ordered_subsequence(&decode_relay(dialect, log).tags, skeleton)?;
                Ok(format!(
                    "read: {read}; door: {door}, skeleton {skeleton:?} in emitted order"
                ))
            },
            &relay_plants(),
        );
        if !pass {
            fails += 1;
        }
    }
    i32::from(fails > 0)
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// cross-parity
// ══════════════════════════════════════════════════════════════════════════════════════════════

fn pair_slice(a: Dialect, b: Dialect) -> &'static str {
    match (a, b) {
        (Dialect::OpenAi, Dialect::OpenAi) => "oo",
        (Dialect::OpenAi, Dialect::Gemini) => "og",
        (Dialect::Gemini, Dialect::OpenAi) => "go",
        (Dialect::Gemini, Dialect::Gemini) => "gg",
    }
}

fn read_fixture(path: &Path) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    Some(bytes_of(&v))
}

/// `cross <pair> <openai dir> <gemini dir> <map>`: for every shared concept of the map, the
/// destination dialect's own fixtures for it pushed through one session on its door (ARCHITECT
/// ruling R-18: the door half pushes per-concept fixtures). The bridge A → IR → B → IR and every
/// asymmetry row are the plane's codec half (`every_shared_concept_survives_the_cross_dialect_bridge`).
pub fn cross(rig: &Rig, pair: &str, oa: &Path, ge: &Path, map: &Value) -> i32 {
    let (a, b) = match pair {
        "oo" => (Dialect::OpenAi, Dialect::OpenAi),
        "og" => (Dialect::OpenAi, Dialect::Gemini),
        "go" => (Dialect::Gemini, Dialect::OpenAi),
        "gg" => (Dialect::Gemini, Dialect::Gemini),
        other => {
            result(other, false, "pair", "unknown ordered pair");
            return 1;
        }
    };
    let slice = pair_slice(a, b);
    let dir = if b == Dialect::OpenAi { oa } else { ge };
    let mut fails = 0;
    let Some(concepts) = map["concepts"].as_array() else {
        result(
            slice,
            false,
            "map",
            "the cross-dialect map has no concepts array",
        );
        return 1;
    };
    for c in concepts {
        let concept = c["concept"].as_str().unwrap_or("?");
        let named: Vec<&str> = c[b.name()]["fixtures"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(Value::as_str)
            .filter(|n| !n.is_empty() && !n.ends_with(".jsonl"))
            .collect();
        if named.is_empty() {
            println!(
                "SUBITEM {slice}:{concept} PENDING — {} carries no fixture of it; the bridge \
                 toward it is the plane's codec half",
                b.name()
            );
            continue;
        }
        let mut wires = Vec::new();
        let mut unread = Vec::new();
        for name in &named {
            match read_fixture(&dir.join(name)) {
                Some(bytes) => match side_of(b, &bytes) {
                    Some(side) => wires.push(Wire { dir: side, bytes }),
                    None => unread.push((*name).to_string()),
                },
                None => unread.push(format!("{name} (missing)")),
            }
        }
        let read = if unread.is_empty() {
            Ok(format!(
                "{} {} fixture(s) of `{concept}`",
                wires.len(),
                b.name()
            ))
        } else {
            Err(format!(
                "the concept's {} fixture(s) {unread:?} read as no frame of the dialect",
                b.name()
            ))
        };
        let what = format!("shared:{}", named.join("+"));
        if !judge_relay(rig, slice, &what, b, &wires, &read) {
            fails += 1;
        }
    }
    for row in map["asymmetry"].as_array().into_iter().flatten() {
        println!(
            "SUBITEM {slice}:asym:{} — a bridge row, the plane's codec half",
            row["id"].as_str().unwrap_or("?")
        );
    }
    i32::from(fails > 0)
}

/// The frame bytes of a JSON value.
pub fn frame(v: &Value) -> Vec<u8> {
    bytes_of(v)
}

/// The far-end concepts a log's frames carry toward the caller, read under `dialect`.
pub fn caller_norms(dialect: Dialect, log: &Log) -> Vec<Norm> {
    decode_relay(dialect, log).caller
}

/// The concepts a log's frames carry toward the far end, read under `dialect`.
pub fn far_norms(dialect: Dialect, log: &Log) -> Vec<Norm> {
    decode_relay(dialect, log).far
}

/// The token units a usage frame reports, as the harness reads it: `(class, amount)`, zeros left
/// out.
pub fn usage_tokens(dialect: Dialect, usage_frame: &[u8]) -> Vec<(u32, u64)> {
    expect(
        dialect,
        &[Wire {
            dir: Dir::Down,
            bytes: usage_frame.to_vec(),
        }],
    )
    .tokens
}
