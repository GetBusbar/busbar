// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE FIXTURE LEGS — `spec-per-dialect`, `replay`, `cross-parity` — over the dialects' published
//! wires, read by this harness ([`crate::wire`]), AND through the door's session pieces.
//!
//! Each fixture is judged twice. The WIRE half reads the fixture by the dialect's published format:
//! it must read as concepts (or be one of the map's documented drops) (spec), a captured transcript
//! must show its concept skeleton in order (replay), a concept bridged A → B by the cross-dialect
//! map must read back with its load-bearing fields (cross). The DOOR half pushes the same wire
//! bytes (for cross: the bridged B wire) through a live session on the door that speaks the
//! dialect — the caller's frames as caller pieces, the far end's as far-end pieces — on the linked
//! and the dropped door, and holds what the door relays to the SESSION RULES the spec states
//! (Law 5's relay, Part 2 #45's lock): a caller frame reaches the far end as it arrived, except
//! that a frame configuring the session or asking for a response takes the session's locked keys
//! (the governed splice, [`crate::wire::governed`]); a far-end frame reaches the caller as it
//! arrived, every one of them (a usage report also becomes reported units), and nothing goes to the
//! far end on the caller's behalf (Law 11). Compared on the correlation fingerprint. The
//! expectation is computed from the wire by this harness, never by the plane: the plane's only
//! public item is its door.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{FROM_CALLER, FROM_FAR_END, UNITS_REPORTED};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::Plugin;
use serde_json::Value;

use crate::door::{facts, judge, open, result, Log, Rig, Session, PUBLIC, SESSION};
use crate::wire::{self, Bridge, GEMINI_SOCKET_PATH, REALTIME_SOCKET_PATH};

// ── the two dialects ────────────────────────────────────────────────────────────────────────────

/// A duplex dialect the plane dials, and the session door that speaks it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dialect {
    /// OpenAI Realtime: the browser's sideband socket (claim 2).
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
            Dialect::OpenAi => 2,
            Dialect::Gemini => 3,
        }
    }

    /// The declared need its far frames ride: the outbound socket need the door's Statement
    /// declares under the dialect's credential style ([`crate::door::Facts`]).
    pub fn ride(self) -> u32 {
        match self {
            Dialect::OpenAi => facts().realtime_socket,
            Dialect::Gemini => facts().live_socket,
        }
    }

    /// The far end's socket, under the member's base URL (the dialect's published endpoint).
    pub const fn socket(self) -> &'static str {
        match self {
            Dialect::OpenAi => REALTIME_SOCKET_PATH,
            Dialect::Gemini => GEMINI_SOCKET_PATH,
        }
    }

    /// A caller frame's concepts, read by the harness.
    pub fn read_up(self, frame: &[u8]) -> Vec<Norm> {
        wire::read_up(self, frame)
    }

    /// A far-end frame's concepts, read by the harness.
    pub fn read_down(self, frame: &[u8]) -> Vec<Norm> {
        wire::read_down(self, frame)
    }
}

fn bytes_of(v: &Value) -> Vec<u8> {
    wire::bytes(v)
}

// ── the shared normal form ──────────────────────────────────────────────────────────────────────

/// Both dialects' concepts, in one dialect-neutral list, so concepts compare uniformly.
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
    /// A conversation item: a message as its role and text parts, any other item as written.
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

/// One correlated tool call, keyed by call id: `(name, args, result)`.
type CallEntry = (Option<String>, Option<Value>, Option<Value>);

/// A call-collapsed fingerprint: tool events merged by call id (an atomic Gemini `toolCall` reads
/// as a streamed triple and OpenAI's done event repeats the whole arguments, so arity differs
/// legitimately; the correlation must survive). Everything else compared verbatim, in order.
#[derive(Debug, Default, PartialEq)]
pub struct Fingerprint {
    calls: BTreeMap<String, CallEntry>,
    other: Vec<Norm>,
}

/// The fingerprint of `norms`.
pub fn fingerprint(norms: &[Norm]) -> Fingerprint {
    let mut fp = Fingerprint::default();
    for n in norms {
        match n {
            Norm::ToolOpen(id, name) => {
                let e = fp.calls.entry(id.clone()).or_default();
                if e.0.is_none() && !name.is_empty() {
                    e.0 = Some(name.clone());
                }
            }
            Norm::ToolArgs(id, args) => {
                let e = fp.calls.entry(id.clone()).or_default();
                if e.1.is_none() && !args.is_null() {
                    e.1 = Some(args.clone());
                }
            }
            Norm::ToolClose(id) => {
                fp.calls.entry(id.clone()).or_default();
            }
            Norm::ToolResult(id, out) => {
                let e = fp.calls.entry(id.clone()).or_default();
                if e.2.is_none() {
                    e.2 = Some(out.clone());
                }
            }
            other => fp.other.push(other.clone()),
        }
    }
    fp
}

/// A concept's tag, for the replay skeleton.
fn tag(n: &Norm) -> &'static str {
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

/// What the session rules say the door must relay for a sequence of wires.
pub struct Expected {
    far: Vec<Norm>,
    caller: Vec<Norm>,
    tokens: Vec<(u32, u64)>,
    answered: bool,
}

/// The session rules over `wires`, read by the harness (never by the door): each caller frame as
/// the session's lock (the section the legs open under, [`SESSION`]) leaves it, each far-end frame
/// as it arrived, and the far end's token reports summed per class.
pub fn expect(dialect: Dialect, wires: &[Wire]) -> Expected {
    let locked = wire::locked_session(SESSION);
    let mut x = Expected {
        far: Vec::new(),
        caller: Vec::new(),
        tokens: Vec::new(),
        answered: false,
    };
    let mut sums = [0_u64; 4];
    for w in wires {
        match w.dir {
            Dir::Up => {
                if let Some(sent) = wire::governed(dialect, &locked, &w.bytes) {
                    x.far.extend(dialect.read_up(&bytes_of(&sent)));
                }
            }
            Dir::Down => {
                x.answered = true;
                let norms = dialect.read_down(&w.bytes);
                for n in &norms {
                    if let Norm::Usage(ai, ao, ti, to) = n {
                        for (sum, k) in sums.iter_mut().zip([*ai, *ao, *ti, *to]) {
                            *sum = sum.saturating_add(k);
                        }
                    }
                }
                x.caller.extend(norms);
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
            dialect.read_up(&e.frame)
        } else {
            dialect.read_down(&e.frame)
        };
        r.tags.extend(n.iter().map(tag));
        if e.to_far {
            r.far.extend(n);
        } else {
            r.caller.extend(n);
        }
    }
    r
}

/// The door's relay of a session against the session rules: every answer READY, no record row,
/// every far frame on the dialect's socket need, both sides' frames on the expected fingerprint,
/// the far end's token reports as reported units (and the session fee once the far end answered).
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
    let r = decode_relay(dialect, log);
    if fingerprint(&r.far) != fingerprint(&x.far) {
        return Err(format!(
            "the far end was sent {:?}; the session rules say {:?}",
            r.far, x.far
        ));
    }
    if fingerprint(&r.caller) != fingerprint(&x.caller) {
        return Err(format!(
            "the caller was sent {:?}; the session rules say {:?}",
            r.caller, x.caller
        ));
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
        .any(|u| u.0 == facts().fee_class && u.2 == 1);
    if fee != x.answered {
        return Err(format!(
            "the session fee unit reported {fee}, the far end answered {}",
            x.answered
        ));
    }
    Ok(format!(
        "the {} door relayed {} far / {} caller concept(s) by the session rules, {} token unit(s)",
        dialect.name(),
        r.far.len(),
        r.caller.len(),
        tokens.len()
    ))
}

/// THE PLANTED WRONG DOOR for a relay: one that reports a token the far end never sent.
pub fn plant_units(log: &Log) -> Log {
    let mut planted = log.clone();
    planted.units.push((1, UNITS_REPORTED, 7));
    planted
}

/// Judge one relay of `wires` on both doors, with `read` (the wire half's verdict) folded in.
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
    judge(
        slice,
        what,
        &seen,
        &|log: &Log| {
            let read = read.clone()?;
            let door = relay_check(dialect, log, &x)?;
            Ok(format!("wire: {read}; door: {door}"))
        },
        &plant_units,
    )
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// spec-per-dialect
// ══════════════════════════════════════════════════════════════════════════════════════════════

/// Fixtures that legitimately read as NOTHING, with the reason (the map's documented drops: a
/// concept with no shared home in the other dialect).
fn drop_reason(dialect: Dialect, fixture: &str) -> Option<&'static str> {
    match (dialect, fixture) {
        (Dialect::Gemini, "goAway.json") => {
            Some("gemini_go_away: no OpenAI advance-disconnect twin (drop+warn)")
        }
        (Dialect::Gemini, "toolCallCancellation.json") => {
            Some("gemini_tool_call_cancellation: no OpenAI server-driven cancel (drop+warn)")
        }
        (Dialect::Gemini, "serverContent.inputTranscription.json") => {
            Some("input transcription side-channel: no shared concept home (drop+warn)")
        }
        (Dialect::Gemini, "serverContent.outputTranscription.json") => {
            Some("output transcription side-channel: no shared concept home (drop+warn)")
        }
        _ => None,
    }
}

/// The wire half of one fixture, and the direction its frame is pushed from: a client message is
/// the caller's, a server message the far end's.
fn spec_read(dialect: Dialect, fixture: &str, frame: &[u8]) -> (Result<String, String>, Dir) {
    let up = dialect.read_up(frame);
    if !up.is_empty() {
        let tags: Vec<&str> = up.iter().map(tag).collect();
        return (
            Ok(format!(
                "read as the client message {tags:?} by {}'s published format",
                dialect.name()
            )),
            Dir::Up,
        );
    }
    let down = dialect.read_down(frame);
    if !down.is_empty() {
        let tags: Vec<&str> = down.iter().map(tag).collect();
        return (
            Ok(format!(
                "read as the server message {tags:?} by {}'s published format",
                dialect.name()
            )),
            Dir::Down,
        );
    }
    // A documented drop is a far-end concept with no shared home: pushed from the far end, the
    // door relays it as it arrived, and it reads as nothing on either side.
    match drop_reason(dialect, fixture) {
        Some(reason) => (Ok(format!("documented drop — {reason}")), Dir::Down),
        None => (
            Err("read as NO concept and is not a documented drop".to_string()),
            Dir::Down,
        ),
    }
}

/// `spec <dialect> <dir>`: every fixture, wire half and door half.
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
        let frame = match fs::read(dir.join(f))
            .map_err(|e| e.to_string())
            .and_then(|b| {
                serde_json::from_slice::<Value>(&b)
                    .map(|v| bytes_of(&v))
                    .map_err(|e| e.to_string())
            }) {
            Ok(frame) => frame,
            Err(e) => {
                result(
                    dialect.name(),
                    false,
                    f,
                    &format!("unreadable fixture: {e}"),
                );
                fails += 1;
                continue;
            }
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

/// The wire half of a replay: every frame read in order by the dialect's published format, and
/// the skeleton in order.
fn replay_read(dialect: Dialect, wires: &[Wire], skeleton: &[&str]) -> Result<String, String> {
    let (mut tags, mut read, mut frames) = (Vec::new(), 0_usize, 0_usize);
    for w in wires {
        let norms = match w.dir {
            Dir::Up => dialect.read_up(&w.bytes),
            Dir::Down => dialect.read_down(&w.bytes),
        };
        frames += usize::from(!norms.is_empty());
        read += norms.len();
        tags.extend(norms.iter().map(tag));
    }
    ordered_subsequence(&tags, skeleton)?;
    Ok(format!(
        "{read} concept(s) read from {frames} frame(s), skeleton {skeleton:?} in order"
    ))
}

/// `replay <root>`: each dialect's captured transcript, wire half and door half.
pub fn replay(rig: &Rig, root: &Path) -> i32 {
    // The skeletons the transcript reads as; the door's relay must show the same concepts in the
    // order it emitted them, less the far end's usage, which a session consumes into units.
    let cases: [(Dialect, &[&str], &[&str]); 2] = [
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
            ],
        ),
    ];
    let mut fails = 0;
    for (dialect, wire_skeleton, door_skeleton) in cases {
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
        let read = replay_read(dialect, &wires, wire_skeleton);
        let x = expect(dialect, &wires);
        let seen = rig.both(|p| relay(p, dialect, &wires));
        let pass = judge(
            "default",
            &what,
            &seen,
            &|log: &Log| {
                let read = read.clone()?;
                let door = relay_check(dialect, log, &x)?;
                ordered_subsequence(&decode_relay(dialect, log).tags, door_skeleton)?;
                Ok(format!(
                    "wire: {read}; door: {door}, skeleton {door_skeleton:?} in emitted order"
                ))
            },
            &plant_units,
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

/// One bridge: the source's concepts, the bridged frames' concepts read back, and the bridged
/// wires (the B dialect's frames, pushed through B's door).
struct Bridged {
    n1: Vec<Norm>,
    n2: Vec<Norm>,
    wires: Vec<Wire>,
}

/// Bridge the frames `vals` FROM `a` TO `b` as one exchange, by the cross-dialect map
/// ([`crate::wire::Bridge`]): within one dialect a frame is carried as it is (Law 5's relay);
/// across dialects each concept becomes `b`'s published frame for it, or nothing where `b` has
/// none.
fn bridge(a: Dialect, b: Dialect, vals: &[Vec<u8>]) -> Bridged {
    let mut map = Bridge::default();
    let mut out = Bridged {
        n1: Vec::new(),
        n2: Vec::new(),
        wires: Vec::new(),
    };
    let carry = |dir: Dir, bytes: Vec<u8>, out: &mut Bridged| {
        out.n2.extend(match dir {
            Dir::Up => b.read_up(&bytes),
            Dir::Down => b.read_down(&bytes),
        });
        out.wires.push(Wire { dir, bytes });
    };
    for v in vals {
        let up = a.read_up(v);
        if !up.is_empty() {
            let frames: Vec<Vec<u8>> = if a == b {
                vec![v.clone()]
            } else if up.iter().any(|n| matches!(n, Norm::Config(_))) {
                wire::bridge_config(a, b, v).iter().map(bytes_of).collect()
            } else {
                up.iter()
                    .filter_map(|n| map.up(b, n))
                    .map(|f| bytes_of(&f))
                    .collect()
            };
            out.n1.extend(up);
            for f in frames {
                carry(Dir::Up, f, &mut out);
            }
            continue;
        }
        let down = a.read_down(v);
        let frames: Vec<Vec<u8>> = if down.is_empty() {
            Vec::new()
        } else if a == b {
            vec![v.clone()]
        } else {
            down.iter()
                .filter_map(|n| map.down(b, n))
                .map(|f| bytes_of(&f))
                .collect()
        };
        out.n1.extend(down);
        for f in frames {
            carry(Dir::Down, f, &mut out);
        }
    }
    out
}

/// The concepts a log's frames carry, both sides, in the order the door emitted them.
pub fn relayed_norms(dialect: Dialect, log: &Log) -> Vec<Norm> {
    log.emissions
        .iter()
        .flat_map(|e| {
            if e.to_far {
                dialect.read_up(&e.frame)
            } else {
                dialect.read_down(&e.frame)
            }
        })
        .collect()
}

fn pair_slice(a: Dialect, b: Dialect) -> &'static str {
    match (a, b) {
        (Dialect::OpenAi, Dialect::OpenAi) => "oo",
        (Dialect::OpenAi, Dialect::Gemini) => "og",
        (Dialect::Gemini, Dialect::OpenAi) => "go",
        (Dialect::Gemini, Dialect::Gemini) => "gg",
    }
}

/// Why a concept has no decoding source fixture (never faked as a pass).
fn none_reason(concept: &str, from: Dialect) -> &'static str {
    match (concept, from) {
        ("input turn commit / end-of-audio", Dialect::Gemini) => {
            "documented drop — gemini audioStreamEnd has no reading on the source side"
        }
        ("server-side VAD speech boundary", Dialect::Gemini) => {
            "dialect-only concept — Gemini has no explicit server-VAD boundary fixture; exercised \
             as the openai_speech_boundary asymmetry in og"
        }
        ("input transcription" | "output transcription", _) => {
            "documented side-channel drop+warn — no shared IR home; the same-dialect round-trip \
             is exercised in spec-per-dialect"
        }
        _ => "no decoding fixture on the source side (exercised in the reverse pair)",
    }
}

/// Concepts the map documents as dropping toward `to` (implicit or absent there).
fn directional_drop(concept: &str, to: Dialect) -> bool {
    matches!(
        (concept, to),
        ("input turn commit / end-of-audio", Dialect::Gemini)
            | ("barge-in / truncate / cancel", Dialect::Gemini)
    )
}

fn cfg_from(norms: &[Norm]) -> Vec<String> {
    norms
        .iter()
        .filter_map(|n| match n {
            Norm::Config(s) => Some(s.clone()),
            _ => None,
        })
        .collect()
}

/// Do the shared concept's load-bearing fields survive `a` → IR → `b` → IR?
fn survives(
    concept: &str,
    n1: &[Norm],
    n2: &[Norm],
    a: Dialect,
    b: Dialect,
) -> Result<String, String> {
    let (f1, f2) = (fingerprint(n1), fingerprint(n2));
    let (an, bn) = (a.name(), b.name());
    if f1 == f2 {
        return Ok(format!("shared fields survive {an}→{bn} ({concept})"));
    }
    if concept.contains("session") && cfg_from(n1) == cfg_from(n2) && !cfg_from(n1).is_empty() {
        return Ok(format!(
            "session config essentials survive {an}→{bn} (modalities-text/VAD/format dropped per map)"
        ));
    }
    if f2.calls.is_empty() && f2.other.is_empty() && directional_drop(concept, b) {
        return Ok(format!(
            "{concept}: documented directional drop {an}→{bn} (implicit / no counterpart per map)"
        ));
    }
    Err(format!(
        "{concept}: shared fields did not survive {an}→{bn}: {f1:?} != {f2:?}"
    ))
}

fn drop_if(cond: bool, msg: &str) -> Result<String, String> {
    if cond {
        Ok(format!("accounted for — {msg}"))
    } else {
        Err(format!("NOT accounted for — {msg}"))
    }
}

/// A one-dialect-only concept bridged toward the other must be ACCOUNTED FOR.
fn asym_drop(id: &str, n1: &[Norm], n2: &[Norm]) -> Result<String, String> {
    let has = |ns: &[Norm], pred: &dyn Fn(&Norm) -> bool| ns.iter().any(pred);
    match id {
        "openai_buffer_clear" => drop_if(
            !has(n2, &|n| matches!(n, Norm::Clear)),
            "clear has no Gemini twin — dropped",
        ),
        "openai_response_overrides" => drop_if(
            !has(n2, &|n| matches!(n, Norm::ResponseCreate)),
            "per-response overrides dropped (Gemini is setup-time only)",
        ),
        "openai_truncate_precision" => drop_if(
            !has(n2, &|n| matches!(n, Norm::Truncate(_))),
            "sample-accurate truncate dropped (Gemini interrupted carries no ms)",
        ),
        "openai_structured_error" => drop_if(
            !has(n2, &|n| matches!(n, Norm::Error(..))),
            "structured error dropped toward Gemini (WS close codes instead)",
        ),
        "openai_event_id" | "openai_noise_reduction" => drop_if(
            true,
            "field never enters the IR (dropped at decode); bridged config omits it",
        ),
        "openai_semantic_vad" | "openai_g711" => drop_if(
            has(n2, &|n| matches!(n, Norm::Config(_))),
            "config bridges; semantic_vad/g711 specifics dropped per map",
        ),
        "openai_speech_boundary" => drop_if(
            has(n2, &|n| matches!(n, Norm::SpeechStart)) || n1.is_empty(),
            "boundary maps to interrupted; ms offset dropped",
        ),
        "openai_uplink_rate" => drop_if(
            !n2.is_empty()
                && n1
                    .iter()
                    .zip(n2.iter())
                    .all(|(a, b)| matches!((a, b), (Norm::AudioUp(x), Norm::AudioUp(y)) if x == y)),
            "uplink audio bridges verbatim at its true rate; the resample toward Gemini's 16 kHz \
             input is not performed",
        ),
        "gemini_go_away" | "gemini_tool_call_cancellation" => drop_if(
            n1.is_empty() && n2.is_empty(),
            "no OpenAI twin — dropped at decode (drop+warn)",
        ),
        "gemini_generation_complete" => drop_if(
            has(n2, &|n| matches!(n, Norm::AudioDone)),
            "turnComplete→AudioDone survives; generationComplete collapsed",
        ),
        "gemini_audio_stream_end" => drop_if(
            has(n1, &|n| matches!(n, Norm::Commit)) && has(n2, &|n| matches!(n, Norm::Commit)),
            "audioStreamEnd ↔ input_audio_buffer.commit: the end-of-uplink turn survives",
        ),
        "gemini_setup_complete" => drop_if(
            has(n2, &|n| matches!(n, Norm::Connect)),
            "ack maps to session.created; gate semantics are the session's, not IR",
        ),
        other => Err(format!("no asymmetry handler for id '{other}'")),
    }
}

fn read_fixture(path: &Path) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    Some(bytes_of(&v))
}

/// `cross <pair> <openai dir> <gemini dir> <map>`: every shared concept, bridge half and door half
/// (the bridged wire through the destination dialect's door), then every asymmetry row, judged on
/// what the destination dialect's door relays of the bridged wire.
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
    let dir_for = |d: Dialect| if d == Dialect::OpenAi { oa } else { ge };
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
        let present: Vec<(String, Vec<u8>)> = c[a.name()]["fixtures"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .filter_map(|fx| {
                let name = fx
                    .as_str()
                    .filter(|n| !n.is_empty() && !n.ends_with(".jsonl"))?;
                Some((name.to_string(), read_fixture(&dir_for(a).join(name))?))
            })
            .collect();
        let mut chosen = present.iter().find_map(|(name, v)| {
            let br = bridge(a, b, std::slice::from_ref(v));
            (!br.n1.is_empty()).then(|| (name.clone(), br))
        });
        // A concept whose transform is stated ACROSS events (the streamed⟷atomic tool call) can
        // bridge one frame to nothing alone; judge its fixtures as the one exchange the map states.
        if chosen.as_ref().is_some_and(|(_, br)| br.n2.is_empty()) && present.len() > 1 {
            let vals: Vec<Vec<u8>> = present.iter().map(|(_, v)| v.clone()).collect();
            let names: Vec<&str> = present.iter().map(|(n, _)| n.as_str()).collect();
            chosen = Some((names.join("+"), bridge(a, b, &vals)));
        }
        match chosen {
            None => println!(
                "SUBITEM {slice}:{concept} PENDING — {}",
                none_reason(concept, a)
            ),
            Some((name, br)) => {
                let bridged = survives(concept, &br.n1, &br.n2, a, b);
                let what = format!("shared:{name}");
                if !judge_relay(rig, slice, &what, b, &br.wires, &bridged) {
                    fails += 1;
                }
            }
        }
    }
    let Some(asym) = map["asymmetry"].as_array() else {
        result(
            slice,
            false,
            "map",
            "the cross-dialect map has no asymmetry array",
        );
        return 1;
    };
    for row in asym {
        let id = row["id"].as_str().unwrap_or("?");
        let origin = row["dialect"].as_str().unwrap_or("?");
        let fixture = row["fixture"].as_str().unwrap_or_default();
        let what = format!("asym:{id}");
        // A row is EXERCISED in its origin → other direction only.
        if a.name() != origin || a == b {
            result(
                slice,
                true,
                &what,
                &format!(
                    "not this pair's drop direction (origin={origin}); exercised in the \
                     {origin}→other pair"
                ),
            );
            continue;
        }
        let name = fixture
            .strip_prefix(&format!("{origin}/"))
            .unwrap_or(fixture);
        let Some(v) = read_fixture(&dir_for(a).join(name)) else {
            result(slice, false, &what, &format!("fixture {fixture} missing"));
            fails += 1;
            continue;
        };
        // The bridged wire through B's door, both ways: the row holds for what the door relays.
        let br = bridge(a, b, std::slice::from_ref(&v));
        let (linked, dropped) = rig.both(|p| relay(p, b, &br.wires));
        let verdict = match &dropped {
            Err(e) => Err(e.clone()),
            Ok(d) if *d != linked => Err(format!(
                "the linked and dropped {} doors relayed the bridged wire differently",
                b.name()
            )),
            Ok(_) => asym_drop(id, &br.n1, &relayed_norms(b, &linked))
                .map(|d| format!("{d}; through the {} door, linked == dropped", b.name())),
        };
        match verdict {
            Ok(d) => result(slice, true, &what, &d),
            Err(d) => {
                result(slice, false, &what, &d);
                fails += 1;
            }
        }
    }
    i32::from(fails > 0)
}

/// An OpenAI Realtime frame bridged toward Gemini Live by the cross-dialect map: the wires a
/// Gemini door is handed for it.
pub fn bridged_to_gemini(frame: &[u8]) -> Vec<Wire> {
    bridge(Dialect::OpenAi, Dialect::Gemini, &[frame.to_vec()]).wires
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

/// The token units a usage frame reports, read by the harness: `(class, amount)`, zeros left out.
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
