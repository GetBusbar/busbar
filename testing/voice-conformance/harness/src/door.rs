// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR, BOTH WAYS: the plumbing every leg drives the streaming plane through.
//!
//! The same door is loaded twice through the ONE loader: compiled in
//! (`busbar_plane_streaming::door::door`, [`load_linked`]) and dropped in (the `streaming_door`
//! example `cdylib` beside this harness, [`load_dropped`] against the linked row's own Statement).
//! Every leg builds a fresh instance of each, drives both with one script, and [`judge`]s the pair:
//! the two observations must be equal, the observation must pass the leg's check, and the leg's
//! PLANTED WRONG ANSWER must be refused by the same check (the RED arm, run in the same process on
//! every assertion). A dropped door that is not built or does not load is a FAIL, never a skip.

use std::cell::Cell;
use std::fmt::Debug;
use std::path::PathBuf;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, Span, BLOB_JSON, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot as life, TickIn, TickOut};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneDriveIn, PlaneDriveOut,
    PlaneOpenIn, PlaneOpenOut, RecordWrite, RefusalIn, RefusalOut, UnitCount, CLAIM_EXACT,
    CLAIM_OPEN, EMIT_DONE, EMIT_TO_FAR_END, FROM_CALLER, FROM_KERNEL, REFUSAL_KERNEL,
};
use busbar_plane_streaming::door;
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};

/// The environment variable naming the dropped-in door's library, when it is not beside the
/// harness.
pub const DOOR_ENV: &str = "VOICE_CONFORM_DOOR";

/// The environment variable that turns every planted wrong answer ON as the subject: each leg must
/// then go RED (the RED arm, observable from the runner).
pub const RED_ENV: &str = "VOICE_CONFORM_RED";

/// The deployment's public base URL every leg opens the door under.
pub const PUBLIC: &str = "https://gw.example.com/ignored?q=1#f";

/// The `streams:` section every leg opens under: the session params a session locks.
pub const SESSION: &[u8] = br#"{"session":{"model":"m-cap"}}"#;

/// The model the section names: the DIRECT route a reaching door names.
pub const MODEL: &str = "m-cap";

/// The kernel's opaque reference for the caller (never the principal, never a credential).
pub const CALLER_REF: &str = "c0ffee";

/// A value all of whose bytes are zero.
pub fn z<T>() -> T {
    // SAFETY: called only for the plane ABI's plain C structs (`in`/`out` frames, `UnitCount`,
    // `OutField`, `RecordWrite`): integers, raw pointers and spans, for which all-zero is valid.
    unsafe { std::mem::zeroed() }
}

/// `n` zeroed buffer elements.
fn zeros<T>(n: usize) -> Vec<T> {
    (0..n).map(|_| z()).collect()
}

/// A JSON blob over static bytes.
pub fn json(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// An octet blob over `b`.
fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

/// A static string, as the ABI lends it.
pub fn text(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// A string the plugin lent, copied.
pub fn read(s: AbiStr) -> String {
    if s.ptr.is_null() || s.len == 0 {
        return String::new();
    }
    // SAFETY: the plugin's text, valid while its generation is live (read before the next call).
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

/// The bytes a span names in `buf`; `<OUTSIDE>` for a span past it.
fn at(buf: &[u8], s: Span) -> String {
    let from = s.offset as usize;
    buf.get(from..from + s.len as usize).map_or_else(
        || "<OUTSIDE>".to_string(),
        |b| String::from_utf8_lossy(b).into_owned(),
    )
}

/// Keep a line printable: one line, bounded.
pub fn clip(s: &str) -> String {
    let one: String = s.chars().map(|c| if c == '\n' { ' ' } else { c }).collect();
    if one.chars().count() > 360 {
        let head: String = one.chars().take(360).collect();
        format!("{head}…")
    } else {
        one
    }
}

/// Whether the planted wrong answers are the subject (`VOICE_CONFORM_RED` set).
pub fn red_mode() -> bool {
    std::env::var_os(RED_ENV).is_some()
}

// ── the two doors ───────────────────────────────────────────────────────────────────────────────

/// The harness's one dispatcher and the two ways it reaches the door.
pub struct Rig {
    dispatcher: Dispatcher,
    count: Cell<u32>,
    dropped_at: Result<PathBuf, String>,
    stated: Vec<u8>,
}

/// Where the dropped-in door is: `VOICE_CONFORM_DOOR`, else the plane's `streaming_door` example
/// library in the profile's `examples/` beside this harness's binary (`cargo build -p
/// busbar-plane-streaming --example streaming_door` puts it there).
fn dropped_path() -> Result<PathBuf, String> {
    if let Some(p) = std::env::var_os(DOOR_ENV) {
        let p = PathBuf::from(p);
        return if p.is_file() {
            Ok(p)
        } else {
            Err(format!("{DOOR_ENV}={} names no file", p.display()))
        };
    }
    let exe = std::env::current_exe().map_err(|e| format!("the harness has no path: {e}"))?;
    let Some(dir) = exe.parent() else {
        return Err("the harness's path has no directory".to_string());
    };
    let name = format!(
        "{}streaming_door{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    );
    let path = dir.join("examples").join(name);
    if path.is_file() {
        Ok(path)
    } else {
        Err(format!(
            "the dropped-in door is not built beside the harness ({}): build the \
             `streaming_door` example",
            path.display()
        ))
    }
}

impl Rig {
    /// The dispatcher, the linked row's Statement, and where the dropped-in door lives.
    pub fn boot() -> Self {
        let row = LinkedRow::of(door::door).expect("the streaming door states itself");
        Rig {
            dispatcher: Dispatcher::new(DispatchConfig::default()),
            count: Cell::new(0),
            dropped_at: dropped_path(),
            stated: row.statement,
        }
    }

    /// The bind for one fresh instance (two instances never share a label).
    fn bind(&self, leg: &str) -> Bind {
        let n = self.count.get() + 1;
        self.count.set(n);
        Bind {
            instance: Arc::from(format!("{leg}-{n}")),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: self.dispatcher.adopter(),
            conns: None,
        }
    }

    /// A fresh instance of the LINKED door.
    pub fn linked(&self) -> Plugin<Plane> {
        let row = LinkedRow::of(door::door).expect("the streaming door states itself");
        load_linked::<Plane>(&row, self.bind("linked")).expect("the linked streaming door loads")
    }

    /// A fresh instance of the DROPPED door, admitted against the Statement the linked row states.
    pub fn dropped(&self) -> Result<Plugin<Plane>, String> {
        let path = match &self.dropped_at {
            Ok(path) => path,
            Err(e) => return Err(e.clone()),
        };
        load_dropped::<Plane>(path, &self.stated, self.bind("dropped")).map_err(|e| {
            format!(
                "the dropped-in door at {} did not load: {e:?}",
                path.display()
            )
        })
    }

    /// `script` run on a fresh instance of each door.
    pub fn both<T>(&self, script: impl Fn(&Plugin<Plane>) -> T) -> (T, Result<T, String>) {
        let linked = script(&self.linked());
        let dropped = self.dropped().map(|p| script(&p));
        (linked, dropped)
    }
}

// ── the verdict ─────────────────────────────────────────────────────────────────────────────────

/// One `RESULT` line.
pub fn result(slice: &str, pass: bool, what: &str, detail: &str) {
    let verdict = if pass { "PASS" } else { "FAIL" };
    println!("RESULT {slice} {verdict} {what} — {}", clip(detail));
}

/// A leg's check over one observation: `Ok(what it proved)` or `Err(what is wrong)`.
pub type Check<'a, T> = &'a dyn Fn(&T) -> Result<String, String>;

/// JUDGE ONE ASSERTION over both doors. PASS only when (1) the dropped door loaded and answered
/// exactly as the linked door did, (2) the linked door's observation passes `check`, and (3) the
/// RED ARM bit: `plant` (the leg's wrong door, restated as the wrong answer it would give) changes
/// the observation and `check` refuses it. Under [`RED_ENV`] the planted answer IS the subject, so
/// the line must come out FAIL. Prints the line; answers whether it passed.
pub fn judge<T: Clone + PartialEq + Debug>(
    slice: &str,
    what: &str,
    seen: &(T, Result<T, String>),
    check: Check<'_, T>,
    plant: &dyn Fn(&T) -> T,
) -> bool {
    let (linked, dropped) = seen;
    let subject = if red_mode() {
        plant(linked)
    } else {
        linked.clone()
    };
    let mut wrong = Vec::new();
    match dropped {
        Ok(dropped) if *dropped == subject => {}
        Ok(dropped) => wrong.push(format!(
            "the linked and dropped doors answered differently: {} vs {}",
            clip(&format!("{subject:?}")),
            clip(&format!("{dropped:?}"))
        )),
        Err(e) => wrong.push(e.clone()),
    }
    let proved = match check(&subject) {
        Ok(proved) => proved,
        Err(e) => {
            wrong.push(e);
            String::new()
        }
    };
    if !red_mode() {
        let planted = plant(linked);
        if planted == *linked {
            wrong.push("RED arm: the planted wrong answer changed nothing".to_string());
        } else if let Ok(accepted) = check(&planted) {
            wrong.push(format!(
                "RED arm: the check accepted a planted wrong answer ({accepted})"
            ));
        }
    }
    if wrong.is_empty() {
        result(
            slice,
            true,
            what,
            &format!("{proved}; linked == dropped; planted wrong answer refused"),
        );
        true
    } else {
        result(slice, false, what, &wrong.join("; "));
        false
    }
}

// ── the lifecycle ───────────────────────────────────────────────────────────────────────────────

/// One claim a snapshot publishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimed {
    /// `VERB TARGET CARRIER[ exact][ open]`.
    pub line: String,
    /// The dialect a refusal on it is rendered in.
    pub refusal_dialect: u16,
}

/// What an `open` answered: its outcome, and the snapshot it published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opened {
    /// The outcome.
    pub outcome: Outcome,
    /// The published claims.
    pub claims: Vec<Claimed>,
    /// The audience a caller's token must carry.
    pub audience: String,
}

/// `open` generation 1 over `settings`, under `public_url`.
pub fn open(
    p: &Plugin<Plane>,
    settings: &'static [u8],
    public_url: Option<&'static str>,
) -> Opened {
    let mut i: PlaneOpenIn = z();
    i.open.head = in_head();
    i.open.generation = 1;
    i.open.settings = json(settings);
    if let Some(u) = public_url {
        i.public_url = text(u);
    }
    let mut o: PlaneOpenOut = z();
    o.open.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(life::OPEN, &mut f);
    let mut opened = Opened {
        outcome: c.outcome,
        claims: Vec::new(),
        audience: String::new(),
    };
    let snap = f.out.snapshot;
    if c.outcome != Outcome::Ready || snap.is_null() {
        return opened;
    }
    // SAFETY: a READY open publishes its generation's snapshot, valid until that generation's
    // `retire` (never called here).
    let s = unsafe { &*snap };
    for n in 0..s.claims_len {
        // SAFETY: the snapshot names `claims_len` claims.
        let c = unsafe { &*s.claims.add(n) };
        let exact = if c.flags & CLAIM_EXACT != 0 {
            " exact"
        } else {
            ""
        };
        let open = if c.flags & CLAIM_OPEN != 0 {
            " open"
        } else {
            ""
        };
        opened.claims.push(Claimed {
            line: format!(
                "{} {} {}{exact}{open}",
                read(c.verb),
                read(c.target),
                read(c.carrier)
            ),
            refusal_dialect: c.refusal_dialect,
        });
    }
    opened.audience = read(s.audience);
    opened
}

/// What `arrive` answered for a claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arrived {
    /// The outcome.
    pub outcome: Outcome,
    /// The dialect index.
    pub dialect: u32,
    /// The op class index.
    pub op_class: u32,
    /// The principal need.
    pub principal: u32,
    /// The route class and the entry it names.
    pub route: (u8, String),
    /// The plane's refusal code and status.
    pub refusal: (u32, u32),
    /// The units the admission was told to expect.
    pub units: u32,
}

/// `arrive` on `claim`.
pub fn arrive(p: &Plugin<Plane>, claim: u32) -> Arrived {
    let mut units: Vec<UnitCount> = zeros(8);
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    a.input.head = in_head();
    a.input.claim = claim;
    a.input.unit = 900 + u64::from(claim);
    a.input.units_buf = units.as_mut_ptr();
    a.input.units_cap = units.len();
    a.out.head = out_head();
    let c = p.call(slot::ARRIVE, &mut a);
    Arrived {
        outcome: c.outcome,
        dialect: a.out.dialect,
        op_class: a.out.op_class,
        principal: a.out.principal_need,
        route: (a.out.route, read(a.out.pool)),
        refusal: (a.out.refusal, a.out.refusal_status),
        units: a.out.units_written,
    }
}

/// What `refusal` rendered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The outcome.
    pub outcome: Outcome,
    /// The rendered body.
    pub body: String,
    /// Its head fields.
    pub fields: Vec<(String, String)>,
    /// The status it answered (`0` = the kernel's).
    pub status: u32,
    /// The record writes it made.
    pub records: u32,
}

/// The kernel refuses unit `unit` on `dialect` with `status` and `words`: the door renders it.
pub fn refusal(
    p: &Plugin<Plane>,
    unit: u64,
    dialect: u32,
    status: u32,
    words: &'static str,
) -> Rendered {
    let mut reply = vec![0u8; 4096];
    let mut fields: Vec<OutField> = zeros(4);
    let mut arena = vec![0u8; 512];
    let mut records: Vec<RecordWrite> = zeros(4);
    let mut i: RefusalIn = z();
    i.head = in_head();
    i.cause = REFUSAL_KERNEL;
    i.status = status;
    i.dialect = dialect;
    i.text = text(words);
    i.unit = unit;
    (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
    (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
    let mut o: RefusalOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(slot::REFUSAL, &mut f);
    let out = f.out;
    let written = (out.reply_written as usize).min(reply.len());
    let n = (out.fields_written as usize).min(fields.len());
    Rendered {
        outcome: c.outcome,
        body: String::from_utf8_lossy(&reply[..written]).into_owned(),
        fields: fields[..n]
            .iter()
            .map(|f| (at(&arena, f.name), at(&arena, f.value)))
            .collect(),
        status: out.status,
        records: out.records_written,
    }
}

/// `drive`: the streams whose sessions owe output of their own.
pub fn drive(p: &Plugin<Plane>) -> (Outcome, Vec<u64>) {
    let mut sessions = [0_u64; 16];
    let mut f: Frame<PlaneDriveIn, PlaneDriveOut> = Frame::new(z(), z());
    f.input.drive.head = in_head();
    (f.input.sessions_buf, f.input.sessions_cap) = (sessions.as_mut_ptr(), sessions.len());
    f.out.head = out_head();
    let c = p.call(life::DRIVE, &mut f);
    let n = (f.out.sessions_written as usize).min(sessions.len());
    (c.outcome, sessions[..n].to_vec())
}

/// `tick` at `now_ns`: its outcome and the next tick it asks for.
pub fn tick(p: &Plugin<Plane>, now_ns: u64) -> (Outcome, u64) {
    let mut k: Frame<TickIn, TickOut> = Frame::new(z(), z());
    k.input.head = in_head();
    k.input.now_ns = now_ns;
    k.out.head = out_head();
    let c = p.call(life::TICK, &mut k);
    (c.outcome, k.out.next_tick_ns)
}

// ── a piece and its answer ──────────────────────────────────────────────────────────────────────

/// One piece pushed to a unit.
#[derive(Clone, Copy, Debug)]
pub struct Piece<'a> {
    /// The kernel's unit key.
    pub unit: u64,
    /// A live session's stream (`0` = a request unit).
    pub stream: u64,
    /// The claim it arrived on.
    pub claim: u32,
    /// Who pushed it.
    pub from: u32,
    /// `PIECE_*`.
    pub flags: u32,
    /// An ATTEMPT's number (`0` = none).
    pub attempt_no: u32,
    /// Its bytes.
    pub bytes: &'a [u8],
    /// The far end's status, with `PIECE_HAS_STATUS`.
    pub status: u32,
    /// The capacity of the units buffer the host lends.
    pub units_cap: usize,
}

/// A piece of request unit `unit` on `claim`.
pub const fn request(unit: u64, claim: u32, from: u32, flags: u32, bytes: &[u8]) -> Piece<'_> {
    Piece {
        unit,
        stream: 0,
        claim,
        from,
        flags,
        attempt_no: 0,
        bytes,
        status: 0,
        units_cap: 16,
    }
}

/// The ATTEMPT that opens attempt `n` of request unit `unit` on `claim`.
pub const fn attempt(unit: u64, claim: u32, n: u32) -> Piece<'static> {
    Piece {
        attempt_no: n,
        ..request(unit, claim, FROM_KERNEL, 0, &[])
    }
}

/// A piece of the live session on stream `stream` (claim `claim`).
pub const fn session(stream: u64, claim: u32, from: u32, flags: u32, bytes: &[u8]) -> Piece<'_> {
    Piece {
        stream,
        ..request(stream, claim, from, flags, bytes)
    }
}

/// What the door answered one piece with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The outcome.
    pub outcome: Outcome,
    /// The bytes it emitted.
    pub emitted: Vec<u8>,
    /// `more`.
    pub more: u32,
    /// The emission is bound for the far end.
    pub to_far: bool,
    /// The unit (or session) is done.
    pub done: bool,
    /// The caller's status.
    pub status: u32,
    /// The far request's verb and target.
    pub verb: String,
    /// See `verb`.
    pub target: String,
    /// The head fields it wrote.
    pub fields: Vec<(String, String)>,
    /// The units it reported: (class, source, amount).
    pub units: Vec<(u32, u32, u64)>,
    /// A short answer's units room.
    pub units_needed: u32,
    /// The declared need a far request rides (`0` = none).
    pub need: u32,
    /// The record writes it made.
    pub records: u32,
}

impl Answer {
    /// The units as `class:source=amount` words.
    pub fn units_line(&self) -> String {
        if self.units_needed != 0 {
            return format!("needed {}", self.units_needed);
        }
        self.units
            .iter()
            .map(|(c, s, a)| format!("{c}:{s}={a}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Push `x` and read the answer.
pub fn piece(p: &Plugin<Plane>, x: &Piece<'_>) -> Answer {
    let mut reply = vec![0u8; 1 << 18];
    let mut units: Vec<UnitCount> = zeros(x.units_cap);
    let mut records: Vec<RecordWrite> = zeros(4);
    let mut fields: Vec<OutField> = zeros(8);
    let mut arena = vec![0u8; 4096];
    let mut i: OnPieceIn = z();
    i.head = in_head();
    (i.unit, i.stream, i.claim, i.from, i.flags) = (x.unit, x.stream, x.claim, x.from, x.flags);
    (i.attempt_no, i.bytes, i.status_code) = (x.attempt_no, octets(x.bytes), x.status);
    i.caller_ref = text(CALLER_REF);
    (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
    (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
    (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
    let mut o: OnPieceOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(slot::ON_PIECE, &mut f);
    let o = f.out;
    let emitted = (o.emitted as usize).min(reply.len());
    let nu = (o.units_written as usize).min(units.len());
    let nf = (o.fields_written as usize).min(fields.len());
    Answer {
        outcome: c.outcome,
        emitted: reply[..emitted].to_vec(),
        more: o.more,
        to_far: o.flags & EMIT_TO_FAR_END != 0,
        done: o.flags & EMIT_DONE != 0,
        status: o.reply_status,
        verb: at(&arena, o.verb),
        target: at(&arena, o.target),
        fields: fields[..nf]
            .iter()
            .map(|f| (at(&arena, f.name), at(&arena, f.value)))
            .collect(),
        units: units[..nu]
            .iter()
            .map(|u| (u.class, u.source, u.amount))
            .collect(),
        units_needed: o.units_needed,
        need: o.need,
        records: o.records_written,
    }
}

// ── one live session ────────────────────────────────────────────────────────────────────────────

/// One frame the door emitted on a session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Emission {
    /// Bound for the far end (else the caller).
    pub to_far: bool,
    /// The frame.
    pub frame: Vec<u8>,
    /// The declared need a far frame rides.
    pub need: u32,
    /// A far frame's verb and target.
    pub verb: String,
    /// See `verb`.
    pub target: String,
}

/// Everything one session showed: every answer that was not READY (or owed `more`), every frame
/// in the order it was emitted, the last cumulative units, the record writes and how many answers
/// ended it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Log {
    /// `what Outcome` per answer that was not a plain READY.
    pub anomalies: Vec<String>,
    /// Every frame, in emission order.
    pub emissions: Vec<Emission>,
    /// The last READY answer's cumulative units.
    pub units: Vec<(u32, u32, u64)>,
    /// Record writes across every answer.
    pub records: u32,
    /// Answers that carried the session's end.
    pub done: u32,
}

/// A live session on one door instance.
pub struct Session<'p> {
    p: &'p Plugin<Plane>,
    stream: u64,
    claim: u32,
    /// What it showed so far.
    pub log: Log,
}

impl<'p> Session<'p> {
    /// The session on `stream` (door `claim`), opened by the caller's first (empty) piece.
    pub fn open(p: &'p Plugin<Plane>, stream: u64, claim: u32) -> Self {
        let mut s = Session {
            p,
            stream,
            claim,
            log: Log::default(),
        };
        let a = piece(p, &session(stream, claim, FROM_CALLER, 0, &[]));
        s.note("open", &a);
        s
    }

    fn note(&mut self, what: &str, a: &Answer) {
        if a.outcome != Outcome::Ready || a.more != 0 {
            self.log
                .anomalies
                .push(format!("{what} {:?} more={}", a.outcome, a.more));
        }
        if !a.emitted.is_empty() {
            self.log.emissions.push(Emission {
                to_far: a.to_far,
                frame: a.emitted.clone(),
                need: a.need,
                verb: a.verb.clone(),
                target: a.target.clone(),
            });
        }
        if a.outcome == Outcome::Ready {
            self.log.units.clone_from(&a.units);
        }
        self.log.records += a.records;
        if a.done {
            self.log.done += 1;
        }
    }

    /// Push `bytes` from `from` (with `flags`), then collect every frame the session still owes.
    /// Answers the piece's own answer.
    pub fn push(&mut self, from: u32, flags: u32, bytes: &[u8]) -> Answer {
        let a = piece(
            self.p,
            &session(self.stream, self.claim, from, flags, bytes),
        );
        self.note("piece", &a);
        if a.outcome == Outcome::Ready && !a.done {
            self.collect();
        }
        a
    }

    /// Collect (`FROM_KERNEL`, nothing, no attempt) until the session owes nothing.
    pub fn collect(&mut self) {
        for _ in 0..64 {
            let a = piece(
                self.p,
                &session(self.stream, self.claim, FROM_KERNEL, 0, &[]),
            );
            let quiet = a.emitted.is_empty() && !a.done;
            self.note("collect", &a);
            if quiet || a.done || a.outcome != Outcome::Ready {
                return;
            }
        }
        self.log.anomalies.push("collect never ran dry".to_string());
    }

    /// The frames emitted so far.
    pub fn emitted(&self) -> usize {
        self.log.emissions.len()
    }
}
