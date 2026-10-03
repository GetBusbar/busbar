// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STREAMING PLANE'S DOOR, BOTH WAYS (#2 (4)/(5): the plugin's own both-ways witness, over the
//! real loader): the same door compiled in (`busbar_plane_streaming::door::door`, through
//! `load_linked`) and dropped in (this crate's `streaming_door` example `cdylib`, which `cargo test`
//! builds, through `load_dropped`), driven by ONE script over the plane kind. Every answer is judged
//! by the kind's own checks on the way; the two transcripts must be identical, and each is pinned.

use std::mem::zeroed;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{
    AbiStr, Blob, Field, Outcome, Span, BLOB_JSON, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::lifecycle::{
    slot as life, CancelIn, CancelOut, GenIn, RefreshIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, PlaneSnapshot, UnitCount, CANCEL_FAILED, CLAIM_EXACT, CLAIM_OPEN, EMIT_DONE,
    EMIT_TO_FAR_END, FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST,
};
use busbar_plane_streaming::{door, driven};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    in_head, load_dropped, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame,
    LinkedRow, NoSink, Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

/// The bind for one instance, labelled `instance` (two instances never share a label).
fn bind(d: &Dispatcher, instance: &str) -> Bind {
    Bind {
        instance: Arc::from(instance),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: None,
    }
}

/// The compiled-in row: the door and the Statement rendering it states.
fn row() -> LinkedRow {
    LinkedRow::of(door::door).expect("the streaming door states itself")
}

fn json(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn text(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

fn read(s: AbiStr) -> String {
    if s.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the plugin's text, valid while its generation is live.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }).into_owned()
}

/// A published snapshot, read while its generation is live: its generation, its claims
/// (`verb target carrier exact?`) and the audience and metadata it binds.
fn snapshot(p: *const PlaneSnapshot) -> String {
    assert!(!p.is_null(), "a READY open/refresh publishes a snapshot");
    // SAFETY: the plugin's generation data, valid until `retire` of its generation.
    let s = unsafe { &*p };
    let claims: Vec<String> = (0..s.claims_len)
        .map(|i| {
            // SAFETY: the snapshot names `claims_len` claims.
            let c = unsafe { &*s.claims.add(i) };
            format!(
                "{} {} {}{}{}",
                read(c.verb),
                read(c.target),
                read(c.carrier),
                if c.flags & CLAIM_EXACT != 0 {
                    " exact"
                } else {
                    ""
                },
                if c.flags & CLAIM_OPEN != 0 {
                    " open"
                } else {
                    ""
                }
            )
        })
        .collect();
    format!(
        "gen={} claims=[{}] audience={} metadata={} routes={}",
        s.generation,
        claims.join(", "),
        read(s.audience),
        read(s.resource_metadata),
        s.admin_routes_len
    )
}

fn linked(d: &Dispatcher) -> Plugin<Plane> {
    load_linked::<Plane>(&row(), bind(d, "linked")).expect("the linked streaming door loads")
}

/// The example `cdylib` in this target dir (`cargo test` builds examples). Under CI a missing
/// artifact is a failure, never a skip.
fn dropped(d: &Dispatcher) -> Option<Plugin<Plane>> {
    let exe = std::env::current_exe().ok()?;
    let path = exe.parent()?.parent()?.join("examples").join(format!(
        "{}streaming_door{}",
        std::env::consts::DLL_PREFIX,
        std::env::consts::DLL_SUFFIX
    ));
    assert!(
        path.exists() || std::env::var_os("CI").is_none(),
        "the streaming_door example cdylib is not built under CI; a both-ways proof must not skip"
    );
    let stated = row().statement;
    path.exists().then(|| {
        load_dropped::<Plane>(&path, &stated, bind(d, "dropped"))
            .expect("the dropped streaming door loads")
    })
}

fn validate(p: &Plugin<Plane>, settings: &'static [u8]) -> Outcome {
    let mut v = Frame::new(
        ValidateIn {
            head: in_head(),
            settings: json(settings),
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        out_head(),
    );
    p.call(life::VALIDATE, &mut v).outcome
}

fn open(
    p: &Plugin<Plane>,
    generation: u64,
    settings: &'static [u8],
    public_url: Option<&'static str>,
) -> (Outcome, String) {
    let mut i: PlaneOpenIn = z();
    i.open.head = in_head();
    i.open.generation = generation;
    i.open.settings = json(settings);
    if let Some(u) = public_url {
        i.public_url = text(u);
    }
    let mut o: PlaneOpenOut = z();
    o.open.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(life::OPEN, &mut f);
    let snap = if c.outcome == Outcome::Ready {
        snapshot(f.out.snapshot)
    } else {
        String::new()
    };
    (c.outcome, snap)
}

/// THE SCRIPT: the lifecycle over two generations, then one unit offered to the door.
fn script(p: &Plugin<Plane>, public_url: Option<&'static str>) -> Vec<String> {
    let mut t = Vec::new();
    t.push(format!(
        "validate unknown key {:?}",
        validate(p, br#"{"nonsense_key":1}"#)
    ));
    t.push(format!(
        "validate zero ceiling {:?}",
        validate(p, br#"{"session_max_secs":0}"#)
    ));
    t.push(format!("validate empty {:?}", validate(p, b"")));
    t.push(format!(
        "validate ceiling {:?}",
        validate(p, br#"{"session_max_secs":1800}"#)
    ));

    let (outcome, snap) = open(p, 1, br#"{"session_max_secs":1800}"#, public_url);
    t.push(format!("open {outcome:?} {snap}"));

    let mut r = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: json(b"{}"),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        PlaneRefreshOut {
            head: out_head(),
            snapshot: std::ptr::null(),
        },
    );
    let c = p.call(life::REFRESH, &mut r);
    t.push(format!(
        "refresh {:?} {}",
        c.outcome,
        snapshot(r.out.snapshot)
    ));

    let mut g = Frame::new(
        GenIn {
            head: in_head(),
            generation: 1,
        },
        out_head(),
    );
    t.push(format!(
        "retire 1 {:?}",
        p.call(life::RETIRE, &mut g).outcome
    ));

    for claim in [3, 5, 9] {
        let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
        a.input.head = in_head();
        a.input.claim = claim;
        a.out.head = out_head();
        let c = p.call(slot::ARRIVE, &mut a);
        t.push(format!(
            "arrive {claim} {:?} dialect={} op={} principal={}",
            c.outcome, a.out.dialect, a.out.op_class, a.out.principal_need
        ));
    }

    let mut k: Frame<TickIn, TickOut> = Frame::new(z(), z());
    k.input.head = in_head();
    k.input.now_ns = 5;
    k.out.head = out_head();
    let c = p.call(life::TICK, &mut k);
    t.push(format!("tick {:?} next={}", c.outcome, k.out.next_tick_ns));

    let mut x: Frame<CancelIn, CancelOut> = Frame::new(z(), z());
    x.input.head = in_head();
    x.out.head = out_head();
    let c = p.call(life::CANCEL, &mut x);
    t.push(format!(
        "cancel {:?} failed={}",
        c.outcome,
        x.out.disposition == CANCEL_FAILED
    ));
    t
}

const PUBLIC: &str = "https://gw.example.com/ignored?q=1#f";

fn expected(public: bool) -> Vec<String> {
    let doors = "POST /v1/realtime/client_secrets http exact, POST /v1/realtime/calls http exact, \
                 GET /v1/realtime/sideband/{call_id} ws, GET /v1/realtime/gemini/{call_id} ws, \
                 GET /twilio/{call_id} ws, \
                 GET /.well-known/oauth-protected-resource/v1/realtime http exact open";
    let (claims, audience, metadata) = if public {
        (
            doors,
            "https://gw.example.com/v1/realtime",
            "https://gw.example.com/.well-known/oauth-protected-resource/v1/realtime",
        )
    } else {
        ("", "", "")
    };
    let snap = |g: u64| {
        format!("gen={g} claims=[{claims}] audience={audience} metadata={metadata} routes=0")
    };
    vec![
        "validate unknown key Refused".into(),
        "validate zero ceiling Refused".into(),
        "validate empty Ready".into(),
        "validate ceiling Ready".into(),
        format!("open Ready {}", snap(1)),
        format!("refresh Ready {}", snap(2)),
        "retire 1 Ready".into(),
        "arrive 3 Ready dialect=1 op=0 principal=1".into(),
        "arrive 5 Ready dialect=0 op=0 principal=0".into(),
        "arrive 9 Refused dialect=0 op=0 principal=0".into(),
        "tick Ready next=0".into(),
        "cancel Ready failed=true".into(),
    ]
}

#[test]
fn the_linked_door_states_the_planes_doors_under_its_public_url() {
    let d = Dispatcher::new(DispatchConfig::default());
    assert_eq!(script(&linked(&d), Some(PUBLIC)), expected(true));
}

#[test]
fn a_deployment_with_no_public_url_is_claimed_by_no_door() {
    let d = Dispatcher::new(DispatchConfig::default());
    assert_eq!(script(&linked(&d), None), expected(false));
}

#[test]
fn the_dropped_door_answers_as_the_linked_door_does() {
    let d = Dispatcher::new(DispatchConfig::default());
    for url in [Some(PUBLIC), None] {
        // A fresh instance of each door per script: the script opens its instance, and an open
        // instance refuses a second open.
        let Some(dropped) = dropped(&d) else {
            eprintln!("skip: the streaming_door example cdylib is not built");
            return;
        };
        assert_eq!(
            script(&dropped, url),
            script(&linked(&d), url),
            "the two doors must answer identically"
        );
    }
}

#[test]
fn the_tail_states_what_the_served_plane_declares() {
    // The billable classes a session counts in, the per-session fee and the `session` grant kind:
    // the served plane's own declaration, read off the tail the door states.
    let t = door::TAIL;
    assert_eq!(read(t.scope), "session");
    assert_eq!(read(t.audit_kind), "streaming_session");
    // SAFETY: the tail's `'static` lists.
    let classes: Vec<String> =
        unsafe { std::slice::from_raw_parts(t.billable_classes, t.billable_classes_len) }
            .iter()
            .map(|c| format!("{}/{}", read(c.class), read(c.family)))
            .collect();
    assert_eq!(
        classes,
        [
            "audio_tokens_in/token",
            "audio_tokens_out/token",
            "text_tokens_in/token",
            "text_tokens_out/token",
            "audio_seconds_in/duration",
            "tool_calls/count",
        ]
    );
    // SAFETY: as above.
    let fees: Vec<String> = unsafe { std::slice::from_raw_parts(t.fee_units, t.fee_units_len) }
        .iter()
        .map(|f| read(*f))
        .collect();
    assert_eq!(fees, ["per_session"]);
    busbar_contract::abi::plane::check::check_tail(t)
        .expect("the kind's own check admits the tail");
}

// ── THE ONE-REQUEST DOORS' PIECES ───────────────────────────────────────────────────────────────

/// The section the unit script opens under: the session params a mint locks the browser to.
const SESSION: &[u8] = br#"{"session":{"model":"m-cap"}}"#;
/// The audience [`PUBLIC`] reads to.
const AUDIENCE: &str = "https://gw.example.com/v1/realtime";
/// The kernel's reference for the caller.
const CALLER_REF: &str = "c0ffee";
/// The body the served plane sent its far end for that mint (the recorded
/// `streams|mint|client-secrets` cell, `golden/1.6.0-pre`).
const MINT_BODY: &str =
    r#"{"expires_after":{"anchor":"created_at","seconds":600},"session":{"model":"m-cap"}}"#;
/// The far end's mint answer.
const MINTED: &[u8] = br#"{"value":"ek_oracle_0001","expires_at":1767225600}"#;
/// The caller's SDP offer, and the far end's answer and where its call lives.
const OFFER: &[u8] = b"v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=oracle-offer\r\nt=0 0\r\n";
const SDP_ANSWER: &[u8] = b"v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\ns=oracle-answer\r\nt=0 0\r\n";
const LOCATION: &str = "/v1/realtime/calls/rtc_oracle0001";

fn octets(b: &[u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn at(buf: &[u8], s: Span) -> String {
    String::from_utf8_lossy(&buf[s.offset as usize..(s.offset + s.len) as usize]).into_owned()
}

/// The host's buffers for one `on_piece`.
struct Bufs {
    reply: Vec<u8>,
    units: Vec<UnitCount>,
    fields: [OutField; 4],
    arena: [u8; 256],
    /// The units the last answer wrote (class, source, amount), or, short, the room it needed.
    last_units: String,
}

/// One piece pushed to a unit: whose it is, its flags, bytes, status and kept head fields.
struct Push<'a> {
    unit: u64,
    /// A live session's stream (`0` = a request unit).
    stream: u64,
    claim: u32,
    from: u32,
    flags: u32,
    attempt_no: u32,
    bytes: &'a [u8],
    status: u32,
    head: &'a [Field],
}

impl Bufs {
    fn new(reply_cap: usize) -> Self {
        Self::with_units(reply_cap, 2)
    }

    fn with_units(reply_cap: usize, units: usize) -> Self {
        Self {
            reply: vec![0; reply_cap],
            units: vec![z(); units],
            fields: [z(); 4],
            arena: [0; 256],
            last_units: String::new(),
        }
    }

    /// `push` answered: the outcome and what it wrote, as text.
    fn call(&mut self, p: &Plugin<Plane>, push: &Push<'_>) -> String {
        let mut i: OnPieceIn = z();
        i.head = in_head();
        (i.unit, i.claim, i.from, i.flags) = (push.unit, push.claim, push.from, push.flags);
        i.stream = push.stream;
        (i.attempt_no, i.bytes, i.status_code) = (push.attempt_no, octets(push.bytes), push.status);
        i.caller_ref = text(CALLER_REF);
        if !push.head.is_empty() {
            (i.head_fields, i.head_fields_len) = (push.head.as_ptr(), push.head.len());
        }
        (i.reply_buf, i.reply_cap) = (self.reply.as_mut_ptr(), self.reply.len());
        (i.units_buf, i.units_cap) = (self.units.as_mut_ptr(), self.units.len());
        (i.fields_buf, i.fields_cap) = (self.fields.as_mut_ptr(), self.fields.len());
        (i.arena_buf, i.arena_cap) = (self.arena.as_mut_ptr(), self.arena.len());
        let mut o: OnPieceOut = z();
        o.head = out_head();
        let mut f = Frame::new(i, o);
        let c = p.call(slot::ON_PIECE, &mut f);
        let o = f.out;
        self.last_units = if o.units_needed != 0 {
            format!("needed {}", o.units_needed)
        } else {
            self.units[..o.units_written as usize]
                .iter()
                .map(|u| format!("{}:{}={}", u.class, u.source, u.amount))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let fields: Vec<String> = self.fields[..o.fields_written as usize]
            .iter()
            .map(|f| format!("{}={}", at(&self.arena, f.name), at(&self.arena, f.value)))
            .collect();
        format!(
            "{:?} emitted={} more={} far={} done={} status={} verb={} target={} fields={fields:?}",
            c.outcome,
            String::from_utf8_lossy(&self.reply[..o.emitted as usize]),
            o.more,
            o.flags & EMIT_TO_FAR_END != 0,
            o.flags & EMIT_DONE != 0,
            o.reply_status,
            at(&self.arena, o.verb),
            at(&self.arena, o.target),
        )
    }
}

/// A piece of `unit` on `claim`.
const fn push(unit: u64, claim: u32, from: u32, flags: u32, bytes: &[u8]) -> Push<'_> {
    Push {
        unit,
        stream: 0,
        claim,
        from,
        flags,
        attempt_no: 0,
        bytes,
        status: 0,
        head: &[],
    }
}

/// The ATTEMPT that opens `unit`'s first attempt.
const fn attempt(unit: u64, claim: u32) -> Push<'static> {
    Push {
        attempt_no: 1,
        ..push(unit, claim, FROM_KERNEL, 0, &[])
    }
}

/// THE UNIT SCRIPT: a mint, an SDP offer, a metadata read written 16 bytes at a time, a session
/// door's piece and an unpublished claim's, in the order the route pump pushes them.
fn unit_script(p: &Plugin<Plane>) -> Vec<String> {
    let mut t = vec![format!("open {:?}", open(p, 1, SESSION, Some(PUBLIC)).0)];
    let mut b = Bufs::new(256);
    let whole = PIECE_HAS_STATUS | PIECE_LAST;

    t.push(format!("mint attempt {}", b.call(p, &attempt(7, 0))));
    let caller = push(7, 0, FROM_CALLER, PIECE_LAST, &[]);
    t.push(format!("mint caller {}", b.call(p, &caller)));
    let far = Push {
        status: 200,
        ..push(7, 0, FROM_FAR_END, whole, MINTED)
    };
    t.push(format!("mint far_end {}", b.call(p, &far)));

    t.push(format!("sdp attempt {}", b.call(p, &attempt(8, 1))));
    let offer = push(8, 1, FROM_CALLER, PIECE_LAST, OFFER);
    t.push(format!("sdp caller {}", b.call(p, &offer)));
    let location = [Field {
        name: text("location"),
        value: text(LOCATION),
    }];
    let far = Push {
        status: 201,
        head: &location,
        ..push(8, 1, FROM_FAR_END, whole, SDP_ANSWER)
    };
    t.push(format!("sdp far_end {}", b.call(p, &far)));

    let mut narrow = Bufs::new(16);
    t.push(format!("metadata {}", narrow.call(p, &attempt(9, 5))));
    for _ in 0..8 {
        let line = narrow.call(p, &push(9, 5, FROM_KERNEL, 0, &[]));
        let done = line.contains("done=true");
        t.push(format!("metadata more {line}"));
        if done {
            break;
        }
    }

    t.push(format!("sideband {}", b.call(p, &attempt(10, 2))));
    t.push(format!("unpublished {}", b.call(p, &attempt(11, 9))));
    t
}

/// What the unit script must read: the served plane's answers, through the door.
fn unit_expected() -> Vec<String> {
    let none = "verb= target= fields=[]";
    let minted = driven::mint_reply(200, MINTED);
    let metadata = driven::metadata_reply(AUDIENCE);
    let mut t = vec![
        "open Ready".to_string(),
        format!(
            "mint attempt Ready emitted={MINT_BODY} more=0 far=true done=false status=0 \
             verb=POST target=/v1/realtime/client_secrets \
             fields=[\"content-type=application/json\", \"OpenAI-Safety-Identifier={CALLER_REF}\"]"
        ),
        format!("mint caller Ready emitted= more=0 far=false done=false status=0 {none}"),
        format!(
            "mint far_end Ready emitted={} more=0 far=false done=true status=200 verb= target= \
             fields=[\"content-type=application/json\"]",
            String::from_utf8_lossy(&minted.body)
        ),
        "sdp attempt Ready emitted= more=0 far=true done=false status=0 verb=POST \
         target=/v1/realtime/calls fields=[\"content-type=application/sdp\"]"
            .to_string(),
        format!(
            "sdp caller Ready emitted={} more=0 far=true done=false status=0 {none}",
            String::from_utf8_lossy(OFFER)
        ),
        format!(
            "sdp far_end Ready emitted={} more=0 far=false done=true status=201 verb= target= \
             fields=[\"content-type=application/sdp\", \"location={LOCATION}\"]",
            String::from_utf8_lossy(SDP_ANSWER)
        ),
    ];
    let chunks: Vec<&[u8]> = metadata.body.chunks(16).collect();
    for (n, chunk) in chunks.iter().enumerate() {
        let last = n + 1 == chunks.len();
        let (lead, status, fields) = if n == 0 {
            (
                "metadata",
                200,
                "[\"cache-control=public, max-age=3600\", \
                 \"content-type=application/json; charset=utf-8\"]",
            )
        } else {
            ("metadata more", 0, "[]")
        };
        t.push(format!(
            "{lead} Ready emitted={} more={} far=false done={last} status={status} verb= target= \
             fields={fields}",
            String::from_utf8_lossy(chunk),
            u32::from(!last),
        ));
    }
    t.push(format!(
        "sideband Refused emitted= more=0 far=false done=false status=0 {none}"
    ));
    t.push(format!(
        "unpublished Refused emitted= more=0 far=false done=false status=0 {none}"
    ));
    t
}

#[test]
fn the_one_request_doors_answer_their_pieces_through_the_door() {
    let d = Dispatcher::new(DispatchConfig::default());
    assert_eq!(unit_script(&linked(&d)), unit_expected());
}

#[test]
fn the_dropped_door_answers_the_one_request_doors_as_the_linked_door_does() {
    let d = Dispatcher::new(DispatchConfig::default());
    let Some(dropped) = dropped(&d) else {
        eprintln!("skip: the streaming_door example cdylib is not built");
        return;
    };
    assert_eq!(
        unit_script(&dropped),
        unit_script(&linked(&d)),
        "the two doors must answer identically"
    );
}

// ── LIVE SESSIONS THROUGH THE DOOR (K6) ──────────────────────────────────────────────────────────

/// A piece of the live session on stream `stream` (claim 2, the sideband socket).
const fn session(stream: u64, from: u32, flags: u32, bytes: &[u8]) -> Push<'_> {
    Push {
        stream,
        ..push(stream, 2, from, flags, bytes)
    }
}

/// `ms` milliseconds of 24 kHz PCM16 uplink audio, as the caller's realtime frame.
fn uplink(ms: usize) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"type":"input_audio_buffer.append",
        "audio": busbar_contract::media::base64_encode(&vec![0u8; ms * 48])}))
    .expect("json")
}

const USAGE_DONE: &[u8] = br#"{"type":"response.done","response":{"usage":{"input_token_details":{"audio_tokens":10,"text_tokens":3},"output_token_details":{"audio_tokens":20,"text_tokens":4}}}}"#;

/// THE SESSION SCRIPT, in the order the driver pushes a session's pieces: the caller's audio (a
/// turn toward the far end), the turn's ATTEMPT, the far end's usage, a collection with nothing
/// owed, an answer short of unit room and its re-call, and the caller's end.
fn session_script(p: &Plugin<Plane>) -> Vec<String> {
    let mut t = vec![format!("open {:?}", open(p, 1, SESSION, Some(PUBLIC)).0)];
    let mut b = Bufs::with_units(1 << 18, 6);
    let line = |t: &mut Vec<String>, b: &mut Bufs, what: &str, push: &Push<'_>| {
        let answer = b.call(p, push);
        t.push(format!("{what} {answer} units=[{}]", b.last_units));
    };
    let audio = uplink(2000);
    line(
        &mut t,
        &mut b,
        "caller audio",
        &session(20, FROM_CALLER, 0, &audio),
    );
    let turn = Push {
        attempt_no: 1,
        ..session(20, FROM_KERNEL, 0, &[])
    };
    line(&mut t, &mut b, "turn attempt", &turn);
    let far = Push {
        status: 101,
        ..session(20, FROM_FAR_END, PIECE_HAS_STATUS, USAGE_DONE)
    };
    line(&mut t, &mut b, "far usage", &far);
    line(&mut t, &mut b, "collect", &session(20, FROM_KERNEL, 0, &[]));
    let mut narrow = Bufs::with_units(1 << 18, 2);
    let short = session(20, FROM_CALLER, 0, &audio);
    let answer = narrow.call(p, &short);
    t.push(format!("short {answer} units=[{}]", narrow.last_units));
    line(&mut t, &mut b, "short re-call", &short);
    line(
        &mut t,
        &mut b,
        "caller end",
        &session(20, FROM_CALLER, PIECE_LAST, &[]),
    );
    line(
        &mut t,
        &mut b,
        "request unit on a session door",
        &attempt(21, 2),
    );
    t
}

#[test]
fn a_live_session_is_answered_through_the_door() {
    let d = Dispatcher::new(DispatchConfig::default());
    let t = session_script(&linked(&d));
    let payload = busbar_contract::media::base64_encode(&vec![0u8; 2000 * 48]);
    let line = |what: &str| {
        t.iter()
            .find(|l| l.starts_with(what))
            .unwrap_or_else(|| panic!("no `{what}` line in {t:#?}"))
            .clone()
    };
    assert_eq!(t[0], "open Ready");
    let caller = line("caller audio");
    assert!(
        caller.contains("far=true")
            && caller.contains("verb=GET target=/v1/realtime ")
            && caller.contains("input_audio_buffer.append")
            && caller.contains(&payload)
            && caller.contains("more=0")
            && caller.ends_with("units=[]"),
        "the caller's frame is one turn toward the far end, its audio unchanged: {caller}"
    );
    assert_eq!(
        line("turn attempt"),
        "turn attempt Ready emitted= more=0 far=false done=false status=0 verb= target= \
         fields=[] units=[]",
        "the turn's request is the caller side's answer"
    );
    let far = line("far usage");
    assert!(
        far.contains("far=false done=false")
            && far.ends_with("units=[0:1=10 1:1=20 2:1=3 3:1=4 4:1=2]"),
        "the closed turn's tokens and its two admitted seconds, reported: {far}"
    );
    assert!(line("collect ").contains("emitted= more=0 far=false done=false"));
    assert!(
        line("short ").starts_with("short Failed") && line("short ").ends_with("units=[needed 5]"),
        "{}",
        line("short ")
    );
    let recall = line("short re-call");
    assert!(
        recall.contains("far=true") && recall.ends_with("units=[0:1=10 1:1=20 2:1=3 3:1=4 4:1=2]"),
        "the re-call answers the same piece once, its audio not counted twice: {recall}"
    );
    let end = line("caller end");
    assert!(
        end.contains("done=true") && end.ends_with("units=[0:1=10 1:1=20 2:1=3 3:1=4 4:1=4]"),
        "the caller's end settles the open turn's two seconds once: {end}"
    );
    assert!(line("request unit on a session door")
        .starts_with("request unit on a session door Refused"));
}

#[test]
fn the_dropped_door_answers_a_live_session_as_the_linked_door_does() {
    let d = Dispatcher::new(DispatchConfig::default());
    let Some(dropped) = dropped(&d) else {
        eprintln!("skip: the streaming_door example cdylib is not built");
        return;
    };
    assert_eq!(
        session_script(&dropped),
        session_script(&linked(&d)),
        "the two doors must answer a session identically"
    );
}
