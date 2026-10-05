// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COMPOSITION LEGS, AT THE DOOR. Each leg judged one seam of a served session; the plane is
//! now served only through its door, so each leg judges the DOOR'S HALF of that seam — what the
//! door states, answers and refuses to do — and names the half that is the kernel's (the plane
//! driver's walk, the identity crate, the money steps, the transport), which the plane cannot see
//! and this harness therefore cannot judge.

use busbar_contract::abi::host::conn::connector::DIRECTION_OUTBOUND;
use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::plane::{
    FROM_CALLER, FROM_FAR_END, FROM_KERNEL, PIECE_HAS_STATUS, PIECE_LAST, PRINCIPAL_NONE,
    PRINCIPAL_REQUIRED, ROUTE_DIRECT, ROUTE_POOL,
};
use busbar_contract::media::base64_encode;
use busbar_plane_streaming::claims::{HTTP_TRANSPORT, WS_TRANSPORT};
use busbar_plane_streaming::door::{
    refusal_body, AUDIT_KIND, LIVE_STYLE, REALTIME_STYLE, REFUSAL_NO_DOOR, RIDES_LIVE_SOCKET,
    RIDES_REALTIME_PASS, RIDES_REALTIME_SOCKET,
};
use busbar_plane_streaming::driven::{
    mint_reply, GEMINI_SOCKET_PATH, MINT_FAILED_STATUS, REALTIME_SOCKET_PATH, SESSION_OPEN_ACTION,
};
use busbar_plane_streaming::provider::{GEMINI_LIVE, OPENAI_REALTIME};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::Plugin;
use serde_json::{json, Value};

use crate::codec_legs::{caller_norms, far_norms, fingerprint, frame, usage_tokens, Dialect, Norm};
use crate::door::{
    arrive, attempt, drive, judge, open, piece, refusal, request, result, session, Answer, Arrived,
    Emission, Log, Opened, Piece, Rendered, Rig, Session, CALLER_REF, MODEL, PUBLIC, SESSION,
};

// ── the frames the legs push ────────────────────────────────────────────────────────────────────

/// A far end's OpenAI Realtime usage report.
pub const USAGE_DONE: &[u8] = br#"{"type":"response.done","response":{"usage":{"input_token_details":{"audio_tokens":10,"text_tokens":3},"output_token_details":{"audio_tokens":20,"text_tokens":4}}}}"#;

/// A far end's Gemini Live usage report.
pub const GEMINI_USAGE: &[u8] = br#"{"usageMetadata":{"promptTokenCount":140,"responseTokenCount":80,"totalTokenCount":220,"promptTokensDetails":[{"modality":"TEXT","tokenCount":40},{"modality":"AUDIO","tokenCount":100}],"responseTokensDetails":[{"modality":"AUDIO","tokenCount":80}]}}"#;

/// The cumulative units a session reports once `USAGE_DONE` closed a turn holding `secs` seconds
/// of the caller's audio: the four token classes, the audio seconds and the session fee.
pub fn usage_units(secs: u64) -> String {
    format!("0:1=10 1:1=20 2:1=3 3:1=4 4:1={secs} 6:1=1")
}

/// `ms` milliseconds of the caller's 24 kHz PCM16 audio, as an OpenAI Realtime frame.
pub fn uplink(ms: usize) -> Vec<u8> {
    frame(&json!({"type": "input_audio_buffer.append",
        "audio": base64_encode(&vec![0_u8; ms * 48])}))
}

/// `ms` milliseconds of the caller's 16 kHz PCM16 audio, as a Gemini Live frame.
pub fn gemini_uplink(ms: usize) -> Vec<u8> {
    frame(
        &json!({"realtimeInput": {"audio": {"mimeType": "audio/pcm;rate=16000",
        "data": base64_encode(&vec![0_u8; ms * 32])}}}),
    )
}

/// `bytes` bytes of the far end's OpenAI Realtime audio.
pub fn downlink(bytes: usize) -> Vec<u8> {
    frame(&json!({"type": "response.output_audio.delta",
        "delta": base64_encode(&vec![0_u8; bytes])}))
}

/// The OpenAI Realtime mint's far-end answer.
const MINTED: &[u8] = br#"{"value":"ek_oracle_0001","expires_at":1767225600}"#;

/// One `answer` as a line: the step, the outcome and the cumulative units.
fn units_of(what: &str, a: &Answer) -> String {
    format!("{what} {:?} units=[{}]", a.outcome, a.units_line())
}

/// `composition <slice>`.
pub fn run(rig: &Rig, slice: &str) -> i32 {
    let pass = match slice {
        "provider-credential" => provider_credential(rig, slice),
        "metering-lease" => metering_lease(rig, slice),
        "session-scope" => session_scope(rig, slice),
        "gemini-live-route" => gemini_live_route(rig, slice),
        "provider-dial" => provider_dial(rig, slice),
        "admit-refusal" => admit_refusal(rig, slice),
        "route-failover" => route_failover(rig, slice),
        "audit-record" => audit_record(rig, slice),
        "exit-terminal" => exit_terminal(rig, slice),
        "tool-reply" => tool_reply(rig, slice),
        other => {
            result(other, false, "slice", "unknown composition slice");
            false
        }
    };
    i32::from(!pass)
}

// ── provider-credential ─────────────────────────────────────────────────────────────────────────

/// One need the Statement declares.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NeedLine {
    direction: u32,
    transport: String,
    auth: String,
    target: String,
}

/// One far request a door answered.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Ride {
    door: &'static str,
    verb: String,
    target: String,
    need: u32,
    fields: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CredObs {
    needs: Vec<NeedLine>,
    dialect_auth: Vec<String>,
    rides: Vec<Ride>,
}

/// Head fields that carry a credential: none may ride a request the door answers.
const CREDENTIAL_FIELDS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "x-goog-api-key",
    "x-api-key",
    "api-key",
    "openai-api-key",
    "cookie",
];

fn ride(door: &'static str, a: &Answer) -> Ride {
    Ride {
        door,
        verb: a.verb.clone(),
        target: a.target.clone(),
        need: a.need,
        fields: a.fields.clone(),
    }
}

fn cred_script(p: &Plugin<Plane>) -> CredObs {
    let served = p.served();
    let needs = served
        .need_auths
        .iter()
        .zip(&served.need_transports)
        .zip(&served.need_targets)
        .map(|((da, t), g)| NeedLine {
            direction: da.0,
            transport: (*t).to_string(),
            auth: da.1.to_string(),
            target: (*g).to_string(),
        })
        .collect();
    let dialect_auth = served
        .dialect_auth
        .iter()
        .map(|(d, style)| {
            let name = served.dialects.get(*d as usize).copied().unwrap_or("?");
            format!("{name}={style}")
        })
        .collect();
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut rides = vec![
        ride("mint", &piece(p, &attempt(7, 0, 1))),
        ride("sdp", &piece(p, &attempt(8, 1, 1))),
    ];
    let mut s = Session::open(p, 20, 2);
    rides.push(ride("sideband", &s.push(FROM_CALLER, 0, &uplink(100))));
    let mut g = Session::open(p, 21, 3);
    rides.push(ride("gemini", &g.push(FROM_CALLER, 0, &gemini_uplink(100))));
    CredObs {
        needs,
        dialect_auth,
        rides,
    }
}

fn cred_check(o: &CredObs) -> Result<String, String> {
    if o.rides.len() != 4 {
        return Err(format!("expected four far requests, saw {:?}", o.rides));
    }
    for r in &o.rides {
        let (transport, style) = match r.door {
            "mint" | "sdp" => (HTTP_TRANSPORT, REALTIME_STYLE),
            "sideband" => (WS_TRANSPORT, REALTIME_STYLE),
            _ => (WS_TRANSPORT, LIVE_STYLE),
        };
        let Some(need) = (r.need as usize)
            .checked_sub(1)
            .and_then(|i| o.needs.get(i))
        else {
            return Err(format!(
                "the {} request rides need {}, which the Statement does not declare",
                r.door, r.need
            ));
        };
        if need.direction != DIRECTION_OUTBOUND
            || need.transport != transport
            || need.auth != style
            || !need.target.is_empty()
        {
            return Err(format!(
                "the {} request rides {need:?}, not an outbound {transport} need under the \
                 {style} style whose address is the member's",
                r.door
            ));
        }
        if let Some((name, _)) = r.fields.iter().find(|(n, v)| {
            CREDENTIAL_FIELDS.contains(&n.to_ascii_lowercase().as_str())
                || v.to_ascii_lowercase().starts_with("bearer ")
        }) {
            return Err(format!(
                "the {} request carries a credential field `{name}`",
                r.door
            ));
        }
        if r.verb.is_empty() || r.target.is_empty() {
            return Err(format!(
                "the {} request names no verb/target: {r:?}",
                r.door
            ));
        }
    }
    let mint = &o.rides[0];
    if !mint
        .fields
        .iter()
        .any(|(n, v)| n.eq_ignore_ascii_case("openai-safety-identifier") && v == CALLER_REF)
    {
        return Err(format!(
            "the mint does not name the caller by the kernel's reference alone: {:?}",
            mint.fields
        ));
    }
    for want in [
        format!("{OPENAI_REALTIME}={REALTIME_STYLE}"),
        format!("{GEMINI_LIVE}={LIVE_STYLE}"),
    ] {
        if !o.dialect_auth.contains(&want) {
            return Err(format!(
                "the tail's dialect auth lacks {want}: {:?}",
                o.dialect_auth
            ));
        }
    }
    Ok(
        "every far request (mint, SDP, the sideband and Gemini sockets) rides a declared outbound \
         need whose auth style the kernel binds the provider credential to; none carries a \
         credential field, the caller is named only by the kernel's reference, and each dialect \
         states its far end's credential style. Resolving the catalog's secret reference, the \
         set-once composition and an unresolvable reference composing nothing are the \
         composition root's (busbar), not the door's"
            .to_string(),
    )
}

fn provider_credential(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "the door's far requests ride declared needs and carry no credential",
        &rig.both(cred_script),
        &cred_check,
        &|o: &CredObs| {
            let mut planted = o.clone();
            planted.rides[0]
                .fields
                .push(("authorization".to_string(), "Bearer sk-caller".to_string()));
            planted
        },
    )
}

// ── metering-lease ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct MeterObs {
    classes: Vec<String>,
    fees: Vec<String>,
    admitted: Vec<u32>,
    lines: Vec<String>,
}

fn meter_script(p: &Plugin<Plane>) -> MeterObs {
    let served = p.served();
    let classes = served
        .billable_classes
        .iter()
        .zip(&served.billable_families)
        .map(|(c, f)| format!("{c}/{f}"))
        .collect();
    let fees = served.fee_units.iter().map(|f| (*f).to_string()).collect();
    let _ = open(p, SESSION, Some(PUBLIC));
    let admitted = (0..5).map(|claim| arrive(p, claim).units).collect();
    let audio = uplink(2000);
    let mut lines = Vec::new();
    let a = piece(p, &session(20, 2, FROM_CALLER, 0, &audio));
    lines.push(units_of("caller audio", &a));
    let turn = Piece {
        attempt_no: 1,
        ..session(20, 2, FROM_KERNEL, 0, &[])
    };
    lines.push(units_of("turn attempt", &piece(p, &turn)));
    let far = Piece {
        status: 101,
        ..session(20, 2, FROM_FAR_END, PIECE_HAS_STATUS, USAGE_DONE)
    };
    lines.push(units_of("far usage", &piece(p, &far)));
    lines.push(units_of(
        "collect",
        &piece(p, &session(20, 2, FROM_KERNEL, 0, &[])),
    ));
    let short = Piece {
        units_cap: 2,
        ..session(20, 2, FROM_CALLER, 0, &audio)
    };
    lines.push(units_of("short", &piece(p, &short)));
    lines.push(units_of(
        "short re-call",
        &piece(p, &session(20, 2, FROM_CALLER, 0, &audio)),
    ));
    lines.push(units_of(
        "caller end",
        &piece(p, &session(20, 2, FROM_CALLER, PIECE_LAST, &[])),
    ));
    lines.push(units_of(
        "unanswered audio",
        &piece(p, &session(30, 2, FROM_CALLER, 0, &audio)),
    ));
    lines.push(units_of(
        "unanswered end",
        &piece(p, &session(30, 2, FROM_CALLER, PIECE_LAST, &[])),
    ));
    MeterObs {
        classes,
        fees,
        admitted,
        lines,
    }
}

fn meter_expected() -> Vec<String> {
    vec![
        "caller audio Ready units=[]".to_string(),
        "turn attempt Ready units=[]".to_string(),
        format!("far usage Ready units=[{}]", usage_units(2)),
        format!("collect Ready units=[{}]", usage_units(2)),
        "short Failed units=[needed 6]".to_string(),
        format!("short re-call Ready units=[{}]", usage_units(2)),
        format!("caller end Ready units=[{}]", usage_units(4)),
        "unanswered audio Ready units=[]".to_string(),
        "unanswered end Ready units=[4:1=2]".to_string(),
    ]
}

fn meter_check(o: &MeterObs) -> Result<String, String> {
    let classes = [
        "audio_tokens_in/token",
        "audio_tokens_out/token",
        "text_tokens_in/token",
        "text_tokens_out/token",
        "audio_seconds_in/duration",
        "tool_calls/count",
        "per_session/count",
    ];
    if o.classes != classes {
        return Err(format!("the tail's billable classes are {:?}", o.classes));
    }
    if o.fees != ["per_session"] {
        return Err(format!("the tail's fee units are {:?}", o.fees));
    }
    if o.admitted.iter().any(|n| *n != 0) {
        return Err(format!(
            "an arrival estimated units before the far end reported any: {:?}",
            o.admitted
        ));
    }
    let want = meter_expected();
    if o.lines != want {
        return Err(format!("the session reported {:?}; want {want:?}", o.lines));
    }
    Ok(
        "the door counts in its six declared classes plus the per-session fee, admits on no \
         estimate, and reports every turn's far-end tokens and audio seconds as cumulative \
         REPORTED units: once per turn (a short answer's re-call does not count its audio \
         twice), the open turn settled once at the end, and no fee unless the far end answered. \
         Reserving against the caller's budget chain, capping at its remaining bucket and \
         ledgering are the kernel's session account"
            .to_string(),
    )
}

fn metering_lease(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "a session's units, reported per declared class",
        &rig.both(meter_script),
        &meter_check,
        &|o: &MeterObs| {
            let mut planted = o.clone();
            planted.lines[2] = planted.lines[2].replace("1:1=20", "1:1=21");
            planted
        },
    )
}

// ── session-scope ───────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct ScopeObs {
    scope_kinds: Vec<String>,
    arrivals: Vec<Arrived>,
    refused: Rendered,
}

const SCOPE_CLAIMS: [u32; 7] = [0, 1, 2, 3, 4, 5, 9];

fn scope_script(p: &Plugin<Plane>) -> ScopeObs {
    let scope_kinds = p
        .declared()
        .scope_kinds
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    let _ = open(p, SESSION, Some(PUBLIC));
    ScopeObs {
        scope_kinds,
        arrivals: SCOPE_CLAIMS.iter().map(|c| arrive(p, *c)).collect(),
        refused: refusal(p, 0, 0, 403, "the key holds no session grant for this door"),
    }
}

/// A rendered refusal's error type and message, read back.
fn error_of(r: &Rendered) -> (String, String) {
    let v: Value = serde_json::from_str(&r.body).unwrap_or(Value::Null);
    (
        v["error"]["type"].as_str().unwrap_or_default().to_string(),
        v["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
    )
}

fn scope_check(o: &ScopeObs) -> Result<String, String> {
    if o.scope_kinds != ["session"] {
        return Err(format!("the tail's grant kinds are {:?}", o.scope_kinds));
    }
    for (claim, a) in SCOPE_CLAIMS.iter().zip(&o.arrivals) {
        let door = *claim <= 4;
        let ok = if door {
            a.outcome == Outcome::Ready && a.principal == PRINCIPAL_REQUIRED && a.op_class == 0
        } else {
            a.outcome == Outcome::Refused && a.refusal == (REFUSAL_NO_DOOR, 404)
        };
        if !ok {
            return Err(format!("claim {claim} arrived as {a:?}"));
        }
    }
    let (kind, words) = error_of(&o.refused);
    if o.refused.outcome != Outcome::Ready
        || kind != "permission_error"
        || words != "the key holds no session grant for this door"
        || o.refused.status != 0
    {
        return Err(format!("the grant refusal rendered as {:?}", o.refused));
    }
    Ok(
        "the door declares the `session` grant kind, every one of its five doors asks for a \
         principal (none admits anonymously) under the one session-open operation, an \
         unpublished claim is refused 404 with the plane's own code, and a grant refusal renders \
         as the dialect's permission_error. Matching the key's grants (wildcard, explicit, \
         another pool, an empty list) is the kernel's approve step"
            .to_string(),
    )
}

fn session_scope(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "the door's grant kind and principal need",
        &rig.both(scope_script),
        &scope_check,
        &|o: &ScopeObs| {
            let mut planted = o.clone();
            planted.arrivals[2].principal = PRINCIPAL_NONE;
            planted
        },
    )
}

// ── gemini-live-route ───────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct RouteObs {
    opened: Opened,
    arrived: Arrived,
    dialect: String,
    handshake: Log,
}

const GEMINI_SETUP: &[u8] = br#"{"setup":{"model":"models/gemini-2.0-flash-exp","generationConfig":{"responseModalities":["AUDIO"]}}}"#;
const SETUP_COMPLETE: &[u8] = br#"{"setupComplete":{}}"#;

fn route_script(p: &Plugin<Plane>) -> RouteObs {
    let opened = open(p, SESSION, Some(PUBLIC));
    let arrived = arrive(p, 3);
    let dialect = p
        .served()
        .dialects
        .get(arrived.dialect as usize)
        .copied()
        .unwrap_or("?")
        .to_string();
    let mut s = Session::open(p, 40, 3);
    s.push(FROM_CALLER, 0, GEMINI_SETUP);
    s.push(FROM_FAR_END, 0, SETUP_COMPLETE);
    RouteObs {
        opened,
        arrived,
        dialect,
        handshake: s.log,
    }
}

fn route_check(o: &RouteObs) -> Result<String, String> {
    let claimed = |line: &str, dialect: u16| {
        o.opened
            .claims
            .iter()
            .any(|c| c.line == line && c.refusal_dialect == dialect)
    };
    if o.opened.outcome != Outcome::Ready
        || !claimed("GET /v1/realtime/gemini/{call_id} ws", 1)
        || !claimed("GET /v1/realtime/sideband/{call_id} ws", 0)
    {
        return Err(format!(
            "the snapshot does not claim the Gemini socket (refused in Gemini's dialect) beside \
             the sideband: {:?}",
            o.opened
        ));
    }
    if o.opened.audience != "https://gw.example.com/v1/realtime" {
        return Err(format!("the one audience is {}", o.opened.audience));
    }
    let a = &o.arrived;
    if a.outcome != Outcome::Ready
        || a.principal != PRINCIPAL_REQUIRED
        || a.route != (ROUTE_DIRECT, MODEL.to_string())
        || o.dialect != GEMINI_LIVE
    {
        return Err(format!(
            "the Gemini door arrived as {a:?} in dialect {}",
            o.dialect
        ));
    }
    let h = &o.handshake;
    if !h.anomalies.is_empty() {
        return Err(format!(
            "the handshake was not answered READY: {:?}",
            h.anomalies
        ));
    }
    let far: Vec<&Emission> = h.emissions.iter().filter(|e| e.to_far).collect();
    let near: Vec<&Emission> = h.emissions.iter().filter(|e| !e.to_far).collect();
    if far.len() != 1
        || far[0].need != RIDES_LIVE_SOCKET
        || far[0].verb != "GET"
        || far[0].target != GEMINI_SOCKET_PATH
    {
        return Err(format!("the caller's setup reached the far end as {far:?}"));
    }
    if !far_norms(Dialect::Gemini, h)
        .iter()
        .any(|n| matches!(n, Norm::Config(_)))
    {
        return Err("the far end was not sent a Gemini setup".to_string());
    }
    let relayed: Value = near
        .first()
        .and_then(|e| serde_json::from_slice(&e.frame).ok())
        .unwrap_or(Value::Null);
    let sent: Value = serde_json::from_slice(SETUP_COMPLETE).unwrap_or(Value::Null);
    if near.len() != 1 || relayed != sent || caller_norms(Dialect::Gemini, h) != [Norm::Connect] {
        return Err(format!(
            "the far end's setupComplete reached the caller as {near:?}"
        ));
    }
    Ok(
        "the Gemini Live socket is claimed under its own path (its refusals in Gemini's dialect) \
         beside the OpenAI doors under the one audience, arrives as gemini_live for a principal \
         on the session model's DIRECT route, and the handshake crosses the door: the caller's \
         setup reaches the far end as a Gemini setup on the Live socket need, the far end's \
         setupComplete reaches the caller verbatim"
            .to_string(),
    )
}

fn gemini_live_route(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "the Gemini Live door: claim, arrival and handshake",
        &rig.both(route_script),
        &route_check,
        &|o: &RouteObs| {
            let mut planted = o.clone();
            for c in &mut planted.opened.claims {
                c.refusal_dialect = 0;
            }
            planted
        },
    )
}

// ── provider-dial ───────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct DialObs {
    openai: Log,
    gemini: Log,
}

fn dial_script(p: &Plugin<Plane>) -> DialObs {
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 50, 2);
    s.push(FROM_CALLER, 0, &uplink(100));
    s.push(FROM_FAR_END, 0, USAGE_DONE);
    let mut g = Session::open(p, 51, 3);
    g.push(FROM_CALLER, 0, &gemini_uplink(100));
    g.push(FROM_FAR_END, 0, GEMINI_USAGE);
    DialObs {
        openai: s.log,
        gemini: g.log,
    }
}

fn dial_one(
    dialect: Dialect,
    log: &Log,
    usage: &[u8],
    need: u32,
    socket: &str,
) -> Result<String, String> {
    if !log.anomalies.is_empty() {
        return Err(format!(
            "{}: not every piece READY: {:?}",
            dialect.name(),
            log.anomalies
        ));
    }
    let far: Vec<&Emission> = log.emissions.iter().filter(|e| e.to_far).collect();
    if far.is_empty()
        || far
            .iter()
            .any(|e| e.verb != "GET" || e.target != socket || e.need != need)
    {
        return Err(format!(
            "{}: the session's far frames are not GET {socket} on need {need}: {far:?}",
            dialect.name()
        ));
    }
    let want = usage_tokens(dialect, usage);
    let got: Vec<(u32, u64)> = log
        .units
        .iter()
        .filter(|u| u.0 < 4)
        .map(|u| (u.0, u.2))
        .collect();
    if want.is_empty() || got != want || !log.units.iter().any(|u| u.0 == 6 && u.2 == 1) {
        return Err(format!(
            "{}: the far end's usage {want:?} was reported as {:?}",
            dialect.name(),
            log.units
        ));
    }
    Ok(format!(
        "{}: GET {socket} on need {need}, the far end's usage reported as {got:?} plus the fee",
        dialect.name()
    ))
}

fn dial_check(o: &DialObs) -> Result<String, String> {
    let a = dial_one(
        Dialect::OpenAi,
        &o.openai,
        USAGE_DONE,
        RIDES_REALTIME_SOCKET,
        REALTIME_SOCKET_PATH,
    )?;
    let b = dial_one(
        Dialect::Gemini,
        &o.gemini,
        GEMINI_USAGE,
        RIDES_LIVE_SOCKET,
        GEMINI_SOCKET_PATH,
    )?;
    Ok(format!(
        "a session names the dialect's socket under the member's base URL on its declared need \
         and reports what arrives over it ({a}; {b}). Opening the socket (net guard, TLS, the \
         upgrade) is the kernel transport's"
    ))
}

fn provider_dial(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "a session's far frames ride the dialect's socket and its usage is reported",
        &rig.both(dial_script),
        &dial_check,
        &|o: &DialObs| {
            let mut planted = o.clone();
            if let Some(e) = planted.openai.emissions.iter_mut().find(|e| e.to_far) {
                e.need = RIDES_REALTIME_PASS;
            }
            planted
        },
    )
}

// ── admit-refusal ───────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct AdmitObs {
    rendered: Vec<(u16, Rendered)>,
    after: Vec<String>,
    drive: (Outcome, Vec<u64>),
    control: Answer,
}

const REFUSALS: [(u16, &str, &str); 3] = [
    (429, "the caller's budget is exhausted", "rate_limit_error"),
    (403, "the key holds no session grant", "permission_error"),
    (401, "no credential was presented", "authentication_error"),
];

fn admit_script(p: &Plugin<Plane>) -> AdmitObs {
    let _ = open(p, SESSION, Some(PUBLIC));
    let rendered = REFUSALS
        .iter()
        .map(|(status, words, _)| (*status, refusal(p, 60, 0, u32::from(*status), words)))
        .collect();
    let far = piece(p, &session(60, 2, FROM_FAR_END, 0, &downlink(96)));
    let collect = piece(p, &session(60, 2, FROM_KERNEL, 0, &[]));
    let after = vec![
        format!("far {:?} emitted={}", far.outcome, far.emitted.len()),
        format!(
            "collect {:?} emitted={}",
            collect.outcome,
            collect.emitted.len()
        ),
    ];
    let drive = drive(p);
    let mut s = Session::open(p, 61, 2);
    let control = s.push(FROM_CALLER, 0, &uplink(100));
    AdmitObs {
        rendered,
        after,
        drive,
        control,
    }
}

fn admit_check(o: &AdmitObs) -> Result<String, String> {
    for ((status, r), (_, words, kind)) in o.rendered.iter().zip(REFUSALS) {
        let body: Value =
            serde_json::from_slice(&refusal_body(*status, words)).unwrap_or(Value::Null);
        let (k, w) = error_of(r);
        if r.outcome != Outcome::Ready
            || k != kind
            || w != words
            || serde_json::from_str::<Value>(&r.body).ok() != Some(body)
            || r.fields != [("content-type".to_string(), "application/json".to_string())]
            || r.status != 0
            || r.records != 0
        {
            return Err(format!("the kernel's {status} refusal rendered as {r:?}"));
        }
    }
    if o.after != ["far Refused emitted=0", "collect Refused emitted=0"] {
        return Err(format!(
            "a refused unit's stream was answered as though a session were open: {:?}",
            o.after
        ));
    }
    if o.drive != (Outcome::Ready, Vec::new()) {
        return Err(format!(
            "drive named a session after the refusal: {:?}",
            o.drive
        ));
    }
    let c = &o.control;
    if c.outcome != Outcome::Ready || !c.to_far || c.need != RIDES_REALTIME_SOCKET {
        return Err(format!(
            "the admitted control did not reach the far end: {c:?}"
        ));
    }
    Ok(
        "the kernel's refusal (budget 429, grant 403, credential 401) is rendered in the \
         dialect's error envelope with the kernel's status kept and no record written; a refused \
         unit opens no session and dials nothing (its stream's far piece and collection are \
         refused, drive names nothing), while an admitted control dials. Reading the caller's \
         chain dry and refusing before the hold is the kernel's admit step"
            .to_string(),
    )
}

fn admit_refusal(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "a refusal opens nothing and is rendered in the dialect's shape",
        &rig.both(admit_script),
        &admit_check,
        &|o: &AdmitObs| {
            let mut planted = o.clone();
            planted.rendered[0].1.body =
                String::from_utf8_lossy(&refusal_body(500, "x")).into_owned();
            planted
        },
    )
}

// ── route-failover ──────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct FailObs {
    arrived: Arrived,
    first: Answer,
    failed: Answer,
    second: Answer,
    caller: Answer,
    answered: Answer,
    terminal_attempt: Answer,
    terminal: Answer,
}

fn fail_script(p: &Plugin<Plane>) -> FailObs {
    let _ = open(p, SESSION, Some(PUBLIC));
    let arrived = arrive(p, 0);
    let first = piece(p, &attempt(70, 0, 1));
    let failed = piece(
        p,
        &Piece {
            status: 503,
            ..request(
                70,
                0,
                FROM_FAR_END,
                PIECE_HAS_STATUS,
                b"upstream unavailable",
            )
        },
    );
    let second = piece(p, &attempt(70, 0, 2));
    let caller = piece(p, &request(70, 0, FROM_CALLER, PIECE_LAST, &[]));
    let answered = piece(
        p,
        &Piece {
            status: 200,
            ..request(70, 0, FROM_FAR_END, PIECE_HAS_STATUS | PIECE_LAST, MINTED)
        },
    );
    let terminal_attempt = piece(p, &attempt(71, 0, 1));
    let terminal = piece(
        p,
        &Piece {
            status: 503,
            ..request(71, 0, FROM_FAR_END, PIECE_HAS_STATUS | PIECE_LAST, b"down")
        },
    );
    FailObs {
        arrived,
        first,
        failed,
        second,
        caller,
        answered,
        terminal_attempt,
        terminal,
    }
}

/// Whether two ATTEMPTs answered the same far request: verb, target, fields, body and need.
fn same_request(a: &Answer, b: &Answer) -> bool {
    a.verb == b.verb
        && a.target == b.target
        && a.fields == b.fields
        && a.emitted == b.emitted
        && a.need == b.need
}

fn fail_check(o: &FailObs) -> Result<String, String> {
    if o.arrived.outcome != Outcome::Ready || o.arrived.route != (ROUTE_DIRECT, MODEL.to_string()) {
        return Err(format!("the mint arrived as {:?}", o.arrived));
    }
    let f = &o.first;
    if f.outcome != Outcome::Ready
        || !f.to_far
        || f.verb != "POST"
        || f.target != "/v1/realtime/client_secrets"
        || f.need != RIDES_REALTIME_PASS
        || f.emitted.is_empty()
    {
        return Err(format!("attempt 1 sent {f:?}"));
    }
    if o.failed.outcome != Outcome::Ready || !o.failed.emitted.is_empty() || o.failed.done {
        return Err(format!(
            "a failing far end's first bytes reached the caller (the walk could no longer fail \
             over): {:?}",
            o.failed
        ));
    }
    if !same_request(&o.second, f) || !same_request(&o.terminal_attempt, f) {
        return Err(format!(
            "a later attempt sent a different request: {:?} vs {:?}",
            o.second, f
        ));
    }
    if o.caller.outcome != Outcome::Ready || !o.caller.emitted.is_empty() {
        return Err(format!(
            "the re-pushed caller body was answered {:?}",
            o.caller
        ));
    }
    let a = &o.answered;
    if a.outcome != Outcome::Ready
        || !a.done
        || a.status != 200
        || a.emitted != mint_reply(200, MINTED).body
    {
        return Err(format!(
            "attempt 2's answer was not the caller's whole answer, free of attempt 1: {a:?}"
        ));
    }
    let t = &o.terminal;
    if t.outcome != Outcome::Ready
        || !t.done
        || t.status != u32::from(MINT_FAILED_STATUS)
        || !String::from_utf8_lossy(&t.emitted)
            .contains("client-secret endpoint returned 503 Service Unavailable")
    {
        return Err(format!("the last attempt's failure was rendered {t:?}"));
    }
    Ok(
        "the mint names the session model's DIRECT route; a failing far end reaches the caller \
         with nothing before its last piece, so the walk may still fail over; each ATTEMPT is \
         answered with the same request afresh, and the next far end's answer is the caller's \
         whole answer; a last attempt that fails is the served plane's 502. Tripping the \
         breaker cell and refusing further dials are the kernel walk's"
            .to_string(),
    )
}

fn route_failover(rig: &Rig, slice: &str) -> bool {
    let failover = judge(
        slice,
        "each attempt is answered afresh and nothing reaches the caller before the answer",
        &rig.both(fail_script),
        &fail_check,
        &|o: &FailObs| {
            let mut planted = o.clone();
            planted.second.emitted = b"planted".to_vec();
            planted
        },
    );
    let unrouted = judge(
        slice,
        "a section with no session model names no route",
        &rig.both(|p| {
            let _ = open(p, b"{}", Some(PUBLIC));
            arrive(p, 0)
        }),
        &|a: &Arrived| {
            if a.outcome == Outcome::Ready && a.route == (ROUTE_POOL, String::new()) {
                Ok(
                    "with no `streams.session.model` the door names no route for the walk to \
                    resolve (the door steps refuse an unnamed keyed route)"
                        .to_string(),
                )
            } else {
                Err(format!("an unrouted mint arrived as {a:?}"))
            }
        },
        &|a: &Arrived| Arrived {
            route: (ROUTE_DIRECT, MODEL.to_string()),
            ..a.clone()
        },
    );
    failover && unrouted
}

// ── audit-record ────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct AuditObs {
    audit_kind: String,
    op_classes: Vec<String>,
    record_kinds: Vec<String>,
    op_of: Vec<(Outcome, u32)>,
    records: u32,
}

fn audit_script(p: &Plugin<Plane>) -> AuditObs {
    let served = p.served();
    let record_kinds = p
        .declared()
        .record_kinds
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    let _ = open(p, SESSION, Some(PUBLIC));
    let op_of = (0..5)
        .map(|c| {
            let a = arrive(p, c);
            (a.outcome, a.op_class)
        })
        .collect();
    let mut records = 0;
    for stream in [80, 81] {
        let mut s = Session::open(p, stream, 2);
        s.push(FROM_CALLER, 0, &uplink(100));
        s.push(FROM_FAR_END, 0, USAGE_DONE);
        s.push(FROM_CALLER, PIECE_LAST, &[]);
        records += s.log.records;
    }
    for x in [
        attempt(82, 0, 1),
        request(82, 0, FROM_CALLER, PIECE_LAST, &[]),
        Piece {
            status: 200,
            ..request(82, 0, FROM_FAR_END, PIECE_HAS_STATUS | PIECE_LAST, MINTED)
        },
    ] {
        records += piece(p, &x).records;
    }
    records += refusal(p, 83, 0, 403, "refused").records;
    AuditObs {
        audit_kind: served.audit_kind.to_string(),
        op_classes: served.op_classes.iter().map(|c| (*c).to_string()).collect(),
        record_kinds,
        op_of,
        records,
    }
}

fn audit_check(o: &AuditObs) -> Result<String, String> {
    if o.audit_kind != AUDIT_KIND || o.op_classes != [SESSION_OPEN_ACTION] {
        return Err(format!(
            "the tail states audit kind {} and op classes {:?}",
            o.audit_kind, o.op_classes
        ));
    }
    if !o.record_kinds.is_empty() {
        return Err(format!(
            "the tail declares record kinds {:?}",
            o.record_kinds
        ));
    }
    if o.op_of
        .iter()
        .any(|(outcome, op)| *outcome != Outcome::Ready || *op != 0)
    {
        return Err(format!(
            "a door's unit is not the one session open: {:?}",
            o.op_of
        ));
    }
    if o.records != 0 {
        return Err(format!(
            "the door wrote {} record row(s) of its own beside the kernel's one fixed record",
            o.records
        ));
    }
    Ok(format!(
        "every door's unit is the one `{SESSION_OPEN_ACTION}` operation under the `{AUDIT_KIND}` \
         audit kind, and the door writes NO row of its own across two whole sessions, a mint and \
         a refusal (it declares no record kind), so the kernel's one fixed record per unit is the \
         only row; writing that row is the kernel's audit step"
    ))
}

fn audit_record(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "the audit kind and operation the kernel's one row is written under",
        &rig.both(audit_script),
        &audit_check,
        &|o: &AuditObs| AuditObs {
            records: o.records + 1,
            ..o.clone()
        },
    )
}

// ── exit-terminal ───────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExitObs {
    end: Answer,
    after: Vec<String>,
    drive: (Outcome, Vec<u64>),
    done: u32,
    interrupted: Answer,
}

fn exit_script(p: &Plugin<Plane>) -> ExitObs {
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 90, 2);
    s.push(FROM_CALLER, 0, &uplink(1000));
    s.push(FROM_FAR_END, 0, USAGE_DONE);
    s.push(FROM_CALLER, 0, &uplink(1000));
    let end = s.push(FROM_CALLER, PIECE_LAST, &[]);
    let collect = piece(p, &session(90, 2, FROM_KERNEL, 0, &[]));
    let far = piece(p, &session(90, 2, FROM_FAR_END, 0, &downlink(96)));
    let after = vec![
        format!(
            "collect {:?} emitted={}",
            collect.outcome,
            collect.emitted.len()
        ),
        format!("far {:?} emitted={}", far.outcome, far.emitted.len()),
    ];
    let drive = drive(p);
    let mut t = Session::open(p, 91, 2);
    let interrupted = t.push(FROM_CALLER, PIECE_LAST, &[]);
    ExitObs {
        end,
        after,
        drive,
        done: s.log.done + t.log.done,
        interrupted,
    }
}

fn exit_check(o: &ExitObs) -> Result<String, String> {
    if o.end.outcome != Outcome::Ready || !o.end.done || o.end.units_line() != usage_units(2) {
        return Err(format!(
            "the caller's end did not settle the open turn once and end the session: {:?}",
            o.end
        ));
    }
    if o.after != ["collect Refused emitted=0", "far Refused emitted=0"] {
        return Err(format!("an ended session still answered: {:?}", o.after));
    }
    if o.drive != (Outcome::Ready, Vec::new()) {
        return Err(format!("drive named an ended session: {:?}", o.drive));
    }
    if o.done != 2 {
        return Err(format!("{} end(s) across two sessions", o.done));
    }
    let i = &o.interrupted;
    if i.outcome != Outcome::Ready || !i.done || !i.units.is_empty() {
        return Err(format!(
            "a session ended before its first frame answered {i:?}"
        ));
    }
    Ok(
        "a session ends ONCE: the caller's end settles the open turn's audio seconds once \
         (cumulative units final), carries the end exactly once, and afterwards the stream is \
         refused on every side and drive names nothing; a session torn down before its first \
         frame ends with no units and no fee. Sealing the session's one line is the kernel's \
         exit step"
            .to_string(),
    )
}

fn exit_terminal(rig: &Rig, slice: &str) -> bool {
    judge(
        slice,
        "one session, one end",
        &rig.both(exit_script),
        &exit_check,
        &|o: &ExitObs| ExitObs {
            done: o.done + 1,
            ..o.clone()
        },
    )
}

// ── tool-reply ──────────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
struct ToolObs {
    log: Log,
    /// Frames emitted once the call was announced.
    announced: usize,
    /// Frames emitted once the turn's usage arrived.
    usage_at: usize,
    /// The cumulative units once the turn closed.
    units: Vec<(u32, u32, u64)>,
}

struct ToolWire {
    dialect: Dialect,
    announce: Vec<Vec<u8>>,
    usage: &'static [u8],
    reply: Vec<u8>,
}

fn tool_wire(dialect: Dialect) -> ToolWire {
    match dialect {
        Dialect::OpenAi => ToolWire {
            dialect,
            announce: vec![
                frame(&json!({"type": "response.output_item.added",
                    "item": {"type": "function_call", "call_id": "call_x", "name": "lookup"}})),
                frame(&json!({"type": "response.function_call_arguments.delta",
                    "call_id": "call_x", "delta": "{\"q\":1}"})),
                frame(&json!({"type": "response.function_call_arguments.done",
                    "call_id": "call_x", "name": "lookup", "arguments": "{\"q\":1}"})),
            ],
            usage: USAGE_DONE,
            reply: frame(&json!({"type": "conversation.item.create",
                "item": {"type": "function_call_output", "call_id": "call_x",
                         "output": "{\"ok\":true}"}})),
        },
        Dialect::Gemini => ToolWire {
            dialect,
            announce: vec![frame(&json!({"toolCall": {"functionCalls": [
                {"id": "call_x", "name": "lookup", "args": {"q": 1}}]}}))],
            usage: GEMINI_USAGE,
            reply: frame(&json!({"toolResponse": {"functionResponses": [
                {"id": "call_x", "name": "lookup", "response": {"ok": true}}]}})),
        },
    }
}

fn tool_script(p: &Plugin<Plane>, w: &ToolWire) -> ToolObs {
    let _ = open(p, SESSION, Some(PUBLIC));
    let mut s = Session::open(p, 95, w.dialect.claim());
    for f in &w.announce {
        s.push(FROM_FAR_END, 0, f);
    }
    let announced = s.emitted();
    s.push(FROM_FAR_END, 0, w.usage);
    let usage_at = s.emitted();
    let units = s.log.units.clone();
    s.push(FROM_CALLER, 0, &w.reply);
    ToolObs {
        log: s.log,
        announced,
        usage_at,
        units,
    }
}

fn phase(log: &Log, from: usize, to: usize) -> Log {
    Log {
        emissions: log.emissions.get(from..to).unwrap_or_default().to_vec(),
        ..Log::default()
    }
}

fn tool_check(dialect: Dialect, o: &ToolObs) -> Result<String, String> {
    let name = dialect.name();
    if !o.log.anomalies.is_empty() {
        return Err(format!(
            "{name}: not every piece READY: {:?}",
            o.log.anomalies
        ));
    }
    let announce = phase(&o.log, 0, o.announced);
    if announce.emissions.iter().any(|e| e.to_far) {
        return Err(format!(
            "{name}: the door sent the far end something for a call it was only to relay (the \
             gateway authors no result): {:?}",
            announce.emissions
        ));
    }
    let call = vec![
        Norm::ToolOpen("call_x".to_string(), "lookup".to_string()),
        Norm::ToolArgs("call_x".to_string(), json!({"q": 1})),
        Norm::ToolClose("call_x".to_string()),
    ];
    let relayed = caller_norms(dialect, &announce);
    if fingerprint(&relayed) != fingerprint(&call) {
        return Err(format!(
            "{name}: the call reached the caller as {relayed:?}"
        ));
    }
    if o.usage_at != o.announced {
        return Err(format!(
            "{name}: the turn's usage was relayed instead of reported"
        ));
    }
    if !o.units.contains(&(5, 1, 1)) {
        return Err(format!(
            "{name}: the call was not counted once: {:?}",
            o.units
        ));
    }
    let reply = phase(&o.log, o.usage_at, o.log.emissions.len());
    let carried = far_norms(dialect, &reply);
    let ok = reply.emissions.len() == 1
        && reply.emissions[0].to_far
        && matches!(carried.as_slice(), [Norm::ToolResult(id, out)] if id == "call_x" && *out == json!({"ok": true}));
    if !ok {
        return Err(format!(
            "{name}: the caller's own result reached the far end as {carried:?} ({} frame(s))",
            reply.emissions.len()
        ));
    }
    Ok(format!(
        "{name}: the far end's call reached the caller as it was made and the door sent the far \
         end nothing for it; the call counted once; the caller's own result reached the far end \
         alone (no door-authored response)"
    ))
}

fn tool_reply(rig: &Rig, slice: &str) -> bool {
    let mut pass = true;
    for dialect in [Dialect::OpenAi, Dialect::Gemini] {
        let w = tool_wire(dialect);
        pass &= judge(
            slice,
            &format!("{} tool call relayed, never answered", dialect.name()),
            &rig.both(|p| tool_script(p, &w)),
            &|o: &ToolObs| tool_check(dialect, o),
            &|o: &ToolObs| {
                let mut planted = o.clone();
                planted.log.emissions.insert(
                    0,
                    Emission {
                        to_far: true,
                        frame: w.reply.clone(),
                        need: dialect.ride(),
                        verb: "GET".to_string(),
                        target: dialect.socket().to_string(),
                    },
                );
                planted.announced += 1;
                planted.usage_at += 1;
                planted
            },
        );
    }
    pass
}
