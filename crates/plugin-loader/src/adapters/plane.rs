// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane adapter: `PlanePort` over the plane kind's `Proxy` (IF §11.3, §8.6).
//!
//! The plane-only describe items are decoded once (`decode_describe`, at `Registry::add`) under the §8.6 describe
//! rules. Every answer is decoded straight into `PlaneOut` items for the sink. The adapter checks the whole answer
//! first and only then hands it over, so a sink never sees part of an answer that ends in a FAULT. It checks
//! framing, the pod and tail rules and where a record may stand (§8.6 placement: TRAILERS, EMIT, WORK, JUDGE, the
//! FORWARD rule, the DEMUX combinations). Session state (the once rule of a deferred FORWARD, the current target) is
//! K8's. A REFUSED or FAILED answer is a `PortError` whose text went through `scrub::fail_text` (I14, C-SCRUB-CUT).

use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub mod protected_reply;

use crate::call::kinds::plane::{OnSession as _, Proxy};
use crate::call::Mono;
use busbar_plugin_abi::fail::fact::{FACT_BACKEND_STATUS, FACT_RETRY_AFTER_S};
use busbar_plugin_abi::fail::refused::R_INVALID;
use busbar_plugin_abi::fail::{failed, CallError, FaultReason};
use busbar_plugin_abi::fallback_usage::{self as attempt_wire, SelectedResource};
use busbar_plugin_abi::host_side::answer::Answer;
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::host_side::driver::Driver;
use busbar_plugin_abi::host_side::needs::Needs;
use busbar_plugin_abi::host_side::pool::{sync_out, Pool};
use busbar_plugin_abi::host_side::scrub::{fail_text, Scrub};
use busbar_plugin_abi::plane::{self as p, tag as t, PlaneReq, Target};
use busbar_plugin_abi::records::{
    commit, tag as g, FactRec, FactTextRec, Rec, RecDelRec, RecErr, RecPredRec, RecPutRec, Records,
    Reply, U32Rec, U64Rec, Writer,
};
use busbar_plugin_abi::types::{Bytes, Slice, Status, Str};

use crate::instance::ErrorBook;
use busbar_ports::codec::fallback_usage::Declaration;
use busbar_ports::codec::plane::decode_provider_schema;
use busbar_ports::plane::{
    PlaneIn, PlaneOut, PlanePort, PlaneSession, RouteInfo, TargetIn, UsageClass,
};
use busbar_ports::PluginCode;
use busbar_ports::{CallCx, FactRef, PortError};

/// `RouteRec.methods` bits. IF gap: the MIN-3 abi names no method bits; these are the kept encoding of
/// busbar-contract abi/transport/route.rs (`METHOD_GET` = 1, `METHOD_POST` = 1 << 2), which K8C's path claims
/// also read (§12.26).
const GET: u32 = 1;
const POST: u32 = 1 << 2;
const ROUTE_BITS: u32 =
    p::ROUTE_CATALOG | p::ROUTE_ADMIN | p::ROUTE_LINE | p::ROUTE_RECOVERY | p::ROUTE_UPGRADE;
const AUTH_BITS: u32 = p::AUTH_PRINCIPAL
    | p::AUTH_OPTIONAL
    | p::AUTH_PUBLIC
    | p::AUTH_TICKET
    | p::AUTH_SIGNED_INGRESS
    | p::AUTH_OPERATOR;
const MSG_BITS: u32 = p::MSG_TEXT | p::MSG_BINARY | p::MSG_FIN;
const DX_BITS: u32 = p::DX_RESIGHT | p::DX_OUTSTANDING | p::DX_BROADCAST | p::DX_FINAL;

/// The plane-only items of one image's describe answer (§8.6), decoded once at `Registry::add`.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PlaneDescribe {
    pub routes: Vec<RouteInfo>,
    pub dialects: Vec<Box<str>>,
    /// The declared usage classes and attempt classes: shared lists, made once when the describe
    /// is decoded, so a session that freezes its declaration shares them and copies none.
    pub usage_classes: Arc<[UsageClass]>,
    pub attempt_classes: Arc<[Box<str>]>,
    pub tick_s: Option<u64>,
    /// D_ADMIN_OPENAPI: the OpenAPI fragment of the ROUTE_ADMIN routes, for K8's admin document merge (round 8).
    pub admin_openapi: Option<Box<str>>,
}

/// A describe the §8.6 rules refuse. The registry turns it into `Refusal { code: DescribeInvalid, field }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescribeInvalid(pub &'static str);

/// Decodes the plane describe items under the §8.6 describe rules. `methods`/`facts` are the image's D_METHODS
/// and D_FACTS. Generic items (tags below 0x0100) and D_DIALECT_AUTH are the registry's and are skipped here.
pub fn decode_describe(
    describe: Records<'_>,
    methods: u64,
    facts: u64,
) -> Result<PlaneDescribe, DescribeInvalid> {
    let mut d = PlaneDescribe::default();
    // The two class lists grow here as the describe is read and become the describe's shared
    // lists once it is whole.
    let mut usage_classes: Vec<UsageClass> = Vec::new();
    let mut attempt_classes: Vec<Box<str>> = Vec::new();
    let mut headers: Vec<(u32, &str)> = Vec::new();
    let mut resource_routes: Vec<(u32, Vec<Box<str>>)> = Vec::new();
    for rec in describe {
        let rec = rec.map_err(|_| DescribeInvalid("describe"))?;
        match rec.tag {
            t::D_ROUTE => {
                let bad = DescribeInvalid("describe.route");
                let (r, tail) = rec.pod_tail::<p::RouteRec>().map_err(|_| bad)?;
                let pattern = core::str::from_utf8(tail).map_err(|_| bad)?;
                route_rules(&r)?;
                if pattern.is_empty() || d.routes.iter().any(|x| x.route == r.route) {
                    return Err(bad);
                }
                let line = |x: u32| x & p::ROUTE_LINE != 0;
                if line(r.flags) && d.routes.iter().any(|x| line(x.flags)) {
                    return Err(DescribeInvalid("describe.route_line"));
                }
                d.routes.push(RouteInfo {
                    route: r.route,
                    methods: r.methods,
                    flags: r.flags,
                    auth: r.auth,
                    pattern: pattern.into(),
                    cred_header: None,
                    resource_kinds: Arc::default(),
                });
            }
            t::D_ROUTE_RESOURCES => {
                let bad = DescribeInvalid("describe.route_resources");
                let (h, tail) = rec.pod_tail::<p::RouteHeaderRec>().map_err(|_| bad)?;
                if h._r != 0 || resource_routes.iter().any(|(r, _)| *r == h.route) {
                    return Err(bad);
                }
                let mut kinds: Vec<Box<str>> = Vec::new();
                for kind in Records::new(tail) {
                    let kind = kind.map_err(|_| bad)?;
                    if kind.tag != g::TEXT || kinds.len() == 8 {
                        return Err(bad);
                    }
                    let k = kind.text().map_err(|_| bad)?;
                    if !busbar_plugin_abi::resource_admission::valid_kind(k)
                        || kinds.iter().any(|s| s.as_ref() == k)
                    {
                        return Err(bad);
                    }
                    kinds.push(k.into());
                }
                if kinds.is_empty() {
                    return Err(bad);
                }
                resource_routes.push((h.route, kinds));
            }
            t::D_ROUTE_CRED_HEADER => {
                let bad = DescribeInvalid("describe.route_cred_header");
                let (h, tail) = rec.pod_tail::<p::RouteHeaderRec>().map_err(|_| bad)?;
                let name = core::str::from_utf8(tail).map_err(|_| bad)?;
                let lower = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-';
                if h._r != 0
                    || !(1..=128).contains(&name.len())
                    || !name.bytes().all(lower)
                    || headers.iter().any(|(r, _)| *r == h.route)
                {
                    return Err(bad);
                }
                headers.push((h.route, name));
            }
            t::D_DIALECT => {
                let bad = DescribeInvalid("describe.dialect");
                let word = rec.text().map_err(|_| bad)?;
                if !word_ok(word, 128) || d.dialects.iter().any(|x| **x == *word) {
                    return Err(bad);
                }
                d.dialects.push(word.into());
            }
            t::D_TICK_S => {
                let bad = DescribeInvalid("describe.tick_s");
                let v: U64Rec = rec.pod().map_err(|_| bad)?;
                if v.value == 0 || d.tick_s.replace(v.value).is_some() {
                    return Err(bad);
                }
            }
            t::D_USAGE_CLASS => {
                let bad = DescribeInvalid("describe.usage_class");
                if facts & (p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES) != 0
                    && usage_classes.len() >= attempt_wire::MAX_CLASSES
                {
                    return Err(bad);
                }
                let (u, tail) = rec.pod_tail::<p::UsageClassRec>().map_err(|_| bad)?;
                let class = class_text(tail).map_err(|_| bad)?;
                let e = u.expected_units;
                if u._r != 0
                    || !(p::UNIT_COUNT..=p::UNIT_CHARACTERS).contains(&u.unit)
                    || !(e.is_nan() || (e.is_finite() && e >= 0.0))
                    || usage_classes.iter().any(|x| *x.class == *class)
                {
                    return Err(bad);
                }
                usage_classes.push(UsageClass {
                    class: class.into(),
                    unit: u.unit,
                    expected_units: (!e.is_nan()).then_some(e),
                });
            }
            t::D_ATTEMPT_CLASS => {
                let class = attempt_wire::class_text(rec.body)
                    .map_err(|_| DescribeInvalid("describe.attempt_class"))?;
                if attempt_classes.len() >= attempt_wire::MAX_CLASSES {
                    return Err(DescribeInvalid("describe.attempt_class"));
                }
                attempt_classes.push(class.into());
            }
            t::D_ADMIN_OPENAPI => {
                let bad = DescribeInvalid("describe.admin_openapi");
                let text = rec.text().map_err(|_| bad)?;
                if text.is_empty() || d.admin_openapi.replace(text.into()).is_some() {
                    return Err(bad);
                }
            }
            t::D_PROVIDER_SCHEMA | t::D_DIALECT_AUTH => {}
            tag if tag < 0x0100 => {}
            _ => return Err(DescribeInvalid("describe")),
        }
    }
    for (route, name) in headers {
        let r = d.routes.iter_mut().find(|r| r.route == route);
        match r {
            Some(r) if r.auth & (p::AUTH_PRINCIPAL | p::AUTH_OPTIONAL) != 0 => {
                r.cred_header = Some(name.into())
            }
            _ => return Err(DescribeInvalid("describe.route_cred_header")),
        }
    }
    if (!resource_routes.is_empty() && facts & p::FB_RESOURCE_ADMISSION == 0)
        || (facts & p::FB_RESOURCE_ADMISSION != 0 && methods & p::M_SELECT_RESOURCES == 0)
    {
        return Err(DescribeInvalid("describe.route_resources"));
    }
    if facts & p::FB_CHANNEL_OPEN != 0
        && methods & (p::M_CHANNEL | p::M_DEMUX) != (p::M_CHANNEL | p::M_DEMUX)
    {
        return Err(DescribeInvalid("describe.channel"));
    }
    for (route, kinds) in resource_routes {
        let route = d
            .routes
            .iter_mut()
            .find(|r| r.route == route)
            .ok_or(DescribeInvalid("describe.route_resources"))?;
        if route.flags != 0 || route.auth != p::AUTH_PRINCIPAL {
            return Err(DescribeInvalid("describe.route_resources"));
        }
        route.resource_kinds = kinds.into();
    }
    let any = |bit: u32| d.routes.iter().any(|r| r.flags & bit != 0);
    if any(p::ROUTE_ADMIN) != d.admin_openapi.is_some() {
        return Err(DescribeInvalid("describe.admin_openapi"));
    }
    if any(p::ROUTE_CATALOG) && methods & p::M_RENDER == 0 {
        return Err(DescribeInvalid("describe.route_catalog"));
    }
    if facts & p::FB_PROBES != 0 && methods & p::M_PROBE == 0 {
        return Err(DescribeInvalid("describe.probes"));
    }
    d.usage_classes = usage_classes.into();
    d.attempt_classes = attempt_classes.into();
    Declaration::new(facts, &d.usage_classes, &d.attempt_classes)
        .map_err(|_| DescribeInvalid("describe.attempt_class"))?;
    if facts & (p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES) != 0 && methods & p::M_UPSTREAM == 0
    {
        return Err(DescribeInvalid("describe.attempt_upstream"));
    }
    decode_provider_schema(describe).map_err(|_| DescribeInvalid("describe.provider_schema"))?;
    Ok(d)
}

/// The RouteRec.flags and auth rules of §8.6 (rounds 8, 10 and 13).
fn route_rules(r: &p::RouteRec) -> Result<(), DescribeInvalid> {
    if r.auth == 0 || r.auth & !AUTH_BITS != 0 {
        return Err(DescribeInvalid("describe.route.auth"));
    }
    if r.flags & !ROUTE_BITS != 0 || r.methods == 0 {
        return Err(DescribeInvalid("describe.route"));
    }
    let alone = |bit: u32| r.flags & bit == 0 || r.flags == bit;
    if !alone(p::ROUTE_LINE) || !alone(p::ROUTE_RECOVERY) || !alone(p::ROUTE_UPGRADE) {
        return Err(DescribeInvalid("describe.route.flags"));
    }
    if r.flags & p::ROUTE_LINE != 0 && r.methods != POST {
        return Err(DescribeInvalid("describe.route_line"));
    }
    if r.flags & p::ROUTE_RECOVERY != 0 && (r.methods != GET || r.auth != p::AUTH_PRINCIPAL) {
        return Err(DescribeInvalid("describe.route_recovery"));
    }
    if r.flags & p::ROUTE_UPGRADE != 0 && r.methods != GET {
        return Err(DescribeInvalid("describe.route_upgrade"));
    }
    if r.flags & p::ROUTE_ADMIN != 0
        && (r.auth != p::AUTH_OPERATOR || r.flags & p::ROUTE_CATALOG != 0)
    {
        return Err(DescribeInvalid("describe.route_admin"));
    }
    Ok(())
}

/// Which call answered. It decides what the answer may hold (§8.6). `Piece` carries `from`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Request,
    Upstream,
    Channel,
    Piece(u32),
    End,
    Rewrite,
    Render,
    Probe,
    Demux,
    /// admin(ADMIN_TICK): PUSH* and EMIT* only.
    Tick,
}

/// What one answer held so far, for the rules that look across records.
#[derive(Default)]
struct Seen {
    forward: bool,
    expect: bool,
    intent: bool,
    client: bool,
    /// ATTEMPT with RETRY, HARD or DECLINE: no to-client record and (DECLINE) no upstream record.
    no_client: bool,
    decline: bool,
    up: bool,
    /// The upstream head records may follow (UP_NEW in this answer, or `upstream`/`probe`).
    head: bool,
    trailers: bool,
    /// Render grammar: 0 = before RESPOND, 1 = head, 2 = after BODY, 3 = trailers, 4 = after END.
    render: u8,
    demux: bool,
    resource_echo: bool,
    attempt_end: bool,
    selected: bool,
    prepared: bool,
    channel: bool,
}

/// A misplaced record: FAULT BadRecords naming the tag.
fn misplaced(tag: u16) -> FaultReason {
    FaultReason::BadRecords(RecErr::Unknown(tag))
}

/// A malformed record: an unknown tag is FAULT UnknownTag, anything else FAULT BadRecords.
fn fault(e: RecErr) -> FaultReason {
    match e {
        RecErr::Unknown(tag) => FaultReason::UnknownTag(tag),
        e => FaultReason::BadRecords(e),
    }
}

/// Decodes one OK answer of `call` into the sink. `demux` = the image declared `demux` (a CHANNEL is otherwise
/// FAULT UnknownTag). The answer is checked whole before the first item reaches the sink.
pub fn decode_answer(
    call: Call,
    demux: bool,
    declaration: Declaration<'_>,
    selected: Option<SelectedResource<'_>>,
    exchange: Option<u32>,
    recs: Records<'_>,
    sink: &mut dyn FnMut(PlaneOut<'_>),
) -> Result<(), FaultReason> {
    walk(
        call,
        demux,
        declaration,
        exchange,
        recs,
        &mut |_: PlaneOut<'_>| {},
    )?;
    if call == Call::Upstream
        && declaration.facts() & (p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES) != 0
    {
        declaration
            .validate_preparation(selected, recs)
            .map_err(fault)?;
    }
    walk(call, demux, declaration, exchange, recs, sink)
}

fn walk(
    call: Call,
    demux: bool,
    declaration: Declaration<'_>,
    exchange: Option<u32>,
    recs: Records<'_>,
    sink: &mut dyn FnMut(PlaneOut<'_>),
) -> Result<(), FaultReason> {
    let mut s = Seen {
        head: matches!(call, Call::Upstream | Call::Probe),
        ..Seen::default()
    };
    for rec in recs {
        let rec = rec.map_err(fault)?;
        if rec.tag == g::METRIC && call != Call::Channel {
            continue;
        }
        if rec.tag == t::CHANNEL && !demux {
            return Err(FaultReason::UnknownTag(t::CHANNEL));
        }
        let feature = match rec.tag {
            t::SELECTED_RESOURCE => p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES,
            t::PREPARED_ESTIMATES => p::FB_PREPARED_ESTIMATES,
            t::ATTEMPT_USAGE | t::ATTEMPT_USAGE_END => p::FB_ATTEMPT_USAGE,
            _ => 0,
        };
        if feature != 0 && declaration.facts() & feature == 0 {
            return Err(misplaced(rec.tag));
        }
        if matches!(rec.tag, t::ATTEMPT_USAGE | t::ATTEMPT_USAGE_END)
            && matches!(call, Call::Piece(_))
            && exchange != Some(0)
        {
            return Err(misplaced(rec.tag));
        }
        place(call, &mut s, &rec)?;
        let out = item(&rec).map_err(fault)?;
        if call == Call::Channel
            && matches!(&out, PlaneOut::Channel { carrier, .. } if *carrier != p::CARRIER_STDIO)
        {
            return Err(misplaced(rec.tag));
        }
        if let PlaneOut::AttemptUsage(usage) = &out {
            if !declaration.is_attempt_class(usage.class) {
                return Err(misplaced(rec.tag));
            }
        }
        sink(out);
    }
    let late = s.forward && (s.intent || s.client);
    if late
        || (s.expect && !s.forward)
        || (s.no_client && s.client)
        || (s.decline && (s.up || s.selected || s.prepared))
    {
        return Err(misplaced(t::FORWARD));
    }
    if s.trailers && s.render != 4 {
        return Err(misplaced(t::TRAILERS));
    }
    if call == Call::Render && s.render != 4 {
        return Err(misplaced(t::END));
    }
    if call == Call::Channel && !s.channel {
        return Err(misplaced(t::CHANNEL));
    }
    Ok(())
}

/// The §8.6 placement rules for one record of a `call` answer.
fn place(call: Call, s: &mut Seen, rec: &Rec<'_>) -> Result<(), FaultReason> {
    let tag = rec.tag;
    let bad = Err(misplaced(tag));
    if call == Call::Channel {
        match tag {
            t::CHANNEL if !core::mem::replace(&mut s.channel, true) => {}
            g::FACT | g::FACT_TEXT => {}
            _ => return bad,
        }
    }
    // After TRAILERS only the trailer PAIRs and END may come (§8.6, round 8).
    if s.trailers && s.render == 3 && tag != g::PAIR && tag != t::END {
        return bad;
    }
    if call == Call::Render {
        s.render = match (s.render, tag) {
            (0, t::RESPOND) | (1, g::PAIR) => 1,
            (1, t::BODY) => 2,
            (1 | 2, t::TRAILERS) | (3, g::PAIR) => 3,
            (1..=3, t::END) => 4,
            _ => return bad,
        };
        s.trailers |= tag == t::TRAILERS;
        return Ok(());
    }
    let session = !matches!(call, Call::Rewrite | Call::Demux | Call::Tick);
    let flow = matches!(call, Call::Request | Call::Piece(_));
    let upstream = matches!(call, Call::Upstream | Call::Probe);
    let ok = match tag {
        g::METRIC => true,
        g::FACT | g::FACT_TEXT => call != Call::Demux && call != Call::Tick,
        t::USAGE | t::AUDIT => session,
        t::SELECTED_RESOURCE | t::PREPARED_ESTIMATES => call == Call::Upstream,
        t::ATTEMPT_USAGE | t::ATTEMPT_USAGE_END => {
            call == Call::Piece(p::FROM_UPSTREAM) || call == Call::End
        }
        t::STORE | t::DELETE => flow || call == Call::End,
        t::PUSH => flow || call == Call::End || call == Call::Tick,
        t::EMIT => session || call == Call::Tick,
        t::OBSERVE => flow || call == Call::End,
        t::SIGHT => flow || call == Call::End,
        t::COMMIT | t::WAKE_AT | t::DETACH | t::SIGNAL | t::FINISH => flow,
        t::RESPOND | t::BODY | t::MSG | t::END | t::TRAILERS => flow,
        t::FORWARD | t::EXPECT => call == Call::Request || call == Call::Piece(p::FROM_CORE),
        t::UP_CARRIER => upstream,
        t::RESOURCE_ECHO => {
            call == Call::Upstream && !core::mem::replace(&mut s.resource_echo, true)
        }
        g::H_METHOD | g::H_PATH | t::UP_SCOPE => s.head && (upstream || flow),
        g::PAIR => upstream || flow,
        t::UP_BODY | t::UP_MSG | t::UP_END | t::UP_NEW | t::EX_MSG | t::UP_CUT => upstream || flow,
        g::CONVERSATION => call == Call::Request,
        t::ATTEMPT => call == Call::Upstream || call == Call::Piece(p::FROM_UPSTREAM),
        t::CHANNEL => flow || call == Call::Probe || call == Call::Channel,
        t::LOOKUP | t::ENTITLE | t::JUDGE | t::MINT | t::SIGN | t::CONNECT | t::TRUST => flow,
        t::WORK | t::RENDEZVOUS | t::OBS_SCOPE | t::CH_READY => flow,
        t::DEMUX => call == Call::Demux && !core::mem::replace(&mut s.demux, true),
        _ => return Err(FaultReason::UnknownTag(tag)),
    };
    if !ok {
        return bad;
    }
    match tag {
        t::RESPOND | t::BODY | t::MSG => s.client = true,
        t::TRAILERS => {
            if core::mem::replace(&mut s.trailers, true) {
                return bad;
            }
            s.client = true;
            s.render = 3;
        }
        t::END => {
            s.client = true;
            s.render = 4;
        }
        t::FORWARD => {
            if core::mem::replace(&mut s.forward, true) {
                return bad;
            }
        }
        t::EXPECT => s.expect = true,
        t::SELECTED_RESOURCE => {
            if core::mem::replace(&mut s.selected, true) {
                return bad;
            }
        }
        t::PREPARED_ESTIMATES => {
            if core::mem::replace(&mut s.prepared, true) {
                return bad;
            }
        }
        t::ATTEMPT_USAGE => {
            if s.attempt_end {
                return bad;
            }
        }
        t::ATTEMPT_USAGE_END => {
            if core::mem::replace(&mut s.attempt_end, true) {
                return bad;
            }
        }
        t::UP_NEW => {
            s.head = true;
            s.up = true;
        }
        t::RESOURCE_ECHO
        | t::UP_CARRIER
        | g::H_METHOD
        | g::H_PATH
        | t::UP_SCOPE
        | t::UP_BODY
        | t::UP_MSG => s.up = true,
        t::UP_END | t::UP_CUT | t::EX_MSG => s.up = true,
        t::LOOKUP | t::ENTITLE | t::JUDGE | t::MINT | t::SIGN | t::CONNECT | t::TRUST => {
            s.intent = true
        }
        t::WORK | t::CHANNEL | t::RENDEZVOUS | t::OBS_SCOPE | t::OBSERVE => s.intent = true,
        t::ATTEMPT => {
            let a: p::AttemptRec = rec.pod_tail::<p::AttemptRec>().map_err(fault)?.0;
            let decline = a.verdict == p::ATT_DECLINE;
            if decline != (call == Call::Upstream) {
                return bad;
            }
            s.decline |= decline;
            s.no_client |= matches!(a.verdict, p::ATT_RETRY | p::ATT_HARD | p::ATT_DECLINE);
        }
        g::FACT | g::FACT_TEXT => {
            let key = rec.pod_tail::<FactTextRec>().map_err(fault)?.0.key;
            if is_want(key) {
                // A want follows FORWARD (§8.6 "FORWARD, then wants as FACT/FACT_TEXT").
                if !s.forward {
                    return bad;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// W_* keys (0x100..=0x1FF): the wants a FORWARD states.
fn is_want(key: u32) -> bool {
    (0x100..0x200).contains(&key)
}

/// One record as its `PlaneOut` item, with its pod and tail rules (§8.6).
fn item<'o>(rec: &Rec<'o>) -> Result<PlaneOut<'o>, RecErr> {
    let body = rec.body;
    let empty = |o: PlaneOut<'o>| {
        if body.is_empty() {
            Ok(o)
        } else {
            Err(RecErr::Size)
        }
    };
    Ok(match rec.tag {
        t::RESOURCE_ECHO => PlaneOut::ResourceEcho(
            busbar_plugin_abi::resource_admission::echo_record(*rec).map_err(|_| RecErr::Size)?,
        ),
        t::RESPOND => {
            let r: p::Respond = rec.pod()?;
            let status = u16::try_from(r.status).map_err(|_| RecErr::Size)?;
            check((100..=599).contains(&status))?;
            PlaneOut::Respond { status }
        }
        g::PAIR => {
            let (name, value) = rec.pair()?;
            PlaneOut::Header(name, value)
        }
        t::BODY => PlaneOut::Body(body),
        t::MSG | t::UP_MSG => {
            let (m, bytes) = rec.pod_tail::<p::MsgRec>()?;
            check(m.flags & !MSG_BITS == 0 && m._r == 0)?;
            if rec.tag == t::MSG {
                PlaneOut::Msg {
                    flags: m.flags,
                    bytes,
                }
            } else {
                PlaneOut::UpMsg {
                    flags: m.flags,
                    bytes,
                }
            }
        }
        t::END => empty(PlaneOut::End)?,
        t::TRAILERS => empty(PlaneOut::Trailers)?,
        t::FORWARD => {
            let f: p::Forward = rec.pod()?;
            check(f.flags & !p::FWD_STREAM == 0 && f._r == 0)?;
            PlaneOut::Forward {
                stream: f.flags & p::FWD_STREAM != 0,
            }
        }
        g::FACT => {
            let f: FactRec = rec.pod()?;
            check(f._r == 0)?;
            fact(f.key, FactRef::U(f.value))
        }
        g::FACT_TEXT => {
            let (f, text) = rec.pod_tail::<FactTextRec>()?;
            check(f._r == 0)?;
            fact(f.key, FactRef::Text(utf8(text)?))
        }
        t::UP_CARRIER => {
            let c: p::UpCarrier = rec.pod()?;
            check(c.carrier <= p::CARRIER_RTC && c.outbound <= p::OUTBOUND_NONE)?;
            PlaneOut::UpCarrier {
                carrier: c.carrier,
                outbound: c.outbound,
            }
        }
        g::H_METHOD => PlaneOut::UpMethod(rec.text()?),
        g::H_PATH => PlaneOut::UpPath(rec.text()?),
        t::UP_SCOPE => PlaneOut::UpScope(rec.text()?),
        t::UP_BODY => PlaneOut::UpBody(body),
        t::UP_END => empty(PlaneOut::UpEnd)?,
        t::UP_CUT => empty(PlaneOut::UpCut)?,
        t::UP_NEW => {
            let n: p::UpNew = rec.pod()?;
            check(n.exchange >= 1 && n.carrier <= p::CARRIER_RTC)?;
            check(n.outbound <= p::OUTBOUND_NONE && n._r == 0)?;
            PlaneOut::UpNew {
                exchange: n.exchange,
                carrier: n.carrier,
                outbound: n.outbound,
            }
        }
        t::EX_MSG => {
            let (m, bytes) = rec.pod_tail::<p::ExMsg>()?;
            check(m.flags & !(MSG_BITS | p::MSG_ASK) == 0)?;
            PlaneOut::ExMsg {
                exchange: m.exchange,
                flags: m.flags,
                stream: m.stream,
                bytes,
            }
        }
        g::CONVERSATION => PlaneOut::Conversation(body),
        t::SELECTED_RESOURCE => PlaneOut::SelectedResource(attempt_wire::decode_selected(*rec)?),
        t::PREPARED_ESTIMATES => PlaneOut::PreparedEstimates(attempt_wire::decode_prepared(*rec)?),
        t::ATTEMPT_USAGE => PlaneOut::AttemptUsage(attempt_wire::decode_attempt_usage(*rec)?),
        t::ATTEMPT_USAGE_END => PlaneOut::AttemptUsageEnd(attempt_wire::decode_attempt_end(*rec)?),
        t::USAGE | t::EXPECT => {
            let (u, tail) = rec.pod_tail::<p::UsageRec>()?;
            let class = class_text(tail)?;
            check(u.scale <= 9 && (p::SRC_REPORTED..=p::SRC_FLOOR).contains(&u.source))?;
            if rec.tag == t::USAGE {
                PlaneOut::Usage {
                    class,
                    amount: u.amount,
                    scale: u.scale,
                    source: u.source,
                }
            } else {
                check(u.source == p::SRC_ESTIMATED)?;
                PlaneOut::Expect {
                    class,
                    amount: u.amount,
                    scale: u.scale,
                }
            }
        }
        t::ATTEMPT => {
            let (a, reason) = rec.pod_tail::<p::AttemptRec>()?;
            check((p::ATT_OK..=p::ATT_DECLINE).contains(&a.verdict))?;
            check(a.class <= p::FC_CONTENT_POLICY)?;
            PlaneOut::Attempt {
                verdict: a.verdict,
                class: a.class,
                retry_after_s: a.retry_after_s,
                reason: utf8(reason)?,
            }
        }
        t::AUDIT => {
            let (a, tail) = rec.pod_tail::<p::AuditRec>()?;
            let n = usize::try_from(a.action_len).map_err(|_| RecErr::Size)?;
            let (action, resource) = tail.split_at_checked(n).ok_or(RecErr::Size)?;
            check((p::AUDIT_APPLIED..=p::AUDIT_DEGRADED).contains(&a.verdict))?;
            check(resource.len() <= 256)?;
            PlaneOut::Audit {
                verdict: a.verdict,
                action: class_text(action)?,
                resource: utf8(resource)?,
            }
        }
        t::OBS_SCOPE => obs_scope(rec)?,
        t::OBSERVE => observe(rec)?,
        t::LOOKUP => {
            let (l, key) = rec.pod_tail::<p::LookupRec>()?;
            let chain = l.flags & p::LK_CHAIN != 0;
            check(l.flags & !(p::LK_PREFIX | p::LK_CALLER | p::LK_CHAIN) == 0)?;
            // Round 12, LK_CHAIN: the chain key then 8 bytes of `after`; never with LK_PREFIX.
            check(
                !(chain && l.flags & p::LK_PREFIX != 0) && key.len() > if chain { 8 } else { 0 },
            )?;
            PlaneOut::Lookup {
                flags: l.flags,
                limit: l.limit,
                key,
            }
        }
        t::STORE => {
            let (st, tail) = rec.pod_tail::<p::StoreRec>()?;
            check(st.flags & !(p::LK_CALLER | p::LK_CHAIN) == 0)?;
            let (key, value) = split(tail, st.key_len)?;
            check(!key.is_empty())?;
            PlaneOut::Store {
                flags: st.flags,
                ttl_s: st.ttl_s,
                key,
                value,
            }
        }
        t::DELETE => {
            // IF gap: §8.6 gives DELETE no pod; it is read as U32Rec(flags) + key, the shape of SignalRec.
            let (d, key) = rec.pod_tail::<U32Rec>()?;
            check(d.value & !p::LK_CALLER == 0 && d._r == 0 && !key.is_empty())?;
            PlaneOut::Delete {
                flags: d.value,
                key,
            }
        }
        t::PUSH => {
            let (push, tail) = rec.pod_tail::<p::PushRec>()?;
            let recs = Records::new(tail);
            order(
                recs,
                &[
                    (g::H_METHOD, 1, 1),
                    (t::PUSH_URL, 1, 1),
                    (g::PAIR, 0, usize::MAX),
                    (t::BODY, 1, 1),
                ],
            )?;
            PlaneOut::Push {
                ttl_s: push.ttl_s,
                recs,
            }
        }
        t::WAKE_AT => PlaneOut::WakeAt(rec.pod::<p::WakeAt>()?.mono_ns),
        t::DETACH => {
            let (d, key) = rec.pod_tail::<p::DetachRec>()?;
            check(d._r == 0)?;
            PlaneOut::Detach {
                ttl_s: d.ttl_s,
                flags: d.flags,
                key,
            }
        }
        t::SIGNAL => {
            let (sg, key) = rec.pod_tail::<p::SignalRec>()?;
            check(sg.flags & !p::LK_CALLER == 0 && sg._r == 0)?;
            PlaneOut::Signal {
                flags: sg.flags,
                key,
            }
        }
        t::FINISH => empty(PlaneOut::Finish)?,
        t::COMMIT => {
            let (c, tail) = rec.pod_tail::<p::CommitRec>()?;
            let ops = Records::new(tail);
            commit_ops(ops)?;
            PlaneOut::Commit {
                check: c.check,
                ops,
            }
        }
        t::SIGHT => {
            let (_, tail) = rec.pod_tail::<p::SightRec>()?;
            let mut n = Nested::new(tail);
            let party = n.text(t::TR_PARTY, 1)?.ok_or(RecErr::Size)?;
            let catalog = n.one(t::TR_CATALOG)?.map(digest).transpose()?;
            let items = n.rest();
            for item in items {
                let item = item?;
                check(item.tag == t::TR_ITEM)?;
                digest(item.pair()?.1)?;
            }
            PlaneOut::Sight {
                party,
                catalog,
                items,
            }
        }
        t::TRUST => trust(rec)?,
        t::ENTITLE => {
            let (e, grant) = rec.pod_tail::<p::EntitleRec>()?;
            let grant = utf8(grant)?;
            check(!grant.is_empty())?;
            PlaneOut::Entitle {
                check: e.check,
                grant,
            }
        }
        t::JUDGE => {
            // The adapter only decodes; K8's session task checks class and flags (§8.6 round 16).
            let (j, dest) = rec.pod_tail::<p::JudgeRec>()?;
            PlaneOut::Judge {
                check: j.check,
                class: j.class,
                flags: j.flags,
                dest: utf8(dest)?,
            }
        }
        t::RENDEZVOUS => {
            let (r, text) = rec.pod_tail::<p::RendezvousRec>()?;
            check(r.flags == p::RV_ACCEPT || r.flags == p::RV_REMOTE)?;
            PlaneOut::Rendezvous {
                exchange: r.exchange,
                flags: r.flags,
                description: utf8(text)?,
            }
        }
        t::MINT => mint(rec)?,
        t::SIGN => {
            let (sg, payload) = rec.pod_tail::<p::SignRec>()?;
            check(sg.flags == p::SIGN_JWS_COMPACT || sg.flags == p::SIGN_JWS_DETACHED)?;
            PlaneOut::Sign {
                check: sg.check,
                flags: sg.flags,
                payload,
            }
        }
        t::CONNECT => {
            let (c, tail) = rec.pod_tail::<p::ConnectRec>()?;
            check((p::CONNECT_BEGIN..=p::CONNECT_REVOKE).contains(&c.op))?;
            let mut n = Nested::new(tail);
            let upstream = n.text(t::CN_UPSTREAM, 1)?.ok_or(RecErr::Size)?;
            let return_to = n.text(t::CN_RETURN_TO, 0)?;
            n.done()?;
            PlaneOut::Connect {
                check: c.check,
                op: c.op,
                upstream,
                return_to,
            }
        }
        t::CHANNEL => channel(rec)?,
        t::CH_READY => {
            let (u, tail) = rec.pod_tail::<U32Rec>()?;
            check(u._r == 0)?;
            PlaneOut::ChReady {
                exchange: u.value,
                tail,
            }
        }
        t::DEMUX => {
            let (dx, tail) = rec.pod_tail::<p::DemuxRec>()?;
            demux_rules(&dx, tail)?;
            PlaneOut::Demux {
                slot: dx.slot,
                flags: dx.flags,
                tail,
            }
        }
        t::EMIT => {
            let (e, bytes) = rec.pod_tail::<p::EmitRec>()?;
            check(e.carrier != 0)?;
            PlaneOut::Emit {
                carrier: e.carrier,
                bytes,
            }
        }
        t::WORK => {
            let (w, tail) = rec.pod_tail::<p::WorkRec>()?;
            let mut n = Nested::new(tail);
            let (target, reference) = match w.op {
                p::WORK_OPEN => (Some(n.bounded(t::WK_TARGET, 512)?), None),
                p::WORK_FIND | p::WORK_SETTLE => (None, Some(n.bounded(t::WK_REF, 128)?)),
                _ => return Err(RecErr::Size),
            };
            n.done()?;
            PlaneOut::Work {
                check: w.check,
                op: w.op,
                target,
                reference,
            }
        }
        tag => return Err(RecErr::Unknown(tag)),
    })
}

fn check(ok: bool) -> Result<(), RecErr> {
    if ok {
        Ok(())
    } else {
        Err(RecErr::Size)
    }
}

fn utf8(b: &[u8]) -> Result<&str, RecErr> {
    core::str::from_utf8(b).map_err(|_| RecErr::Utf8)
}

/// A usage class or audit action: `[a-z0-9_.:]{1,64}`.
fn class_text(b: &[u8]) -> Result<&str, RecErr> {
    let ok = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_.:".contains(c);
    check((1..=64).contains(&b.len()) && b.iter().all(ok))?;
    utf8(b)
}

/// A dialect word or ticket prefix: `[A-Za-z0-9._-]{1,max}`.
fn word_ok(w: &str, max: usize) -> bool {
    (1..=max).contains(&w.len())
        && w.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

fn fact(key: u32, v: FactRef<'_>) -> PlaneOut<'_> {
    if is_want(key) {
        PlaneOut::Want(key, v)
    } else {
        PlaneOut::Fact(key, v)
    }
}

fn digest(b: &[u8]) -> Result<[u8; 32], RecErr> {
    b.try_into().map_err(|_| RecErr::Size)
}

/// `key_len` bytes of key, then the value.
fn split(tail: &[u8], key_len: u32) -> Result<(&[u8], &[u8]), RecErr> {
    let n = usize::try_from(key_len).map_err(|_| RecErr::Size)?;
    tail.split_at_checked(n).ok_or(RecErr::Size)
}

/// The bytes one record takes: head, body, zero padding to 8 (§3).
fn size(len: usize) -> usize {
    (8 + len).next_multiple_of(8)
}

/// Records in a fixed order, each tag between `min` and `max` times.
fn order(recs: Records<'_>, grammar: &[(u16, usize, usize)]) -> Result<(), RecErr> {
    let mut at = 0;
    let mut n = 0;
    for rec in recs {
        let rec = rec?;
        while at < grammar.len() && (grammar[at].0 != rec.tag || n == grammar[at].2) {
            check(n >= grammar[at].1)?;
            at += 1;
            n = 0;
        }
        check(at < grammar.len())?;
        n += 1;
    }
    for (i, rule) in grammar.iter().enumerate().skip(at) {
        check(rule.1 <= if i == at { n } else { 0 })?;
    }
    Ok(())
}

/// A cursor over a record's nested tail, for the optional-then-repeated shapes of §8.6.
struct Nested<'o> {
    bytes: &'o [u8],
}

impl<'o> Nested<'o> {
    fn new(bytes: &'o [u8]) -> Self {
        Self { bytes }
    }

    /// The next record if it has `tag` (consumed), else None.
    fn one(&mut self, tag: u16) -> Result<Option<&'o [u8]>, RecErr> {
        match Records::new(self.bytes).next() {
            Some(rec) => {
                let rec = rec?;
                if rec.tag != tag {
                    return Ok(None);
                }
                self.bytes = &self.bytes[size(rec.body.len())..];
                Ok(Some(rec.body))
            }
            None => Ok(None),
        }
    }

    /// An optional text record of at least `min` bytes.
    fn text(&mut self, tag: u16, min: usize) -> Result<Option<&'o str>, RecErr> {
        self.one(tag)?
            .map(|b| {
                check(b.len() >= min)?;
                utf8(b)
            })
            .transpose()
    }

    /// A required text record of 1..=max bytes.
    fn bounded(&mut self, tag: u16, max: usize) -> Result<&'o str, RecErr> {
        let text = self.text(tag, 1)?.ok_or(RecErr::Size)?;
        check(text.len() <= max)?;
        Ok(text)
    }

    /// The records left.
    fn rest(&self) -> Records<'o> {
        Records::new(self.bytes)
    }

    fn done(&self) -> Result<(), RecErr> {
        check(self.bytes.is_empty())
    }
}

/// OBS_SCOPE: OBS_SCOPE_ID (ATTACH, CLOSE only), then OBS_REQUIRE* class texts.
fn obs_scope<'o>(rec: &Rec<'o>) -> Result<PlaneOut<'o>, RecErr> {
    let (o, tail) = rec.pod_tail::<p::ObsScopeRec>()?;
    check((p::OBS_CREATE..=p::OBS_CLOSE).contains(&o.op))?;
    let mut n = Nested::new(tail);
    let scope = n.one(t::OBS_SCOPE_ID)?.map(digest).transpose()?;
    check(scope.is_some() == (o.op != p::OBS_CREATE))?;
    let require = n.rest();
    for r in require {
        let r = r?;
        check(r.tag == t::OBS_REQUIRE)?;
        class_text(r.body)?;
    }
    Ok(PlaneOut::ObsScope {
        check: o.check,
        op: o.op,
        scope,
        require,
    })
}

/// OBSERVE: OBS_SCOPE_ID, OBS_EVENT, OBS_COMPONENT, OBS_REVISION?, OBS_COUNT*, OBS_EVIDENCE?, in that order.
fn observe<'o>(rec: &Rec<'o>) -> Result<PlaneOut<'o>, RecErr> {
    let (o, tail) = rec.pod_tail::<p::ObserveRec>()?;
    check((p::OBS_PROVISIONAL..=p::OBS_FINAL).contains(&o.state) && o._r == 0)?;
    let mut n = Nested::new(tail);
    let scope = digest(n.one(t::OBS_SCOPE_ID)?.ok_or(RecErr::Size)?)?;
    let mut field = |tag, max: usize| -> Result<Option<&'o [u8]>, RecErr> {
        let b = n.one(tag)?;
        check(b.is_none_or(|b| b.len() <= max))?;
        Ok(b)
    };
    let event = field(t::OBS_EVENT, 128)?.ok_or(RecErr::Size)?;
    let component = field(t::OBS_COMPONENT, 128)?.ok_or(RecErr::Size)?;
    let revision = field(t::OBS_REVISION, 128)?;
    check(revision.is_some() || o.revision_order == 0)?;
    let start = n.bytes;
    let mut len = 0;
    while let Some(count) = n.one(t::OBS_COUNT)? {
        let (u, class) = Rec {
            tag: t::OBS_COUNT,
            body: count,
        }
        .pod_tail::<p::UsageRec>()?;
        class_text(class)?;
        check(u.scale <= 9)?;
        len += size(count.len());
    }
    let counts = Records::new(&start[..len]);
    let evidence = n.one(t::OBS_EVIDENCE)?;
    check(evidence.is_none_or(|e| e.len() <= 256))?;
    n.done()?;
    Ok(PlaneOut::Observe {
        check: o.check,
        state: o.state,
        rated_subject: o.rated_subject,
        revision_order: o.revision_order,
        scope,
        event,
        component,
        revision,
        counts,
        evidence,
    })
}

/// TRUST: SERVES (TR_PARTY, TR_ITEM?), STATE (TR_PARTY), VERIFY (TR_PARTY, TR_PAYLOAD, TR_SIGNATURES).
fn trust<'o>(rec: &Rec<'o>) -> Result<PlaneOut<'o>, RecErr> {
    let (tr, tail) = rec.pod_tail::<p::TrustRec>()?;
    let mut n = Nested::new(tail);
    let party = n.text(t::TR_PARTY, 1)?.ok_or(RecErr::Size)?;
    let out = match tr.op {
        p::TRUST_VERIFY => PlaneOut::TrustVerify {
            check: tr.check,
            party,
            payload: n.one(t::TR_PAYLOAD)?.ok_or(RecErr::Size)?,
            signatures: n.one(t::TR_SIGNATURES)?.ok_or(RecErr::Size)?,
        },
        p::TRUST_SERVES | p::TRUST_STATE => {
            let item = match n.rest().next() {
                Some(r) if tr.op == p::TRUST_SERVES => {
                    let r = r?;
                    check(r.tag == t::TR_ITEM)?;
                    let (name, d) = r.pair()?;
                    n.bytes = &n.bytes[size(r.body.len())..];
                    Some((name, (!d.is_empty()).then(|| digest(d)).transpose()?))
                }
                _ => None,
            };
            PlaneOut::Trust {
                check: tr.check,
                op: tr.op,
                party,
                item,
            }
        }
        _ => return Err(RecErr::Size),
    };
    n.done()?;
    Ok(out)
}

/// MINT: MT_SCOPE?, MT_AUDIENCE?, MT_PREFIX?, MT_RECORD?, each checked (§8.6 round 15). The item carries
/// `MintRec.flags` (MINT_ONCE), MT_PREFIX and MT_RECORD, which §12.11 `TicketMint` takes.
fn mint<'o>(rec: &Rec<'o>) -> Result<PlaneOut<'o>, RecErr> {
    let (m, tail) = rec.pod_tail::<p::MintRec>()?;
    check(m.flags & !p::MINT_ONCE == 0)?;
    let mut n = Nested::new(tail);
    let scope = n.text(t::MT_SCOPE, 0)?;
    let audience = n.text(t::MT_AUDIENCE, 0)?;
    let prefix = n.text(t::MT_PREFIX, 1)?;
    check(prefix.is_none_or(|w| word_ok(w, 16) && !w.contains('.')))?;
    let record = n.one(t::MT_RECORD)?;
    check(record.is_none_or(|r| r.len() as u64 <= p::MAX_TICKET_RECORD))?;
    n.done()?;
    Ok(PlaneOut::Mint {
        check: m.check,
        flags: m.flags,
        ttl_s: m.ttl_s,
        scope,
        audience,
        prefix,
        record,
    })
}

/// CHANNEL: ChanRec, then nested TEXT key (1..=128 bytes) and, for CARRIER_HTTP, the head H_METHOD, H_PATH, PAIR*.
///
/// IF reading: §8.6 says "ChanRec + key, then head records"; the key is the first nested record so the head can
/// follow it in the same body.
fn channel<'o>(rec: &Rec<'o>) -> Result<PlaneOut<'o>, RecErr> {
    let (c, tail) = rec.pod_tail::<p::ChanRec>()?;
    check(c.carrier == p::CARRIER_STDIO || c.carrier == p::CARRIER_HTTP)?;
    check(c.flags & !(p::CH_PER_CALLER | p::CH_SERIAL) == 0 && c.framing <= p::CH_FRAME_SSE)?;
    let mut n = Nested::new(tail);
    let key = n.bounded(g::TEXT, 128)?;
    let head = n.rest();
    if c.carrier == p::CARRIER_HTTP {
        order(
            head,
            &[
                (g::H_METHOD, 1, 1),
                (g::H_PATH, 1, 1),
                (g::PAIR, 0, usize::MAX),
            ],
        )?;
    } else {
        n.done()?;
    }
    Ok(PlaneOut::Channel {
        exchange: c.exchange,
        carrier: c.carrier,
        flags: c.flags,
        framing: c.framing,
        key,
        head,
    })
}

/// The combinations §8.6 DemuxRec forbids (round 18).
fn demux_rules(dx: &p::DemuxRec, tail: &[u8]) -> Result<(), RecErr> {
    let has = |bit: u32| dx.flags & bit != 0;
    check(dx.flags & !DX_BITS == 0 && dx._r == 0)?;
    check(!(has(p::DX_OUTSTANDING) && has(p::DX_BROADCAST)))?;
    if dx.slot != 0 {
        return check(!has(p::DX_OUTSTANDING) && !has(p::DX_BROADCAST) && tail.is_empty());
    }
    check(!has(p::DX_FINAL))?;
    if has(p::DX_BROADCAST) {
        check((1..=128).contains(&tail.len()))
    } else if has(p::DX_OUTSTANDING) {
        check(tail.len() <= 4096)
    } else {
        check(tail.is_empty())
    }
}

/// COMMIT: REC_PRED* then REC_PUT*/REC_DEL*, each well formed (§12.5). The op count is core's (R_INVALID).
fn commit_ops(ops: Records<'_>) -> Result<(), RecErr> {
    let mut mutating = false;
    for op in ops {
        let op = op?;
        match op.tag {
            g::REC_PRED => {
                check(!mutating)?;
                let (pr, tail) = op.pod_tail::<RecPredRec>()?;
                let kind = pr.flags & commit::PRED_MASK;
                check(pr.flags & !(commit::PRED_MASK | commit::REC_CALLER) == 0)?;
                check((commit::PRED_ABSENT..=commit::PRED_EQUALS).contains(&kind))?;
                let (key, value) = split(tail, pr.key_len)?;
                check(!key.is_empty() && (kind == commit::PRED_EQUALS || value.is_empty()))?;
            }
            g::REC_PUT => {
                let (put, tail) = op.pod_tail::<RecPutRec>()?;
                check(
                    put.flags & !commit::REC_CALLER == 0 && !split(tail, put.key_len)?.0.is_empty(),
                )?;
                mutating = true;
            }
            g::REC_DEL => {
                let (del, key) = op.pod_tail::<RecDelRec>()?;
                check(del.flags & !commit::REC_CALLER == 0 && del._r == 0 && !key.is_empty())?;
                mutating = true;
            }
            tag => return Err(RecErr::Unknown(tag)),
        }
    }
    Ok(())
}

/// A REFUSED or FAILED answer as a `PortError`: the text scrubbed whole, then cut (I14); the facts are the
/// FAILED answer's own (a REFUSED answer carries none).
pub fn port_error(
    scrub: &Scrub,
    failed_answer: bool,
    code: u32,
    text: &str,
    facts: (Option<u64>, Option<u64>),
    error: Option<PluginCode>,
) -> PortError {
    let text: Box<str> = fail_text(scrub, text).as_ref().into();
    if failed_answer {
        PortError::Failed {
            code,
            text,
            retry_after_s: facts.0,
            backend_status: facts.1,
            error,
        }
    } else {
        PortError::Refused { code, text, error }
    }
}

/// The clock reading of a session call. The plane port's session methods carry none today, so none is
/// handed in and a plane that needs the time asks the host once; when the port gains the reading (one per
/// operation, made by the kernel), it replaces this constant at each call below and nothing else changes.
const NOW: Mono = Mono::NONE;

/// The plane port over one instance's proxy.
pub struct PlaneAdapter<N: Needs> {
    proxy: Proxy,
    needs: Arc<N>,
    describe: PlaneDescribe,
    /// The image's `ErrorBook` (§11.2), for the ERROR number of a REFUSED or FAILED answer.
    errors: &'static ErrorBook,
    /// The undeclared-number WARN latch (once per instance, Relaxed, no RMW).
    latch: AtomicBool,
}

impl<N: Needs> PlaneAdapter<N> {
    /// Built by `Registry::open_plane` after INSTANCE: `describe` is the image's `decode_describe`, `errors` its book.
    pub fn new(
        proxy: Proxy,
        needs: Arc<N>,
        describe: PlaneDescribe,
        errors: &'static ErrorBook,
    ) -> Self {
        Self {
            proxy,
            needs,
            describe,
            errors,
            latch: AtomicBool::new(false),
        }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }

    fn live(&self) -> Result<usize, PortError> {
        let inst = self.proxy.instance();
        if inst.is_live() {
            Ok(inst.max_out)
        } else {
            Err(PortError::Call(CallError::Quarantined))
        }
    }

    /// The call's `Caller`, borrowed from the instance (no refcount RMW). `chain` is 0: `Driver::new` mints it.
    fn caller<'a>(&'a self, cx: &CallCx) -> Caller<'a> {
        let inst = self.proxy.instance();
        Caller {
            plugin: &inst.identity,
            kind: inst.kind,
            name: &inst.name,
            instance: inst.id,
            slot: inst.slot,
            chain: 0,
            deadline: cx.deadline,
            stack: cx.stack,
            out_of_process: false,
            limits: inst.limits,
        }
    }

    /// REFUSED and FAILED are `PortError`s; any status but OK is a contract break.
    fn failure(&self, answer: &Answer<'_>) -> Result<(), PortError> {
        let status = answer.status;
        if status == Status::OK {
            return Ok(());
        }
        let refused = status == Status::REFUSED;
        if !refused && status != Status::FAILED {
            return Err(PortError::Call(CallError::Fault(FaultReason::BadStatus(
                status.0,
            ))));
        }
        let Some((code, text)) = answer.fail() else {
            return Err(PortError::Call(CallError::Fault(FaultReason::MissingFail)));
        };
        let error = self.errors.resolve(answer.fail_error(), &self.latch);
        let facts = if refused {
            (None, None)
        } else {
            (
                answer.fail_fact(FACT_RETRY_AFTER_S),
                answer.fail_fact(FACT_BACKEND_STATUS),
            )
        };
        Err(port_error(
            &self.proxy.instance().scrub,
            !refused,
            code,
            text,
            facts,
            error,
        ))
    }

    fn declaration(&self) -> Result<Declaration<'_>, PortError> {
        Declaration::new(
            self.proxy.instance().facts,
            &self.describe.usage_classes,
            &self.describe.attempt_classes,
        )
        .map_err(|r| PortError::Call(CallError::Fault(fault(r))))
    }

    /// An answer of `call` into the sink, whole or not at all.
    fn finish(
        &self,
        call: Call,
        answer: &Answer<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
        selected: Option<SelectedResource<'_>>,
        exchange: Option<u32>,
    ) -> Result<(), PortError> {
        self.failure(answer)?;
        let demux = self.proxy.instance().methods & p::M_DEMUX != 0;
        decode_answer(
            call,
            demux,
            self.declaration()?,
            selected,
            exchange,
            answer.records(),
            sink,
        )
        .map_err(|r| PortError::Call(CallError::Fault(r)))
    }
}

fn plane_req<'a>(r: &'a PlaneIn<'a>) -> PlaneReq<'a> {
    PlaneReq {
        route: r.route,
        flags: r.flags,
        auth: r.auth,
        _r: 0,
        method: Str::new(r.method),
        path: Str::new(r.path),
        query: Str::new(r.query),
        headers: Slice::new(r.headers),
        identity: Bytes::new(r.identity),
        request_id: r.request_id,
        carrier: r.carrier,
        work: Str::new(r.work),
        ticket_record: Bytes::new(r.ticket_record),
    }
}

fn target<'a>(x: &'a TargetIn<'a>) -> Target<'a> {
    Target {
        attempt: x.attempt,
        flags: x.flags,
        dialect: Str::new(x.dialect),
        model: Str::new(x.model),
        base_path: Str::new(x.base_path),
        upstream: Str::new(x.upstream),
        provider: Str::new(x.provider),
        params: Slice::new(x.params),
        admission: Bytes::new(x.admission),
    }
}

/// An opener answered OK without a session token.
fn no_token() -> PortError {
    PortError::Call(CallError::Fault(FaultReason::MissingToken))
}

/// Copies core's admin argument (already §8.8 records) into the request buffer, record by record.
fn copy_records(w: &mut impl Writer, arg: &[u8]) -> Result<(), PortError> {
    for rec in Records::new(arg) {
        let rec = rec.map_err(|_| PortError::Refused {
            code: R_INVALID,
            text: "core's plane admin argument is not records".into(),
            error: None,
        })?;
        w.put(rec.tag, rec.body).map_err(|_| PortError::Failed {
            code: failed::F_LIMIT,
            text: "the plane admin argument does not fit the request buffer".into(),
            retry_after_s: None,
            backend_status: None,
            error: None,
        })?;
    }
    Ok(())
}

impl<N: Needs> PlanePort for PlaneAdapter<N> {
    fn routes(&self) -> &[RouteInfo] {
        &self.describe.routes
    }

    fn dialects(&self) -> &[Box<str>] {
        &self.describe.dialects
    }

    fn usage_classes(&self) -> &[UsageClass] {
        &self.describe.usage_classes
    }

    fn attempt_classes(&self) -> &[Box<str>] {
        &self.describe.attempt_classes
    }

    fn usage_shared(&self) -> (Arc<[UsageClass]>, Arc<[Box<str>]>) {
        (
            Arc::clone(&self.describe.usage_classes),
            Arc::clone(&self.describe.attempt_classes),
        )
    }

    fn facts(&self) -> u64 {
        self.proxy.instance().facts
    }

    fn has_demux(&self) -> bool {
        self.proxy.instance().methods & p::M_DEMUX != 0
    }

    fn tick_s(&self) -> Option<u64> {
        self.describe.tick_s
    }

    fn admin_openapi(&self) -> Option<&str> {
        self.describe.admin_openapi.as_deref()
    }

    fn charge(&self, reason: FaultReason) {
        let _ = self.proxy.instance().charge(reason);
    }

    fn resource_facts(
        &self,
        mode: u32,
        req: &PlaneIn<'_>,
        body: &[u8],
        byte_limit: usize,
    ) -> Result<Vec<u8>, PortError> {
        use busbar_plugin_abi::resource_admission as resources;
        let kinds = self.resource_kinds(req.route);
        if self.facts() & p::FB_RESOURCE_ADMISSION == 0
            || kinds.is_empty()
            || req.auth != 0
            || !req.identity.is_empty()
            || !req.ticket_record.is_empty()
            || req.carrier != 0
            || !req.work.is_empty()
            || !matches!(mode, p::RESOURCE_INVENTORY | p::RESOURCE_SELECT)
        {
            return Err(PortError::Refused {
                code: R_INVALID,
                text: "resource selection is unavailable".into(),
                error: None,
            });
        }
        let max_out = self.live()?.min(byte_limit);
        let max_out = if mode == p::RESOURCE_SELECT {
            max_out.min(resources::MAX_SELECTION_BYTES)
        } else {
            max_out
        };
        let req = plane_req(req);
        sync_out(max_out, |out| {
            let answer = self
                .proxy
                .select_resources(out, NOW, mode, &req, body)
                .map_err(PortError::Call)?;
            self.failure(&answer)?;
            let bytes = answer.records().rest();
            let valid = if mode == p::RESOURCE_SELECT {
                resources::decode_selection(bytes).map(|scopes| {
                    scopes
                        .iter()
                        .all(|s| kinds.iter().any(|k| k.as_ref() == s.kind))
                })
            } else {
                resources::decode_inventory(bytes, byte_limit).map(|entries| {
                    entries
                        .iter()
                        .all(|r| kinds.iter().any(|k| k.as_ref() == r.scope.kind))
                })
            };
            if valid != Ok(true) {
                return Err(PortError::Call(CallError::Fault(FaultReason::BadRecords(
                    RecErr::Size,
                ))));
            }
            Ok(bytes.to_vec())
        })
    }

    fn request(
        &self,
        req: &PlaneIn<'_>,
        body: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        let max_out = self.live()?;
        let req = plane_req(req);
        sync_out(max_out, |out| {
            let (session, answer) = self
                .proxy
                .request(out, NOW, &req, body)
                .map_err(PortError::Call)?;
            self.finish(Call::Request, &answer, sink, None, None)?;
            session.ok_or_else(no_token)
        })
    }

    fn upstream(
        &self,
        s: &mut PlaneSession,
        tgt: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let max_out = self.live()?;
        let view = target(tgt);
        let enabled =
            self.proxy.instance().facts & (p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES) != 0;
        let selected = if enabled {
            attempt_wire::selected_from_admission(tgt.admission)
                .map_err(|r| PortError::Call(CallError::Fault(fault(r))))?
        } else {
            None
        };
        if (enabled && selected.is_none())
            || selected.is_some_and(|selected| selected.attempt != tgt.attempt)
        {
            return Err(PortError::Call(CallError::Fault(misplaced(
                t::SELECTED_RESOURCE,
            ))));
        }
        sync_out(max_out, |out| {
            let answer = s.upstream(out, NOW, &view).map_err(PortError::Call)?;
            self.finish(Call::Upstream, &answer, sink, selected, None)
        })
    }

    fn channel(
        &self,
        s: &mut PlaneSession,
        tgt: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let max_out = self.live()?;
        if self.facts() & p::FB_CHANNEL_OPEN == 0
            || self.proxy.instance().methods & (p::M_CHANNEL | p::M_DEMUX)
                != (p::M_CHANNEL | p::M_DEMUX)
        {
            return Err(PortError::Refused {
                code: busbar_plugin_abi::fail::refused::R_UNSUPPORTED,
                text: "selected channel preparation is unavailable".into(),
                error: None,
            });
        }
        if !Arc::ptr_eq(self.proxy.instance(), s.instance()) {
            return Err(PortError::Call(CallError::Fault(FaultReason::BadInstance)));
        }
        let view = target(tgt);
        sync_out(max_out, |out| {
            let answer = s.channel(out, NOW, &view).map_err(PortError::Call)?;
            self.finish(Call::Channel, &answer, sink, None, None)
        })
    }

    fn piece(
        &self,
        s: &mut PlaneSession,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let max_out = self.live()?;
        sync_out(max_out, |out| {
            let answer = s
                .piece(out, NOW, from, exchange, flags, bytes)
                .map_err(PortError::Call)?;
            self.finish(Call::Piece(from), &answer, sink, None, Some(exchange))
        })
    }

    fn piece_fixed(
        &self,
        s: &mut PlaneSession,
        from: u32,
        exchange: u32,
        flags: u32,
        bytes: &[u8],
        out: &mut [u8],
    ) -> Result<usize, PortError> {
        self.live()?;
        if !Arc::ptr_eq(self.proxy.instance(), s.instance()) {
            return Err(PortError::Call(CallError::Fault(FaultReason::BadInstance)));
        }
        let (answer, len) = s
            .piece_fixed(out, NOW, from, exchange, flags, bytes)
            .map_err(PortError::Call)?;
        // Same whole-answer validation and failure translation as pooled piece. No effect escapes
        // until the caller classifies the validated fixed backing and admits its complete answer.
        self.finish(
            Call::Piece(from),
            &answer,
            &mut |_| {},
            None,
            Some(exchange),
        )?;
        Ok(len)
    }

    fn decode_fixed_piece(
        &self,
        from: u32,
        exchange: u32,
        bytes: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let max_out = self.live()?;
        if bytes.len() > max_out || Records::new(bytes).any(|r| r.is_ok_and(|r| r.tag == g::TOKEN))
        {
            return Err(PortError::Call(CallError::Fault(FaultReason::BadRecords(
                RecErr::Reserved,
            ))));
        }
        let answer = Answer::parse(Status::OK, bytes)
            .map_err(|reason| PortError::Call(CallError::Fault(reason)))?;
        self.finish(Call::Piece(from), &answer, sink, None, Some(exchange))
    }

    fn rewrite(
        &self,
        s: &mut PlaneSession,
        conversation: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let max_out = self.live()?;
        sync_out(max_out, |out| {
            let answer = s.rewrite(out, NOW, conversation).map_err(PortError::Call)?;
            self.finish(Call::Rewrite, &answer, sink, None, None)
        })
    }

    fn end(&self, s: PlaneSession, sink: &mut dyn FnMut(PlaneOut<'_>)) -> Result<(), PortError> {
        let max_out = self.live()?;
        sync_out(max_out, |out| {
            let answer = s.end(out, NOW).map_err(PortError::Call)?;
            self.finish(Call::End, &answer, sink, None, None)
        })
    }

    fn render(
        &self,
        req: &PlaneIn<'_>,
        what: u32,
        arg: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let max_out = self.live()?;
        let req = plane_req(req);
        sync_out(max_out, |out| {
            let answer = self
                .proxy
                .render(out, NOW, &req, what, arg)
                .map_err(PortError::Call)?;
            self.finish(Call::Render, &answer, sink, None, None)
        })
    }

    fn probe(
        &self,
        tgt: &TargetIn<'_>,
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<PlaneSession, PortError> {
        let max_out = self.live()?;
        let view = target(tgt);
        sync_out(max_out, |out| {
            let (session, answer) = self.proxy.probe(out, NOW, &view).map_err(PortError::Call)?;
            self.finish(Call::Probe, &answer, sink, None, None)?;
            session.ok_or_else(no_token)
        })
    }

    fn demux(
        &self,
        key: &str,
        message: &[u8],
        sink: &mut dyn FnMut(PlaneOut<'_>),
    ) -> Result<(), PortError> {
        let max_out = self.live()?;
        sync_out(max_out, |out| {
            let answer = self
                .proxy
                .demux(out, NOW, key, message)
                .map_err(PortError::Call)?;
            self.finish(Call::Demux, &answer, sink, None, None)
        })
    }

    fn admin<'a>(
        &'a self,
        cx: CallCx,
        op: u32,
        arg: &'a [u8],
    ) -> BoxFut<'a, Result<Vec<u8>, PortError>> {
        Box::pin(async move {
            let max_out = self.live()?;
            let mut req = Pool::global().acquire(max_out);
            copy_records(&mut req, arg)?;
            let mut drv = Driver::new(&*self.needs, self.caller(&cx));
            let owned = self
                .proxy
                .admin(&mut drv, crate::call::at(&cx), req, op)
                .await
                .map_err(PortError::Call)?;
            let answer = owned.answer();
            self.failure(&answer)?;
            let recs = answer.records();
            admin_answer(op, self.declaration()?, recs)
                .map_err(|r| PortError::Call(CallError::Fault(r)))?;
            let mut copy = Reply::new();
            for rec in recs {
                let rec = rec.map_err(|e| PortError::Call(CallError::Fault(fault(e))))?;
                copy.put(rec.tag, rec.body).map_err(|_| no_room())?;
            }
            Ok::<Vec<u8>, PortError>(copy.as_bytes().to_vec())
        })
    }
}

fn no_room() -> PortError {
    PortError::Failed {
        code: failed::F_LIMIT,
        text: "the plane admin answer passed the reply cap".into(),
        retry_after_s: None,
        backend_status: None,
        error: None,
    }
}

/// ADMIN_TICK answers PUSH* and EMIT* only; ADMIN_CARRIER_END answers nothing; EMIT and PUSH are BadRecords in any
/// other admin answer (§8.6). CATALOG and HYDRATE answers go to core as they are.
fn admin_answer(
    op: u32,
    declaration: Declaration<'_>,
    recs: Records<'_>,
) -> Result<(), FaultReason> {
    if op == p::ADMIN_TICK {
        return walk(
            Call::Tick,
            false,
            declaration,
            None,
            recs,
            &mut |_: PlaneOut<'_>| {},
        );
    }
    for rec in recs {
        let rec = rec.map_err(fault)?;
        let any = op == p::ADMIN_CARRIER_END && rec.tag != g::METRIC;
        if any || rec.tag == t::EMIT || rec.tag == t::PUSH {
            return Err(misplaced(rec.tag));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::records::{Reply, Writer};

    #[test]
    fn resource_echo_is_unique_upstream_only_and_checked_before_delivery() {
        use busbar_plugin_abi::resource_admission::{write_echo, DescriptorEcho};
        let describe = PlaneDescribe::default();
        let declaration =
            Declaration::new(0, &describe.usage_classes, &describe.attempt_classes).unwrap();
        let mut out = Reply::new();
        let echo = DescriptorEcho {
            invocation: 1,
            generation: 7,
            route: 3,
            descriptor: 9,
            instance: "plane/test",
        };
        write_echo(&mut out, echo).unwrap();
        out.put(g::H_METHOD, b"POST").unwrap();
        out.put(g::H_PATH, b"/generate").unwrap();
        out.put(t::UP_BODY, b"{}").unwrap();
        let mut delivered = false;
        decode_answer(
            Call::Upstream,
            false,
            declaration,
            None,
            None,
            Records::new(out.as_bytes()),
            &mut |item| {
                if let PlaneOut::ResourceEcho(got) = item {
                    assert_eq!(got, echo);
                    delivered = true;
                }
            },
        )
        .unwrap();
        assert!(delivered);
        assert!(decode_answer(
            Call::Request,
            false,
            declaration,
            None,
            None,
            Records::new(out.as_bytes()),
            &mut |_| panic!("partial delivery")
        )
        .is_err());
        write_echo(&mut out, echo).unwrap();
        assert!(decode_answer(
            Call::Upstream,
            false,
            declaration,
            None,
            None,
            Records::new(out.as_bytes()),
            &mut |_| panic!("partial delivery")
        )
        .is_err());
    }

    fn route(r: &mut Reply, route: u32, methods: u32, flags: u32, auth: u32, pattern: &str) {
        let rec = p::RouteRec {
            route,
            methods,
            flags,
            auth,
        };
        r.put_pod_tail(t::D_ROUTE, &rec, pattern.as_bytes())
            .unwrap();
    }

    fn cred(r: &mut Reply, route: u32, name: &str) {
        let rec = p::RouteHeaderRec { route, _r: 0 };
        r.put_pod_tail(t::D_ROUTE_CRED_HEADER, &rec, name.as_bytes())
            .unwrap();
    }

    fn describe(r: &Reply, methods: u64, facts: u64) -> Result<PlaneDescribe, DescribeInvalid> {
        decode_describe(Records::new(r.as_bytes()), methods, facts)
    }

    fn label(o: &PlaneOut<'_>) -> String {
        match o {
            PlaneOut::Respond { status } => format!("respond {status}"),
            PlaneOut::Header(n, v) => format!("header {n}={}", String::from_utf8_lossy(v)),
            PlaneOut::Body(b) => format!("body {}", String::from_utf8_lossy(b)),
            PlaneOut::Trailers => "trailers".into(),
            PlaneOut::End => "end".into(),
            PlaneOut::Forward { stream } => format!("forward {stream}"),
            PlaneOut::Want(k, _) => format!("want {k:#x}"),
            PlaneOut::Fact(k, _) => format!("fact {k:#x}"),
            PlaneOut::Expect { class, amount, .. } => format!("expect {class} {amount}"),
            PlaneOut::Work {
                op,
                target,
                reference,
                ..
            } => format!("work {op} {target:?} {reference:?}"),
            PlaneOut::Lookup { flags, key, .. } => format!("lookup {flags} {}", key.len()),
            PlaneOut::Demux { slot, flags, tail } => format!("demux {slot} {flags} {}", tail.len()),
            PlaneOut::Emit { carrier, bytes } => {
                format!("emit {carrier} {}", String::from_utf8_lossy(bytes))
            }
            PlaneOut::Channel { key, carrier, .. } => format!("channel {carrier} {key}"),
            PlaneOut::Attempt { verdict, .. } => format!("attempt {verdict}"),
            PlaneOut::UpMethod(m) => format!("method {m}"),
            _ => "other".into(),
        }
    }

    /// Every item the sink saw, as labels.
    fn run(call: Call, r: &Reply) -> Result<Vec<String>, FaultReason> {
        let mut seen = Vec::new();
        decode_answer(
            call,
            true,
            Declaration::legacy(),
            None,
            None,
            Records::new(r.as_bytes()),
            &mut |o: PlaneOut<'_>| seen.push(label(&o)),
        )?;
        Ok(seen)
    }

    fn respond(r: &mut Reply, status: u32) {
        r.put_pod(t::RESPOND, &p::Respond { status, flags: 0 })
            .unwrap();
    }

    fn forward(r: &mut Reply) {
        r.put_pod(t::FORWARD, &p::Forward { flags: 0, _r: 0 })
            .unwrap();
    }

    fn work(r: &mut Reply, op: u32, inner_tag: u16, text: &str) {
        let mut inner = Reply::new();
        inner.put_text(inner_tag, text).unwrap();
        r.put_pod_tail(t::WORK, &p::WorkRec { check: 1, op }, inner.as_bytes())
            .unwrap();
    }

    fn demux(r: &mut Reply, slot: u64, flags: u32, tail: &[u8]) {
        let rec = p::DemuxRec { slot, flags, _r: 0 };
        r.put_pod_tail(t::DEMUX, &rec, tail).unwrap();
    }

    fn emit(r: &mut Reply) {
        r.put_pod_tail(t::EMIT, &p::EmitRec { carrier: 7 }, b"line")
            .unwrap();
    }

    fn attempt(r: &mut Reply, verdict: u32) {
        let rec = p::AttemptRec {
            verdict,
            class: p::FC_SERVER,
            retry_after_s: 0,
        };
        r.put_pod_tail(t::ATTEMPT, &rec, b"").unwrap();
    }

    fn bad(tag: u16) -> FaultReason {
        FaultReason::BadRecords(RecErr::Unknown(tag))
    }

    #[test]
    fn a_describe_decodes_routes_dialects_classes_and_the_tick() {
        let mut r = Reply::new();
        cred(&mut r, 1, "x-sig");
        route(&mut r, 1, POST, 0, p::AUTH_PRINCIPAL, "/v1/chat");
        route(
            &mut r,
            2,
            GET,
            p::ROUTE_RECOVERY,
            p::AUTH_PRINCIPAL,
            "/poll/{*rest}",
        );
        r.put_text(t::D_DIALECT, "openai").unwrap();
        let class = p::UsageClassRec {
            unit: p::UNIT_TOKENS,
            _r: 0,
            expected_units: f64::NAN,
        };
        r.put_pod_tail(t::D_USAGE_CLASS, &class, b"tokens.in")
            .unwrap();
        r.put_pod(t::D_TICK_S, &U64Rec { value: 30 }).unwrap();
        r.put_metric(1, 1, 1.0, &[]).unwrap();
        let d = describe(&r, p::ALL, 0).unwrap();
        assert_eq!(d.routes.len(), 2);
        assert_eq!(d.routes[0].cred_header.as_deref(), Some("x-sig"));
        assert_eq!(d.routes[1].flags, p::ROUTE_RECOVERY);
        assert_eq!(&*d.dialects[0], "openai");
        assert_eq!(d.usage_classes[0].expected_units, None);
        assert_eq!(d.tick_s, Some(30));
        assert_eq!(d.admin_openapi, None);
    }

    #[test]
    fn admin_routes_need_the_openapi_fragment_and_operator_auth() {
        let mut r = Reply::new();
        route(&mut r, 1, GET, p::ROUTE_ADMIN, p::AUTH_OPERATOR, "/health");
        assert_eq!(
            describe(&r, p::ALL, 0),
            Err(DescribeInvalid("describe.admin_openapi"))
        );
        r.put_text(t::D_ADMIN_OPENAPI, "{\"/health\":{}}").unwrap();
        assert_eq!(
            describe(&r, p::ALL, 0).unwrap().admin_openapi.as_deref(),
            Some("{\"/health\":{}}")
        );
        let mut r = Reply::new();
        route(&mut r, 1, GET, p::ROUTE_ADMIN, p::AUTH_PRINCIPAL, "/health");
        assert_eq!(
            describe(&r, p::ALL, 0),
            Err(DescribeInvalid("describe.route_admin"))
        );
        let mut r = Reply::new();
        route(&mut r, 1, GET, 0, p::AUTH_PUBLIC, "/x");
        r.put_text(t::D_ADMIN_OPENAPI, "{}").unwrap();
        assert_eq!(
            describe(&r, p::ALL, 0),
            Err(DescribeInvalid("describe.admin_openapi"))
        );
    }

    #[test]
    fn catalog_needs_render_probes_need_probe_and_auth_is_never_zero() {
        let mut r = Reply::new();
        route(
            &mut r,
            1,
            GET,
            p::ROUTE_CATALOG,
            p::AUTH_PUBLIC,
            "/v1/models",
        );
        let no_render = p::ALL & !p::M_RENDER;
        assert_eq!(
            describe(&r, no_render, 0),
            Err(DescribeInvalid("describe.route_catalog"))
        );
        assert!(describe(&r, p::ALL, 0).is_ok());
        let no_probe = p::ALL & !p::M_PROBE;
        assert_eq!(
            describe(&r, no_probe, p::FB_PROBES),
            Err(DescribeInvalid("describe.probes"))
        );
        let mut r = Reply::new();
        route(&mut r, 1, GET, 0, 0, "/x");
        assert_eq!(
            describe(&r, p::ALL, 0),
            Err(DescribeInvalid("describe.route.auth"))
        );
    }

    #[test]
    fn a_cred_header_needs_a_declared_principal_route_and_a_lowercase_name() {
        let mut r = Reply::new();
        route(&mut r, 1, POST, 0, p::AUTH_PUBLIC, "/hook");
        cred(&mut r, 1, "x-sig");
        let refused = Err(DescribeInvalid("describe.route_cred_header"));
        assert_eq!(describe(&r, p::ALL, 0), refused);
        let mut r = Reply::new();
        cred(&mut r, 9, "x-sig");
        assert_eq!(describe(&r, p::ALL, 0), refused);
        let mut r = Reply::new();
        route(&mut r, 1, POST, 0, p::AUTH_OPTIONAL, "/hook");
        cred(&mut r, 1, "X-Sig");
        assert_eq!(describe(&r, p::ALL, 0), refused);
    }

    #[test]
    fn a_local_answer_reaches_the_sink_in_order() {
        let mut r = Reply::new();
        respond(&mut r, 200);
        r.put_pair(g::PAIR, "content-type", b"application/grpc")
            .unwrap();
        r.put(t::BODY, b"hi").unwrap();
        r.put_metric(1, 1, 1.0, &[]).unwrap();
        r.put(t::TRAILERS, b"").unwrap();
        r.put_pair(g::PAIR, "grpc-status", b"0").unwrap();
        r.put(t::END, b"").unwrap();
        let seen = run(Call::Request, &r).unwrap();
        assert_eq!(
            seen,
            [
                "respond 200",
                "header content-type=application/grpc",
                "body hi",
                "trailers",
                "header grpc-status=0",
                "end"
            ]
        );
    }

    #[test]
    fn render_takes_trailers_before_end_and_nothing_else() {
        let mut r = Reply::new();
        respond(&mut r, 200);
        r.put(t::TRAILERS, b"").unwrap();
        r.put_pair(g::PAIR, "grpc-status", b"7").unwrap();
        r.put(t::END, b"").unwrap();
        assert_eq!(run(Call::Render, &r).unwrap().len(), 4);
        let mut r = Reply::new();
        respond(&mut r, 403);
        r.put(t::BODY, b"a").unwrap();
        r.put(t::BODY, b"b").unwrap();
        r.put(t::END, b"").unwrap();
        assert_eq!(run(Call::Render, &r), Err(bad(t::BODY)));
        let mut r = Reply::new();
        respond(&mut r, 403);
        assert_eq!(run(Call::Render, &r), Err(bad(t::END)));
    }

    #[test]
    fn trailers_are_once_and_only_before_end() {
        let mut r = Reply::new();
        respond(&mut r, 200);
        r.put(t::TRAILERS, b"").unwrap();
        r.put(t::BODY, b"late").unwrap();
        r.put(t::END, b"").unwrap();
        assert_eq!(run(Call::Request, &r), Err(bad(t::BODY)));
        let mut r = Reply::new();
        respond(&mut r, 200);
        r.put(t::TRAILERS, b"").unwrap();
        assert_eq!(run(Call::Request, &r), Err(bad(t::TRAILERS)));
    }

    #[test]
    fn a_fault_late_in_an_answer_reaches_no_sink() {
        let mut r = Reply::new();
        respond(&mut r, 200);
        r.put(t::BODY, b"hi").unwrap();
        r.put(0x01FF, b"").unwrap();
        let mut calls = 0;
        let got = decode_answer(
            Call::Request,
            true,
            Declaration::legacy(),
            None,
            None,
            Records::new(r.as_bytes()),
            &mut |_: PlaneOut<'_>| calls += 1,
        );
        assert_eq!(got, Err(FaultReason::UnknownTag(0x01FF)));
        assert_eq!(calls, 0);
    }

    #[test]
    fn forward_comes_with_wants_and_never_beside_an_intent_or_from_the_client() {
        let mut r = Reply::new();
        forward(&mut r);
        r.put_fact(p::W_MODEL, 1).unwrap();
        r.put_pod_tail(
            t::EXPECT,
            &p::UsageRec {
                amount: 10,
                scale: 0,
                source: p::SRC_ESTIMATED,
            },
            b"tokens",
        )
        .unwrap();
        assert_eq!(
            run(Call::Request, &r).unwrap(),
            ["forward false", "want 0x100", "expect tokens 10"]
        );
        assert!(run(Call::Piece(p::FROM_CORE), &r).is_ok());
        assert_eq!(run(Call::Piece(p::FROM_CLIENT), &r), Err(bad(t::FORWARD)));
        let mut r2 = Reply::new();
        forward(&mut r2);
        r2.put_pod_tail(t::LOOKUP, &p::LookupRec { flags: 0, limit: 1 }, b"k")
            .unwrap();
        assert_eq!(run(Call::Request, &r2), Err(bad(t::FORWARD)));
        let mut r3 = Reply::new();
        r3.put_fact(p::W_MODEL, 1).unwrap();
        assert_eq!(run(Call::Request, &r3), Err(bad(g::FACT)));
    }

    #[test]
    fn work_and_judge_answer_in_request_and_piece_only() {
        let mut r = Reply::new();
        work(&mut r, p::WORK_OPEN, t::WK_TARGET, "/poll?id=1");
        assert_eq!(
            run(Call::Request, &r).unwrap(),
            ["work 1 Some(\"/poll?id=1\") None"]
        );
        assert_eq!(run(Call::End, &r), Err(bad(t::WORK)));
        let mut r = Reply::new();
        work(&mut r, p::WORK_FIND, t::WK_TARGET, "/poll");
        assert_eq!(
            run(Call::Request, &r),
            Err(FaultReason::BadRecords(RecErr::Size))
        );
        let mut r = Reply::new();
        let judge = p::JudgeRec {
            check: 1,
            class: 0,
            flags: 0,
            _r: 0,
        };
        r.put_pod_tail(t::JUDGE, &judge, b"https://x").unwrap();
        assert!(run(Call::Piece(p::FROM_CORE), &r).is_ok());
        assert_eq!(run(Call::End, &r), Err(bad(t::JUDGE)));
    }

    #[test]
    fn emit_is_for_session_answers_and_the_tick() {
        let describe = PlaneDescribe::default();
        let declaration =
            Declaration::new(0, &describe.usage_classes, &describe.attempt_classes).unwrap();
        let mut r = Reply::new();
        emit(&mut r);
        assert_eq!(run(Call::Request, &r).unwrap(), ["emit 7 line"]);
        assert!(run(Call::End, &r).is_ok());
        assert!(admin_answer(p::ADMIN_TICK, declaration, Records::new(r.as_bytes())).is_ok());
        assert_eq!(run(Call::Rewrite, &r), Err(bad(t::EMIT)));
        assert_eq!(run(Call::Render, &r), Err(bad(t::EMIT)));
        assert_eq!(
            admin_answer(p::ADMIN_CATALOG, declaration, Records::new(r.as_bytes())),
            Err(bad(t::EMIT))
        );
        let mut r = Reply::new();
        r.put_fact(p::F_MODEL, 1).unwrap();
        assert_eq!(
            admin_answer(p::ADMIN_TICK, declaration, Records::new(r.as_bytes())),
            Err(bad(g::FACT))
        );
    }

    #[test]
    fn demux_refuses_every_combination_round_18_forbids() {
        let one = |slot: u64, flags: u32, tail: &[u8]| {
            let mut r = Reply::new();
            demux(&mut r, slot, flags, tail);
            run(Call::Demux, &r)
        };
        let size = Err(FaultReason::BadRecords(RecErr::Size));
        assert_eq!(one(3, p::DX_FINAL, b"").unwrap(), ["demux 3 8 0"]);
        assert!(one(0, p::DX_BROADCAST, b"k").is_ok());
        assert!(one(0, p::DX_OUTSTANDING, b"").is_ok());
        assert_eq!(one(3, p::DX_OUTSTANDING, b""), size);
        assert_eq!(one(3, p::DX_BROADCAST, b"k"), size);
        assert_eq!(one(0, p::DX_FINAL, b""), size);
        assert_eq!(one(3, 0, b"tail"), size);
        assert_eq!(one(0, p::DX_BROADCAST, b""), size);
        assert_eq!(one(0, p::DX_BROADCAST, &[b'k'; 129]), size);
        assert_eq!(one(0, p::DX_OUTSTANDING, &[b'x'; 4097]), size);
        assert_eq!(one(0, p::DX_OUTSTANDING | p::DX_BROADCAST, b"k"), size);
        let mut r = Reply::new();
        demux(&mut r, 1, 0, b"");
        demux(&mut r, 2, 0, b"");
        assert_eq!(run(Call::Demux, &r), Err(bad(t::DEMUX)));
    }

    #[test]
    fn a_channel_needs_demux_and_an_http_head() {
        let mut key = Reply::new();
        key.put_text(g::TEXT, "tools").unwrap();
        let chan = |carrier: u32| p::ChanRec {
            exchange: 1,
            carrier,
            flags: 0,
            framing: p::CH_FRAME_NDJSON,
        };
        let mut r = Reply::new();
        r.put_pod_tail(t::CHANNEL, &chan(p::CARRIER_STDIO), key.as_bytes())
            .unwrap();
        let recs = Records::new(r.as_bytes());
        assert_eq!(
            decode_answer(
                Call::Request,
                false,
                Declaration::legacy(),
                None,
                None,
                recs,
                &mut |_: PlaneOut<'_>| {}
            ),
            Err(FaultReason::UnknownTag(t::CHANNEL))
        );
        assert_eq!(run(Call::Request, &r).unwrap(), ["channel 5 tools"]);
        let mut r = Reply::new();
        r.put_pod_tail(t::CHANNEL, &chan(p::CARRIER_HTTP), key.as_bytes())
            .unwrap();
        assert_eq!(
            run(Call::Request, &r),
            Err(FaultReason::BadRecords(RecErr::Size))
        );
        key.put_text(g::H_METHOD, "GET").unwrap();
        key.put_text(g::H_PATH, "/sse").unwrap();
        let mut r = Reply::new();
        r.put_pod_tail(t::CHANNEL, &chan(p::CARRIER_HTTP), key.as_bytes())
            .unwrap();
        assert!(run(Call::Request, &r).is_ok());
    }

    #[test]
    fn lk_chain_carries_after_and_never_lk_prefix() {
        let one = |flags: u32, key: &[u8]| {
            let mut r = Reply::new();
            r.put_pod_tail(t::LOOKUP, &p::LookupRec { flags, limit: 5 }, key)
                .unwrap();
            run(Call::Request, &r)
        };
        let size = Err(FaultReason::BadRecords(RecErr::Size));
        assert_eq!(
            one(p::LK_CHAIN, b"log\0\0\0\0\0\0\0\0").unwrap(),
            ["lookup 4 11"]
        );
        assert_eq!(one(p::LK_CHAIN, &[0; 8]), size);
        assert_eq!(
            one(p::LK_CHAIN | p::LK_PREFIX, b"log\0\0\0\0\0\0\0\0"),
            size
        );
    }

    #[test]
    fn attempt_verdicts_stand_where_section_8_6_puts_them() {
        let mut r = Reply::new();
        attempt(&mut r, p::ATT_DECLINE);
        assert_eq!(run(Call::Upstream, &r).unwrap(), ["attempt 5"]);
        assert_eq!(run(Call::Piece(p::FROM_UPSTREAM), &r), Err(bad(t::ATTEMPT)));
        r.put_text(g::H_METHOD, "POST").unwrap();
        assert_eq!(run(Call::Upstream, &r), Err(bad(t::FORWARD)));
        let mut r = Reply::new();
        attempt(&mut r, p::ATT_RETRY);
        respond(&mut r, 500);
        assert_eq!(run(Call::Piece(p::FROM_UPSTREAM), &r), Err(bad(t::FORWARD)));
        let mut r = Reply::new();
        attempt(&mut r, p::ATT_RELAY);
        respond(&mut r, 401);
        assert!(run(Call::Piece(p::FROM_UPSTREAM), &r).is_ok());
        assert_eq!(run(Call::Upstream, &r), Err(bad(t::ATTEMPT)));
    }

    #[test]
    fn a_failure_text_is_scrubbed_and_only_failed_keeps_its_facts() {
        let scrub = Scrub::from_needles([b"s3cr3t-value".as_slice()]);
        let e = port_error(
            &scrub,
            true,
            7,
            "upstream said s3cr3t-value",
            (Some(30), Some(503)),
            None,
        );
        let PortError::Failed {
            text,
            retry_after_s,
            backend_status,
            ..
        } = e
        else {
            panic!("a FAILED answer is PortError::Failed");
        };
        assert!(!text.contains("s3cr3t-value"));
        assert_eq!((retry_after_s, backend_status), (Some(30), Some(503)));
        let e = port_error(&scrub, false, 4, "no", (None, None), None);
        assert!(matches!(e, PortError::Refused { code: 4, .. }));
    }

    #[test]
    fn selected_channel_requires_one_complete_channel_and_only_facts() {
        let channel = |out: &mut Reply| {
            let mut key = Reply::new();
            key.put_text(g::TEXT, "member").unwrap();
            out.put_pod_tail(
                t::CHANNEL,
                &p::ChanRec {
                    exchange: 7,
                    flags: 0,
                    carrier: p::CARRIER_STDIO,
                    framing: p::CH_FRAME_NDJSON,
                },
                key.as_bytes(),
            )
            .unwrap();
        };
        let mut valid = Reply::new();
        channel(&mut valid);
        assert!(run(Call::Channel, &valid).is_ok());
        assert!(run(Call::Upstream, &valid).is_err());
        assert!(run(Call::Channel, &Reply::new()).is_err());
        for extra in [
            t::CHANNEL,
            t::EX_MSG,
            g::METRIC,
            t::UP_BODY,
            t::ATTEMPT,
            t::STORE,
        ] {
            let mut answer = Reply::new();
            channel(&mut answer);
            if extra == t::CHANNEL {
                channel(&mut answer);
            } else {
                answer.put(extra, b"").unwrap();
            }
            let mut delivered = 0;
            assert!(decode_answer(
                Call::Channel,
                true,
                Declaration::legacy(),
                None,
                None,
                Records::new(answer.as_bytes()),
                &mut |_| delivered += 1
            )
            .is_err());
            assert_eq!(delivered, 0, "whole-answer validation precedes publication");
        }
        let mut malformed = Reply::new();
        malformed
            .put_pod_tail(
                t::CHANNEL,
                &p::ChanRec {
                    exchange: 7,
                    flags: 0,
                    carrier: p::CARRIER_STDIO,
                    framing: p::CH_FRAME_NDJSON,
                },
                b"member",
            )
            .unwrap();
        assert!(run(Call::Channel, &malformed).is_err());
    }

    #[test]
    fn the_admin_argument_is_copied_record_for_record() {
        let mut arg = Reply::new();
        arg.put_pod(g::TEXT, &U64Rec { value: 9 }).unwrap();
        arg.put_text(g::TEXT, "abc").unwrap();
        let mut req = Reply::new();
        copy_records(&mut req, arg.as_bytes()).unwrap();
        assert_eq!(req.as_bytes(), arg.as_bytes());
        let refused = copy_records(&mut Reply::new(), &[1, 0, 0]);
        assert!(matches!(
            refused,
            Err(PortError::Refused {
                code: R_INVALID,
                ..
            })
        ));
    }
}

#[cfg(test)]
#[path = "plane_fallback_tests.rs"]
mod fallback_tests;
