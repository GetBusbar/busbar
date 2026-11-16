// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The plane adapter: `PlanePort` over the plane kind's `Proxy` (IF §11.3, §8.6). W1-L8 red: the decode and
//! failure seams with `todo!()` bodies, so the tests below compile and fail; the green commit fills them.

use busbar_plugin_abi::fail::refused::R_INVALID;
use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::host_side::scrub::Scrub;
use busbar_plugin_abi::plane::{self as p, tag as t, Proxy};
use busbar_plugin_abi::records::{tag as g, RecErr, Records, U64Rec, Writer};

use crate::instance::PluginCode;
use crate::ports::plane::{PlaneOut, RouteInfo, UsageClass};
use crate::ports::PortError;

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
    pub usage_classes: Vec<UsageClass>,
    pub tick_s: Option<u64>,
    /// D_ADMIN_OPENAPI: the OpenAPI fragment of the ROUTE_ADMIN routes, for K8's admin document merge (round 8).
    pub admin_openapi: Option<Box<str>>,
}

/// A describe the §8.6 rules refuse. The registry turns it into `Refusal { code: DescribeInvalid, field }`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DescribeInvalid(pub &'static str);

/// Decodes the plane describe items under the §8.6 describe rules.
pub fn decode_describe(
    describe: Records<'_>,
    methods: u64,
    facts: u64,
) -> Result<PlaneDescribe, DescribeInvalid> {
    let _ = (describe, methods, facts);
    todo!("W1-L8 red")
}

/// Which call answered. It decides what the answer may hold (§8.6). `Piece` carries `from`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Call {
    Request,
    Upstream,
    Piece(u32),
    End,
    Rewrite,
    Render,
    Probe,
    Demux,
    /// admin(ADMIN_TICK): PUSH* and EMIT* only.
    Tick,
}

/// Decodes one OK answer of `call` into the sink, whole or not at all.
pub fn decode_answer(
    call: Call,
    demux: bool,
    recs: Records<'_>,
    sink: &mut dyn FnMut(PlaneOut<'_>),
) -> Result<(), FaultReason> {
    let _ = (call, demux, recs, sink);
    todo!("W1-L8 red")
}

/// A REFUSED or FAILED answer as a `PortError`.
pub fn port_error(
    scrub: &Scrub,
    failed_answer: bool,
    code: u32,
    text: &str,
    facts: (Option<u64>, Option<u64>),
    error: Option<PluginCode>,
) -> PortError {
    let _ = (scrub, failed_answer, code, text, facts, error);
    todo!("W1-L8 red")
}

/// Copies core's admin argument into the request buffer, record by record.
fn copy_records(w: &mut impl Writer, arg: &[u8]) -> Result<(), PortError> {
    let _ = (w, arg, R_INVALID);
    todo!("W1-L8 red")
}

/// The admin answer placement rules (§8.6).
fn admin_answer(op: u32, recs: Records<'_>) -> Result<(), FaultReason> {
    let _ = (op, recs, RecErr::Size, U64Rec { value: 0 }, g::TEXT, t::END);
    todo!("W1-L8 red")
}

/// The plane port over one instance's proxy (W0 stub until the green commit).
pub struct PlaneAdapter {
    proxy: Proxy,
}

impl PlaneAdapter {
    pub fn new(proxy: Proxy) -> Self {
        Self { proxy }
    }

    pub fn proxy(&self) -> &Proxy {
        &self.proxy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use busbar_plugin_abi::records::{Reply, Writer};

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
        let mut r = Reply::new();
        emit(&mut r);
        assert_eq!(run(Call::Request, &r).unwrap(), ["emit 7 line"]);
        assert!(run(Call::End, &r).is_ok());
        assert!(admin_answer(p::ADMIN_TICK, Records::new(r.as_bytes())).is_ok());
        assert_eq!(run(Call::Rewrite, &r), Err(bad(t::EMIT)));
        assert_eq!(run(Call::Render, &r), Err(bad(t::EMIT)));
        assert_eq!(
            admin_answer(p::ADMIN_CATALOG, Records::new(r.as_bytes())),
            Err(bad(t::EMIT))
        );
        let mut r = Reply::new();
        r.put_fact(p::F_MODEL, 1).unwrap();
        assert_eq!(
            admin_answer(p::ADMIN_TICK, Records::new(r.as_bytes())),
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
            decode_answer(Call::Request, false, recs, &mut |_: PlaneOut<'_>| {}),
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
