// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHAT THE DOOR HOLDS AND GATHERS IS BOUNDED. A unit the kernel refuses is over, and the door
//! drops it; an upstream's answer is gathered only under the SDK's reply ceiling.
//!
//! The units are driven through the linked door op by op, as `tests/conformance.rs` drives it.

use std::mem::zeroed;
use std::path::Path;
use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Field, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::GenIn;
use busbar_contract::abi::plane::{
    slot, ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, OutField, PlaneOpenIn, PlaneOpenOut,
    RecordWrite, RefusalIn, RefusalOut, UnitCount, FROM_CALLER, FROM_FAR_END, PIECE_LAST,
    REFUSAL_GATE,
};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_plane_mcp::codec::{H_MCP_METHOD, H_PROTOCOL_VERSION, PROTOCOL_VERSION};
use busbar_plane_mcp::{door, tool_door as plane_door};
use busbar_plugin_loader::dispatch::kinds::plane::Plane;
use busbar_plugin_loader::dispatch::{
    in_head, load_linked, out_head, Bind, DispatchConfig, Dispatcher, Frame, LinkedRow, NoSink,
    Plugin,
};

fn z<T>() -> T {
    // SAFETY: every `in`/`out` here is plain C data; all-zero is a valid value of each.
    unsafe { zeroed() }
}

fn octets(b: &'static [u8]) -> Blob {
    Blob {
        ptr: b.as_ptr(),
        len: b.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn text(b: &'static [u8]) -> AbiStr {
    AbiStr {
        ptr: b.as_ptr(),
        len: b.len(),
    }
}

const SECTION: &[u8] =
    br#"{"fs": {"url": "https://mcp.example/fs", "pin": {"mechanism": "unpinned"}}}"#;
const PUBLIC_URL: &str = "https://busbar.example";
const TOOLS_LIST: &[u8] = br#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
const LIST_FIELDS: &[Field] = &[
    Field {
        name: abi_str(H_PROTOCOL_VERSION),
        value: abi_str(PROTOCOL_VERSION),
    },
    Field {
        name: abi_str(H_MCP_METHOD),
        value: abi_str("tools/list"),
    },
];

/// The linked door, opened over [`SECTION`] and started.
fn started(d: &Dispatcher) -> Plugin<Plane> {
    let row = LinkedRow::of(plane_door::door).expect("the linked door states its Statement");
    let bind = Bind {
        instance: Arc::from("the-instance"),
        max_inflight_cap: 64,
        sink: Arc::new(NoSink),
        dispatcher: d.adopter(),
        conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
    };
    let p = load_linked(&row, bind).expect("the linked door loads");
    let mut i: PlaneOpenIn = z();
    i.open.head = in_head();
    (i.open.generation, i.open.settings) = (1, octets(SECTION));
    i.public_url = text(PUBLIC_URL.as_bytes());
    let mut o: PlaneOpenOut = z();
    o.open.head = out_head();
    let (c, _) = p.open(&mut Frame::new(i, o));
    assert_eq!(c.outcome, Outcome::Ready, "open");
    for op in [slot::HYDRATE, slot::START] {
        let mut g = Frame::new(
            GenIn {
                head: in_head(),
                generation: 1,
            },
            out_head(),
        );
        assert_eq!(p.call(op, &mut g).outcome, Outcome::Ready);
    }
    p
}

/// A `tools/list` of `unit` arrives (the plane answers it from what it holds).
fn arrive_list(p: &Plugin<Plane>, unit: u64) {
    let route = door::ROUTES
        .iter()
        .position(|r| r.verb == "POST" && r.target == "/mcp")
        .expect("the door routes it");
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    a.input.unit = unit;
    a.input.claim = u32::try_from(route).expect("a small table");
    (a.input.method, a.input.target) = (text(b"POST"), text(b"/mcp"));
    a.input.body = octets(TOOLS_LIST);
    (a.input.fields, a.input.fields_len) = (LIST_FIELDS.as_ptr(), LIST_FIELDS.len());
    assert_eq!(
        p.call(slot::ARRIVE, &mut a).outcome,
        Outcome::Ready,
        "arrive"
    );
}

/// What one `on_piece` answered: its outcome, the status it stated and the bytes it emitted.
struct Piece {
    outcome: Outcome,
    status: u32,
    reply: Vec<u8>,
}

/// One `on_piece` of `unit` from `from` carrying `flags`, `stream` and `caller`, through a reply
/// buffer of `cap` bytes and buffers that hold the rest.
fn push(
    p: &Plugin<Plane>,
    (unit, from, flags): (u64, u32, u32),
    (stream, caller): (u64, &'static str),
    cap: usize,
) -> Piece {
    let mut reply = vec![0_u8; cap];
    let (mut fields, mut arena) = ([z::<OutField>(); 16], vec![0_u8; 4096]);
    let mut records = [z::<RecordWrite>(); 16];
    let mut units = [z::<UnitCount>(); 8];
    let mut i: OnPieceIn = z();
    i.head = in_head();
    (i.unit, i.from, i.stream) = (unit, from, stream);
    i.caller_ref = text(caller.as_bytes());
    (i.flags, i.bytes) = (flags, octets(TOOLS_LIST));
    (i.reply_buf, i.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (i.fields_buf, i.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (i.arena_buf, i.arena_cap) = (arena.as_mut_ptr(), arena.len());
    (i.records_buf, i.records_cap) = (records.as_mut_ptr(), records.len());
    (i.units_buf, i.units_cap) = (units.as_mut_ptr(), units.len());
    let mut o: OnPieceOut = z();
    o.head = out_head();
    let mut f = Frame::new(i, o);
    let c = p.call(slot::ON_PIECE, &mut f);
    let emitted = usize::try_from(f.out.emitted).expect("small");
    Piece {
        outcome: c.outcome,
        status: f.out.reply_status,
        reply: reply[..emitted].to_vec(),
    }
}

/// One whole-body `on_piece` of `unit` from `from`: its outcome.
fn piece(p: &Plugin<Plane>, unit: u64, from: u32) -> Outcome {
    push(p, (unit, from, PIECE_LAST), (0, ""), 1 << 16).outcome
}

/// The kernel refuses `unit` (a gate's `403`), and the plane renders the refusal.
fn refuse(p: &Plugin<Plane>, unit: u64) {
    let (mut reply, mut fields, mut arena) =
        (vec![0_u8; 4096], [z::<OutField>(); 4], vec![0_u8; 512]);
    let mut records = [z::<RecordWrite>(); 4];
    let mut r: Frame<RefusalIn, RefusalOut> = Frame::new(z(), z());
    (r.input.head, r.out.head) = (in_head(), out_head());
    r.input.unit = unit;
    (r.input.cause, r.input.status) = (REFUSAL_GATE, 403);
    r.input.text = text(b"denied");
    (r.input.reply_buf, r.input.reply_cap) = (reply.as_mut_ptr(), reply.len());
    (r.input.fields_buf, r.input.fields_cap) = (fields.as_mut_ptr(), fields.len());
    (r.input.arena_buf, r.input.arena_cap) = (arena.as_mut_ptr(), arena.len());
    (r.input.records_buf, r.input.records_cap) = (records.as_mut_ptr(), records.len());
    assert_eq!(
        p.call(slot::REFUSAL, &mut r).outcome,
        Outcome::Ready,
        "refusal"
    );
}

/// A unit the kernel refuses after it arrived is over: the plane no longer holds it, so a piece
/// naming it is refused rather than answered from the request params it kept.
#[test]
fn a_unit_the_kernel_refuses_is_dropped() {
    let d = Dispatcher::new(DispatchConfig::default());
    let p = started(&d);
    arrive_list(&p, 7);
    refuse(&p, 7);
    assert_eq!(
        piece(&p, 7, FROM_CALLER),
        Outcome::Refused,
        "the refused unit is still held"
    );
}

/// A unit a piece of which the plane refuses is over too: nothing else would ever end it.
#[test]
fn a_unit_whose_piece_the_plane_refuses_is_dropped() {
    let d = Dispatcher::new(DispatchConfig::default());
    let p = started(&d);
    arrive_list(&p, 8);
    // A far end's piece for a unit that sent nothing on.
    assert_eq!(piece(&p, 8, FROM_FAR_END), Outcome::Refused);
    assert_eq!(
        piece(&p, 8, FROM_CALLER),
        Outcome::Refused,
        "the unit whose piece was refused is still held"
    );
}

/// An upstream's answer is gathered only under the SDK's reply ceiling, and the call that passes it
/// fails as any bad upstream answer does. The gather site is reached only by a call the kernel has
/// admitted and entitled, which this harness has no host to do, so the bound is read off the source
/// at that site.
#[test]
fn an_upstreams_answer_is_gathered_only_under_the_reply_ceiling() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tool_door.rs");
    let source = std::fs::read_to_string(path).expect("the door's source reads");
    let lines: Vec<&str> = source.lines().collect();
    let gather = lines
        .iter()
        .position(|l| l.contains("relay.far.extend_from_slice(bytes)"))
        .expect("the gather site");
    let guard = lines[gather.saturating_sub(8)..gather].join("\n");
    assert!(
        guard.contains("REPLY_MAX") && guard.contains("upstream_failed"),
        "the gather is not bounded by the reply ceiling, failing the call past it:\n{guard}"
    );
}

/// A `subscriptions/listen` of `unit` arrives, opting in to a list category.
fn arrive_listen(p: &Plugin<Plane>, unit: u64) {
    const LISTEN: &[u8] = br#"{"jsonrpc":"2.0","id":3,"method":"subscriptions/listen","params":{"notifications":{"toolsListChanged":true},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;
    const FIELDS: &[Field] = &[
        Field {
            name: abi_str(H_PROTOCOL_VERSION),
            value: abi_str(PROTOCOL_VERSION),
        },
        Field {
            name: abi_str(H_MCP_METHOD),
            value: abi_str("subscriptions/listen"),
        },
    ];
    let route = door::ROUTES
        .iter()
        .position(|r| r.verb == "POST" && r.target == "/mcp")
        .expect("the door routes it");
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    a.input.unit = unit;
    a.input.claim = u32::try_from(route).expect("a small table");
    (a.input.method, a.input.target) = (text(b"POST"), text(b"/mcp"));
    a.input.body = octets(LISTEN);
    (a.input.fields, a.input.fields_len) = (FIELDS.as_ptr(), FIELDS.len());
    assert_eq!(
        p.call(slot::ARRIVE, &mut a).outcome,
        Outcome::Ready,
        "arrive listen"
    );
}

/// One caller opening its quota's worth of subscriptions, plus one, cuts off no other caller's
/// stream: the extra one is refused, in the caller's own answer.
#[test]
fn a_caller_at_its_subscription_quota_is_refused_and_evicts_no_other_caller() {
    const QUOTA: u64 = 64;
    let d = Dispatcher::new(DispatchConfig::default());
    let p = started(&d);
    // Streams are opened through a one-byte reply buffer, so each stays held, its head part written.
    let open = |unit: u64, caller: &'static str, cap: usize| {
        arrive_listen(&p, unit);
        push(&p, (unit, FROM_CALLER, 0), (unit, caller), cap)
    };
    open(1, "caller-b", 1);
    for unit in 100..100 + QUOTA {
        assert_eq!(open(unit, "caller-a", 1).outcome, Outcome::Ready);
    }
    let over = open(100 + QUOTA, "caller-a", 1 << 16);
    assert_eq!(
        over.status, 429,
        "the caller's extra subscription is refused"
    );
    assert!(
        String::from_utf8_lossy(&over.reply).contains("subscription_quota"),
        "the refusal names its reason"
    );
    let b = push(&p, (1, FROM_CALLER, 0), (1, "caller-b"), 1 << 16);
    assert_eq!(
        b.outcome,
        Outcome::Ready,
        "caller B's stream survives caller A"
    );
    assert!(
        !b.reply.is_empty(),
        "caller B's stream still has its frame to write"
    );
}

/// A `tools/list` of `unit` arrives: its outcome and the status the plane refused it with.
fn arrival(p: &Plugin<Plane>, unit: u64) -> (Outcome, u32) {
    let route = door::ROUTES
        .iter()
        .position(|r| r.verb == "POST" && r.target == "/mcp")
        .expect("the door routes it");
    let mut a: Frame<ArriveIn, ArriveOut> = Frame::new(z(), z());
    (a.input.head, a.out.head) = (in_head(), out_head());
    a.input.unit = unit;
    a.input.claim = u32::try_from(route).expect("a small table");
    (a.input.method, a.input.target) = (text(b"POST"), text(b"/mcp"));
    a.input.body = octets(TOOLS_LIST);
    (a.input.fields, a.input.fields_len) = (LIST_FIELDS.as_ptr(), LIST_FIELDS.len());
    let outcome = p.call(slot::ARRIVE, &mut a).outcome;
    (outcome, a.out.refusal_status)
}

/// A full unit table refuses the next arrival (429) and never evicts: the first unit is still held
/// and still answers.
#[test]
fn a_full_unit_table_refuses_the_next_arrival_and_evicts_nothing() {
    let d = Dispatcher::new(DispatchConfig::default());
    let p = started(&d);
    for unit in 1..=4096 {
        assert_eq!(arrival(&p, unit).0, Outcome::Ready, "unit {unit}");
    }
    assert_eq!(
        arrival(&p, 4097),
        (Outcome::Refused, 429),
        "the arrival past the cap"
    );
    assert_eq!(
        piece(&p, 1, FROM_CALLER),
        Outcome::Ready,
        "the first unit was evicted to make room"
    );
}
