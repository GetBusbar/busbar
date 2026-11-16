// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-PLANE-DESCRIBE-R10 (ABI-MIN3-INTERFACE §14): ROUTE_LINE/ROUTE_RECOVERY describe rules (DescribeInvalid) and
//! EMIT/WORK placement (BadRecords).
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).

use busbar_plugin_abi::fail::FaultReason;
use busbar_plugin_abi::plane::{self as p, tag as t};
use busbar_plugin_abi::records::{RecErr, Records, Reply, Writer};
use busbar_plugin_loader::adapters::plane::{
    decode_answer, decode_describe, Call, DescribeInvalid, PlaneDescribe,
};
use busbar_ports::plane::PlaneOut;

/// `RouteRec.methods` bits (the kept route encoding: GET = 1, POST = 1 << 2).
const GET: u32 = 1;
const POST: u32 = 1 << 2;

fn describe(routes: &[(u32, u32, u32)]) -> Result<PlaneDescribe, DescribeInvalid> {
    let mut r = Reply::new();
    for (i, &(methods, flags, auth)) in routes.iter().enumerate() {
        let rec = p::RouteRec {
            route: i as u32 + 1,
            methods,
            flags,
            auth,
        };
        r.put_pod_tail(t::D_ROUTE, &rec, b"/r").unwrap();
    }
    decode_describe(Records::new(r.as_bytes()), p::ALL, 0)
}

fn answer(call: Call, r: &Reply) -> Result<(), FaultReason> {
    decode_answer(
        call,
        true,
        Records::new(r.as_bytes()),
        &mut |_: PlaneOut<'_>| {},
    )
}

#[test]
fn route_line_and_route_recovery_rules() {
    let line = |f: &'static str| Err(DescribeInvalid(f));
    // A ROUTE_LINE route takes POST only, and an instance has at most one.
    assert!(describe(&[(POST, p::ROUTE_LINE, p::AUTH_PRINCIPAL)]).is_ok());
    assert_eq!(
        describe(&[(GET, p::ROUTE_LINE, p::AUTH_PRINCIPAL)]),
        line("describe.route_line")
    );
    let two = [
        (POST, p::ROUTE_LINE, p::AUTH_PRINCIPAL),
        (POST, p::ROUTE_LINE, p::AUTH_PUBLIC),
    ];
    assert_eq!(describe(&two), line("describe.route_line"));
    // Neither ROUTE_LINE nor ROUTE_RECOVERY combines with another ROUTE_* bit.
    let flags = line("describe.route.flags");
    assert_eq!(
        describe(&[(POST, p::ROUTE_LINE | p::ROUTE_CATALOG, p::AUTH_PRINCIPAL)]),
        flags
    );
    assert_eq!(
        describe(&[(GET, p::ROUTE_RECOVERY | p::ROUTE_ADMIN, p::AUTH_PRINCIPAL)]),
        flags
    );
    // A ROUTE_RECOVERY route takes GET only, under AUTH_PRINCIPAL only.
    assert!(describe(&[(GET, p::ROUTE_RECOVERY, p::AUTH_PRINCIPAL)]).is_ok());
    let recovery = line("describe.route_recovery");
    assert_eq!(
        describe(&[(POST, p::ROUTE_RECOVERY, p::AUTH_PRINCIPAL)]),
        recovery
    );
    assert_eq!(
        describe(&[(GET, p::ROUTE_RECOVERY, p::AUTH_OPTIONAL)]),
        recovery
    );

    // EMIT in a `render` answer is BadRecords; in a session answer it is an item.
    let mut emit = Reply::new();
    emit.put_pod_tail(t::EMIT, &p::EmitRec { carrier: 1 }, b"line")
        .unwrap();
    let misplaced = |tag| Err(FaultReason::BadRecords(RecErr::Unknown(tag)));
    assert_eq!(answer(Call::Render, &emit), misplaced(t::EMIT));
    assert!(answer(Call::Request, &emit).is_ok());

    // WORK in an `end` answer is BadRecords; in `request` and `piece` answers it is an intent.
    let mut target = Reply::new();
    target.put_text(t::WK_TARGET, "/poll?id=1").unwrap();
    let mut work = Reply::new();
    let rec = p::WorkRec {
        check: 1,
        op: p::WORK_OPEN,
    };
    work.put_pod_tail(t::WORK, &rec, target.as_bytes()).unwrap();
    assert_eq!(answer(Call::End, &work), misplaced(t::WORK));
    assert!(answer(Call::Request, &work).is_ok());
    assert!(answer(Call::Piece(p::FROM_CORE), &work).is_ok());
}
