// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The layout of every method's call (core 3.0, interface revision C.3): how many bytes of `head`, how many
//! texts and how many blobs each of the 34 methods of the seven kinds crosses with, as the kind's own packer
//! builds it. This is the table plugins and the engine's adapters are written against; a row that moves
//! here is a change to that kind's contract (appending is its second number, anything else its first).

use busbar_plugin_abi::types::{Bytes, Call, Slice, Str};
use busbar_plugin_abi::{auth, export, hook, plane, secret, store, transport};

/// (bytes of head, texts, blobs).
fn shape(call: &Call<'_>) -> (usize, usize, usize) {
    (call.head().len(), call.texts().len(), call.blobs().len())
}

const B: Bytes<'static> = Bytes::EMPTY;
const S: Str<'static> = Str::EMPTY;

fn plane_req() -> plane::PlaneReq<'static> {
    plane::PlaneReq {
        route: 0,
        flags: 0,
        auth: 0,
        _r: 0,
        method: S,
        path: S,
        query: S,
        headers: Slice::EMPTY,
        identity: B,
        request_id: 0,
        carrier: 0,
        work: S,
        ticket_record: B,
    }
}

fn target() -> plane::Target<'static> {
    plane::Target {
        attempt: 0,
        flags: 0,
        dialect: S,
        model: S,
        base_path: S,
        upstream: S,
        provider: S,
        params: Slice::EMPTY,
        admission: B,
    }
}

#[test]
fn store_secret_hook_and_export_layouts() {
    assert_eq!(store::ENTRIES, 5);
    assert_eq!(store::METHODS, ["read", "scan", "commit", "clock", "info"]);
    assert_eq!(store::pack::read(0, B, shape), (0, 0, 1));
    assert_eq!(store::pack::scan(0, B, shape), (0, 0, 1));
    assert_eq!(store::pack::commit(0, B, shape), (0, 0, 1));
    assert_eq!(store::pack::clock(0, B, shape), (0, 0, 1));
    assert_eq!(store::pack::info(0, shape), (0, 0, 0));

    assert_eq!(secret::ENTRIES, 1);
    assert_eq!(secret::pack::resolve(0, B, shape), (0, 0, 1));

    assert_eq!(hook::ENTRIES, 2);
    assert_eq!(hook::pack::on(0, 1, B, shape), (4, 0, 1));
    assert_eq!(hook::pack::on_io(0, 1, B, shape), (4, 0, 1));

    assert_eq!(export::ENTRIES, 3);
    // stream u32 @0, delivery u64 @8, attempt u32 @16, lines u32 @20.
    assert_eq!(export::pack::deliver(0, 1, 2, 3, 4, B, shape), (24, 0, 1));
    assert_eq!(export::pack::render(0, 1, B, shape), (4, 0, 1));
    assert_eq!(export::pack::confirm(0, 2, shape), (8, 0, 0));
    export::pack::deliver(0, 1, 2, 3, 4, B, |call| {
        assert_eq!(&call.head()[..4], &1u32.to_le_bytes());
        assert_eq!(&call.head()[8..16], &2u64.to_le_bytes());
        assert_eq!(&call.head()[16..20], &3u32.to_le_bytes());
        assert_eq!(&call.head()[20..24], &4u32.to_le_bytes());
    });
}

#[test]
fn auth_layouts() {
    assert_eq!(auth::ENTRIES, 5);
    assert_eq!(
        auth::METHODS,
        ["verify", "login", "outbound", "refresh", "serve"]
    );
    let req = auth::AuthReq {
        flags: 1,
        _r: 0,
        method: S,
        path: S,
        query: S,
        authority: S,
        headers: Slice::EMPTY,
        peer: S,
        tls_peer_cert: B,
        body: B,
        issued: B,
        now_s: 9,
    };
    // flags, _r, now_s; method, path, query, authority, peer; headers, tls_peer_cert, body, issued.
    assert_eq!(auth::pack::verify(0, &req, shape), (16, 5, 4));
    auth::pack::verify(0, &req, |call| {
        assert_eq!(&call.head()[8..16], &9u64.to_le_bytes());
    });
    assert_eq!(auth::pack::login(0, 1, B, shape), (4, 0, 1));
    assert_eq!(auth::pack::outbound(0, B, shape), (0, 0, 1));
    assert_eq!(auth::pack::refresh(0, shape), (0, 0, 0));
    assert_eq!(auth::pack::serve(0, B, shape), (0, 0, 1));
}

#[test]
fn plane_layouts() {
    assert_eq!(plane::ENTRIES, 11);
    assert_eq!(
        plane::METHODS,
        [
            "request",
            "upstream",
            "piece",
            "end",
            "rewrite",
            "render",
            "admin",
            "probe",
            "demux",
            "select_resources",
            "channel"
        ]
    );
    let (req, t) = (plane_req(), target());
    // route, flags, auth, _r, request_id, carrier; method, path, query, work; headers, identity,
    // ticket_record, then the method's own body.
    assert_eq!(plane::pack::request(0, &req, B, shape), (32, 4, 4));
    assert_eq!(plane::pack::upstream(0, &t, shape), (8, 5, 2));
    assert_eq!(plane::pack::piece(0, 1, 2, 3, B, shape), (12, 0, 1));
    assert_eq!(plane::pack::end(0, shape), (0, 0, 0));
    assert_eq!(plane::pack::rewrite(0, B, shape), (0, 0, 1));
    assert_eq!(plane::pack::render(0, &req, 1, B, shape), (36, 4, 4));
    assert_eq!(plane::pack::admin(0, 1, B, shape), (4, 0, 1));
    assert_eq!(plane::pack::probe(0, &t, shape), (8, 5, 2));
    assert_eq!(plane::pack::demux(0, S, B, shape), (0, 1, 1));
    // mode u32 @0, then the request's numbers: its two u64 land at 24 and 32.
    assert_eq!(
        plane::pack::select_resources(0, 1, &req, B, shape),
        (40, 4, 4)
    );
    assert_eq!(plane::pack::channel(0, &t, shape), (8, 5, 2));
}

#[test]
fn transport_layouts() {
    assert_eq!(transport::ENTRIES, 7);
    let conn = transport::ConnInfo {
        role: transport::ROLE_SERVER,
        flags: 0,
        alpn: S,
        sni: S,
        peer: S,
        local: S,
        tls_peer_cert: B,
        leftover: B,
        head: B,
        local_fingerprint: S,
        mono_ns: 0,
    };
    // role, flags, mono_ns; alpn, sni, peer, local, local_fingerprint; tls_peer_cert, leftover, head.
    assert_eq!(transport::pack::begin(0, &conn, shape), (16, 5, 3));
    assert_eq!(transport::pack::ingest(0, B, shape), (0, 0, 1));
    // stream u64, pieces u32, arg u32, credit u64; one blob per piece present.
    let parts = [B, B, B];
    let together = transport::E_HEAD | transport::E_BODY | transport::E_END;
    assert_eq!(
        transport::pack::emit(0, 1, together, 0, 0, Slice::new(&parts), shape),
        (24, 0, 3)
    );
    assert_eq!(
        transport::pack::emit(0, 1, transport::E_CONSUMED, 0, 4096, Slice::EMPTY, shape),
        (24, 0, 0)
    );
    assert_eq!(transport::pack::timer(0, shape), (0, 0, 0));
    assert_eq!(transport::pack::datagram(0, 1, 0, B, shape), (8, 0, 1));
    assert_eq!(transport::pack::event(0, 1, B, shape), (4, 0, 1));
    assert_eq!(transport::pack::offer(0, 1, shape), (4, 0, 0));
}

/// Every method's clock reading crosses as given, and a pair list crosses as one blob.
#[test]
fn the_clock_and_a_pair_list_cross() {
    use busbar_plugin_abi::types::Pair;
    let pairs = [Pair {
        name: Str::new("accept"),
        value: Bytes::new(b"*/*"),
    }];
    let mut req = plane_req();
    req.headers = Slice::new(&pairs);
    plane::pack::request(77, &req, B, |call| {
        assert_eq!(call.mono_ns(), 77);
        assert_eq!(call.session(), 0, "the packer never chooses a session");
        assert_eq!(call.blobs()[0].len(), core::mem::size_of::<Pair<'static>>());
    });
}
