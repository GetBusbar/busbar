// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The old HTTPS stand-in's host-bound timing matrix at the existing raw connection boundary.
//! This proves the actual host's separation of dial/request bounds, not a real TLS handshake.

use super::*;
use crate::dispatch::{Adopter, Bind, ConnTable, NoSink};
use busbar_contract::abi::host::conn::connector::Need;
use busbar_contract::abi::mechanism::door::{Door, Statement};
use busbar_contract::abi::mechanism::ticket::{HostTables, Ticket};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::transport::FrameSpan;
use std::task::Poll;

fn bind(table: Arc<dyn DeclaredConns>, timeout_ms: u64) -> Plugin<TestKind> {
    // SAFETY: the loader's own test door and Statement are static; the restated need is leaked
    // for the same lifetime, as are its copied door and Statement.
    let real: Door = unsafe { *crate::dispatch_test_plugin::busbar_plugin_door() };
    let statement: Statement = unsafe { *real.statement() };
    let needs = Box::leak(Box::new([Need {
        direction: DIRECTION_OUTBOUND,
        transport: abi_str("http"),
        timeout_ms,
        ..Need::ZERO
    }]));
    let statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..statement
    }));
    // SAFETY: every part is the real door's or the live static Statement above.
    let door = Box::leak(Box::new(unsafe {
        Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
            statement,
            ..real.parts()
        })
    }));
    let validated = crate::dispatch::load::validate_door::<TestKind>(door).unwrap();
    Plugin::bind(
        validated,
        None,
        Bind {
            instance: Arc::from("immediate-framed-timeout"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: ConnTable::Host(table),
        },
    )
    .unwrap()
}

fn ready<T: std::fmt::Debug>(
    answer: Poll<Result<T, busbar_contract::abi::sdk::conn::ConnFailure>>,
) -> T {
    match answer {
        Poll::Ready(Ok(answer)) => answer,
        other => panic!("an immediate existing raw boundary must answer: {other:?}"),
    }
}

#[test]
fn the_real_host_reaches_an_immediate_reply_with_independent_declared_and_caller_bounds() {
    for (need_ms, establish_ms, request_ms, expected_dial) in [
        (700, 0, 0, 700),
        (700, 123, 0, 123),
        (700, 123, 900, 123),
        (0, 0, 0, 0),
    ] {
        let table = Arc::new(Scripted {
            framed: true,
            ..Scripted::default()
        });
        table.script.lock().unwrap().extend([
            (
                super::piece(PieceKind::Fields, Some(201), None, 0),
                Vec::new(),
            ),
            (
                super::piece(PieceKind::Body, None, None, 6),
                b"answer".to_vec(),
            ),
            (
                super::piece(PieceKind::Completion, None, None, 0),
                Vec::new(),
            ),
        ]);
        let plugin = bind(table.clone(), need_ms);
        let tables = HostTables {
            size: std::mem::size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: plugin.inner.ctx(),
            wake: None,
            conns: &CONN_SLOTS,
            services: std::ptr::null(),
            io: std::ptr::null(),
        };
        // SAFETY: this registry-backed context and static connector table remain valid; the SDK
        // copies the slot table and retains no pointer into this local HostTables value.
        let host = unsafe { Host::from_raw(&tables) };
        let mut conn = host.connector(Ticket {
            slot: 7,
            generation: 3,
        });
        let stream =
            ready(conn.establish_timed(0, Some("https://far.example/base"), "", establish_ms));
        assert!(
            table.opened.lock().unwrap().is_empty(),
            "a framed establish stays unopened until the request ends"
        );
        let head = RequestPiece {
            kind: REQUEST_HEAD,
            method: FrameSpan { offset: 0, len: 3 },
            target: FrameSpan { offset: 3, len: 6 },
            timeout_ms: request_ms,
            ..RequestPiece::ZERO
        };
        ready(conn.write_request(stream, &head, b"GET/reply"));
        ready(conn.write_request(
            stream,
            &RequestPiece {
                kind: REQUEST_BODY,
                ..RequestPiece::ZERO
            },
            b"body",
        ));
        ready(conn.write_request(
            stream,
            &RequestPiece {
                kind: REQUEST_END,
                ..RequestPiece::ZERO
            },
            b"",
        ));
        assert_eq!(
            *table.timeouts.lock().unwrap(),
            [(expected_dial, request_ms)]
        );
        assert_eq!(*table.declared_timeouts.lock().unwrap(), [need_ms]);
        let opened = table.opened.lock().unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].0, NeedId(0));
        assert_eq!(opened[0].1, "https://far.example/base");
        assert_eq!(opened[0].2, b"GET");
        assert_eq!(opened[0].3, b"/reply");
        assert_eq!(opened[0].5, b"body");
        drop(opened);

        let mut buf = [0; 32];
        let mut piece = ReplyPiece::default();
        let reply = ready(conn.read_reply(stream, &mut buf, &mut piece));
        assert_eq!(reply.piece.kind, REPLY_HEAD);
        assert_eq!(reply.piece.code, 201);
        let reply = ready(conn.read_reply(stream, &mut buf, &mut piece));
        assert_eq!(reply.piece.kind, REPLY_BODY);
        assert_eq!(&buf[..reply.len], b"answer");
        assert_eq!(
            ready(conn.read_reply(stream, &mut buf, &mut piece))
                .piece
                .kind,
            REPLY_END
        );
        ready(conn.close(stream));
    }
}
