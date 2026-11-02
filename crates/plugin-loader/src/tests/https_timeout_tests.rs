// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};
use std::task::Poll;

use busbar_contract::abi::host::conn::connector::{
    Need, ReplyPiece, RequestPiece, DIRECTION_OUTBOUND, REPLY_BODY, REPLY_END, REPLY_HEAD,
    REQUEST_BODY, REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::mechanism::door::{Door, Statement};
use busbar_contract::abi::mechanism::rendering::{ReadBlob, ReadNeed};
use busbar_contract::abi::mechanism::ticket::{HostTables, Ticket};
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::transport::FrameSpan;
use busbar_contract::conn::{
    ConnError, ConnId, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
};
use busbar_contract::transport::ConnFacts;

use crate::dispatch::conn_services::CONN_SLOTS;
use crate::dispatch::{Adopter, Bind, ConnTable, NoSink, Plugin};
use crate::dispatch_tests::TestKind;
use crate::https_conns::HttpsConns;
use crate::stand_in::FramedFacts;

type Opening = (u64, u64, Vec<u8>, Vec<u8>, Vec<u8>);

struct Observed {
    table: Arc<HttpsConns>,
    openings: Mutex<Vec<Opening>>,
}

impl Conns for Observed {
    fn open(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.table.open(owner, need, desc)
    }
    fn write(
        &self,
        owner: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        self.table.write(owner, conn, bytes, end, text)
    }
    fn read(
        &self,
        owner: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.table.read(owner, conn, ticket, buf)
    }
    fn wait(&self, owner: InstanceId, set: &[ConnId], ticket: u64) -> Result<usize, ConnError> {
        self.table.wait(owner, set, ticket)
    }
    fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.table.facts(owner, conn)
    }
    fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.table.close(owner, conn)
    }
}

impl DeclaredConns for Observed {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        self.table.declare(owner, need, spec, target, trust)
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.table.declared(owner, need)
    }
    fn serves_scheme(&self, scheme: &str) -> bool {
        self.table.serves_scheme(scheme)
    }
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.table.framed(owner, need)
    }
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        secure: bool,
        dial_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.openings.lock().unwrap().push((
            dial_ms,
            desc.timeout_ms,
            desc.method.to_vec(),
            desc.head_target.to_vec(),
            desc.body.to_vec(),
        ));
        self.table.open_request(owner, need, desc, secure, dial_ms)
    }
}

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
        Poll::Ready(Ok(value)) => value,
        other => panic!("immediate fixture did not answer: {other:?}"),
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
        let table = Arc::new(HttpsConns::framing(FramedFacts::stand_in()));
        table.serve("https://far.example/reply", None, 201, "answer");
        let observed = Arc::new(Observed {
            table: table.clone(),
            openings: Mutex::new(Vec::new()),
        });
        let plugin = bind(observed.clone(), need_ms);
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
            table.sent().is_empty(),
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
            *observed.openings.lock().unwrap(),
            vec![(
                expected_dial,
                request_ms,
                b"GET".to_vec(),
                b"/reply".to_vec(),
                b"body".to_vec()
            )]
        );
        assert_eq!(
            table.sent(),
            vec![(0, "https://far.example/reply".to_owned())]
        );
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

fn need(transport: &str) -> ReadNeed {
    ReadNeed {
        direction: DIRECTION_OUTBOUND,
        egress_class: 0,
        transport: transport.to_owned(),
        auth: String::new(),
        target_from: String::new(),
        trust_from: String::new(),
        details: ReadBlob {
            fmt: 0,
            flags: 0,
            bytes: Vec::new(),
        },
        timeout_ms: 700,
        keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
        keep_response_headers: Vec::new(),
        deny_response_headers: Vec::new(),
    }
}

#[test]
fn distinct_bounds_keep_secure_delivery_trust_and_unreached_refusals_on_the_existing_path() {
    let owner = InstanceId(7);
    let id = NeedId(0);
    let facts = FramedFacts::stand_in();
    let table = HttpsConns::framing(facts.clone());
    table.serve("https://far.example/reply", None, 200, "ok");
    table
        .declare(owner, id, &need(&facts.transport), None, None)
        .unwrap();
    let desc = OpenDesc {
        target: "https://far.example/reply",
        ..Default::default()
    };
    assert_eq!(
        table.open_request(owner, id, &desc, true, 123),
        Err(ConnError::AuthRefused)
    );
    assert!(
        table.sent().is_empty(),
        "existing secure-delivery refusal happens before an open"
    );
    assert_eq!(
        table.open_request(owner, NeedId(8), &desc, false, 123),
        Err(ConnError::UndeclaredNeed)
    );
    assert!(table.sent().is_empty());
    assert_eq!(
        table.open_request(
            owner,
            id,
            &OpenDesc {
                target: "https://missing.example/reply",
                ..Default::default()
            },
            false,
            123
        ),
        Err(ConnError::Refused)
    );
    assert_eq!(
        table.sent(),
        vec![(0, "https://missing.example/reply".to_owned())]
    );

    let untrusted = HttpsConns::framing(facts.clone());
    untrusted.serve("https://far.example/reply", Some("presented CA"), 200, "ok");
    let mut spec = need(&facts.transport);
    spec.trust_from = "settings.ca".to_owned();
    untrusted
        .declare(owner, id, &spec, None, Some("another CA"))
        .unwrap();
    assert_eq!(
        untrusted.open_request(owner, id, &desc, false, 123),
        Err(ConnError::Refused)
    );
    assert_eq!(
        untrusted.sent(),
        vec![(0, "https://far.example/reply".to_owned())]
    );

    let unreached = HttpsConns::framing(facts).unreached(["other-framer".to_owned()]);
    unreached
        .declare(owner, id, &need("other-framer"), None, None)
        .unwrap();
    assert_eq!(
        unreached.open_request(owner, id, &desc, false, 123),
        Err(ConnError::Refused)
    );
    assert_eq!(
        unreached.unreached_opens(),
        vec![("other-framer".to_owned(), 1)]
    );
    assert!(unreached.sent().is_empty());
}
