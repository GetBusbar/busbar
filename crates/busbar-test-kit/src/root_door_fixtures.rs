// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST ONLY: THE COMPOSITION ROOT'S DOOR FIXTURES (`BUSBAR-1.6.0.md` l.272-274). A door is built
//! by the contract's door macro, whose expansion writes `unsafe`; the root is `forbid(unsafe_code)`
//! and must hold no such expansion, so the doors its tests drive are built HERE, in the test kit
//! (a dev-dependency only), and the root's tests reach them as `busbar_test_kit::root_door_fixtures`.
//! Moved verbatim from `crates/busbar/src/root/tests/doors_refresh.rs` (the held-down carrier)
//! and `crates/busbar/src/root/tests/linked_door_root.rs` (the door-root crates in miniature).

#[path = "root_door_fixtures/scoped_mux.rs"]
pub mod scoped_mux;

#[path = "root_door_fixtures/datagram_order.rs"]
pub mod datagram_order;

#[path = "root_door_fixtures/datagram_feedback.rs"]
pub mod datagram_feedback;

#[path = "root_door_fixtures/raw_udp_ingress.rs"]
pub mod raw_udp_ingress;

/// The carrier under test: a member's program it holds down once it ended, until its `refresh`.
pub mod held_down {
    use std::marker::PhantomData;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, PoisonError};

    use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
    use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
    use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
    use busbar_contract::abi::transport::{
        AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn, ConnOut,
        DialIn, EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn, IoOut, ListenIn,
        ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, SettingDecl, ShutIn, TransportTail,
        WriteIn, CANCEL_NOTHING_MOVED, FRAME_PIECE_SIZE, FRAMING_STREAM, ROLE_CARRIER,
        SETTING_COUNT, UNIT0_FIRST_LINE,
    };

    /// Its claim.
    const KEY: &str = "row159-held-down";
    /// The one setting it reads, at its 1.5.5 path.
    pub const TIMEOUT: &str = "limits.upstream_request_timeout_secs";
    /// The value its `refresh` refuses.
    pub const REFUSED_TIMEOUT_SECS: u64 = 1;

    const NONE: AbiStr = AbiStr::ZERO;

    const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

    const CLAIMS: &[Claim] = &[Claim {
        selector_forms: abi_str(""),
        egress_selector_forms: abi_str(""),
        status_namespace: NONE,
        session: 1,
        session_bound: 1,
        unit0_trigger: UNIT0_FIRST_LINE,
        ..Claim::ZERO
    }];

    const SETTINGS: &[SettingDecl] = &[SettingDecl {
        path: abi_str(TIMEOUT),
        kind: SETTING_COUNT,
        default: abi_str("600"),
        ..SettingDecl::ZERO
    }];

    const TAIL: TransportTail = TransportTail {
        head: KindTailHead {
            size: std::mem::size_of::<TransportTail>() as u32,
            ..KindTailHead::ZERO
        },
        role: ROLE_CARRIER,
        framing: FRAMING_STREAM,
        claim_rows: CLAIMS.as_ptr(),
        claim_rows_len: CLAIMS.len(),
        settings: SETTINGS.as_ptr(),
        settings_len: SETTINGS.len(),
        frame_piece_size: FRAME_PIECE_SIZE,
        ..TransportTail::ZERO
    };

    const STATEMENT: Statement = Statement {
        kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
        claims: CLAIM_NAMES.as_ptr(),
        claims_len: CLAIM_NAMES.len(),
        ..statement(KEY, "0.0.1", 64)
    };

    /// The instance: whether it holds the member's program down, and the timeout it was handed.
    pub struct Program {
        held: AtomicBool,
        timeout: Mutex<Option<u64>>,
    }

    fn timeout_of(settings: &[u8]) -> Option<u64> {
        serde_json::from_slice::<serde_json::Value>(settings)
            .ok()?
            .get(TIMEOUT)?
            .as_u64()
    }

    impl Life for Program {
        const CANCEL: u32 = CANCEL_NOTHING_MOVED;

        fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Self {
                held: AtomicBool::new(false),
                timeout: Mutex::new(timeout_of(settings)),
            })
        }

        /// The new settings, and the hold released; the sentinel timeout is refused, and then
        /// nothing it holds moves.
        fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            let next = timeout_of(settings);
            if next == Some(REFUSED_TIMEOUT_SECS) {
                return Err(Refusal::refused("refresh: the sentinel timeout is refused"));
            }
            *self.timeout.lock().unwrap_or_else(PoisonError::into_inner) = next;
            self.held.store(false, Ordering::SeqCst);
            Ok(Refreshed::default())
        }
    }

    type State = Held<Program>;

    fn program<'a>(i: &Instance<'a, State>) -> Option<&'a Program> {
        i.get().map(Held::life)
    }

    /// A slot it does not serve: REFUSED.
    pub struct Refused<I, O>(PhantomData<(I, O)>);

    impl<I: AbiIn, O: AbiOut> SafeSlot for Refused<I, O> {
        type In = I;
        type Out = O;
        type State = State;
        fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
            Outcome::Refused
        }
    }

    /// `dial`: the program is spawned unless it is held down.
    pub struct Dial;

    impl SafeSlot for Dial {
        type In = DialIn;
        type Out = ConnOut;
        type State = State;
        fn call(
            inst: Instance<'_, State>,
            _: Lent<'_, DialIn>,
            mut o: Out<'_, ConnOut>,
        ) -> Outcome {
            match program(&inst) {
                Some(p) if !p.held.load(Ordering::SeqCst) => Outcome::Ready,
                Some(_) => o.fail(Refusal::failed("dial: the program is held down")),
                None => Outcome::Fault,
            }
        }
    }

    /// `shut`: the program ended, and is held down until the instance is refreshed.
    pub struct Shut;

    impl SafeSlot for Shut {
        type In = ShutIn;
        type Out = OutHead;
        type State = State;
        fn call(inst: Instance<'_, State>, _: Lent<'_, ShutIn>, _: Out<'_, OutHead>) -> Outcome {
            match program(&inst) {
                Some(p) => {
                    p.held.store(true, Ordering::SeqCst);
                    Outcome::Ready
                }
                None => Outcome::Fault,
            }
        }
    }

    /// `flush`: READY when its connection token is the timeout the instance holds (the test's
    /// window on the settings it was handed).
    pub struct Flush;

    impl SafeSlot for Flush {
        type In = ConnIn;
        type Out = OutHead;
        type State = State;
        fn call(inst: Instance<'_, State>, i: Lent<'_, ConnIn>, _: Out<'_, OutHead>) -> Outcome {
            let Some(p) = program(&inst) else {
                return Outcome::Fault;
            };
            let held = *p.timeout.lock().unwrap_or_else(PoisonError::into_inner);
            if held == Some(i.conn) {
                Outcome::Ready
            } else {
                Outcome::Refused
            }
        }
    }

    busbar_contract::plugin_door! {
        ops: Ops,
        statement: STATEMENT,
        lifecycle: life(Program),
        kind_ops: {
            listen: Safe<Refused<ListenIn, ListenOut>>,
            accept: Safe<Refused<AcceptIn, AcceptOut>>,
            dial: Safe<Dial>,
            read: Safe<Refused<ReadIn, IoOut>>,
            write: Safe<Refused<WriteIn, IoOut>>,
            flush: Safe<Flush>,
            shut: Safe<Shut>,
            arrival: Safe<Refused<ArrivalIn, ArrivalOut>>,
            locate: Safe<Refused<LocateIn, LocateOut>>,
            begin: Safe<Refused<BeginIn, FramerOut>>,
            ingest: Safe<Refused<IngestIn, FramerOut>>,
            emit: Safe<Refused<EmitIn, FramerOut>>,
            encode: Safe<Refused<EncodeIn, FramerOut>>,
            refuse: Safe<Refused<RefuseIn, FramerOut>>,
            finish: Safe<Refused<FinishIn, FramerOut>>,
            detach: Safe<Refused<FramingIn, FramerOut>>,
            adopt: Safe<Refused<AdoptIn, FramerOut>>,
            timer: Safe<Refused<FramingIn, FramerOut>>,
        },
    }
}

/// A DOOR-ROOT TRANSPORT CRATE IN MINIATURE: a module `$module` whose only public item is `door`,
/// a carrier whose Statement is named `$name`, whose one claim is `$claim`, whose tail composes over
/// `$layers`, and whose claim row's `session` is `$session`. Every kind op answers REFUSED: the
/// tests read what the door states and open it, and never carry a byte through it.
macro_rules! door_root {
    ($module:ident, $name:literal, $claim:literal, [$($layer:literal),*], $session:literal) => {
        door_root!(
            $module,
            $name,
            $claim,
            [$($layer),*],
            $session,
            busbar_contract::abi::transport::FRAME_PIECE_SIZE
        );
    };
    ($module:ident, $name:literal, $claim:literal, [$($layer:literal),*], $session:literal, $piece:expr) => {
        pub mod $module {
            mod door {
                use std::marker::PhantomData;

                use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
                use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
                use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
                use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
                use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
                use busbar_contract::abi::transport::{
                    AcceptIn, AcceptOut, AdoptIn, ArrivalIn, ArrivalOut, BeginIn, Claim, ConnIn,
                    ConnOut, DialIn, EmitIn, EncodeIn, FinishIn, FramerOut, FramingIn, IngestIn,
                    IoOut, ListenIn, ListenOut, LocateIn, LocateOut, Ops, ReadIn, RefuseIn, ShutIn,
                    TransportTail, WriteIn, CANCEL_NOTHING_MOVED, FRAMING_STREAM,
                    ROLE_CARRIER, ROLE_FRAMER, UNIT0_FIRST_BYTES,
                };
                use busbar_contract::abi::mechanism::call::OutHead;

                const NONE: AbiStr = AbiStr::ZERO;

                const CLAIM_NAMES: &[AbiStr] = &[abi_str($claim)];

                const LAYERS: &[AbiStr] = &[$(abi_str($layer)),*];

                const CLAIMS: &[Claim] = &[Claim {
                    selector_forms: abi_str(""),
                    egress_selector_forms: abi_str(""),
                    status_namespace: NONE,
                    session: $session,
                    session_bound: 0,
                    unit0_trigger: UNIT0_FIRST_BYTES,
                    ..Claim::ZERO
                }];

                const TAIL: TransportTail = TransportTail {
                    head: KindTailHead {
                        size: std::mem::size_of::<TransportTail>() as u32,
                        ..KindTailHead::ZERO
                    },
                    // A carrier composes over nothing (`check_tail`): a fixture that names a layer is a
                    // framer.
                    role: if LAYERS.is_empty() {
                        ROLE_CARRIER
                    } else {
                        ROLE_FRAMER
                    },
                    framing: FRAMING_STREAM,
                    composes_over: LAYERS.as_ptr(),
                    composes_over_len: LAYERS.len(),
                    claim_rows: CLAIMS.as_ptr(),
                    claim_rows_len: CLAIMS.len(),
                    frame_piece_size: $piece,
                    ..TransportTail::ZERO
                };

                const STATEMENT: Statement = Statement {
                    kind_tail: (&TAIL as *const TransportTail).cast::<KindTailHead>(),
                    claims: CLAIM_NAMES.as_ptr(),
                    claims_len: CLAIM_NAMES.len(),
                    ..statement($name, "0.0.1", 64)
                };

                /// The instance: it holds nothing.
                pub struct Wire;

                impl Life for Wire {
                    const CANCEL: u32 = CANCEL_NOTHING_MOVED;

                    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
                        Ok(Self)
                    }

                    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
                        Ok(Refreshed::default())
                    }
                }

                type State = Held<Wire>;

                /// Every slot: REFUSED.
                pub struct Refused<I, O>(PhantomData<(I, O)>);

                impl<I: AbiIn, O: AbiOut> SafeSlot for Refused<I, O> {
                    type In = I;
                    type Out = O;
                    type State = State;
                    fn call(_: Instance<'_, State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
                        Outcome::Refused
                    }
                }

                busbar_contract::plugin_door! {
                    ops: Ops,
                    statement: STATEMENT,
                    lifecycle: life(Wire),
                    kind_ops: {
                        listen: Safe<Refused<ListenIn, ListenOut>>,
                        accept: Safe<Refused<AcceptIn, AcceptOut>>,
                        dial: Safe<Refused<DialIn, ConnOut>>,
                        read: Safe<Refused<ReadIn, IoOut>>,
                        write: Safe<Refused<WriteIn, IoOut>>,
                        flush: Safe<Refused<ConnIn, OutHead>>,
                        shut: Safe<Refused<ShutIn, OutHead>>,
                        arrival: Safe<Refused<ArrivalIn, ArrivalOut>>,
                        locate: Safe<Refused<LocateIn, LocateOut>>,
                        begin: Safe<Refused<BeginIn, FramerOut>>,
                        ingest: Safe<Refused<IngestIn, FramerOut>>,
                        emit: Safe<Refused<EmitIn, FramerOut>>,
                        encode: Safe<Refused<EncodeIn, FramerOut>>,
                        refuse: Safe<Refused<RefuseIn, FramerOut>>,
                        finish: Safe<Refused<FinishIn, FramerOut>>,
                        detach: Safe<Refused<FramingIn, FramerOut>>,
                        adopt: Safe<Refused<AdoptIn, FramerOut>>,
                        timer: Safe<Refused<FramingIn, FramerOut>>,
                    },
                }
            }

            /// THE CRATE'S ONE PUBLIC ITEM (BUSBAR-1.6.0.md l.3560): its door.
            pub use door::door;
        }
    };
}

// A door-root wire: named for its own claim, over nothing, carrying a session.
door_root!(wire, "door-root-wire", "door-root-wire", [], 1);
// A door-root wire whose tail names a layer and whose claim carries no session: what it states is
// read, never a default.
door_root!(
    layered,
    "door-root-layered",
    "door-root-layered",
    ["door-root-under"],
    0
);
// A door whose Statement is named one thing and whose own claim is another.
door_root!(misnamed, "door-root-named", "door-root-claimed", [], 1);
// A door the loader refuses: its tail states another frame piece than the host's (row 167).
door_root!(
    bad_piece,
    "door-root-bad-piece",
    "door-root-bad-piece",
    [],
    1,
    busbar_contract::abi::transport::FRAME_PIECE_SIZE - 8
);

/// A stub plugin that migrates its own settings (`--migrate-config`, owner ruling 2026-10-27): its
/// door states `migrate` over [`migrate_stub::StubMigration`], which renames `signing-secret` to
/// `signing_secret` (renamed in 1.6.0) and raises the host its `url` names as a destination to allow.
pub mod migrate_stub {
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::migrate::{Migrate, MigrateNeed, Migrated};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
    use busbar_contract::abi::secret::{ResolveIn, ResolveOut};

    /// Its Statement name.
    pub const NAME: &str = "busbar-secret-stub";

    /// The stub's own migration.
    pub struct StubMigration;
    impl Migrate for StubMigration {
        fn migrate(mut settings: serde_json::Value, from: &str) -> Migrated {
            let mut report = Vec::new();
            let mut needs = Vec::new();
            if let Some(m) = settings.as_object_mut() {
                if let Some(v) = m.remove("signing-secret") {
                    m.insert("signing_secret".into(), v);
                    report.push(format!(
                        "settings.signing-secret -> settings.signing_secret (renamed in 1.6.0; the \
                         configuration came from {from})"
                    ));
                }
                if let Some(host) = m.get("url").and_then(|u| u.as_str()) {
                    needs.push(MigrateNeed::AllowDestination(host.to_string()));
                }
            }
            Migrated {
                settings,
                report,
                needs,
            }
        }
    }

    /// Its lifecycle: opens on anything.
    pub struct L;
    impl Life for L {
        const CANCEL: u32 = 0;
        fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            Ok(Self)
        }
        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }

    /// `resolve`: never reached.
    pub struct Resolve;
    impl SafeSlot for Resolve {
        type In = ResolveIn;
        type Out = ResolveOut;
        type State = Held<L>;
        fn call(
            _: Instance<'_, Held<L>>,
            _: Lent<'_, ResolveIn>,
            _: Out<'_, ResolveOut>,
        ) -> Outcome {
            Outcome::Refused
        }
    }

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(NAME, "1.6.0", 1),
        lifecycle: life(L),
        migrate: busbar_contract::abi::sdk::migrate::Migrator<StubMigration>,
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<Resolve> },
    }
}

/// A TEST HTTP/1.1 FRAMER'S ACCEPTING SIDE, in Rust behind the connector's [`FramerDoor`] seam: the
/// least an accepting framer does, for the composition root's data door cells (core never tests a
/// plugin). Each whole request (a request line, field lines, a `content-length` body) comes up as
/// one field block with its method and target in the stream's head slots, then its body; an
/// answer's first emit is its head (a field block, with the status on the emit), every later one
/// its body. It records what crossed: each `begin`'s lent guest list and each head emit's status.
///
/// [`FramerDoor`]: busbar_core_connector::framer::FramerDoor
pub mod h1_accept {
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::transport::{
        fields, FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots, PIECE_END,
        PIECE_END_OF_FRAME, PIECE_FIELDS, ROLE_FRAMER, YIELD_ENDED,
    };
    use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};

    /// The instance identity the fixture states.
    pub const INSTANCE: u64 = 0x5eed;

    /// What one `begin` was lent: each line's id, auth points and whether it carries a handle.
    pub type Lent = Vec<(u32, u32, bool)>;

    #[derive(Default)]
    struct State {
        inbound: Vec<u8>,
        outbound: VecDeque<u8>,
        next: u64,
        ended: bool,
    }

    /// The fixture.
    pub struct H1Accept {
        facts: DoorFacts,
        accepts: bool,
        framings: Mutex<HashMap<u64, State>>,
        next: AtomicU64,
        /// The guest list every `begin` was lent, in order.
        pub begun: Mutex<Vec<Lent>>,
        /// The status every head emit carried, in order.
        pub statuses: Mutex<Vec<u32>>,
    }

    impl H1Accept {
        /// The fixture answering `http`; `accepts` = its tail states `FACT_ACCEPTS`.
        #[must_use]
        pub fn new(accepts: bool) -> Self {
            Self {
                facts: DoorFacts {
                    name: "test-h1-accept".into(),
                    claims: vec!["http"],
                    role: ROLE_FRAMER,
                    composes_over: Vec::new(),
                    ported: false,
                    status_rows: Vec::new(),
                    duplex: Vec::new(),
                    datagram: false,
                },
                accepts,
                framings: Mutex::new(HashMap::new()),
                next: AtomicU64::new(1),
                begun: Mutex::new(Vec::new()),
                statuses: Mutex::new(Vec::new()),
            }
        }
    }

    fn raw<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
        if ptr.is_null() || len == 0 {
            return &[];
        }
        // SAFETY: host-borrowed input of `len` bytes, valid for the call.
        unsafe { std::slice::from_raw_parts(ptr, len) }
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    /// One request as it came up: method, target, field block, body.
    type Request = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

    /// One whole request off the front of `inbound`.
    fn request(inbound: &mut Vec<u8>) -> Result<Option<Request>, &'static str> {
        let Some(head_end) = find(inbound, b"\r\n\r\n") else {
            return Ok(None);
        };
        let head = String::from_utf8_lossy(&inbound[..head_end]).into_owned();
        let mut lines = head.split("\r\n");
        let mut start = lines.next().ok_or("missing request line")?.split(' ');
        let (method, target) = (
            start
                .next()
                .filter(|s| !s.is_empty())
                .ok_or("missing method")?
                .to_owned(),
            start
                .next()
                .filter(|s| !s.is_empty())
                .ok_or("missing target")?
                .to_owned(),
        );
        let mut block = Vec::new();
        let mut len = 0_usize;
        for line in lines {
            let (name, value) = line.split_once(':').ok_or("malformed field line")?;
            let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
            if name == "content-length" {
                len = value.parse().map_err(|_| "malformed content-length")?;
                continue;
            }
            if fields::hop_by_hop(&name, std::iter::empty()) {
                continue;
            }
            block.extend_from_slice(name.as_bytes());
            block.extend_from_slice(fields::SEPARATOR);
            block.extend_from_slice(value.as_bytes());
            block.extend_from_slice(fields::LINE_END);
        }
        let body_at = head_end.checked_add(4).ok_or("request length overflow")?;
        let end = body_at.checked_add(len).ok_or("request length overflow")?;
        if inbound.len() < end {
            return Ok(None);
        }
        let body = inbound[body_at..end].to_vec();
        inbound.drain(..end);
        Ok(Some((
            method.into_bytes(),
            target.into_bytes(),
            block,
            body,
        )))
    }

    /// Answer what the framing owes: its wire bytes, and every whole request it holds.
    fn answer(st: &mut State, sink: &FramerSink, o: &mut FramerOut) -> Crossed {
        let y = &mut o.yielded;
        let w = st.outbound.len().min(sink.wire_cap);
        for i in 0..w {
            let b = st.outbound.pop_front().unwrap_or_default();
            // SAFETY: a host buffer of `wire_cap` bytes; `i < w <= wire_cap`.
            unsafe { sink.wire.add(i).write(b) };
        }
        y.wire_len = w as u64;
        let (mut frame, mut pieces, mut heads) = (0_usize, 0_usize, 0_usize);
        let put = |bytes: &[u8], frame: &mut usize| -> u64 {
            let at = *frame;
            // SAFETY: the host's frame buffer; the cells' requests fit it.
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), sink.frame.add(at), bytes.len());
            }
            *frame += bytes.len();
            at as u64
        };
        while pieces + 2 <= sink.pieces_cap && heads < sink.heads_cap {
            let (method, target, block, body) = match request(&mut st.inbound) {
                Ok(Some(request)) => request,
                Ok(None) => break,
                Err(reason) => {
                    return Crossed {
                        outcome: Outcome::Failed,
                        error: Some(reason.as_bytes().to_vec()),
                    }
                }
            };
            let needed = [method.len(), target.len(), block.len(), body.len()]
                .into_iter()
                .try_fold(frame, usize::checked_add);
            if !needed.is_some_and(|n| n <= sink.frame_cap) {
                return Crossed {
                    outcome: Outcome::Failed,
                    error: Some(b"request exceeds lent frame buffer".to_vec()),
                };
            }
            let stream = st.next * 2 + 1;
            st.next += 1;
            let m = put(&method, &mut frame);
            let t = put(&target, &mut frame);
            let b = put(&block, &mut frame);
            // SAFETY: `heads < heads_cap` and `pieces + 2 <= pieces_cap`.
            unsafe {
                sink.heads.add(heads).write(HeadSlots {
                    stream,
                    method: FrameSpan {
                        offset: m,
                        len: method.len() as u64,
                    },
                    target: FrameSpan {
                        offset: t,
                        len: target.len() as u64,
                    },
                    ..HeadSlots::default()
                });
                let end = if body.is_empty() { PIECE_END } else { 0 };
                sink.pieces.add(pieces).write(FramePiece {
                    stream,
                    offset: b,
                    len: block.len() as u64,
                    code: 0,
                    status_class: 0,
                    flags: PIECE_FIELDS | PIECE_END_OF_FRAME | end,
                    fault: 0,
                    retry_after_secs: 0,
                    declared_len: 0,
                });
                pieces += 1;
                if !body.is_empty() {
                    let at = put(&body, &mut frame);
                    sink.pieces.add(pieces).write(FramePiece {
                        stream,
                        offset: at,
                        len: body.len() as u64,
                        code: 0,
                        status_class: 0,
                        flags: PIECE_END_OF_FRAME | PIECE_END,
                        fault: 0,
                        retry_after_secs: 0,
                        declared_len: 0,
                    });
                    pieces += 1;
                }
            }
            heads += 1;
        }
        y.frame_len = frame as u64;
        y.pieces_len = pieces as u32;
        y.heads_len = heads as u32;
        if st.ended && st.outbound.is_empty() {
            y.flags |= YIELD_ENDED;
        }
        Crossed {
            outcome: Outcome::Ready,
            error: None,
        }
    }

    /// The reason phrase of the statuses the cells answer.
    fn reason(status: u32) -> &'static str {
        match status {
            200 => "OK",
            404 => "Not Found",
            _ => "",
        }
    }

    impl FramerDoor for H1Accept {
        fn facts(&self) -> &DoorFacts {
            &self.facts
        }

        fn accepts(&self) -> bool {
            self.accepts
        }

        fn instance(&self) -> Option<u64> {
            Some(INSTANCE)
        }

        fn cross(&self, call: Call<'_>) -> Crossed {
            let ok = Crossed {
                outcome: Outcome::Ready,
                error: None,
            };
            let failed = Crossed {
                outcome: Outcome::Failed,
                error: Some(b"no such framing".to_vec()),
            };
            let mut framings = self.framings.lock().unwrap_or_else(|e| e.into_inner());
            match call {
                Call::Locate(_, _) => ok,
                Call::Begin(i, o) => {
                    let lines = if i.lines.is_null() {
                        &[][..]
                    } else {
                        // SAFETY: the host's line table, `lines_len` live entries for the call.
                        unsafe { std::slice::from_raw_parts(i.lines, i.lines_len) }
                    };
                    self.begun.lock().unwrap_or_else(|e| e.into_inner()).push(
                        lines
                            .iter()
                            .map(|l| (l.line, l.points, !l.auth.is_none()))
                            .collect(),
                    );
                    let token = self.next.fetch_add(1, Ordering::Relaxed);
                    let mut st = State::default();
                    answer(&mut st, &i.sink, o);
                    framings.insert(token, st);
                    o.framing = token;
                    ok
                }
                Call::Ingest(i, o) => match framings.get_mut(&i.framing) {
                    None => failed,
                    Some(st) => {
                        st.inbound.extend_from_slice(raw(i.bytes, i.len));
                        st.ended |= i.end != 0;
                        answer(st, &i.sink, o)
                    }
                },
                Call::Emit(i, o) => match framings.get_mut(&i.framing) {
                    None => failed,
                    Some(st) => {
                        let bytes = raw(i.bytes, i.len);
                        if i.status != 0 {
                            self.statuses
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .push(i.status);
                            let line = format!("HTTP/1.1 {} {}\r\n", i.status, reason(i.status));
                            st.outbound.extend(line.as_bytes());
                            st.outbound.extend(bytes);
                            st.outbound.extend(b"\r\n");
                        } else {
                            st.outbound.extend(bytes);
                        }
                        answer(st, &i.sink, o)
                    }
                },
                Call::Timer(i, o) => match framings.get_mut(&i.framing) {
                    None => failed,
                    Some(st) => answer(st, &i.sink, o),
                },
                Call::Refuse(i, o) => match framings.get_mut(&i.framing) {
                    None => failed,
                    Some(st) => answer(st, &i.sink, o),
                },
                Call::Finish(i, o) => {
                    framings.remove(&i.framing);
                    o.yielded.flags = YIELD_ENDED;
                    ok
                }
                Call::Encode(_, _) | Call::Detach(_, _) | Call::Adopt(_, _) => Crossed {
                    outcome: Outcome::Refused,
                    error: Some(b"not this fixture's".to_vec()),
                },
            }
        }
    }
}

/// Controlled pending response emits over the accepting HTTP fixture.
pub mod pending_h1_accept {
    use super::h1_accept::H1Accept;
    use busbar_core_connector::framer::FramerDoor;
    use std::sync::Arc;

    #[derive(Default)]
    struct HeadGate {
        released: std::sync::atomic::AtomicBool,
        waker: std::sync::Mutex<Option<std::task::Waker>>,
    }

    impl HeadGate {
        fn release(&self) {
            self.released
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let waker = { self.waker.lock().unwrap().take() };
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct HeadTicket {
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        gate: Arc<HeadGate>,
    }

    impl busbar_core_connector::carrier::Side for HeadTicket {
        fn ticket(&self) -> busbar_contract::abi::mechanism::ticket::Ticket {
            self.ticket
        }

        fn register(&self, waker: &std::task::Waker) {
            let next = waker.clone();
            let retired = { self.gate.waker.lock().unwrap().replace(next) };
            drop(retired);
        }
    }

    #[cfg(test)]
    mod waker_tests {
        use super::*;
        use busbar_core_connector::carrier::Side;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::task::{Wake, Waker};

        struct Reentrant {
            gate: Arc<HeadGate>,
            retired: Arc<AtomicBool>,
        }
        impl Wake for Reentrant {
            fn wake(self: Arc<Self>) {
                assert!(self.gate.waker.try_lock().is_ok(), "wake under gate lock");
            }
        }
        impl Drop for Reentrant {
            fn drop(&mut self) {
                assert!(
                    self.gate.waker.try_lock().is_ok(),
                    "waker drop under gate lock"
                );
                self.retired.store(true, Ordering::SeqCst);
            }
        }
        #[test]
        fn release_and_replacement_run_waker_callbacks_outside_the_gate() {
            let gate = Arc::new(HeadGate::default());
            let ticket = HeadTicket {
                ticket: busbar_contract::abi::mechanism::ticket::Ticket::NONE,
                gate: Arc::clone(&gate),
            };
            let retired = Arc::new(AtomicBool::new(false));
            let old = Waker::from(Arc::new(Reentrant {
                gate: Arc::clone(&gate),
                retired: Arc::clone(&retired),
            }));
            ticket.register(&old);
            drop(old);
            let next_retired = Arc::new(AtomicBool::new(false));
            let next = Waker::from(Arc::new(Reentrant {
                gate: Arc::clone(&gate),
                retired: next_retired,
            }));
            ticket.register(&next);
            assert!(retired.load(Ordering::SeqCst));
            drop(next);
            gate.release();
        }
    }

    struct HeldHead {
        bytes: Vec<u8>,
        framing: u64,
        stream: u64,
        status: u32,
        end: u32,
        flags: u32,
        deadline_ns: u64,
    }

    /// A single-request HTTP fixture with a one-shot gate holding a response emit until release.
    pub struct ParkedHeadDoor {
        inner: H1Accept,
        gate: Arc<HeadGate>,
        entered: tokio::sync::Notify,
        held: std::sync::Mutex<Option<HeldHead>>,
        next: std::sync::atomic::AtomicU32,
        final_body: bool,
        completed: std::sync::atomic::AtomicU32,
    }

    /// A fresh fixture with its response-head gate closed.
    pub fn parked_head() -> ParkedHeadDoor {
        ParkedHeadDoor {
            inner: H1Accept::new(true),
            gate: Arc::new(HeadGate::default()),
            entered: tokio::sync::Notify::new(),
            held: std::sync::Mutex::new(None),
            next: std::sync::atomic::AtomicU32::new(1),
            final_body: false,
            completed: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// A fresh fixture that parks the final body emit, after all body bytes have been produced.
    pub fn parked_final_body() -> ParkedHeadDoor {
        ParkedHeadDoor {
            final_body: true,
            ..parked_head()
        }
    }

    impl ParkedHeadDoor {
        /// Wait until the response-head crossing has copied its input and parked.
        pub async fn wait_for_head(&self) {
            self.entered.notified().await;
        }

        /// Wait until the selected response emit has copied its input and parked.
        pub async fn wait_for_emit(&self) {
            self.entered.notified().await;
        }

        /// Release the copied emit and wake its registered connection task.
        pub fn release(&self) {
            self.gate.release();
        }

        /// Every response status the underlying accepting fixture emitted.
        pub fn statuses(&self) -> Vec<u32> {
            self.inner.statuses.lock().unwrap().clone()
        }

        /// Number of selected emits that completed through the accepting fixture.
        pub fn completions(&self) -> u32 {
            self.completed.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl FramerDoor for ParkedHeadDoor {
        fn facts(&self) -> &busbar_core_connector::framer::DoorFacts {
            self.inner.facts()
        }

        fn accepts(&self) -> bool {
            self.inner.accepts()
        }

        fn instance(&self) -> Option<u64> {
            self.inner.instance()
        }

        fn cross(
            &self,
            call: busbar_core_connector::framer::Call<'_>,
        ) -> busbar_core_connector::framer::Crossed {
            self.inner.cross(call)
        }

        fn framing_side(&self) -> Option<Box<dyn busbar_core_connector::carrier::Side>> {
            Some(Box::new(HeadTicket {
                ticket: busbar_contract::abi::mechanism::ticket::Ticket {
                    slot: self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                    generation: 1,
                },
                gate: Arc::clone(&self.gate),
            }))
        }

        fn cross_on(
            &self,
            _side: &dyn busbar_core_connector::carrier::Side,
            resume: bool,
            call: busbar_core_connector::framer::Call<'_>,
        ) -> busbar_core_connector::framer::Crossed {
            use busbar_contract::abi::mechanism::call::Outcome;
            use busbar_core_connector::framer::{Call, Crossed};
            match call {
                Call::Emit(input, output)
                    if resume
                        || (!self.final_body && input.status != 0)
                        || (self.final_body && input.status == 0 && input.end_of_frame != 0) =>
                {
                    if !resume {
                        // SAFETY: the host lends these input bytes for this crossing only. Retain an
                        // owned copy, never its pointer or sink, while the emit is parked.
                        let bytes = if input.len == 0 {
                            Vec::new()
                        } else {
                            unsafe { std::slice::from_raw_parts(input.bytes, input.len) }.to_vec()
                        };
                        *self.held.lock().unwrap() = Some(HeldHead {
                            bytes,
                            framing: input.framing,
                            stream: input.stream,
                            status: input.status,
                            end: input.end_of_frame,
                            flags: input.flags,
                            deadline_ns: input.deadline_ns,
                        });
                        self.entered.notify_one();
                    }
                    if !self.gate.released.load(std::sync::atomic::Ordering::SeqCst) {
                        return Crossed {
                            outcome: Outcome::Pending,
                            error: None,
                        };
                    }
                    let held = self
                        .held
                        .lock()
                        .unwrap()
                        .take()
                        .expect("the pending emit is owned");
                    let mut replay = *input;
                    replay.bytes = held.bytes.as_ptr();
                    replay.len = held.bytes.len();
                    replay.framing = held.framing;
                    replay.stream = held.stream;
                    replay.status = held.status;
                    replay.end_of_frame = held.end;
                    replay.flags = held.flags;
                    replay.deadline_ns = held.deadline_ns;
                    let crossed = self.inner.cross(Call::Emit(&mut replay, output));
                    if crossed.outcome == Outcome::Ready {
                        self.completed
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    crossed
                }
                other => self.inner.cross(other),
            }
        }
    }
}

/// A two-stream accepting protocol: input bytes `1` and `3` open independent requests.
/// Stream one's response head parks; stream three can finish before it is released.
pub mod pending_mux_accept {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::{Arc, Mutex};

    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::mechanism::ticket::Ticket;
    use busbar_contract::abi::transport::{
        FramePiece, FrameSpan, FramerOut, FramerSink, HeadSlots, PIECE_END, PIECE_END_OF_FRAME,
        PIECE_FIELDS, ROLE_FRAMER,
    };
    use busbar_core_connector::framer::{Call, Crossed, DoorFacts, FramerDoor};

    #[derive(Default)]
    struct Gate {
        released: AtomicBool,
        wake: Mutex<Option<std::task::Waker>>,
    }

    struct Side {
        ticket: Ticket,
        gate: Arc<Gate>,
    }

    impl busbar_core_connector::carrier::Side for Side {
        fn ticket(&self) -> Ticket {
            self.ticket
        }

        fn register(&self, waker: &std::task::Waker) {
            let next = waker.clone();
            let retired = { self.gate.wake.lock().unwrap().replace(next) };
            drop(retired);
        }
    }

    #[cfg(test)]
    mod waker_tests {
        use super::*;
        use busbar_core_connector::carrier::Side as _;
        use std::task::{Wake, Waker};
        struct Reentrant(Arc<Gate>);
        impl Wake for Reentrant {
            fn wake(self: Arc<Self>) {
                assert!(self.0.wake.try_lock().is_ok());
            }
        }
        impl Drop for Reentrant {
            fn drop(&mut self) {
                assert!(self.0.wake.try_lock().is_ok());
            }
        }
        #[test]
        fn replacement_and_release_retire_after_unlocking() {
            let fixture = Mux::default();
            let gate = Arc::clone(&fixture.gate);
            let side = Side {
                ticket: busbar_contract::abi::mechanism::ticket::Ticket::NONE,
                gate: Arc::clone(&gate),
            };
            let old = Waker::from(Arc::new(Reentrant(Arc::clone(&gate))));
            side.register(&old);
            drop(old);
            let next = Waker::from(Arc::new(Reentrant(Arc::clone(&gate))));
            side.register(&next);
            drop(next);
            fixture.release();
        }
    }

    /// Owned response data retained for inspection, never a pointer into a crossing.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Emitted {
        pub stream: u64,
        pub status: u32,
        pub bytes: Vec<u8>,
        pub end: bool,
    }

    /// One connection, with a gate on stream one's head and independently emitted stream three.
    pub struct Mux {
        facts: DoorFacts,
        session: bool,
        gate: Arc<Gate>,
        entered: tokio::sync::Notify,
        second_done: tokio::sync::Notify,
        held: Mutex<Option<Emitted>>,
        emitted: Mutex<Vec<Emitted>>,
        next: AtomicU32,
    }

    impl Default for Mux {
        fn default() -> Self {
            Self {
                session: false,
                facts: DoorFacts {
                    name: "test-pending-mux".into(),
                    claims: vec!["http"],
                    role: ROLE_FRAMER,
                    composes_over: Vec::new(),
                    ported: false,
                    status_rows: Vec::new(),
                    duplex: Vec::new(),
                    datagram: false,
                },
                gate: Arc::new(Gate::default()),
                entered: tokio::sync::Notify::new(),
                second_done: tokio::sync::Notify::new(),
                held: Mutex::new(None),
                emitted: Mutex::new(Vec::new()),
                next: AtomicU32::new(1),
            }
        }
    }

    impl Mux {
        pub fn with_session() -> Self {
            let mut fixture = Self {
                session: true,
                ..Self::default()
            };
            fixture.facts.claims.push("ws");
            fixture
        }

        pub async fn wait_for_head(&self) {
            self.entered.notified().await;
        }

        pub async fn wait_for_second(&self) {
            self.second_done.notified().await;
        }

        pub fn release(&self) {
            self.gate.released.store(true, Ordering::SeqCst);
            let wake = { self.gate.wake.lock().unwrap().take() };
            if let Some(wake) = wake {
                wake.wake();
            }
        }

        pub fn emitted(&self) -> Vec<Emitted> {
            self.emitted.lock().unwrap().clone()
        }
    }

    fn copied(ptr: *const u8, len: usize) -> Vec<u8> {
        if len == 0 {
            return Vec::new();
        }
        // SAFETY: the crossing lends `len` bytes for this call. Only the owned copy survives it.
        unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
    }

    fn request(stream: u64, sink: &FramerSink, out: &mut FramerOut) {
        let path: &[u8] = if stream == 1 { b"/first" } else { b"/second" };
        assert!(sink.frame_cap >= 3 + path.len() && sink.heads_cap >= 1 && sink.pieces_cap >= 1);
        // SAFETY: the three sink buffers have been checked above; only this crossing uses them.
        unsafe {
            std::ptr::copy_nonoverlapping(b"GET".as_ptr(), sink.frame, 3);
            std::ptr::copy_nonoverlapping(path.as_ptr(), sink.frame.add(3), path.len());
            sink.heads.write(HeadSlots {
                stream,
                method: FrameSpan { offset: 0, len: 3 },
                target: FrameSpan {
                    offset: 3,
                    len: path.len() as u64,
                },
                ..HeadSlots::default()
            });
            sink.pieces.write(FramePiece {
                stream,
                flags: PIECE_FIELDS | PIECE_END_OF_FRAME | PIECE_END,
                ..FramePiece::default()
            });
        }
        out.yielded.frame_len = (3 + path.len()) as u64;
        out.yielded.heads_len = 1;
        out.yielded.pieces_len = 1;
    }

    impl FramerDoor for Mux {
        fn facts(&self) -> &DoorFacts {
            &self.facts
        }
        fn accepts(&self) -> bool {
            true
        }
        fn instance(&self) -> Option<u64> {
            Some(0x5eee)
        }

        fn framing_side(&self) -> Option<Box<dyn busbar_core_connector::carrier::Side>> {
            Some(Box::new(Side {
                ticket: Ticket {
                    slot: self.next.fetch_add(1, Ordering::SeqCst),
                    generation: 1,
                },
                gate: Arc::clone(&self.gate),
            }))
        }

        fn cross(&self, call: Call<'_>) -> Crossed {
            self.cross_on(
                &Side {
                    ticket: Ticket {
                        slot: 0,
                        generation: 1,
                    },
                    gate: Arc::clone(&self.gate),
                },
                false,
                call,
            )
        }

        fn cross_on(
            &self,
            _: &dyn busbar_core_connector::carrier::Side,
            resume: bool,
            call: Call<'_>,
        ) -> Crossed {
            let ready = Crossed {
                outcome: Outcome::Ready,
                error: None,
            };
            match call {
                Call::Begin(_, out) => out.framing = 1,
                Call::Ingest(input, out) => {
                    let bytes = copied(input.bytes, input.len);
                    assert!(bytes.len() <= 1, "send one stream opener at a time");
                    if let Some(&byte) = bytes.first() {
                        assert!(byte == b'1' || byte == b'3');
                        request(u64::from(byte - b'0'), &input.sink, out);
                    }
                }
                Call::Emit(input, _) => {
                    let value = if resume {
                        if !self.gate.released.load(Ordering::SeqCst) {
                            return Crossed {
                                outcome: Outcome::Pending,
                                error: None,
                            };
                        }
                        self.held
                            .lock()
                            .unwrap()
                            .take()
                            .expect("owned pending head")
                    } else {
                        let value = Emitted {
                            stream: input.stream,
                            status: input.status,
                            bytes: copied(input.bytes, input.len),
                            end: input.end_of_frame != 0,
                        };
                        if input.stream == 1
                            && ((self.session
                                && input.framing == 2
                                && !self.gate.released.load(Ordering::SeqCst))
                                || (!self.session && input.status != 0))
                        {
                            *self.held.lock().unwrap() = Some(value);
                            self.entered.notify_one();
                            return Crossed {
                                outcome: Outcome::Pending,
                                error: None,
                            };
                        }
                        value
                    };
                    let second_done = value.stream == 3 && value.status == 0 && value.end;
                    self.emitted.lock().unwrap().push(value);
                    if second_done {
                        self.second_done.notify_one();
                    }
                }
                Call::Detach(_, _) if self.session => {}
                Call::Adopt(_, out) if self.session => out.framing = 2,
                Call::Locate(_, _)
                | Call::Timer(_, _)
                | Call::Refuse(_, _)
                | Call::Finish(_, _) => {}
                Call::Encode(_, _) | Call::Detach(_, _) | Call::Adopt(_, _) => {
                    return Crossed {
                        outcome: Outcome::Refused,
                        error: Some(b"not this fixture's".to_vec()),
                    }
                }
            }
            ready
        }
    }
}
