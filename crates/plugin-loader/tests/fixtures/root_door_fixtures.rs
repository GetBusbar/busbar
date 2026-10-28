// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! TEST ONLY: THE COMPOSITION ROOT'S DOOR FIXTURES (`BUSBAR-1.6.0.md` l.272-274). A door is built by the contract's door macro, whose expansion
//! writes `unsafe`; the root is `forbid(unsafe_code)` and must hold no such expansion, so the doors
//! its tests drive are built HERE, in the loader's reviewed allow-list, and the root's tests reach
//! them by path (the `test-support` feature, which only the root's `[dev-dependencies]` edge turns
//! on). Moved verbatim from `crates/busbar/src/root/tests/doors_refresh.rs` (the held-down carrier)
//! and `crates/busbar/src/root/tests/linked_door_root.rs` (the door-root crates in miniature).

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
