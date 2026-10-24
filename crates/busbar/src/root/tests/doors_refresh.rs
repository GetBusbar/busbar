// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A CONFIG APPLY REFRESHES EVERY OPENED TRANSPORT INSTANCE (`root::doors::refresh_live`): the host
//! keeps the instances it opened at boot across an apply, so what a transport holds for a member (a
//! program it holds down after it kept ending) is cleared only by the instance's own `refresh`. A
//! plugin is a plugin: every kind's `refresh` slot is called on an apply, as the planes' and the
//! credentials' are. The subject is a compiled-in carrier door whose `refresh` clears the hold it
//! keeps, and refuses one sentinel setting.

use std::sync::Arc;

use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::sdk::door::{blank_in, blank_out};
use busbar_contract::abi::transport::{ConnIn, ConnOut, DialIn, ShutIn};
use busbar_contract::transport::TransportSettings;
use busbar_core_connector::carrier::Carry;
use busbar_core_connector::framer::FramerDoor;

use crate::root::doors::{refresh_named, row_bind, Dispatched};

/// The carrier under test: a member's program it holds down once it ended, until its `refresh`.
mod held_down {
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

    const NONE: AbiStr = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };

    const CLAIM_NAMES: &[AbiStr] = &[abi_str(KEY)];

    const CLAIMS: &[Claim] = &[Claim {
        selector_forms: abi_str(""),
        egress_selector_forms: abi_str(""),
        facts: std::ptr::null(),
        facts_len: 0,
        status_namespace: NONE,
        session: 1,
        session_bound: 1,
        unit0_trigger: UNIT0_FIRST_LINE,
        status_at: 0,
        _reserved: 0,
    }];

    const SETTINGS: &[SettingDecl] = &[SettingDecl {
        path: abi_str(TIMEOUT),
        kind: SETTING_COUNT,
        _reserved: 0,
        default: abi_str("600"),
    }];

    const TAIL: TransportTail = TransportTail {
        head: KindTailHead {
            size: std::mem::size_of::<TransportTail>() as u32,
            _reserved: 0,
        },
        role: ROLE_CARRIER,
        framing: FRAMING_STREAM,
        facts: 0,
        handshake_max_steps: 0,
        composes_over: std::ptr::null(),
        composes_over_len: 0,
        claim_rows: CLAIMS.as_ptr(),
        claim_rows_len: CLAIMS.len(),
        upgrades_to: std::ptr::null(),
        upgrades_to_len: 0,
        handoff_from: NONE,
        handoff_to: NONE,
        handoff_binding_fact: NONE,
        handshake_frame_kind: NONE,
        status_rows: std::ptr::null(),
        status_rows_len: 0,
        settings: SETTINGS.as_ptr(),
        settings_len: SETTINGS.len(),
        fault_rows: std::ptr::null(),
        fault_rows_len: 0,
        frame_piece_size: FRAME_PIECE_SIZE,
        _reserved: 0,
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

/// The carrier, compiled in and opened through the one door with `settings`, as boot opens every
/// transport.
fn opened(row: &str, settings: &TransportSettings) -> Arc<Dispatched> {
    let plugin = crate::root::test_plugins::linked_transport(
        held_down::door,
        row_bind(row).expect("the row binds"),
    );
    Arc::new(Dispatched::open(plugin, settings).expect("the carrier opens"))
}

/// One `dial` through the door, as the connector carries it.
fn dial(door: &Dispatched) -> Outcome {
    let side = door.side().expect("a carrier crosses on a side");
    let (mut i, mut o) = (blank_in::<DialIn>(), blank_out::<ConnOut>());
    door.carry(side.as_ref(), false, Carry::Dial(&mut i, &mut o))
        .outcome
}

/// The program ends: one `shut` through the door.
fn end(door: &Dispatched) {
    let side = door.side().expect("a carrier crosses on a side");
    let (mut i, mut o) = (blank_in::<ShutIn>(), blank_out::<OutHead>());
    let shut = door.carry(side.as_ref(), false, Carry::Shut(&mut i, &mut o));
    assert_eq!(shut.outcome, Outcome::Ready, "the program's end is taken");
}

/// Whether the instance holds `secs` as its timeout.
fn holds(door: &Dispatched, secs: u64) -> bool {
    let side = door.side().expect("a carrier crosses on a side");
    let mut i = blank_in::<ConnIn>();
    i.conn = secs;
    let mut o = blank_out::<OutHead>();
    door.carry(side.as_ref(), false, Carry::Flush(&mut i, &mut o))
        .outcome
        == Outcome::Ready
}

/// AN APPLY CLEARS A HELD-DOWN PROGRAM, AND THE NEXT DIAL SPAWNS. RED without the apply's refresh:
/// the host keeps the instance it opened at boot, and nothing else reaches what it holds.
#[test]
fn an_apply_refreshes_a_live_transport_and_its_next_dial_spawns() {
    let settings = TransportSettings::default();
    let door = opened("row159-apply-clears", &settings);
    assert_eq!(
        dial(&door),
        Outcome::Ready,
        "a fresh member's program spawns"
    );
    end(&door);
    assert_eq!(
        dial(&door),
        Outcome::Failed,
        "a program that ended is held down by its carrier"
    );
    // The apply's walk over every live transport (`refresh_live`), kept to this file's carriers so
    // the other cells' transports are not refreshed under them.
    let refused = refresh_named(&settings, |name| name.starts_with("row159-"));
    assert!(
        refused.is_empty(),
        "the carrier took the apply's refresh: {refused:?}"
    );
    assert_eq!(
        dial(&door),
        Outcome::Ready,
        "after the apply the carrier's refresh released the hold, and the next dial spawns"
    );
    assert!(
        holds(&door, settings.request_timeout_secs),
        "the refresh handed it the applied timeout"
    );
}

/// A TRANSPORT WHOSE REFRESH IS REFUSED KEEPS THE SETTINGS IT HOLDS, and keeps serving: the host
/// answers the refusal and closes nothing.
#[test]
fn a_refused_refresh_keeps_the_prior_settings() {
    let settings = TransportSettings::default();
    let door = opened("row159-refused-keeps", &settings);
    assert!(
        holds(&door, settings.request_timeout_secs),
        "it opened with the deployment's timeout"
    );
    let refusing = TransportSettings {
        request_timeout_secs: held_down::REFUSED_TIMEOUT_SECS,
        ..settings
    };
    let why = door
        .refresh(&refusing)
        .expect_err("the sentinel timeout is refused");
    assert!(
        why.contains("did not refresh"),
        "the refusal says so: {why}"
    );
    assert!(
        holds(&door, settings.request_timeout_secs),
        "the refused refresh left the prior timeout in place"
    );
    assert!(
        !holds(&door, held_down::REFUSED_TIMEOUT_SECS),
        "the refused value was not taken"
    );
    assert_eq!(dial(&door), Outcome::Ready, "the instance keeps serving");
}
