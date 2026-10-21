// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LINKED TRANSPORT ROW IS ITS BARE `door` (coordinator ruling (b), row 159): a door-root crate's
//! only public item is `door` (`BUSBAR-1.6.0.md` A.1, l.3560), and a linked row holds that door and
//! reaches the same `'static` table a dropped-in copy does (l.3561). So the row's key, the layers it
//! composes over and whether it carries a session are read off the door's Statement (A.2,
//! l.3564-3577: the name, the claims, the kind tail), never off a constant the crate exports beside
//! `door`. The fixtures here are door-root crates in miniature: each module's only public item is
//! `door`; it exports no `KEY`, `COMPOSES_OVER` or `SESSION`.

use busbar_contract::transport::TransportSettings;

use crate::root::doors::{row_facts, stated_row, RowFacts};
use crate::root::linked::linked_transport;
use crate::root::registry::{compose, Dropped};

/// A DOOR-ROOT TRANSPORT CRATE IN MINIATURE: a module `$module` whose only public item is `door`,
/// a carrier whose Statement is named `$name`, whose one claim is `$claim`, whose tail composes over
/// `$layers`, and whose claim row's `session` is `$session`. Every kind op answers REFUSED: the
/// tests read what the door states and open it, and never carry a byte through it.
macro_rules! door_root {
    ($module:ident, $name:literal, $claim:literal, [$($layer:literal),*], $session:literal) => {
        mod $module {
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
                    TransportTail, WriteIn, CANCEL_NOTHING_MOVED, FRAME_PIECE_SIZE, FRAMING_STREAM,
                    ROLE_CARRIER, UNIT0_FIRST_BYTES,
                };
                use busbar_contract::abi::mechanism::call::OutHead;

                const NONE: AbiStr = AbiStr {
                    ptr: std::ptr::null(),
                    len: 0,
                };

                const CLAIM_NAMES: &[AbiStr] = &[abi_str($claim)];

                const LAYERS: &[AbiStr] = &[$(abi_str($layer)),*];

                const CLAIMS: &[Claim] = &[Claim {
                    selector_forms: abi_str(""),
                    egress_selector_forms: abi_str(""),
                    facts: std::ptr::null(),
                    facts_len: 0,
                    status_namespace: NONE,
                    session: $session,
                    session_bound: 0,
                    unit0_trigger: UNIT0_FIRST_BYTES,
                    status_at: 0,
                    _reserved: 0,
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
                    composes_over: LAYERS.as_ptr(),
                    composes_over_len: LAYERS.len(),
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
                    settings: std::ptr::null(),
                    settings_len: 0,
                    fault_rows: std::ptr::null(),
                    fault_rows_len: 0,
                    frame_piece_size: FRAME_PIECE_SIZE,
                    _reserved: 0,
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

/// GREEN: A DOOR-ROOT ROW LINKS WITH THE KEY, LAYERS AND SESSION ITS STATEMENT STATES. The row is
/// built by the macro the generated linked table expands for every `transport` row, from the bare
/// `door` and nothing else; the boot seal's fold builds it (its door admitted, opened and admitted
/// to be served) and registers it under the key the Statement states. RED without the mechanism:
/// the row would need the crate's `KEY` and `COMPOSES_OVER`, which a door-root crate does not have.
#[test]
fn a_door_root_row_links_with_the_key_layers_and_session_its_statement_states() {
    let row = linked_transport!(wire::door);
    assert_eq!(
        (row.key)(),
        "door-root-wire",
        "the key is the door's own claim"
    );
    assert!(
        (row.composes_over)().is_empty(),
        "the layers are the tail's: none"
    );
    assert_eq!(
        row_facts(wire::door),
        RowFacts {
            key: "door-root-wire",
            composes_over: Vec::new(),
            session: true,
        },
        "the session is the claim row's"
    );
    let built = compose(&[row], Dropped::NONE, &TransportSettings::default())
        .expect("the door-root row composes");
    let keys: Vec<&str> = built.iter().map(|(r, _)| r.key).collect();
    assert_eq!(
        keys,
        ["door-root-wire"],
        "the fold registers it under its key"
    );
    assert_eq!(
        built[0].1.key(),
        "door-root-wire",
        "the boot's admission of its door answers the same key"
    );

    // What a door states is read, never defaulted: a tail that names a layer, and a claim row that
    // carries no session.
    let layered = linked_transport!(layered::door);
    assert_eq!((layered.key)(), "door-root-layered");
    assert_eq!((layered.composes_over)(), ["door-root-under"]);
    assert!(
        !row_facts(layered::door).session,
        "its claim row carries no session"
    );
}

/// RED: A DOOR WHOSE OWN CLAIM IS NOT ITS STATEMENT'S NAME IS REFUSED AT BOOT. The reader refuses it
/// naming both spellings, and the boot seal's fold over a row of it does not register it: the
/// boot is refused with the reader's words.
#[test]
fn a_door_whose_own_claim_is_not_its_statement_name_is_refused_at_boot() {
    let refused = stated_row(misnamed::door).expect_err("a misnamed door is refused");
    assert!(
        refused.contains("`door-root-named`") && refused.contains("`door-root-claimed`"),
        "the refusal names both spellings: {refused}"
    );
    let row = linked_transport!(misnamed::door);
    let boot = std::panic::catch_unwind(|| {
        compose(&[row], Dropped::NONE, &TransportSettings::default()).map(|built| built.len())
    })
    .expect_err("the boot is refused");
    let said = boot
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| boot.downcast_ref::<&str>().map(|s| (*s).to_owned()))
        .unwrap_or_default();
    assert!(
        said.contains("a linked transport door is refused") && said.contains(&refused),
        "the boot refusal is the reader's: {said}"
    );
}

/// EVERY ROW THIS BUILD LINKS, door-root or `linked`-module alike, reads its key off its door's
/// Statement through the one reader: each linked transport door states its own claim as its name,
/// and the linked table's rows are keyed, in order, by what those doors state.
#[test]
fn every_linked_transport_row_is_keyed_by_its_doors_statement() {
    let doors = crate::linked_transport_doors();
    let keys: Vec<&str> = crate::LINKED.transports.iter().map(|t| (t.key)()).collect();
    assert_eq!(
        doors.iter().map(|(key, _)| *key).collect::<Vec<_>>(),
        keys,
        "the connector's doors and the linked rows are one list, keyed alike"
    );
    for (key, door) in doors {
        let stated = stated_row(*door).unwrap_or_else(|e| panic!("`{key}`: {e}"));
        assert_eq!(stated.key, *key, "`{key}` is keyed by its door's own claim");
        assert_eq!(
            crate::LINKED
                .transports
                .iter()
                .find(|t| (t.key)() == *key)
                .map(|t| (t.composes_over)().to_vec()),
            Some(stated.composes_over),
            "`{key}`'s layers are its door's tail's"
        );
    }
}
