// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::os::raw::c_void;
use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{service, EstablishIn, IoIn, StreamIn};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{DoorParts, KindTailHead, Statement};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{PlaneTail, ANSWER_LAYOUT};
use busbar_contract::abi::sdk::door::RawDoorFn;
use busbar_contract::abi::transport::{FramePiece, TransportTail};
use busbar_contract::conn::{ConnError, DeclaredConns};

use super::{
    bind, connection_fixture, dispatcher, load, load_dropped_staged, real_door, restated_door,
    with_an_outbound_need, Auth, Export, Hook, Leg, Plane, Secret, Store, Subject, Transport,
    CONNECTED, FINGERPRINTED, LAID, PIECED, VERSIONED,
};
use crate::dispatch::conn_services::CONN_SLOTS;
use crate::dispatch::load::rendering_of_raw;
use crate::dispatch::{load_linked, Bind, ConnTable, Kind, LinkedRow, LoadError, Plugin};

const VERSIONED_DOOR: RawDoorFn = restated_door::<1>;
const CONNECTED_DOOR: RawDoorFn = restated_door::<2>;

const PIECED_DOOR: RawDoorFn = restated_door::<3>;

const LAID_DOOR: RawDoorFn = restated_door::<4>;

const FINGERPRINTED_DOOR: RawDoorFn = restated_door::<5>;

const KINDS: [KindCode; 7] = KindCode::ALL;

const OTHER_VERSION: &str = "0.0.0-conformance-restated";

fn with_another_version(real: DoorParts) -> DoorParts {
    // SAFETY: a door's Statement is `'static`; only its version is restated.
    let st: Statement = unsafe { real.statement.read_unaligned() };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        version: AbiStr {
            ptr: OTHER_VERSION.as_ptr(),
            len: OTHER_VERSION.len(),
        },
        ..st
    }));
    DoorParts {
        statement: st,
        ..real
    }
}

pub fn red_statement(s: &Subject) {
    let stated = s.stated();
    let _held = VERSIONED.hold(with_another_version(real_door(s)));
    let lying = rendering_of_raw(VERSIONED_DOOR)
        .expect("the door with another version still renders a valid Statement");
    busbar_contract::abi::mechanism::rendering::read(&lying)
        .expect("the mismatched Statement must pass rendering validation");
    assert_ne!(
        lying, stated,
        "the other version changes the stated rendering"
    );
    by_kind!(s.kind(), K => {
        let d = dispatcher();
        load::<K>(s, Leg::Linked, s.bind(&d, "honest-linked")).expect("the honest door loads linked");
        load::<K>(s, Leg::Dropped, s.bind(&d, "honest-dropped"))
            .expect("the honest library loads dropped in");
        let row = LinkedRow { statement: lying.clone(), door: s.door };
        assert_eq!(
            load_linked::<K>(&row, s.bind(&d, "red-linked")).map(|_| ()).err(),
            Some(LoadError::StatementMismatch),
            "a linked row stating another Statement is refused"
        );
        assert_eq!(
            load_dropped_staged::<K>(&s.cdylib(), &lying, s.bind(&d, "red-dropped")).map(|_| ()).err(),
            Some(LoadError::StatementMismatch),
            "a signed manifest stating another Statement is refused"
        );
        let row = LinkedRow { statement: stated.clone(), door: VERSIONED_DOOR };
        assert_eq!(
            load_linked::<K>(&row, s.bind(&d, "red-restated")).map(|_| ()).err(),
            Some(LoadError::StatementMismatch),
            "a door stating another version than its row is refused"
        );
    });
}

pub fn red_kind_layout(s: &Subject) {
    let kind = s.kind();
    let host = kind.layout_fingerprint();
    let real = real_door(s);
    assert_eq!(
        real.layout, host,
        "the {kind:?} door states its kind's layout fingerprint"
    );
    let stated_rendering = s.stated();
    by_kind!(kind, K => {
        let d = dispatcher();
        load::<K>(s, Leg::Linked, s.bind(&d, "honest-linked"))
            .expect("the honest door loads linked");
        load::<K>(s, Leg::Dropped, s.bind(&d, "honest-dropped"))
            .expect("the honest library loads dropped in");
        for stated in [host ^ 1, 0] {
            let _held = FINGERPRINTED.hold(DoorParts { layout: stated, ..real });
            let refused = rendering_of_raw(FINGERPRINTED_DOOR)
                .expect_err("the pack tool signs no door at another kind layout");
            let LoadError::KindLayout { kind: named, stated: said, host: read, .. } = &refused
            else {
                panic!("the restated {kind:?} door is refused for its layout: {refused:?}");
            };
            assert_eq!(
                (*named, *said, *read),
                (kind, stated, host),
                "the kind and both numbers, named"
            );
            assert!(
                refused.to_string().contains("rebuild against this busbar-contract"),
                "{refused}"
            );
            let honest_row = LinkedRow {
                statement: stated_rendering.clone(),
                door: FINGERPRINTED_DOOR,
            };
            let linked = load_linked::<K>(&honest_row, s.bind(&d, "red-kind-layout"))
                .map(|_| ())
                .expect_err("a linked door at another kind layout is refused under its honest row");
            assert_eq!(linked, refused, "the same refusal, linked");
            let own = LinkedRow::of_raw(FINGERPRINTED_DOOR)
                .and_then(|row| {
                    load_linked::<K>(&row, s.bind(&d, "red-kind-layout-own")).map(|_| ())
                })
                .expect_err("a linked door at another kind layout is refused under its own row");
            assert_eq!(own, refused, "the same refusal, under its own row");
        }
    });
}

fn with_another_piece(real: DoorParts, stated: u32) -> DoorParts {
    // SAFETY: a door's Statement is `'static`.
    let st: Statement = unsafe { real.statement.read_unaligned() };
    // SAFETY: the honest door loaded, so its kind tail is a whole `'static` `TransportTail` (the
    // loader refuses a shorter one). Only the piece size is restated.
    let tail: TransportTail = unsafe { st.kind_tail.cast::<TransportTail>().read_unaligned() };
    let tail: &'static TransportTail = Box::leak(Box::new(TransportTail {
        frame_piece_size: stated,
        ..tail
    }));
    let st: &'static Statement = Box::leak(Box::new(Statement {
        kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
        ..st
    }));
    DoorParts {
        statement: st,
        ..real
    }
}

pub fn red_frame_piece(s: &Subject) {
    if s.kind() != KindCode::Transport {
        return;
    }
    let host = std::mem::size_of::<FramePiece>() as u32;
    let stated = host - 8;
    let d = dispatcher();
    load::<Transport>(s, Leg::Linked, s.bind(&d, "honest-linked"))
        .expect("the honest door loads linked");
    load::<Transport>(s, Leg::Dropped, s.bind(&d, "honest-dropped"))
        .expect("the honest library loads dropped in");
    let _held = PIECED.hold(with_another_piece(real_door(s), stated));
    let refused = crate::dispatch::load::rendering_of_raw(PIECED_DOOR)
        .expect_err("the pack tool signs no door at another piece");
    let LoadError::FramePieceSize {
        stated: said,
        host: read,
        ..
    } = &refused
    else {
        panic!("the restated door is refused for its piece: {refused:?}");
    };
    assert_eq!((*said, *read), (stated, host), "both sizes, named");
    assert!(
        refused
            .to_string()
            .contains("rebuild against this busbar-contract"),
        "{refused}"
    );
    let linked = LinkedRow::of_raw(PIECED_DOOR)
        .and_then(|row| load_linked::<Transport>(&row, s.bind(&d, "red-piece")).map(|_| ()))
        .expect_err("a linked transport at another piece is refused");
    assert_eq!(linked, refused, "the same refusal, linked");
}

fn with_another_layout(real: DoorParts, stated: u32) -> DoorParts {
    // SAFETY: a door's Statement is `'static`.
    let st: Statement = unsafe { real.statement.read_unaligned() };
    // The honest door loaded, so its kind tail is `'static` plugin data of its stated size, at
    // least up to its answer layout. Its bytes are copied over zeros (a tail ending before a subsequent
    // field reads it absent, as the host reads it), its stated size kept; only the layout is
    // restated.
    // SAFETY: a non-NULL kind tail leads with a `KindTailHead`.
    let size = unsafe { st.kind_tail.read_unaligned() }.size as usize;
    // SAFETY: an all-zero `PlaneTail` is a valid value (integers and pointers).
    let mut tail: PlaneTail = unsafe { std::mem::zeroed() };
    // SAFETY: at most the plugin's stated size and at most a `PlaneTail` is copied.
    unsafe {
        std::ptr::copy_nonoverlapping(
            st.kind_tail.cast::<u8>(),
            std::ptr::from_mut(&mut tail).cast::<u8>(),
            size.min(std::mem::size_of::<PlaneTail>()),
        );
    }
    let tail: &'static PlaneTail = Box::leak(Box::new(PlaneTail {
        answer_layout: stated,
        ..tail
    }));
    let st: &'static Statement = Box::leak(Box::new(Statement {
        kind_tail: std::ptr::from_ref(tail).cast::<KindTailHead>(),
        ..st
    }));
    DoorParts {
        statement: st,
        ..real
    }
}

pub fn red_plane_layout(s: &Subject) {
    if s.kind() != KindCode::Plane {
        return;
    }
    let host = ANSWER_LAYOUT;
    let stated = host - 1;
    let d = dispatcher();
    load::<Plane>(s, Leg::Linked, s.bind(&d, "honest-linked"))
        .expect("the honest door loads linked");
    load::<Plane>(s, Leg::Dropped, s.bind(&d, "honest-dropped"))
        .expect("the honest library loads dropped in");
    let _held = LAID.hold(with_another_layout(real_door(s), stated));
    let refused = crate::dispatch::load::rendering_of_raw(LAID_DOOR)
        .expect_err("the pack tool signs no door at another layout");
    let LoadError::PlaneLayout {
        stated: said,
        host: read,
        ..
    } = &refused
    else {
        panic!("the restated door is refused for its layout: {refused:?}");
    };
    assert_eq!((*said, *read), (stated, host), "both layouts, named");
    assert!(
        refused
            .to_string()
            .contains("rebuild against this busbar-contract"),
        "{refused}"
    );
    let linked = LinkedRow::of_raw(LAID_DOOR)
        .and_then(|row| load_linked::<Plane>(&row, s.bind(&d, "red-layout")).map(|_| ()))
        .expect_err("a linked plane at another layout is refused");
    assert_eq!(linked, refused, "the same refusal, linked");
}

fn as_kind<K: Kind>(s: &Subject) -> (Option<LoadError>, Option<LoadError>) {
    let d = dispatcher();
    let linked = load::<K>(s, Leg::Linked, s.bind(&d, "red-kind-linked")).err();
    let dropped = load::<K>(s, Leg::Dropped, s.bind(&d, "red-kind-dropped")).err();
    (linked, dropped)
}

pub fn red_wrong_kind(s: &Subject) {
    let own = s.kind();
    by_kind!(own, K => {
        let d = dispatcher();
        load::<K>(s, Leg::Linked, s.bind(&d, "honest-linked")).expect("the honest door loads linked");
        load::<K>(s, Leg::Dropped, s.bind(&d, "honest-dropped"))
            .expect("the honest library loads dropped in");
    });
    for want in KINDS.into_iter().filter(|k| *k != own) {
        let (linked, dropped) = by_kind!(want, K => as_kind::<K>(s));
        assert_eq!(
            linked,
            Some(LoadError::ManifestKind { stated: own, want }),
            "the {own:?} door asked for as {want:?}, linked"
        );
        assert_eq!(
            dropped,
            Some(LoadError::ManifestKind { stated: own, want }),
            "the {own:?} library asked for as {want:?}, dropped in"
        );
    }
}

fn head(op: u32, size: usize) -> ServiceHead {
    ServiceHead {
        size: u32::try_from(size).unwrap_or(u32::MAX),
        op,
        handle: CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        },
    }
}

fn out() -> ServiceOut {
    // SAFETY: a plain repr(C) value of integers and a NULL/0 string: all-zero is valid.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    out.size = std::mem::size_of::<ServiceOut>() as u32;
    out
}

fn answered(raw: RawOutcome, o: &ServiceOut) -> (Outcome, u64, String) {
    let text = if o.error.ptr.is_null() {
        String::new()
    } else {
        // SAFETY: the host's text, `'static` (interned) or held for the call.
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) })
            .into_owned()
    };
    (raw.outcome(), o.value, text)
}

fn establish<K: Kind>(p: &Plugin<K>, need: u32, target: &str) -> (Outcome, u64, String) {
    let none = AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    };
    let i = EstablishIn {
        head: head(service::ESTABLISH, std::mem::size_of::<EstablishIn>()),
        need,
        timeout_ms: 5_000,
        target: AbiStr {
            ptr: target.as_ptr(),
            len: target.len(),
        },
        within: none,
        member: none,
    };
    let mut o = out();
    let f = CONN_SLOTS.establish.expect("the host offers ESTABLISH");
    // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
    let raw = unsafe {
        f(
            p.inner.ctx(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
    answered(raw, &o)
}

fn io<K: Kind>(p: &Plugin<K>, stream: u64, write: bool) -> (Outcome, u64, String) {
    let mut buf = *b"x";
    let (op, f) = if write {
        (service::WRITE, CONN_SLOTS.write)
    } else {
        (service::READ, CONN_SLOTS.read)
    };
    let i = IoIn {
        head: head(op, std::mem::size_of::<IoIn>()),
        stream,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
    };
    let mut o = out();
    // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
    let raw = unsafe {
        f.expect("the host offers READ and WRITE")(
            p.inner.ctx(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
    answered(raw, &o)
}

fn close_stream<K: Kind>(p: &Plugin<K>, stream: u64) -> (Outcome, u64, String) {
    let i = StreamIn {
        head: head(service::CLOSE, std::mem::size_of::<StreamIn>()),
        stream,
    };
    let mut o = out();
    // SAFETY: the local input, exclusive output, nested buffers and strings live through this crossing.
    let raw = unsafe {
        CONN_SLOTS.close.expect("the host offers CLOSE")(
            p.inner.ctx(),
            std::ptr::from_ref(&i).cast::<c_void>(),
            &mut o,
        )
    };
    answered(raw, &o)
}

fn connected<K: Kind>(table: &Arc<dyn DeclaredConns>, instance: &str) -> Plugin<K> {
    let d = dispatcher();
    let row = LinkedRow::of_raw(CONNECTED_DOOR).expect("the restated door states its Statement");
    load_linked::<K>(
        &row,
        Bind {
            conns: ConnTable::Host(Arc::clone(table)),
            ..bind(&d, instance)
        },
    )
    .expect("the door with a need of its own binds over the table")
}

pub fn red_undeclared_need(s: &Subject) {
    let _held = CONNECTED.hold(with_an_outbound_need(real_door(s)));
    let (table, _listening, at) = connection_fixture(s, CONNECTED_DOOR);
    let undeclared = ConnError::UndeclaredNeed.text();
    by_kind!(s.kind(), K => {
        let p = connected::<K>(&table, "red-need");
        let (outcome, stream, text) = establish(&p, 0, &at);
        assert_eq!(outcome, Outcome::Ready, "the declared need opens: {text}");
        assert_eq!(close_stream(&p, stream).0, Outcome::Ready);
        for need in [1, u32::MAX] {
            let (outcome, _, text) = establish(&p, need, &at);
            assert_eq!(
                (outcome, text.as_str()),
                (Outcome::Refused, undeclared),
                "a connection over need {need}, never declared"
            );
        }
    });
}

pub fn red_cross_instance_conn(s: &Subject) {
    let _held = CONNECTED.hold(with_an_outbound_need(real_door(s)));
    let (table, _listening, at) = connection_fixture(s, CONNECTED_DOOR);
    let not_owner = ConnError::NotOwner.text();
    by_kind!(s.kind(), K => {
        let owner = connected::<K>(&table, "red-conn-owner");
        let other = connected::<K>(&table, "red-conn-other");
        let (outcome, stream, text) = establish(&owner, 0, &at);
        assert_eq!(outcome, Outcome::Ready, "the owner opens its declared need: {text}");
        assert_eq!(io(&owner, stream, true).0, Outcome::Ready, "the owner writes on its own");
        for (what, (outcome, _, text)) in [
            ("write", io(&other, stream, true)),
            ("read", io(&other, stream, false)),
            ("close", close_stream(&other, stream)),
        ] {
            assert_eq!(
                (outcome, text.as_str()),
                (Outcome::Refused, not_owner),
                "another instance's {what} of the owner's connection"
            );
        }
        assert_eq!(
            io(&owner, stream, true).0,
            Outcome::Ready,
            "the owner's connection is untouched by the refused calls"
        );
        assert_eq!(close_stream(&owner, stream).0, Outcome::Ready);
    });
}
