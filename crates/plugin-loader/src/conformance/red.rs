// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMISSION AND CONNECTION RED ARMS every plugin's run carries, whatever its kind (`BUSBAR-1.6.0.md`
//! §2: a plugin is admitted only as the Statement its row or signed manifest states, only as the
//! kind it is asked for, and it reaches the network only over the needs it declared, on
//! connections of its own instance). Each arm drives the plugin's own door into the misbehaviour
//! and requires the host to refuse it, and each keeps an honest twin that must pass beside it:
//!
//! * [`red_statement`]: the door under a row or manifest stating another Statement (one byte off),
//!   and the door restated with another version under its honest row, are refused
//!   ([`LoadError::StatementMismatch`]), linked and dropped in;
//! * [`red_wrong_kind`]: the door asked for as every other kind is refused, linked
//!   ([`LoadError::WrongKind`]) and dropped in, before `dlopen` ([`LoadError::ManifestKind`]);
//! * [`red_undeclared_need`]: the door's instance, bound over a connection table, establishing a
//!   connection over a need its Statement never declared is refused (`UndeclaredNeed`), as its
//!   declared need opens;
//! * [`red_cross_instance_conn`]: one instance writing, reading or closing a connection another
//!   instance of the door opened is refused (`NotOwner`), and the owner's connection is untouched.
//!
//! The connection arms bind the door restated with one outbound need of its own (as
//! [`super::red_no_table`] restates it, [`super::connection_fixture`]), over the loader's test table
//! dialing a listener of the arm's own on loopback, and call the HOST's connector slots on the instance's own context, the
//! calls the plugin makes through the tables `open` hands it.

use std::os::raw::c_void;
use std::sync::Arc;

use busbar_contract::abi::host::conn::connector::{service, EstablishIn, IoIn, StreamIn};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, DoorFn, Statement};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::conn::{ConnError, DeclaredConns};

use super::{
    bind, connection_fixture, dispatcher, load, real_door, with_an_outbound_need, Auth, Export,
    Hook, Leg, Plane, Restated, Secret, Store, Subject, Transport,
};
use crate::dispatch::conn_services::CONN_SLOTS;
use crate::dispatch::{
    load_dropped, load_linked, Bind, ConnTable, Kind, LinkedRow, LoadError, Plugin,
};

static VERSIONED: Restated = Restated::new();
static CONNECTED: Restated = Restated::new();

extern "C" fn versioned_door() -> *const Door {
    VERSIONED.get()
}
extern "C" fn connected_door() -> *const Door {
    CONNECTED.get()
}

/// Every kind the host has.
const KINDS: [KindCode; 7] = [
    KindCode::Store,
    KindCode::Secret,
    KindCode::Auth,
    KindCode::Hook,
    KindCode::Export,
    KindCode::Plane,
    KindCode::Transport,
];

/// The version the restated door states instead of its own.
const OTHER_VERSION: &str = "0.0.0-conformance-restated";

/// The real door restated with another version in its Statement.
fn with_another_version(real: Door) -> Door {
    // SAFETY: a door's Statement is `'static`; only its version is restated.
    let st: Statement = unsafe { real.statement.read_unaligned() };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        version: AbiStr {
            ptr: OTHER_VERSION.as_ptr(),
            len: OTHER_VERSION.len(),
        },
        ..st
    }));
    Door {
        statement: st,
        ..real
    }
}

/// **RED: a door whose Statement is not the one its row or signed manifest states is refused, both
/// ways.** The honest door loads linked and dropped in; under a rendering one byte off it is
/// refused linked and dropped in; the door restated with another version is refused under its
/// honest row. Every refusal is [`LoadError::StatementMismatch`].
///
/// # Panics
/// When a mismatched door loads, or the honest one does not.
pub fn red_statement(s: &Subject) {
    let stated = s.stated();
    let mut lying = stated.clone();
    let last = lying.len() - 1;
    lying[last] ^= 1;
    VERSIONED.set(with_another_version(real_door(s)));
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
            load_dropped::<K>(&s.cdylib(), &lying, s.bind(&d, "red-dropped")).map(|_| ()).err(),
            Some(LoadError::StatementMismatch),
            "a signed manifest stating another Statement is refused"
        );
        let row = LinkedRow { statement: stated.clone(), door: versioned_door as DoorFn };
        assert_eq!(
            load_linked::<K>(&row, s.bind(&d, "red-restated")).map(|_| ()).err(),
            Some(LoadError::StatementMismatch),
            "a door stating another version than its row is refused"
        );
    });
}

/// The door asked for as kind `want`: the linked refusal and the dropped-in one.
fn as_kind<K: Kind>(s: &Subject) -> (Option<LoadError>, Option<LoadError>) {
    let d = dispatcher();
    let linked = load::<K>(s, Leg::Linked, s.bind(&d, "red-kind-linked")).err();
    let dropped = load::<K>(s, Leg::Dropped, s.bind(&d, "red-kind-dropped")).err();
    (linked, dropped)
}

/// **RED: a door asked for as another kind is refused, both ways, for every kind.** For each kind
/// the door is not, the linked row is refused ([`LoadError::WrongKind`]) and the dropped-in library
/// is refused before `dlopen` ([`LoadError::ManifestKind`]); asked for as its own kind it loads,
/// both ways.
///
/// # Panics
/// When the door loads as another kind, or not as its own.
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
            Some(LoadError::WrongKind { door: own, want }),
            "the {own:?} door asked for as {want:?}, linked"
        );
        assert_eq!(
            dropped,
            Some(LoadError::ManifestKind { stated: own, want }),
            "the {own:?} library asked for as {want:?}, dropped in"
        );
    }
}

/// A head for connector service `op`, `size` bytes, on no ticket.
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

/// An empty service `out`.
fn out() -> ServiceOut {
    // SAFETY: a plain repr(C) value of integers and a NULL/0 string: all-zero is valid.
    unsafe { std::mem::zeroed() }
}

/// A host slot's answer: its outcome, scalar and text.
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

/// `ESTABLISH` of `need` at `target`, on `p`'s own context, as the plugin calls it.
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
    let raw = f(
        p.inner.ctx(),
        std::ptr::from_ref(&i).cast::<c_void>(),
        &mut o,
    );
    answered(raw, &o)
}

/// `WRITE` (`write`) or `READ` of `stream`, on `p`'s own context.
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
    let raw = f.expect("the host offers READ and WRITE")(
        p.inner.ctx(),
        std::ptr::from_ref(&i).cast::<c_void>(),
        &mut o,
    );
    answered(raw, &o)
}

/// `CLOSE` of `stream`, on `p`'s own context.
fn close_stream<K: Kind>(p: &Plugin<K>, stream: u64) -> (Outcome, u64, String) {
    let i = StreamIn {
        head: head(service::CLOSE, std::mem::size_of::<StreamIn>()),
        stream,
    };
    let mut o = out();
    let raw = CONN_SLOTS.close.expect("the host offers CLOSE")(
        p.inner.ctx(),
        std::ptr::from_ref(&i).cast::<c_void>(),
        &mut o,
    );
    answered(raw, &o)
}

/// The door restated with one outbound need, bound linked as `instance` over `table`.
fn connected<K: Kind>(table: &Arc<dyn DeclaredConns>, instance: &str) -> Plugin<K> {
    let d = dispatcher();
    let row = LinkedRow::of(connected_door).expect("the restated door states its Statement");
    load_linked::<K>(
        &row,
        Bind {
            conns: ConnTable::Host(Arc::clone(table)),
            ..bind(&d, instance)
        },
    )
    .expect("the door with a need of its own binds over the table")
}

/// **RED: a connection over a need the plugin never declared is refused.** The door, restated with
/// one outbound need (need 0), is bound over the test table; on its own context, ESTABLISH of
/// need 0 to a loopback listener opens (the GREEN twin), and ESTABLISH of need 1 and of the
/// highest need index is REFUSED, naming the undeclared need.
///
/// # Panics
/// When an undeclared need opens, or the declared one does not.
pub fn red_undeclared_need(s: &Subject) {
    CONNECTED.set(with_an_outbound_need(real_door(s)));
    let (table, _listening, at) = connection_fixture(s, connected_door);
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

/// **RED: a plugin instance using a connection another instance opened is refused.** Two instances
/// of the door, restated with one outbound need, are bound over ONE table; the first opens
/// a connection to a loopback listener and writes on it (the GREEN twin); the second's WRITE, READ
/// and CLOSE of that connection are each REFUSED, naming the other owner, and the first's
/// connection still writes after them.
///
/// # Panics
/// When an instance reaches another's connection, or the owner cannot use its own.
pub fn red_cross_instance_conn(s: &Subject) {
    CONNECTED.set(with_an_outbound_need(real_door(s)));
    let (table, _listening, at) = connection_fixture(s, connected_door);
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
