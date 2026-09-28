// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

const A: InstanceId = InstanceId(1);
const B: InstanceId = InstanceId(2);
const NEED: NeedId = NeedId(0);

fn slab() -> ConnSlab<&'static str> {
    let s = ConnSlab::default();
    s.declare(A, NEED);
    s.declare(B, NEED);
    s
}

/// The owner reaches its own connection, with the need it opened it for.
#[test]
fn the_owner_reaches_its_connection() {
    let s = slab();
    let conn = s.insert(A, NEED, "a's").unwrap();
    let (need, state) = s.get(A, conn).unwrap();
    assert_eq!((need, *state), (NEED, "a's"));
}

/// RED ARM — a CROSS-INSTANCE id is refused, on every operation, with its own refusal text; the
/// owner's connection is untouched by the attempt.
#[test]
fn another_instances_connection_is_refused() {
    let s = slab();
    let conn = s.insert(A, NEED, "a's").unwrap();
    assert_eq!(s.get(B, conn).unwrap_err(), ConnError::NotOwner);
    assert_eq!(s.remove(B, conn).unwrap_err(), ConnError::NotOwner);
    assert_eq!(
        ConnError::NotOwner.to_string(),
        "the connection belongs to another plugin instance"
    );
    assert!(s.get(A, conn).is_ok(), "the owner's connection stands");
}

/// RED ARM — a CLOSED id is refused, and a later connection that reuses its slot is not reached
/// through it: the id carries its generation.
#[test]
fn a_closed_connection_is_refused_and_its_slot_reuse_is_not_reached() {
    let s = slab();
    let conn = s.insert(A, NEED, "first").unwrap();
    assert_eq!(*s.remove(A, conn).unwrap(), "first");
    assert_eq!(s.get(A, conn).unwrap_err(), ConnError::Closed);
    assert_eq!(s.remove(A, conn).unwrap_err(), ConnError::Closed);
    let reused = s.insert(A, NEED, "second").unwrap();
    assert_ne!(reused, conn, "the slot is reused under a new generation");
    assert_eq!(s.get(A, conn).unwrap_err(), ConnError::Closed);
    assert_eq!(*s.get(A, reused).unwrap().1, "second");
    assert_eq!(s.get(A, ConnId(0)).unwrap_err(), ConnError::Closed);
    assert_eq!(ConnError::Closed.to_string(), "the connection is closed");
}

/// RED ARM — a need the caller never DECLARED opens nothing, even when another instance declared
/// the same number.
#[test]
fn an_undeclared_need_opens_nothing() {
    let s: ConnSlab<()> = ConnSlab::default();
    s.declare(B, NeedId(3));
    assert_eq!(
        s.insert(A, NeedId(3), ()).unwrap_err(),
        ConnError::UndeclaredNeed
    );
    assert_eq!(s.check_need(A, NeedId(3)), Err(ConnError::UndeclaredNeed));
    assert_eq!(s.check_need(B, NeedId(3)), Ok(()));
    assert_eq!(
        ConnError::UndeclaredNeed.to_string(),
        "the plugin did not declare this need"
    );
}
