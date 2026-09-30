// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR SLOTS, both ways: an instance whose Statement declares a need is declared on the
//! host's one connection table at bind (the whole need, under its Statement index) and handed the
//! slots, whose `ESTABLISH` reaches the table under its own identity; an instance that declares no
//! need is handed no table, and the table refuses an open under its identity.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::conn::connector::{service, EstablishIn, Need, DIRECTION_OUTBOUND};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome, RawOutcome};
use busbar_contract::abi::mechanism::door::{Door, Statement};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::conn::{
    ConnError, ConnFacts, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc,
    Piece,
};

use super::CONN_SLOTS;
use crate::dispatch::load::validate_door;
use crate::dispatch::{Adopter, Bind, NoSink, Plugin, NO_BLOB};
use crate::dispatch_test_plugin as plug;
use crate::dispatch_tests::TestKind;

/// A connection table that records what reached it, ownership kept by the shared [`ConnSlab`].
#[derive(Default)]
struct Recording {
    slab: ConnSlab<()>,
    declared: Mutex<Vec<(InstanceId, NeedId, ReadNeed)>>,
    opened: Mutex<Vec<(InstanceId, NeedId, String)>>,
}

impl DeclaredConns for Recording {
    fn declare(&self, owner: InstanceId, need: NeedId, spec: &ReadNeed) -> Result<(), ConnError> {
        self.slab.declare(owner, need);
        self.declared
            .lock()
            .unwrap()
            .push((owner, need, spec.clone()));
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
}

impl Conns for Recording {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        let id = self.slab.insert(caller, need, ())?;
        self.opened
            .lock()
            .unwrap()
            .push((caller, need, desc.target.to_owned()));
        Ok(id)
    }
    fn write(&self, _: InstanceId, _: ConnId, _: &[u8], _: bool) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn read(&self, _: InstanceId, _: ConnId, _: u64, _: &mut [u8]) -> Result<Piece, ConnError> {
        Err(ConnError::Closed)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Closed)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        Err(ConnError::Closed)
    }
    fn close(&self, _: InstanceId, _: ConnId) -> Result<(), ConnError> {
        Ok(())
    }
}

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

static NEEDS: [Need; 1] = [Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: 0,
    transport: abi_str("sock"),
    auth: NONE,
    target_from: abi_str("settings.upstream"),
    trust_from: NONE,
    details: NO_BLOB,
}];

/// The test plugin's door, its Statement declaring `needs`, bound over `table`.
fn bound(needs: &'static [Need], table: &Arc<Recording>) -> Plugin<TestKind> {
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    let door: &'static Door = Box::leak(Box::new(Door {
        statement: st,
        ..real
    }));
    let v = validate_door::<TestKind>(door).expect("the door validates");
    let conns: Arc<dyn DeclaredConns> = table.clone();
    Plugin::bind(
        v,
        None,
        Bind {
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: Some(conns),
        },
    )
    .expect("the instance binds")
}

/// `ESTABLISH` through the slots, under `p`'s context, for `need` at `target`.
fn establish(p: &Plugin<TestKind>, need: u32, target: &'static str) -> ServiceOut {
    let i = EstablishIn {
        head: ServiceHead {
            size: std::mem::size_of::<EstablishIn>() as u32,
            op: service::ESTABLISH,
            handle: CompletionHandle {
                ticket: Ticket::NONE,
                seq: 0,
                _reserved: 0,
            },
        },
        need,
        _reserved: 0,
        target: abi_str(target),
    };
    // SAFETY: an all-zero `ServiceOut` is a valid value the slot overwrites.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    let slot = CONN_SLOTS.establish.expect("ESTABLISH is served");
    let _: RawOutcome = slot(p.inner.ctx(), std::ptr::from_ref(&i).cast(), &mut out);
    out
}

/// RED: the instance that declares a need is declared on the table at bind — the whole need, its
/// target source intact — handed the slots, and `ESTABLISH` opens it under its own identity.
#[test]
fn an_instance_with_a_declared_need_is_declared_and_its_establish_reaches_the_table() {
    let table = Arc::new(Recording::default());
    let p = bound(&NEEDS, &table);
    assert!(!p.inner.conns_table().is_null(), "it is handed the slots");
    let declared = table.declared.lock().unwrap().clone();
    assert_eq!(declared.len(), 1);
    let (owner, need, spec) = &declared[0];
    assert_eq!((*owner, *need), (p.instance(), NeedId(0)));
    assert_eq!(spec.direction, DIRECTION_OUTBOUND);
    assert_eq!(spec.transport, "sock");
    assert_eq!(
        spec.target_from, "settings.upstream",
        "the target source reaches declare intact"
    );
    let out = establish(&p, 0, "127.0.0.1:9");
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Ready));
    assert_eq!(
        table.opened.lock().unwrap().as_slice(),
        &[(p.instance(), NeedId(0), "127.0.0.1:9".to_owned())]
    );
}

/// RED: an instance that declares no need is handed no table, its slots (reached anyway) answer
/// that it is unarmed, and the table refuses an open under its identity as undeclared.
#[test]
fn an_instance_without_a_need_is_handed_no_table_and_its_open_is_undeclared() {
    let table = Arc::new(Recording::default());
    let p = bound(&[], &table);
    assert!(p.inner.conns_table().is_null(), "no need, no table");
    assert!(table.declared.lock().unwrap().is_empty());
    let out = establish(&p, 0, "127.0.0.1:9");
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Refused));
    assert_eq!(
        table.open(p.instance(), NeedId(0), &OpenDesc::default()),
        Err(ConnError::UndeclaredNeed)
    );
    assert_ne!(
        bound(&NEEDS, &table).instance(),
        p.instance(),
        "every bind mints its own identity"
    );
}
