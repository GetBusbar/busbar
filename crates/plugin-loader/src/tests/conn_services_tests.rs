// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR SLOTS, both ways: an instance whose Statement declares a need is handed the slots
//! and its needs are declared on the host's one connection table (the whole need, under its
//! Statement index) — a need whose `target_from` names a config path at `open` and every `refresh`,
//! pinned to what the path resolves to in the settings (ARCHITECT ruling 2026-09-30 on the conns
//! fill, option A); `ESTABLISH` reaches the table under the instance's own identity. An instance
//! that declares no need is handed no table, and the table refuses an open under its identity.

use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::conn::connector::{service, EstablishIn, Need, DIRECTION_OUTBOUND};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{Door, Statement};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, RefreshIn};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::conn::{
    ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc, Piece,
};
use busbar_contract::transport::ConnFacts;

use super::CONN_SLOTS;
use crate::dispatch::load::validate_door;
use crate::dispatch::{in_head, out_head, Adopter, Bind, Frame, NoSink, Plugin, NO_BLOB};
use crate::dispatch_test_plugin as plug;
use crate::dispatch_tests::TestKind;

/// One declaration as it reached the table: owner, need, the need, the target it resolved to.
type Declared = (InstanceId, NeedId, ReadNeed, Option<String>);

/// A connection table that records what reached it, ownership kept by the shared [`ConnSlab`].
#[derive(Default)]
struct Recording {
    slab: ConnSlab<()>,
    declared: Mutex<Vec<Declared>>,
    opened: Mutex<Vec<(InstanceId, NeedId, String)>>,
}

impl DeclaredConns for Recording {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared
            .lock()
            .unwrap()
            .push((owner, need, spec.clone(), target.map(str::to_owned)));
        if !spec.target_from.is_empty() && target.is_none() {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
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

const NEEDS: [Need; 1] = [Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: 0,
    transport: abi_str("sock"),
    auth: NONE,
    target_from: abi_str("settings.upstream"),
    trust_from: NONE,
    details: NO_BLOB,
    timeout_ms: 0,
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

/// A JSON settings blob over `json`.
fn settings(json: &'static [u8]) -> Blob {
    Blob {
        ptr: json.as_ptr(),
        len: json.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

/// `open` with `json` as the instance's settings, ticket-less.
fn open_with(p: &Plugin<TestKind>, json: &'static [u8]) -> Outcome {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: settings(json),
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
        },
    );
    p.call(slot::OPEN, &mut f).outcome
}

/// `refresh` with `json` as the instance's new settings, ticket-less.
fn refresh_with(p: &Plugin<TestKind>, json: &'static [u8]) -> Outcome {
    let mut f = Frame::new(
        RefreshIn {
            head: in_head(),
            generation: 2,
            settings: settings(json),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    );
    p.call(slot::REFRESH, &mut f).outcome
}

/// The targets `table` was last declared with for `p`'s need 0, oldest first.
fn targets(table: &Recording, p: &Plugin<TestKind>) -> Vec<Option<String>> {
    table
        .declared
        .lock()
        .unwrap()
        .iter()
        .filter(|(owner, need, _, _)| (*owner, *need) == (p.instance(), NeedId(0)))
        .map(|(_, _, _, target)| target.clone())
        .collect()
}

/// RED: the instance that declares a need is handed the slots; its config-targeted need is not
/// declared at bind (an establish before `open` is refused as undeclared), and at `open` it is
/// declared whole — its target source intact — pinned to the target its `target_from` resolves to
/// in the settings, after which `ESTABLISH` opens it under the instance's own identity.
#[test]
fn an_instance_with_a_declared_need_is_declared_and_its_establish_reaches_the_table() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert!(!p.inner.conns_table().is_null(), "it is handed the slots");
    assert!(
        table.declared.lock().unwrap().is_empty(),
        "a config-targeted need waits for its settings"
    );
    assert_eq!(
        establish(&p, 0, "127.0.0.1:9").outcome,
        RawOutcome::of(Outcome::Refused),
        "an establish before open is undeclared"
    );
    assert_eq!(open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#), Outcome::Ready);
    let declared = table.declared.lock().unwrap().clone();
    assert_eq!(declared.len(), 1);
    let (owner, need, spec, target) = &declared[0];
    assert_eq!((*owner, *need), (p.instance(), NeedId(0)));
    assert_eq!(spec.direction, DIRECTION_OUTBOUND);
    assert_eq!(spec.transport, "sock");
    assert_eq!(
        spec.target_from, "settings.upstream",
        "the target source reaches declare intact"
    );
    assert_eq!(target.as_deref(), Some("127.0.0.1:9"), "pinned to its setting");
    let out = establish(&p, 0, "127.0.0.1:9");
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Ready));
    assert_eq!(
        table.opened.lock().unwrap().as_slice(),
        &[(p.instance(), NeedId(0), "127.0.0.1:9".to_owned())]
    );
}

/// RED: a `refresh` that changes the setting re-declares the need at the new target, and one whose
/// `target_from` resolves to nothing declares it without a target, which the table refuses.
#[test]
fn a_refresh_re_declares_a_config_targeted_need_at_its_new_target() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert_eq!(open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#), Outcome::Ready);
    assert_eq!(refresh_with(&p, br#"{"upstream":"127.0.0.2:9"}"#), Outcome::Ready);
    assert_eq!(refresh_with(&p, br#"{"other":"127.0.0.3:9"}"#), Outcome::Ready);
    assert_eq!(
        targets(&table, &p),
        vec![
            Some("127.0.0.1:9".to_owned()),
            Some("127.0.0.2:9".to_owned()),
            None
        ]
    );
}

/// `target_from` names `settings.<key>[.<key>...]`, walked to a non-empty string.
#[test]
fn a_target_from_path_resolves_only_to_a_non_empty_string_under_settings() {
    use crate::dispatch::plugin::resolve_target;
    let doc = serde_json::json!({
        "upstream": "db:5432",
        "nested": {"url": "h:1"},
        "n": 3,
        "e": "",
    });
    assert_eq!(resolve_target(&doc, "settings.upstream").as_deref(), Some("db:5432"));
    assert_eq!(resolve_target(&doc, "settings.nested.url").as_deref(), Some("h:1"));
    for miss in ["settings.n", "settings.e", "settings.absent", "upstream", "settings.nested"] {
        assert_eq!(resolve_target(&doc, miss), None, "{miss}");
    }
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
        bound(Box::leak(Box::new(NEEDS)), &table).instance(),
        p.instance(),
        "every bind mints its own identity"
    );
}
