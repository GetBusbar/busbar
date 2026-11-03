// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::conn::connector::{
    service, EstablishIn, Need, DIRECTION_INBOUND, DIRECTION_OUTBOUND, KEEP_NAMED,
};
use busbar_contract::abi::host::service::{ServiceHead, ServiceOut};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, Outcome, RawOutcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{Door, Statement};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, RefreshIn};
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::conn::{
    ConnCause, ConnError, ConnId, ConnSlab, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc,
    Piece,
};
use busbar_contract::transport::ConnFacts;

use super::CONN_SLOTS;
use crate::dispatch::load::validate_door;
use crate::dispatch::{in_head, out_head, Adopter, Bind, Frame, NoSink, Plugin, NO_BLOB};
use crate::dispatch_test_plugin as plug;
use crate::dispatch_tests::TestKind;

type Declared = (InstanceId, NeedId, ReadNeed, Option<String>, Option<String>);

/// A connection table that records what reached it, ownership kept by the shared [`ConnSlab`].
#[derive(Default)]
struct Recording {
    slab: ConnSlab<()>,
    declared: Mutex<Vec<Declared>>,
    opened: Mutex<Vec<(InstanceId, NeedId, String)>>,
    /// The registration every open named (`OpenDesc::member`), in order.
    named: Mutex<Vec<String>>,
    /// The schemes no loaded transport serves, as this table answers [`DeclaredConns::serves`].
    unserved: Vec<&'static str>,
    /// Every program declaration: owner, need and the program.
    programs: Mutex<Vec<(InstanceId, NeedId, busbar_contract::conn::Program)>>,
    /// Every member-program declaration: owner, need and the members' programs.
    members: Mutex<Vec<MemberDeclared>>,
    /// Every instance whose authority the host was asked to hold, and how many of its needs had
    /// been declared by then.
    held: Mutex<Vec<(InstanceId, usize)>>,
    /// Every instance the table was told is gone ([`DeclaredConns::forget`]), in order.
    forgotten: Mutex<Vec<InstanceId>>,
    /// The table refuses every CONFIG-FREE need (no `target_from`, no `trust_from`): the one the
    /// loader declares at bind.
    refuse_config_free: bool,
}

type MemberDeclared = (
    InstanceId,
    NeedId,
    Vec<(String, busbar_contract::conn::Program)>,
);

impl DeclaredConns for Recording {
    fn forget(&self, owner: InstanceId) {
        self.forgotten.lock().unwrap().push(owner);
    }
    fn hold_authority(&self, owner: InstanceId) {
        let before = self
            .declared
            .lock()
            .unwrap()
            .iter()
            .filter(|d| d.0 == owner)
            .count();
        self.held.lock().unwrap().push((owner, before));
    }
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared.lock().unwrap().push((
            owner,
            need,
            spec.clone(),
            target.map(str::to_owned),
            trust.map(str::to_owned),
        ));

        if (!spec.target_from.is_empty() && target.is_none())
            || (!spec.trust_from.is_empty() && trust.is_none())
            || (self.refuse_config_free
                && spec.target_from.is_empty()
                && spec.trust_from.is_empty())
            || trust.is_some_and(|t| !t.starts_with("PEM"))
        {
            return Err(ConnError::Refused);
        }
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn serves_scheme(&self, transport: &str) -> bool {
        !self.unserved.contains(&transport)
    }
    fn declare_program(
        &self,
        owner: InstanceId,
        need: NeedId,
        _spec: &ReadNeed,
        program: &busbar_contract::conn::Program,
    ) -> Result<(), ConnError> {
        self.programs
            .lock()
            .unwrap()
            .push((owner, need, program.clone()));
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declare_member_programs(
        &self,
        owner: InstanceId,
        need: NeedId,
        _spec: &ReadNeed,
        programs: &[(String, busbar_contract::conn::Program)],
    ) -> Result<(), ConnError> {
        self.members
            .lock()
            .unwrap()
            .push((owner, need, programs.to_vec()));
        self.slab.declare(owner, need);
        Ok(())
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
        self.named.lock().unwrap().push(desc.member.to_owned());
        Ok(id)
    }
    fn write(
        &self,
        _: InstanceId,
        _: ConnId,
        _: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
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
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: core::ptr::null(),
    deny_response_headers_len: 0,
}];

fn bound(needs: &'static [Need], table: &Arc<Recording>) -> Plugin<TestKind> {
    bind_over(needs, table).expect("the instance binds")
}

fn bind_over(
    needs: &'static [Need],
    table: &Arc<Recording>,
) -> Result<Plugin<TestKind>, crate::dispatch::LoadError> {
    let conns: Arc<dyn DeclaredConns> = table.clone();
    bind_as(needs, crate::dispatch::ConnTable::Host(conns))
}

fn bind_as(
    needs: &'static [Need],
    conns: crate::dispatch::ConnTable,
) -> Result<Plugin<TestKind>, crate::dispatch::LoadError> {
    bind_as_kind::<TestKind>(needs, conns)
}

fn bind_as_kind<K: crate::dispatch::Kind>(
    needs: &'static [Need],
    conns: crate::dispatch::ConnTable,
) -> Result<Plugin<K>, crate::dispatch::LoadError> {
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement() };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        kind: K::CODE as u32,
        kind_abi: K::CODE.abi_version(),
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    let door: &'static Door = Box::leak(Box::new(unsafe {
        Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
            kind: K::CODE as u32,
            kind_abi: K::CODE.abi_version(),
            layout: K::CODE.layout_fingerprint(),
            statement: st,
            ..real.parts()
        })
    }));
    let v = validate_door::<K>(door).expect("the door validates");
    Plugin::bind(
        v,
        None,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns,
        },
    )
}

#[test]
fn a_serving_bind_of_a_networked_door_with_no_table_is_refused_by_name() {
    let refused = bind_as(
        Box::leak(Box::new(NEEDS)),
        crate::dispatch::ConnTable::NoNeeds,
    )
    .expect_err("a networked door serving with no table is refused");
    let name = "dispatch-test-plugin";
    assert_eq!(
        refused,
        crate::dispatch::LoadError::NoConnectionTable {
            plugin: name.to_owned(),
            needs: 1,
        }
    );
    assert_eq!(
        refused.to_string(),
        format!(
            "plugin '{name}' declares 1 connection need(s) and was bound with no connection table"
        )
    );
}

#[test]
fn a_probe_bind_with_no_table_binds_and_a_door_with_no_need_serves_with_none() {
    let p = bind_as(
        Box::leak(Box::new(NEEDS)),
        crate::dispatch::ConnTable::Probe,
    )
    .expect("a probe binds with no table");
    assert!(
        p.inner.conns_table().is_null(),
        "a probe is handed no slots"
    );
    let p = bind_as(&[], crate::dispatch::ConnTable::NoNeeds).expect("no need, no table");
    assert!(p.inner.conns_table().is_null());
}

fn establish(p: &Plugin<TestKind>, need: u32, target: &'static str) -> ServiceOut {
    establish_on(p, need, target, Ticket::NONE)
}

fn establish_on(
    p: &Plugin<TestKind>,
    need: u32,
    target: &'static str,
    ticket: Ticket,
) -> ServiceOut {
    establish_as(
        p,
        need,
        target,
        ticket,
        None,
        std::mem::size_of::<EstablishIn>(),
    )
}

fn establish_as(
    p: &Plugin<TestKind>,
    need: u32,
    target: &'static str,
    ticket: Ticket,
    member: Option<&'static str>,
    size: usize,
) -> ServiceOut {
    let i = EstablishIn {
        head: ServiceHead {
            size: size as u32,
            op: service::ESTABLISH,
            handle: CompletionHandle {
                ticket,
                seq: 0,
                _reserved: 0,
            },
        },
        need,
        timeout_ms: 0,
        target: abi_str(target),
        within: NONE,
        member: member.map_or(NONE, abi_str),
    };
    // SAFETY: an all-zero `ServiceOut` is a valid value the slot overwrites.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    out.size = std::mem::size_of::<ServiceOut>() as u32;
    let slot = CONN_SLOTS.establish.expect("ESTABLISH is served");
    let _: RawOutcome = unsafe { slot(p.inner.ctx(), std::ptr::from_ref(&i).cast(), &mut out) };
    out
}

fn settings(json: &'static [u8]) -> Blob {
    Blob {
        ptr: json.as_ptr(),
        len: json.len(),
        fmt: BLOB_JSON,
        flags: 0,
    }
}

fn open_with<K: crate::dispatch::Kind>(p: &Plugin<K>, json: &'static [u8]) -> Outcome {
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: settings(json),
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    p.call(slot::OPEN, &mut f).outcome
}

fn refresh_with<K: crate::dispatch::Kind>(p: &Plugin<K>, json: &'static [u8]) -> Outcome {
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

fn belongs_to<K: crate::dispatch::Kind>(p: &Plugin<K>, owner: InstanceId) -> bool {
    let supplier = crate::dispatch::handle::supplier_of(p.instance()).unwrap();
    crate::dispatch::handle::supplier_of(owner).is_some_and(|wake| std::ptr::eq(wake, supplier))
}

fn assert_generation_owners<K: crate::dispatch::Kind>(
    table: &Recording,
    p: &Plugin<K>,
    count: usize,
) {
    let owners: Vec<_> = table
        .declared
        .lock()
        .unwrap()
        .iter()
        .filter(|(owner, need, ..)| belongs_to(p, *owner) && *need == NeedId(0))
        .map(|(owner, ..)| *owner)
        .collect();
    assert_eq!(owners.len(), count);
    assert_eq!(owners[0], p.instance());
    for (index, owner) in owners.iter().enumerate() {
        assert!(
            !owners[..index].contains(owner),
            "each generation owns a distinct authority"
        );
    }
}

fn targets(table: &Recording, p: &Plugin<TestKind>) -> Vec<Option<String>> {
    table
        .declared
        .lock()
        .unwrap()
        .iter()
        .filter(|(owner, need, ..)| belongs_to(p, *owner) && *need == NeedId(0))
        .map(|(_, _, _, target, _)| target.clone())
        .collect()
}

#[test]
fn a_need_over_an_unserved_scheme_refuses_the_load_naming_plugin_and_scheme() {
    let unserved = Arc::new(Recording {
        unserved: vec!["sock"],
        ..Recording::default()
    });
    let Err(refusal) = bind_over(Box::leak(Box::new(NEEDS)), &unserved) else {
        panic!("a need over an unserved scheme must refuse the load");
    };
    let crate::dispatch::LoadError::UnservedScheme {
        plugin,
        inbound,
        scheme,
    } = &refusal
    else {
        panic!("refused for the wrong reason: {refusal}");
    };
    assert_eq!(scheme, "sock");
    assert!(!inbound);
    assert!(!plugin.is_empty(), "the refusal names the plugin");
    let text = refusal.to_string();
    assert!(
        text.contains(plugin.as_str()) && text.contains("`sock`"),
        "{text}"
    );
    assert!(unserved.declared.lock().unwrap().is_empty());

    let served = Arc::new(Recording::default());
    assert!(bind_over(Box::leak(Box::new(NEEDS)), &served).is_ok());
}

#[test]
fn a_config_free_need_the_table_refuses_refuses_the_load_naming_plugin_and_need() {
    const CONFIG_FREE: [Need; 1] = [Need {
        target_from: NONE,
        ..NEEDS[0]
    }];
    let refusing = Arc::new(Recording {
        refuse_config_free: true,
        ..Recording::default()
    });
    let Err(refusal) = bind_over(Box::leak(Box::new(CONFIG_FREE)), &refusing) else {
        panic!("a config-free need the table refuses must refuse the load");
    };
    // SAFETY: the test door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement() };
    let plugin = String::from_utf8_lossy(
        crate::dispatch::plugin::str_bytes(st.name).expect("the test door is named"),
    )
    .into_owned();
    let text = refusal.to_string();
    assert!(
        text.contains(plugin.as_str())
            && text.contains("need 0")
            && text.contains("`sock`")
            && text.contains("refused"),
        "the refusal names the plugin, the need and why: {text}"
    );
    assert_eq!(
        refusing.declared.lock().unwrap().len(),
        1,
        "the need reached the table"
    );
    assert_eq!(
        refusing.forgotten.lock().unwrap().len(),
        1,
        "what the refused instance declared is forgotten"
    );

    let carrying = Arc::new(Recording::default());
    assert!(bind_over(Box::leak(Box::new(CONFIG_FREE)), &carrying).is_ok());
}

#[test]
fn an_inbound_need_over_an_unserved_scheme_refuses_the_load_naming_plugin_and_scheme() {
    const INBOUND: [Need; 1] = [Need {
        direction: DIRECTION_INBOUND,
        target_from: NONE,
        ..NEEDS[0]
    }];
    let unserved = Arc::new(Recording {
        unserved: vec!["sock"],
        ..Recording::default()
    });
    let Err(refusal) = bind_over(Box::leak(Box::new(INBOUND)), &unserved) else {
        panic!("an inbound need over an unserved scheme must refuse the load");
    };
    let crate::dispatch::LoadError::UnservedScheme {
        plugin,
        inbound,
        scheme,
    } = &refusal
    else {
        panic!("refused for the wrong reason: {refusal}");
    };
    assert_eq!(scheme, "sock");
    assert!(*inbound, "the refusal says the need is inbound");
    let text = refusal.to_string();
    assert!(
        text.contains(plugin.as_str()) && text.contains("inbound") && text.contains("`sock`"),
        "{text}"
    );
    assert!(unserved.declared.lock().unwrap().is_empty());

    let served = Arc::new(Recording::default());
    assert!(bind_over(Box::leak(Box::new(INBOUND)), &served).is_ok());
}

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
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    let declared = table.declared.lock().unwrap().clone();
    assert_eq!(declared.len(), 1);
    let (owner, need, spec, target, _) = &declared[0];
    assert_eq!((*owner, *need), (p.instance(), NeedId(0)));
    assert_eq!(spec.direction, DIRECTION_OUTBOUND);
    assert_eq!(spec.transport, "sock");
    assert_eq!(
        spec.target_from, "settings.upstream",
        "the target source reaches declare intact"
    );
    assert_eq!(
        target.as_deref(),
        Some("127.0.0.1:9"),
        "pinned to its setting"
    );
    let out = establish(&p, 0, "127.0.0.1:9");
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Ready));
    assert_eq!(
        table.opened.lock().unwrap().as_slice(),
        &[(p.instance(), NeedId(0), "127.0.0.1:9".to_owned())]
    );
}

#[test]
fn a_refresh_re_declares_a_config_targeted_need_at_its_new_target() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    assert_eq!(
        refresh_with(&p, br#"{"upstream":"127.0.0.2:9"}"#),
        Outcome::Ready
    );
    assert_eq!(
        refresh_with(&p, br#"{"other":"127.0.0.3:9"}"#),
        Outcome::Ready
    );
    assert_generation_owners(&table, &p, 3);
    assert_eq!(
        targets(&table, &p),
        vec![
            Some("127.0.0.1:9".to_owned()),
            Some("127.0.0.2:9".to_owned()),
            None
        ]
    );
}

const TRUSTING: [Need; 1] = [Need {
    target_from: NONE,
    trust_from: abi_str("settings.ca"),
    ..NEEDS[0]
}];

#[test]
fn a_trust_from_need_is_declared_with_its_settings_ca_at_open_and_every_refresh() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(TRUSTING)), &table);
    assert!(
        table.declared.lock().unwrap().is_empty(),
        "a need whose trust comes from config waits for its settings"
    );
    assert_eq!(open_with(&p, br#"{"ca":"PEM-A"}"#), Outcome::Ready);
    assert_eq!(refresh_with(&p, br#"{"ca":"PEM-B"}"#), Outcome::Ready);
    assert_eq!(refresh_with(&p, br#"{"other":"PEM-C"}"#), Outcome::Ready);
    assert_generation_owners(&table, &p, 3);
    let declared = table.declared.lock().unwrap().clone();
    let seen: Vec<(Option<String>, Option<String>)> = declared
        .iter()
        .filter(|(owner, need, ..)| belongs_to(&p, *owner) && *need == NeedId(0))
        .map(|(_, _, spec, target, trust)| {
            assert_eq!(
                spec.trust_from, "settings.ca",
                "the trust source reaches declare"
            );
            (target.clone(), trust.clone())
        })
        .collect();
    assert_eq!(
        seen,
        vec![
            (None, Some("PEM-A".to_owned())),
            (None, Some("PEM-B".to_owned())),
            (None, None),
        ]
    );
}

const NOT_A_PEM: &str = "NOT-A-PEM";

#[test]
fn an_open_whose_settings_ca_the_table_refuses_fails_naming_it() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(TRUSTING)), &table);
    let mut f = Frame::new(
        OpenIn {
            head: in_head(),
            host: std::ptr::null(),
            settings: settings(br#"{"ca":"NOT-A-PEM"}"#),
            secrets: std::ptr::null(),
            secrets_len: 0,
            generation: 1,
            err_buf: std::ptr::null_mut(),
            err_cap: 0,
        },
        OpenOut {
            head: out_head(),
            instance: std::ptr::null_mut(),
            err_len: 0,
        },
    );
    let c = p.call(slot::OPEN, &mut f);
    assert_eq!(
        c.outcome,
        Outcome::Failed,
        "a refused trust anchor fails the open"
    );
    let text = c.open_failure("trusting");
    assert!(text.contains("settings.ca"), "{text}");
    assert!(
        !text.contains(NOT_A_PEM),
        "the value is never repeated: {text}"
    );

    let good = bound(Box::leak(Box::new(TRUSTING)), &table);
    assert_eq!(open_with(&good, br#"{"ca":"PEM-A"}"#), Outcome::Ready);
}

const OWNED_TRUSTING: [Need; 1] = [Need {
    target_from: NONE,
    trust_from: abi_str("owned.agent_push.ca"),
    ..NEEDS[0]
}];

struct PlaneShaped;
impl crate::dispatch::Kind for PlaneShaped {
    const CODE: busbar_contract::abi::mechanism::KindCode =
        busbar_contract::abi::mechanism::KindCode::Plane;
    type Ops = busbar_contract::abi::mechanism::lifecycle::OpsHead;
    const TIMEOUT: Outcome = Outcome::Failed;
    fn context(st: &Statement) -> Result<Option<Box<crate::dispatch::Context>>, String> {
        <TestKind as crate::dispatch::Kind>::context(st)
    }
    fn check(
        answer: &crate::dispatch::Answer,
    ) -> Result<(), busbar_contract::abi::mechanism::check::Fault> {
        <TestKind as crate::dispatch::Kind>::check(answer)
    }
}

fn refresh_owning<K: crate::dispatch::Kind>(
    p: &Plugin<K>,
    json: &'static [u8],
    owned: &[u8],
) -> Outcome {
    use busbar_contract::abi::mechanism::call::BLOB_OCTETS;
    let extensions = busbar_contract::abi::mechanism::extensions::encode(&[(
        busbar_contract::abi::plane::EXT_OWNED,
        owned,
    )]);
    let mut head = in_head();
    head.extensions = Blob {
        ptr: extensions.as_ptr(),
        len: extensions.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    };
    let mut f = Frame::new(
        RefreshIn {
            head,
            generation: 2,
            settings: settings(json),
            secrets: std::ptr::null(),
            secrets_len: 0,
        },
        out_head(),
    );
    p.call(slot::REFRESH, &mut f).outcome
}

#[test]
fn an_owned_trust_from_resolves_against_the_owned_sections_alone() {
    let table = Arc::new(Recording::default());
    let conns: Arc<dyn DeclaredConns> = table.clone();
    let p = bind_as_kind::<PlaneShaped>(
        Box::leak(Box::new(OWNED_TRUSTING)),
        crate::dispatch::ConnTable::Host(conns),
    )
    .expect("the plane-shaped fixture binds");
    let decoy: &'static [u8] = br#"{"agent_push":{"ca":"PEM-IN-SETTINGS"},"owned":{"agent_push":{"ca":"PEM-IN-SETTINGS"}}}"#;
    assert_eq!(open_with(&p, decoy), Outcome::Ready);
    assert_eq!(
        refresh_owning(&p, decoy, br#"{"agent_push":{"ca":"PEM-OWNED"}}"#),
        Outcome::Ready
    );
    assert_eq!(refresh_with(&p, decoy), Outcome::Ready);
    let declared = table.declared.lock().unwrap().clone();
    assert_generation_owners(&table, &p, 3);
    let seen: Vec<Option<String>> = declared
        .iter()
        .filter(|(owner, need, ..)| belongs_to(&p, *owner) && *need == NeedId(0))
        .map(|(_, _, spec, _, trust)| {
            assert_eq!(spec.trust_from, "owned.agent_push.ca");
            trust.clone()
        })
        .collect();
    assert_eq!(
        seen,
        vec![None, Some("PEM-OWNED".to_owned()), None],
        "the settings are never read for an owned path"
    );
}

#[test]
fn recycling_one_instances_ticket_never_replays_anothers_establish() {
    use super::{forget, forget_worker};
    let first = Ticket {
        slot: 0,
        generation: 1,
    };
    let (one_table, two_table) = (
        Arc::new(Recording::default()),
        Arc::new(Recording::default()),
    );
    let one = bound(Box::leak(Box::new(NEEDS)), &one_table);
    let two = bound(Box::leak(Box::new(NEEDS)), &two_table);
    for p in [&one, &two] {
        assert_eq!(
            open_with(p, br#"{"upstream":"127.0.0.1:9"}"#),
            Outcome::Ready
        );
    }
    let opens = |t: &Recording| t.opened.lock().unwrap().len();
    let one_stream = establish_on(&one, 0, "127.0.0.1:9", first);
    let two_stream = establish_on(&two, 0, "127.0.0.1:9", first);
    assert_eq!(two_stream.outcome, RawOutcome::of(Outcome::Ready));
    assert_eq!((opens(&one_table), opens(&two_table)), (1, 1));

    drop(forget(one.instance(), first));
    let replayed = establish_on(&two, 0, "127.0.0.1:9", first);
    assert_eq!(
        (replayed.outcome, replayed.value),
        (two_stream.outcome, two_stream.value),
        "the other instance redeems its stored stream"
    );
    assert_eq!(
        opens(&two_table),
        1,
        "the other instance's establish never ran twice"
    );
    let rerun = establish_on(&one, 0, "127.0.0.1:9", first);
    assert_eq!(
        opens(&one_table),
        2,
        "the recycled instance's re-issue is a new call"
    );
    assert_ne!(rerun.value, one_stream.value);

    forget_worker(&[one.instance()], 0);
    let _ = establish_on(&two, 0, "127.0.0.1:9", first);
    assert_eq!(
        opens(&two_table),
        1,
        "a replaced worker forgets only its own instances"
    );
}

#[test]
fn a_config_program_is_declared_as_a_program() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert_eq!(
        open_with(
            &p,
            br#"{"upstream":{"command":"/usr/bin/server","args":["--serve"],"env":{"T":"v"}}}"#
        ),
        Outcome::Ready
    );
    assert_eq!(
        table.programs.lock().unwrap().as_slice(),
        &[(
            p.instance(),
            NeedId(0),
            busbar_contract::conn::Program {
                command: "/usr/bin/server".into(),
                cwd: None,
                args: vec!["--serve".into()],
                env: vec![("T".into(), "v".into())],
                env_refs: Vec::new(),
            }
        )]
    );
    assert!(
        targets(&table, &p).is_empty(),
        "no target string was declared"
    );
    assert_eq!(
        refresh_with(&p, br#"{"upstream":{"command":"server"}}"#),
        Outcome::Ready
    );
    let owners: Vec<_> = table
        .programs
        .lock()
        .unwrap()
        .iter()
        .map(|(owner, ..)| *owner)
        .collect();
    assert_eq!(
        owners,
        vec![p.instance()],
        "the open owns the program authority"
    );
    let refreshed = table.declared.lock().unwrap()[0].0;
    assert_ne!(refreshed, p.instance(), "refresh mints its own authority");
    assert!(belongs_to(&p, refreshed));
    assert_eq!(targets(&table, &p), vec![None], "a misspelled program");
    assert_eq!(table.programs.lock().unwrap().len(), 1);
}

#[test]
fn a_target_from_path_resolves_only_to_a_non_empty_string_under_settings() {
    use crate::dispatch::plugin::resolve_setting;
    let doc = serde_json::json!({
        "upstream": "db:5432",
        "nested": {"url": "h:1"},
        "n": 3,
        "e": "",
    });
    assert_eq!(
        resolve_setting(&doc, "settings.upstream").as_deref(),
        Some("db:5432")
    );
    assert_eq!(
        resolve_setting(&doc, "settings.nested.url").as_deref(),
        Some("h:1")
    );
    for miss in [
        "settings.n",
        "settings.e",
        "settings.absent",
        "upstream",
        "settings.nested",
    ] {
        assert_eq!(resolve_setting(&doc, miss), None, "{miss}");
    }
}

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

use std::collections::VecDeque;

use busbar_contract::abi::auth::AuthPoints;
use busbar_contract::abi::host::conn::connector::{
    IoIn, ReplyIn, ReplyPiece, RequestIn, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END,
    REPLY_HEAD, REQUEST_BODY, REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::host::service::ServiceFn;
use busbar_contract::abi::transport::FrameSpan;
use busbar_contract::auth_calls::{AuthField, Fielding, Fields, FieldsRequest, OutboundAuth};
use busbar_contract::conn::ConnAuth;
use busbar_contract::conn::PieceKind;
use busbar_contract::ids::StreamId;
use busbar_contract::redacted::Secret;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering as AtomicOrdering};

type Opened = (
    NeedId,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<(String, Vec<u8>)>,
    Vec<u8>,
);

/// A connection table whose needs are framed (or not), whose opens are recorded (or refused) and
/// whose reads answer a script, one piece and its bytes per read.
#[derive(Default)]
struct Scripted {
    slab: ConnSlab<()>,
    framed: bool,
    refuse: Option<ConnError>,
    opened: Mutex<Vec<Opened>>,
    /// The address set each open was stated within, in open order.
    within: Mutex<Vec<Vec<std::net::IpAddr>>>,
    opened_units: Mutex<Vec<u64>>,
    writes: Mutex<Vec<Vec<u8>>>,
    script: Mutex<VecDeque<(Piece, Vec<u8>)>>,
    /// Every upgrade call: the stream, the name offered and the trust reference.
    upgrades: Mutex<Vec<Upgrade>>,
    /// How many upgrade calls answer PENDING before one answers done.
    upgrade_pends: Mutex<u32>,
    /// Each upgrade call's verify-off request, in order.
    verify_offs: Mutex<Vec<bool>>,
    /// What `facts` answers; `None` = the stream is closed.
    facts: Mutex<Option<ConnFacts>>,
    /// Every read fails with this, the table naming this cause.
    failing: Option<(ConnError, ConnCause)>,
    /// The member binding every request is authenticated with (`auth_of`); `None` = none.
    member_auth: Option<busbar_contract::conn::ConnAuth>,
    /// The member binding every request this table carries is authed by (none = no binding).
    auth: Option<Arc<dyn OutboundAuth>>,
    /// An open reached the table while the calling thread held the connector's lock.
    opened_under_lock: AtomicBool,
    /// Every read that parked: the caller and the ticket it registered interest under, as the
    /// connector keeps them to wake.
    parked: Mutex<Vec<(InstanceId, u64)>>,
    /// Armed, a close parks here until released: a transport door wedged in its close.
    close_gate: Gate,
    /// Every dial is still connecting when its establish asks: `landed` answers PENDING.
    landing: bool,
    /// The independent dial and whole-request bounds every actual open received.
    timeouts: Mutex<Vec<(u64, u64)>>,
    declared_timeouts: Mutex<Vec<u64>>,
}

/// A door double's park: armed, the next caller notes it entered and waits for the release (at
/// most thirty seconds, so a test that never releases fails rather than hangs).
#[derive(Default)]
struct Gate {
    armed: AtomicBool,
    entered: AtomicBool,
    released: AtomicBool,
}

impl Gate {
    fn park(&self) {
        if !self.armed.load(AtomicOrdering::SeqCst) {
            return;
        }
        self.entered.store(true, AtomicOrdering::SeqCst);
        let since = std::time::Instant::now();
        while !self.released.load(AtomicOrdering::SeqCst)
            && since.elapsed() < std::time::Duration::from_secs(30)
        {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    fn entered_within(&self, wait: std::time::Duration) -> bool {
        let since = std::time::Instant::now();
        while !self.entered.load(AtomicOrdering::SeqCst) {
            if since.elapsed() > wait {
                return false;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        true
    }
}

type Upgrade = (ConnId, Option<String>, Option<String>);

impl DeclaredConns for Scripted {
    fn open_request(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        require_secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.timeouts
            .lock()
            .unwrap()
            .push((dial_timeout_ms, desc.timeout_ms));
        self.open_with_security(caller, need, desc, require_secure)
    }

    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
        self.declared_timeouts.lock().unwrap().push(spec.timeout_ms);
        self.slab.declare(owner, need);
        Ok(())
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.slab.check_need(owner, need).ok().map(Ok)
    }
    fn framed(&self, _: InstanceId, _: NeedId) -> bool {
        self.framed
    }
    fn serves_scheme(&self, _: &str) -> bool {
        true
    }
    fn upgrade_secure(
        &self,
        caller: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        _: u64,
    ) -> Result<(), ConnError> {
        self.slab.get(caller, conn)?;
        self.verify_offs.lock().unwrap().push(verify_off);
        self.upgrades.lock().unwrap().push((
            conn,
            name.map(str::to_owned),
            trust.map(str::to_owned),
        ));
        let mut pends = self.upgrade_pends.lock().unwrap();
        if *pends > 0 {
            *pends -= 1;
            return Err(ConnError::Pending);
        }
        Ok(())
    }

    fn cause(&self, _: InstanceId, _: ConnId) -> Option<ConnCause> {
        self.failing.as_ref().map(|(_, c)| c.clone())
    }

    fn landed(&self, caller: InstanceId, conn: ConnId, _: u64) -> Result<(), ConnError> {
        self.slab.get(caller, conn)?;
        if self.landing {
            return Err(ConnError::Pending);
        }
        Ok(())
    }

    fn auth_of(
        &self,
        _: InstanceId,
        _: NeedId,
        _: &str,
        _: &str,
    ) -> Option<busbar_contract::conn::ConnAuth> {
        self.member_auth.clone().or_else(|| {
            self.auth.as_ref().map(|auth| ConnAuth {
                auth: Arc::clone(auth),
                handle: 1,
                style_flags: 0,
                points: AuthPoints::EMPTY,
                passthrough: false,
                lender: None,
                per_request: None,
            })
        })
    }
}

impl Conns for Scripted {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
        if held_here() {
            self.opened_under_lock.store(true, AtomicOrdering::SeqCst);
        }
        self.opened.lock().unwrap().push((
            need,
            desc.target.to_owned(),
            desc.method.to_vec(),
            desc.head_target.to_vec(),
            desc.fields
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.to_vec()))
                .collect(),
            desc.body.to_vec(),
        ));
        self.within.lock().unwrap().push(desc.within.to_vec());
        self.opened_units.lock().unwrap().push(desc.unit);
        if let Some(e) = self.refuse {
            return Err(e);
        }
        self.slab.insert(caller, need, ())
    }
    fn write(
        &self,
        c: InstanceId,
        id: ConnId,
        b: &[u8],
        _: bool,
        _: bool,
    ) -> Result<usize, ConnError> {
        self.slab.get(c, id)?;
        self.writes.lock().unwrap().push(b.to_vec());
        Ok(b.len())
    }
    fn read(
        &self,
        c: InstanceId,
        id: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        if let Some((e, _)) = &self.failing {
            return Err(*e);
        }
        let Some((mut p, bytes)) = self.script.lock().unwrap().pop_front() else {
            self.parked.lock().unwrap().push((c, ticket));
            return Err(ConnError::Pending);
        };
        buf[..bytes.len()].copy_from_slice(&bytes);
        p.len = p.len.min(bytes.len());
        Ok(p)
    }
    fn wait(&self, _: InstanceId, _: &[ConnId], _: u64) -> Result<usize, ConnError> {
        Err(ConnError::Pending)
    }
    fn facts(&self, _: InstanceId, _: ConnId) -> Result<ConnFacts, ConnError> {
        self.facts.lock().unwrap().clone().ok_or(ConnError::Closed)
    }
    fn close(&self, c: InstanceId, id: ConnId) -> Result<(), ConnError> {
        self.close_gate.park();
        self.slab.remove(c, id).map(|_| ())
    }
}

const NAMED: [Need; 1] = [Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: 0,
    transport: abi_str("sock"),
    auth: NONE,
    target_from: NONE,
    trust_from: NONE,
    details: NO_BLOB,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: core::ptr::null(),
    deny_response_headers_len: 0,
}];

const T: Ticket = Ticket {
    slot: 7,
    generation: 3,
};

fn bound_over(table: &Arc<Scripted>) -> Plugin<TestKind> {
    bound_over_by(table, Adopter::unwatched())
}

fn bound_over_by(table: &Arc<Scripted>, adopter: Adopter) -> Plugin<TestKind> {
    bound_over_needs(table.clone(), adopter, &NAMED)
}

fn bound_over_needs(
    conns: Arc<dyn DeclaredConns>,
    adopter: Adopter,
    needs: &'static [Need],
) -> Plugin<TestKind> {
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement() };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    let door: &'static Door = Box::leak(Box::new(unsafe {
        Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
            statement: st,
            ..real.parts()
        })
    }));
    let v = validate_door::<TestKind>(door).expect("the door validates");
    Plugin::bind(
        v,
        None,
        Bind {
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: adopter,
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the instance binds")
}

#[path = "conn_timeout_tests.rs"]
mod conn_timeout_tests;

fn head_of<I>(op: u32, seq: u32) -> ServiceHead {
    ServiceHead {
        size: std::mem::size_of::<I>() as u32,
        op,
        handle: CompletionHandle {
            ticket: T,
            seq,
            _reserved: 0,
        },
    }
}

fn call<I>(p: &Plugin<TestKind>, f: Option<ServiceFn>, input: &I) -> ServiceOut {
    // SAFETY: an all-zero `ServiceOut` is a valid value the slot overwrites.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    out.size = std::mem::size_of::<ServiceOut>() as u32;
    let _: RawOutcome =
        unsafe { f.expect("served")(p.inner.ctx(), std::ptr::from_ref(input).cast(), &mut out) };
    out
}

fn opened_stream(p: &Plugin<TestKind>, seq: u32) -> ServiceOut {
    pinned_stream(p, seq, "")
}

fn pinned_stream(p: &Plugin<TestKind>, seq: u32, within: &'static str) -> ServiceOut {
    let i = EstablishIn {
        head: head_of::<EstablishIn>(service::ESTABLISH, seq),
        need: 0,
        timeout_ms: 0,
        target: abi_str("127.0.0.1:9"),
        within: abi_str(within),
        member: abi_str(""),
    };
    call(p, CONN_SLOTS.establish, &i)
}

fn request(
    p: &Plugin<TestKind>,
    seq: u32,
    stream: u64,
    piece: &RequestPiece,
    bytes: &[u8],
) -> ServiceOut {
    let i = RequestIn {
        head: head_of::<RequestIn>(service::WRITE_REQUEST, seq),
        stream,
        buf: bytes.as_ptr(),
        len: bytes.len(),
        piece: std::ptr::from_ref(piece),
    };
    call(p, CONN_SLOTS.write_request, &i)
}

fn span(offset: usize, len: usize) -> FrameSpan {
    FrameSpan {
        offset: offset as u64,
        len: len as u64,
    }
}

const HEAD_BYTES: &[u8] = b"PATCH/v1/xa: 1\r\n";

fn head_piece() -> RequestPiece {
    RequestPiece {
        kind: REQUEST_HEAD,
        _reserved: 0,
        method: span(0, 5),
        target: span(5, 5),
        fields: span(10, 6),
        timeout_ms: 250,
    }
}

fn kind_piece(kind: u32) -> RequestPiece {
    RequestPiece {
        kind,
        ..RequestPiece::default()
    }
}

fn read_reply(
    p: &Plugin<TestKind>,
    seq: u32,
    stream: u64,
    buf: &mut [u8],
) -> (ServiceOut, ReplyPiece) {
    let mut piece = ReplyPiece::default();
    let i = ReplyIn {
        head: head_of::<ReplyIn>(service::READ_REPLY, seq),
        stream,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
        piece: std::ptr::from_mut(&mut piece),
    };
    let out = call(p, CONN_SLOTS.read_reply, &i);
    (out, piece)
}

fn ready(o: &ServiceOut) -> bool {
    o.outcome == RawOutcome::of(Outcome::Ready)
}

fn error_text(o: &ServiceOut) -> String {
    if o.error.ptr.is_null() {
        return String::new();
    }
    // SAFETY: the host's static text.
    String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(o.error.ptr, o.error.len) })
        .into_owned()
}

fn piece(
    kind: PieceKind,
    code: Option<u32>,
    reason: Option<std::ops::Range<usize>>,
    len: usize,
) -> Piece {
    Piece {
        kind,
        stream: StreamId(0),
        len,
        end: true,
        status: None,
        status_code: code,
        status_namespace: None,
        retry_after_secs: None,
        fault: None,
        reason,
        declared_len: None,
    }
}

#[test]
fn a_framed_request_goes_out_whole_as_the_opening_message_with_its_head_words() {
    let table = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let est = opened_stream(&p, 0);
    assert!(ready(&est));
    assert!(
        table.opened.lock().unwrap().is_empty(),
        "nothing is sent at establish"
    );
    let stream = est.value;
    let h = request(&p, 1, stream, &head_piece(), HEAD_BYTES);
    assert!(ready(&h));
    assert_eq!(h.len, HEAD_BYTES.len() as u64);
    assert!(ready(&request(
        &p,
        2,
        stream,
        &kind_piece(REQUEST_BODY),
        b"hi"
    )));
    assert!(ready(&request(
        &p,
        3,
        stream,
        &kind_piece(REQUEST_BODY),
        b"!"
    )));
    assert!(
        table.opened.lock().unwrap().is_empty(),
        "nothing is sent before the end"
    );
    assert!(ready(&request(
        &p,
        4,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    assert_eq!(
        table.opened.lock().unwrap().as_slice(),
        &[(
            NeedId(0),
            "127.0.0.1:9".to_owned(),
            b"PATCH".to_vec(),
            b"/v1/x".to_vec(),
            vec![("a".to_owned(), b"1".to_vec())],
            b"hi!".to_vec()
        )]
    );
}

#[test]
fn write_request_is_refused_on_a_raw_stream_and_out_of_order() {
    let raw = Arc::new(Scripted::default());
    let p = bound_over(&raw);
    let stream = opened_stream(&p, 0).value;
    assert_eq!(
        raw.opened.lock().unwrap().len(),
        1,
        "a raw stream opens at establish"
    );
    let o = request(&p, 1, stream, &head_piece(), HEAD_BYTES);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    let framed = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let q = bound_over(&framed);
    let held = opened_stream(&q, 0).value;
    let o = request(&q, 1, held, &kind_piece(REQUEST_BODY), b"x");
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
}

#[test]
fn a_reply_reads_its_head_its_body_and_one_terminal_end() {
    let table = Arc::new(Scripted::default());
    table.script.lock().unwrap().extend([
        (
            piece(PieceKind::Fields, Some(201), Some(6..16), 6),
            b"x: y\r\nFine By Me".to_vec(),
        ),
        (piece(PieceKind::Body, None, None, 3), b"abc".to_vec()),
        (piece(PieceKind::Completion, None, None, 0), Vec::new()),
    ]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let mut buf = [0_u8; 64];
    let (o, h) = read_reply(&p, 1, stream, &mut buf);
    assert!(ready(&o));
    assert_eq!(
        h,
        ReplyPiece {
            kind: REPLY_HEAD,
            code: 201,
            reason: span(6, 10),
            fields: span(0, 6),
        }
    );
    assert_eq!(&buf[6..16], b"Fine By Me");
    let (o, b) = read_reply(&p, 2, stream, &mut buf);
    assert_eq!((b.kind, o.len), (REPLY_BODY, 3));
    assert_eq!(&buf[..3], b"abc");
    let (o, e) = read_reply(&p, 3, stream, &mut buf);
    assert!(ready(&o));
    assert_eq!(e.kind, REPLY_END);
    let (o, _) = read_reply(&p, 4, stream, &mut buf);
    assert_eq!(
        o.outcome,
        RawOutcome::of(Outcome::Failed),
        "one terminal piece"
    );
}

#[test]
fn a_reply_without_a_head_ends_in_one_ack() {
    let table = Arc::new(Scripted::default());
    table.script.lock().unwrap().extend([
        (piece(PieceKind::Body, None, None, 2), b"ok".to_vec()),
        (piece(PieceKind::Completion, None, None, 0), Vec::new()),
    ]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let mut buf = [0_u8; 8];
    assert_eq!(read_reply(&p, 1, stream, &mut buf).1.kind, REPLY_BODY);
    let (o, ack) = read_reply(&p, 2, stream, &mut buf);
    assert!(ready(&o));
    assert_eq!(ack.kind, REPLY_ACK);
}

#[test]
fn an_egress_refusal_is_a_failed_ack_with_its_text() {
    let table = Arc::new(Scripted {
        framed: true,
        refuse: Some(ConnError::Refused),
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    assert!(ready(&request(&p, 1, stream, &head_piece(), HEAD_BYTES)));
    assert!(ready(&request(
        &p,
        2,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    let mut buf = [0_u8; 8];
    let (o, _) = read_reply(&p, 3, stream, &mut buf);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    assert_eq!(error_text(&o), ConnError::Refused.text());
    let (o, _) = read_reply(&p, 4, stream, &mut buf);
    assert_eq!(
        o.outcome,
        RawOutcome::of(Outcome::Failed),
        "the reply has ended"
    );
}

#[test]
fn a_failed_reply_names_the_stage_and_the_underlying_error() {
    use busbar_contract::abi::host::conn::connector::CAUSE_CONNECT;
    let table = Arc::new(Scripted {
        failing: Some((
            ConnError::Refused,
            ConnCause {
                stage: CAUSE_CONNECT,
                text: "Connection refused (os error 111)".into(),
            },
        )),
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let mut buf = [0_u8; 8];
    let (o, _) = read_reply(&p, 1, stream, &mut buf);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    assert_eq!(o.value, CAUSE_CONNECT);
    assert_eq!(error_text(&o), "Connection refused (os error 111)");
}

#[test]
fn a_replayed_handle_never_runs_its_service_twice() {
    let raw = Arc::new(Scripted::default());
    let p = bound_over(&raw);
    let first = opened_stream(&p, 0);
    let again = opened_stream(&p, 0);
    assert_eq!(again.value, first.value);
    assert_eq!(raw.opened.lock().unwrap().len(), 1, "one open");
    let w = IoIn {
        head: head_of::<IoIn>(service::WRITE, 1),
        stream: first.value,
        buf: b"once".as_ptr().cast_mut(),
        len: 4,
    };
    assert!(ready(&call(&p, CONN_SLOTS.write, &w)));
    assert!(ready(&call(&p, CONN_SLOTS.write, &w)));
    assert_eq!(raw.writes.lock().unwrap().len(), 1, "one write");

    let framed = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let q = bound_over(&framed);
    let stream = opened_stream(&q, 0).value;
    let h = request(&q, 1, stream, &head_piece(), HEAD_BYTES);
    let replayed = request(&q, 1, stream, &head_piece(), HEAD_BYTES);
    assert!(ready(&h));
    assert!(
        ready(&replayed),
        "the replay answers the stored result, not a second head"
    );
    assert_eq!(replayed.len, h.len);
    drop(super::forget(q.instance(), T));
    let fresh = request(&q, 1, stream, &head_piece(), HEAD_BYTES);
    assert_eq!(
        fresh.outcome,
        RawOutcome::of(Outcome::Refused),
        "a forgotten ticket's handle runs afresh"
    );
}

#[test]
fn establish_within_reaches_the_connect_raw_and_framed() {
    let set: Vec<std::net::IpAddr> = vec![
        "203.0.113.5".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
    ];
    let raw = Arc::new(Scripted::default());
    let p = bound_over(&raw);
    assert!(ready(&pinned_stream(&p, 0, "203.0.113.5,2001:db8::1")));
    assert!(ready(&pinned_stream(&p, 1, "")));
    assert_eq!(
        raw.within.lock().unwrap().as_slice(),
        &[set.clone(), Vec::new()]
    );

    let framed = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let p = bound_over(&framed);
    let stream = pinned_stream(&p, 0, "203.0.113.5,2001:db8::1").value;
    assert!(
        framed.within.lock().unwrap().is_empty(),
        "nothing opens at establish"
    );
    assert!(ready(&request(&p, 1, stream, &head_piece(), HEAD_BYTES)));
    assert!(
        framed.within.lock().unwrap().is_empty(),
        "nor before the end"
    );
    assert!(ready(&request(
        &p,
        2,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    assert_eq!(framed.within.lock().unwrap().as_slice(), &[set]);

    let refused = Arc::new(Scripted::default());
    let p = bound_over(&refused);
    for (seq, bad) in [(0, "203.0.113.5,api.example.com"), (1, "203.0.113.5:443")] {
        let o = pinned_stream(&p, seq, bad);
        assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused), "{bad}");
        assert_eq!(
            error_text(&o),
            "an address the dial must land on is not an IP literal"
        );
    }
    assert!(refused.opened.lock().unwrap().is_empty(), "nothing opened");
}

fn admit(p: &Plugin<TestKind>, need: u32) -> Outcome {
    use busbar_contract::abi::host::service::{op, NeedAdmitIn};
    let i = NeedAdmitIn {
        head: ServiceHead {
            size: std::mem::size_of::<NeedAdmitIn>() as u32,
            op: op::NEED_ADMIT,
            handle: CompletionHandle {
                ticket: Ticket::NONE,
                seq: 0,
                _reserved: 0,
            },
        },
        need,
        _reserved: 0,
    };
    // SAFETY: an all-zero `ServiceOut` is a valid value the slot overwrites.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    out.size = std::mem::size_of::<ServiceOut>() as u32;
    let slot = crate::dispatch::services::HOST_SLOTS
        .need_admit
        .expect("need.admit is served");
    let _: RawOutcome = unsafe { slot(p.inner.ctx(), std::ptr::from_ref(&i).cast(), &mut out) };
    out.outcome.outcome()
}

#[test]
fn need_admit_answers_the_tables_verdict_on_the_declared_need() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert_eq!(admit(&p, 0), Outcome::Refused, "not yet declared");
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    assert_eq!(admit(&p, 0), Outcome::Ready, "declared and admitted");
    assert_eq!(admit(&p, 1), Outcome::Refused, "no such need");

    let refused = Arc::new(Recording::default());
    let q = bound(Box::leak(Box::new(NEEDS)), &refused);
    assert_eq!(open_with(&q, b"{}"), Outcome::Ready);
    assert_eq!(admit(&q, 0), Outcome::Refused, "the table refused it");
}

fn sdk_host(p: &Plugin<TestKind>) -> busbar_contract::abi::sdk::conn::Host {
    use busbar_contract::abi::mechanism::ticket::HostTables;
    /* SAFETY: these harness tables and callbacks are live for the snapshot. */
    unsafe {
        busbar_contract::abi::sdk::conn::Host::from_raw(&HostTables {
            size: std::mem::size_of::<HostTables>() as u32,
            _reserved: 0,
            ctx: p.inner.ctx(),
            wake: None,
            conns: &CONN_SLOTS,
            services: std::ptr::null(),
            io: std::ptr::null(),
        })
    }
}

#[test]
fn an_sdk_upgrade_reaches_the_table_and_follows_the_replay_rule() {
    use std::task::Poll;
    let table = Arc::new(Scripted {
        upgrade_pends: Mutex::new(1),
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let host = sdk_host(&p);
    let entry = |host: &busbar_contract::abi::sdk::conn::Host| {
        let mut c = host.connector(T);
        let Poll::Ready(Ok(stream)) = c.establish(0, Some("127.0.0.1:9"), "") else {
            panic!("the raw stream is established");
        };
        (stream, c.upgrade_secure(stream, Some("ldap.example"), None))
    };
    let (stream, first) = entry(&host);
    assert_eq!(first, Poll::Pending, "the handshake is running");
    let (again, second) = entry(&host);
    assert_eq!(again, stream, "the establish is redeemed on re-entry");
    assert_eq!(second, Poll::Ready(Ok(())));
    let (_, third) = entry(&host);
    assert_eq!(third, Poll::Ready(Ok(())));
    assert_eq!(table.opened.lock().unwrap().len(), 1, "dialled once");
    let upgrades = table.upgrades.lock().unwrap().clone();
    assert_eq!(
        upgrades,
        vec![(ConnId(stream), Some("ldap.example".to_owned()), None); 2],
        "run until done, never after"
    );
}

#[test]
fn an_upgrade_on_no_ticket_or_a_framed_stream_is_refused() {
    use busbar_contract::abi::host::conn::connector::UpgradeIn;
    let table = Arc::new(Scripted {
        upgrade_pends: Mutex::new(1),
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let upgrade = |stream: u64, ticket: Ticket| UpgradeIn {
        head: ServiceHead {
            size: std::mem::size_of::<UpgradeIn>() as u32,
            op: service::UPGRADE_SECURE,
            handle: CompletionHandle {
                ticket,
                seq: 9,
                _reserved: 0,
            },
        },
        stream,
        offered_name: NONE,
        trust: NONE,
        flags: 0,
        _reserved: 0,
    };
    let out = call(
        &p,
        CONN_SLOTS.upgrade_secure,
        &upgrade(stream, Ticket::NONE),
    );
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Refused));
    let framed = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let q = bound_over(&framed);
    let held = opened_stream(&q, 0).value;
    let out = call(&q, CONN_SLOTS.upgrade_secure, &upgrade(held, T));
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Refused));
    assert!(framed.upgrades.lock().unwrap().is_empty());
}

#[test]
fn facts_expose_the_peer_certificate_hash() {
    use busbar_contract::abi::host::conn::connector::{FactsIn, StreamFacts};
    let table = Arc::new(Scripted::default());
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let read = |seq: u32| {
        // SAFETY: an all-zero `StreamFacts` is a valid value the slot overwrites.
        let mut f: StreamFacts = unsafe { std::mem::zeroed() };
        let i = FactsIn {
            head: head_of::<FactsIn>(service::FACTS, seq),
            stream,
            facts: &mut f,
        };
        let out = call(&p, CONN_SLOTS.facts, &i);
        assert_eq!(out.outcome, RawOutcome::of(Outcome::Ready));
        let text = |s: AbiStr| {
            (!s.ptr.is_null()).then(|| {
                // SAFETY: the host holds the facts' strings until the stream closes.
                String::from_utf8(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }.to_vec())
                    .unwrap()
            })
        };
        (f.secure, text(f.peer_cert_hash))
    };
    *table.facts.lock().unwrap() = Some(ConnFacts::default());
    assert_eq!(read(1), (0, None), "in the clear");
    *table.facts.lock().unwrap() = Some(ConnFacts {
        peer_cert: Some(busbar_contract::transport::wire::CertFacts {
            subject: String::new(),
            issuer: String::new(),
            fingerprint: "ab".repeat(32),
        }),
        ..ConnFacts::default()
    });
    assert_eq!(read(2), (1, Some("ab".repeat(32))), "secured");
}

#[test]
fn a_replayed_facts_writes_the_same_facts_again() {
    use busbar_contract::abi::host::conn::connector::{FactsIn, StreamFacts, StreamIn};
    let table = Arc::new(Scripted::default());
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let ask = |seq: u32| {
        // SAFETY: an all-zero `StreamFacts` is a valid value the slot overwrites.
        let mut f: StreamFacts = unsafe { std::mem::zeroed() };
        let i = FactsIn {
            head: head_of::<FactsIn>(service::FACTS, seq),
            stream,
            facts: &mut f,
        };
        let out = call(&p, CONN_SLOTS.facts, &i);
        let text = |s: AbiStr| {
            (!s.ptr.is_null()).then(|| {
                // SAFETY: the host holds the facts' strings for the caller.
                String::from_utf8(unsafe { std::slice::from_raw_parts(s.ptr, s.len) }.to_vec())
                    .unwrap()
            })
        };
        (ready(&out), f.secure, text(f.peer_cert_hash))
    };
    *table.facts.lock().unwrap() = Some(ConnFacts {
        peer_cert: Some(busbar_contract::transport::wire::CertFacts {
            subject: String::new(),
            issuer: String::new(),
            fingerprint: "ab".repeat(32),
        }),
        ..ConnFacts::default()
    });
    let secured = (true, 1, Some("ab".repeat(32)));
    assert_eq!(ask(1), secured, "the first run's facts");

    *table.facts.lock().unwrap() = Some(ConnFacts::default());
    assert_eq!(ask(1), secured, "the replayed facts");
    let c = StreamIn {
        head: head_of::<StreamIn>(service::CLOSE, 2),
        stream,
    };
    assert!(ready(&call(&p, CONN_SLOTS.close, &c)));
    assert_eq!(ask(1), secured, "the replayed facts, the stream closed");
}

#[test]
fn an_upgrades_verify_off_reaches_the_table_and_a_v1_in_reads_none() {
    use busbar_contract::abi::host::conn::connector::{
        UpgradeIn, UPGRADE_IN_V1_SIZE, UPGRADE_VERIFY_OFF,
    };
    let table = Arc::new(Scripted::default());
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let upgrade = |size: usize, flags: u32, seq: u32| UpgradeIn {
        head: ServiceHead {
            size: size as u32,
            op: service::UPGRADE_SECURE,
            handle: CompletionHandle {
                ticket: T,
                seq,
                _reserved: 0,
            },
        },
        stream,
        offered_name: NONE,
        trust: NONE,
        flags,
        _reserved: 0,
    };
    let full = std::mem::size_of::<UpgradeIn>();
    for (size, flags, seq) in [
        (full, UPGRADE_VERIFY_OFF, 20),
        (full, 0, 21),
        (UPGRADE_IN_V1_SIZE, UPGRADE_VERIFY_OFF, 22),
    ] {
        let out = call(&p, CONN_SLOTS.upgrade_secure, &upgrade(size, flags, seq));
        assert_eq!(out.outcome, RawOutcome::of(Outcome::Ready));
    }
    assert_eq!(*table.verify_offs.lock().unwrap(), vec![true, false, false]);
}

const MEMBER_NEEDS: [Need; 1] = [Need {
    target_from: abi_str("settings.*"),
    ..NEEDS[0]
}];

#[test]
fn a_member_program_need_is_declared_with_each_registrations_program() {
    use busbar_contract::conn::Program;
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(MEMBER_NEEDS)), &table);
    assert_eq!(
        open_with(
            &p,
            br#"{"one":{"transport":"piped","command":"/usr/bin/one","args":["--serve"],
                 "env":{"PLAIN":"v","KEY":{"env":"BUSBAR_LOADER_MEMBER_PROGRAM_SECRET"}},
                 "pin":{"mechanism":"unpinned"},"tools_allow":["a"]},
                "web":{"url":"https://upstream.example/rpc","pin":{"mechanism":"unpinned"}},
                "bad":{"transport":"piped","command":"relative"},
                "pools":{"p":{"members":["one"]}}}"#
        ),
        Outcome::Ready
    );
    let members = table.members.lock().unwrap().clone();
    assert_eq!(
        members,
        vec![(
            p.instance(),
            NeedId(0),
            vec![(
                "one".to_owned(),
                Program {
                    command: "/usr/bin/one".into(),
                    cwd: None,
                    args: vec!["--serve".into()],
                    env: vec![("PLAIN".into(), "v".into())],
                    env_refs: vec![(
                        "KEY".into(),
                        busbar_contract::secret_ref::SecretRef::env(
                            "BUSBAR_LOADER_MEMBER_PROGRAM_SECRET"
                        ),
                    )],
                }
            )]
        )]
    );
    assert!(
        targets(&table, &p).is_empty(),
        "no target string was declared"
    );
    assert!(table.programs.lock().unwrap().is_empty());
    assert_eq!(
        refresh_with(&p, br#"{"two":{"command":"/usr/bin/two"}}"#),
        Outcome::Ready
    );
    let members = table.members.lock().unwrap().clone();
    assert_eq!(members.len(), 2, "a refresh declares the members again");
    assert_eq!(
        members[1].2,
        vec![(
            "two".to_owned(),
            Program {
                command: "/usr/bin/two".into(),
                cwd: None,
                args: Vec::new(),
                env: Vec::new(),
                env_refs: Vec::new(),
            }
        )]
    );
}

#[test]
fn an_establish_names_its_registration_and_a_shorter_head_names_none() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    let full = std::mem::size_of::<EstablishIn>();
    let memberless = std::mem::offset_of!(EstablishIn, member);
    let named = establish_as(&p, 0, "127.0.0.1:9", Ticket::NONE, Some("inside"), full);
    assert_eq!(named.outcome, RawOutcome::of(Outcome::Ready));
    let short = establish_as(
        &p,
        0,
        "127.0.0.1:9",
        Ticket::NONE,
        Some("ignored"),
        memberless,
    );
    assert_eq!(
        short.outcome,
        RawOutcome::of(Outcome::Ready),
        "a shorter head is served"
    );
    assert_eq!(
        table.named.lock().unwrap().as_slice(),
        &["inside".to_owned(), String::new()],
        "the named registration, then none"
    );
}

fn held_here() -> bool {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut id = 1;
    while let Some(w) = crate::dispatch::handle::supplier_of(InstanceId(id)) {
        loop {
            match w.conn_state.streams.try_lock() {
                Ok(_) | Err(std::sync::TryLockError::Poisoned(_)) => break,
                Err(std::sync::TryLockError::WouldBlock) if std::time::Instant::now() < until => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::WouldBlock) => return true,
            }
        }
        id += 1;
    }
    false
}

fn streams_of(
    id: InstanceId,
) -> std::sync::MutexGuard<'static, std::collections::HashMap<u64, super::Stream>> {
    crate::dispatch::handle::supplier_of(id)
        .expect("a minted instance")
        .conn_state
        .streams()
}

/// A member binding's auth instance that answers one bearer field, recording whether any of its
/// calls ran while the calling thread held the connector's lock: answered on the spot (`now`), or
/// from a submitted call polled by the read.
#[derive(Default)]
struct LockProbe {
    now: bool,
    seen: Arc<Seen>,
}

/// What a [`LockProbe`]'s calls saw.
#[derive(Default)]
struct Seen {
    calls: AtomicU32,
    under_lock: AtomicBool,
}

impl Seen {
    fn call(&self) {
        self.calls.fetch_add(1, AtomicOrdering::SeqCst);
        if held_here() {
            self.under_lock.store(true, AtomicOrdering::SeqCst);
        }
    }
}

fn bearer() -> Fields {
    Fields::Ready(vec![AuthField {
        name: b"authorization".to_vec(),
        value: Secret::new(b"Bearer member".to_vec()),
        sensitive: true,
        query: false,
        require_secure: false,
    }])
}

impl OutboundAuth for LockProbe {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(&self, _: u64, _: &FieldsRequest) -> Option<Fields> {
        self.seen.call();
        self.now.then(bearer)
    }
    fn fields(&self, _: u64, _: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        Box::new(Polled(Arc::clone(&self.seen)))
    }
}

struct Polled(Arc<Seen>);

impl std::future::Future for Polled {
    type Output = Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Fields> {
        self.0.call();
        std::task::Poll::Ready(bearer())
    }
}

impl Fielding for Polled {
    fn settled(&mut self) -> Option<Fields> {
        None
    }
}

fn whole_request(p: &Plugin<TestKind>, seq: u32) -> u64 {
    let est = opened_stream(p, seq);
    assert!(ready(&est));
    let stream = est.value;
    assert!(ready(&request(
        p,
        seq + 1,
        stream,
        &head_piece(),
        HEAD_BYTES
    )));
    assert!(ready(&request(
        p,
        seq + 2,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    stream
}

#[test]
fn a_members_auth_call_and_its_open_run_outside_the_connectors_lock() {
    let probe = Arc::new(LockProbe {
        now: true,
        ..LockProbe::default()
    });
    let table = Arc::new(Scripted {
        framed: true,
        auth: Some(probe.clone()),
        ..Scripted::default()
    });

    let dispatcher = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let p = bound_over_by(&table, dispatcher.adopter());
    whole_request(&p, 0);
    assert_eq!(
        probe.seen.calls.load(AtomicOrdering::SeqCst),
        1,
        "one auth call"
    );
    assert!(
        !probe.seen.under_lock.load(AtomicOrdering::SeqCst),
        "the auth plugin's fields ran under the connector's lock"
    );
    assert!(
        !table.opened_under_lock.load(AtomicOrdering::SeqCst),
        "the open ran under the connector's lock"
    );
    let opened = table.opened.lock().unwrap();
    assert_eq!(opened.len(), 1, "one open");
    assert_eq!(
        opened[0].4[0].0, "authorization",
        "the member's field leads"
    );
}

#[test]
fn an_auth_door_query_field_is_never_opened_as_a_header() {
    let auth = Arc::new(crate::dispatch::auth_outbound::tests::opened());
    let handle = auth
        .open_outbound("query", b"key", &serde_json::json!({}))
        .unwrap();
    let table = Arc::new(Scripted {
        framed: true,
        member_auth: Some(ConnAuth {
            auth,
            handle,
            style_flags: 0,
            points: AuthPoints::EMPTY,
            passthrough: false,
            lender: None,
            per_request: None,
        }),
        ..Scripted::default()
    });
    let dispatcher = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let p = bound_over_by(&table, dispatcher.adopter());
    whole_request(&p, 0);
    let opened = table.opened.lock().unwrap();
    assert_eq!(opened.len(), 1);
    let fields = &opened[0].4;
    assert!(!fields.iter().any(|(n, _)| n == "authorization"));
    assert_eq!(
        fields
            .iter()
            .filter(|(n, _)| n == "busbar-sealed-query")
            .map(|(_, v)| v.as_slice())
            .collect::<Vec<_>>(),
        [
            b"authorization=query%20%2F%2B%26%25".as_slice(),
            b"authorization=second"
        ],
        "query order, duplicate names and percent encoding survive the host-only handoff"
    );
    assert!(fields
        .iter()
        .any(|(n, v)| n == "x-signature" && v == b"signed"));
    assert!(
        !opened[0].1.contains("query"),
        "credentials never enter the dial target"
    );
    assert!(
        !opened[0].3.windows(5).any(|w| w == b"query"),
        "the connector alone appends the credential"
    );
}

#[test]
fn a_members_pending_auth_call_is_polled_and_opened_outside_the_connectors_lock() {
    let probe = Arc::new(LockProbe::default());
    let table = Arc::new(Scripted {
        framed: true,
        auth: Some(probe.clone()),
        ..Scripted::default()
    });
    table
        .script
        .lock()
        .unwrap()
        .push_back((piece(PieceKind::Fields, Some(200), None, 0), Vec::new()));

    let dispatcher = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let p = bound_over_by(&table, dispatcher.adopter());
    let stream = whole_request(&p, 0);
    assert!(
        table.opened.lock().unwrap().is_empty(),
        "not opened before the call answers"
    );
    let mut buf = [0u8; 64];
    let (out, got) = read_reply(&p, 3, stream, &mut buf);
    assert!(ready(&out), "{}", error_text(&out));
    assert_eq!(got.kind, REPLY_HEAD);
    assert_eq!(
        probe.seen.calls.load(AtomicOrdering::SeqCst),
        2,
        "on the spot, then polled"
    );
    assert!(
        !probe.seen.under_lock.load(AtomicOrdering::SeqCst),
        "the auth call was polled under the connector's lock"
    );
    assert!(
        !table.opened_under_lock.load(AtomicOrdering::SeqCst),
        "the open ran under the connector's lock"
    );
    assert_eq!(table.opened.lock().unwrap().len(), 1, "one open");
}

#[test]
fn red_a_forged_ticket_through_a_connection_slot_quarantines_its_supplier() {
    let table = Arc::new(Scripted::default());
    let d = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let latch: &'static crate::dispatch::handle::Latch =
        Box::leak(Box::new(crate::dispatch::handle::Latch::new()));
    d.judge_against(latch);
    let p = bound_over_by(&table, d.adopter());
    let est = opened_stream(&p, 0);
    assert!(ready(&est), "{}", error_text(&est));
    let t = d.mint(0).expect("a ticket");
    let forged = Ticket {
        slot: t.slot,
        generation: t.generation ^ 0x5a5a_5a5a,
    };
    let mut buf = [0u8; 16];
    let i = IoIn {
        head: ServiceHead {
            size: std::mem::size_of::<IoIn>() as u32,
            op: service::READ,
            handle: CompletionHandle {
                ticket: forged,
                seq: 1,
                _reserved: 0,
            },
        },
        stream: est.value,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
    };
    let out = call(&p, CONN_SLOTS.read, &i);
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Pending));
    let parked = table.parked.lock().unwrap().clone();
    assert_eq!(
        parked,
        vec![(
            p.instance(),
            crate::dispatch::conn_services::conn_ticket(forged)
        )],
        "the read parked under its caller and the forged ticket"
    );
    let (owner, ticket) = parked[0];
    (d.conn_waker())(owner, ticket);
    let started = std::time::Instant::now();
    while !p.is_faulted() {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "the supplier of the forged ticket was not quarantined"
        );
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    assert_eq!(
        (latch.forged(), latch.unattributed()),
        (1, 0),
        "the forged ticket was not judged, or counted toward the latch"
    );
    d.recycle(t);
}

#[test]
fn a_framed_stream_written_raw_opens_outside_the_connectors_lock() {
    let table = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let est = opened_stream(&p, 0);
    let w = IoIn {
        head: head_of::<IoIn>(service::WRITE, 1),
        stream: est.value,
        buf: b"raw".as_ptr().cast_mut(),
        len: 3,
    };
    assert!(ready(&call(&p, CONN_SLOTS.write, &w)));
    assert_eq!(table.opened.lock().unwrap().len(), 1, "opened once");
    assert!(
        !table.opened_under_lock.load(AtomicOrdering::SeqCst),
        "the open ran under the connector's lock"
    );
}

#[test]
fn a_stream_closed_while_it_opens_leaves_nothing_open() {
    let id = InstanceId(u64::MAX - 7);
    let stream = super::HELD | 0x00ff_ffff_0000;
    let recorded = Arc::new(Scripted::default());
    recorded.slab.declare(id, NeedId(0));
    let conn = recorded.slab.insert(id, NeedId(0), ()).expect("a slot");
    let table: Arc<dyn DeclaredConns> = recorded.clone();
    let st = super::ConnState::default();

    super::install(&st, id, stream, &table, super::Conn::Open(conn));
    assert!(
        recorded.slab.get(id, conn).is_err(),
        "the orphaned open is closed on the table"
    );
    assert!(st.streams().get(&stream).is_none(), "nothing is held");
}

#[test]
fn a_replayed_identity_writes_the_callers_memory_again() {
    use busbar_contract::abi::host::conn::connector::{IdentityIn, ProcessIdentity};
    let p = bound_over(&Arc::new(Scripted::default()));
    let ask = |into: &mut ProcessIdentity| {
        let i = IdentityIn {
            head: head_of::<IdentityIn>(service::IDENTITY, 5),
            identity: std::ptr::from_mut(into),
        };
        call(&p, CONN_SLOTS.identity, &i)
    };
    // SAFETY: an all-zero `ProcessIdentity` is a valid value the service overwrites.
    let mut first: ProcessIdentity = unsafe { std::mem::zeroed() };
    assert!(ready(&ask(&mut first)));
    assert_eq!(first.pid, u64::from(std::process::id()));
    let expected_user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default();
    let user_of = |identity: &ProcessIdentity| {
        if identity.os_user.len == 0 {
            return "";
        }
        // SAFETY: the actual identity service lends its process-lifetime OS-user
        // bytes; the successful crossing above initialized this complete AbiStr.
        let bytes =
            unsafe { std::slice::from_raw_parts(identity.os_user.ptr, identity.os_user.len) };
        std::str::from_utf8(bytes).expect("the actual OS-user string is UTF-8")
    };
    assert_eq!(user_of(&first), expected_user);
    // SAFETY: as above.
    let mut replayed: ProcessIdentity = unsafe { std::mem::zeroed() };
    assert!(ready(&ask(&mut replayed)), "the same handle, again");
    assert_eq!(
        replayed.pid,
        u64::from(std::process::id()),
        "a replay answered READY without writing the identity"
    );
    assert_eq!(
        user_of(&replayed),
        expected_user,
        "the replay must also write the actual OS-user identity"
    );
}

#[test]
fn a_replayed_read_reply_writes_its_piece_and_bytes_again() {
    let table = Arc::new(Scripted::default());
    table.script.lock().unwrap().extend([
        (
            piece(PieceKind::Fields, Some(201), Some(6..16), 6),
            b"x: y\r\nFine By Me".to_vec(),
        ),
        (piece(PieceKind::Body, None, None, 3), b"abc".to_vec()),
        (piece(PieceKind::Completion, None, None, 0), Vec::new()),
    ]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let mut first = [0_u8; 64];
    let (o, h) = read_reply(&p, 1, stream, &mut first);
    assert!(ready(&o));
    let (_, b) = read_reply(&p, 2, stream, &mut first);
    assert_eq!(b.kind, REPLY_BODY);
    let (_, e) = read_reply(&p, 3, stream, &mut first);
    assert_eq!(e.kind, REPLY_END);
    let mut again = [0_u8; 64];
    let (ro, rh) = read_reply(&p, 1, stream, &mut again);
    assert!(ready(&ro) && ro.len == o.len);
    assert_eq!(rh, h, "the replayed head's piece");
    assert_eq!(
        &again[..16],
        b"x: y\r\nFine By Me",
        "the replayed head's bytes"
    );
    let (ro, rb) = read_reply(&p, 2, stream, &mut again);
    assert_eq!((rb.kind, ro.len), (REPLY_BODY, 3));
    assert_eq!(&again[..3], b"abc", "the replayed body's bytes");
    assert_eq!(read_reply(&p, 3, stream, &mut again).1.kind, REPLY_END);
    assert!(
        table.script.lock().unwrap().is_empty(),
        "every piece was read from the far end once"
    );
    let mut short = [0xEE; 4];
    let (out, untouched) = read_reply(&p, 1, stream, &mut short);
    assert_eq!(out.outcome, RawOutcome::of(Outcome::Failed));
    assert_eq!((out.needed_bytes, out.len), (16, 0));
    assert_eq!(short, [0xEE; 4], "a short replay writes no bytes");
    assert_eq!(
        untouched,
        ReplyPiece::default(),
        "nor a descriptor with invalid spans"
    );
    let invalid = ReplyIn {
        head: head_of::<ReplyIn>(service::READ_REPLY, 1),
        stream,
        piece: std::ptr::null_mut(),
        buf: again.as_mut_ptr(),
        len: again.len(),
    };
    assert_eq!(
        call(&p, CONN_SLOTS.read_reply, &invalid).outcome,
        RawOutcome::of(Outcome::Fault)
    );
    again.fill(0);
    let (retried, retried_piece) = read_reply(&p, 1, stream, &mut again);
    assert!(ready(&retried));
    assert_eq!(retried_piece, h);
    assert_eq!(&again[..16], b"x: y\r\nFine By Me");
    drop(super::forget(p.instance(), T));
    let mut fresh = [0_u8; 64];
    let (_, gone) = read_reply(&p, 1, stream, &mut fresh);
    assert_ne!(gone, h, "a forgotten ticket's read is not replayed");
}

#[test]
fn a_members_auth_failure_and_refusal_keep_their_causes() {
    use busbar_contract::abi::host::conn::connector::{CAUSE_AUTH_FAILED, CAUSE_AUTH_REFUSED};
    struct AnswerAuth {
        failed: bool,
        now: bool,
    }
    impl AnswerAuth {
        fn answer(&self) -> Fields {
            if self.failed {
                Fields::Failed
            } else {
                Fields::Refused
            }
        }
    }
    impl OutboundAuth for AnswerAuth {
        fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
            Ok(1)
        }
        fn fields_now(&self, _: u64, _: &FieldsRequest) -> Option<Fields> {
            self.now.then(|| self.answer())
        }
        fn fields(&self, _: u64, _: FieldsRequest, _: u64) -> Box<dyn Fielding> {
            Box::new(AnswerLater {
                failed: self.failed,
                pended: false,
            })
        }
    }
    struct AnswerLater {
        failed: bool,
        pended: bool,
    }
    impl std::future::Future for AnswerLater {
        type Output = Fields;
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Fields> {
            if !self.pended {
                self.pended = true;
                return std::task::Poll::Pending;
            }
            std::task::Poll::Ready(if self.failed {
                Fields::Failed
            } else {
                Fields::Refused
            })
        }
    }
    impl Fielding for AnswerLater {
        fn settled(&mut self) -> Option<Fields> {
            None
        }
    }
    for now in [true, false] {
        for failed in [false, true] {
            let table = Arc::new(Scripted {
                framed: true,
                auth: Some(Arc::new(AnswerAuth { failed, now })),
                ..Scripted::default()
            });
            let dispatcher =
                crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
            let p = bound_over_by(&table, dispatcher.adopter());
            let stream = whole_request(&p, 0);
            let mut buf = [0; 16];
            if !now {
                assert_eq!(
                    read_reply(&p, 3, stream, &mut buf).0.outcome,
                    RawOutcome::of(Outcome::Pending)
                );
            }
            let (out, _) = read_reply(&p, 3, stream, &mut buf);
            let (outcome, cause, error) = if failed {
                (Outcome::Failed, CAUSE_AUTH_FAILED, ConnError::AuthFailed)
            } else {
                (Outcome::Refused, CAUSE_AUTH_REFUSED, ConnError::AuthRefused)
            };
            assert_eq!((out.outcome, out.value), (RawOutcome::of(outcome), cause));
            assert_eq!(error_text(&out), error.text());
            assert!(
                table.opened.lock().unwrap().is_empty(),
                "no unauthorized connector open"
            );
        }
    }
}

fn raw_read(p: &Plugin<TestKind>, seq: u32, stream: u64, buf: &mut [u8]) -> ServiceOut {
    let i = IoIn {
        head: head_of::<IoIn>(service::READ, seq),
        stream,
        buf: buf.as_mut_ptr(),
        len: buf.len(),
    };
    call(p, CONN_SLOTS.read, &i)
}

#[test]
fn a_replayed_raw_read_writes_its_bytes_again() {
    let table = Arc::new(Scripted::default());
    table.script.lock().unwrap().extend([
        (piece(PieceKind::Body, None, None, 6), b"*2\r\n$3".to_vec()),
        (piece(PieceKind::Body, None, None, 5), b"\r\nabc".to_vec()),
    ]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    let mut buf = [0_u8; 16];
    let first = raw_read(&p, 1, stream, &mut buf);
    assert!(ready(&first) && first.len == 6);
    let second = raw_read(&p, 2, stream, &mut buf);
    assert!(ready(&second) && second.len == 5);

    let r1 = raw_read(&p, 1, stream, &mut buf);
    assert!(ready(&r1) && r1.len == 6);
    assert_eq!(&buf[..6], b"*2\r\n$3", "the replayed first read's bytes");
    let r2 = raw_read(&p, 2, stream, &mut buf);
    assert!(ready(&r2) && r2.len == 5);
    assert_eq!(&buf[..5], b"\r\nabc", "the replayed second read's bytes");
    assert!(
        table.script.lock().unwrap().is_empty(),
        "every read reached the far end once"
    );
    let mut small = [0xEE_u8; 4];
    let short = raw_read(&p, 1, stream, &mut small);
    assert_eq!(
        (short.outcome, short.needed_bytes, short.len),
        (RawOutcome::of(Outcome::Failed), 6, 0),
        "a replay buffer below the kept piece is a short answer"
    );
    assert_eq!(small, [0xEE; 4], "a short answer writes nothing");
    let mut again = [0_u8; 6];
    let r1 = raw_read(&p, 1, stream, &mut again);
    assert!(
        ready(&r1) && r1.len == 6,
        "the kept answer is still redeemable"
    );
    assert_eq!(&again, b"*2\r\n$3");
    drop(super::forget(p.instance(), T));
    let gone = raw_read(&p, 1, stream, &mut buf);
    assert!(!ready(&gone), "a forgotten ticket's read is not replayed");
}

#[test]
fn a_dropped_instance_is_forgotten_on_the_table_and_a_live_neighbour_is_not() {
    let table = Arc::new(Recording::default());
    let gone = bound(Box::leak(Box::new(NEEDS)), &table);
    let neighbour = bound(Box::leak(Box::new(NEEDS)), &table);
    for p in [&gone, &neighbour] {
        assert_eq!(
            open_with(p, br#"{"upstream":"127.0.0.1:9"}"#),
            Outcome::Ready
        );
    }
    let (id, kept) = (gone.instance(), neighbour.instance());
    assert_ne!(id, kept);
    assert!(
        table.forgotten.lock().unwrap().is_empty(),
        "no live instance is forgotten"
    );
    drop(gone);
    assert_eq!(
        *table.forgotten.lock().unwrap(),
        vec![id],
        "the dropped instance is forgotten on the table, once"
    );
    assert_eq!(
        establish(&neighbour, 0, "127.0.0.1:9").outcome,
        RawOutcome::of(Outcome::Ready),
        "the live neighbour still reaches its need"
    );
    drop(neighbour);
    assert_eq!(*table.forgotten.lock().unwrap(), vec![id, kept]);
}

#[test]
fn refreshed_connection_authorities_are_each_forgotten_once() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(NEEDS)), &table);
    let original = p.instance();
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    assert_eq!(
        refresh_with(&p, br#"{"upstream":"127.0.0.2:9"}"#),
        Outcome::Ready
    );
    let replacement = table.declared.lock().unwrap().last().unwrap().0;
    assert_ne!(original, replacement);
    assert!(
        table.forgotten.lock().unwrap().is_empty(),
        "the original root authority remains alive for member authentication"
    );
    p.inner.let_go_held();
    p.inner.let_go_held();
    drop(p);
    assert_eq!(
        table.forgotten.lock().unwrap().clone(),
        vec![original, replacement]
    );
}

#[test]
fn retrying_a_failed_export_open_retires_its_new_authority() {
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(TRUSTING)), &table);
    let original = p.instance();
    assert_eq!(open_with(&p, br#"{"ca":"NOT-A-PEM"}"#), Outcome::Failed);
    assert_eq!(table.forgotten.lock().unwrap().clone(), vec![original]);
    assert_eq!(open_with(&p, br#"{"ca":"PEM-A"}"#), Outcome::Ready);
    let replacement = table.declared.lock().unwrap().last().unwrap().0;
    assert_ne!(original, replacement);
    assert!(belongs_to(&p, replacement));
    drop(p);
    assert_eq!(
        table.forgotten.lock().unwrap().clone(),
        vec![original, replacement]
    );
}

#[test]
fn the_connector_serves_no_random_of_its_own() {
    assert!(CONN_SLOTS.random.is_none());
}

#[test]
fn a_dropped_instance_leaves_nothing_on_the_connectors_maps() {
    let table = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let p = bound_over(&table);
    let id = p.instance();
    let stream = whole_request(&p, 0);
    let conn = match streams_of(id).get(&stream).map(|s| &s.conn) {
        Some(super::Conn::Open(c)) => *c,
        other => panic!("the whole request is open on the table: {other:?}"),
    };
    assert!(table.slab.get(id, conn).is_ok());
    drop(p);
    assert!(
        streams_of(id).is_empty(),
        "a dropped instance's stream entries stayed on the connector's map"
    );
    assert!(
        table.slab.get(id, conn).is_err(),
        "a dropped instance's open connection stayed open"
    );
}

#[path = "member_secret_tests.rs"]
mod member_secret_tests;

struct Resolving {
    answers: Mutex<std::collections::VecDeque<Option<u64>>>,
    asked: std::sync::atomic::AtomicU64,
}

impl busbar_contract::auth_calls::PerRequestHandle for Resolving {
    fn handle_now(&self) -> Option<u64> {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.answers.lock().unwrap().pop_front().flatten()
    }
}

/// An auth binding presenting the handle it is asked on (`authorization: Bearer h<handle>`).
#[derive(Default)]
struct ByHandle {
    calls: std::sync::atomic::AtomicU64,
}

impl busbar_contract::auth_calls::OutboundAuth for ByHandle {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(
        &self,
        handle: u64,
        _: &busbar_contract::auth_calls::FieldsRequest,
    ) -> Option<busbar_contract::auth_calls::Fields> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Some(busbar_contract::auth_calls::Fields::Ready(vec![
            busbar_contract::auth_calls::AuthField {
                name: b"authorization".to_vec(),
                value: format!("Bearer h{handle}").into_bytes().into(),
                sensitive: true,
                query: false,
                require_secure: false,
            },
        ]))
    }
    fn fields(
        &self,
        _: u64,
        _: busbar_contract::auth_calls::FieldsRequest,
        _: u64,
    ) -> Box<dyn busbar_contract::auth_calls::Fielding> {
        unreachable!("a header binding answers on the spot")
    }
}

fn resolving_table(answers: &[Option<u64>]) -> (Arc<Scripted>, Arc<Resolving>, Arc<ByHandle>) {
    let per = Arc::new(Resolving {
        answers: Mutex::new(answers.iter().copied().collect()),
        asked: std::sync::atomic::AtomicU64::new(0),
    });
    let auth = Arc::new(ByHandle::default());
    let table = Arc::new(Scripted {
        framed: true,
        member_auth: Some(busbar_contract::conn::ConnAuth {
            auth: Arc::clone(&auth) as Arc<dyn busbar_contract::auth_calls::OutboundAuth>,
            handle: 1,
            style_flags: 0,
            points: busbar_contract::abi::auth::AuthPoints::HEAD,
            passthrough: false,
            lender: None,
            per_request: Some(
                Arc::clone(&per) as Arc<dyn busbar_contract::auth_calls::PerRequestHandle>
            ),
        }),
        ..Scripted::default()
    });
    (table, per, auth)
}

const WAIVED_HEAD: &[u8] = b"PATCH/v1/xbusbar-no-member-auth: 1\r\na: 1\r\n";

fn whole_request_with(p: &Plugin<TestKind>, seq: u32, head: &RequestPiece, bytes: &[u8]) {
    let stream = opened_stream(p, seq).value;
    assert!(ready(&request(p, seq + 1, stream, head, bytes)));
    assert!(ready(&request(
        p,
        seq + 2,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
}

#[test]
fn a_waived_request_carries_no_member_auth_and_the_waiver_never_reaches_the_table() {
    let (table, per, auth) = resolving_table(&[Some(4), Some(6)]);

    let dispatcher = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let p = bound_over_by(&table, dispatcher.adopter());
    let waived = RequestPiece {
        fields: span(10, WAIVED_HEAD.len() - 10),
        ..head_piece()
    };
    whole_request_with(&p, 0, &waived, WAIVED_HEAD);
    whole_request_with(&p, 3, &head_piece(), HEAD_BYTES);
    whole_request_with(&p, 6, &head_piece(), HEAD_BYTES);
    let fields: Vec<Vec<(String, Vec<u8>)>> = table
        .opened
        .lock()
        .unwrap()
        .iter()
        .map(|o| o.4.clone())
        .collect();
    assert_eq!(
        fields,
        vec![
            vec![("a".to_owned(), b"1".to_vec())],
            vec![
                ("authorization".to_owned(), b"Bearer h4".to_vec()),
                ("a".to_owned(), b"1".to_vec())
            ],
            vec![
                ("authorization".to_owned(), b"Bearer h6".to_vec()),
                ("a".to_owned(), b"1".to_vec())
            ],
        ],
        "the waived request presented nothing and its waiver never reached the table; each \
         other request the handle its credential resolved to for it"
    );
    assert_eq!(per.asked.load(std::sync::atomic::Ordering::SeqCst), 2);
    assert_eq!(auth.calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn a_request_whose_member_credential_no_longer_resolves_is_refused_and_opens_nothing() {
    let (table, per, auth) = resolving_table(&[None]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    assert!(ready(&request(&p, 1, stream, &head_piece(), HEAD_BYTES)));
    assert!(ready(&request(
        &p,
        2,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
    let mut buf = [0_u8; 8];
    let (o, _) = read_reply(&p, 3, stream, &mut buf);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    assert!(table.opened.lock().unwrap().is_empty(), "nothing opened");
    assert_eq!(per.asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(
        auth.calls.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing presented"
    );
}

#[test]
fn a_request_refused_for_an_unavailable_credential_names_that_cause() {
    use busbar_contract::abi::host::conn::connector::CAUSE_CREDENTIAL_UNAVAILABLE;
    let (table, _, _) = resolving_table(&[None]);
    let p = bound_over(&table);
    let stream = opened_stream(&p, 0).value;
    whole_request_on(&p, 1, stream);
    let mut buf = [0_u8; 8];
    let (o, _) = read_reply(&p, 3, stream, &mut buf);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    assert_eq!(o.value, CAUSE_CREDENTIAL_UNAVAILABLE);
    assert_eq!(error_text(&o), ConnError::CredentialUnavailable.text());

    let plain = Arc::new(Scripted {
        failing: Some((
            ConnError::Refused,
            ConnCause {
                stage: 0,
                text: "".into(),
            },
        )),
        ..Scripted::default()
    });
    let p = bound_over(&plain);
    let stream = opened_stream(&p, 0).value;
    let (o, _) = read_reply(&p, 1, stream, &mut buf);
    assert_eq!(o.outcome, RawOutcome::of(Outcome::Refused));
    assert_ne!(o.value, CAUSE_CREDENTIAL_UNAVAILABLE);
    assert_eq!(error_text(&o), ConnError::Refused.text());
}

fn whole_request_on(p: &Plugin<TestKind>, seq: u32, stream: u64) {
    assert!(ready(&request(p, seq, stream, &head_piece(), HEAD_BYTES)));
    assert!(ready(&request(
        p,
        seq + 1,
        stream,
        &kind_piece(REQUEST_END),
        b""
    )));
}

struct AuthShaped;
impl crate::dispatch::Kind for AuthShaped {
    const CODE: busbar_contract::abi::mechanism::KindCode =
        busbar_contract::abi::mechanism::KindCode::Auth;
    type Ops = busbar_contract::abi::mechanism::lifecycle::OpsHead;
    const TIMEOUT: Outcome = Outcome::Failed;
}

#[test]
fn an_auth_instances_authority_is_held_before_its_needs_are_declared() {
    use busbar_contract::abi::mechanism::KindCode;
    let table = Arc::new(Recording::default());
    let unpinned: &'static [Need] = Box::leak(Box::new([Need {
        target_from: NONE,
        ..NEEDS[0]
    }]));
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement() };
    let auth = KindCode::Auth;
    let st: &'static Statement = Box::leak(Box::new(Statement {
        kind: auth as u32,
        kind_abi: auth.abi_version(),
        needs: unpinned.as_ptr(),
        needs_len: unpinned.len(),
        ..st
    }));
    let door: &'static Door = Box::leak(Box::new(unsafe {
        Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
            kind: auth as u32,
            kind_abi: auth.abi_version(),
            layout: auth.layout_fingerprint(),
            statement: st,
            ..real.parts()
        })
    }));
    let v = validate_door::<AuthShaped>(door).expect("the auth-kind door validates");
    let conns: Arc<dyn DeclaredConns> = table.clone();
    let p = Plugin::<AuthShaped>::bind(
        v,
        None,
        Bind {
            instance: Arc::from("the-auth-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the auth-kind instance binds");
    let declared: Vec<InstanceId> = table.declared.lock().unwrap().iter().map(|d| d.0).collect();
    assert_eq!(declared.len(), 1, "its one need is declared at bind");
    assert_eq!(
        *table.held.lock().unwrap(),
        vec![(declared[0], 0)],
        "the auth instance is held, before any of its needs is declared"
    );
    drop(p);

    let other = Arc::new(Recording::default());
    let _p = bound(unpinned, &other);
    assert_eq!(other.declared.lock().unwrap().len(), 1);
    assert!(
        other.held.lock().unwrap().is_empty(),
        "a non-auth instance keeps the host field it writes"
    );
}

#[test]
fn red_a_connector_buffer_over_the_byte_cap_is_refused_before_any_slice() {
    let mut buf = [0_u8; 8];
    let over = u32::MAX as usize + 1;
    // SAFETY: the range is refused before any slice is formed; nothing reads or writes it.
    let formed = unsafe { super::bytes(buf.as_mut_ptr(), over) }.map(|b| b.len());
    assert_eq!(
        formed, None,
        "a buffer stated over the byte cap was formed into a slice"
    );
    // SAFETY: the test's own eight bytes.
    let within = unsafe { super::bytes(buf.as_mut_ptr(), buf.len()) }.map(|b| b.len());
    assert_eq!(within, Some(8), "a buffer within the cap is the caller's");
}

#[test]
fn red_an_instances_last_drop_on_a_worker_closes_with_no_worker_lock_held() {
    let table = Arc::new(Scripted {
        framed: true,
        ..Scripted::default()
    });
    let d = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let p = bound_over_by(&table, d.adopter());
    assert_eq!(open_with(&p, b"{}"), Outcome::Ready);
    let id = p.instance();
    let stream = whole_request(&p, 0);
    assert!(
        matches!(
            streams_of(id).get(&stream).map(|s| &s.conn),
            Some(super::Conn::Open(_))
        ),
        "the whole request is open on the table"
    );
    let driver = d.driver(&p, 0).expect("a driver ticket");

    drop(p);
    table.close_gate.armed.store(true, AtomicOrdering::SeqCst);
    d.recycle(driver);
    let parked = table
        .close_gate
        .entered_within(std::time::Duration::from_secs(10));
    let minted = std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        let d = &d;
        s.spawn(move || {
            let _ = tx.send(d.mint(0));
        });
        let minted = rx.recv_timeout(std::time::Duration::from_secs(5));

        table
            .close_gate
            .released
            .store(true, AtomicOrdering::SeqCst);
        minted
    });
    assert!(
        parked,
        "the dropped instance's close never reached the table"
    );
    let minted = minted.expect(
        "a mint on the worker blocked while a transport close ran: the instance was let go under \
         the worker's state lock",
    );
    let t = minted.expect("a ticket");
    d.recycle(t);
}

#[test]
fn red_a_dial_left_in_flight_is_closed_with_no_worker_lock_held() {
    let table = Arc::new(Scripted {
        landing: true,
        ..Scripted::default()
    });
    let d = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
    let p = bound_over_by(&table, d.adopter());
    assert_eq!(open_with(&p, b"{}"), Outcome::Ready);
    let driver = d.driver(&p, 0).expect("a driver ticket");
    let pending = establish_on(&p, 0, "127.0.0.1:9", driver);
    assert_eq!(
        pending.outcome,
        RawOutcome::of(Outcome::Pending),
        "the dial is still connecting"
    );
    assert_eq!(table.opened.lock().unwrap().len(), 1, "one dial in flight");
    table.close_gate.armed.store(true, AtomicOrdering::SeqCst);
    d.recycle(driver);
    let parked = table
        .close_gate
        .entered_within(std::time::Duration::from_secs(10));
    let minted = std::thread::scope(|s| {
        let (tx, rx) = std::sync::mpsc::channel();
        let d = &d;
        s.spawn(move || {
            let _ = tx.send(d.mint(0));
        });
        let minted = rx.recv_timeout(std::time::Duration::from_secs(5));

        table
            .close_gate
            .released
            .store(true, AtomicOrdering::SeqCst);
        minted
    });
    assert!(parked, "the dial left in flight was never closed");
    let minted = minted.expect(
        "a mint on the worker blocked while a transport close ran: the dial left in flight was \
         closed under the worker's state lock",
    );
    let t = minted.expect("a ticket");
    d.recycle(t);
    drop(p);
}

#[repr(C, align(8))]
struct LentOut([u8; 96]);

impl LentOut {
    fn stating(size: u32) -> Self {
        let mut b = [0xAA_u8; 96];
        b[..4].copy_from_slice(&size.to_ne_bytes());
        Self(b)
    }

    fn out(&mut self) -> *mut busbar_contract::abi::host::service::ServiceOut {
        self.0.as_mut_ptr().cast()
    }

    fn untouched_from(&self, from: usize) -> bool {
        self.0[from..].iter().all(|b| *b == 0xAA)
    }
}

#[test]
fn red_the_connector_service_frame_writes_no_further_than_the_out_the_caller_stated() {
    use busbar_contract::abi::host::service::SERVICE_OUT_V1;
    use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
    let mut lent = LentOut::stating(32);
    let raw: RawOutcome = super::slot(
        busbar_contract::abi::mechanism::ticket::HostCtx::NONE,
        std::ptr::null(),
        lent.out(),
        0,
        0,
        |_, _, _, _| -> super::Answered { unreachable!("a NULL `in` never reaches the body") },
    );
    assert_eq!(raw.outcome(), Outcome::Refused, "a short `out` was served");
    assert!(lent.untouched_from(4), "a short `out` was written");
    let mut lent = LentOut::stating(SERVICE_OUT_V1 as u32);
    let raw: RawOutcome = super::slot(
        busbar_contract::abi::mechanism::ticket::HostCtx::NONE,
        std::ptr::null(),
        lent.out(),
        0,
        0,
        |_, _, _, _| -> super::Answered { unreachable!("a NULL `in` never reaches the body") },
    );
    assert_eq!(raw.outcome(), Outcome::Fault, "a NULL `in` is FAULT");
    assert!(
        lent.untouched_from(SERVICE_OUT_V1),
        "the host wrote past the `out` stated"
    );
    assert_eq!(lent.0[5], 0, "`exited` is written zero by every frame");
}

#[test]
fn the_auth_request_signs_the_authority_the_socket_dials() {
    let binding = busbar_contract::conn::ConnAuth {
        auth: Arc::new(ByHandle::default()) as Arc<dyn OutboundAuth>,
        handle: 1,
        style_flags: 0,
        points: busbar_contract::abi::auth::AuthPoints::HEAD,
        passthrough: false,
        lender: None,
        per_request: None,
    };
    let head = super::Head {
        method: b"GET".to_vec(),
        target: Vec::new(),
        fields: Vec::new(),
        timeout_ms: 0,
        dial_timeout_ms: 0,
    };
    for (target, authority, path, query) in [
        (
            "https://svc.example\\@other.example/x?q=1",
            "svc.example",
            &b"/@other.example/x"[..],
            Some(&b"q=1"[..]),
        ),
        (
            "https://user:pw@svc.example/x",
            "svc.example",
            &b"/x"[..],
            None,
        ),
        (
            "https://svc.example#f@other.example/x",
            "svc.example",
            &b"/"[..],
            None,
        ),
        (
            "https://svc.example:8443",
            "svc.example:8443",
            &b"/"[..],
            None,
        ),
    ] {
        let asked = super::auth_request(&binding, &head, target, b"", None, &[])
            .expect("a non-passthrough binding asks");
        assert_eq!(asked.authority, authority, "{target}");
        assert_eq!(asked.path, path, "{target}");
        assert_eq!(asked.query.as_deref(), query, "{target}");
    }
}

#[test]
fn the_auth_request_signs_the_lines_the_open_completes_the_head_with() {
    let binding = busbar_contract::conn::ConnAuth {
        auth: Arc::new(ByHandle::default()) as Arc<dyn OutboundAuth>,
        handle: 1,
        style_flags: busbar_contract::abi::auth::STYLE_NEEDS_HEADERS,
        points: busbar_contract::abi::auth::AuthPoints::HEAD,
        passthrough: false,
        lender: None,
        per_request: None,
    };
    let head = super::Head {
        method: b"POST".to_vec(),
        target: b"/x".to_vec(),
        fields: vec![
            ("content-type".to_owned(), b"application/json".to_vec()),
            ("busbar-sealed-query".to_owned(), b"forged=value".to_vec()),
        ],
        timeout_ms: 0,
        dial_timeout_ms: 0,
    };
    let located = busbar_contract::conn::HeadDefaults {
        lines: vec![
            (b"accept".to_vec(), b"*/*".to_vec()),
            (b"host".to_vec(), b"svc.example".to_vec()),
        ],
        states_length: true,
    };
    let added = located.completing(
        |name| {
            head.fields
                .iter()
                .any(|(n, _)| n.as_bytes().eq_ignore_ascii_case(name))
        },
        2,
    );
    let asked = super::auth_request(
        &binding,
        &head,
        "https://svc.example/x",
        b"{}",
        None,
        &added,
    )
    .expect("a non-passthrough binding asks");
    let signed: Vec<(&[u8], &[u8])> = asked
        .headers
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    assert_eq!(
        signed,
        [
            (&b"content-type"[..], &b"application/json"[..]),
            (b"accept", b"*/*"),
            (b"host", b"svc.example"),
            (b"content-length", b"2"),
        ]
    );
}

fn bound_labelled(needs: &'static [Need], table: &Arc<Recording>, label: &str) -> Plugin<TestKind> {
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement() };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: needs.as_ptr(),
        needs_len: needs.len(),
        ..st
    }));
    let door: &'static Door = Box::leak(Box::new(unsafe {
        Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
            statement: st,
            ..real.parts()
        })
    }));
    let v = validate_door::<TestKind>(door).expect("the door validates");
    let conns: Arc<dyn DeclaredConns> = table.clone();
    Plugin::bind(
        v,
        None,
        Bind {
            instance: Arc::from(label),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the instance binds")
}

fn refused_for(label: &str) -> Vec<String> {
    crate::observe::testing::refused(label)
        .into_iter()
        .map(|(_, _, refusal)| refusal)
        .collect()
}

#[test]
fn a_need_refused_at_open_is_audited_once() {
    let label = "bind-audit-need-refused";
    let table = Arc::new(Recording::default());
    let p = bound_labelled(Box::leak(Box::new(NEEDS)), &table, label);
    assert_eq!(
        open_with(&p, br#"{"upstream":"127.0.0.1:9"}"#),
        Outcome::Ready
    );
    assert!(
        refused_for(label).is_empty(),
        "an admitted need is not a refusal"
    );

    assert_eq!(
        refresh_with(&p, br#"{"other":"127.0.0.3:9"}"#),
        Outcome::Ready
    );
    let refused = refused_for(label);
    assert_eq!(
        refused,
        vec![format!(
            "{:?}",
            crate::observe::BindRefusal::Need {
                need: 0,
                reason: "target_unresolved"
            }
        )],
        "one record for the one refusal"
    );
}

#[test]
fn a_need_refused_by_the_table_is_audited_in_its_word() {
    let label = "bind-audit-trust-refused";
    let table = Arc::new(Recording::default());
    let p = bound_labelled(Box::leak(Box::new(TRUSTING)), &table, label);
    assert_eq!(open_with(&p, br#"{"ca":"junk"}"#), Outcome::Failed);
    assert_eq!(
        refused_for(label),
        vec![format!(
            "{:?}",
            crate::observe::BindRefusal::Need {
                need: 0,
                reason: "refused"
            }
        )]
    );
}

#[test]
fn an_unwritten_settings_trust_is_refused_but_not_audited() {
    let label = "bind-audit-trust-unwritten";
    let table = Arc::new(Recording::default());
    let p = bound_labelled(Box::leak(Box::new(TRUSTING)), &table, label);
    assert_eq!(open_with(&p, br#"{"other":"PEM-C"}"#), Outcome::Ready);
    assert_eq!(refresh_with(&p, br#"{"other":"PEM-D"}"#), Outcome::Ready);
    assert!(
        refused_for(label).is_empty(),
        "an unwritten optional anchor is no audited refusal: {:?}",
        refused_for(label)
    );

    let trusts: Vec<Option<String>> = table
        .declared
        .lock()
        .unwrap()
        .iter()
        .filter(|(owner, need, ..)| belongs_to(&p, *owner) && *need == NeedId(0))
        .map(|(.., trust)| trust.clone())
        .collect();
    assert_generation_owners(&table, &p, 2);
    assert_eq!(trusts, vec![None, None]);

    assert_eq!(refresh_with(&p, br#"{"ca":"junk"}"#), Outcome::Failed);
    assert_generation_owners(&table, &p, 3);
    assert_eq!(
        refused_for(label),
        vec![format!(
            "{:?}",
            crate::observe::BindRefusal::Need {
                need: 0,
                reason: "refused"
            }
        )]
    );
}

#[test]
fn a_declared_open_warning_is_audited_once() {
    let label = "bind-audit-open-flagged";
    let table = Arc::new(Recording::default());
    let p = bound_labelled(&[], &table, label);
    assert_eq!(open_with(&p, plug::FLAG_OPEN), Outcome::Ready);
    assert_eq!(
        refused_for(label),
        vec![format!(
            "{:?}",
            crate::observe::BindRefusal::Open { code: "m1.note" }
        )]
    );
}

fn tick_with(p: &Plugin<TestKind>, mode: &'static [u8]) -> Outcome {
    let mut head = in_head();
    head.extensions = Blob {
        ptr: mode.as_ptr(),
        len: mode.len(),
        fmt: busbar_contract::abi::mechanism::call::BLOB_OCTETS,
        flags: 0,
    };
    let mut f = Frame::new(
        busbar_contract::abi::mechanism::lifecycle::TickIn {
            head,
            now_ns: crate::dispatch::now_ns(),
        },
        busbar_contract::abi::mechanism::lifecycle::TickOut {
            head: out_head(),
            next_tick_ns: 0,
        },
    );
    p.call(slot::TICK, &mut f).outcome
}

#[test]
fn a_declared_error_an_op_raises_is_audited() {
    let label = "op-audit-flagged";
    let table = Arc::new(Recording::default());
    let p = bound_labelled(&[], &table, label);
    assert_eq!(open_with(&p, br"{}"), Outcome::Ready);
    assert_eq!(tick_with(&p, b"answer:1"), Outcome::Ready);
    assert!(
        refused_for(label).is_empty(),
        "a declared warning at an op is a log, not a record"
    );
    assert_eq!(tick_with(&p, plug::FLAG_OP), Outcome::Ready);
    assert_eq!(
        refused_for(label),
        vec![format!(
            "{:?}",
            crate::observe::BindRefusal::Op { code: "m1.note" }
        )]
    );
}

#[test]
fn a_quiet_open_is_not_audited() {
    let label = "bind-audit-open-quiet";
    let table = Arc::new(Recording::default());
    let p = bound_labelled(&[], &table, label);
    assert_eq!(open_with(&p, br"{}"), Outcome::Ready);
    assert!(refused_for(label).is_empty());
}

struct ProtectedAuth(bool);

fn protected_fields() -> Fields {
    let Fields::Ready(mut fields) = bearer() else {
        unreachable!()
    };
    fields[0].require_secure = true;
    Fields::Ready(fields)
}

impl OutboundAuth for ProtectedAuth {
    fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
        Ok(1)
    }
    fn fields_now(&self, _: u64, _: &FieldsRequest) -> Option<Fields> {
        self.0.then(protected_fields)
    }
    fn fields(&self, _: u64, _: FieldsRequest, _: u64) -> Box<dyn Fielding> {
        Box::new(ProtectedReply)
    }
}

struct ProtectedReply;
impl std::future::Future for ProtectedReply {
    type Output = Fields;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Fields> {
        std::task::Poll::Ready(protected_fields())
    }
}
impl Fielding for ProtectedReply {
    fn settled(&mut self) -> Option<Fields> {
        Some(protected_fields())
    }
}

#[test]
fn a_members_protected_fields_never_open_on_a_table_without_secure_custody() {
    for now in [true, false] {
        let table = Arc::new(Scripted {
            framed: true,
            auth: Some(Arc::new(ProtectedAuth(now))),
            ..Scripted::default()
        });
        let dispatcher =
            crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
        let p = bound_over_by(&table, dispatcher.adopter());
        let stream = whole_request(&p, 0);
        let mut buf = [0; 64];
        let _ = read_reply(&p, 3, stream, &mut buf);
        assert!(
            table.opened.lock().unwrap().is_empty(),
            "protected field escaped through the raw open"
        );
    }
}

mod refresh_driver_generation {
    use super::*;
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, FLAG_RESUME};
    use busbar_contract::abi::mechanism::lifecycle::OpsHead;
    use std::ffi::c_void;
    use std::sync::atomic::{AtomicBool, Ordering};

    static OBSERVED: Mutex<Vec<(InstanceId, bool)>> = Mutex::new(Vec::new());
    static FINISH: AtomicBool = AtomicBool::new(false);

    crate::dispatch_tests::c_abi! {
        fn drive(_: *mut c_void, input: *const c_void, out: *mut c_void) -> RawOutcome {
            let input = unsafe { &*input.cast::<InHead>() };
            let binding = crate::dispatch::export_bindings::current().expect("driver binding");
            let owner = binding.conn.as_ref().expect("driver authority").0;
            let outcome = if FINISH.load(Ordering::SeqCst) { Outcome::Ready } else { Outcome::Pending };
            unsafe { (*out.cast::<OutHead>()).outcome = RawOutcome::of(outcome); }
            OBSERVED.lock().unwrap().push((owner, input.flags & FLAG_RESUME != 0));
            RawOutcome::of(outcome)
        }
    }

    fn wait(count: usize) {
        let start = std::time::Instant::now();
        while OBSERVED.lock().unwrap().len() < count {
            assert!(
                start.elapsed() < std::time::Duration::from_secs(10),
                "driver crossing {count}"
            );
            std::thread::yield_now();
        }
    }

    #[test]
    fn pending_driver_keeps_authority_and_autonomous_next_cycle_uses_refreshed_generation() {
        OBSERVED.lock().unwrap().clear();
        FINISH.store(false, Ordering::SeqCst);
        let d = crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
        let table = Arc::new(Recording::default());
        let conns: Arc<dyn DeclaredConns> = table.clone();
        let real = unsafe { *plug::busbar_plugin_door() };
        let statement = unsafe { *real.statement() };
        let needs = Box::leak(Box::new(NEEDS));
        let statement = Box::leak(Box::new(Statement {
            kind: busbar_contract::abi::mechanism::KindCode::Plane as u32,
            kind_abi: busbar_contract::abi::mechanism::KindCode::Plane.abi_version(),
            needs: needs.as_ptr(),
            needs_len: needs.len(),
            ..statement
        }));
        let ops = unsafe { *real.parts().ops.cast::<OpsHead>() };
        let ops = Box::leak(Box::new(OpsHead {
            drive: Some(drive),
            ..ops
        }));
        let door = Box::leak(Box::new(unsafe {
            Door::__from_parts(busbar_contract::abi::mechanism::door::DoorParts {
                kind: busbar_contract::abi::mechanism::KindCode::Plane as u32,
                kind_abi: busbar_contract::abi::mechanism::KindCode::Plane.abi_version(),
                layout: busbar_contract::abi::mechanism::KindCode::Plane.layout_fingerprint(),
                statement,
                ops,
                ..real.parts()
            })
        }));
        let plugin = Plugin::<PlaneShaped>::bind(
            validate_door::<PlaneShaped>(door).unwrap(),
            None,
            Bind {
                instance: Arc::from("driver-generation"),
                max_inflight_cap: 8,
                sink: Arc::new(NoSink),
                dispatcher: d.adopter(),
                conns: crate::dispatch::ConnTable::Host(conns),
            },
        )
        .unwrap();
        assert_eq!(
            open_with(&plugin, br#"{"upstream":"127.0.0.1:9"}"#),
            Outcome::Ready
        );
        let old = plugin.instance();
        let driver = d.driver(&plugin, 0).unwrap();
        crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
        wait(1);
        assert!(d.retirement_barrier(driver, std::time::Duration::from_secs(10)));
        assert_eq!(
            refresh_with(&plugin, br#"{"upstream":"127.0.0.2:9"}"#),
            Outcome::Ready
        );
        let new = table.declared.lock().unwrap().last().unwrap().0;
        assert_ne!(old, new);
        FINISH.store(true, Ordering::SeqCst);
        crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
        wait(2);
        assert!(d.retirement_barrier(driver, std::time::Duration::from_secs(10)));
        crate::dispatch::ticket::host_wake(plugin.inner.ctx(), driver);
        wait(3);
        assert_eq!(
            *OBSERVED.lock().unwrap(),
            vec![(old, false), (old, true), (new, false)]
        );
        d.recycle(driver);
        assert!(d.retirement_barrier(driver, std::time::Duration::from_secs(10)));
    }
}

#[path = "ordinary_connector_bounds.rs"]
mod ordinary_connector_bounds;

#[test]
fn framed_opens_keep_the_serving_unit_through_sync_and_pending_auth() {
    struct UnitAuth {
        pending: bool,
        units: Mutex<Vec<u64>>,
    }
    impl OutboundAuth for UnitAuth {
        fn open_outbound(&self, _: &str, _: &[u8], _: &serde_json::Value) -> Result<u64, String> {
            Ok(1)
        }
        fn fields_now(&self, _: u64, request: &FieldsRequest) -> Option<Fields> {
            self.units.lock().unwrap().push(request.unit);
            (!self.pending).then(|| Fields::Ready(Vec::new()))
        }
        fn fields(&self, _: u64, request: FieldsRequest, _: u64) -> Box<dyn Fielding> {
            self.units.lock().unwrap().push(request.unit);
            Box::new(UnitFields(false))
        }
    }
    struct UnitFields(bool);
    impl std::future::Future for UnitFields {
        type Output = Fields;
        fn poll(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Fields> {
            if !self.0 {
                self.0 = true;
                cx.waker().wake_by_ref();
                std::task::Poll::Pending
            } else {
                std::task::Poll::Ready(Fields::Ready(Vec::new()))
            }
        }
    }
    impl Fielding for UnitFields {
        fn settled(&mut self) -> Option<Fields> {
            None
        }
    }
    for pending in [false, true] {
        let auth = Arc::new(UnitAuth {
            pending,
            units: Mutex::new(Vec::new()),
        });
        let table = Arc::new(Scripted {
            framed: true,
            auth: Some(auth.clone()),
            ..Scripted::default()
        });
        let dispatcher =
            crate::dispatch::Dispatcher::new(crate::dispatch::DispatchConfig::default());
        let p = bound_over_by(&table, dispatcher.adopter());
        for (index, unit) in [71, 93].into_iter().enumerate() {
            let seq = index as u32 * 10;
            let stream = {
                let _serving = crate::dispatch::services::serving(Some(unit));
                whole_request(&p, seq)
            };
            if pending {
                table
                    .script
                    .lock()
                    .unwrap()
                    .push_back((piece(PieceKind::Fields, Some(200), None, 0), Vec::new()));
                let mut buf = [0u8; 64];
                let _serving = crate::dispatch::services::serving(Some(999));
                let (out, _) = read_reply(&p, seq + 3, stream, &mut buf);
                assert_eq!(out.outcome, RawOutcome::of(Outcome::Pending));
                assert_eq!(table.opened_units.lock().unwrap().len(), index);
                let (out, got) = read_reply(&p, seq + 3, stream, &mut buf);
                assert!(ready(&out), "{}", error_text(&out));
                assert_eq!(got.kind, REPLY_HEAD);
            }
        }
        assert_eq!(*table.opened_units.lock().unwrap(), [71, 93]);
        assert_eq!(
            *auth.units.lock().unwrap(),
            if pending {
                vec![71, 71, 93, 93]
            } else {
                vec![71, 93]
            }
        );
    }
}
