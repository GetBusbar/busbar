// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONNECTOR SLOTS, both ways: an instance whose Statement declares a need is handed the slots
//! and its needs are declared on the host's one connection table (the whole need, under its
//! Statement index) — a need whose `target_from` names a config path at `open` and every `refresh`,
//! pinned to what the path resolves to in the settings (ARCHITECT ruling 2026-09-30 on the conns
//! fill, option A); `ESTABLISH` reaches the table under the instance's own identity. An instance
//! that declares no need is handed no table, and the table refuses an open under its identity.

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

/// One declaration as it reached the table: owner, need, the need, the target and the trust it
/// resolved to.
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
}

/// One member-program declaration as it reached the table.
type MemberDeclared = (
    InstanceId,
    NeedId,
    Vec<(String, busbar_contract::conn::Program)>,
);

impl DeclaredConns for Recording {
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

/// The test plugin's door, its Statement declaring `needs`, bound over `table`.
fn bound(needs: &'static [Need], table: &Arc<Recording>) -> Plugin<TestKind> {
    bind_over(needs, table).expect("the instance binds")
}

/// The test plugin's door, its Statement declaring `needs`, bound over `table`: the bind's answer.
fn bind_over(
    needs: &'static [Need],
    table: &Arc<Recording>,
) -> Result<Plugin<TestKind>, crate::dispatch::LoadError> {
    let conns: Arc<dyn DeclaredConns> = table.clone();
    bind_as(needs, crate::dispatch::ConnTable::Host(conns))
}

/// The test plugin's door, its Statement declaring `needs`, bound with `conns`: the bind's answer.
fn bind_as(
    needs: &'static [Need],
    conns: crate::dispatch::ConnTable,
) -> Result<Plugin<TestKind>, crate::dispatch::LoadError> {
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

/// RED (Q-P4-3): a door whose Statement declares a need, bound to SERVE with no connection table,
/// is refused at bind, naming the plugin and its count of needs; never bound to fail at its first
/// dial.
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

/// GREEN twins: a PROBE bind of the same door, with no table, binds (its need not declared, no
/// slots handed); a door that declares no need serves with no table.
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

/// `ESTABLISH` through the slots, under `p`'s context, for `need` at `target`.
fn establish(p: &Plugin<TestKind>, need: u32, target: &'static str) -> ServiceOut {
    establish_on(p, need, target, Ticket::NONE)
}

/// [`establish`] on `ticket`'s first completion handle.
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

/// An `ESTABLISH` naming the registration `member`, its head stating `size` bytes.
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
        .filter(|(owner, need, ..)| (*owner, *need) == (p.instance(), NeedId(0)))
        .map(|(_, _, _, target, _)| target.clone())
        .collect()
}

/// RED (spec Part 2 #50, THE BOOT'S SCHEME MATCH): an outbound need over a scheme no loaded
/// transport serves refuses the load, naming the plugin and the scheme, and declares nothing; the
/// same need over a served scheme binds.
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

/// RED (spec Part 0: core refuses at boot; Part 2 #50; ARCHITECT ruling 2026-10-02): an INBOUND need
/// over a scheme no loaded transport serves refuses the load the same way, naming the plugin and the
/// scheme; the same inbound need over a served scheme binds.
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

/// RED: a `refresh` that changes the setting re-declares the need at the new target, and one whose
/// `target_from` resolves to nothing declares it without a target, which the table refuses.
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
    assert_eq!(
        targets(&table, &p),
        vec![
            Some("127.0.0.1:9".to_owned()),
            Some("127.0.0.2:9".to_owned()),
            None
        ]
    );
}

/// A need whose target the plugin names and whose trust anchors come from `settings.ca`.
const TRUSTING: [Need; 1] = [Need {
    target_from: NONE,
    trust_from: abi_str("settings.ca"),
    ..NEEDS[0]
}];

/// RED: a need whose `trust_from` names a config path is not declared at bind; at `open` it is
/// declared with the PEM that path resolves to in the settings, a `refresh` that changes it
/// re-declares it with the new PEM, and one where it resolves to nothing declares it without a
/// trust, for the table to refuse (ARCHITECT ruling 2026-10-02; spec section 5, PB-100's fill).
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
    let declared = table.declared.lock().unwrap().clone();
    let seen: Vec<(Option<String>, Option<String>)> = declared
        .iter()
        .filter(|(owner, need, ..)| (*owner, *need) == (p.instance(), NeedId(0)))
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

/// RED (Q-FC7): two instances, each on its own dispatcher, whose first tickets collide (fresh
/// dispatchers mint identical first tickets). Recycling one's ticket forgets only its own kept
/// answers: the other's re-issued `ESTABLISH` redeems its stored stream and is never run a second
/// time, while the recycled instance's re-issue is a new call. A replaced worker forgets only its
/// own instances' answers in the same way.
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

    forget(one.instance(), first);
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

/// RED (ARCHITECT round 4 (e)): a need whose `target_from` names a PROGRAM in the settings
/// (`{command, args, env}`) is declared as that program, at `open` and every `refresh`; a program
/// the settings misspell (a bare command name) is declared with no target, which the table refuses.
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
                args: vec!["--serve".into()],
                env: vec![("T".into(), "v".into())],
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
    assert_eq!(targets(&table, &p), vec![None], "a misspelled program");
    assert_eq!(table.programs.lock().unwrap().len(), 1);
}

/// `target_from` names `settings.<key>[.<key>...]`, walked to a non-empty string.
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

// ── FRAMED REQUESTS, REPLIES AND THE REPLAY RULE ──

use std::collections::VecDeque;

use busbar_contract::abi::host::conn::connector::{
    IoIn, ReplyIn, ReplyPiece, RequestIn, RequestPiece, REPLY_ACK, REPLY_BODY, REPLY_END,
    REPLY_HEAD, REQUEST_BODY, REQUEST_END, REQUEST_HEAD,
};
use busbar_contract::abi::host::service::ServiceFn;
use busbar_contract::abi::transport::FrameSpan;
use busbar_contract::conn::PieceKind;
use busbar_contract::ids::StreamId;

/// What one open carried: the need, target, head words, fields and body.
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
}

/// One upgrade call as it reached the table: the stream, the name offered, the trust reference.
type Upgrade = (ConnId, Option<String>, Option<String>);

impl DeclaredConns for Scripted {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        _: &ReadNeed,
        _: Option<&str>,
        _: Option<&str>,
    ) -> Result<(), ConnError> {
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
}

impl Conns for Scripted {
    fn open(
        &self,
        caller: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.slab.check_need(caller, need)?;
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
    fn read(&self, c: InstanceId, id: ConnId, _: u64, buf: &mut [u8]) -> Result<Piece, ConnError> {
        self.slab.get(c, id)?;
        if let Some((e, _)) = &self.failing {
            return Err(*e);
        }
        let (mut p, bytes) = self
            .script
            .lock()
            .unwrap()
            .pop_front()
            .ok_or(ConnError::Pending)?;
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
        self.slab.remove(c, id).map(|_| ())
    }
}

/// A need the plugin names the target of: declared at bind.
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

/// The ticket every op in these tests runs on.
const T: Ticket = Ticket {
    slot: 7,
    generation: 3,
};

fn bound_over(table: &Arc<Scripted>) -> Plugin<TestKind> {
    // SAFETY: the real door and its Statement are `'static`.
    let real: Door = unsafe { *plug::busbar_plugin_door() };
    let st: Statement = unsafe { *real.statement };
    let st: &'static Statement = Box::leak(Box::new(Statement {
        needs: NAMED.as_ptr(),
        needs_len: NAMED.len(),
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
            instance: Arc::from("the-instance"),
            max_inflight_cap: 8,
            sink: Arc::new(NoSink),
            dispatcher: Adopter::unwatched(),
            conns: crate::dispatch::ConnTable::Host(conns),
        },
    )
    .expect("the instance binds")
}

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

/// One crossing of `f` with `input`, under `p`'s context.
fn call<I>(p: &Plugin<TestKind>, f: Option<ServiceFn>, input: &I) -> ServiceOut {
    // SAFETY: an all-zero `ServiceOut` is a valid value the slot overwrites.
    let mut out: ServiceOut = unsafe { std::mem::zeroed() };
    let _: RawOutcome =
        f.expect("served")(p.inner.ctx(), std::ptr::from_ref(input).cast(), &mut out);
    out
}

fn opened_stream(p: &Plugin<TestKind>, seq: u32) -> ServiceOut {
    pinned_stream(p, seq, "")
}

/// `ESTABLISH` of need 0 at `127.0.0.1:9`, its dial stated `within` the address set `within`.
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

/// `PATCH /v1/x` with one field, as `exchange()` lays its head out.
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
    }
}

/// RED: a framed need's ESTABLISH opens nothing (no request goes out before the plugin wrote
/// one); WRITE_REQUEST's head, body and end then open it ONCE, the whole request its opening
/// message: the head words, the field block's fields, the body and the timeout.
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

/// RED: a raw stream refuses WRITE_REQUEST (its bytes go through WRITE), and a framed request's
/// body before its head is refused.
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

/// RED: the reply reads as its head (code, reason exactly as sent, field block), its body, and
/// ONE terminal END; nothing reads after the end.
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

/// RED: a reply that had no head (a raw stream) ends in ONE ack.
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

/// RED: a framed request whose open the egress class refused is handed over (its end answers),
/// and its reply is the FAILED ACK: the refusal, with its text; the reply has ended.
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

/// A reply the connection failed is the failed ack naming WHY: the table's `CAUSE_*` stage in
/// `value` and the underlying error's own text, not the table's generic refusal.
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

/// RED: the host never runs a service twice: a re-issued ESTABLISH handle answers the same
/// stream without a second open, a re-issued WRITE_REQUEST head is not a second head, and a
/// re-issued WRITE writes once.
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
    super::forget(q.instance(), T);
    let fresh = request(&q, 1, stream, &head_piece(), HEAD_BYTES);
    assert_eq!(
        fresh.outcome,
        RawOutcome::of(Outcome::Refused),
        "a forgotten ticket's handle runs afresh"
    );
}

/// THE LANDING RULE AT THE LOADER: ESTABLISH's `within` reaches the connection table's open, the
/// connect, for a raw need at ESTABLISH and for a FRAMED need at WRITE_REQUEST's end, the open
/// that carries the request; so the connector holds its pinned address to the set before the
/// request's bytes leave. An empty `within` states no set (today's open); an entry that is not an
/// IP literal is REFUSED and nothing opens. RED on the loader that dropped `within`.
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

/// `need.admit` for `need`, under `p`'s context.
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
    let slot = crate::dispatch::services::HOST_SLOTS
        .need_admit
        .expect("need.admit is served");
    let _: RawOutcome = slot(p.inner.ctx(), std::ptr::from_ref(&i).cast(), &mut out);
    out.outcome.outcome()
}

/// `need.admit` answers the connection table's verdict on the need as it was declared: REFUSED
/// before it is declared (and for a need the Statement does not have), REFUSED when the table
/// refused it (a target source that resolved to nothing), READY once the table admitted it. RED:
/// the host answered every ask REFUSED ("unimplemented"), so a sink that asks was never admitted.
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

// ── UPGRADE_SECURE AND FACTS (ARCHITECT ruling Q-FC3) ──────────────────────────────────────────

/// The instance's host tables as `open` hands them: its context and the connector slots.
fn sdk_host(p: &Plugin<TestKind>) -> busbar_contract::abi::sdk::conn::Host {
    use busbar_contract::abi::mechanism::ticket::HostTables;
    busbar_contract::abi::sdk::conn::Host::of(&HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: p.inner.ctx(),
        wake: None,
        conns: &CONN_SLOTS,
        services: std::ptr::null(),
        io: std::ptr::null(),
    })
}

/// RED (Q-FC3): the plugin-facing path. Through the SDK's `Connector`, an op establishes a raw
/// stream and upgrades it: the upgrade reaches the host's table under the instance's identity with
/// the stream, the name offered and the trust reference; while the handshake runs it is PENDING,
/// and the op's re-entry on the same ticket redeems the establish (never dialled twice) and drives
/// the upgrade to done, after which a further re-entry redeems that too (never run again).
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

/// RED (Q-FC3): an upgrade that would pend on no ticket is refused, and a framed stream (one the
/// host holds for its framer) is never upgraded.
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

/// RED (Q-FC3): `FACTS` writes the stream's facts: secure, and the far end's certificate hash
/// (the channel-binding input) as the table answered it; a stream in the clear is not secure and
/// carries no hash.
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

/// Q-L16-4: `UpgradeIn::flags`' verify-off reaches the table; an `in` from before the flags
/// (`UPGRADE_IN_V1_SIZE`) reads them as 0, never past what the head states.
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

/// An `env` secret reference's value, as the linked `env` secret plugin resolves it.
fn env_reference(r: &busbar_contract::secret_ref::SecretRef) -> Result<String, String> {
    (r.module == busbar_contract::secret_ref::SECRET_MODULE_ENV)
        .then(|| r.settings.get("key").and_then(serde_json::Value::as_str))
        .flatten()
        .and_then(|k| std::env::var(k).ok())
        .ok_or_else(|| format!("{} does not resolve", r.describe()))
}

/// The member-program need (`settings.*`): each registration that names a program is a member.
const MEMBER_NEEDS: [Need; 1] = [Need {
    target_from: abi_str("settings.*"),
    ..NEEDS[0]
}];

/// RED (ARCHITECT round 5 Q-L3B-STDIO-UPSTREAM (A)): a need whose `target_from` is the
/// member-program path is declared with ONE program per registration that names a `command` —
/// its `command`, `args` and `env`, every other key ignored, an `env` secret reference resolved —
/// at `open` and again at every `refresh` (so the table can retire a changed or removed member); a
/// registration naming no program is no member, and one whose program does not read is left out.
#[test]
fn a_member_program_need_is_declared_with_each_registrations_program() {
    use busbar_contract::conn::Program;
    // The variable one member's `env` reference names; set for this test alone.
    std::env::set_var("BUSBAR_LOADER_MEMBER_PROGRAM_SECRET", "resolved-value");
    // The root installs the linked secret plugins' resolver; this one reads `env` references alone.
    let _ = crate::dispatch::install_member_secrets(env_reference);
    let table = Arc::new(Recording::default());
    let p = bound(Box::leak(Box::new(MEMBER_NEEDS)), &table);
    assert_eq!(
        open_with(
            &p,
            br#"{"one":{"transport":"stdio","command":"/usr/bin/one","args":["--serve"],
                 "env":{"PLAIN":"v","KEY":{"env":"BUSBAR_LOADER_MEMBER_PROGRAM_SECRET"}},
                 "pin":{"mechanism":"unpinned"},"tools_allow":["a"]},
                "web":{"url":"https://upstream.example/rpc","pin":{"mechanism":"unpinned"}},
                "bad":{"transport":"stdio","command":"relative"},
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
                    args: vec!["--serve".into()],
                    env: vec![
                        ("KEY".into(), "resolved-value".into()),
                        ("PLAIN".into(), "v".into()),
                    ],
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
                args: Vec::new(),
                env: Vec::new(),
            }
        )]
    );
}

/// RED (SEAM-4k): an `ESTABLISH` that names a REGISTRATION (`EstablishIn::member`, appended) opens
/// on the table under that name, so what the host sealed for that registration alone (its private
/// reach) applies to the stream; a head whose `size` ends before the field names none and is
/// still served.
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
